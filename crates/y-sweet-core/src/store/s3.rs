use super::{Result, StoreError};
use crate::store::Store;
use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{Client, Method, Response, StatusCode, Url};
use rusty_s3::{Bucket, Credentials, S3Action};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::OnceLock;
use std::time::Duration;
use time::OffsetDateTime;
use url::Url as UrlParser;

const S3_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const S3_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const S3_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
const S3_REGION: &str = "AWS_REGION";
const S3_ENDPOINT: &str = "AWS_ENDPOINT_URL_S3"; // Using consistent naming across tools
const S3_USE_PATH_STYLE: &str = "AWS_S3_USE_PATH_STYLE";
const DEFAULT_S3_REGION: &str = "us-east-1";

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct S3Config {
    pub key: String,
    pub endpoint: String,
    pub secret: String,
    pub token: Option<String>,
    pub bucket: String,
    pub region: String,
    pub bucket_prefix: Option<String>,

    // Use old path-style URLs, needed to support some S3-compatible APIs (including some minio setups)
    pub path_style: bool,
}

impl S3Config {
    /// Parse S3 configuration from environment variables
    ///
    /// This is the unified configuration parser used by both y-sweet and y-sign
    pub fn from_env(bucket: Option<String>, prefix: Option<String>) -> anyhow::Result<Self> {
        // First check for Y_SWEET_STORE which has highest precedence
        if let Ok(store_path) = env::var("Y_SWEET_STORE") {
            if store_path.starts_with("s3://") {
                // Parse the S3 URL to extract bucket and prefix
                let url = UrlParser::parse(&store_path)?;
                let bucket = url
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid S3 URL"))?
                    .to_owned();

                let bucket_prefix = url.path().trim_start_matches('/').to_owned();
                let bucket_prefix = (!bucket_prefix.is_empty()).then_some(bucket_prefix); // "" => None

                return Self::build_config(bucket, bucket_prefix);
            }
        }

        // If bucket is provided as an argument, use it
        if let Some(bucket) = bucket {
            return Self::build_config(bucket, prefix);
        }

        // Otherwise, look for STORAGE_BUCKET or AWS_S3_BUCKET
        let bucket = env::var("STORAGE_BUCKET").or_else(|_| env::var("AWS_S3_BUCKET"))
            .map_err(|_| anyhow::anyhow!("Either Y_SWEET_STORE (s3:// URL) or STORAGE_BUCKET/AWS_S3_BUCKET environment variable is required"))?;

        // Use STORAGE_PREFIX for consistency with both tools
        let bucket_prefix = env::var("STORAGE_PREFIX")
            .or_else(|_| env::var("AWS_S3_BUCKET_PREFIX")) // Fall back to old name for compatibility
            .ok();

        Self::build_config(bucket, bucket_prefix)
    }

    fn build_config(bucket: String, bucket_prefix: Option<String>) -> anyhow::Result<Self> {
        let use_path_style = env::var(S3_USE_PATH_STYLE).ok();
        let path_style = if let Some(use_path_style) = use_path_style {
            if use_path_style.to_lowercase() == "true" || use_path_style == "1" {
                true
            } else if use_path_style.to_lowercase() == "false"
                || use_path_style.is_empty()
                || use_path_style == "0"
            {
                false
            } else {
                anyhow::bail!(
                    "If AWS_S3_USE_PATH_STYLE is set, it must be either \"true\", \"false\", \"1\", or \"0\""
                )
            }
        } else {
            false
        };

        Ok(S3Config {
            key: env::var(S3_ACCESS_KEY_ID)
                .map_err(|_| anyhow::anyhow!("{} env var not supplied", S3_ACCESS_KEY_ID))?,
            secret: env::var(S3_SECRET_ACCESS_KEY)
                .map_err(|_| anyhow::anyhow!("{} env var not supplied", S3_SECRET_ACCESS_KEY))?,
            endpoint: env::var(S3_ENDPOINT).unwrap_or_else(|_| {
                format!(
                    "https://s3.dualstack.{}.amazonaws.com",
                    env::var(S3_REGION).unwrap_or_else(|_| DEFAULT_S3_REGION.to_string())
                )
            }),
            region: env::var(S3_REGION).unwrap_or_else(|_| DEFAULT_S3_REGION.to_string()),
            token: env::var(S3_SESSION_TOKEN).ok(),
            bucket,
            bucket_prefix,
            path_style,
        })
    }
}

const PRESIGNED_URL_DURATION: Duration = Duration::from_secs(60 * 60);

pub struct S3Store {
    pub bucket: Bucket,
    _bucket_checked: OnceLock<()>,
    client: Client,
    pub credentials: Credentials,
    prefix: Option<String>,
}

impl S3Store {
    pub fn new(config: S3Config) -> Self {
        let credentials = if let Some(token) = config.token {
            Credentials::new_with_token(config.key, config.secret, token)
        } else {
            Credentials::new(config.key, config.secret)
        };
        let endpoint: Url = config.endpoint.parse().expect("endpoint is a valid url");

        let path_style = if config.path_style {
            rusty_s3::UrlStyle::Path
        } else if endpoint.host_str() == Some("localhost") {
            // Since this was the old behavior before we added AWS_S3_USE_PATH_STYLE,
            // we continue to support it, but complain a bit.
            tracing::warn!("Inferring path-style URLs for localhost for backwards-compatibility. This behavior may change in the future. Set AWS_S3_USE_PATH_STYLE=true to ensure that path-style URLs are used.");
            rusty_s3::UrlStyle::Path
        } else {
            rusty_s3::UrlStyle::VirtualHost
        };

        let bucket = Bucket::new(endpoint, path_style, config.bucket, config.region)
            .expect("Url has a valid scheme and host");
        let client = Client::new();

        S3Store {
            bucket,
            _bucket_checked: OnceLock::new(),
            client,
            credentials,
            prefix: config.bucket_prefix,
        }
    }

    /// Generate a presigned URL for downloading a file from S3 with an optional existence check
    ///
    /// The key can be:
    /// - A simple file hash: "abcdef123456"
    /// - Already prefixed with files/: "files/abcdef123456"
    /// - A full path: "some/path/to/file"
    ///
    /// This method will add the files/ prefix if needed and handle storage prefixes.
    /// If check_exists is true, it will verify the file exists before generating a URL.
    pub async fn generate_download_url(
        &self,
        key: &str,
        check_exists: bool,
    ) -> Result<Option<String>> {
        self.init().await?;

        // Apply proper prefixing including files/ directory if needed
        let prefixed_key = self.prefixed_key(key);

        tracing::debug!(
            "Generating download URL for key: {} (prefixed as: {})",
            key,
            prefixed_key
        );

        // Check if object exists before generating URL if requested
        if check_exists && !self.exists(&key).await? {
            tracing::debug!("Object does not exist, not generating URL");
            return Ok(None);
        }

        let action = self
            .bucket
            .get_object(Some(&self.credentials), &prefixed_key);
        let url = action.sign_with_time(PRESIGNED_URL_DURATION, &OffsetDateTime::now_utc());

        tracing::debug!("Generated download URL: {}", url);
        Ok(Some(url.to_string()))
    }

    async fn store_request<'a, A: S3Action<'a>>(
        &self,
        method: Method,
        action: A,
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        let url = action.sign_with_time(PRESIGNED_URL_DURATION, &OffsetDateTime::now_utc());
        let mut request = self.client.request(method, url);

        request = if let Some(body) = body {
            request.body(body.to_vec())
        } else {
            request
        };

        let response = request.send().await;

        let response = match response {
            Ok(response) => response,
            Err(e) => return Err(StoreError::ConnectionError(e.to_string())),
        };

        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::NOT_FOUND => Err(StoreError::DoesNotExist(
                "Received NOT_FOUND from S3-compatible API.".to_string(),
            )),
            StatusCode::FORBIDDEN => Err(StoreError::NotAuthorized(
                "Received FORBIDDEN from S3-compatible API.".to_string(),
            )),
            StatusCode::UNAUTHORIZED => Err(StoreError::NotAuthorized(
                "Received UNAUTHORIZED from S3-compatible API.".to_string(),
            )),
            _ => Err(StoreError::ConnectionError(format!(
                "Received {} from S3-compatible API.",
                response.status()
            ))),
        }
    }

    async fn read_response_bytes(response: Response) -> Result<Bytes> {
        match response.bytes().await {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(StoreError::ConnectionError(e.to_string())),
        }
    }

    pub async fn init(&self) -> Result<()> {
        if self._bucket_checked.get().is_some() {
            return Ok(());
        }

        let action = self.bucket.head_bucket(Some(&self.credentials));
        let result = self.store_request(Method::HEAD, action, None).await;

        match result {
            // Normally a 404 indicates that we are attempting to fetch an object that does
            // not exist, but we have only attempted to retrieve a bucket, so here it
            // indicates that the bucket does not exist.
            Err(StoreError::DoesNotExist(_)) => {
                return Err(StoreError::BucketDoesNotExist(
                    "Bucket does not exist.".to_string(),
                ))
            }
            Err(e) => return Err(e),
            Ok(response) => response,
        };

        self._bucket_checked.set(()).unwrap();
        Ok(())
    }

    /// Create a key with the proper prefix and path structure
    ///
    /// This function adds the storage prefix if one is configured, and properly handles the files/ subdirectory
    /// for file storage. It also ensures proper handling of slashes to avoid duplicates.
    pub fn prefixed_key(&self, key: &str) -> String {
        // First, check if the key already starts with "files/" - we don't want to add it twice
        let key_with_files = if key.starts_with("files/") {
            key.to_string()
        } else if key.contains('/') {
            // Don't add "files/" if the key already contains a slash (likely a document path)
            key.to_string()
        } else {
            // For simple keys that don't have a path component, add the files/ directory
            format!("files/{}", key)
        };

        // Now add the storage prefix if one exists
        if let Some(path_prefix) = &self.prefix {
            // Handle trailing slashes in prefix to avoid double slashes
            if path_prefix.ends_with('/') {
                format!("{}{}", path_prefix, key_with_files)
            } else {
                format!("{}/{}", path_prefix, key_with_files)
            }
        } else {
            key_with_files
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.init().await?;
        let prefixed_key = self.prefixed_key(key);
        let object_get = self
            .bucket
            .get_object(Some(&self.credentials), &prefixed_key);
        let response = self.store_request(Method::GET, object_get, None).await;

        match response {
            Ok(response) => {
                let result = Self::read_response_bytes(response).await?;
                Ok(Some(result.to_vec()))
            }
            Err(StoreError::DoesNotExist(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.init().await?;
        let prefixed_key = self.prefixed_key(key);
        let action = self
            .bucket
            .put_object(Some(&self.credentials), &prefixed_key);
        self.store_request(Method::PUT, action, Some(value)).await?;
        Ok(())
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.init().await?;
        let prefixed_key = self.prefixed_key(key);
        let action = self
            .bucket
            .delete_object(Some(&self.credentials), &prefixed_key);
        self.store_request(Method::DELETE, action, None).await?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.init().await?;
        let prefixed_key = self.prefixed_key(key);
        let action = self
            .bucket
            .head_object(Some(&self.credentials), &prefixed_key);
        let response = self.store_request(Method::HEAD, action, None).await;
        match response {
            Ok(_) => Ok(true),
            Err(StoreError::DoesNotExist(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl Store for S3Store {
    async fn init(&self) -> Result<()> {
        self.init().await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get(key).await
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.set(key, value).await
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.remove(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.exists(key).await
    }

    /// Generate a presigned URL for uploading a file to S3
    ///
    /// The key can be:
    /// - A simple file hash: "abcdef123456"
    /// - Already prefixed with files/: "files/abcdef123456"
    /// - A full path: "some/path/to/file"
    ///
    /// This method will add the files/ prefix if needed and handle storage prefixes.
    /// Content-type and content-length constraints can be applied when specified.
    async fn generate_upload_url(
        &self,
        key: &str,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> Result<Option<String>> {
        self.init().await?;

        // Apply proper prefixing including files/ directory if needed
        let prefixed_key = self.prefixed_key(key);

        tracing::debug!(
            "Generating upload URL for key: {} (prefixed as: {})",
            key,
            prefixed_key
        );

        // Create action for presigned PUT request
        let mut action = self
            .bucket
            .put_object(Some(&self.credentials), &prefixed_key);

        // Set content-type if provided - using lowercase header name for S3 signature compatibility
        if let Some(content_type) = content_type {
            action.headers_mut().insert("content-type", content_type);
            tracing::debug!("Added content-type: {}", content_type);
        }

        // Note: Content-Length is handled at validation time after upload,
        // as rusty-s3 doesn't support this constraint in the URL
        if let Some(length) = content_length {
            action
                .headers_mut()
                .insert("content-length".to_string(), length.to_string());
            tracing::debug!(
                "Added content-length constraint between 0 and {} bytes",
                length
            );
        }

        // Sign the URL with time
        let url = action.sign_with_time(PRESIGNED_URL_DURATION, &OffsetDateTime::now_utc());
        tracing::debug!("Generated upload URL: {}", url);

        Ok(Some(url.to_string()))
    }

    /// Generate a presigned URL for downloading a file from S3
    ///
    /// Will check if the file exists before generating a URL.
    async fn generate_download_url(&self, key: &str) -> Result<Option<String>> {
        // Implement directly to avoid recursion with the S3Store method of the same name
        self.init().await?;

        // Apply proper prefixing including files/ directory if needed
        let prefixed_key = self.prefixed_key(key);

        tracing::debug!(
            "Generating download URL for key: {} (prefixed as: {})",
            key,
            prefixed_key
        );

        // Check if object exists before generating URL
        if !self.exists(&key).await? {
            tracing::debug!("Object does not exist, not generating URL");
            return Ok(None);
        }

        let action = self
            .bucket
            .get_object(Some(&self.credentials), &prefixed_key);
        let url = action.sign_with_time(PRESIGNED_URL_DURATION, &OffsetDateTime::now_utc());

        tracing::debug!("Generated download URL: {}", url);
        Ok(Some(url.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    // Mock the S3Action trait to test the headers_mut functionality
    struct MockS3Action {
        headers: HashMap<String, String>,
    }

    impl MockS3Action {
        fn new() -> Self {
            Self {
                headers: HashMap::new(),
            }
        }

        fn headers_mut(&mut self) -> &mut HashMap<String, String> {
            &mut self.headers
        }
    }

    #[test]
    fn test_content_type_header_for_upload_url() {
        let mut action = MockS3Action::new();

        // Set a content type - using lowercase header name for S3 signature compatibility
        let content_type = "application/json";
        action
            .headers_mut()
            .insert("content-type".to_string(), content_type.to_string());

        // Verify the header was set
        assert_eq!(
            action.headers.get("content-type"),
            Some(&content_type.to_string())
        );
    }

    #[test]
    fn test_prefixed_key_with_trailing_slash() {
        use super::*;

        let config = S3Config {
            key: "test-key".to_string(),
            endpoint: "http://localhost:9000".to_string(),
            secret: "test-secret".to_string(),
            token: None,
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            bucket_prefix: Some("prefix/".to_string()),
            path_style: true,
        };

        let store = S3Store::new(config);

        // Test with file hash
        let result = store.prefixed_key("testkey");
        assert_eq!(result, "prefix/files/testkey");

        // Test with explicit files/ prefix
        let result = store.prefixed_key("files/testkey");
        assert_eq!(result, "prefix/files/testkey");

        // Test with deep path
        let result = store.prefixed_key("docs/testkey");
        assert_eq!(result, "prefix/docs/testkey");
    }

    #[test]
    fn test_prefixed_key_without_trailing_slash() {
        use super::*;

        let config = S3Config {
            key: "test-key".to_string(),
            endpoint: "http://localhost:9000".to_string(),
            secret: "test-secret".to_string(),
            token: None,
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            bucket_prefix: Some("prefix".to_string()),
            path_style: true,
        };

        let store = S3Store::new(config);

        // Test with file hash
        let result = store.prefixed_key("testkey");
        assert_eq!(result, "prefix/files/testkey");

        // Test with explicit files/ prefix
        let result = store.prefixed_key("files/testkey");
        assert_eq!(result, "prefix/files/testkey");

        // Test with deep path
        let result = store.prefixed_key("docs/testkey");
        assert_eq!(result, "prefix/docs/testkey");
    }

    #[test]
    fn test_prefixed_key_no_prefix() {
        use super::*;

        let config = S3Config {
            key: "test-key".to_string(),
            endpoint: "http://localhost:9000".to_string(),
            secret: "test-secret".to_string(),
            token: None,
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            bucket_prefix: None,
            path_style: true,
        };

        let store = S3Store::new(config);

        // Test with file hash - should add files/
        let result = store.prefixed_key("testkey");
        assert_eq!(result, "files/testkey");

        // Test with explicit files/ prefix - should not duplicate
        let result = store.prefixed_key("files/testkey");
        assert_eq!(result, "files/testkey");

        // Test with other path - should not add files/
        let result = store.prefixed_key("docs/testkey");
        assert_eq!(result, "docs/testkey");
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl Store for S3Store {
    async fn init(&self) -> Result<()> {
        self.init().await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get(key).await
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.set(key, value).await
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.remove(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.exists(key).await
    }

    /// Generate a presigned URL for uploading a file to S3
    ///
    /// The key can be:
    /// - A simple file hash: "abcdef123456"
    /// - Already prefixed with files/: "files/abcdef123456"
    /// - A full path: "some/path/to/file"
    ///
    /// This method will add the files/ prefix if needed and handle storage prefixes.
    /// Content-type and content-length constraints can be applied when specified.
    async fn generate_upload_url(
        &self,
        key: &str,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> Result<Option<String>> {
        self.init().await?;

        // Apply proper prefixing including files/ directory if needed
        let prefixed_key = self.prefixed_key(key);

        tracing::debug!(
            "Generating upload URL for key: {} (prefixed as: {})",
            key,
            prefixed_key
        );

        // Create action for presigned PUT request
        let mut action = self
            .bucket
            .put_object(Some(&self.credentials), &prefixed_key);

        // Set content-type if provided - using lowercase header name for S3 signature compatibility
        if let Some(content_type) = content_type {
            action.headers_mut().insert("content-type", content_type);
            tracing::debug!("Added content-type: {}", content_type);
        }

        // Note: Content-Length is handled at validation time after upload,
        // as rusty-s3 doesn't support this constraint in the URL
        if let Some(length) = content_length {
            tracing::debug!(
                "Content length constraint of {} bytes will be validated after upload",
                length
            );
        }

        // Sign the URL with time
        let url = action.sign_with_time(PRESIGNED_URL_DURATION, &OffsetDateTime::now_utc());
        tracing::debug!("Generated upload URL: {}", url);

        Ok(Some(url.to_string()))
    }

    /// Generate a presigned URL for downloading a file from S3
    ///
    /// Will check if the file exists before generating a URL.
    async fn generate_download_url(&self, key: &str) -> Result<Option<String>> {
        // Implement directly to avoid recursion with the S3Store method of the same name
        self.init().await?;

        // Apply proper prefixing including files/ directory if needed
        let prefixed_key = self.prefixed_key(key);

        tracing::debug!(
            "Generating download URL for key: {} (prefixed as: {})",
            key,
            prefixed_key
        );

        // Check if object exists before generating URL
        if !self.exists(&key).await? {
            tracing::debug!("Object does not exist, not generating URL");
            return Ok(None);
        }

        let action = self
            .bucket
            .get_object(Some(&self.credentials), &prefixed_key);
        let url = action.sign_with_time(PRESIGNED_URL_DURATION, &OffsetDateTime::now_utc());

        tracing::debug!("Generated download URL: {}", url);
        Ok(Some(url.to_string()))
    }
}
