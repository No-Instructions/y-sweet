pub mod s3;

use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Store bucket does not exist. {0}")]
    BucketDoesNotExist(String),
    #[error("Object does not exist. {0}")]
    DoesNotExist(String),
    #[error("Not authorized to access store. {0}")]
    NotAuthorized(String),
    #[error("Error connecting to store. {0}")]
    ConnectionError(String),
    #[error("Unsupported operation. {0}")]
    UnsupportedOperation(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub key: String,
    pub size: u64,
    pub last_modified: u64, // timestamp in milliseconds
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait Store: 'static {
    async fn init(&self) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()>;
    async fn remove(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;

    // Generate presigned URL for uploading file to storage
    async fn generate_upload_url(
        &self,
        _key: &str,
        _content_type: Option<&str>,
        _content_length: Option<u64>,
    ) -> Result<Option<String>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support generating presigned URLs".to_string(),
        ))
    }

    // Generate presigned URL for downloading file from storage
    async fn generate_download_url(&self, _key: &str) -> Result<Option<String>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support generating presigned URLs".to_string(),
        ))
    }

    // List files with a common prefix and return their file info (key, size, last_modified)
    async fn list(&self, _prefix: &str) -> Result<Vec<FileInfo>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support listing files".to_string(),
        ))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait Store: Send + Sync {
    async fn init(&self) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()>;
    async fn remove(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;

    // Generate presigned URL for uploading file to storage
    async fn generate_upload_url(
        &self,
        _key: &str,
        _content_type: Option<&str>,
        _content_length: Option<u64>,
    ) -> Result<Option<String>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support generating presigned URLs".to_string(),
        ))
    }

    // Generate presigned URL for downloading file from storage
    async fn generate_download_url(&self, _key: &str) -> Result<Option<String>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support generating presigned URLs".to_string(),
        ))
    }

    // List files with a common prefix and return their file info (key, size, last_modified)
    async fn list(&self, _prefix: &str) -> Result<Vec<FileInfo>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support listing files".to_string(),
        ))
    }
}
