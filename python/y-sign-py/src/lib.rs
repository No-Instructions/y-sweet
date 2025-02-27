use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::time::SystemTime;
use y_sweet_core::{
    api_types::Authorization,
    auth::{Authenticator, AuthError, ExpirationTimeEpochMillis},
};

// Define custom Python exceptions
create_exception!(y_sign_py, YSignError, PyException);
create_exception!(y_sign_py, TokenExpiredError, YSignError);
create_exception!(y_sign_py, InvalidTokenError, YSignError);
create_exception!(y_sign_py, InvalidResourceError, YSignError);
create_exception!(y_sign_py, InvalidSignatureError, YSignError);
create_exception!(y_sign_py, KeyMismatchError, YSignError);

// Convert Rust AuthError to Python exceptions
fn convert_auth_error(err: &AuthError) -> PyErr {
    match err {
        AuthError::InvalidToken => InvalidTokenError::new_err("The token is not a valid format"),
        AuthError::Expired => TokenExpiredError::new_err("The token is expired"),
        AuthError::InvalidResource => {
            InvalidResourceError::new_err("The token is not valid for the requested resource")
        }
        AuthError::InvalidSignature => {
            InvalidSignatureError::new_err("The token signature is invalid")
        }
        AuthError::KeyMismatch => KeyMismatchError::new_err("The key ID did not match"),
    }
}

// Python enum for Authorization
#[pyclass]
#[derive(Clone)]
enum PyAuthorization {
    ReadOnly,
    Full,
}

// Convert from Python enum to Rust enum
impl From<PyAuthorization> for Authorization {
    fn from(auth: PyAuthorization) -> Self {
        match auth {
            PyAuthorization::ReadOnly => Authorization::ReadOnly,
            PyAuthorization::Full => Authorization::Full,
        }
    }
}

// Convert from Rust enum to Python enum
impl From<Authorization> for PyAuthorization {
    fn from(auth: Authorization) -> Self {
        match auth {
            Authorization::ReadOnly => PyAuthorization::ReadOnly,
            Authorization::Full => PyAuthorization::Full,
        }
    }
}

// Main token generator class
#[pyclass]
struct TokenGenerator {
    authenticator: Authenticator,
}

#[pymethods]
impl TokenGenerator {
    #[new]
    fn new(auth_key: &str) -> PyResult<Self> {
        let authenticator = Authenticator::new(auth_key)
            .map_err(|e| InvalidTokenError::new_err(format!("Invalid auth key: {}", e)))?;
        Ok(Self { authenticator })
    }

    // Generate a document token
    fn generate_document_token(
        &self,
        doc_id: &str,
        authorization: PyAuthorization,
        py: Python<'_>,
    ) -> PyResult<PyObject> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                YSignError::new_err(format!("Failed to get current time: {}", e))
            })?
            .as_millis() as u64;
        
        let expiration = ExpirationTimeEpochMillis(
            current_time + (y_sweet_core::auth::DEFAULT_EXPIRATION_SECONDS * 1000),
        );
        
        let auth_rust: Authorization = authorization.into();
        let token = self.authenticator.gen_doc_token(doc_id, auth_rust, expiration);
        
        // Create Python dict to return
        let result = PyDict::new(py);
        result.set_item("docId", doc_id)?;
        result.set_item("token", token)?;
        result.set_item("type", "document")?;
        
        let auth_value = match auth_rust {
            Authorization::ReadOnly => "read-only",
            Authorization::Full => "full",
        };
        result.set_item("authorization", auth_value)?;
        
        Ok(result.into())
    }

    // Generate a file token
    fn generate_file_token(
        &self,
        file_hash: &str,
        authorization: PyAuthorization,
        py: Python<'_>,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> PyResult<PyObject> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                YSignError::new_err(format!("Failed to get current time: {}", e))
            })?
            .as_millis() as u64;
        
        let expiration = ExpirationTimeEpochMillis(
            current_time + (y_sweet_core::auth::DEFAULT_EXPIRATION_SECONDS * 1000),
        );
        
        let auth_rust: Authorization = authorization.into();
        let token = self.authenticator.gen_file_token(file_hash, auth_rust, expiration, content_type, content_length);
        
        // Create Python dict to return
        let result = PyDict::new(py);
        result.set_item("fileHash", file_hash)?;
        result.set_item("token", token)?;
        result.set_item("type", "file")?;
        
        let auth_value = match auth_rust {
            Authorization::ReadOnly => "read-only",
            Authorization::Full => "full",
        };
        result.set_item("authorization", auth_value)?;
        
        // Add content type and length if provided
        if let Some(ct) = content_type {
            result.set_item("contentType", ct)?;
        }
        
        if let Some(cl) = content_length {
            result.set_item("contentLength", cl)?;
        }
        
        Ok(result.into())
    }

    // Generate a server token
    fn generate_server_token(&self) -> PyResult<String> {
        Ok(self.authenticator.server_token())
    }

    // Verify a document token
    fn verify_document_token(&self, token: &str, doc_id: &str) -> PyResult<PyAuthorization> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                YSignError::new_err(format!("Failed to get current time: {}", e))
            })?
            .as_millis() as u64;
        
        match self.authenticator.verify_doc_token(token, doc_id, current_time) {
            Ok(authorization) => Ok(authorization.into()),
            Err(e) => Err(convert_auth_error(&e)),
        }
    }

    // Verify a server token
    fn verify_server_token(&self, token: &str) -> PyResult<bool> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| {
                YSignError::new_err(format!("Failed to get current time: {}", e))
            })?
            .as_millis() as u64;
        
        match self.authenticator.verify_server_token(token, current_time) {
            Ok(()) => Ok(true),
            Err(e) => Err(convert_auth_error(&e)),
        }
    }

    // Decode a token to get its payload (without verification)
    fn decode_token(&self, token: &str, py: Python<'_>) -> PyResult<PyObject> {
        let payload = self.authenticator.decode_token(token)
            .map_err(|e| convert_auth_error(&e))?;
        
        // Create Python dict to return
        let result = PyDict::new(py);
        
        match payload.payload {
            y_sweet_core::auth::Permission::Server => {
                result.set_item("type", "server")?;
            },
            y_sweet_core::auth::Permission::Doc(doc_permission) => {
                result.set_item("type", "document")?;
                result.set_item("docId", doc_permission.doc_id)?;
                
                let auth_value = match doc_permission.authorization {
                    Authorization::ReadOnly => "read-only",
                    Authorization::Full => "full",
                };
                result.set_item("authorization", auth_value)?;
            },
            y_sweet_core::auth::Permission::File(file_permission) => {
                result.set_item("type", "file")?;
                result.set_item("fileHash", file_permission.file_hash)?;
                
                let auth_value = match file_permission.authorization {
                    Authorization::ReadOnly => "read-only",
                    Authorization::Full => "full",
                };
                result.set_item("authorization", auth_value)?;
                
                // Add content type and length if available
                if let Some(content_type) = &file_permission.content_type {
                    result.set_item("contentType", content_type)?;
                }
                
                if let Some(content_length) = file_permission.content_length {
                    result.set_item("contentLength", content_length)?;
                }
            },
        }
        
        // Add expiration if available
        if let Some(expiration) = payload.expiration_millis {
            result.set_item("expiration_millis", expiration.0)?;
        }
        
        Ok(result.into())
    }
    
    // Generate a presigned upload URL for a file
    #[pyo3(signature = (token, endpoint=None, path_style=false))]
    fn generate_presigned_upload_url(
        &self,
        token: &str,
        endpoint: Option<String>,
        path_style: bool,
        py: Python<'_>,
    ) -> PyResult<PyObject> {
        // To implement this, we need to interact with the S3Store, but that would
        // require more of the y-sweet-core to be exposed. For now, we'll
        // recommend using the y-sign CLI directly with the presign subcommand.
        
        let error_msg = "This functionality is not directly supported in the Python bindings. \
                         Please use the YSignTokenGenerator class from the 'y_sign' module \
                         which uses the y-sign CLI binary.";
        
        Err(YSignError::new_err(error_msg))
    }
    
    // Generate a presigned download URL for a file
    #[pyo3(signature = (token, endpoint=None, path_style=false))]
    fn generate_presigned_download_url(
        &self,
        token: &str,
        endpoint: Option<String>,
        path_style: bool,
        py: Python<'_>,
    ) -> PyResult<PyObject> {
        // Same as above, recommend using the y-sign CLI directly
        
        let error_msg = "This functionality is not directly supported in the Python bindings. \
                         Please use the YSignTokenGenerator class from the 'y_sign' module \
                         which uses the y-sign CLI binary.";
        
        Err(YSignError::new_err(error_msg))
    }
}

// Module definition
#[pymodule]
fn y_sign_py(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<TokenGenerator>()?;
    m.add_class::<PyAuthorization>()?;
    
    // Add exceptions
    m.add("YSignError", py.get_type::<YSignError>())?;
    m.add("TokenExpiredError", py.get_type::<TokenExpiredError>())?;
    m.add("InvalidTokenError", py.get_type::<InvalidTokenError>())?;
    m.add("InvalidResourceError", py.get_type::<InvalidResourceError>())?;
    m.add("InvalidSignatureError", py.get_type::<InvalidSignatureError>())?;
    m.add("KeyMismatchError", py.get_type::<KeyMismatchError>())?;
    
    Ok(())
}