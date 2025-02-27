# Y-Sign Python Bindings

Python bindings for the `y-sign` Rust binary, which provides token generation and verification for Y-Sweet.

## Installation

First, ensure the Rust `y-sign` binary is installed and accessible in your PATH.

Then install the Python package:

```bash
# From the root of the y-sweet repo
pip install -e python
```

## Usage

```python
from y_sign import YSignTokenGenerator, Authorization

# Initialize with your Y-Sweet authentication key
auth_key = "your-y-sweet-auth-key"  # Get this from your Y-Sweet configuration
generator = YSignTokenGenerator(auth_key)

# Generate a document token
doc_token = generator.generate_document_token("my-document-id")
print(f"Document token: {doc_token['token']}")

# Generate a read-only document token
readonly_token = generator.generate_document_token(
    "my-document-id", 
    authorization=Authorization.READ_ONLY
)

# Generate a file token
file_token = generator.generate_file_token("file-hash-value")

# Verify a token
try:
    verification = generator.verify_token(doc_token["token"], "my-document-id")
    print(f"Token is valid: {verification['verification']['valid']}")
except Exception as e:
    print(f"Token verification failed: {e}")

# Simple validity check
is_valid = generator.is_token_valid(doc_token["token"], "my-document-id")
print(f"Token is valid: {is_valid}")
```

## API Reference

### `YSignTokenGenerator`

The main class for generating and verifying Y-Sweet tokens.

#### Constructor

```python
YSignTokenGenerator(auth_key, binary_path=None)
```

- `auth_key`: The Y-Sweet authentication key
- `binary_path`: Optional path to the y-sign binary. If not provided, the binary will be searched in the PATH.

#### Methods

##### `generate_document_token(doc_id, authorization=Authorization.FULL)`

Generate a token for document access.

- `doc_id`: The document ID to generate a token for
- `authorization`: The authorization level (Authorization.READ_ONLY or Authorization.FULL)

Returns a dictionary containing the token information.

##### `generate_file_token(file_hash, authorization=Authorization.FULL, content_type=None, content_length=None)`

Generate a token for file access.

- `file_hash`: The file hash to generate a token for
- `authorization`: The authorization level (Authorization.READ_ONLY or Authorization.FULL)
- `content_type`: Optional content type for the file (e.g., "text/plain")
- `content_length`: Optional content length in bytes for the file

Returns a dictionary containing the token information.

##### `verify_token(token, resource_id=None)`

Verify a token and return information about it.

- `token`: The token to verify
- `resource_id`: Optional document ID or file hash to verify against

Returns a dictionary containing verification results.

##### `is_token_valid(token, resource_id=None)`

Check if a token is valid.

- `token`: The token to verify
- `resource_id`: Optional document ID or file hash to verify against

Returns a boolean indicating whether the token is valid.

##### `generate_presigned_upload_url(token, endpoint=None, path_style=False)`

Generate a presigned URL for uploading a file.

- `token`: The file token to use
- `endpoint`: Optional S3 endpoint URL
- `path_style`: Whether to use path-style S3 URLs (default: False)

Returns a dictionary containing the presigned URL and metadata.

##### `generate_presigned_download_url(token, endpoint=None, path_style=False)`

Generate a presigned URL for downloading a file.

- `token`: The file token to use
- `endpoint`: Optional S3 endpoint URL
- `path_style`: Whether to use path-style S3 URLs (default: False)

Returns a dictionary containing the presigned URL and metadata.

### Enums

#### `Authorization`

Enum for authorization levels:

- `Authorization.READ_ONLY`: Read-only access
- `Authorization.FULL`: Full access

### Exceptions

#### `YSignError`

Base exception for all y-sign related errors.

#### `YSignBinaryError`

Exception raised when the y-sign binary encounters an error.

#### `YSignInvalidTokenError`

Exception raised when a token is invalid.