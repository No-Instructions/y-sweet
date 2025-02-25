# Y-Sign Python Bindings

Native Python bindings for Y-Sweet's token generation and verification functionality.

This package provides Python bindings to the Rust library used by the `y-sign` command-line tool. It allows you to generate and verify tokens for Y-Sweet documents and files directly from Python, with the full performance of the native Rust implementation.

## Installation

```bash
pip install y-sign
```

## Usage

```python
from y_sign import TokenGenerator, PyAuthorization

# Initialize with your Y-Sweet authentication key
auth_key = "your-y-sweet-auth-key" 
generator = TokenGenerator(auth_key)

# Generate a document token with full access
doc_token = generator.generate_document_token("my-document-id", PyAuthorization.Full)
print(f"Document token: {doc_token['token']}")

# Generate a read-only document token
readonly_token = generator.generate_document_token(
    "my-document-id", 
    PyAuthorization.ReadOnly
)

# Generate a file token
file_token = generator.generate_file_token("file-hash-value", PyAuthorization.Full)

# Verify a document token
try:
    auth_level = generator.verify_document_token(doc_token["token"], "my-document-id")
    print(f"Token authorization level: {auth_level}")
except Exception as e:
    print(f"Token verification failed: {e}")

# Generate a server token
server_token = generator.generate_server_token()

# Verify a server token
try:
    is_valid = generator.verify_server_token(server_token)
    print(f"Server token is valid: {is_valid}")
except Exception as e:
    print(f"Server token verification failed: {e}")

# Decode a token to inspect its payload
token_payload = generator.decode_token(doc_token["token"])
print(f"Token payload: {token_payload}")
```

## API Reference

### `TokenGenerator`

The main class for generating and verifying Y-Sweet tokens.

#### Constructor

```python
TokenGenerator(auth_key)
```

- `auth_key`: The Y-Sweet authentication key

#### Methods

##### `generate_document_token(doc_id, authorization)`

Generate a token for document access.

- `doc_id`: The document ID to generate a token for
- `authorization`: The authorization level (`PyAuthorization.ReadOnly` or `PyAuthorization.Full`)

Returns a dictionary containing the token information.

##### `generate_file_token(file_hash, authorization)`

Generate a token for file access.

- `file_hash`: The file hash to generate a token for
- `authorization`: The authorization level (`PyAuthorization.ReadOnly` or `PyAuthorization.Full`)

Returns a dictionary containing the token information.

##### `generate_server_token()`

Generate a server token.

Returns the token as a string.

##### `verify_document_token(token, doc_id)`

Verify a document token.

- `token`: The token to verify
- `doc_id`: The document ID to verify against

Returns the authorization level if valid, raises an exception if invalid.

##### `verify_server_token(token)`

Verify a server token.

- `token`: The token to verify

Returns `True` if valid, raises an exception if invalid.

##### `decode_token(token)`

Decode a token to inspect its payload without verifying it.

- `token`: The token to decode

Returns a dictionary with the token payload.

### Enums

#### `PyAuthorization`

Enum for authorization levels:

- `PyAuthorization.ReadOnly`: Read-only access
- `PyAuthorization.Full`: Full access

### Exceptions

- `YSignError`: Base exception for all y-sign related errors
- `TokenExpiredError`: Exception for expired tokens
- `InvalidTokenError`: Exception for invalid token format
- `InvalidResourceError`: Exception for tokens used with the wrong resource
- `InvalidSignatureError`: Exception for tokens with invalid signatures
- `KeyMismatchError`: Exception for key ID mismatches

## Development

This package is built using PyO3 and Maturin to create Python bindings for the Rust code in the `y-sweet-core` crate.

To build the project:

```bash
cd python/y-sign-py
maturin develop
```

To build a release version:

```bash
maturin build --release
```