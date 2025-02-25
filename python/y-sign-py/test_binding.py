import y_sign
import os
import json

# Get the auth key from environment
auth_key = os.environ.get("Y_SWEET_AUTH")
if not auth_key:
    print("Please set Y_SWEET_AUTH environment variable")
    exit(1)

print(f"Testing y_sign module with auth key: {auth_key}")

# Initialize the token generator
generator = y_sign.TokenGenerator(auth_key)

# Generate a document token
doc_id = "test-doc-id"
print(f"\nGenerating document token for {doc_id}")
doc_token = generator.generate_document_token(doc_id, y_sign.PyAuthorization.Full)
print(f"Document token: {json.dumps(doc_token, indent=2)}")

# Generate a read-only document token
print(f"\nGenerating read-only document token for {doc_id}")
readonly_token = generator.generate_document_token(doc_id, y_sign.PyAuthorization.ReadOnly)
print(f"Read-only document token: {json.dumps(readonly_token, indent=2)}")

# Generate a file token
file_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
print(f"\nGenerating file token for {file_hash}")
file_token = generator.generate_file_token(file_hash, y_sign.PyAuthorization.Full)
print(f"File token: {json.dumps(file_token, indent=2)}")

# Generate a server token
print("\nGenerating server token")
server_token = generator.generate_server_token()
print(f"Server token: {server_token}")

# Verify the server token
print("\nVerifying server token")
is_valid = generator.verify_server_token(server_token)
print(f"Server token is valid: {is_valid}")

# Decode the document token
print("\nDecoding document token")
token_payload = generator.decode_token(doc_token["token"])
print(f"Token payload: {json.dumps(token_payload, indent=2)}")

# Decode the file token
print("\nDecoding file token")
file_payload = generator.decode_token(file_token["token"])
print(f"File token payload: {json.dumps(file_payload, indent=2)}")

# Verify the document token
print("\nVerifying document token")
auth_level = generator.verify_document_token(doc_token["token"], doc_id)
print(f"Document token is valid with auth level: {auth_level}")

# Verify the read-only token
print("\nVerifying read-only document token")
readonly_auth_level = generator.verify_document_token(readonly_token["token"], doc_id)
print(f"Read-only token is valid with auth level: {readonly_auth_level}")

print("\nAll tests passed!")