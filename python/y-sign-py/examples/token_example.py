#!/usr/bin/env python3
"""
Example usage of the y_sign module using the native Python bindings.
"""

import os
import sys
import json
from y_sign import TokenGenerator, PyAuthorization, YSignError

def main():
    """
    Demonstrate basic usage of the y_sign module with native Python bindings.
    """
    # Get the auth key from environment variable or use a default for demo
    auth_key = os.environ.get("Y_SWEET_AUTH", "replace_with_your_auth_key")
    
    try:
        # Initialize the token generator
        generator = TokenGenerator(auth_key)
        
        # Example document ID and file hash
        doc_id = "example-doc-123"
        file_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        
        # Generate a document token with full access
        print("Generating document token...")
        doc_token = generator.generate_document_token(doc_id, PyAuthorization.Full)
        print(f"Document token: {json.dumps(doc_token, indent=2)}")
        
        # Generate a read-only document token
        print("\nGenerating read-only document token...")
        readonly_token = generator.generate_document_token(doc_id, PyAuthorization.ReadOnly)
        print(f"Read-only token: {json.dumps(readonly_token, indent=2)}")
        
        # Generate a file token
        print("\nGenerating file token...")
        file_token = generator.generate_file_token(
            file_hash, 
            PyAuthorization.Full,
            content_type="text/plain",
            content_length=len(file_hash)
        )
        print(f"File token: {json.dumps(file_token, indent=2)}")
        
        # Generate a server token
        print("\nGenerating server token...")
        server_token = generator.generate_server_token()
        print(f"Server token: {server_token}")
        
        # Verify the document token
        print("\nVerifying document token...")
        try:
            auth_level = generator.verify_document_token(doc_token["token"], doc_id)
            print(f"Token is valid with authorization level: {auth_level}")
        except YSignError as e:
            print(f"Token verification failed: {e}")
        
        # Verify the server token
        print("\nVerifying server token...")
        try:
            is_valid = generator.verify_server_token(server_token)
            print(f"Server token is valid: {is_valid}")
        except YSignError as e:
            print(f"Server token verification failed: {e}")
        
        # Decode token (without verification)
        print("\nDecoding document token...")
        payload = generator.decode_token(doc_token["token"])
        print(f"Token payload: {json.dumps(payload, indent=2)}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())