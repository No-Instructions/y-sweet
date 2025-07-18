#!/usr/bin/env python3
"""
Example usage of the y_sign module for Y-Sweet token generation and verification.
"""

import os
import sys
import json
from y_sign import YSignTokenGenerator, Authorization, YSignError

def main():
    """
    Demonstrate basic usage of the y_sign module.
    """
    # Get the auth key from environment variable or use a default for demo
    auth_key = os.environ.get("RELAY_SERVER_AUTH", "replace_with_your_auth_key")
    
    # You can specify a custom path to the y-sign binary if needed
    # binary_path = "/path/to/y-sign"
    
    try:
        # Initialize the token generator
        generator = YSignTokenGenerator(auth_key)
        
        # Example document ID and file hash
        doc_id = "example-doc-123"
        file_hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        
        # Generate a document token with full access
        print("Generating document token...")
        doc_token = generator.generate_document_token(doc_id)
        print(f"Document token: {json.dumps(doc_token, indent=2)}")
        
        # Generate a read-only document token
        print("\nGenerating read-only document token...")
        readonly_token = generator.generate_document_token(doc_id, Authorization.READ_ONLY)
        print(f"Read-only token: {json.dumps(readonly_token, indent=2)}")
        
        # Generate a file token
        print("\nGenerating file token...")
        file_token = generator.generate_file_token(file_hash)
        print(f"File token: {json.dumps(file_token, indent=2)}")
        
        # Verify a token
        print("\nVerifying document token...")
        try:
            verification = generator.verify_token(doc_token["token"], doc_id)
            print(f"Verification result: {json.dumps(verification, indent=2)}")
        except YSignError as e:
            print(f"Verification failed: {e}")
        
        # Simple validity check
        is_valid = generator.is_token_valid(doc_token["token"], doc_id)
        print(f"\nIs document token valid? {is_valid}")
        
        # Check an invalid token
        print("\nChecking invalid token...")
        is_valid = generator.is_token_valid("invalid-token", doc_id)
        print(f"Is invalid token valid? {is_valid}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())