#!/usr/bin/env python
# Simple test script to verify y_sign Python bindings

import y_sign
import json
import sys

def main():
    try:
        print("Testing y_sign Python bindings...")
        
        # Create a simple token
        private_key = "test-key"
        doc_id = "test-doc-123"
        
        print(f"Generating document token with key: {private_key}, doc_id: {doc_id}")
        token = y_sign.gen_doc_token(private_key, doc_id, False, 3600)
        print(f"Generated token: {token[:20]}...{token[-20:] if len(token) > 40 else ''}")
        
        # Verify the token
        print("Verifying document token...")
        verification = y_sign.verify_doc_token(private_key, token, doc_id)
        
        # Generate a file token
        print("Generating file token...")
        file_hash = "testfilehash123456789"
        file_token = y_sign.gen_file_token(private_key, file_hash, False, 3600, "text/plain", 1024)
        print(f"Generated file token: {file_token[:20]}...{file_token[-20:] if len(file_token) > 40 else ''}")
        
        # Verify the file token
        print("Verifying file token...")
        file_verification = y_sign.verify_file_token(private_key, file_token, file_hash)
        
        # Check the results
        if verification and file_verification:
            print("\n✅ SUCCESS! y_sign Python bindings are working correctly!")
            print(f"✓ Document token verification: {verification}")
            print(f"✓ File token verification: {file_verification}")
            return 0
        else:
            print("\n❌ ERROR: Token verification failed!")
            print(f"✗ Document token verification: {verification}")
            print(f"✗ File token verification: {file_verification}")
            return 1
            
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return 1

if __name__ == "__main__":
    sys.exit(main())