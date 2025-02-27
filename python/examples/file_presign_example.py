#!/usr/bin/env python3
"""
Example usage of the file presign functionality in y_sign module.

This example demonstrates how to:
1. Generate a file token with content type and size constraints
2. Create a presigned upload URL
3. Create a presigned download URL
"""

import os
import sys
import json
import hashlib
import base64
import requests
from y_sign import YSignTokenGenerator, Authorization, YSignError

def calculate_hash(content):
    """Calculate SHA-256 hash of content and encode it as base64."""
    hasher = hashlib.sha256()
    if isinstance(content, str):
        hasher.update(content.encode('utf-8'))
    else:
        hasher.update(content)
    
    return base64.b64encode(hasher.digest()).decode('utf-8')

def main():
    """
    Demonstrate file presign functionality of the y_sign module.
    """
    # Get the auth key from environment variable
    auth_key = os.environ.get("Y_SWEET_AUTH")
    if not auth_key:
        print("Error: Y_SWEET_AUTH environment variable is required.", file=sys.stderr)
        return 1
    
    # Check if S3 environment variables are set
    if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
        print("Warning: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY should be set for S3 operations.")
    
    if not os.environ.get("STORAGE_BUCKET") and not os.environ.get("Y_SWEET_STORE"):
        print("Warning: STORAGE_BUCKET or Y_SWEET_STORE should be set for S3 operations.")
    
    try:
        # Initialize the token generator
        generator = YSignTokenGenerator(auth_key)
        
        # Create test content
        test_content = "This is a test file for Y-Sweet file presign functionality."
        content_type = "text/plain"
        content_length = len(test_content)
        
        # Calculate the file hash
        file_hash = calculate_hash(test_content)
        print(f"File hash: {file_hash}")
        
        # Generate a file token with content constraints
        print("\nGenerating file token with content type and length constraints...")
        file_token = generator.generate_file_token(
            file_hash,
            Authorization.FULL,
            content_type=content_type,
            content_length=content_length
        )
        print(f"File token: {json.dumps(file_token, indent=2)}")
        
        # Generate a presigned upload URL
        print("\nGenerating presigned upload URL...")
        try:
            upload_result = generator.generate_presigned_upload_url(file_token["token"])
            print(f"Upload URL result: {json.dumps(upload_result, indent=2)}")
            
            # Upload the file if we have a URL
            if "url" in upload_result:
                upload_url = upload_result["url"]
                print("\nUploading file using presigned URL...")
                
                headers = {"Content-Type": content_type}
                response = requests.put(upload_url, data=test_content, headers=headers)
                
                if response.status_code == 200:
                    print(f"Upload successful! Status code: {response.status_code}")
                    
                    # Now get a download URL
                    print("\nGenerating presigned download URL...")
                    download_result = generator.generate_presigned_download_url(file_token["token"])
                    print(f"Download URL result: {json.dumps(download_result, indent=2)}")
                    
                    if "url" in download_result:
                        download_url = download_result["url"]
                        print("\nDownloading file using presigned URL...")
                        
                        download_response = requests.get(download_url)
                        if download_response.status_code == 200:
                            print(f"Download successful! Status code: {download_response.status_code}")
                            print(f"Downloaded content: {download_response.text}")
                            
                            # Verify the content
                            if download_response.text == test_content:
                                print("\nContent verification successful!")
                            else:
                                print("\nContent verification failed!", file=sys.stderr)
                        else:
                            print(f"Download failed. Status code: {download_response.status_code}", file=sys.stderr)
                            print(f"Response: {download_response.text}", file=sys.stderr)
                    else:
                        print("Failed to generate download URL", file=sys.stderr)
                else:
                    print(f"Upload failed. Status code: {response.status_code}", file=sys.stderr)
                    print(f"Response: {response.text}", file=sys.stderr)
            else:
                print("Failed to generate upload URL", file=sys.stderr)
        except YSignError as e:
            print(f"Error generating presigned URL: {e}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())