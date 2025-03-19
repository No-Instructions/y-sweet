#!/usr/bin/env python3
"""
Test script for the y-sign presign functionality.

This script demonstrates how to:
1. Generate a file token using y-sign
2. Generate a presigned URL using that token
3. Upload a file using the presigned URL
4. Verify the upload was successful

Required environment variables:
- Y_SWEET_AUTH - Authentication key for y-sweet
- AWS_ACCESS_KEY_ID - S3 access key ID
- AWS_SECRET_ACCESS_KEY - S3 secret access key
- STORAGE_BUCKET - S3 bucket name (replaces AWS_S3_BUCKET)
- AWS_REGION - S3 region (optional, defaults to us-east-1)
- AWS_ENDPOINT_URL - S3 endpoint URL (optional)
- Y_SWEET_STORE - Storage URL with optional prefix path (optional)

Usage:
    export Y_SWEET_AUTH="your-auth-key"
    export AWS_ACCESS_KEY_ID="your-access-key"
    export AWS_SECRET_ACCESS_KEY="your-secret-key"
    export STORAGE_BUCKET="your-bucket"
    export AWS_REGION="your-region"  # Optional
    export AWS_ENDPOINT_URL="your-endpoint"  # Optional
    export Y_SWEET_STORE="s3://your-bucket/optional-prefix"  # Optional
    ./test_presign.py
"""

import json
import subprocess
import os
import requests
import hashlib
import base64
import re
import sys
import urllib.parse

# Configure detailed logging
DEBUG = True

def log(message, level="INFO"):
    """Log a message with a specified level."""
    if not DEBUG and level == "DEBUG":
        return
    print(f"[{level}] {message}")

def redact_url(url):
    """Redact sensitive parts of a URL while keeping the structure visible."""
    if not url:
        return "None"
    
    # Redact AWS signatures in S3 URLs
    redacted = re.sub(r'(X-Amz-Signature=)[^&]+', r'\1REDACTED', url)
    redacted = re.sub(r'(AWSAccessKeyId=)[^&]+', r'\1REDACTED', redacted)
    redacted = re.sub(r'(Signature=)[^&]+', r'\1REDACTED', redacted)
    
    return redacted

def print_env_vars():
    """Print relevant environment variables (with secrets redacted)."""
    env_vars = {
        "Y_SWEET_AUTH": "REDACTED" if "Y_SWEET_AUTH" in os.environ else "Not set",
        "AWS_ACCESS_KEY_ID": "REDACTED" if "AWS_ACCESS_KEY_ID" in os.environ else "Not set",
        "AWS_SECRET_ACCESS_KEY": "REDACTED" if "AWS_SECRET_ACCESS_KEY" in os.environ else "Not set",
        "STORAGE_BUCKET": os.environ.get("STORAGE_BUCKET", "Not set"),
        "AWS_S3_BUCKET": os.environ.get("AWS_S3_BUCKET", "Not set"),
        "AWS_REGION": os.environ.get("AWS_REGION", "Not set"),
        "AWS_ENDPOINT_URL": os.environ.get("AWS_ENDPOINT_URL", "Not set"),
        "AWS_SESSION_TOKEN": "REDACTED" if "AWS_SESSION_TOKEN" in os.environ else "Not set",
        "AWS_S3_BUCKET_PREFIX": os.environ.get("AWS_S3_BUCKET_PREFIX", "Not set"),
        "AWS_S3_USE_PATH_STYLE": os.environ.get("AWS_S3_USE_PATH_STYLE", "Not set"),
        "Y_SWEET_STORE": os.environ.get("Y_SWEET_STORE", "Not set"),
    }
    
    log("Environment variables:")
    for key, value in env_vars.items():
        log(f"  {key}={value}", "DEBUG")

def run_y_sign(args, stdin_data=None, label=""):
    """Run y-sign with the given arguments and stdin data."""
    cmd = ["./target/debug/y-sign"] + args
    
    log(f"Running command: {' '.join(cmd)}", "DEBUG")
    
    if isinstance(stdin_data, dict):
        stdin_data_str = json.dumps(stdin_data)
        log(f"Input data (JSON): {stdin_data_str}", "DEBUG")
        stdin_data = stdin_data_str.encode('utf-8')
    elif isinstance(stdin_data, str):
        log(f"Input data (string): {stdin_data}", "DEBUG")
        stdin_data = stdin_data.encode('utf-8')
    
    try:
        result = subprocess.run(
            cmd, 
            input=stdin_data, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            check=True
        )
        
        stdout = result.stdout.decode('utf-8')
        stderr = result.stderr.decode('utf-8')
        
        if stderr:
            log(f"STDERR from {label}: {stderr}", "DEBUG")
        
        log(f"STDOUT from {label}: {stdout}", "DEBUG")
        
        result_json = json.loads(stdout)
        
        # If we have a URL in the result, redact it for logging
        if "url" in result_json:
            log_result = result_json.copy()
            log_result["url"] = redact_url(log_result["url"])
            log(f"Parsed result: {json.dumps(log_result, indent=2)}", "DEBUG")
        else:
            log(f"Parsed result: {json.dumps(result_json, indent=2)}", "DEBUG")
        
        return result_json
        
    except subprocess.CalledProcessError as e:
        log(f"Command failed with exit code {e.returncode}", "ERROR")
        log(f"STDOUT: {e.stdout.decode('utf-8')}", "ERROR")
        log(f"STDERR: {e.stderr.decode('utf-8')}", "ERROR")
        raise
    except json.JSONDecodeError as e:
        log(f"Failed to parse JSON output: {e}", "ERROR")
        log(f"Raw output: {result.stdout.decode('utf-8')}", "ERROR")
        raise

def calculate_hash(content):
    """Calculate SHA-256 hash of content and encode it as base64."""
    hasher = hashlib.sha256()
    if isinstance(content, str):
        hasher.update(content.encode('utf-8'))
    else:
        hasher.update(content)
    
    return base64.b64encode(hasher.digest()).decode('utf-8')

def pretty_print_request(req):
    """
    Print a request in a readable format.
    """
    log(f"Request: {req.method} {redact_url(req.url)}", "DEBUG")
    log("Headers:", "DEBUG")
    for header, value in req.headers.items():
        log(f"  {header}: {value}", "DEBUG")
    
    if req.body:
        log(f"Body: {req.body if len(req.body) < 100 else req.body[:100] + '... [truncated]'}", "DEBUG")

def analyze_token(token):
    """Try to analyze the token structure to debug issues."""
    log("---- Analyzing Token Structure ----")
    
    # Check if token is valid
    if not token:
        log("Token is empty or None", "ERROR")
        return
    
    # Basic token stats
    log(f"Token length: {len(token)} characters")
    log(f"Token prefix: {token[:20]}...")
    log(f"Token suffix: ...{token[-20:]}")
    
    # Try to decode if it looks like base64
    try:
        # Check if it's base64 encoded
        base64_part = token
        if '.' in token:
            # Handle format with key_id.token
            log("Token appears to have a key_id prefix", "DEBUG")
            parts = token.split('.')
            log(f"Token parts: {len(parts)}", "DEBUG")
            base64_part = parts[1] if len(parts) > 1 else parts[0]
        
        # Try various padding options for base64
        for padding in ['', '=', '==', '===']:
            try:
                decoded = base64.b64decode(base64_part + padding, validate=True)
                log(f"Successfully decoded with padding: '{padding}'", "DEBUG")
                log(f"Decoded length: {len(decoded)} bytes", "DEBUG")
                
                # Check if it's binary data (likely serialized)
                if any(b < 32 and b != 10 and b != 13 and b != 9 for b in decoded):
                    log("Decoded content appears to be binary data (likely serialized)", "DEBUG")
                else:
                    # Might be JSON or text
                    log(f"Decoded as text: {decoded.decode('utf-8', errors='replace')[:100]}...", "DEBUG")
                    
                    # Try to parse as JSON
                    try:
                        json_data = json.loads(decoded.decode('utf-8'))
                        log(f"Successfully parsed as JSON: {json.dumps(json_data, indent=2)[:500]}...", "DEBUG")
                    except json.JSONDecodeError:
                        log("Not valid JSON", "DEBUG")
                
                break
            except Exception as e:
                if padding == '===':
                    log(f"Failed to decode token as base64: {str(e)}", "DEBUG")
    except Exception as e:
        log(f"Error analyzing token: {str(e)}", "ERROR")

def main():
    # Print environment variables for debugging
    log("Starting test_presign.py script")
    print_env_vars()
    
    # Check if Y_SWEET_STORE is set and has a prefix
    y_sweet_store = os.environ.get("Y_SWEET_STORE", "")
    if y_sweet_store:
        log(f"Y_SWEET_STORE is set to: {y_sweet_store}")
        # Parse the URL to extract prefix
        try:
            # Parse s3:// URL format
            if y_sweet_store.startswith("s3://"):
                parts = y_sweet_store[5:].split('/', 1)
                bucket = parts[0]
                prefix = parts[1] if len(parts) > 1 else ""
                log(f"Extracted bucket: {bucket}, prefix: {prefix}")
                
                # IMPORTANT: Y-SIGN USES AWS_S3_BUCKET_PREFIX NOT Y_SWEET_STORE
                # Need to set AWS_S3_BUCKET_PREFIX for y-sign to use the prefix
                if prefix:
                    os.environ["AWS_S3_BUCKET_PREFIX"] = prefix
                    log(f"Setting AWS_S3_BUCKET_PREFIX={prefix} for y-sign to use")
                    
                    log(f"Testing with bucket prefix: {prefix}")
                    log(f"NOTE: There is a known issue with trailing slashes in bucket prefixes.")
                    if prefix.endswith('/'):
                        log(f"WARNING: Your prefix ends with a slash, which may cause double slashes in URLs: '{prefix}'", "WARNING")
                        log(f"This can result in the pattern '{prefix}/files/' becoming '{prefix}//files/' in paths")
        except Exception as e:
            log(f"Error parsing Y_SWEET_STORE: {str(e)}", "ERROR")
    
    # Create a test file
    test_content = "Hello, world! This is a test file."
    file_hash = calculate_hash(test_content)
    
    log(f"Created test content with hash: {file_hash}")
    
    # Step 1: Generate a file token
    token_data = {
        "fileHash": file_hash,
        "type": "file",
        "authorization": "full",
        "contentType": "text/plain",
        "contentLength": len(test_content)
    }
    
    log("Step 1: Generating file token")
    token_result = run_y_sign(
        ["sign", "--auth", os.environ.get("Y_SWEET_AUTH", "")], 
        token_data,
        "token generation"
    )
    
    token = token_result.get('token', '')
    log(f"Generated token: {token[:20]}...{token[-20:] if len(token) > 40 else ''}")
    
    # Analyze token structure
    analyze_token(token)
    
    # Step 2: Generate a presigned upload URL using the token
    log("Step 2: Generating presigned upload URL")
    upload_result = run_y_sign(
        ["presign", "upload-url", "--auth", os.environ.get("Y_SWEET_AUTH", "")], 
        token,
        "upload URL generation"
    )
    
    if "url" not in upload_result:
        log(f"Failed to generate presigned upload URL: {upload_result}", "ERROR")
        return
    
    upload_url = upload_result["url"]
    log(f"Generated upload URL (redacted): {redact_url(upload_url)}")
    
    # Detailed log of URL components for debugging
    log("URL components breakdown:", "DEBUG")
    url_parts = urllib.parse.urlparse(upload_url)
    log(f"  Scheme: {url_parts.scheme}", "DEBUG")
    log(f"  Netloc: {url_parts.netloc}", "DEBUG")
    log(f"  Path: {url_parts.path}", "DEBUG")
    log(f"  Params: {url_parts.params}", "DEBUG")
    log(f"  Query (redacted): {redact_url('?' + url_parts.query) if url_parts.query else 'None'}", "DEBUG")
    log(f"  Fragment: {url_parts.fragment}", "DEBUG")
    
    # Extract query parameters for debugging
    query_params = urllib.parse.parse_qs(url_parts.query)
    log("URL query parameters:", "DEBUG")
    for key, values in query_params.items():
        # Redact signature
        if key == 'X-Amz-Signature':
            log(f"  {key}: REDACTED", "DEBUG")
        else:
            log(f"  {key}: {values[0]}", "DEBUG")
    
    # Check if the URL path contains the expected prefix if Y_SWEET_STORE was set with a prefix
    path_match = True
    if y_sweet_store and '/' in y_sweet_store[5:]:
        _, prefix = y_sweet_store[5:].split('/', 1)
        if prefix:
            # Get prefix with and without trailing slash
            prefix_with_slash = prefix if prefix.endswith('/') else f"{prefix}/"
            prefix_no_slash = prefix.rstrip('/')
            
            # Look for correct path pattern with prefix
            expected_pattern = f"{prefix_no_slash}/files/"
            
            # Debug information to help diagnose the issue
            log(f"DEBUG PATH INFO:", "DEBUG")
            log(f"- URL path: {url_parts.path}", "DEBUG")
            log(f"- Expected pattern: {expected_pattern}", "DEBUG")
            log(f"- File hash: {file_hash}", "DEBUG")
            log(f"- Complete URL (redacted): {redact_url(upload_url)}", "DEBUG")
            log(f"- Environment - Y_SWEET_STORE: {y_sweet_store}", "DEBUG")
            
            # Proceed with the actual check
            if expected_pattern in url_parts.path:
                log(f"SUCCESS: URL correctly includes prefix path '{expected_pattern}' in: {url_parts.path}")
                path_match = True
            else:
                # Also check if the path has "files/" without the prefix - this is still wrong
                if "/files/" in url_parts.path or f"/{file_hash}" in url_parts.path:
                    log(f"ERROR: URL contains 'files/' but missing prefix '{prefix}'. Path: {url_parts.path}", "ERROR")
                    log(f"The bucket prefix '{prefix}' is not being correctly applied to the URL. Check Y_SWEET_STORE setting.", "ERROR")
                    # Continue execution for debug purpose instead of exiting
                    path_match = False  # Mark as failed but continue for debugging
                else:
                    log(f"ERROR: URL does not contain expected prefix path '{expected_pattern}' in: {url_parts.path}", "ERROR")
                    log(f"The bucket prefix '{prefix}' is not being correctly applied to the URL. Check Y_SWEET_STORE setting.", "ERROR")
                    # Continue execution for debug purpose instead of exiting
                    path_match = False  # Mark as failed but continue for debugging
    
    # Step 3: Upload the file using the presigned URL
    log("Step 3: Uploading file using presigned URL")
    headers = {"Content-Type": "text/plain"}
    
    # Prepare the request
    req = requests.Request('PUT', upload_url, data=test_content, headers=headers)
    prepared_req = req.prepare()
    
    # Log the request details
    pretty_print_request(prepared_req)
    
    # Send the request
    with requests.Session() as s:
        upload_response = s.send(prepared_req)
    
    log(f"Upload response status code: {upload_response.status_code}")
    log(f"Upload response headers: {dict(upload_response.headers)}", "DEBUG")
    
    if upload_response.status_code == 200:
        log(f"Successfully uploaded file! Status code: {upload_response.status_code}")
        upload_successful = True
    else:
        log(f"Failed to upload. Status code: {upload_response.status_code}", "ERROR")
        log(f"Response: {upload_response.text}", "ERROR")
        log(f"Response headers: {dict(upload_response.headers)}", "ERROR")
        upload_successful = False
    
    # Step 3.1: Test uploading with the wrong content size
    log("Step 3.1: Testing upload with wrong content size")
    wrong_size_content = test_content + " Extra content to change the size."
    
    req = requests.Request('PUT', upload_url, data=wrong_size_content, headers=headers)
    prepared_req = req.prepare()
    
    log(f"Attempting upload with wrong size: {len(wrong_size_content)} bytes (expected {len(test_content)} bytes)")
    pretty_print_request(prepared_req)
    
    with requests.Session() as s:
        wrong_size_response = s.send(prepared_req)
    
    log(f"Wrong size upload response status code: {wrong_size_response.status_code}")
    if wrong_size_response.status_code >= 400:
        log(f"✅ Successfully rejected upload with wrong size: {wrong_size_response.status_code}")
        log(f"Response: {wrong_size_response.text[:200]}", "DEBUG")
    else:
        log(f"❌ FAILED: Upload with wrong size was accepted! Status code: {wrong_size_response.status_code}", "ERROR")
        log(f"Response: {wrong_size_response.text[:200]}", "ERROR")
        wrong_size_test_failed = True
    
    # Step 3.2: Test uploading with the wrong filename
    # For this test, we'll manipulate the upload URL to change the filename/path
    log("Step 3.2: Testing upload with wrong filename")
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(upload_url)
    path_parts = parsed_url.path.split('/')
    
    # Change the filename part (usually the last part is the hash)
    if len(path_parts) > 0:
        # Replace the last part with a different hash
        wrong_hash = "wronghash" + file_hash[9:] 
        path_parts[-1] = wrong_hash
        wrong_path = '/'.join(path_parts)
        
        # Rebuild the URL with the wrong path
        wrong_url_parts = list(parsed_url)
        wrong_url_parts[2] = wrong_path  # Replace path
        wrong_file_url = urllib.parse.urlunparse(wrong_url_parts)
        
        log(f"Original path: {parsed_url.path}")
        log(f"Modified path: {wrong_path}")
        log(f"Attempting upload to wrong path URL (redacted): {redact_url(wrong_file_url)}")
        
        req = requests.Request('PUT', wrong_file_url, data=test_content, headers=headers)
        prepared_req = req.prepare()
        
        pretty_print_request(prepared_req)
        
        with requests.Session() as s:
            wrong_file_response = s.send(prepared_req)
        
        log(f"Wrong filename upload response status code: {wrong_file_response.status_code}")
        if wrong_file_response.status_code >= 400:
            log(f"✅ Successfully rejected upload with wrong filename: {wrong_file_response.status_code}")
            log(f"Response: {wrong_file_response.text[:200]}", "DEBUG")
        else:
            log(f"❌ FAILED: Upload with wrong filename was accepted! Status code: {wrong_file_response.status_code}", "ERROR")
            log(f"Response: {wrong_file_response.text[:200]}", "ERROR")
            wrong_filename_test_failed = True
    else:
        log("Could not parse URL path to create wrong filename test", "ERROR")
        wrong_filename_test_failed = True
    
    # Step 4: Generate a download URL for verification
    log("Step 4: Generating presigned download URL")
    download_result = run_y_sign(
        ["presign", "download-url", "--auth", os.environ.get("Y_SWEET_AUTH", "")], 
        token,
        "download URL generation"
    )
    
    if "url" not in download_result:
        log(f"Failed to generate download URL: {download_result}", "ERROR")
        return
    
    download_url = download_result["url"]
    log(f"Generated download URL (redacted): {redact_url(download_url)}")
    
    # Check if the download URL path contains the expected prefix
    download_url_parts = urllib.parse.urlparse(download_url)
    if y_sweet_store and '/' in y_sweet_store[5:]:
        _, prefix = y_sweet_store[5:].split('/', 1)
        if prefix:
            # Get prefix with and without trailing slash
            prefix_with_slash = prefix if prefix.endswith('/') else f"{prefix}/"
            prefix_no_slash = prefix.rstrip('/')
            
            # Look for correct path pattern with prefix
            expected_pattern = f"{prefix_no_slash}/files/"
            
            # Debug information to help diagnose the issue
            log(f"DEBUG DOWNLOAD PATH INFO:", "DEBUG")
            log(f"- Download URL path: {download_url_parts.path}", "DEBUG")
            log(f"- Expected pattern: {expected_pattern}", "DEBUG")
            log(f"- File hash: {file_hash}", "DEBUG")
            log(f"- Complete URL (redacted): {redact_url(download_url)}", "DEBUG")
            
            # Proceed with the actual check
            if expected_pattern in download_url_parts.path:
                log(f"SUCCESS: Download URL correctly includes prefix path '{expected_pattern}' in: {download_url_parts.path}")
                path_match = True
            else:
                # Also check if the path has "files/" without the prefix - this is still wrong
                if "/files/" in download_url_parts.path or f"/{file_hash}" in download_url_parts.path:
                    log(f"ERROR: Download URL contains 'files/' but missing prefix '{prefix}'. Path: {download_url_parts.path}", "ERROR")
                    log(f"The bucket prefix '{prefix}' is not being correctly applied to the URL. Check Y_SWEET_STORE setting.", "ERROR")
                    # Continue execution for debug purpose instead of exiting
                    path_match = False  # Mark as failed but continue for debugging
                else:
                    log(f"ERROR: Download URL does not contain expected prefix path '{expected_pattern}' in: {download_url_parts.path}", "ERROR")
                    log(f"The bucket prefix '{prefix}' is not being correctly applied to the URL. Check Y_SWEET_STORE setting.", "ERROR")
                    # Continue execution for debug purpose instead of exiting
                    path_match = False  # Mark as failed but continue for debugging
    
    # Step 5: Verify file download
    log("Step 5: Verifying file download")
    
    # Prepare the request
    req = requests.Request('GET', download_url)
    prepared_req = req.prepare()
    
    # Log the request details
    pretty_print_request(prepared_req)
    
    # Send the request
    with requests.Session() as s:
        download_response = s.send(prepared_req)
    
    log(f"Download response status code: {download_response.status_code}")
    
    if download_response.status_code == 200:
        content = download_response.text
        content_hash = calculate_hash(content)
        log(f"Downloaded content hash: {content_hash}")
        
        if content == test_content:
            log("Successfully verified file content!")
            download_successful = True
        else:
            log(f"File content doesn't match!", "ERROR")
            log(f"Expected: {test_content}", "ERROR")
            log(f"Got: {content[:100]}{' ... [truncated]' if len(content) > 100 else ''}", "ERROR")
            download_successful = False
    else:
        log(f"Failed to download file. Status code: {download_response.status_code}", "ERROR")
        log(f"Response: {download_response.text}", "ERROR")
        log(f"Response headers: {dict(download_response.headers)}", "ERROR")
        download_successful = False
    
    # Check if all paths were valid for prefix
    prefix_test_passed = True
    if y_sweet_store and '/' in y_sweet_store[5:]:
        prefix_test_passed = path_match
    
    # Check if wrong size and wrong filename tests were correctly rejected
    wrong_size_test_passed = not wrong_size_test_failed if 'wrong_size_test_failed' in locals() else True
    wrong_filename_test_passed = not wrong_filename_test_failed if 'wrong_filename_test_failed' in locals() else True

    # Overall result
    if upload_successful and download_successful and wrong_size_test_passed and wrong_filename_test_passed:
        log("Upload/download test completed successfully!")
        
        if y_sweet_store and '/' in y_sweet_store[5:]:
            if prefix_test_passed:
                log("✅ Prefix test passed: URLs correctly include the bucket prefix")
            else:
                log("❌ Prefix test FAILED: URLs do not correctly include the bucket prefix", "ERROR")
                sys.exit(1)
                
        if wrong_size_test_passed:
            log("✅ Wrong size test passed: Upload with incorrect size was rejected")
        else:
            log("❌ Wrong size test FAILED: Upload with incorrect size was accepted", "ERROR")
            
        if wrong_filename_test_passed:
            log("✅ Wrong filename test passed: Upload with incorrect filename was rejected")
        else:
            log("❌ Wrong filename test FAILED: Upload with incorrect filename was accepted", "ERROR")
    else:
        log("Test completed with errors.", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"Test failed with exception: {str(e)}", "ERROR")
        import traceback
        log(traceback.format_exc(), "ERROR")
        sys.exit(1)
