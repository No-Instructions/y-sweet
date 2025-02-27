"""
The token generator module for y-sign.

This module provides Python bindings to interact with the y-sign Rust binary
for generating and verifying authentication tokens for Y-Sweet documents and files.
"""

import enum
import json
import os
import subprocess
import tempfile
from typing import Dict, List, Optional, Union, Any

from .error import YSignError, YSignBinaryError, YSignInvalidTokenError


class Authorization(enum.Enum):
    """
    Authorization levels for tokens.
    """
    READ_ONLY = "read"
    FULL = "full"


class YSignTokenGenerator:
    """
    Generator for Y-Sweet authentication tokens.
    """

    def __init__(self, auth_key: str, binary_path: Optional[str] = None):
        """
        Initialize a token generator with the given authentication key.

        Args:
            auth_key: The authentication key to use for signing tokens
            binary_path: Optional path to the y-sign binary. If not provided,
                         will look for 'y-sign' in PATH.
        """
        self.auth_key = auth_key
        self.binary_path = binary_path or "y-sign"

    def _run_y_sign(self, args: List[str], input_data: Optional[Union[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Run the y-sign binary with the given arguments and input data.

        Args:
            args: The arguments to pass to the y-sign binary
            input_data: Optional input data to pass to stdin. If a dict, it will be
                        converted to JSON.

        Returns:
            The JSON-decoded output from the y-sign binary

        Raises:
            YSignBinaryError: If the y-sign binary returns a non-zero exit code
            YSignError: If there's an error processing the output
        """
        # Add auth key if not provided in args
        if "--auth" not in args:
            args.extend(["--auth", self.auth_key])

        cmd = [self.binary_path] + args
        
        # Prepare input data
        stdin_data = None
        if input_data is not None:
            if isinstance(input_data, dict):
                stdin_data = json.dumps(input_data).encode('utf-8')
            else:
                stdin_data = str(input_data).encode('utf-8')

        try:
            # Run the command
            result = subprocess.run(
                cmd,
                input=stdin_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            
            # Process the output
            stdout = result.stdout.decode('utf-8').strip()
            try:
                return json.loads(stdout)
            except json.JSONDecodeError as e:
                raise YSignError(f"Failed to parse y-sign output as JSON: {e}. Output: {stdout}")
                
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode('utf-8').strip()
            raise YSignBinaryError(f"y-sign binary failed", e.returncode, stderr)
        
    def generate_document_token(self, doc_id: str, authorization: Authorization = Authorization.FULL) -> Dict[str, Any]:
        """
        Generate a token for accessing a document.

        Args:
            doc_id: The document ID to generate a token for
            authorization: The level of access to grant (default: FULL)

        Returns:
            A dictionary containing the token and metadata
        """
        data = {
            "docId": doc_id,
            "type": "document",
            "authorization": authorization.value
        }
        
        return self._run_y_sign(["sign"], data)
    
    def generate_file_token(
        self, 
        file_hash: str, 
        authorization: Authorization = Authorization.FULL,
        content_type: Optional[str] = None,
        content_length: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate a token for accessing a file.

        Args:
            file_hash: The file hash to generate a token for
            authorization: The level of access to grant (default: FULL)
            content_type: Optional content type for the file
            content_length: Optional content length for the file

        Returns:
            A dictionary containing the token and metadata
        """
        data = {
            "fileHash": file_hash,
            "type": "file",
            "authorization": authorization.value
        }
        
        # Add content type and length if provided
        if content_type is not None:
            data["contentType"] = content_type
        
        if content_length is not None:
            data["contentLength"] = content_length
        
        return self._run_y_sign(["sign"], data)
    
    def verify_token(self, token: str, resource_id: str) -> Dict[str, Any]:
        """
        Verify a token for a specific resource.

        Args:
            token: The token to verify
            resource_id: The document ID or file hash to verify against

        Returns:
            A dictionary containing the verification result

        Raises:
            YSignError: If the token is invalid
        """
        result = self._run_y_sign(["verify", "--doc-id", resource_id], token)
        
        # Check if verification failed
        verification = result.get("verification", {})
        if verification.get("valid", False) is not True:
            error = verification.get("error", "Unknown error")
            raise YSignInvalidTokenError(f"Token verification failed: {error}")
        
        return verification
    
    def is_token_valid(self, token: str, resource_id: str) -> bool:
        """
        Check if a token is valid for a specific resource.

        Args:
            token: The token to verify
            resource_id: The document ID or file hash to verify against

        Returns:
            True if the token is valid, False otherwise
        """
        try:
            self.verify_token(token, resource_id)
            return True
        except Exception:
            return False
            
    def generate_presigned_upload_url(
        self, 
        token: str, 
        endpoint: Optional[str] = None, 
        path_style: bool = False
    ) -> Dict[str, Any]:
        """
        Generate a presigned URL for uploading a file using a file token.

        Args:
            token: The file token to use
            endpoint: Optional S3 endpoint URL
            path_style: Whether to use path-style S3 URLs

        Returns:
            A dictionary containing the presigned URL and metadata

        Raises:
            YSignError: If the token is invalid or the URL generation fails
        """
        args = ["presign", "upload-url"]
        
        # Add optional arguments
        if endpoint:
            args.extend(["--endpoint", endpoint])
        
        if path_style:
            args.append("--path-style")
        
        return self._run_y_sign(args, token)
    
    def generate_presigned_download_url(
        self, 
        token: str, 
        endpoint: Optional[str] = None, 
        path_style: bool = False
    ) -> Dict[str, Any]:
        """
        Generate a presigned URL for downloading a file using a file token.

        Args:
            token: The file token to use
            endpoint: Optional S3 endpoint URL
            path_style: Whether to use path-style S3 URLs

        Returns:
            A dictionary containing the presigned URL and metadata

        Raises:
            YSignError: If the token is invalid or the URL generation fails
        """
        args = ["presign", "download-url"]
        
        # Add optional arguments
        if endpoint:
            args.extend(["--endpoint", endpoint])
        
        if path_style:
            args.append("--path-style")
        
        return self._run_y_sign(args, token)