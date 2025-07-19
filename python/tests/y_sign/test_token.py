import pytest
import json
import os
from unittest import mock
from y_sign import YSignTokenGenerator, Authorization, YSignBinaryError, YSignInvalidTokenError


class TestYSignTokenGenerator:
    """Tests for the YSignTokenGenerator class."""
    
    @pytest.fixture
    def mock_which(self):
        """Mock shutil.which to return a fake binary path."""
        with mock.patch("shutil.which", return_value="/path/to/y-sign"):
            yield
    
    @pytest.fixture
    def mock_subprocess_run(self):
        """Mock subprocess.run to return fake successful responses."""
        with mock.patch("subprocess.run") as mock_run:
            # Set up default return for version command
            mock_run.return_value = mock.Mock(
                stdout="0.8.1\n",
                stderr="",
                returncode=0
            )
            yield mock_run
    
    def test_init_with_custom_path(self, mock_subprocess_run):
        """Test initializing with a custom binary path."""
        with mock.patch("os.path.isfile", return_value=True):
            generator = YSignTokenGenerator("test-key", binary_path="/custom/path/to/y-sign")
            assert generator.binary_path == "/custom/path/to/y-sign"
    
    def test_init_with_path_search(self, mock_which, mock_subprocess_run):
        """Test initializing with automatic path search."""
        generator = YSignTokenGenerator("test-key")
        assert generator.binary_path == "/path/to/y-sign"
    
    def test_init_binary_not_found(self):
        """Test initialization when binary is not found."""
        with mock.patch("shutil.which", return_value=None):
            with pytest.raises(YSignBinaryError, match="y-sign binary not found in PATH"):
                YSignTokenGenerator("test-key")
    
    def test_generate_document_token(self, mock_which, mock_subprocess_run):
        """Test generating a document token."""
        # Mock the sign command response
        mock_subprocess_run.return_value.stdout = json.dumps({
            "docId": "test-doc",
            "token": "test-token",
            "type": "document",
            "authorization": "full"
        })
        
        generator = YSignTokenGenerator("test-key")
        result = generator.generate_document_token("test-doc")
        
        # Check subprocess was called correctly
        call_args = mock_subprocess_run.call_args[0][0]
        assert call_args[0] == "/path/to/y-sign"
        assert call_args[1] == "sign"
        
        # Check input data was correct
        input_data = mock_subprocess_run.call_args[1]["input"]
        assert json.loads(input_data) == {
            "docId": "test-doc",
            "type": "document",
            "authorization": "full"
        }
        
        # Check result was parsed correctly
        assert result["docId"] == "test-doc"
        assert result["token"] == "test-token"

    def test_generate_document_token_cwt(self, mock_which, mock_subprocess_run):
        """Test generating a document token with the CWT flag."""
        mock_subprocess_run.return_value.stdout = json.dumps({
            "docId": "test-doc",
            "token": "test-token",
            "type": "document",
            "authorization": "full",
        })

        generator = YSignTokenGenerator("test-key")
        result = generator.generate_document_token("test-doc", cwt=True)

        call_args = mock_subprocess_run.call_args[0][0]
        assert "--cwt" in call_args

        input_data = mock_subprocess_run.call_args[1]["input"]
        assert json.loads(input_data)["docId"] == "test-doc"
        assert result["token"] == "test-token"
    
    def test_generate_file_token(self, mock_which, mock_subprocess_run):
        """Test generating a file token."""
        # Mock the sign command response
        mock_subprocess_run.return_value.stdout = json.dumps({
            "fileHash": "test-hash",
            "token": "test-token",
            "type": "file",
            "authorization": "full"
        })
        
        generator = YSignTokenGenerator("test-key")
        result = generator.generate_file_token("test-hash")
        
        # Check subprocess was called correctly
        call_args = mock_subprocess_run.call_args[0][0]
        assert call_args[0] == "/path/to/y-sign"
        assert call_args[1] == "sign"
        
        # Check input data was correct
        input_data = mock_subprocess_run.call_args[1]["input"]
        assert json.loads(input_data) == {
            "fileHash": "test-hash",
            "type": "file",
            "authorization": "full"
        }
        
        # Check result was parsed correctly
        assert result["fileHash"] == "test-hash"
        assert result["token"] == "test-token"

    def test_generate_file_token_cwt(self, mock_which, mock_subprocess_run):
        """Test generating a file token with the CWT flag."""
        mock_subprocess_run.return_value.stdout = json.dumps({
            "fileHash": "test-hash",
            "token": "test-token",
            "type": "file",
            "authorization": "full",
        })

        generator = YSignTokenGenerator("test-key")
        result = generator.generate_file_token("test-hash", cwt=True)

        call_args = mock_subprocess_run.call_args[0][0]
        assert "--cwt" in call_args

        input_data = mock_subprocess_run.call_args[1]["input"]
        assert json.loads(input_data)["fileHash"] == "test-hash"
        assert result["token"] == "test-token"
    
    def test_verify_token(self, mock_which, mock_subprocess_run):
        """Test verifying a token."""
        # Mock the verify command response
        mock_subprocess_run.return_value.stdout = json.dumps({
            "token": {"raw": "test-token"},
            "verification": {
                "valid": True,
                "kind": "document",
                "docId": "test-doc",
                "authorization": "full"
            }
        })
        
        generator = YSignTokenGenerator("test-key")
        result = generator.verify_token("test-token", "test-doc")
        
        # Check subprocess was called correctly
        call_args = mock_subprocess_run.call_args[0][0]
        assert call_args[0] == "/path/to/y-sign"
        assert call_args[1] == "verify"
        assert "--doc-id" in call_args
        assert call_args[call_args.index("--doc-id") + 1] == "test-doc"
        
        # Check input data was correct
        input_data = mock_subprocess_run.call_args[1]["input"]
        assert input_data == "test-token"
        
        # Check result was parsed correctly
        assert result["verification"]["valid"] is True
        assert result["verification"]["docId"] == "test-doc"
    
    def test_verify_invalid_token(self, mock_which, mock_subprocess_run):
        """Test verifying an invalid token."""
        # Mock the verify command response
        mock_subprocess_run.return_value.stdout = json.dumps({
            "token": {"raw": "test-token"},
            "verification": {
                "valid": False,
                "kind": "document",
                "docId": "test-doc",
                "error": "Token expired"
            }
        })
        
        generator = YSignTokenGenerator("test-key")
        
        with pytest.raises(YSignInvalidTokenError, match="Invalid token: Token expired"):
            generator.verify_token("test-token", "test-doc")
    
    def test_is_token_valid(self, mock_which, mock_subprocess_run):
        """Test the is_token_valid helper method."""
        # Mock the verify command response
        mock_subprocess_run.return_value.stdout = json.dumps({
            "token": {"raw": "test-token"},
            "verification": {
                "valid": True,
                "kind": "document",
                "docId": "test-doc"
            }
        })
        
        generator = YSignTokenGenerator("test-key")
        result = generator.is_token_valid("test-token", "test-doc")
        
        assert result is True
    
    def test_is_token_invalid(self, mock_which, mock_subprocess_run):
        """Test the is_token_valid helper with an invalid token."""
        # Mock the verify command response
        mock_subprocess_run.return_value.stdout = json.dumps({
            "token": {"raw": "test-token"},
            "verification": {
                "valid": False,
                "kind": "document",
                "error": "Token expired"
            }
        })
        
        generator = YSignTokenGenerator("test-key")
        result = generator.is_token_valid("test-token", "test-doc")
        
        assert result is False