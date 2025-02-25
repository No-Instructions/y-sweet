"""
Error classes for the y-sign module.
"""

class YSignError(Exception):
    """Base exception for all y-sign related errors."""
    pass


class YSignBinaryError(YSignError):
    """Exception raised when the y-sign binary encounters an error."""
    
    def __init__(self, message, return_code=None, stderr=None):
        self.return_code = return_code
        self.stderr = stderr
        super().__init__(f"{message} (return code: {return_code}): {stderr}")


class YSignInvalidTokenError(YSignError):
    """Exception raised when a token is invalid."""
    pass