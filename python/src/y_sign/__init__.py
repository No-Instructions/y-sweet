"""
Python bindings for y-sign, a token generation and verification tool for Y-Sweet.

This module provides Python functions that interface with the y-sign Rust binary
to generate and verify authentication tokens for Y-Sweet documents and files.
"""

from .token import YSignTokenGenerator, Authorization
from .error import YSignError, YSignBinaryError, YSignInvalidTokenError

__all__ = [
    "YSignTokenGenerator",
    "Authorization",
    "YSignError",
    "YSignBinaryError", 
    "YSignInvalidTokenError"
]