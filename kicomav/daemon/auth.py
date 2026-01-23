# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Daemon Authentication Module

This module provides API key authentication for:
- FastAPI REST endpoints
- Socket protocol commands
"""

import hmac
import logging
from typing import Optional

from .config import get_daemon_config

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


def verify_api_key(provided_key: Optional[str]) -> bool:
    """Verify an API key against the configured key.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        provided_key: The API key to verify

    Returns:
        True if valid, False otherwise
    """
    config = get_daemon_config()

    # If auth not required, always return True
    if not config.require_auth:
        return True

    # If auth required but no key configured, reject
    if not config.api_key:
        logger.warning("Authentication required but no API key configured")
        return False

    # If no key provided, reject
    if not provided_key:
        return False

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(config.api_key, provided_key)


def require_auth() -> bool:
    """Check if authentication is required.

    Returns:
        True if authentication is required
    """
    config = get_daemon_config()
    return config.require_auth


# FastAPI dependency
def get_api_key_dependency():
    """Create FastAPI dependency for API key authentication.

    Returns:
        FastAPI dependency function
    """
    try:
        from fastapi import Header, HTTPException, status
    except ImportError:
        raise ImportError("FastAPI is required for API authentication. Install with: pip install kicomav[daemon]")

    async def verify_api_key_header(
        x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ) -> Optional[str]:
        """FastAPI dependency to verify API key from header.

        Args:
            x_api_key: API key from X-API-Key header

        Returns:
            The verified API key

        Raises:
            HTTPException: If authentication fails
        """
        config = get_daemon_config()

        # If auth not required, skip verification
        if not config.require_auth:
            return None

        # Verify the key
        if not verify_api_key(x_api_key):
            logger.warning("API authentication failed")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        return x_api_key

    return verify_api_key_header


def verify_socket_auth(auth_line: str) -> bool:
    """Verify authentication from socket protocol.

    Socket auth format: AUTH <api_key>

    Args:
        auth_line: The AUTH command line

    Returns:
        True if valid, False otherwise
    """
    config = get_daemon_config()

    # If auth not required, always return True
    if not config.require_auth:
        return True

    # Parse AUTH command
    parts = auth_line.strip().split(maxsplit=1)
    if len(parts) != 2 or parts[0].upper() != "AUTH":
        return False

    provided_key = parts[1]
    return verify_api_key(provided_key)


class SocketAuthState:
    """Track authentication state for a socket connection."""

    def __init__(self):
        self.authenticated = False
        self._auth_required = require_auth()

    def is_authenticated(self) -> bool:
        """Check if the connection is authenticated.

        Returns:
            True if authenticated or auth not required
        """
        if not self._auth_required:
            return True
        return self.authenticated

    def authenticate(self, auth_line: str) -> bool:
        """Attempt to authenticate with the given auth line.

        Args:
            auth_line: The AUTH command line

        Returns:
            True if authentication successful
        """
        if verify_socket_auth(auth_line):
            self.authenticated = True
            return True
        return False

    def requires_auth(self) -> bool:
        """Check if authentication is required.

        Returns:
            True if authentication is required
        """
        return self._auth_required
