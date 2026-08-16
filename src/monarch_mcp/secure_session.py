"""
Secure session management for Monarch Money MCP Server using keyring.
"""

import json
import logging
import os
from typing import Dict, Optional

import keyring
from monarchmoney import MonarchMoney, LoginFailedException
from gql.transport.exceptions import TransportServerError

logger = logging.getLogger(__name__)

# Keyring service identifiers
KEYRING_SERVICE = "com.mcp.monarch-mcp"
KEYRING_USERNAME = "monarch-token"
KEYRING_COOKIES_USERNAME = "monarch-cookies"

# Monarch's password-login endpoint is now gated behind a browser-only flow
# (Cloudflare + a current client version), so we authenticate by reusing a
# browser session's cookies instead. Monarch also gates GraphQL on a current
# web-client version; the library ships a stale value, so we override it with
# the version the live web app currently sends. Bump this when calls start
# failing with "Please update to the latest version of the app".
MONARCH_CLIENT_VERSION = "v1.0.3906"

# Cookies required for cookie-based auth (matches the library's REQUIRED_COOKIES).
REQUIRED_COOKIE_NAMES = ("session_id", "csrftoken")


class SecureMonarchSession:
    """Manages Monarch Money sessions securely using the system keyring."""

    def save_token(self, token: str) -> None:
        """Save the authentication token to the system keyring."""
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, token)
            logger.info("Token saved securely to keyring")

            # Clean up any old insecure files
            self._cleanup_old_session_files()

        except Exception as e:
            logger.error("Failed to save token to keyring: %s", e)
            raise

    def load_token(self) -> Optional[str]:
        """Load the authentication token from the system keyring."""
        try:
            token = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if token:
                logger.info("Token loaded from keyring")
                return token
            logger.info("No token found in keyring")
            return None
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to load token from keyring: %s", e)
            return None

    def delete_token(self) -> None:
        """Delete the authentication token from the system keyring."""
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
            logger.info("Token deleted from keyring")

            # Also clean up any old insecure files
            self._cleanup_old_session_files()

        except keyring.errors.PasswordDeleteError:
            logger.info("No token found in keyring to delete")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to delete token from keyring: %s", e)

    def save_cookies(self, cookies: Dict[str, str]) -> None:
        """Save Monarch session cookies (session_id + csrftoken) to the keyring."""
        missing = [k for k in REQUIRED_COOKIE_NAMES if not cookies.get(k)]
        if missing:
            raise ValueError(
                f"Missing required cookies: {', '.join(missing)}. "
                "Both session_id and csrftoken are required."
            )
        try:
            keyring.set_password(
                KEYRING_SERVICE, KEYRING_COOKIES_USERNAME, json.dumps(cookies)
            )
            logger.info("Monarch session cookies saved securely to keyring")
            self._cleanup_old_session_files()
        except Exception as e:
            logger.error("Failed to save cookies to keyring: %s", e)
            raise

    def load_cookies(self) -> Optional[Dict[str, str]]:
        """Load Monarch session cookies from the keyring."""
        try:
            raw = keyring.get_password(KEYRING_SERVICE, KEYRING_COOKIES_USERNAME)
            if raw:
                cookies = json.loads(raw)
                if isinstance(cookies, dict):
                    return cookies
            return None
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to load cookies from keyring: %s", e)
            return None

    def delete_cookies(self) -> None:
        """Delete Monarch session cookies from the keyring."""
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_COOKIES_USERNAME)
            logger.info("Cookies deleted from keyring")
        except keyring.errors.PasswordDeleteError:
            logger.info("No cookies found in keyring to delete")
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to delete cookies from keyring: %s", e)

    @staticmethod
    def _apply_client_version(client: MonarchMoney) -> None:
        """Override the library's stale ``monarch-client-version`` header.

        Monarch rejects requests carrying an old client version; the library
        hardcodes a stale one, so we replace it with the current web-app value.
        """
        headers = getattr(client, "_headers", None)
        if not isinstance(headers, dict):
            return
        for key in list(headers):
            if key.lower() == "monarch-client-version":
                del headers[key]
        headers["Monarch-Client-Version"] = MONARCH_CLIENT_VERSION

    def get_authenticated_client(self) -> Optional[MonarchMoney]:
        """Get an authenticated MonarchMoney client.

        Prefers cookie-based auth (a reused browser session), falling back to a
        legacy stored token if present.
        """
        cookies = self.load_cookies()
        if cookies:
            try:
                client = MonarchMoney()
                client.set_cookies(cookies)
                self._apply_client_version(client)
                logger.info("MonarchMoney client created from stored cookies")
                return client
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Failed to build cookie-authenticated client: %s", e)
                # Fall through to token auth if available.

        token = self.load_token()
        if not token:
            return None

        try:
            client = MonarchMoney(token=token)
            logger.info("MonarchMoney client created with stored token")
            return client
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to create MonarchMoney client: %s", e)
            return None

    def save_authenticated_session(self, mm: MonarchMoney) -> None:
        """Save the session from an authenticated MonarchMoney instance."""
        if mm.token:
            self.save_token(mm.token)
        else:
            logger.warning("MonarchMoney instance has no token to save")

    def _cleanup_old_session_files(self) -> None:
        """Clean up old insecure session files."""
        cleanup_paths = [
            ".mm/mm_session.pickle",
            "monarch_session.json",
            ".mm",  # Remove the entire directory if empty
        ]

        for path in cleanup_paths:
            try:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        os.remove(path)
                        logger.info("Cleaned up old insecure session file: %s", path)
                    elif os.path.isdir(path) and not os.listdir(path):
                        os.rmdir(path)
                        logger.info("Cleaned up empty session directory: %s", path)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Could not clean up %s: %s", path, e)


def is_auth_error(exc: Exception) -> bool:
    """Return True if the exception signals an expired or invalid auth token.

    Covers the two concrete error paths from the monarchmoney / gql stack:

    1. Expired token on a GraphQL call -> gql raises
       ``TransportServerError`` with ``.code == 401`` or ``.code == 403``.
    2. Token/headers never set -> monarchmoney raises
       ``LoginFailedException``.

    For 403 responses, we distinguish genuine auth failures from WAF
    (Web Application Firewall) blocks.  Monarch's WAF returns 403 with
    an HTML body when it rejects input containing patterns like
    ``<script>`` tags.  These are NOT auth errors and must not trigger
    token deletion / re-auth.

    gql wraps the underlying ``aiohttp.ClientResponseError`` as the
    ``__cause__`` of the ``TransportServerError``.  The cause carries
    the original response headers, letting us check ``Content-Type``:
    API auth errors return ``application/json``; WAF blocks return
    ``text/html``.
    """
    if isinstance(exc, TransportServerError):
        code = getattr(exc, "code", None)
        if code == 401:
            return True
        if code == 403:
            cause = exc.__cause__
            if cause is not None:
                headers = getattr(cause, "headers", None) or {}
                content_type = str(headers.get("content-type", "")).lower()
                if "application/json" not in content_type:
                    logger.warning(
                        "403 with content-type %r — likely WAF block, not auth error",
                        content_type,
                    )
                    return False
            return True
    if isinstance(exc, LoginFailedException):
        return True
    return False


# Global session manager instance
secure_session = SecureMonarchSession()
