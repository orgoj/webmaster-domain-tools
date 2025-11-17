"""HTTP utilities for analyzers."""

from dataclasses import dataclass
from typing import Any

import httpx

from ..constants import DEFAULT_HTTP_TIMEOUT, DEFAULT_USER_AGENT


@dataclass
class HTTPResult:
    """
    Result of an HTTP request.

    Either contains a successful response or error information.
    """

    success: bool
    response: httpx.Response | None = None
    error: str | None = None
    error_type: str | None = None  # "timeout", "http_error", "ssl_error", "connection_error"


def safe_http_get(
    url: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
    follow_redirects: bool = True,
    user_agent: str | None = None,
    **kwargs: Any,
) -> HTTPResult:
    """
    Perform HTTP GET with standardized error handling.

    This utility centralizes HTTP GET logic that was previously duplicated
    across multiple analyzers. It provides consistent error handling for:
    - Timeout exceptions
    - HTTP status errors (4xx, 5xx)
    - SSL/TLS errors
    - Connection errors
    - Other general errors

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds (default from constants)
        follow_redirects: Whether to follow redirects (default: True)
        user_agent: Custom user agent string (default from constants)
        **kwargs: Additional httpx.Client or httpx.get arguments

    Returns:
        HTTPResult with either successful response or error information

    Example:
        >>> result = safe_http_get("https://example.com/robots.txt")
        >>> if result.success:
        ...     print(result.response.text)
        ... else:
        ...     print(f"Error: {result.error}")
    """
    ua = user_agent or DEFAULT_USER_AGENT
    headers = kwargs.pop("headers", {})
    if "User-Agent" not in headers:
        headers["User-Agent"] = ua

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            **kwargs,
        ) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            return HTTPResult(success=True, response=response)

    except httpx.TimeoutException:
        return HTTPResult(
            success=False,
            error=f"Timeout accessing {url} ({timeout}s)",
            error_type="timeout",
        )

    except httpx.HTTPStatusError as e:
        return HTTPResult(
            success=False,
            response=e.response,
            error=f"HTTP {e.response.status_code}: {url}",
            error_type="http_error",
        )

    except httpx.ConnectError as e:
        # Check if it's SSL-related error
        error_msg = str(e).lower()
        is_ssl_error = any(ssl_term in error_msg for ssl_term in ["ssl", "certificate", "tls"])

        if is_ssl_error:
            return HTTPResult(
                success=False,
                error=f"SSL error accessing {url}: {e}",
                error_type="ssl_error",
            )
        else:
            return HTTPResult(
                success=False,
                error=f"Connection error accessing {url}: {e}",
                error_type="connection_error",
            )

    except Exception as e:
        return HTTPResult(
            success=False,
            error=f"Error accessing {url}: {e}",
            error_type="general",
        )


def safe_http_get_content(
    url: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
    follow_redirects: bool = True,
    user_agent: str | None = None,
    **kwargs: Any,
) -> tuple[bytes | None, str | None]:
    """
    Perform HTTP GET and return content bytes or error.

    Convenience wrapper around safe_http_get for simple content fetching.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
        user_agent: Custom user agent string
        **kwargs: Additional httpx arguments

    Returns:
        Tuple of (content_bytes, error_message).
        If successful: (bytes, None)
        If error: (None, error_message)

    Example:
        >>> content, error = safe_http_get_content("https://example.com/favicon.ico")
        >>> if content:
        ...     print(f"Downloaded {len(content)} bytes")
        ... else:
        ...     print(f"Error: {error}")
    """
    result = safe_http_get(
        url,
        timeout=timeout,
        follow_redirects=follow_redirects,
        user_agent=user_agent,
        **kwargs,
    )

    if result.success and result.response:
        return result.response.content, None
    else:
        return None, result.error
