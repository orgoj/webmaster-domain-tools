"""HTTP/HTTPS analysis module for checking web responses and redirects."""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

import httpx

from ..constants import (
    DEFAULT_HTTP_MAX_REDIRECTS,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_USER_AGENT,
    MAX_REDIRECT_WARNING,
)
from .base import BaseAnalysisResult, BaseAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class HTTPResponse:
    """Represents an HTTP response in a redirect chain."""

    url: str
    status_code: int
    headers: dict[str, str]
    redirect_to: str | None = None
    response_time: float = 0.0
    ssl_verified: bool = True
    error: str | None = None


@dataclass
class PathCheckResult:
    """Result of checking a specific path on the final URL."""

    path: str
    full_url: str
    status_code: int | None = None
    content_length: int | None = None
    response_time: float = 0.0
    error: str | None = None
    success: bool = False


@dataclass
class RedirectChain:
    """Represents a chain of HTTP redirects."""

    start_url: str
    final_url: str
    responses: list[HTTPResponse] = field(default_factory=list)
    total_time: float = 0.0


@dataclass
class HTTPAnalysisResult(BaseAnalysisResult):
    """Results from HTTP/HTTPS analysis."""

    chains: list[RedirectChain] = field(default_factory=list)
    preferred_final_url: str | None = None  # URL used for further analysis (headers, verification)
    path_check_result: PathCheckResult | None = None  # Result of checking specific path


class HTTPAnalyzer(BaseAnalyzer[HTTPAnalysisResult]):
    """Analyzes HTTP/HTTPS responses and redirect chains."""

    def __init__(
        self,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        max_redirects: int = DEFAULT_HTTP_MAX_REDIRECTS,
        user_agent: str | None = None,
        skip_www: bool = False,
    ):
        """
        Initialize HTTP analyzer.

        Args:
            timeout: Request timeout in seconds
            max_redirects: Maximum number of redirects to follow
            user_agent: Custom user agent string
            skip_www: Skip testing www subdomain (useful for subdomains or domains without www)
        """
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.skip_www = skip_www

    def analyze(self, domain: str) -> HTTPAnalysisResult:
        """
        Perform comprehensive HTTP/HTTPS analysis of a domain.

        Args:
            domain: The domain to analyze

        Returns:
            HTTPAnalysisResult with all HTTP information and redirect chains
        """
        logger.info(f"Starting HTTP analysis for {domain}")
        result = HTTPAnalysisResult(domain=domain)

        # Normalize domain (remove protocol if present)
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

        # Test all variants: http/https with and without www
        urls_to_test = [
            f"http://{domain}",
            f"https://{domain}",
        ]

        # Add www variants unless skip_www is enabled
        if not self.skip_www:
            urls_to_test.extend(
                [
                    f"http://www.{domain}",
                    f"https://www.{domain}",
                ]
            )

        for url in urls_to_test:
            logger.debug(f"Testing URL: {url}")
            chain = self._follow_redirects(url)
            result.chains.append(chain)

            # Validate redirect chain
            self._validate_chain(chain, result)

        return result

    def _follow_redirects(self, start_url: str) -> RedirectChain:
        """
        Follow redirect chain for a given URL.

        Args:
            start_url: The starting URL

        Returns:
            RedirectChain with all responses
        """
        chain = RedirectChain(start_url=start_url, final_url=start_url)
        current_url = start_url
        redirect_count = 0
        start_time = datetime.now()

        while redirect_count <= self.max_redirects:
            try:
                # Make request without following redirects
                with httpx.Client(
                    timeout=self.timeout,
                    follow_redirects=False,
                    verify=True,
                ) as client:
                    request_start = datetime.now()
                    response = client.get(
                        current_url,
                        headers={"User-Agent": self.user_agent},
                    )
                    response_time = (datetime.now() - request_start).total_seconds()

                    # Create HTTPResponse object
                    http_response = HTTPResponse(
                        url=current_url,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        response_time=response_time,
                        ssl_verified=True,
                    )

                    # Check for redirects
                    if response.status_code in (301, 302, 303, 307, 308):
                        redirect_to = response.headers.get("Location")
                        if redirect_to:
                            # Handle relative URLs
                            if redirect_to.startswith("/"):
                                parsed = urlparse(current_url)
                                redirect_to = f"{parsed.scheme}://{parsed.netloc}{redirect_to}"

                            http_response.redirect_to = redirect_to
                            chain.responses.append(http_response)

                            current_url = redirect_to
                            redirect_count += 1
                            logger.debug(
                                f"Redirect {redirect_count}: {response.status_code} -> {redirect_to}"
                            )
                        else:
                            # Redirect status but no Location header
                            http_response.error = "Redirect status without Location header"
                            chain.responses.append(http_response)
                            break
                    else:
                        # Final response (no redirect)
                        chain.responses.append(http_response)
                        chain.final_url = current_url
                        break

            except httpx.ConnectError as e:
                # ConnectError includes SSL errors, connection refused, etc.
                logger.debug(f"Connection error for {current_url}: {e}")

                # Check if it's SSL-related error by looking at the error message
                error_msg = str(e).lower()
                is_ssl_error = any(
                    ssl_term in error_msg for ssl_term in ["ssl", "certificate", "tls"]
                )

                http_response = HTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    error=f"SSL error: {str(e)}" if is_ssl_error else f"Connection error: {str(e)}",
                    ssl_verified=False if is_ssl_error else True,
                )
                chain.responses.append(http_response)
                break

            except httpx.TimeoutException:
                logger.warning(f"Timeout for {current_url}")
                http_response = HTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    error=f"Request timeout ({self.timeout}s)",
                )
                chain.responses.append(http_response)
                break

            except Exception as e:
                logger.error(f"Unexpected error for {current_url}: {e}")
                http_response = HTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    error=f"Unexpected error: {str(e)}",
                )
                chain.responses.append(http_response)
                break

        # Check if max redirects exceeded
        if redirect_count > self.max_redirects:
            chain.responses[-1].error = f"Too many redirects (>{self.max_redirects})"

        chain.total_time = (datetime.now() - start_time).total_seconds()
        return chain

    def _validate_chain(self, chain: RedirectChain, result: HTTPAnalysisResult) -> None:
        """Validate redirect chain and add warnings/errors."""
        if not chain.responses:
            result.errors.append(f"No response received for {chain.start_url}")
            return

        last_response = chain.responses[-1]

        # Check for errors
        if last_response.error:
            result.errors.append(f"{chain.start_url}: {last_response.error}")

        # Check for HTTP on final URL (should use HTTPS)
        ends_on_http = chain.final_url.startswith("http://") and last_response.status_code == 200
        if ends_on_http:
            result.warnings.append(f"{chain.start_url} ends on HTTP (insecure): {chain.final_url}")

        # Check for mixed HTTP->HTTPS redirects
        # Skip if already warned about ending on HTTP
        if chain.start_url.startswith("http://") and not ends_on_http:
            https_redirected = any(
                r.redirect_to and r.redirect_to.startswith("https://") for r in chain.responses
            )
            if not https_redirected and last_response.status_code == 200:
                result.warnings.append(f"{chain.start_url} does not redirect to HTTPS")

        # Check for too many redirects
        if len(chain.responses) > MAX_REDIRECT_WARNING:
            result.warnings.append(
                f"{chain.start_url} has {len(chain.responses)} redirects (consider reducing)"
            )

        # Check for 302 (temporary) when 301 (permanent) might be better
        temp_redirects = [r for r in chain.responses if r.status_code == 302]
        if temp_redirects:
            result.warnings.append(
                f"{chain.start_url} uses 302 (temporary) redirects - consider 301 (permanent)"
            )

    def check_path(self, base_url: str, path: str) -> PathCheckResult:
        """
        Check if a specific path exists on the base URL.

        Args:
            base_url: The base URL to check (e.g., "https://example.com")
            path: The path to check (e.g., "/.wdt.hosting.info.txt")

        Returns:
            PathCheckResult with status and content information
        """
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path

        # Remove trailing slash from base_url
        base_url = base_url.rstrip("/")

        full_url = f"{base_url}{path}"

        result = PathCheckResult(path=path, full_url=full_url)

        try:
            start_time = datetime.now()
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,  # Follow redirects for path check
                verify=True,
            ) as client:
                response = client.get(
                    full_url,
                    headers={"User-Agent": self.user_agent},
                )

            result.response_time = (datetime.now() - start_time).total_seconds()
            result.status_code = response.status_code

            # Check if successful (200 OK)
            if response.status_code == 200:
                content = response.text
                result.content_length = len(content)

                # Check if content is not empty
                if content and content.strip():
                    result.success = True
                    logger.info(
                        f"Path check successful: {full_url} ({result.content_length} bytes)"
                    )
                else:
                    result.error = "Path returned 200 but content is empty"
                    logger.warning(f"Path check failed: {full_url} - empty content")
            else:
                result.error = f"HTTP {response.status_code}"
                logger.warning(f"Path check failed: {full_url} - status {response.status_code}")

        except httpx.ConnectError as e:
            result.error = f"Connection error: {str(e)}"
            logger.error(f"Path check connection error for {full_url}: {e}")

        except httpx.TimeoutException:
            result.error = f"Request timeout ({self.timeout}s)"
            logger.error(f"Path check timeout for {full_url}")

        except Exception as e:
            result.error = f"Unexpected error: {str(e)}"
            logger.error(f"Path check unexpected error for {full_url}: {e}")

        return result
