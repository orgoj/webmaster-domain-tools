"""HTTP/HTTPS analysis module for checking web responses and redirects."""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

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
class RedirectChain:
    """Represents a chain of HTTP redirects."""

    start_url: str
    final_url: str
    responses: list[HTTPResponse] = field(default_factory=list)
    total_time: float = 0.0


@dataclass
class HTTPAnalysisResult:
    """Results from HTTP/HTTPS analysis."""

    domain: str
    chains: list[RedirectChain] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class HTTPAnalyzer:
    """Analyzes HTTP/HTTPS responses and redirect chains."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 10,
        user_agent: str | None = None,
    ):
        """
        Initialize HTTP analyzer.

        Args:
            timeout: Request timeout in seconds
            max_redirects: Maximum number of redirects to follow
            user_agent: Custom user agent string
        """
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent or (
            "Mozilla/5.0 (compatible; WebmasterDomainTool/0.1; +https://github.com/orgoj/webmaster-domain-tool)"
        )

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
            f"http://www.{domain}",
            f"https://www.{domain}",
        ]

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
                                from urllib.parse import urlparse

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

            except httpx.SSLError as e:
                logger.warning(f"SSL error for {current_url}: {e}")
                http_response = HTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    error=f"SSL error: {str(e)}",
                    ssl_verified=False,
                )
                chain.responses.append(http_response)
                break

            except httpx.ConnectError as e:
                logger.warning(f"Connection error for {current_url}: {e}")
                http_response = HTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    error=f"Connection error: {str(e)}",
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
        if chain.final_url.startswith("http://") and last_response.status_code == 200:
            result.warnings.append(
                f"{chain.start_url} ends on HTTP (insecure): {chain.final_url}"
            )

        # Check for mixed HTTP->HTTPS redirects
        if chain.start_url.startswith("http://"):
            https_redirected = any(
                r.redirect_to and r.redirect_to.startswith("https://")
                for r in chain.responses
            )
            if not https_redirected and last_response.status_code == 200:
                result.warnings.append(
                    f"{chain.start_url} does not redirect to HTTPS"
                )

        # Check for too many redirects
        if len(chain.responses) > 3:
            result.warnings.append(
                f"{chain.start_url} has {len(chain.responses)} redirects (consider reducing)"
            )

        # Check for 302 (temporary) when 301 (permanent) might be better
        temp_redirects = [
            r for r in chain.responses if r.status_code == 302
        ]
        if temp_redirects:
            result.warnings.append(
                f"{chain.start_url} uses 302 (temporary) redirects - consider 301 (permanent)"
            )
