"""HTTP/HTTPS analysis module for checking web responses and redirects.

This analyzer performs comprehensive HTTP/HTTPS analysis including redirect chains,
status codes, SSL verification, and response times. Completely self-contained with
config, logic, and output formatting.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

import httpx
from pydantic import Field, field_validator

from ..constants import (
    DEFAULT_HTTP_MAX_REDIRECTS,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_USER_AGENT,
    MAX_REDIRECT_WARNING,
)
from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class HTTPConfig(AnalyzerConfig):
    """HTTP analyzer configuration."""

    timeout: float = Field(default=DEFAULT_HTTP_TIMEOUT, description="Request timeout in seconds")
    max_redirects: int = Field(
        default=DEFAULT_HTTP_MAX_REDIRECTS, description="Maximum number of redirects to follow"
    )
    user_agent: str = Field(default=DEFAULT_USER_AGENT, description="Custom user agent string")
    skip_www: bool = Field(
        default=False,
        description="Skip testing www subdomain (useful for subdomains or domains without www)",
    )

    @field_validator("user_agent", mode="before")
    @classmethod
    def validate_user_agent(cls, v):
        """Ensure user_agent is never None - use default if missing."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return DEFAULT_USER_AGENT
        return v


# ============================================================================
# Result Models
# ============================================================================


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
class HTTPAnalysisResult:
    """Results from HTTP/HTTPS analysis."""

    domain: str
    chains: list[RedirectChain] = field(default_factory=list)
    preferred_final_url: str | None = None  # URL used for further analysis (headers, verification)
    path_check_result: PathCheckResult | None = None  # Result of checking specific path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class HTTPAnalyzer:
    """
    Analyzes HTTP/HTTPS responses and redirect chains.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (HTTPConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "http"
    name = "HTTP/HTTPS Analysis"
    description = "Analyze HTTP/HTTPS responses and redirect chains"
    category = "general"
    icon = "globe"
    config_class = HTTPConfig
    depends_on = ["dns"]  # HTTP needs DNS resolution

    # ========================================================================
    # Core Analysis Logic
    # ========================================================================

    def analyze(self, domain: str, config: HTTPConfig) -> HTTPAnalysisResult:
        """
        Perform comprehensive HTTP/HTTPS analysis of a domain.

        Args:
            domain: The domain to analyze
            config: HTTP analyzer configuration

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
        if not config.skip_www:
            urls_to_test.extend(
                [
                    f"http://www.{domain}",
                    f"https://www.{domain}",
                ]
            )

        for url in urls_to_test:
            logger.debug(f"Testing URL: {url}")
            chain = self._follow_redirects(url, config)
            result.chains.append(chain)

            # Validate redirect chain
            self._validate_chain(chain, result)

        # Determine preferred final URL (where site actually runs)
        # Priority: HTTPS www > HTTPS bare > HTTP www > HTTP bare
        result.preferred_final_url = self._determine_preferred_url(result, domain, config)

        return result

    def _determine_preferred_url(
        self, result: HTTPAnalysisResult, domain: str, config: HTTPConfig
    ) -> str | None:
        """
        Determine the preferred final URL where the site runs.

        Priority order:
        1. https://www.{domain} with 200 status
        2. https://{domain} with 200 status
        3. http://www.{domain} with 200 status
        4. http://{domain} with 200 status
        5. Any other successful URL

        Args:
            result: HTTP analysis result with chains
            domain: Original domain
            config: HTTP config

        Returns:
            Preferred final URL or None if no successful response
        """
        # Build priority list
        priority_urls = [
            f"https://www.{domain}",
            f"https://{domain}",
            f"http://www.{domain}",
            f"http://{domain}",
        ]

        # Find chains that ended successfully (status 200)
        successful_chains = []
        for chain in result.chains:
            if chain.responses and chain.responses[-1].status_code == 200:
                successful_chains.append(chain)

        if not successful_chains:
            return None

        # Check priority URLs first
        for priority_url in priority_urls:
            for chain in successful_chains:
                if chain.start_url == priority_url:
                    return chain.final_url

        # Fall back to first successful final URL
        return successful_chains[0].final_url

    def _follow_redirects(self, start_url: str, config: HTTPConfig) -> RedirectChain:
        """
        Follow redirect chain for a given URL.

        Args:
            start_url: The starting URL
            config: HTTP analyzer configuration

        Returns:
            RedirectChain with all responses
        """
        chain = RedirectChain(start_url=start_url, final_url=start_url)
        current_url = start_url
        redirect_count = 0
        start_time = datetime.now()

        while redirect_count <= config.max_redirects:
            logger.debug(f"→ HTTP GET: {current_url} (timeout={config.timeout}s)")
            request_start = datetime.now()

            try:
                # Make request without following redirects
                with httpx.Client(
                    timeout=config.timeout,
                    follow_redirects=False,
                    verify=True,
                ) as client:
                    response = client.get(
                        current_url,
                        headers={"User-Agent": config.user_agent},
                    )
                    response_time = (datetime.now() - request_start).total_seconds()

                    logger.debug(
                        f"✓ HTTP {response.status_code}: {current_url} ({response_time:.2f}s)"
                    )

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
                elapsed = (datetime.now() - request_start).total_seconds()

                # Check if it's SSL-related error by looking at the error message
                error_msg = str(e).lower()
                is_ssl_error = any(
                    ssl_term in error_msg for ssl_term in ["ssl", "certificate", "tls"]
                )

                if is_ssl_error:
                    logger.debug(f"✗ SSL error: {current_url} ({elapsed:.2f}s)")
                else:
                    logger.debug(f"✗ Connection error: {current_url} ({elapsed:.2f}s)")

                http_response = HTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    error=f"SSL error: {str(e)}" if is_ssl_error else f"Connection error: {str(e)}",
                    ssl_verified=False if is_ssl_error else True,
                    response_time=elapsed,
                )
                chain.responses.append(http_response)
                break

            except httpx.TimeoutException:
                elapsed = (datetime.now() - request_start).total_seconds()
                logger.debug(f"✗ Timeout: {current_url} ({elapsed:.2f}s, limit={config.timeout}s)")
                http_response = HTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    error=f"Request timeout ({config.timeout}s)",
                )
                chain.responses.append(http_response)
                break

            except Exception as e:
                logger.debug(f"Unexpected error for {current_url}: {e}")
                http_response = HTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    error=f"Unexpected error: {str(e)}",
                )
                chain.responses.append(http_response)
                break

        # Check if max redirects exceeded
        if redirect_count > config.max_redirects:
            chain.responses[-1].error = f"Too many redirects (>{config.max_redirects})"

        chain.total_time = (datetime.now() - start_time).total_seconds()
        return chain

    def _validate_chain(self, chain: RedirectChain, result: HTTPAnalysisResult) -> None:
        """Validate redirect chain and add warnings."""
        if not chain.responses:
            # Don't add to errors - will be displayed as part of chain
            return

        last_response = chain.responses[-1]

        # Note: Errors are shown in chain display, not added to result.errors
        # This prevents duplicate error messages

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

    def check_path(self, base_url: str, path: str, config: HTTPConfig) -> PathCheckResult:
        """
        Check if a specific path exists on the base URL.

        Args:
            base_url: The base URL to check (e.g., "https://example.com")
            path: The path to check (e.g., "/.wdt.hosting.info.txt")
            config: HTTP analyzer configuration

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
                timeout=config.timeout,
                follow_redirects=True,  # Follow redirects for path check
                verify=True,
            ) as client:
                response = client.get(
                    full_url,
                    headers={"User-Agent": config.user_agent},
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
                    logger.debug(f"Path check failed: {full_url} - empty content")
            else:
                result.error = f"HTTP {response.status_code}"
                logger.debug(f"Path check failed: {full_url} - status {response.status_code}")

        except httpx.ConnectError as e:
            result.error = f"Connection error: {str(e)}"
            logger.debug(f"Path check connection error for {full_url}: {e}")

        except httpx.TimeoutException:
            result.error = f"Request timeout ({config.timeout}s)"
            logger.debug(f"Path check timeout for {full_url}")

        except Exception as e:
            result.error = f"Unexpected error: {str(e)}"
            logger.debug(f"Path check unexpected error for {full_url}: {e}")

        return result

    # ========================================================================
    # Output Protocol Methods
    # ========================================================================

    def describe_output(self, result: HTTPAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: HTTP analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        descriptor.quiet_summary = lambda r: (
            f"HTTP: {len([c for c in r.chains if c.responses and c.responses[-1].status_code == 200])}/"
            f"{len(r.chains)} endpoints successful"
        )

        # Show final URL where site is running (successful HTTPS preferred)
        if result.preferred_final_url:
            descriptor.add_row(
                label="Final URL",
                value=result.preferred_final_url,
                style_class="success",
                severity="info",
                icon="check",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Show redirect chains
        for chain in result.chains:
            if not chain.responses:
                continue

            last_response = chain.responses[-1]

            # Build redirect chain display (always in NORMAL mode)
            if len(chain.responses) > 1:
                # Multi-hop redirect: show chain with codes and times
                chain_parts = []
                for resp in chain.responses:
                    if resp.redirect_to:
                        chain_parts.append(
                            f"{resp.url} {resp.status_code} ({resp.response_time:.2f}s) →"
                        )
                    else:
                        # Final response
                        chain_parts.append(
                            f"{resp.url} {resp.status_code} ({resp.response_time:.2f}s)"
                        )

                chain_display = " ".join(chain_parts)

                # Display chain (without error in message)
                if last_response.error:
                    # Show chain as info (not error)
                    descriptor.add_row(
                        value=chain_display,
                        section_type="text",
                        style_class="error",
                        severity="info",  # Don't add to error summary
                        icon="cross",
                        verbosity=VerbosityLevel.NORMAL,
                    )
                    # Add separate error row for summary with URL
                    descriptor.add_row(
                        value=f"{chain.start_url}: {last_response.error}",
                        section_type="text",
                        style_class="error",
                        severity="error",  # This goes to summary
                        icon="cross",
                        verbosity=VerbosityLevel.NORMAL,
                    )
                elif last_response.status_code == 200:
                    descriptor.add_row(
                        value=chain_display,
                        section_type="text",
                        style_class="success",
                        severity="info",
                        icon="check",
                        verbosity=VerbosityLevel.NORMAL,
                    )
                else:
                    descriptor.add_row(
                        value=chain_display,
                        section_type="text",
                        style_class="warning",
                        severity="warning",
                        icon="warning",
                        verbosity=VerbosityLevel.NORMAL,
                    )

            else:
                # Single-hop (no redirect): simple display
                if last_response.error:
                    descriptor.add_row(
                        label=chain.start_url,
                        value=last_response.error,
                        style_class="error",
                        severity="error",
                        icon="cross",
                        verbosity=VerbosityLevel.NORMAL,
                    )
                elif last_response.status_code == 200:
                    descriptor.add_row(
                        label=chain.start_url,
                        value=f"{last_response.status_code} OK - Direct ({chain.total_time:.2f}s)",
                        style_class="success",
                        severity="info",
                        icon="check",
                        verbosity=VerbosityLevel.NORMAL,
                    )
                else:
                    descriptor.add_row(
                        label=chain.start_url,
                        value=f"HTTP {last_response.status_code}",
                        style_class="warning",
                        severity="warning",
                        icon="warning",
                        verbosity=VerbosityLevel.NORMAL,
                    )

        # Path check result
        if result.path_check_result:
            path_result = result.path_check_result
            if path_result.success:
                descriptor.add_row(
                    label="Path Check",
                    value=f"{path_result.path} - {path_result.status_code} OK ({path_result.content_length} bytes)",
                    style_class="success",
                    severity="info",
                    icon="check",
                    verbosity=VerbosityLevel.NORMAL,
                )
            elif path_result.error:
                descriptor.add_row(
                    label="Path Check",
                    value=f"{path_result.path} - {path_result.error}",
                    style_class="warning",
                    severity="warning",
                    icon="warning",
                    verbosity=VerbosityLevel.NORMAL,
                )

        # Warnings only (errors are already shown in chain display)
        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                severity="warning",
                icon="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        return descriptor

    def to_dict(self, result: HTTPAnalysisResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: HTTP analysis result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "chains": [
                {
                    "start_url": chain.start_url,
                    "final_url": chain.final_url,
                    "total_time": chain.total_time,
                    "responses": [
                        {
                            "url": resp.url,
                            "status_code": resp.status_code,
                            "headers": resp.headers,
                            "redirect_to": resp.redirect_to,
                            "response_time": resp.response_time,
                            "ssl_verified": resp.ssl_verified,
                            "error": resp.error,
                        }
                        for resp in chain.responses
                    ],
                }
                for chain in result.chains
            ],
            "preferred_final_url": result.preferred_final_url,
            "path_check_result": (
                {
                    "path": result.path_check_result.path,
                    "full_url": result.path_check_result.full_url,
                    "status_code": result.path_check_result.status_code,
                    "content_length": result.path_check_result.content_length,
                    "response_time": result.path_check_result.response_time,
                    "error": result.path_check_result.error,
                    "success": result.path_check_result.success,
                }
                if result.path_check_result
                else None
            ),
            "errors": result.errors,
            "warnings": result.warnings,
        }
