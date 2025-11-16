"""Favicon analyzer - detect all favicon versions."""

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


@dataclass
class FaviconInfo:
    """Information about a single favicon."""

    url: str
    rel: str | None = None  # icon, shortcut icon, apple-touch-icon, etc.
    sizes: str | None = None  # e.g., "32x32", "180x180"
    type: str | None = None  # e.g., "image/png", "image/x-icon"
    exists: bool = False
    status_code: int | None = None
    size_bytes: int | None = None


@dataclass
class FaviconAnalysisResult:
    """Results from favicon analysis."""

    domain: str
    base_url: str
    favicons: list[FaviconInfo] = field(default_factory=list)
    has_default_favicon: bool = False  # /favicon.ico exists
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class FaviconAnalyzer:
    """Analyzes favicon presence and variants."""

    # Common default favicon locations
    DEFAULT_PATHS = [
        "/favicon.ico",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
    ]

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str | None = None,
        check_html: bool = True,
        check_defaults: bool = True,
    ):
        """
        Initialize favicon analyzer.

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
            check_html: Parse HTML for favicon links
            check_defaults: Check default favicon locations
        """
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (compatible; WebmasterDomainTool/0.1; +https://github.com/orgoj/webmaster-domain-tool)"
        )
        self.check_html = check_html
        self.check_defaults = check_defaults

    def analyze(self, base_url: str) -> FaviconAnalysisResult:
        """
        Analyze favicons for a given base URL.

        Args:
            base_url: Base URL to check (e.g., "https://example.com")

        Returns:
            FaviconAnalysisResult with all found favicons
        """
        # Extract domain for result
        parsed = urlparse(base_url)
        domain = parsed.netloc or base_url

        result = FaviconAnalysisResult(domain=domain, base_url=base_url)

        # Parse HTML for favicon links
        if self.check_html:
            html_favicons = self._parse_html_favicons(base_url)
            result.favicons.extend(html_favicons)

        # Check default locations
        if self.check_defaults:
            default_favicons = self._check_default_favicons(base_url)
            result.favicons.extend(default_favicons)

        # Check if default /favicon.ico exists
        favicon_ico = next(
            (f for f in result.favicons if f.url.endswith('/favicon.ico') and f.exists),
            None
        )
        result.has_default_favicon = favicon_ico is not None

        # Warnings
        if not result.favicons:
            result.warnings.append("No favicons found (consider adding one)")
        elif not any(f.exists for f in result.favicons):
            result.warnings.append("Favicon links found but none are accessible")

        if not result.has_default_favicon:
            result.warnings.append("Default /favicon.ico not found (recommended for compatibility)")

        return result

    def _parse_html_favicons(self, base_url: str) -> list[FaviconInfo]:
        """Parse HTML to find favicon links."""
        favicons = []

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(base_url, headers={"User-Agent": self.user_agent})

            if response.status_code != 200:
                logger.warning(f"Failed to fetch HTML: {base_url} - status {response.status_code}")
                return favicons

            html = response.text

            # Find all link tags with icon-related rel attributes
            # Pattern: <link rel="..." href="..." sizes="..." type="...">
            link_pattern = re.compile(
                r'<link\s+[^>]*rel=["\']([^"\']*icon[^"\']*)["\'][^>]*>',
                re.IGNORECASE
            )

            for match in link_pattern.finditer(html):
                link_tag = match.group(0)
                rel = match.group(1)

                # Extract href
                href_match = re.search(r'href=["\']([^"\']+)["\']', link_tag, re.IGNORECASE)
                if not href_match:
                    continue

                href = href_match.group(1)
                full_url = urljoin(base_url, href)

                # Extract sizes
                sizes_match = re.search(r'sizes=["\']([^"\']+)["\']', link_tag, re.IGNORECASE)
                sizes = sizes_match.group(1) if sizes_match else None

                # Extract type
                type_match = re.search(r'type=["\']([^"\']+)["\']', link_tag, re.IGNORECASE)
                fav_type = type_match.group(1) if type_match else None

                favicon = FaviconInfo(
                    url=full_url,
                    rel=rel,
                    sizes=sizes,
                    type=fav_type
                )

                # Check if favicon actually exists
                self._check_favicon_exists(favicon)

                favicons.append(favicon)
                logger.debug(f"Found favicon in HTML: {full_url} (rel={rel})")

        except httpx.TimeoutException:
            logger.error(f"Timeout fetching HTML for favicon detection: {base_url}")
        except Exception as e:
            logger.error(f"Error parsing HTML for favicons: {base_url} - {e}")

        return favicons

    def _check_default_favicons(self, base_url: str) -> list[FaviconInfo]:
        """Check default favicon locations."""
        favicons = []

        for path in self.DEFAULT_PATHS:
            url = urljoin(base_url, path)

            # Skip if already checked from HTML
            favicon = FaviconInfo(url=url, rel="default")
            self._check_favicon_exists(favicon)

            if favicon.exists:
                favicons.append(favicon)
                logger.debug(f"Found default favicon: {url}")

        return favicons

    def _check_favicon_exists(self, favicon: FaviconInfo) -> None:
        """Check if a favicon URL is accessible."""
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.head(
                    favicon.url,
                    headers={"User-Agent": self.user_agent}
                )

            favicon.status_code = response.status_code

            if response.status_code == 200:
                favicon.exists = True

                # Try to get content length
                content_length = response.headers.get('content-length')
                if content_length:
                    try:
                        favicon.size_bytes = int(content_length)
                    except ValueError:
                        pass

                logger.debug(f"Favicon accessible: {favicon.url}")
            else:
                logger.debug(f"Favicon not accessible: {favicon.url} - status {response.status_code}")

        except httpx.TimeoutException:
            logger.debug(f"Timeout checking favicon: {favicon.url}")
        except Exception as e:
            logger.debug(f"Error checking favicon: {favicon.url} - {e}")
