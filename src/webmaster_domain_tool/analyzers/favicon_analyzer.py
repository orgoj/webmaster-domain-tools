"""Favicon analyzer - detect all favicon versions."""

import io
import logging
import re
import struct
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


def _get_image_dimensions(image_data: bytes) -> tuple[int | None, int | None]:
    """
    Extract image dimensions from image data.

    Supports PNG, ICO, JPEG, GIF formats.

    Args:
        image_data: Raw image bytes

    Returns:
        Tuple of (width, height) or (None, None) if cannot determine
    """
    if not image_data or len(image_data) < 24:
        return None, None

    # PNG format
    if image_data[:8] == b'\x89PNG\r\n\x1a\n':
        try:
            # PNG IHDR chunk is at bytes 16-24
            width, height = struct.unpack('>II', image_data[16:24])
            return width, height
        except struct.error:
            pass

    # ICO format
    elif image_data[:4] == b'\x00\x00\x01\x00':
        try:
            # ICO directory entry at offset 6
            # Width and height are at bytes 6 and 7 (0 means 256)
            width = image_data[6] or 256
            height = image_data[7] or 256
            return width, height
        except (IndexError, struct.error):
            pass

    # JPEG format
    elif image_data[:2] == b'\xff\xd8':
        try:
            # JPEG uses markers - scan for SOF0 (Start of Frame)
            data = io.BytesIO(image_data)
            data.seek(2)  # Skip SOI marker

            while True:
                marker = data.read(2)
                if len(marker) != 2:
                    break

                # SOF0, SOF1, SOF2 markers
                if marker[0] == 0xff and marker[1] in (0xc0, 0xc1, 0xc2):
                    data.read(3)  # Skip length and precision
                    height, width = struct.unpack('>HH', data.read(4))
                    return width, height

                # Skip to next marker
                length = struct.unpack('>H', data.read(2))[0]
                data.seek(length - 2, 1)
        except (struct.error, IOError):
            pass

    # GIF format
    elif image_data[:6] in (b'GIF87a', b'GIF89a'):
        try:
            # GIF dimensions at bytes 6-10
            width, height = struct.unpack('<HH', image_data[6:10])
            return width, height
        except struct.error:
            pass

    return None, None


@dataclass
class FaviconInfo:
    """Information about a single favicon."""

    url: str
    source: str  # "html" or "default"
    rel: str | None = None  # icon, shortcut icon, apple-touch-icon, etc.
    sizes: str | None = None  # e.g., "32x32", "180x180" (from HTML attribute)
    type: str | None = None  # e.g., "image/png", "image/x-icon"
    exists: bool = False
    status_code: int | None = None
    size_bytes: int | None = None
    actual_width: int | None = None  # Real width from image data
    actual_height: int | None = None  # Real height from image data


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
        html_favicons = []
        if self.check_html:
            html_favicons = self._parse_html_favicons(base_url)
            result.favicons.extend(html_favicons)

        # Collect URLs found in HTML
        html_urls = {f.url for f in html_favicons}

        # Check default locations
        if self.check_defaults:
            default_favicons = self._check_default_favicons(base_url)

            # Deduplicate: only add default favicons not already in HTML
            for default_fav in default_favicons:
                if default_fav.url not in html_urls:
                    result.favicons.append(default_fav)

                    # Warning: favicon exists but not referenced in HTML
                    if default_fav.exists:
                        result.warnings.append(
                            f"Favicon exists at {default_fav.url} but is not referenced in HTML"
                        )
                # If URL already in HTML, skip it (HTML source takes precedence)

        # Check if default /favicon.ico exists
        favicon_ico = next(
            (f for f in result.favicons if f.url.endswith('/favicon.ico') and f.exists),
            None
        )
        result.has_default_favicon = favicon_ico is not None

        # General warnings
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
                    source="html",
                    rel=rel,
                    sizes=sizes,
                    type=fav_type
                )

                # Check if favicon actually exists and get dimensions
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

            favicon = FaviconInfo(url=url, source="default")
            self._check_favicon_exists(favicon)

            if favicon.exists:
                favicons.append(favicon)
                logger.debug(f"Found default favicon: {url}")

        return favicons

    def _check_favicon_exists(self, favicon: FaviconInfo) -> None:
        """Check if a favicon URL is accessible and get its dimensions."""
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                # First try HEAD to check existence
                head_response = client.head(
                    favicon.url,
                    headers={"User-Agent": self.user_agent}
                )

            favicon.status_code = head_response.status_code

            if head_response.status_code == 200:
                favicon.exists = True

                # Get content length from HEAD response
                content_length = head_response.headers.get('content-length')
                if content_length:
                    try:
                        favicon.size_bytes = int(content_length)
                    except ValueError:
                        pass

                # Download the image to get dimensions
                # Only download if size is reasonable (< 5MB)
                if favicon.size_bytes and favicon.size_bytes > 5 * 1024 * 1024:
                    logger.warning(f"Favicon too large to download for dimension check: {favicon.url}")
                else:
                    try:
                        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                            get_response = client.get(
                                favicon.url,
                                headers={"User-Agent": self.user_agent}
                            )

                        if get_response.status_code == 200:
                            image_data = get_response.content

                            # Update size if not already known
                            if not favicon.size_bytes:
                                favicon.size_bytes = len(image_data)

                            # Get dimensions from image data
                            width, height = _get_image_dimensions(image_data)
                            if width and height:
                                favicon.actual_width = width
                                favicon.actual_height = height
                                logger.debug(f"Favicon dimensions: {width}x{height} - {favicon.url}")
                    except httpx.TimeoutException:
                        logger.debug(f"Timeout downloading favicon for dimension check: {favicon.url}")
                    except Exception as e:
                        logger.debug(f"Error downloading favicon for dimensions: {favicon.url} - {e}")

                logger.debug(f"Favicon accessible: {favicon.url}")
            else:
                logger.debug(f"Favicon not accessible: {favicon.url} - status {head_response.status_code}")

        except httpx.TimeoutException:
            logger.debug(f"Timeout checking favicon: {favicon.url}")
        except Exception as e:
            logger.debug(f"Error checking favicon: {favicon.url} - {e}")
