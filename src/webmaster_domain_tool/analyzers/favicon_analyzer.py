"""Favicon analyzer - detect all favicon versions."""

import io
import json
import logging
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from .base import BaseAnalysisResult, BaseAnalyzer

logger = logging.getLogger(__name__)


def _get_image_dimensions(image_data: bytes) -> tuple[int | None, int | None]:
    """
    Extract image dimensions from image data.

    Supports PNG, ICO, JPEG, GIF, SVG formats.

    Args:
        image_data: Raw image bytes

    Returns:
        Tuple of (width, height) or (None, None) if cannot determine
    """
    if not image_data:
        return None, None

    # SVG format (XML-based)
    if image_data[:5] in (b'<?xml', b'<svg ') or b'<svg' in image_data[:200]:
        try:
            # Parse SVG as XML
            svg_text = image_data.decode('utf-8', errors='ignore')

            # Try to parse with ElementTree
            root = ET.fromstring(svg_text)

            # Check for width/height attributes
            width_str = root.get('width')
            height_str = root.get('height')

            if width_str and height_str:
                # Extract numeric value (strip 'px', 'pt', etc.)
                width = int(re.search(r'\d+', width_str).group()) if re.search(r'\d+', width_str) else None
                height = int(re.search(r'\d+', height_str).group()) if re.search(r'\d+', height_str) else None
                if width and height:
                    return width, height

            # Fallback to viewBox if no width/height
            viewbox = root.get('viewBox')
            if viewbox:
                # viewBox format: "x y width height"
                parts = viewbox.split()
                if len(parts) == 4:
                    try:
                        width = int(float(parts[2]))
                        height = int(float(parts[3]))
                        return width, height
                    except ValueError:
                        pass
        except Exception as e:
            logger.debug(f"Error parsing SVG dimensions: {e}")
            pass

    # Check minimum size for binary formats
    if len(image_data) < 24:
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


def _get_ico_all_dimensions(image_data: bytes) -> list[tuple[int, int]]:
    """
    Extract all dimensions from multi-layer ICO file.

    ICO files can contain multiple images at different resolutions.

    Args:
        image_data: Raw ICO file bytes

    Returns:
        List of (width, height) tuples for all layers, or empty list if not ICO
    """
    if not image_data or len(image_data) < 6:
        return []

    # Check ICO signature
    if image_data[:4] != b'\x00\x00\x01\x00':
        return []

    try:
        # ICO header structure:
        # Bytes 0-1: Reserved (0)
        # Bytes 2-3: Image type (1 for ICO)
        # Bytes 4-5: Number of images

        num_images = struct.unpack('<H', image_data[4:6])[0]

        if num_images == 0 or num_images > 256:  # Sanity check
            return []

        dimensions = []

        # Each directory entry is 16 bytes, starting at offset 6
        for i in range(num_images):
            offset = 6 + (i * 16)

            if offset + 16 > len(image_data):
                break

            # Directory entry structure:
            # Byte 0: Width (0 means 256)
            # Byte 1: Height (0 means 256)
            # Bytes 2-15: Other data (color count, planes, bit count, size, offset)

            width = image_data[offset] or 256
            height = image_data[offset + 1] or 256

            dimensions.append((width, height))

        return dimensions

    except (struct.error, IndexError) as e:
        logger.debug(f"Error parsing ICO dimensions: {e}")
        return []


@dataclass
class FaviconInfo:
    """Information about a single favicon."""

    url: str
    source: str  # "html", "default", "manifest", or "meta"
    rel: str | None = None  # icon, shortcut icon, apple-touch-icon, mask-icon, etc.
    sizes: str | None = None  # e.g., "32x32", "180x180" (from HTML attribute)
    type: str | None = None  # e.g., "image/png", "image/x-icon", "image/svg+xml"
    color: str | None = None  # For Safari mask-icon
    purpose: str | None = None  # For Web App Manifest (e.g., "any", "maskable")
    exists: bool = False
    status_code: int | None = None
    size_bytes: int | None = None
    actual_width: int | None = None  # Real width from image data (primary/first layer)
    actual_height: int | None = None  # Real height from image data (primary/first layer)
    all_dimensions: list[str] | None = None  # All dimensions for multi-layer ICO (e.g., ["16x16", "32x32", "48x48"])


@dataclass
class FaviconAnalysisResult(BaseAnalysisResult):
    """Results from favicon analysis."""

    base_url: str = ""
    favicons: list[FaviconInfo] = field(default_factory=list)
    has_default_favicon: bool = False  # /favicon.ico exists


class FaviconAnalyzer(BaseAnalyzer[FaviconAnalysisResult]):
    """Analyzes favicon presence and variants."""

    # Common default favicon locations (ordered by priority/frequency)
    DEFAULT_PATHS = [
        # Standard favicon
        "/favicon.ico",
        "/favicon.svg",
        "/icon.svg",

        # Apple Touch Icons (modern sizes first)
        "/apple-touch-icon.png",  # Default (usually 180x180)
        "/apple-touch-icon-180x180.png",  # iPhone XS/XR/11/12/13/14/15
        "/apple-touch-icon-167x167.png",  # iPad Pro
        "/apple-touch-icon-152x152.png",  # iPad Retina
        "/apple-touch-icon-120x120.png",  # iPhone Retina
        "/apple-touch-icon-76x76.png",  # iPad
        "/apple-touch-icon-60x60.png",  # iPhone (older)

        # Apple Touch Icons (precomposed - legacy iOS)
        "/apple-touch-icon-precomposed.png",
        "/apple-touch-icon-180x180-precomposed.png",
        "/apple-touch-icon-152x152-precomposed.png",
        "/apple-touch-icon-120x120-precomposed.png",
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

            # Check if HTML has any existing favicons
            has_html_favicons = any(f.exists for f in html_favicons)

            # Deduplicate: only add default favicons not already in HTML
            for default_fav in default_favicons:
                if default_fav.url not in html_urls:
                    result.favicons.append(default_fav)

                    # Warning: favicon exists on default path but not referenced in HTML
                    # Only warn if HTML has favicons (meaning site uses favicons but didn't reference this one)
                    if default_fav.exists and has_html_favicons:
                        # For main defaults (/favicon.ico, /apple-touch-icon.png), warn about potential conflict
                        if default_fav.url.endswith(('/favicon.ico', '/apple-touch-icon.png')):
                            result.warnings.append(
                                f"Favicon exists at {default_fav.url} but is not referenced in HTML (potential conflict with HTML-defined favicons)"
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
        """Parse HTML to find favicon links, meta tags, and manifest."""
        favicons = []

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(base_url, headers={"User-Agent": self.user_agent})

            if response.status_code != 200:
                logger.warning(f"Failed to fetch HTML: {base_url} - status {response.status_code}")
                return favicons

            html = response.text

            # 1. Find all link tags with icon-related rel attributes
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

                # Extract color (for mask-icon)
                color_match = re.search(r'color=["\']([^"\']+)["\']', link_tag, re.IGNORECASE)
                color = color_match.group(1) if color_match else None

                favicon = FaviconInfo(
                    url=full_url,
                    source="html",
                    rel=rel,
                    sizes=sizes,
                    type=fav_type,
                    color=color
                )

                # Check if favicon actually exists and get dimensions
                self._check_favicon_exists(favicon)

                favicons.append(favicon)
                logger.debug(f"Found favicon in HTML: {full_url} (rel={rel})")

            # 2. Find Microsoft Tile meta tags
            # <meta name="msapplication-TileImage" content="...">
            ms_tile_pattern = re.compile(
                r'<meta\s+name=["\']msapplication-TileImage["\']\s+content=["\']([^"\']+)["\']',
                re.IGNORECASE
            )
            for match in ms_tile_pattern.finditer(html):
                tile_url = urljoin(base_url, match.group(1))
                favicon = FaviconInfo(
                    url=tile_url,
                    source="meta",
                    rel="msapplication-TileImage",
                    type="image/png"  # Usually PNG
                )
                self._check_favicon_exists(favicon)
                favicons.append(favicon)
                logger.debug(f"Found Microsoft Tile icon: {tile_url}")

            # 3. Check for Web App Manifest
            # <link rel="manifest" href="manifest.json">
            manifest_pattern = re.compile(
                r'<link\s+rel=["\']manifest["\']\s+href=["\']([^"\']+)["\']',
                re.IGNORECASE
            )
            manifest_match = manifest_pattern.search(html)
            if manifest_match:
                manifest_url = urljoin(base_url, manifest_match.group(1))
                manifest_favicons = self._parse_manifest(manifest_url, base_url)
                favicons.extend(manifest_favicons)

        except httpx.TimeoutException:
            logger.error(f"Timeout fetching HTML for favicon detection: {base_url}")
        except Exception as e:
            logger.error(f"Error parsing HTML for favicons: {base_url} - {e}")

        return favicons

    def _parse_manifest(self, manifest_url: str, base_url: str) -> list[FaviconInfo]:
        """Parse Web App Manifest (manifest.json) for icon definitions."""
        favicons = []

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(manifest_url, headers={"User-Agent": self.user_agent})

            if response.status_code != 200:
                logger.debug(f"Failed to fetch manifest: {manifest_url} - status {response.status_code}")
                return favicons

            try:
                manifest = response.json()
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON in manifest {manifest_url}: {e}")
                return favicons

            # Parse icons array
            icons = manifest.get('icons', [])
            if not isinstance(icons, list):
                logger.warning(f"Manifest icons is not an array: {manifest_url}")
                return favicons

            for icon in icons:
                if not isinstance(icon, dict):
                    continue

                src = icon.get('src')
                if not src:
                    continue

                # Build full URL
                icon_url = urljoin(manifest_url, src)

                favicon = FaviconInfo(
                    url=icon_url,
                    source="manifest",
                    rel="manifest-icon",
                    sizes=icon.get('sizes'),
                    type=icon.get('type'),
                    purpose=icon.get('purpose')
                )

                self._check_favicon_exists(favicon)
                favicons.append(favicon)
                logger.debug(f"Found manifest icon: {icon_url} (sizes={favicon.sizes})")

        except httpx.TimeoutException:
            logger.debug(f"Timeout fetching manifest: {manifest_url}")
        except Exception as e:
            logger.warning(f"Error parsing manifest {manifest_url}: {e}")

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

                            # Check if this is a multi-layer ICO file
                            if image_data[:4] == b'\x00\x00\x01\x00':
                                # Get all dimensions from ICO file
                                ico_dimensions = _get_ico_all_dimensions(image_data)
                                if ico_dimensions:
                                    # Store all dimensions as strings
                                    favicon.all_dimensions = [f"{w}×{h}" for w, h in ico_dimensions]

                                    # Set primary dimensions to largest or first
                                    largest = max(ico_dimensions, key=lambda d: d[0] * d[1])
                                    favicon.actual_width = largest[0]
                                    favicon.actual_height = largest[1]

                                    logger.debug(f"Multi-layer ICO favicon: {', '.join(favicon.all_dimensions)} - {favicon.url}")
                                else:
                                    # Fallback to single dimension detection
                                    width, height = _get_image_dimensions(image_data)
                                    if width and height:
                                        favicon.actual_width = width
                                        favicon.actual_height = height
                                        logger.debug(f"Favicon dimensions: {width}×{height} - {favicon.url}")
                            else:
                                # Get dimensions from image data (PNG, SVG, JPEG, GIF)
                                width, height = _get_image_dimensions(image_data)
                                if width and height:
                                    favicon.actual_width = width
                                    favicon.actual_height = height
                                    logger.debug(f"Favicon dimensions: {width}×{height} - {favicon.url}")
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
