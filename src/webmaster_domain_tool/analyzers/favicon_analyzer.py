"""Favicon analyzer - detect all favicon versions.

This analyzer detects favicons from HTML tags, Web App Manifest, and default paths.
Completely self-contained with config, logic, and output formatting.
"""

import io
import json
import logging
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Helper Functions
# ============================================================================


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
    if image_data[:5] in (b"<?xml", b"<svg ") or b"<svg" in image_data[:200]:
        try:
            # Parse SVG as XML
            svg_text = image_data.decode("utf-8", errors="ignore")

            # Try to parse with ElementTree
            root = ET.fromstring(svg_text)

            # Check for width/height attributes
            width_str = root.get("width")
            height_str = root.get("height")

            if width_str and height_str:
                # Extract numeric value (strip 'px', 'pt', etc.)
                width = (
                    int(re.search(r"\d+", width_str).group())
                    if re.search(r"\d+", width_str)
                    else None
                )
                height = (
                    int(re.search(r"\d+", height_str).group())
                    if re.search(r"\d+", height_str)
                    else None
                )
                if width and height:
                    return width, height

            # Fallback to viewBox if no width/height
            viewbox = root.get("viewBox")
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
    if image_data[:8] == b"\x89PNG\r\n\x1a\n":
        try:
            # PNG IHDR chunk is at bytes 16-24
            width, height = struct.unpack(">II", image_data[16:24])
            return width, height
        except struct.error:
            pass

    # ICO format
    elif image_data[:4] == b"\x00\x00\x01\x00":
        try:
            # ICO directory entry at offset 6
            # Width and height are at bytes 6 and 7 (0 means 256)
            width = image_data[6] or 256
            height = image_data[7] or 256
            return width, height
        except (IndexError, struct.error):
            pass

    # JPEG format
    elif image_data[:2] == b"\xff\xd8":
        try:
            # JPEG uses markers - scan for SOF0 (Start of Frame)
            data = io.BytesIO(image_data)
            data.seek(2)  # Skip SOI marker

            while True:
                marker = data.read(2)
                if len(marker) != 2:
                    break

                # SOF0, SOF1, SOF2 markers
                if marker[0] == 0xFF and marker[1] in (0xC0, 0xC1, 0xC2):
                    data.read(3)  # Skip length and precision
                    height, width = struct.unpack(">HH", data.read(4))
                    return width, height

                # Skip to next marker
                length = struct.unpack(">H", data.read(2))[0]
                data.seek(length - 2, 1)
        except (OSError, struct.error):
            pass

    # GIF format
    elif image_data[:6] in (b"GIF87a", b"GIF89a"):
        try:
            # GIF dimensions at bytes 6-10
            width, height = struct.unpack("<HH", image_data[6:10])
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
    if image_data[:4] != b"\x00\x00\x01\x00":
        return []

    try:
        # ICO header structure:
        # Bytes 0-1: Reserved (0)
        # Bytes 2-3: Image type (1 for ICO)
        # Bytes 4-5: Number of images

        num_images = struct.unpack("<H", image_data[4:6])[0]

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


# ============================================================================
# Configuration
# ============================================================================


class FaviconConfig(AnalyzerConfig):
    """Favicon analyzer configuration."""

    user_agent: str = Field(
        default=(
            "Mozilla/5.0 (compatible; WebmasterDomainTool/0.1; "
            "+https://github.com/orgoj/webmaster-domain-tool)"
        ),
        description="User agent for HTTP requests",
    )
    check_html: bool = Field(default=True, description="Parse HTML for favicon links")
    check_defaults: bool = Field(default=True, description="Check default favicon locations")


# ============================================================================
# Result Models
# ============================================================================


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
    all_dimensions: list[str] | None = (
        None  # All dimensions for multi-layer ICO (e.g., ["16x16", "32x32", "48x48"])
    )


@dataclass
class FaviconAnalysisResult:
    """Results from favicon analysis."""

    domain: str
    base_url: str = ""
    favicons: list[FaviconInfo] = field(default_factory=list)
    has_default_favicon: bool = False  # /favicon.ico exists
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class FaviconAnalyzer:
    """
    Analyzes favicon presence and variants.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (FaviconConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "favicon"
    name = "Favicon Detection"
    description = "Detect all favicon versions and formats"
    category = "seo"
    icon = "star"
    config_class = FaviconConfig
    depends_on = ["http"]  # Needs HTTP to fetch HTML

    # ========================================================================
    # Default Favicon Locations
    # ========================================================================

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

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: FaviconConfig) -> FaviconAnalysisResult:
        """
        Analyze favicons for a given domain.

        Args:
            domain: Domain to analyze (e.g., "example.com")
            config: Favicon analyzer configuration

        Returns:
            FaviconAnalysisResult with all found favicons
        """
        # Construct base URL from domain
        # Assume HTTPS first, could fallback to HTTP if needed
        base_url = f"https://{domain}" if not domain.startswith("http") else domain

        # Extract clean domain for result
        parsed = urlparse(base_url)
        clean_domain = parsed.netloc or domain

        result = FaviconAnalysisResult(domain=clean_domain, base_url=base_url)

        # Parse HTML for favicon links
        html_favicons = []
        if config.check_html:
            html_favicons = self._parse_html_favicons(base_url, config)
            result.favicons.extend(html_favicons)

        # Collect URLs found in HTML
        html_urls = {f.url for f in html_favicons}

        # Check default locations
        if config.check_defaults:
            default_favicons = self._check_default_favicons(base_url, config)

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
                        if default_fav.url.endswith(("/favicon.ico", "/apple-touch-icon.png")):
                            result.warnings.append(
                                f"Favicon exists at {default_fav.url} but is not referenced in HTML (potential conflict with HTML-defined favicons)"
                            )
                # If URL already in HTML, skip it (HTML source takes precedence)

        # Check if default /favicon.ico exists
        favicon_ico = next(
            (f for f in result.favicons if f.url.endswith("/favicon.ico") and f.exists), None
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

    def _parse_html_favicons(self, base_url: str, config: FaviconConfig) -> list[FaviconInfo]:
        """Parse HTML to find favicon links, meta tags, and manifest."""
        favicons = []

        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(base_url, headers={"User-Agent": config.user_agent})

            if response.status_code != 200:
                logger.debug(f"Failed to fetch HTML: {base_url} - status {response.status_code}")
                return favicons

            html = response.text

            # 1. Find all link tags with icon-related rel attributes
            # Pattern: <link rel="..." href="..." sizes="..." type="...">
            link_pattern = re.compile(
                r'<link\s+[^>]*rel=["\']([^"\']*icon[^"\']*)["\'][^>]*>', re.IGNORECASE
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
                    url=full_url, source="html", rel=rel, sizes=sizes, type=fav_type, color=color
                )

                # Check if favicon actually exists and get dimensions
                self._check_favicon_exists(favicon, config)

                favicons.append(favicon)
                logger.debug(f"Found favicon in HTML: {full_url} (rel={rel})")

            # 2. Find Microsoft Tile meta tags
            # <meta name="msapplication-TileImage" content="...">
            ms_tile_pattern = re.compile(
                r'<meta\s+name=["\']msapplication-TileImage["\']\s+content=["\']([^"\']+)["\']',
                re.IGNORECASE,
            )
            for match in ms_tile_pattern.finditer(html):
                tile_url = urljoin(base_url, match.group(1))
                favicon = FaviconInfo(
                    url=tile_url,
                    source="meta",
                    rel="msapplication-TileImage",
                    type="image/png",  # Usually PNG
                )
                self._check_favicon_exists(favicon, config)
                favicons.append(favicon)
                logger.debug(f"Found Microsoft Tile icon: {tile_url}")

            # 3. Check for Web App Manifest
            # <link rel="manifest" href="manifest.json">
            manifest_pattern = re.compile(
                r'<link\s+rel=["\']manifest["\']\s+href=["\']([^"\']+)["\']', re.IGNORECASE
            )
            manifest_match = manifest_pattern.search(html)
            if manifest_match:
                manifest_url = urljoin(base_url, manifest_match.group(1))
                manifest_favicons = self._parse_manifest(manifest_url, base_url, config)
                favicons.extend(manifest_favicons)

        except httpx.TimeoutException:
            logger.debug(f"Timeout fetching HTML for favicon detection: {base_url}")
        except Exception as e:
            logger.debug(f"Error parsing HTML for favicons: {base_url} - {e}")

        return favicons

    def _parse_manifest(
        self, manifest_url: str, base_url: str, config: FaviconConfig
    ) -> list[FaviconInfo]:
        """Parse Web App Manifest (manifest.json) for icon definitions."""
        favicons = []

        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(manifest_url, headers={"User-Agent": config.user_agent})

            if response.status_code != 200:
                logger.debug(
                    f"Failed to fetch manifest: {manifest_url} - status {response.status_code}"
                )
                return favicons

            try:
                manifest = response.json()
            except json.JSONDecodeError as e:
                logger.debug(f"Invalid JSON in manifest {manifest_url}: {e}")
                return favicons

            # Parse icons array
            icons = manifest.get("icons", [])
            if not isinstance(icons, list):
                logger.debug(f"Manifest icons is not an array: {manifest_url}")
                return favicons

            for icon in icons:
                if not isinstance(icon, dict):
                    continue

                src = icon.get("src")
                if not src:
                    continue

                # Build full URL
                icon_url = urljoin(manifest_url, src)

                favicon = FaviconInfo(
                    url=icon_url,
                    source="manifest",
                    rel="manifest-icon",
                    sizes=icon.get("sizes"),
                    type=icon.get("type"),
                    purpose=icon.get("purpose"),
                )

                self._check_favicon_exists(favicon, config)
                favicons.append(favicon)
                logger.debug(f"Found manifest icon: {icon_url} (sizes={favicon.sizes})")

        except httpx.TimeoutException:
            logger.debug(f"Timeout fetching manifest: {manifest_url}")
        except Exception as e:
            logger.debug(f"Error parsing manifest {manifest_url}: {e}")

        return favicons

    def _check_default_favicons(self, base_url: str, config: FaviconConfig) -> list[FaviconInfo]:
        """Check default favicon locations."""
        favicons = []

        for path in self.DEFAULT_PATHS:
            url = urljoin(base_url, path)

            favicon = FaviconInfo(url=url, source="default")
            self._check_favicon_exists(favicon, config)

            if favicon.exists:
                favicons.append(favicon)
                logger.debug(f"Found default favicon: {url}")

        return favicons

    def _check_favicon_exists(self, favicon: FaviconInfo, config: FaviconConfig) -> None:
        """Check if a favicon URL is accessible and get its dimensions."""
        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                # First try HEAD to check existence
                head_response = client.head(favicon.url, headers={"User-Agent": config.user_agent})

            favicon.status_code = head_response.status_code

            if head_response.status_code == 200:
                favicon.exists = True

                # Get content length from HEAD response
                content_length = head_response.headers.get("content-length")
                if content_length:
                    try:
                        favicon.size_bytes = int(content_length)
                    except ValueError:
                        pass

                # Download the image to get dimensions
                # Only download if size is reasonable (< 5MB)
                if favicon.size_bytes and favicon.size_bytes > 5 * 1024 * 1024:
                    logger.debug(
                        f"Favicon too large to download for dimension check: {favicon.url}"
                    )
                else:
                    try:
                        with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                            get_response = client.get(
                                favicon.url, headers={"User-Agent": config.user_agent}
                            )

                        if get_response.status_code == 200:
                            image_data = get_response.content

                            # Update size if not already known
                            if not favicon.size_bytes:
                                favicon.size_bytes = len(image_data)

                            # Check if this is a multi-layer ICO file
                            if image_data[:4] == b"\x00\x00\x01\x00":
                                # Get all dimensions from ICO file
                                ico_dimensions = _get_ico_all_dimensions(image_data)
                                if ico_dimensions:
                                    # Store all dimensions as strings
                                    favicon.all_dimensions = [f"{w}×{h}" for w, h in ico_dimensions]

                                    # Set primary dimensions to largest or first
                                    largest = max(ico_dimensions, key=lambda d: d[0] * d[1])
                                    favicon.actual_width = largest[0]
                                    favicon.actual_height = largest[1]

                                    logger.debug(
                                        f"Multi-layer ICO favicon: {', '.join(favicon.all_dimensions)} - {favicon.url}"
                                    )
                                else:
                                    # Fallback to single dimension detection
                                    width, height = _get_image_dimensions(image_data)
                                    if width and height:
                                        favicon.actual_width = width
                                        favicon.actual_height = height
                                        logger.debug(
                                            f"Favicon dimensions: {width}×{height} - {favicon.url}"
                                        )
                            else:
                                # Get dimensions from image data (PNG, SVG, JPEG, GIF)
                                width, height = _get_image_dimensions(image_data)
                                if width and height:
                                    favicon.actual_width = width
                                    favicon.actual_height = height
                                    logger.debug(
                                        f"Favicon dimensions: {width}×{height} - {favicon.url}"
                                    )
                    except httpx.TimeoutException:
                        logger.debug(
                            f"Timeout downloading favicon for dimension check: {favicon.url}"
                        )
                    except Exception as e:
                        logger.debug(
                            f"Error downloading favicon for dimensions: {favicon.url} - {e}"
                        )

                logger.debug(f"Favicon accessible: {favicon.url}")
            else:
                logger.debug(
                    f"Favicon not accessible: {favicon.url} - status {head_response.status_code}"
                )

        except httpx.TimeoutException:
            logger.debug(f"Timeout checking favicon: {favicon.url}")
        except Exception as e:
            logger.debug(f"Error checking favicon: {favicon.url} - {e}")

    def describe_output(self, result: FaviconAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: Favicon analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        descriptor.quiet_summary = lambda r: (
            f"Favicons: {len([f for f in r.favicons if f.exists])} found"
        )

        # Summary row
        existing_favicons = [f for f in result.favicons if f.exists]
        if existing_favicons:
            descriptor.add_row(
                label="Favicons Found",
                value=f"{len(existing_favicons)} favicon(s) detected",
                style_class="success",
                icon="check",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )
        else:
            descriptor.add_row(
                label="Favicons Found",
                value="No favicons detected",
                style_class="muted",
                icon="warning",
                severity="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Default favicon.ico status
        if result.has_default_favicon:
            descriptor.add_row(
                label="Default Favicon",
                value="/favicon.ico exists",
                style_class="success",
                icon="check",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )
        else:
            descriptor.add_row(
                label="Default Favicon",
                value="/favicon.ico not found",
                style_class="muted",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Verbose - show all favicons
        if existing_favicons and VerbosityLevel.VERBOSE:
            # Group by source
            html_favicons = [f for f in existing_favicons if f.source == "html"]
            manifest_favicons = [f for f in existing_favicons if f.source == "manifest"]
            default_favicons = [f for f in existing_favicons if f.source == "default"]
            meta_favicons = [f for f in existing_favicons if f.source == "meta"]

            # HTML favicons
            if html_favicons:
                for fav in html_favicons:
                    # Build value string with all info
                    value_parts = [fav.url]
                    if fav.rel:
                        value_parts.append(f"rel={fav.rel}")
                    if fav.sizes:
                        value_parts.append(f"sizes={fav.sizes}")
                    if fav.actual_width and fav.actual_height:
                        value_parts.append(f"actual={fav.actual_width}×{fav.actual_height}")
                    if fav.all_dimensions:
                        value_parts.append(f"layers=[{', '.join(fav.all_dimensions)}]")
                    if fav.size_bytes:
                        size_kb = fav.size_bytes / 1024
                        value_parts.append(f"size={size_kb:.1f}KB")

                    descriptor.add_row(
                        label="HTML Favicon",
                        value=" | ".join(value_parts),
                        style_class="info",
                        severity="info",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

            # Manifest favicons
            if manifest_favicons:
                for fav in manifest_favicons:
                    value_parts = [fav.url]
                    if fav.sizes:
                        value_parts.append(f"sizes={fav.sizes}")
                    if fav.type:
                        value_parts.append(f"type={fav.type}")
                    if fav.purpose:
                        value_parts.append(f"purpose={fav.purpose}")

                    descriptor.add_row(
                        label="Manifest Favicon",
                        value=" | ".join(value_parts),
                        style_class="info",
                        severity="info",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

            # Default path favicons
            if default_favicons:
                for fav in default_favicons:
                    value_parts = [fav.url]
                    if fav.actual_width and fav.actual_height:
                        value_parts.append(f"actual={fav.actual_width}×{fav.actual_height}")
                    if fav.all_dimensions:
                        value_parts.append(f"layers=[{', '.join(fav.all_dimensions)}]")

                    descriptor.add_row(
                        label="Default Path Favicon",
                        value=" | ".join(value_parts),
                        style_class="info",
                        severity="info",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

            # Meta tag favicons
            if meta_favicons:
                for fav in meta_favicons:
                    descriptor.add_row(
                        label="Meta Tag Favicon",
                        value=f"{fav.url} ({fav.rel})",
                        style_class="info",
                        severity="info",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

        # Errors
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Warnings
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

    def to_dict(self, result: FaviconAnalysisResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Favicon analysis result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "base_url": result.base_url,
            "has_default_favicon": result.has_default_favicon,
            "favicons": [
                {
                    "url": fav.url,
                    "source": fav.source,
                    "rel": fav.rel,
                    "sizes": fav.sizes,
                    "type": fav.type,
                    "color": fav.color,
                    "purpose": fav.purpose,
                    "exists": fav.exists,
                    "status_code": fav.status_code,
                    "size_bytes": fav.size_bytes,
                    "actual_width": fav.actual_width,
                    "actual_height": fav.actual_height,
                    "all_dimensions": fav.all_dimensions,
                }
                for fav in result.favicons
            ],
            "errors": result.errors,
            "warnings": result.warnings,
        }
