"""Mobile-friendly analysis module.

Analyzes mobile-friendliness of websites including:
- Viewport meta tag configuration
- Responsive design detection
- Touch targets size validation (minimum 48x48px)
- Font readability checks
- Mobile performance indicators
"""

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup
from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class MobileConfig(AnalyzerConfig):
    """Mobile-friendly analyzer configuration."""

    user_agent_mobile: str = Field(
        default="Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        description="Mobile user agent string for HTTP requests",
    )
    user_agent_desktop: str = Field(
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        description="Desktop user agent string for responsive checks",
    )
    min_touch_target_size: int = Field(
        default=48,
        description="Minimum touch target size in pixels (Google recommends 48x48px)",
    )
    min_font_size: int = Field(
        default=12,
        description="Minimum readable font size in pixels",
    )


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class ViewportResult:
    """Result of viewport meta tag analysis."""

    present: bool = False
    content: str | None = None
    width: str | None = None
    initial_scale: float | None = None
    user_scalable: bool | None = None
    issues: list[str] = field(default_factory=list)


@dataclass
class TouchTargetResult:
    """Result of touch target analysis."""

    total_tap_targets: int = 0
    small_targets: list[dict] = field(default_factory=list)  # Targets smaller than 48x48px
    close_targets: list[dict] = field(default_factory=list)  # Targets too close together
    passed: bool = True
    issues: list[str] = field(default_factory=list)


@dataclass
class FontReadabilityResult:
    """Result of font readability analysis."""

    smallest_font_size: int | None = None
    small_font_elements: list[dict] = field(default_factory=list)  # Elements with small fonts
    passed: bool = True
    issues: list[str] = field(default_factory=list)


@dataclass
class ResponsiveResult:
    """Result of responsive design detection."""

    uses_media_queries: bool = False
    uses_flexbox: bool = False
    uses_grid: bool = False
    uses_viewport_units: bool = False
    has_mobile_stylesheets: bool = False
    responsive_score: int = 0  # 0-100
    indicators: list[str] = field(default_factory=list)


@dataclass
class MobilePerformanceResult:
    """Result of mobile performance checks."""

    page_size_bytes: int = 0
    html_size_bytes: int = 0
    css_size_bytes: int = 0
    js_size_bytes: int = 0
    image_count: int = 0
    external_requests: int = 0
    uses_amp: bool = False
    has_lazy_loading: bool = False
    issues: list[str] = field(default_factory=list)


@dataclass
class MobileAnalysisResult:
    """Complete mobile-friendly analysis result."""

    domain: str
    url: str = ""
    success: bool = False
    is_mobile_friendly: bool = False
    mobile_score: int = 0  # 0-100

    # Individual checks
    viewport: ViewportResult | None = None
    touch_targets: TouchTargetResult | None = None
    font_readability: FontReadabilityResult | None = None
    responsive: ResponsiveResult | None = None
    performance: MobilePerformanceResult | None = None

    # Summary
    passed_checks: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class MobileAnalyzer:
    """
    Mobile-Friendly Analyzer.

    Performs comprehensive mobile-friendliness analysis including:
    - Viewport meta tag configuration
    - Touch targets size validation (Google recommends 48x48px minimum)
    - Font readability (minimum readable sizes)
    - Responsive design detection
    - Mobile performance indicators

    This analyzer fetches and parses the HTML to detect mobile issues.

    Dependencies:
    - http: Optional, uses HTTP analyzer to determine URL
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "mobile"
    name = "Mobile-Friendly"
    description = "Mobile-friendly test with viewport, touch targets, and responsive design checks"
    category = "seo"
    icon = "smartphone"
    config_class = MobileConfig
    depends_on = ["http"]

    # ========================================================================
    # Protocol Methods
    # ========================================================================

    def analyze(
        self,
        domain: str,
        config: MobileConfig,
        context: dict[str, object] | None = None,
    ) -> MobileAnalysisResult:
        """
        Analyze mobile-friendliness of a website.

        Args:
            domain: Domain to analyze
            config: Mobile analyzer configuration
            context: Context from previous analyzers

        Returns:
            MobileAnalysisResult with all mobile-friendliness findings
        """
        url = self._get_url_to_analyze(domain, context)
        result = MobileAnalysisResult(domain=domain, url=url)

        try:
            # Fetch the page with mobile user agent
            html_content, response_headers = self._fetch_page(url, config)

            if not html_content:
                result.errors.append("Failed to fetch page content")
                return result

            result.success = True

            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")

            # Run all checks
            result.viewport = self._check_viewport(soup)
            result.touch_targets = self._check_touch_targets(soup, config)
            result.font_readability = self._check_font_readability(soup, config)
            result.responsive = self._check_responsive(html_content, soup)
            result.performance = self._check_mobile_performance(soup, html_content, response_headers)

            # Calculate overall score and mobile-friendliness
            self._calculate_score(result)

        except httpx.HTTPError as e:
            logger.error(f"HTTP error analyzing {url}: {e}")
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"Mobile analysis failed for {domain}: {e}", exc_info=True)
            result.errors.append(f"Analysis failed: {e}")

        return result

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _get_url_to_analyze(self, domain: str, context: dict[str, object] | None) -> str:
        """Get URL to analyze from context or fallback."""
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "preferred_final_url") and http_result.preferred_final_url:
                return http_result.preferred_final_url
        return f"https://{domain}"

    def _fetch_page(
        self, url: str, config: MobileConfig
    ) -> tuple[str | None, dict[str, str]]:
        """Fetch page content with mobile user agent."""
        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(
                    url,
                    headers={
                        "User-Agent": config.user_agent_mobile,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                    },
                )
                response.raise_for_status()
                return response.text, dict(response.headers)

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return None, {}

    def _check_viewport(self, soup: BeautifulSoup) -> ViewportResult:
        """Check viewport meta tag configuration."""
        result = ViewportResult()

        # Find viewport meta tag
        viewport_meta = soup.find("meta", attrs={"name": "viewport"})

        if not viewport_meta:
            result.issues.append("Missing viewport meta tag - page won't scale properly on mobile")
            return result

        result.present = True
        result.content = viewport_meta.get("content", "")

        if not result.content:
            result.issues.append("Viewport meta tag has empty content attribute")
            return result

        content = result.content.lower()

        # Parse viewport directives
        directives = {}
        for part in content.split(","):
            if "=" in part:
                key, value = part.split("=", 1)
                directives[key.strip()] = value.strip()

        # Check width
        result.width = directives.get("width")
        if result.width == "device-width":
            pass  # Good!
        elif result.width:
            result.issues.append(
                f"Viewport width is set to '{result.width}' instead of 'device-width'"
            )
        else:
            result.issues.append("Viewport width not specified - should be 'device-width'")

        # Check initial scale
        if "initial-scale" in directives:
            try:
                result.initial_scale = float(directives["initial-scale"])
                if result.initial_scale != 1.0:
                    result.issues.append(
                        f"Initial scale is {result.initial_scale} instead of 1.0"
                    )
            except ValueError:
                result.issues.append("Invalid initial-scale value")

        # Check user-scalable
        if "user-scalable" in directives:
            user_scalable = directives["user-scalable"]
            result.user_scalable = user_scalable not in ("no", "0", "false")
            if not result.user_scalable:
                result.issues.append(
                    "User scaling is disabled - this hurts accessibility"
                )

        # Check for maximum-scale=1 (bad practice)
        if "maximum-scale" in directives:
            try:
                max_scale = float(directives["maximum-scale"])
                if max_scale <= 1.0:
                    result.issues.append(
                        "Maximum scale is 1.0 or less - prevents zooming, hurts accessibility"
                    )
            except ValueError:
                pass

        return result

    def _check_touch_targets(
        self, soup: BeautifulSoup, config: MobileConfig
    ) -> TouchTargetResult:
        """Check touch target sizes (links, buttons, inputs)."""
        result = TouchTargetResult()

        # Find all tappable elements
        tap_elements = soup.find_all(["a", "button", "input", "select", "textarea", "label"])

        # Filter to only visible elements (basic check)
        visible_elements = []
        for elem in tap_elements:
            # Skip hidden elements
            style = elem.get("style", "")
            if "display: none" in style or "visibility: hidden" in style:
                continue
            if elem.get("hidden"):
                continue
            visible_elements.append(elem)

        result.total_tap_targets = len(visible_elements)

        # We can't actually measure rendered sizes from HTML alone,
        # but we can check inline styles for small sizes
        for elem in visible_elements:
            style = elem.get("style", "")

            # Check for explicitly small sizes in inline styles
            width_match = re.search(r"width\s*:\s*(\d+)px", style)
            height_match = re.search(r"height\s*:\s*(\d+)px", style)

            if width_match and height_match:
                width = int(width_match.group(1))
                height = int(height_match.group(1))

                if width < config.min_touch_target_size or height < config.min_touch_target_size:
                    result.small_targets.append({
                        "tag": elem.name,
                        "text": elem.get_text(strip=True)[:50] if elem.get_text() else elem.get("type", "unknown"),
                        "width": width,
                        "height": height,
                    })

        if result.small_targets:
            result.passed = False
            result.issues.append(
                f"Found {len(result.small_targets)} tap target(s) smaller than {config.min_touch_target_size}x{config.min_touch_target_size}px"
            )

        # Check for potentially close targets (links in dense text)
        paragraphs = soup.find_all("p")
        for p in paragraphs:
            links = p.find_all("a")
            if len(links) > 3:
                # Multiple links in same paragraph might be too close
                link_texts = [a.get_text(strip=True) for a in links if a.get_text(strip=True)]
                if link_texts:
                    result.close_targets.append({
                        "context": "paragraph",
                        "link_count": len(links),
                        "links": link_texts[:5],  # Limit to first 5
                    })

        if result.close_targets:
            result.issues.append(
                f"Found {len(result.close_targets)} area(s) with potentially crowded tap targets"
            )

        return result

    def _check_font_readability(
        self, soup: BeautifulSoup, config: MobileConfig
    ) -> FontReadabilityResult:
        """Check font sizes for readability on mobile."""
        result = FontReadabilityResult()

        # Find all elements with text content
        text_elements = soup.find_all(string=True)

        for text_node in text_elements:
            parent = text_node.parent
            if not parent or parent.name in ["script", "style", "noscript", "meta"]:
                continue

            style = parent.get("style", "")

            # Check for font-size in inline styles
            font_size_match = re.search(r"font-size\s*:\s*(\d+)px", style)

            if font_size_match:
                font_size = int(font_size_match.group(1))

                # Track smallest font
                if result.smallest_font_size is None or font_size < result.smallest_font_size:
                    result.smallest_font_size = font_size

                # Flag small fonts
                if font_size < config.min_font_size:
                    text_preview = str(text_node).strip()[:50]
                    if text_preview:
                        result.small_font_elements.append({
                            "tag": parent.name,
                            "font_size": font_size,
                            "text": text_preview,
                        })

        # Evaluate results
        if result.smallest_font_size is not None and result.smallest_font_size < config.min_font_size:
            result.passed = False
            result.issues.append(
                f"Found font size as small as {result.smallest_font_size}px (minimum recommended: {config.min_font_size}px)"
            )

        if len(result.small_font_elements) > 10:
            result.passed = False
            result.issues.append(
                f"Found {len(result.small_font_elements)} elements with font size smaller than {config.min_font_size}px"
            )

        return result

    def _check_responsive(
        self, html_content: str, soup: BeautifulSoup
    ) -> ResponsiveResult:
        """Detect responsive design patterns."""
        result = ResponsiveResult()

        # Check for media queries in inline styles
        if "@media" in html_content:
            result.uses_media_queries = True
            result.indicators.append("Uses CSS media queries")

        # Check for flexbox
        if any(
            keyword in html_content
            for keyword in ["display: flex", "display:flex", "flex-wrap", "flex-direction"]
        ):
            result.uses_flexbox = True
            result.indicators.append("Uses CSS flexbox")

        # Check for grid
        if any(
            keyword in html_content
            for keyword in ["display: grid", "display:grid", "grid-template"]
        ):
            result.uses_grid = True
            result.indicators.append("Uses CSS grid")

        # Check for viewport units
        if any(
            unit in html_content
            for unit in ["vw", "vh", "vmin", "vmax"]
        ):
            result.uses_viewport_units = True
            result.indicators.append("Uses viewport units (vw, vh)")

        # Check for mobile-specific stylesheets
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href", "").lower()
            media = link.get("media", "").lower()

            if "mobile" in href or "handheld" in href:
                result.has_mobile_stylesheets = True
                result.indicators.append("Has mobile-specific stylesheet")
                break

            if "max-width" in media or "mobile" in media:
                result.has_mobile_stylesheets = True
                result.indicators.append("Has media-specific stylesheet")
                break

        # Check for common responsive frameworks (only add once)
        responsive_classes = [
            "container", "row", "col-",  # Bootstrap
            "md:", "lg:", "xl:",  # Tailwind
            "responsive", "mobile",  # Generic
        ]

        has_responsive_grid = False
        for elem in soup.find_all(class_=True):
            if has_responsive_grid:
                break
            classes = " ".join(elem.get("class", []))
            for pattern in responsive_classes:
                if pattern in classes:
                    has_responsive_grid = True
                    break

        if has_responsive_grid:
            result.indicators.append("Uses responsive grid system")

        # Check for responsive images
        for img in soup.find_all("img"):
            if img.get("srcset") or "img-fluid" in " ".join(img.get("class", [])):
                result.indicators.append("Uses responsive images")
                break

        # Calculate responsive score
        score = 0
        if result.uses_media_queries:
            score += 30
        if result.uses_flexbox or result.uses_grid:
            score += 20
        if result.uses_viewport_units:
            score += 15
        if result.has_mobile_stylesheets:
            score += 15
        if result.indicators:
            score += min(20, len(result.indicators) * 5)

        result.responsive_score = min(100, score)

        return result

    def _check_mobile_performance(
        self,
        soup: BeautifulSoup,
        html_content: str,
        response_headers: dict[str, str],
    ) -> MobilePerformanceResult:
        """Check mobile performance indicators."""
        result = MobilePerformanceResult()

        # Page size
        result.html_size_bytes = len(html_content.encode("utf-8"))

        # Check content-length header for total size estimate
        content_length = response_headers.get("content-length")
        if content_length:
            result.page_size_bytes = int(content_length)
        else:
            result.page_size_bytes = result.html_size_bytes

        # Count external resources
        stylesheets = soup.find_all("link", rel="stylesheet")
        scripts = soup.find_all("script", src=True)
        images = soup.find_all("img", src=True)

        result.css_size_bytes = sum(
            len(str(s)) for s in stylesheets
        )  # Rough estimate
        result.js_size_bytes = sum(
            len(str(s)) for s in scripts
        )
        result.image_count = len(images)
        result.external_requests = len(stylesheets) + len(scripts) + len(images)

        # Check for AMP
        amp_html = soup.find("html", attrs={"amp": True})
        amp_link = soup.find("link", rel="amphtml")
        if amp_html or amp_link:
            result.uses_amp = True

        # Check for lazy loading
        for img in images:
            if img.get("loading") == "lazy" or img.get("data-src"):
                result.has_lazy_loading = True
                break

        # Performance warnings
        if result.page_size_bytes > 1_500_000:  # 1.5MB
            result.issues.append(
                f"Large page size: {result.page_size_bytes / 1024 / 1024:.1f}MB"
            )

        if result.external_requests > 50:
            result.issues.append(
                f"Many external requests: {result.external_requests} (consider reducing)"
            )

        if result.image_count > 20:
            result.issues.append(
                f"Many images on page: {result.image_count} (may slow mobile loading)"
            )

        return result

    def _calculate_score(self, result: MobileAnalysisResult) -> None:
        """Calculate overall mobile-friendliness score."""
        score = 0
        max_score = 100

        # Viewport check (25 points)
        if result.viewport:
            if result.viewport.present and not result.viewport.issues:
                score += 25
                result.passed_checks.append("Viewport meta tag properly configured")
            elif result.viewport.present:
                score += 10
                result.failed_checks.append("Viewport meta tag issues")
            else:
                result.failed_checks.append("Missing viewport meta tag")

        # Touch targets (25 points)
        if result.touch_targets:
            if result.touch_targets.passed:
                score += 25
                result.passed_checks.append("Touch targets are appropriately sized")
            elif len(result.touch_targets.small_targets) <= 3:
                score += 15
                result.failed_checks.append("Some touch targets too small")
            else:
                result.failed_checks.append("Many touch targets too small")

        # Font readability (20 points)
        if result.font_readability:
            if result.font_readability.passed:
                score += 20
                result.passed_checks.append("Font sizes are readable on mobile")
            elif result.font_readability.smallest_font_size and result.font_readability.smallest_font_size >= 10:
                score += 10
                result.failed_checks.append("Some fonts may be hard to read")
            else:
                result.failed_checks.append("Font sizes too small for mobile")

        # Responsive design (20 points)
        if result.responsive:
            score += min(20, result.responsive.responsive_score // 5)
            if result.responsive.responsive_score >= 60:
                result.passed_checks.append("Uses responsive design patterns")
            else:
                result.warnings.append("Limited responsive design detected")

        # Performance (10 points)
        if result.performance:
            if result.performance.uses_amp:
                score += 5
                result.passed_checks.append("Uses AMP")
            if result.performance.has_lazy_loading:
                score += 3
            if result.performance.page_size_bytes < 500_000:
                score += 2
                result.passed_checks.append("Page size is optimized")
            elif result.performance.page_size_bytes > 1_500_000:
                result.warnings.append("Large page size affects mobile performance")

        result.mobile_score = min(max_score, score)
        result.is_mobile_friendly = score >= 70

    def describe_output(self, result: MobileAnalysisResult) -> OutputDescriptor:
        """Describe how to render mobile-friendly results."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        if result.is_mobile_friendly:
            descriptor.quiet_summary = lambda r: f"Mobile: ✓ Friendly ({result.mobile_score}/100)"
        else:
            descriptor.quiet_summary = lambda r: f"Mobile: ✗ Issues ({result.mobile_score}/100)"

        if not result.success:
            descriptor.add_row(
                value="Failed to analyze mobile-friendliness",
                style_class="error",
                severity="error",
            )
            return descriptor

        # Overall Score
        score_style = (
            "success" if result.mobile_score >= 80
            else "warning" if result.mobile_score >= 60
            else "error"
        )
        friendly_text = "Mobile-Friendly" if result.is_mobile_friendly else "Not Mobile-Friendly"

        descriptor.add_row(
            label="Mobile Score",
            value=f"{result.mobile_score}/100 - {friendly_text}",
            style_class=score_style,
            icon="smartphone",
            section_name="Summary",
        )

        # Passed/Failed checks summary
        if result.passed_checks:
            descriptor.add_row(
                label="Passed Checks",
                value=len(result.passed_checks),
                style_class="success",
                verbosity=VerbosityLevel.VERBOSE,
                section_name="Summary",
            )

        if result.failed_checks:
            descriptor.add_row(
                label="Failed Checks",
                value=len(result.failed_checks),
                style_class="error",
                verbosity=VerbosityLevel.VERBOSE,
                section_name="Summary",
            )

        # ====================================================================
        # Viewport Section
        # ====================================================================
        if result.viewport:
            viewport = result.viewport
            descriptor.add_row(
                section_name="Viewport Configuration",
                section_type="heading",
                verbosity=VerbosityLevel.NORMAL,
            )

            if viewport.present:
                descriptor.add_row(
                    label="Viewport Meta Tag",
                    value="Present",
                    style_class="success" if not viewport.issues else "warning",
                    icon="check" if not viewport.issues else "warning",
                )

                if viewport.content:
                    descriptor.add_row(
                        label="Content",
                        value=viewport.content,
                        style_class="muted",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

                if viewport.width:
                    width_ok = viewport.width == "device-width"
                    descriptor.add_row(
                        label="Width",
                        value=viewport.width,
                        style_class="success" if width_ok else "warning",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

                if viewport.initial_scale is not None:
                    scale_ok = viewport.initial_scale == 1.0
                    descriptor.add_row(
                        label="Initial Scale",
                        value=str(viewport.initial_scale),
                        style_class="success" if scale_ok else "warning",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

                if viewport.user_scalable is False:
                    descriptor.add_row(
                        label="User Scalable",
                        value="Disabled (accessibility issue)",
                        style_class="warning",
                        icon="warning",
                    )

                for issue in viewport.issues:
                    descriptor.add_row(
                        value=f"• {issue}",
                        style_class="warning",
                        severity="warning",
                        verbosity=VerbosityLevel.NORMAL,
                    )
            else:
                descriptor.add_row(
                    label="Viewport Meta Tag",
                    value="Missing",
                    style_class="error",
                    icon="cross",
                    severity="error",
                )

        # ====================================================================
        # Touch Targets Section
        # ====================================================================
        if result.touch_targets:
            targets = result.touch_targets
            descriptor.add_row(
                section_name="Touch Targets",
                section_type="heading",
                verbosity=VerbosityLevel.NORMAL,
            )

            descriptor.add_row(
                label="Total Tap Targets",
                value=str(targets.total_tap_targets),
                verbosity=VerbosityLevel.VERBOSE,
            )

            if targets.passed:
                descriptor.add_row(
                    label="Size Check",
                    value="All targets properly sized",
                    style_class="success",
                    icon="check",
                )
            else:
                descriptor.add_row(
                    label="Size Check",
                    value=f"{len(targets.small_targets)} target(s) too small",
                    style_class="error" if len(targets.small_targets) > 5 else "warning",
                    icon="warning",
                )

                for target in targets.small_targets[:5]:
                    descriptor.add_row(
                        value=f"  • {target['tag']}: {target['width']}x{target['height']}px - \"{target['text']}\"",
                        style_class="warning",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

            if targets.close_targets:
                descriptor.add_row(
                    label="Crowded Areas",
                    value=f"{len(targets.close_targets)} area(s) with crowded targets",
                    style_class="warning",
                    verbosity=VerbosityLevel.VERBOSE,
                )

        # ====================================================================
        # Font Readability Section
        # ====================================================================
        if result.font_readability:
            fonts = result.font_readability
            descriptor.add_row(
                section_name="Font Readability",
                section_type="heading",
                verbosity=VerbosityLevel.NORMAL,
            )

            if fonts.passed:
                descriptor.add_row(
                    label="Font Sizes",
                    value="Readable on mobile",
                    style_class="success",
                    icon="check",
                )
            else:
                if fonts.smallest_font_size:
                    descriptor.add_row(
                        label="Smallest Font",
                        value=f"{fonts.smallest_font_size}px (min recommended: 12px)",
                        style_class="error" if fonts.smallest_font_size < 10 else "warning",
                        icon="warning",
                    )

                for elem in fonts.small_font_elements[:5]:
                    descriptor.add_row(
                        value=f"  • {elem['font_size']}px in <{elem['tag']}>: \"{elem['text'][:30]}\"",
                        style_class="warning",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

        # ====================================================================
        # Responsive Design Section
        # ====================================================================
        if result.responsive:
            resp = result.responsive
            descriptor.add_row(
                section_name="Responsive Design",
                section_type="heading",
                verbosity=VerbosityLevel.NORMAL,
            )

            score_style = (
                "success" if resp.responsive_score >= 60
                else "warning" if resp.responsive_score >= 30
                else "error"
            )
            descriptor.add_row(
                label="Responsive Score",
                value=f"{resp.responsive_score}/100",
                style_class=score_style,
            )

            for indicator in resp.indicators:
                descriptor.add_row(
                    value=f"✓ {indicator}",
                    style_class="success",
                    verbosity=VerbosityLevel.VERBOSE,
                )

        # ====================================================================
        # Mobile Performance Section
        # ====================================================================
        if result.performance:
            perf = result.performance
            descriptor.add_row(
                section_name="Mobile Performance",
                section_type="heading",
                verbosity=VerbosityLevel.NORMAL,
            )

            # Page size
            size_mb = perf.page_size_bytes / 1024 / 1024
            size_style = (
                "success" if size_mb < 0.5
                else "warning" if size_mb < 1.5
                else "error"
            )
            descriptor.add_row(
                label="Page Size",
                value=f"{size_mb:.2f} MB",
                style_class=size_style,
            )

            # External requests
            req_style = (
                "success" if perf.external_requests < 30
                else "warning" if perf.external_requests < 50
                else "error"
            )
            descriptor.add_row(
                label="External Requests",
                value=str(perf.external_requests),
                style_class=req_style,
                verbosity=VerbosityLevel.VERBOSE,
            )

            # Images
            descriptor.add_row(
                label="Images",
                value=str(perf.image_count),
                verbosity=VerbosityLevel.VERBOSE,
            )

            # Best practices
            if perf.uses_amp:
                descriptor.add_row(
                    label="AMP",
                    value="Using AMP",
                    style_class="success",
                    icon="check",
                )

            if perf.has_lazy_loading:
                descriptor.add_row(
                    label="Lazy Loading",
                    value="Enabled",
                    style_class="success",
                    icon="check",
                )

            for issue in perf.issues:
                descriptor.add_row(
                    value=f"• {issue}",
                    style_class="warning",
                    severity="warning",
                )

        # ====================================================================
        # Recommendations Section
        # ====================================================================
        if result.failed_checks or result.warnings:
            descriptor.add_row(
                section_name="Recommendations",
                section_type="heading",
                verbosity=VerbosityLevel.NORMAL,
            )

            for failed in result.failed_checks:
                descriptor.add_row(
                    value=f"✗ {failed}",
                    style_class="error",
                    icon="cross",
                )

            for warning in result.warnings:
                descriptor.add_row(
                    value=f"⚠ {warning}",
                    style_class="warning",
                    icon="warning",
                )

        # ====================================================================
        # Errors
        # ====================================================================
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
            )

        return descriptor

    def to_dict(self, result: MobileAnalysisResult) -> dict:
        """Serialize result to JSON-compatible dictionary."""
        def viewport_to_dict(v: ViewportResult | None) -> dict | None:
            if v is None:
                return None
            return {
                "present": v.present,
                "content": v.content,
                "width": v.width,
                "initial_scale": v.initial_scale,
                "user_scalable": v.user_scalable,
                "issues": v.issues,
            }

        def touch_targets_to_dict(t: TouchTargetResult | None) -> dict | None:
            if t is None:
                return None
            return {
                "total_tap_targets": t.total_tap_targets,
                "small_targets": t.small_targets,
                "close_targets": t.close_targets,
                "passed": t.passed,
                "issues": t.issues,
            }

        def fonts_to_dict(f: FontReadabilityResult | None) -> dict | None:
            if f is None:
                return None
            return {
                "smallest_font_size": f.smallest_font_size,
                "small_font_elements": f.small_font_elements,
                "passed": f.passed,
                "issues": f.issues,
            }

        def responsive_to_dict(r: ResponsiveResult | None) -> dict | None:
            if r is None:
                return None
            return {
                "uses_media_queries": r.uses_media_queries,
                "uses_flexbox": r.uses_flexbox,
                "uses_grid": r.uses_grid,
                "uses_viewport_units": r.uses_viewport_units,
                "has_mobile_stylesheets": r.has_mobile_stylesheets,
                "responsive_score": r.responsive_score,
                "indicators": r.indicators,
            }

        def performance_to_dict(p: MobilePerformanceResult | None) -> dict | None:
            if p is None:
                return None
            return {
                "page_size_bytes": p.page_size_bytes,
                "html_size_bytes": p.html_size_bytes,
                "image_count": p.image_count,
                "external_requests": p.external_requests,
                "uses_amp": p.uses_amp,
                "has_lazy_loading": p.has_lazy_loading,
                "issues": p.issues,
            }

        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "is_mobile_friendly": result.is_mobile_friendly,
            "mobile_score": result.mobile_score,
            "viewport": viewport_to_dict(result.viewport),
            "touch_targets": touch_targets_to_dict(result.touch_targets),
            "font_readability": fonts_to_dict(result.font_readability),
            "responsive": responsive_to_dict(result.responsive),
            "performance": performance_to_dict(result.performance),
            "passed_checks": result.passed_checks,
            "failed_checks": result.failed_checks,
            "warnings": result.warnings,
            "errors": result.errors,
        }
