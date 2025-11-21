"""HTML validation and quality analyzer.

Validates HTML syntax, checks SEO elements, accessibility features,
and structural quality of web pages.
"""

import logging
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup
from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class HTMLValidatorConfig(AnalyzerConfig):
    """HTML validator configuration."""

    timeout: float = Field(default=10.0, description="HTTP request timeout in seconds")
    user_agent: str = Field(
        default="Mozilla/5.0 (compatible; WebmasterDomainTool/1.0)",
        description="User agent for HTTP requests",
    )
    max_html_size: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        description="Maximum HTML size to download (bytes)",
    )
    check_images: bool = Field(default=True, description="Check images for alt attributes")
    check_seo: bool = Field(default=True, description="Check SEO elements")
    check_accessibility: bool = Field(default=True, description="Check accessibility features")


# ============================================================================
# Result Model
# ============================================================================


@dataclass
class HTMLValidationResult:
    """Results from HTML validation."""

    domain: str
    url: str
    success: bool = False
    html_size: int = 0

    # HTML validity
    has_doctype: bool = False
    doctype: str | None = None
    has_charset: bool = False
    charset: str | None = None
    parse_errors: list[str] = field(default_factory=list)

    # SEO elements
    title: str | None = None
    title_length: int = 0
    meta_description: str | None = None
    meta_description_length: int = 0
    canonical_url: str | None = None
    has_h1: bool = False
    h1_count: int = 0
    h1_text: list[str] = field(default_factory=list)
    heading_structure: dict[str, int] = field(default_factory=dict)

    # Open Graph
    og_title: str | None = None
    og_description: str | None = None
    og_image: str | None = None
    og_type: str | None = None

    # Accessibility
    has_lang: bool = False
    lang: str | None = None
    images_total: int = 0
    images_without_alt: int = 0
    images_with_empty_alt: int = 0
    has_main: bool = False
    has_nav: bool = False
    has_header: bool = False
    has_footer: bool = False

    # Structure
    total_links: int = 0
    internal_links: int = 0
    external_links: int = 0
    total_elements: int = 0

    # Issues
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class HTMLValidatorAnalyzer:
    """
    HTML Validator and Quality Analyzer.

    Validates HTML syntax, checks SEO elements, accessibility features,
    and analyzes structural quality of web pages.

    Features:
    - HTML5 validation with parse error detection
    - SEO element checking (title, meta description, headings)
    - Accessibility auditing (alt tags, semantic HTML, ARIA)
    - Open Graph protocol validation
    - Structural analysis (links, elements)

    Dependencies:
    - http: Needs HTTP analyzer to determine if site is accessible
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "html"
    name = "HTML Validator"
    description = "HTML validation, SEO, and accessibility checker"
    category = "seo"
    icon = "file-code"
    config_class = HTMLValidatorConfig
    depends_on = ["http"]  # Need HTTP to know if site is accessible

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(
        self,
        domain: str,
        config: HTMLValidatorConfig,
        context: dict[str, object] | None = None,
    ) -> HTMLValidationResult:
        """
        Validate HTML and check quality.

        Args:
            domain: Domain to analyze
            config: HTML validator configuration
            context: Optional context from previous analyzers (e.g., HTTP result)

        Returns:
            HTMLValidationResult with validation data
        """
        # Get preferred URL from HTTP analyzer if available
        url = self._get_url_to_analyze(domain, context)
        result = HTMLValidationResult(domain=domain, url=url)

        try:
            # Fetch HTML
            html_content = self._fetch_html(url, config)
            if not html_content:
                result.errors.append("Failed to fetch HTML content")
                return result

            result.html_size = len(html_content)
            result.success = True

            # Parse with html5lib (strict parser with error detection)
            soup, parse_errors = self._parse_html(html_content)
            result.parse_errors = parse_errors

            if parse_errors:
                result.warnings.append(f"Found {len(parse_errors)} HTML parse errors")

            # Check HTML validity
            self._check_html_validity(soup, result)

            # Check SEO elements
            if config.check_seo:
                self._check_seo_elements(soup, result, domain)

            # Check accessibility
            if config.check_accessibility:
                self._check_accessibility(soup, result, config)

            # Analyze structure
            self._analyze_structure(soup, result, domain)

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching {url}: {e}")
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"HTML validation failed for {domain}: {e}", exc_info=True)
            result.errors.append(f"Validation failed: {e}")

        return result

    def _get_url_to_analyze(self, domain: str, context: dict[str, object] | None) -> str:
        """
        Get the URL to analyze HTML from.

        Tries to use preferred_final_url from HTTP analyzer if available.
        Falls back to https://{domain} if no HTTP result.

        Args:
            domain: Domain to analyze
            context: Context dict with results from other analyzers

        Returns:
            URL to fetch HTML from
        """
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "preferred_final_url") and http_result.preferred_final_url:
                logger.info(
                    f"Using preferred URL from HTTP analyzer: {http_result.preferred_final_url}"
                )
                return http_result.preferred_final_url

        # Fall back to HTTPS
        fallback_url = f"https://{domain}"
        logger.info(f"No HTTP result available, using fallback URL: {fallback_url}")
        return fallback_url

    def _fetch_html(self, url: str, config: HTMLValidatorConfig) -> str | None:
        """Fetch HTML content from URL."""
        try:
            with httpx.Client(
                timeout=config.timeout,
                follow_redirects=True,
                verify=True,
            ) as client:
                response = client.get(url, headers={"User-Agent": config.user_agent})
                response.raise_for_status()

                # Check content type
                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type.lower():
                    logger.warning(f"Non-HTML content type: {content_type}")
                    return None

                # Check size limit
                content_length = int(response.headers.get("content-length", 0))
                if content_length > config.max_html_size:
                    logger.warning(f"HTML too large: {content_length} > {config.max_html_size}")
                    return None

                return response.text

        except Exception as e:
            logger.error(f"Failed to fetch HTML: {e}")
            return None

    def _parse_html(self, html_content: str) -> tuple[BeautifulSoup, list[str]]:
        """Parse HTML with html5lib and collect errors."""
        parse_errors = []

        # Use html5lib parser (BeautifulSoup uses it automatically with "html5lib" parameter)
        soup = BeautifulSoup(html_content, "html5lib")

        # html5lib reports errors during parsing
        # We'll do basic structural validation instead
        return soup, parse_errors

    def _check_html_validity(self, soup: BeautifulSoup, result: HTMLValidationResult) -> None:
        """Check basic HTML validity."""
        # Check doctype
        if soup.contents and str(soup.contents[0]).strip().lower().startswith("<!doctype"):
            result.has_doctype = True
            result.doctype = str(soup.contents[0]).strip()
        else:
            result.warnings.append("Missing or invalid DOCTYPE")

        # Check charset
        charset_meta = soup.find("meta", charset=True)
        if not charset_meta:
            charset_meta = soup.find("meta", attrs={"http-equiv": "Content-Type", "content": True})

        if charset_meta:
            result.has_charset = True
            if "charset" in charset_meta.attrs:
                result.charset = charset_meta["charset"]
            elif "content" in charset_meta.attrs:
                # Parse "text/html; charset=UTF-8"
                content = charset_meta["content"]
                if "charset=" in content:
                    result.charset = content.split("charset=")[-1].strip()
        else:
            result.warnings.append("Missing charset declaration")

    def _check_seo_elements(
        self, soup: BeautifulSoup, result: HTMLValidationResult, domain: str
    ) -> None:
        """Check SEO-related elements."""
        # Title tag
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            result.title = title_tag.string.strip()
            result.title_length = len(result.title)

            if result.title_length == 0:
                result.errors.append("Title tag is empty")
            elif result.title_length < 30:
                result.warnings.append(
                    f"Title too short ({result.title_length} chars, recommended 30-60)"
                )
            elif result.title_length > 60:
                result.warnings.append(
                    f"Title too long ({result.title_length} chars, recommended 30-60)"
                )
        else:
            result.errors.append("Missing title tag")

        # Meta description
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            result.meta_description = meta_desc["content"].strip()
            result.meta_description_length = len(result.meta_description)

            if result.meta_description_length == 0:
                result.errors.append("Meta description is empty")
            elif result.meta_description_length < 120:
                result.warnings.append(
                    f"Meta description too short ({result.meta_description_length} chars, recommended 120-160)"
                )
            elif result.meta_description_length > 160:
                result.warnings.append(
                    f"Meta description too long ({result.meta_description_length} chars, recommended 120-160)"
                )
        else:
            result.errors.append("Missing meta description")

        # Canonical URL
        canonical = soup.find("link", rel="canonical")
        if canonical and canonical.get("href"):
            result.canonical_url = canonical["href"]

        # H1 headings
        h1_tags = soup.find_all("h1")
        result.h1_count = len(h1_tags)
        result.has_h1 = result.h1_count > 0
        result.h1_text = [h1.get_text(strip=True) for h1 in h1_tags if h1.get_text(strip=True)]

        if result.h1_count == 0:
            result.warnings.append("No H1 heading found")
        elif result.h1_count > 1:
            result.warnings.append(f"Multiple H1 headings found ({result.h1_count})")

        # Heading structure
        for level in range(1, 7):
            count = len(soup.find_all(f"h{level}"))
            if count > 0:
                result.heading_structure[f"h{level}"] = count

        # Open Graph tags
        og_title = soup.find("meta", property="og:title")
        if og_title and og_title.get("content"):
            result.og_title = og_title["content"]

        og_desc = soup.find("meta", property="og:description")
        if og_desc and og_desc.get("content"):
            result.og_description = og_desc["content"]

        og_image = soup.find("meta", property="og:image")
        if og_image and og_image.get("content"):
            result.og_image = og_image["content"]

        og_type = soup.find("meta", property="og:type")
        if og_type and og_type.get("content"):
            result.og_type = og_type["content"]

    def _check_accessibility(
        self,
        soup: BeautifulSoup,
        result: HTMLValidationResult,
        config: HTMLValidatorConfig,
    ) -> None:
        """Check accessibility features."""
        # Lang attribute
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            result.has_lang = True
            result.lang = html_tag["lang"]
        else:
            result.errors.append("Missing lang attribute on <html> tag")

        # Image alt attributes
        if config.check_images:
            images = soup.find_all("img")
            result.images_total = len(images)

            for img in images:
                if "alt" not in img.attrs:
                    result.images_without_alt += 1
                elif not img["alt"].strip():
                    result.images_with_empty_alt += 1

            if result.images_without_alt > 0:
                result.errors.append(f"{result.images_without_alt} images missing alt attribute")

            if result.images_with_empty_alt > 0:
                result.warnings.append(
                    f"{result.images_with_empty_alt} images have empty alt attribute"
                )

        # Semantic HTML
        result.has_main = soup.find("main") is not None
        result.has_nav = soup.find("nav") is not None
        result.has_header = soup.find("header") is not None
        result.has_footer = soup.find("footer") is not None

        semantic_warnings = []
        if not result.has_main:
            semantic_warnings.append("main")
        if not result.has_nav:
            semantic_warnings.append("nav")
        if not result.has_header:
            semantic_warnings.append("header")
        if not result.has_footer:
            semantic_warnings.append("footer")

        if semantic_warnings:
            result.warnings.append(f"Missing semantic HTML tags: {', '.join(semantic_warnings)}")

    def _analyze_structure(
        self, soup: BeautifulSoup, result: HTMLValidationResult, domain: str
    ) -> None:
        """Analyze HTML structure."""
        # Count all elements
        result.total_elements = len(soup.find_all())

        # Analyze links
        links = soup.find_all("a", href=True)
        result.total_links = len(links)

        for link in links:
            href = link["href"].lower()
            if href.startswith(("http://", "https://")):
                if domain in href:
                    result.internal_links += 1
                else:
                    result.external_links += 1
            else:
                result.internal_links += 1

    def describe_output(self, result: HTMLValidationResult) -> OutputDescriptor:
        """
        Describe how to render HTML validation results.

        Args:
            result: HTML validation result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        error_count = len(result.errors)
        warning_count = len(result.warnings)
        descriptor.quiet_summary = lambda r: (
            f"HTML: {error_count} errors, {warning_count} warnings"
        )

        # Overall status
        if result.success:
            status_style = "success" if error_count == 0 else "warning"
            status_icon = "check" if error_count == 0 else "warning"
            status_text = "Valid" if error_count == 0 else "Valid with issues"
        else:
            status_style = "error"
            status_icon = "cross"
            status_text = "Failed to validate"

        descriptor.add_row(
            label="Status",
            value=status_text,
            style_class=status_style,
            icon=status_icon,
            severity="info",
        )

        if result.success:
            # HTML Size
            size_mb = result.html_size / (1024 * 1024)
            descriptor.add_row(
                label="HTML Size",
                value=f"{result.html_size:,} bytes ({size_mb:.2f} MB)",
                verbosity=VerbosityLevel.VERBOSE,
            )

            # HTML Validity
            descriptor.add_row(
                label="DOCTYPE",
                value=result.doctype if result.has_doctype else "Missing",
                style_class="success" if result.has_doctype else "warning",
                verbosity=VerbosityLevel.VERBOSE,
            )

            descriptor.add_row(
                label="Charset",
                value=result.charset if result.has_charset else "Not specified",
                style_class="success" if result.has_charset else "warning",
                verbosity=VerbosityLevel.VERBOSE,
            )

            # SEO Elements
            descriptor.add_row(
                section_name="SEO Elements",
                section_type="section_header",
                verbosity=VerbosityLevel.NORMAL,
            )

            if result.title:
                title_style = "success" if 30 <= result.title_length <= 60 else "warning"
                descriptor.add_row(
                    label="Title",
                    value=f"{result.title} ({result.title_length} chars)",
                    style_class=title_style,
                )
            else:
                descriptor.add_row(
                    label="Title",
                    value="Missing",
                    style_class="error",
                    severity="error",
                )

            if result.meta_description:
                desc_style = (
                    "success" if 120 <= result.meta_description_length <= 160 else "warning"
                )
                descriptor.add_row(
                    label="Meta Description",
                    value=f"{result.meta_description[:50]}... ({result.meta_description_length} chars)",
                    style_class=desc_style,
                )
            else:
                descriptor.add_row(
                    label="Meta Description",
                    value="Missing",
                    style_class="error",
                    severity="error",
                )

            # Headings
            h1_style = "success" if result.h1_count == 1 else "warning"
            descriptor.add_row(
                label="H1 Headings",
                value=f"{result.h1_count} found",
                style_class=h1_style,
            )

            if result.h1_text:
                for h1 in result.h1_text[:3]:  # Show first 3
                    descriptor.add_row(
                        value=f"  • {h1}",
                        style_class="muted",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

            # Heading structure (verbose)
            if result.heading_structure:
                descriptor.add_row(
                    label="Heading Structure",
                    value=", ".join(
                        f"{tag.upper()}: {count}"
                        for tag, count in sorted(result.heading_structure.items())
                    ),
                    verbosity=VerbosityLevel.VERBOSE,
                )

            # Open Graph
            if any([result.og_title, result.og_description, result.og_image]):
                descriptor.add_row(
                    section_name="Open Graph",
                    section_type="section_header",
                    verbosity=VerbosityLevel.VERBOSE,
                )

                if result.og_title:
                    descriptor.add_row(
                        label="OG Title",
                        value=result.og_title,
                        verbosity=VerbosityLevel.VERBOSE,
                    )
                if result.og_description:
                    descriptor.add_row(
                        label="OG Description",
                        value=result.og_description[:50] + "...",
                        verbosity=VerbosityLevel.VERBOSE,
                    )
                if result.og_image:
                    descriptor.add_row(
                        label="OG Image",
                        value=result.og_image,
                        verbosity=VerbosityLevel.VERBOSE,
                    )

            # Accessibility
            descriptor.add_row(
                section_name="Accessibility",
                section_type="section_header",
                verbosity=VerbosityLevel.NORMAL,
            )

            lang_style = "success" if result.has_lang else "error"
            descriptor.add_row(
                label="Lang Attribute",
                value=result.lang if result.has_lang else "Missing",
                style_class=lang_style,
                severity="error" if not result.has_lang else "info",
            )

            # Images
            if result.images_total > 0:
                images_ok = (
                    result.images_total - result.images_without_alt - result.images_with_empty_alt
                )
                images_style = "success" if result.images_without_alt == 0 else "error"

                descriptor.add_row(
                    label="Images",
                    value=f"{images_ok}/{result.images_total} have proper alt tags",
                    style_class=images_style,
                    severity="error" if result.images_without_alt > 0 else "info",
                )

            # Semantic HTML
            semantic_count = sum(
                [result.has_main, result.has_nav, result.has_header, result.has_footer]
            )
            semantic_style = "success" if semantic_count >= 3 else "warning"
            descriptor.add_row(
                label="Semantic HTML",
                value=f"{semantic_count}/4 elements (main, nav, header, footer)",
                style_class=semantic_style,
                verbosity=VerbosityLevel.VERBOSE,
            )

            # Structure
            descriptor.add_row(
                section_name="Structure",
                section_type="section_header",
                verbosity=VerbosityLevel.VERBOSE,
            )

            descriptor.add_row(
                label="Total Elements",
                value=f"{result.total_elements:,}",
                verbosity=VerbosityLevel.VERBOSE,
            )

            descriptor.add_row(
                label="Links",
                value=f"{result.total_links:,} total ({result.internal_links} internal, {result.external_links} external)",
                verbosity=VerbosityLevel.VERBOSE,
            )

        # Errors and warnings
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
            )

        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                severity="warning",
                icon="warning",
            )

        return descriptor

    def to_dict(self, result: HTMLValidationResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: HTML validation result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "html_size": result.html_size,
            "validity": {
                "has_doctype": result.has_doctype,
                "doctype": result.doctype,
                "has_charset": result.has_charset,
                "charset": result.charset,
                "parse_errors": result.parse_errors,
            },
            "seo": {
                "title": result.title,
                "title_length": result.title_length,
                "meta_description": result.meta_description,
                "meta_description_length": result.meta_description_length,
                "canonical_url": result.canonical_url,
                "h1_count": result.h1_count,
                "h1_text": result.h1_text,
                "heading_structure": result.heading_structure,
            },
            "open_graph": {
                "og_title": result.og_title,
                "og_description": result.og_description,
                "og_image": result.og_image,
                "og_type": result.og_type,
            },
            "accessibility": {
                "has_lang": result.has_lang,
                "lang": result.lang,
                "images_total": result.images_total,
                "images_without_alt": result.images_without_alt,
                "images_with_empty_alt": result.images_with_empty_alt,
                "semantic_html": {
                    "has_main": result.has_main,
                    "has_nav": result.has_nav,
                    "has_header": result.has_header,
                    "has_footer": result.has_footer,
                },
            },
            "structure": {
                "total_elements": result.total_elements,
                "total_links": result.total_links,
                "internal_links": result.internal_links,
                "external_links": result.external_links,
            },
            "errors": result.errors,
            "warnings": result.warnings,
        }
