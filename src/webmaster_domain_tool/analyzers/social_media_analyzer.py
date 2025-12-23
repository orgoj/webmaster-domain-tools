"""Social media settings analyzer.

Analyzes Open Graph, Twitter Cards, and other social media meta tags.
Validates configuration for optimal sharing on Facebook, Twitter, LinkedIn, etc.
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


class SocialMediaConfig(AnalyzerConfig):
    """Social media analyzer configuration."""

    timeout: float = Field(default=10.0, description="HTTP request timeout in seconds")
    user_agent: str = Field(
        default="Mozilla/5.0 (compatible; WebmasterDomainTool/1.0)",
        description="User agent for HTTP requests",
    )
    check_image_dimensions: bool = Field(
        default=False,
        description="Check if og:image dimensions are specified (recommended for optimal display)",
    )


# ============================================================================
# Result Model
# ============================================================================


@dataclass
class OpenGraphData:
    """Open Graph protocol data."""

    # Required
    title: str | None = None
    type: str | None = None
    image: str | None = None
    url: str | None = None

    # Optional
    description: str | None = None
    site_name: str | None = None
    locale: str | None = None

    # Image metadata
    image_secure_url: str | None = None
    image_type: str | None = None
    image_width: str | None = None
    image_height: str | None = None
    image_alt: str | None = None

    # Article metadata (if type=article)
    article_published_time: str | None = None
    article_modified_time: str | None = None
    article_author: str | None = None
    article_section: str | None = None
    article_tag: list[str] = field(default_factory=list)


@dataclass
class TwitterCardData:
    """Twitter Card data."""

    # Required
    card: str | None = None  # summary, summary_large_image, app, player

    # Optional
    site: str | None = None  # @username
    creator: str | None = None  # @username
    title: str | None = None
    description: str | None = None
    image: str | None = None
    image_alt: str | None = None


@dataclass
class SocialMediaResult:
    """Results from social media analysis."""

    domain: str
    url: str
    success: bool = False

    # Open Graph data
    og: OpenGraphData = field(default_factory=OpenGraphData)

    # Twitter Card data
    twitter: TwitterCardData = field(default_factory=TwitterCardData)

    # Validation
    has_og_required: bool = False  # Has all 4 required OG tags
    has_twitter_card: bool = False

    # Issues
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class SocialMediaAnalyzer:
    """
    Social Media Settings Analyzer.

    Analyzes Open Graph protocol tags, Twitter Cards, and other social media
    meta tags to ensure optimal display when sharing links on social platforms.

    Features:
    - Complete Open Graph validation (Facebook, LinkedIn, etc.)
    - Twitter Card detection and validation
    - Image dimension checking
    - Best practice recommendations

    Dependencies:
    - http: Needs HTTP analyzer to determine if site is accessible
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "social-media"
    name = "Social Media"
    description = "Open Graph and Twitter Cards analyzer"
    category = "seo"
    icon = "share"
    config_class = SocialMediaConfig
    depends_on = ["http"]  # Need HTTP to know if site is accessible

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(
        self,
        domain: str,
        config: SocialMediaConfig,
        context: dict[str, object] | None = None,
    ) -> SocialMediaResult:
        """
        Analyze social media meta tags.

        Args:
            domain: Domain to analyze
            config: Social media analyzer configuration
            context: Optional context from previous analyzers (e.g., HTTP result)

        Returns:
            SocialMediaResult with Open Graph and Twitter Card data
        """
        # Get preferred URL from HTTP analyzer if available
        url = self._get_url_to_analyze(domain, context)
        result = SocialMediaResult(domain=domain, url=url)

        try:
            # Fetch HTML
            html_content = self._fetch_html(url, config)
            if not html_content:
                result.errors.append("Failed to fetch HTML content")
                return result

            result.success = True

            # Parse HTML
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract Open Graph tags
            self._extract_open_graph(soup, result)

            # Extract Twitter Card tags
            self._extract_twitter_card(soup, result)

            # Validate and generate recommendations
            self._validate(result, config)

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching {url}: {e}")
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"Social media analysis failed for {domain}: {e}", exc_info=True)
            result.errors.append(f"Analysis failed: {e}")

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

    def _fetch_html(self, url: str, config: SocialMediaConfig) -> str | None:
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

                return response.text

        except Exception as e:
            logger.error(f"Failed to fetch HTML: {e}")
            return None

    def _extract_open_graph(self, soup: BeautifulSoup, result: SocialMediaResult) -> None:
        """Extract Open Graph meta tags."""
        og = result.og

        # Find all Open Graph meta tags (property="og:*")
        og_tags = soup.find_all("meta", property=lambda x: x and x.startswith("og:"))

        for tag in og_tags:
            prop = tag.get("property", "")
            content = tag.get("content", "")

            if not content:
                continue

            # Map property to field
            if prop == "og:title":
                og.title = content
            elif prop == "og:type":
                og.type = content
            elif prop == "og:image":
                og.image = content
            elif prop == "og:url":
                og.url = content
            elif prop == "og:description":
                og.description = content
            elif prop == "og:site_name":
                og.site_name = content
            elif prop == "og:locale":
                og.locale = content
            elif prop == "og:image:secure_url":
                og.image_secure_url = content
            elif prop == "og:image:type":
                og.image_type = content
            elif prop == "og:image:width":
                og.image_width = content
            elif prop == "og:image:height":
                og.image_height = content
            elif prop == "og:image:alt":
                og.image_alt = content
            elif prop == "article:published_time":
                og.article_published_time = content
            elif prop == "article:modified_time":
                og.article_modified_time = content
            elif prop == "article:author":
                og.article_author = content
            elif prop == "article:section":
                og.article_section = content
            elif prop == "article:tag":
                og.article_tag.append(content)

        # Check if all 4 required OG tags are present
        result.has_og_required = all([og.title, og.type, og.image, og.url])

    def _extract_twitter_card(self, soup: BeautifulSoup, result: SocialMediaResult) -> None:
        """Extract Twitter Card meta tags."""
        twitter = result.twitter

        # Find all Twitter Card meta tags (name="twitter:*")
        twitter_tags = soup.find_all(
            "meta", attrs={"name": lambda x: x and x.startswith("twitter:")}
        )

        for tag in twitter_tags:
            name = tag.get("name", "")
            content = tag.get("content", "")

            if not content:
                continue

            # Map name to field
            if name == "twitter:card":
                twitter.card = content
            elif name == "twitter:site":
                twitter.site = content
            elif name == "twitter:creator":
                twitter.creator = content
            elif name == "twitter:title":
                twitter.title = content
            elif name == "twitter:description":
                twitter.description = content
            elif name == "twitter:image":
                twitter.image = content
            elif name == "twitter:image:alt":
                twitter.image_alt = content

        result.has_twitter_card = twitter.card is not None

    def _validate(self, result: SocialMediaResult, config: SocialMediaConfig) -> None:
        """Validate social media configuration and generate recommendations."""
        og = result.og
        twitter = result.twitter

        # Open Graph validation
        if not result.has_og_required:
            missing = []
            if not og.title:
                missing.append("og:title")
            if not og.type:
                missing.append("og:type")
            if not og.image:
                missing.append("og:image")
            if not og.url:
                missing.append("og:url")

            if missing:
                result.errors.append(f"Missing required Open Graph tags: {', '.join(missing)}")
        else:
            # Validate Open Graph values
            if og.title:
                title_len = len(og.title)
                if title_len < 15:
                    result.warnings.append(
                        f"og:title too short ({title_len} chars, recommended 15-88)"
                    )
                elif title_len > 88:
                    result.warnings.append(
                        f"og:title too long ({title_len} chars, recommended 15-88)"
                    )

            if og.description:
                desc_len = len(og.description)
                if desc_len < 50:
                    result.warnings.append(
                        f"og:description too short ({desc_len} chars, recommended 50-300)"
                    )
                elif desc_len > 300:
                    result.warnings.append(
                        f"og:description too long ({desc_len} chars, recommended 50-300)"
                    )
            else:
                result.recommendations.append("Add og:description for better social sharing")

            if not og.site_name:
                result.recommendations.append("Add og:site_name for brand recognition")

            if og.image and config.check_image_dimensions:
                if not og.image_width or not og.image_height:
                    result.recommendations.append(
                        "Add og:image:width and og:image:height for faster rendering"
                    )

                if not og.image_alt:
                    result.recommendations.append("Add og:image:alt for accessibility")

        # Twitter Card validation
        if not result.has_twitter_card:
            result.warnings.append("No Twitter Card found (twitter:card)")
        else:
            # Validate Twitter Card type
            valid_cards = ["summary", "summary_large_image", "app", "player"]
            if twitter.card not in valid_cards:
                result.warnings.append(
                    f"Invalid twitter:card type '{twitter.card}' (valid: {', '.join(valid_cards)})"
                )

            # Check Twitter-specific fields
            if not twitter.site:
                result.recommendations.append(
                    "Add twitter:site (@username) to attribute content to your account"
                )

            # Twitter falls back to OG tags if not specified
            if not twitter.title and not og.title:
                result.warnings.append("No twitter:title or og:title found")

            if not twitter.description and not og.description:
                result.warnings.append("No twitter:description or og:description found")

            if not twitter.image and not og.image:
                result.warnings.append("No twitter:image or og:image found")

        # General recommendations
        if og.image and og.image.startswith("http://"):
            result.warnings.append(
                "og:image uses HTTP instead of HTTPS (may not display on some platforms)"
            )

        if twitter.image and twitter.image.startswith("http://"):
            result.warnings.append("twitter:image uses HTTP instead of HTTPS (may not display)")

    def describe_output(self, result: SocialMediaResult) -> OutputDescriptor:
        """
        Describe how to render social media analysis results.

        Args:
            result: Social media analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        og_status = "✓" if result.has_og_required else "✗"
        twitter_status = "✓" if result.has_twitter_card else "✗"
        descriptor.quiet_summary = lambda r: (
            f"Social Media: OG {og_status}, Twitter {twitter_status}"
        )

        # Overall status
        if result.success:
            if result.has_og_required and result.has_twitter_card:
                status_style = "success"
                status_icon = "check"
                status_text = "Configured"
            elif result.has_og_required or result.has_twitter_card:
                status_style = "warning"
                status_icon = "warning"
                status_text = "Partially configured"
            else:
                status_style = "error"
                status_icon = "cross"
                status_text = "Not configured"
        else:
            status_style = "error"
            status_icon = "cross"
            status_text = "Failed to analyze"

        descriptor.add_row(
            label="Status",
            value=status_text,
            style_class=status_style,
            icon=status_icon,
            severity="info",
        )

        if result.success:
            # Open Graph section
            og_style = "success" if result.has_og_required else "error"
            descriptor.add_row(
                label="OG Required Tags",
                value="Complete" if result.has_og_required else "Incomplete",
                style_class=og_style,
                severity="error" if not result.has_og_required else "info",
            )

            # Detailed Open Graph section (verbose)
            descriptor.add_row(
                value="Open Graph",
                section_type="heading",
                verbosity=VerbosityLevel.VERBOSE,
            )

            if result.og.title:
                descriptor.add_row(
                    label="og:title",
                    value=f"{result.og.title} ({len(result.og.title)} chars)",
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if result.og.type:
                descriptor.add_row(
                    label="og:type",
                    value=result.og.type,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if result.og.image:
                descriptor.add_row(
                    label="og:image",
                    value=result.og.image,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if result.og.url:
                descriptor.add_row(
                    label="og:url",
                    value=result.og.url,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if result.og.description:
                descriptor.add_row(
                    label="og:description",
                    value=f"{result.og.description[:60]}... ({len(result.og.description)} chars)",
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if result.og.site_name:
                descriptor.add_row(
                    label="og:site_name",
                    value=result.og.site_name,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            # Twitter Card section
            twitter_style = "success" if result.has_twitter_card else "warning"
            descriptor.add_row(
                label="Twitter Card",
                value="Configured" if result.has_twitter_card else "Not configured",
                style_class=twitter_style,
                severity="warning" if not result.has_twitter_card else "info",
            )

            # Detailed Twitter Card section (verbose)
            descriptor.add_row(
                value="Twitter Card Details",
                section_type="heading",
                verbosity=VerbosityLevel.VERBOSE,
            )

            if result.twitter.card:
                descriptor.add_row(
                    label="twitter:card",
                    value=result.twitter.card,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if result.twitter.site:
                descriptor.add_row(
                    label="twitter:site",
                    value=result.twitter.site,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if result.twitter.creator:
                descriptor.add_row(
                    label="twitter:creator",
                    value=result.twitter.creator,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            # Show fallback info if Twitter uses OG tags
            if not result.twitter.title and result.og.title:
                descriptor.add_row(
                    value="Twitter will use og:title",
                    style_class="info",
                    icon="info",
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if not result.twitter.description and result.og.description:
                descriptor.add_row(
                    value="Twitter will use og:description",
                    style_class="info",
                    icon="info",
                    verbosity=VerbosityLevel.VERBOSE,
                )

            if not result.twitter.image and result.og.image:
                descriptor.add_row(
                    value="Twitter will use og:image",
                    style_class="info",
                    icon="info",
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
            )

        # Warnings
        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                severity="warning",
                icon="warning",
            )

        # Recommendations
        for recommendation in result.recommendations:
            descriptor.add_row(
                value=recommendation,
                section_type="text",
                style_class="info",
                severity="info",
                icon="lightbulb",
                verbosity=VerbosityLevel.VERBOSE,
            )

        return descriptor

    def to_dict(self, result: SocialMediaResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Social media analysis result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "open_graph": {
                "title": result.og.title,
                "type": result.og.type,
                "image": result.og.image,
                "url": result.og.url,
                "description": result.og.description,
                "site_name": result.og.site_name,
                "locale": result.og.locale,
                "image_secure_url": result.og.image_secure_url,
                "image_type": result.og.image_type,
                "image_width": result.og.image_width,
                "image_height": result.og.image_height,
                "image_alt": result.og.image_alt,
                "article": {
                    "published_time": result.og.article_published_time,
                    "modified_time": result.og.article_modified_time,
                    "author": result.og.article_author,
                    "section": result.og.article_section,
                    "tags": result.og.article_tag,
                },
            },
            "twitter_card": {
                "card": result.twitter.card,
                "site": result.twitter.site,
                "creator": result.twitter.creator,
                "title": result.twitter.title,
                "description": result.twitter.description,
                "image": result.twitter.image,
                "image_alt": result.twitter.image_alt,
            },
            "validation": {
                "has_og_required": result.has_og_required,
                "has_twitter_card": result.has_twitter_card,
            },
            "errors": result.errors,
            "warnings": result.warnings,
            "recommendations": result.recommendations,
        }
