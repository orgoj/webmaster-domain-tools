"""SEO files analyzer - robots.txt, llms.txt, sitemap.xml checker.

This analyzer checks SEO-related files and provides insights on their configuration.
Completely self-contained with config, logic, and output formatting.
"""

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin

import httpx
from pydantic import Field

from ..core.registry import registry
from .protocol import (
    AnalyzerConfig,
    OutputDescriptor,
    VerbosityLevel,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class SEOConfig(AnalyzerConfig):
    """SEO files analyzer configuration."""

    user_agent: str = Field(
        default="Mozilla/5.0 (compatible; WebmasterDomainTool/0.1; +https://github.com/orgoj/webmaster-domain-tool)",
        description="User agent string for HTTP requests",
    )
    check_robots: bool = Field(default=True, description="Check robots.txt file")
    check_llms_txt: bool = Field(
        default=True, description="Check llms.txt file (AI crawler instructions)"
    )
    check_sitemap: bool = Field(default=True, description="Check sitemap.xml files")


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class RobotsResult:
    """Result of robots.txt analysis."""

    url: str
    exists: bool = False
    content: str | None = None
    size: int | None = None
    user_agents: list[str] = field(default_factory=list)
    disallow_rules: list[str] = field(default_factory=list)
    allow_rules: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class LLMsTxtResult:
    """Result of llms.txt analysis."""

    url: str
    exists: bool = False
    content: str | None = None
    size: int | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SitemapResult:
    """Result of sitemap.xml analysis."""

    url: str
    exists: bool = False
    is_index: bool = False  # Is this a sitemap index?
    url_count: int = 0
    sitemap_count: int = 0  # For sitemap index
    last_modified: datetime | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SEOFilesAnalysisResult:
    """Results from SEO files analysis."""

    domain: str
    robots: RobotsResult | None = None
    llms_txt: LLMsTxtResult | None = None
    sitemaps: list[SitemapResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class SEOFilesAnalyzer:
    """
    Analyzes SEO-related files (robots.txt, llms.txt, sitemap.xml).

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (SEOConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "seo"
    name = "SEO Files"
    description = "Check robots.txt, llms.txt, and sitemap.xml files"
    category = "seo"
    icon = "search"
    config_class = SEOConfig
    depends_on = ["http"]  # Needs HTTP to fetch SEO files

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: SEOConfig) -> SEOFilesAnalysisResult:
        """
        Analyze SEO files for a given domain.

        Args:
            domain: Domain to analyze (e.g., "example.com")
            config: SEO analyzer configuration

        Returns:
            SEOFilesAnalysisResult with all findings
        """
        # Construct base URL from domain
        # Assume HTTPS, fall back to HTTP if needed
        base_url = f"https://{domain}" if not domain.startswith(("http://", "https://")) else domain

        result = SEOFilesAnalysisResult(domain=domain)

        # Check robots.txt
        if config.check_robots:
            result.robots = self._check_robots_txt(base_url, config)

        # Check llms.txt
        if config.check_llms_txt:
            result.llms_txt = self._check_llms_txt(base_url, config)

        # Check sitemap.xml
        if config.check_sitemap:
            sitemap_urls = []

            # Get sitemaps from robots.txt if available
            if result.robots and result.robots.sitemaps:
                sitemap_urls.extend(result.robots.sitemaps)
            else:
                # Try default sitemap locations
                default_sitemaps = [
                    urljoin(base_url, "/sitemap.xml"),
                    urljoin(base_url, "/sitemap_index.xml"),
                ]
                sitemap_urls.extend(default_sitemaps)

            # Check each sitemap
            for sitemap_url in sitemap_urls:
                sitemap_result = self._check_sitemap(sitemap_url, config)
                if sitemap_result.exists or sitemap_result.errors:
                    result.sitemaps.append(sitemap_result)

        # Aggregate errors and warnings
        if result.robots:
            result.errors.extend(result.robots.errors)
            result.warnings.extend(result.robots.warnings)

        if result.llms_txt:
            result.errors.extend(result.llms_txt.errors)
            result.warnings.extend(result.llms_txt.warnings)

        for sitemap in result.sitemaps:
            result.errors.extend(sitemap.errors)
            result.warnings.extend(sitemap.warnings)

        return result

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _check_robots_txt(self, base_url: str, config: SEOConfig) -> RobotsResult:
        """Check robots.txt file."""
        robots_url = urljoin(base_url, "/robots.txt")
        result = RobotsResult(url=robots_url)

        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(robots_url, headers={"User-Agent": config.user_agent})

            if response.status_code == 200:
                result.exists = True
                result.content = response.text
                result.size = len(response.text)

                # Parse robots.txt
                self._parse_robots_txt(result.content, result)

                logger.info(f"robots.txt found: {robots_url} ({result.size} bytes)")
            elif response.status_code == 404:
                result.warnings.append("robots.txt not found (consider creating one)")
                logger.debug(f"robots.txt not found: {robots_url}")
            else:
                result.errors.append(f"robots.txt returned HTTP {response.status_code}")
                logger.debug(f"robots.txt error: {robots_url} - status {response.status_code}")

        except httpx.TimeoutException:
            result.errors.append(f"Timeout fetching robots.txt ({config.timeout}s)")
            logger.debug(f"Timeout fetching robots.txt: {robots_url}")
        except Exception as e:
            result.errors.append(f"Error fetching robots.txt: {str(e)}")
            logger.debug(f"Error fetching robots.txt: {robots_url} - {e}")

        return result

    def _parse_robots_txt(self, content: str, result: RobotsResult) -> None:
        """Parse robots.txt content."""
        lines = content.split("\n")

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Split on first colon
            if ":" in line:
                directive, value = line.split(":", 1)
                directive = directive.strip().lower()
                value = value.strip()

                if directive == "user-agent":
                    if value and value not in result.user_agents:
                        result.user_agents.append(value)

                elif directive == "disallow":
                    if value and value not in result.disallow_rules:
                        result.disallow_rules.append(value)

                elif directive == "allow":
                    if value and value not in result.allow_rules:
                        result.allow_rules.append(value)

                elif directive == "sitemap":
                    if value and value not in result.sitemaps:
                        result.sitemaps.append(value)

    def _check_llms_txt(self, base_url: str, config: SEOConfig) -> LLMsTxtResult:
        """Check /llms.txt file (new standard for AI crawlers)."""
        llms_url = urljoin(base_url, "/llms.txt")
        result = LLMsTxtResult(url=llms_url)

        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(llms_url, headers={"User-Agent": config.user_agent})

            if response.status_code == 200:
                result.exists = True
                result.content = response.text
                result.size = len(response.text)
                logger.info(f"llms.txt found: {llms_url} ({result.size} bytes)")
            elif response.status_code == 404:
                # Not an error - llms.txt is optional
                logger.debug(f"llms.txt not found: {llms_url}")
            else:
                result.warnings.append(f"llms.txt returned HTTP {response.status_code}")
                logger.debug(f"llms.txt warning: {llms_url} - status {response.status_code}")

        except httpx.TimeoutException:
            result.warnings.append(f"Timeout fetching llms.txt ({config.timeout}s)")
            logger.debug(f"Timeout fetching llms.txt: {llms_url}")
        except Exception as e:
            result.warnings.append(f"Error fetching llms.txt: {str(e)}")
            logger.debug(f"Error fetching llms.txt: {llms_url} - {e}")

        return result

    def _check_sitemap(self, sitemap_url: str, config: SEOConfig) -> SitemapResult:
        """Check sitemap.xml file."""
        result = SitemapResult(url=sitemap_url)

        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(sitemap_url, headers={"User-Agent": config.user_agent})

            if response.status_code == 200:
                result.exists = True

                # Try to parse XML
                try:
                    root = ET.fromstring(response.content)

                    # Get namespace
                    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

                    # Check if it's a sitemap index
                    if root.tag.endswith("sitemapindex"):
                        result.is_index = True
                        sitemaps = root.findall("sm:sitemap", namespace)
                        result.sitemap_count = len(sitemaps)
                        logger.info(
                            f"Sitemap index found: {sitemap_url} ({result.sitemap_count} sitemaps)"
                        )

                    # Regular sitemap
                    elif root.tag.endswith("urlset"):
                        urls = root.findall("sm:url", namespace)
                        result.url_count = len(urls)

                        # Get last modification date
                        lastmod_elements = root.findall(".//sm:lastmod", namespace)
                        if lastmod_elements:
                            try:
                                lastmod_text = lastmod_elements[0].text
                                result.last_modified = datetime.fromisoformat(
                                    lastmod_text.replace("Z", "+00:00")
                                )
                            except Exception:
                                pass

                        logger.info(f"Sitemap found: {sitemap_url} ({result.url_count} URLs)")

                        # Error if sitemap is empty
                        if result.url_count == 0:
                            result.errors.append("Sitemap is empty (0 URLs)")
                        # Warn if sitemap is very large
                        elif result.url_count > 50000:
                            result.warnings.append(
                                f"Sitemap has {result.url_count} URLs (max recommended: 50,000)"
                            )

                    else:
                        result.errors.append(f"Unknown sitemap format: {root.tag}")

                except ET.ParseError as e:
                    result.errors.append(f"Failed to parse sitemap XML: {str(e)}")
                    logger.debug(f"Sitemap XML parse error: {sitemap_url} - {e}")

            elif response.status_code == 404:
                # Not necessarily an error if it's a default location
                logger.debug(f"Sitemap not found: {sitemap_url}")
            else:
                result.errors.append(f"Sitemap returned HTTP {response.status_code}")
                logger.debug(f"Sitemap error: {sitemap_url} - status {response.status_code}")

        except httpx.TimeoutException:
            result.errors.append(f"Timeout fetching sitemap ({config.timeout}s)")
            logger.debug(f"Timeout fetching sitemap: {sitemap_url}")
        except Exception as e:
            result.errors.append(f"Error fetching sitemap: {str(e)}")
            logger.debug(f"Error fetching sitemap: {sitemap_url} - {e}")

        return result

    def describe_output(self, result: SEOFilesAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: SEO files analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        files_found = []
        if result.robots and result.robots.exists:
            files_found.append("robots.txt")
        if result.llms_txt and result.llms_txt.exists:
            files_found.append("llms.txt")
        if result.sitemaps:
            sitemap_count = len([s for s in result.sitemaps if s.exists])
            if sitemap_count > 0:
                files_found.append(f"{sitemap_count} sitemap(s)")

        descriptor.quiet_summary = lambda r: (
            f"SEO: {', '.join(files_found)}" if files_found else "SEO: No files"
        )

        # ====================================================================
        # robots.txt Section
        # ====================================================================
        if result.robots:
            robots = result.robots

            if robots.exists:
                # robots.txt found
                descriptor.add_row(
                    label="robots.txt",
                    value="Found",
                    style_class="success",
                    icon="check",
                    severity="info",
                    verbosity=VerbosityLevel.NORMAL,
                    section_name="robots.txt",
                )

                descriptor.add_row(
                    label="Size",
                    value=f"{robots.size} bytes",
                    style_class="info",
                    severity="info",
                    verbosity=VerbosityLevel.NORMAL,
                    section_name="robots.txt",
                )

                # User agents
                if robots.user_agents:
                    descriptor.add_row(
                        label="User Agents",
                        value=robots.user_agents,
                        section_type="list",
                        style_class="info",
                        verbosity=VerbosityLevel.VERBOSE,
                        section_name="robots.txt",
                    )

                # Disallow rules
                if robots.disallow_rules:
                    descriptor.add_row(
                        label="Disallow Rules",
                        value=robots.disallow_rules[:10],  # Show first 10
                        section_type="list",
                        style_class="warning",
                        verbosity=VerbosityLevel.VERBOSE,
                        section_name="robots.txt",
                    )
                    if len(robots.disallow_rules) > 10:
                        descriptor.add_row(
                            value=f"... and {len(robots.disallow_rules) - 10} more disallow rules",
                            section_type="text",
                            style_class="muted",
                            verbosity=VerbosityLevel.VERBOSE,
                            section_name="robots.txt",
                        )

                # Allow rules
                if robots.allow_rules:
                    descriptor.add_row(
                        label="Allow Rules",
                        value=robots.allow_rules,
                        section_type="list",
                        style_class="success",
                        verbosity=VerbosityLevel.VERBOSE,
                        section_name="robots.txt",
                    )

                # Sitemaps declared in robots.txt
                if robots.sitemaps:
                    descriptor.add_row(
                        label="Sitemaps Declared",
                        value=robots.sitemaps,
                        section_type="list",
                        style_class="info",
                        verbosity=VerbosityLevel.NORMAL,
                        section_name="robots.txt",
                    )
            else:
                # robots.txt not found or error
                if robots.warnings:
                    descriptor.add_row(
                        label="robots.txt",
                        value="Not found",
                        style_class="warning",
                        icon="warning",
                        severity="warning",
                        verbosity=VerbosityLevel.NORMAL,
                        section_name="robots.txt",
                    )

        # ====================================================================
        # llms.txt Section
        # ====================================================================
        if result.llms_txt:
            llms = result.llms_txt

            if llms.exists:
                descriptor.add_row(
                    label="llms.txt",
                    value="Found",
                    style_class="success",
                    icon="check",
                    severity="info",
                    verbosity=VerbosityLevel.NORMAL,
                    section_name="llms.txt",
                )

                descriptor.add_row(
                    label="Size",
                    value=f"{llms.size} bytes",
                    style_class="info",
                    severity="info",
                    verbosity=VerbosityLevel.VERBOSE,
                    section_name="llms.txt",
                )

                # Show content preview in debug mode
                if llms.content:
                    preview = (
                        llms.content[:200] + "..." if len(llms.content) > 200 else llms.content
                    )
                    descriptor.add_row(
                        label="Content Preview",
                        value=preview,
                        style_class="muted",
                        verbosity=VerbosityLevel.DEBUG,
                        section_name="llms.txt",
                    )
            else:
                descriptor.add_row(
                    label="llms.txt",
                    value="Not found (optional)",
                    style_class="muted",
                    severity="info",
                    verbosity=VerbosityLevel.VERBOSE,
                    section_name="llms.txt",
                )

        # ====================================================================
        # Sitemap Section
        # ====================================================================
        if result.sitemaps:
            existing_sitemaps = [s for s in result.sitemaps if s.exists]

            if existing_sitemaps:
                descriptor.add_row(
                    label="Sitemaps Found",
                    value=f"{len(existing_sitemaps)} sitemap(s)",
                    style_class="success",
                    icon="check",
                    severity="info",
                    verbosity=VerbosityLevel.NORMAL,
                    section_name="Sitemaps",
                )

                # Details for each sitemap
                for sitemap in existing_sitemaps:
                    if sitemap.is_index:
                        descriptor.add_row(
                            label="Sitemap Index",
                            value=f"{sitemap.url} ({sitemap.sitemap_count} sitemaps)",
                            style_class="info",
                            verbosity=VerbosityLevel.VERBOSE,
                            section_name="Sitemaps",
                        )
                    else:
                        descriptor.add_row(
                            label="Sitemap",
                            value=f"{sitemap.url} ({sitemap.url_count} URLs)",
                            style_class="info",
                            verbosity=VerbosityLevel.VERBOSE,
                            section_name="Sitemaps",
                        )

                        if sitemap.last_modified:
                            descriptor.add_row(
                                label="Last Modified",
                                value=sitemap.last_modified.strftime("%Y-%m-%d %H:%M:%S"),
                                style_class="muted",
                                verbosity=VerbosityLevel.DEBUG,
                                section_name="Sitemaps",
                            )
            else:
                descriptor.add_row(
                    label="Sitemaps",
                    value="Not found",
                    style_class="warning",
                    icon="warning",
                    severity="warning",
                    verbosity=VerbosityLevel.NORMAL,
                    section_name="Sitemaps",
                )

        # ====================================================================
        # Errors and Warnings
        # ====================================================================
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
                verbosity=VerbosityLevel.NORMAL,
            )

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

    def to_dict(self, result: SEOFilesAnalysisResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: SEO files analysis result

        Returns:
            JSON-serializable dict
        """
        output = {
            "domain": result.domain,
            "errors": result.errors,
            "warnings": result.warnings,
        }

        # robots.txt
        if result.robots:
            output["robots_txt"] = {
                "url": result.robots.url,
                "exists": result.robots.exists,
                "size": result.robots.size,
                "user_agents": result.robots.user_agents,
                "disallow_rules": result.robots.disallow_rules,
                "allow_rules": result.robots.allow_rules,
                "sitemaps": result.robots.sitemaps,
                "errors": result.robots.errors,
                "warnings": result.robots.warnings,
            }

        # llms.txt
        if result.llms_txt:
            output["llms_txt"] = {
                "url": result.llms_txt.url,
                "exists": result.llms_txt.exists,
                "size": result.llms_txt.size,
                "content": result.llms_txt.content,
                "errors": result.llms_txt.errors,
                "warnings": result.llms_txt.warnings,
            }

        # Sitemaps
        if result.sitemaps:
            output["sitemaps"] = [
                {
                    "url": s.url,
                    "exists": s.exists,
                    "is_index": s.is_index,
                    "url_count": s.url_count,
                    "sitemap_count": s.sitemap_count,
                    "last_modified": s.last_modified.isoformat() if s.last_modified else None,
                    "errors": s.errors,
                    "warnings": s.warnings,
                }
                for s in result.sitemaps
            ]

        return output
