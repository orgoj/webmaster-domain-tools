"""SEO files analyzer - robots.txt, llms.txt, sitemap.xml checker."""

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx

from .base import BaseAnalysisResult, BaseAnalyzer

logger = logging.getLogger(__name__)


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
class SEOFilesAnalysisResult(BaseAnalysisResult):
    """Results from SEO files analysis."""

    robots: RobotsResult | None = None
    llms_txt: LLMsTxtResult | None = None
    sitemaps: list[SitemapResult] = field(default_factory=list)


class SEOFilesAnalyzer(BaseAnalyzer[SEOFilesAnalysisResult]):
    """Analyzes SEO-related files (robots.txt, llms.txt, sitemap.xml)."""

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str | None = None,
        check_robots: bool = True,
        check_llms_txt: bool = True,
        check_sitemap: bool = True,
    ):
        """
        Initialize SEO files analyzer.

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
            check_robots: Check robots.txt
            check_llms_txt: Check /llms.txt
            check_sitemap: Check sitemap.xml
        """
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (compatible; WebmasterDomainTool/0.1; +https://github.com/orgoj/webmaster-domain-tool)"
        )
        self.check_robots = check_robots
        self.check_llms_txt = check_llms_txt
        self.check_sitemap = check_sitemap

    def analyze(self, base_url: str) -> SEOFilesAnalysisResult:
        """
        Analyze SEO files for a given base URL.

        Args:
            base_url: Base URL to check (e.g., "https://example.com")

        Returns:
            SEOFilesAnalysisResult with all findings
        """
        # Extract domain for result
        parsed = urlparse(base_url)
        domain = parsed.netloc or base_url

        result = SEOFilesAnalysisResult(domain=domain)

        # Check robots.txt
        if self.check_robots:
            result.robots = self._check_robots_txt(base_url)

        # Check llms.txt
        if self.check_llms_txt:
            result.llms_txt = self._check_llms_txt(base_url)

        # Check sitemap.xml
        if self.check_sitemap:
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
                sitemap_result = self._check_sitemap(sitemap_url)
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

    def _check_robots_txt(self, base_url: str) -> RobotsResult:
        """Check robots.txt file."""
        robots_url = urljoin(base_url, "/robots.txt")
        result = RobotsResult(url=robots_url)

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(robots_url, headers={"User-Agent": self.user_agent})

            if response.status_code == 200:
                result.exists = True
                result.content = response.text
                result.size = len(response.text)

                # Parse robots.txt
                self._parse_robots_txt(result.content, result)

                logger.info(f"robots.txt found: {robots_url} ({result.size} bytes)")
            elif response.status_code == 404:
                result.warnings.append("robots.txt not found (consider creating one)")
                logger.warning(f"robots.txt not found: {robots_url}")
            else:
                result.errors.append(f"robots.txt returned HTTP {response.status_code}")
                logger.error(f"robots.txt error: {robots_url} - status {response.status_code}")

        except httpx.TimeoutException:
            result.errors.append(f"Timeout fetching robots.txt ({self.timeout}s)")
            logger.error(f"Timeout fetching robots.txt: {robots_url}")
        except Exception as e:
            result.errors.append(f"Error fetching robots.txt: {str(e)}")
            logger.error(f"Error fetching robots.txt: {robots_url} - {e}")

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

    def _check_llms_txt(self, base_url: str) -> LLMsTxtResult:
        """Check /llms.txt file (new standard for AI crawlers)."""
        llms_url = urljoin(base_url, "/llms.txt")
        result = LLMsTxtResult(url=llms_url)

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(llms_url, headers={"User-Agent": self.user_agent})

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
                logger.warning(f"llms.txt warning: {llms_url} - status {response.status_code}")

        except httpx.TimeoutException:
            result.warnings.append(f"Timeout fetching llms.txt ({self.timeout}s)")
            logger.warning(f"Timeout fetching llms.txt: {llms_url}")
        except Exception as e:
            result.warnings.append(f"Error fetching llms.txt: {str(e)}")
            logger.warning(f"Error fetching llms.txt: {llms_url} - {e}")

        return result

    def _check_sitemap(self, sitemap_url: str) -> SitemapResult:
        """Check sitemap.xml file."""
        result = SitemapResult(url=sitemap_url)

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(sitemap_url, headers={"User-Agent": self.user_agent})

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

                        # Warn if sitemap is very large
                        if result.url_count > 50000:
                            result.warnings.append(
                                f"Sitemap has {result.url_count} URLs (max recommended: 50,000)"
                            )

                    else:
                        result.errors.append(f"Unknown sitemap format: {root.tag}")

                except ET.ParseError as e:
                    result.errors.append(f"Failed to parse sitemap XML: {str(e)}")
                    logger.error(f"Sitemap XML parse error: {sitemap_url} - {e}")

            elif response.status_code == 404:
                # Not necessarily an error if it's a default location
                logger.debug(f"Sitemap not found: {sitemap_url}")
            else:
                result.errors.append(f"Sitemap returned HTTP {response.status_code}")
                logger.error(f"Sitemap error: {sitemap_url} - status {response.status_code}")

        except httpx.TimeoutException:
            result.errors.append(f"Timeout fetching sitemap ({self.timeout}s)")
            logger.error(f"Timeout fetching sitemap: {sitemap_url}")
        except Exception as e:
            result.errors.append(f"Error fetching sitemap: {str(e)}")
            logger.error(f"Error fetching sitemap: {sitemap_url} - {e}")

        return result
