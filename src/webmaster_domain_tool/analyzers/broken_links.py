"""Broken links analyzer for detecting dead links on websites.

Crawls a website and checks all links for HTTP errors:
- 4xx client errors (404, 410, etc.)
- 5xx server errors
- Timeouts
- DNS resolution failures
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class BrokenLinksConfig(AnalyzerConfig):
    """Broken links analyzer configuration."""

    timeout: float = Field(default=10.0, description="HTTP request timeout in seconds")
    max_pages: int = Field(default=100, description="Maximum pages to crawl")
    max_links_per_page: int = Field(default=100, description="Maximum links to extract per page")
    max_links_to_check: int = Field(default=500, description="Maximum total links to check")
    concurrent_requests: int = Field(default=5, description="Maximum concurrent HTTP requests")
    user_agent: str = Field(
        default="Mozilla/5.0 (compatible; WebmasterDomainTool/1.0 Broken Links Checker)",
        description="User agent for HTTP requests",
    )
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    check_external: bool = Field(default=True, description="Check external links (not just same domain)")
    respect_robots: bool = Field(default=True, description="Skip links disallowed by robots.txt")


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class BrokenLink:
    """Represents a single broken link."""

    url: str
    status_code: int | None = None
    error_type: str | None = None  # "timeout", "dns", "connection", "ssl", "http"
    error_message: str | None = None
    link_text: str | None = None
    source_page: str | None = None
    is_internal: bool = True


@dataclass
class CrawlStats:
    """Statistics about the crawl process."""

    pages_crawled: int = 0
    total_links_found: int = 0
    links_checked: int = 0
    links_skipped: int = 0
    crawl_time_seconds: float = 0.0


@dataclass
class BrokenLinksResult:
    """Results from broken links analysis."""

    domain: str
    url: str = ""
    success: bool = False
    timestamp: str = ""
    
    # Summary stats
    total_links: int = 0
    broken_links_count: int = 0
    internal_broken: int = 0
    external_broken: int = 0
    redirects_found: int = 0
    
    # Detailed results
    broken_links_list: list[BrokenLink] = field(default_factory=list)
    crawl_stats: CrawlStats | None = None
    
    # Status
    pages_crawled: int = 0
    links_checked: int = 0
    
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class BrokenLinksAnalyzer:
    """
    Broken Links Analyzer.

    Crawls a website and checks all links for broken status:
    - 4xx client errors (404 Not Found, 410 Gone, etc.)
    - 5xx server errors
    - Connection timeouts
    - DNS resolution failures

    Features:
    - Respects max pages limit to avoid excessive crawling
    - Checks both internal and external links
    - Uses HEAD requests first, falls back to GET
    - Ignores mailto:, tel:, javascript:, and anchor links

    Dependencies:
    - http: Optional, uses HTTP analyzer to determine URL
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "broken-links"
    name = "Broken Links"
    description = "Check for broken (dead) links on the website"
    category = "seo"
    icon = "link"
    config_class = BrokenLinksConfig
    depends_on = ["http"]

    # Link schemes to ignore
    IGNORED_SCHEMES = {"mailto:", "tel:", "javascript:", "ftp:", "file:", "data:", "#"}

    def analyze(
        self,
        domain: str,
        config: BrokenLinksConfig,
        context: dict[str, object] | None = None,
    ) -> BrokenLinksResult:
        """
        Analyze a website for broken links.

        Args:
            domain: Domain to analyze
            config: Broken links analyzer configuration
            context: Context from previous analyzers

        Returns:
            BrokenLinksResult with all broken link findings
        """
        url = self._get_url_to_analyze(domain, context)
        result = BrokenLinksResult(
            domain=domain,
            url=url,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

        start_time = time.time()
        crawl_stats = CrawlStats()

        try:
            # Get base URL for determining internal vs external links
            parsed_base = urlparse(url)
            base_domain = parsed_base.netloc.lower()

            # Track visited pages and found links
            visited_pages: set[str] = set()
            all_links: dict[str, BrokenLink] = {}  # url -> BrokenLink info
            pages_to_crawl: deque[str] = deque([url])

            # Crawl pages
            while pages_to_crawl and crawl_stats.pages_crawled < config.max_pages:
                current_page = pages_to_crawl.popleft()
                
                if current_page in visited_pages:
                    continue
                    
                visited_pages.add(current_page)
                crawl_stats.pages_crawled += 1

                # Fetch and parse page
                html_content = self._fetch_page(current_page, config)
                if not html_content:
                    continue

                soup = BeautifulSoup(html_content, "html.parser")
                
                # Extract links from this page
                links_found = self._extract_links(soup, current_page, base_domain, config)
                
                for link_info in links_found:
                    link_url = link_info.url
                    
                    # Track all unique links
                    if link_url not in all_links:
                        all_links[link_url] = link_info
                        crawl_stats.total_links_found += 1
                    
                    # Add internal links to crawl queue
                    if link_info.is_internal and link_url not in visited_pages:
                        pages_to_crawl.append(link_url)

            # Check all collected links
            crawl_stats.links_checked = min(len(all_links), config.max_links_to_check)
            links_to_check = list(all_links.items())[:config.max_links_to_check]
            
            for link_url, link_info in links_to_check:
                # Skip ignored schemes
                if self._should_skip_link(link_url):
                    crawl_stats.links_skipped += 1
                    continue
                
                # Check link status
                is_broken, status_code, error_type, error_msg = self._check_link(link_url, config)
                
                if is_broken:
                    link_info.status_code = status_code
                    link_info.error_type = error_type
                    link_info.error_message = error_msg
                    result.broken_links_list.append(link_info)
                    
                    if link_info.is_internal:
                        result.internal_broken += 1
                    else:
                        result.external_broken += 1
                
                # Track redirects (3xx status)
                elif status_code and 300 <= status_code < 400:
                    result.redirects_found += 1

            # Calculate summary
            result.total_links = crawl_stats.total_links_found
            result.broken_links_count = len(result.broken_links_list)
            result.pages_crawled = crawl_stats.pages_crawled
            result.links_checked = crawl_stats.links_checked
            result.success = True

            crawl_stats.crawl_time_seconds = time.time() - start_time
            result.crawl_stats = crawl_stats

            # Add warnings for limits reached
            if crawl_stats.pages_crawled >= config.max_pages:
                result.warnings.append(f"Reached max page limit ({config.max_pages}). Some pages may not be checked.")
            if crawl_stats.total_links_found > config.max_links_to_check:
                result.warnings.append(f"Found {crawl_stats.total_links_found} links but only checked {config.max_links_to_check} due to limit.")

        except Exception as e:
            logger.error(f"Broken links analysis failed for {domain}: {e}", exc_info=True)
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

    def _fetch_page(self, url: str, config: BrokenLinksConfig) -> str | None:
        """Fetch page HTML content."""
        try:
            with httpx.Client(
                timeout=config.timeout,
                follow_redirects=config.follow_redirects,
            ) as client:
                response = client.get(
                    url,
                    headers={"User-Agent": config.user_agent},
                )
                response.raise_for_status()
                
                # Only parse HTML content
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" in content_type:
                    return response.text
                return None
                
        except httpx.HTTPError as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return None

    def _extract_links(
        self,
        soup: BeautifulSoup,
        source_page: str,
        base_domain: str,
        config: BrokenLinksConfig,
    ) -> list[BrokenLink]:
        """Extract all links from a page."""
        links = []
        
        for i, anchor in enumerate(soup.find_all("a", href=True, limit=config.max_links_per_page)):
            href = anchor.get("href", "").strip()
            
            # Skip empty or ignored schemes
            if not href or self._should_skip_link(href):
                continue
            
            # Resolve relative URLs
            absolute_url = urljoin(source_page, href)
            
            # Parse and validate URL
            parsed = urlparse(absolute_url)
            if not parsed.scheme or not parsed.netloc:
                continue
            
            # Skip non-HTTP(S) URLs
            if parsed.scheme not in ("http", "https"):
                continue
            
            # Determine if internal or external
            is_internal = parsed.netloc.lower() == base_domain
            
            # Get link text
            link_text = anchor.get_text(strip=True) or anchor.get("title", "") or None
            if link_text:
                link_text = link_text[:100]  # Truncate long text
            
            links.append(BrokenLink(
                url=absolute_url,
                link_text=link_text,
                source_page=source_page,
                is_internal=is_internal,
            ))
        
        return links

    def _should_skip_link(self, url: str) -> bool:
        """Check if a link should be skipped."""
        url_lower = url.lower().strip()
        
        # Skip ignored schemes
        for scheme in self.IGNORED_SCHEMES:
            if url_lower.startswith(scheme):
                return True
        
        # Skip anchor-only links
        if url_lower.startswith("#"):
            return True
            
        return False

    def _check_link(
        self,
        url: str,
        config: BrokenLinksConfig,
    ) -> tuple[bool, int | None, str | None, str | None]:
        """
        Check if a link is broken.
        
        Returns:
            Tuple of (is_broken, status_code, error_type, error_message)
        """
        try:
            with httpx.Client(
                timeout=config.timeout,
                follow_redirects=False,  # Don't follow for status check
            ) as client:
                # Try HEAD request first (faster, less bandwidth)
                try:
                    response = client.head(
                        url,
                        headers={"User-Agent": config.user_agent},
                        follow_redirects=True,
                    )
                    status_code = response.status_code
                    
                    # Check if broken (4xx or 5xx)
                    if 400 <= status_code < 600:
                        return True, status_code, "http", f"HTTP {status_code}"
                    
                    return False, status_code, None, None
                    
                except httpx.HTTPStatusError as e:
                    status_code = e.response.status_code
                    if 400 <= status_code < 600:
                        return True, status_code, "http", f"HTTP {status_code}"
                    return False, status_code, None, None
                    
                except httpx.TimeoutException:
                    # HEAD timed out, try GET as some servers don't support HEAD
                    pass
            
            # Fallback to GET request
            with httpx.Client(
                timeout=config.timeout,
                follow_redirects=True,
            ) as client:
                response = client.get(
                    url,
                    headers={"User-Agent": config.user_agent},
                )
                status_code = response.status_code
                
                if 400 <= status_code < 600:
                    return True, status_code, "http", f"HTTP {status_code}"
                
                return False, status_code, None, None
                
        except httpx.TimeoutException:
            return True, None, "timeout", f"Request timed out after {config.timeout}s"
            
        except httpx.ConnectError as e:
            error_msg = str(e).lower()
            if "dns" in error_msg or "name or service not known" in error_msg:
                return True, None, "dns", f"DNS resolution failed for {urlparse(url).netloc}"
            return True, None, "connection", f"Connection failed: {e}"
            
        except httpx.ConnectTimeout:
            return True, None, "timeout", f"Connection timed out after {config.timeout}s"
            
        except httpx.ReadTimeout:
            return True, None, "timeout", f"Read timed out after {config.timeout}s"
            
        except httpx.SSLError as e:
            return True, None, "ssl", f"SSL/TLS error: {e}"
            
        except Exception as e:
            logger.debug(f"Unexpected error checking {url}: {e}")
            return False, None, None, None  # Don't mark as broken for unexpected errors

    def describe_output(self, result: BrokenLinksResult) -> OutputDescriptor:
        """Describe how to render broken links results."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        if result.broken_links_count == 0:
            descriptor.quiet_summary = lambda r: f"Broken Links: ✓ None found ({result.links_checked} checked)"
        else:
            descriptor.quiet_summary = lambda r: f"Broken Links: ✗ {result.broken_links_count} broken"

        if not result.success:
            descriptor.add_row(
                value="Failed to analyze broken links",
                style_class="error",
                severity="error",
            )
            return descriptor

        # Summary section
        descriptor.add_row(
            section_name="Summary",
            section_type="heading",
        )

        # Overall status
        if result.broken_links_count == 0:
            descriptor.add_row(
                label="Status",
                value=f"✓ All links working ({result.links_checked} checked)",
                style_class="success",
                icon="check",
            )
        else:
            descriptor.add_row(
                label="Status",
                value=f"✗ {result.broken_links_count} broken link(s) found",
                style_class="error",
                icon="cross",
            )

        # Stats
        descriptor.add_row(
            label="Pages Crawled",
            value=str(result.pages_crawled),
            verbosity=VerbosityLevel.VERBOSE,
        )
        descriptor.add_row(
            label="Links Checked",
            value=str(result.links_checked),
            verbosity=VerbosityLevel.VERBOSE,
        )
        
        if result.redirects_found > 0:
            descriptor.add_row(
                label="Redirects",
                value=str(result.redirects_found),
                style_class="info",
                verbosity=VerbosityLevel.VERBOSE,
            )

        # Broken down by type
        if result.broken_links_count > 0:
            descriptor.add_row(
                label="Internal Broken",
                value=str(result.internal_broken),
                style_class="error" if result.internal_broken > 0 else "muted",
            )
            descriptor.add_row(
                label="External Broken",
                value=str(result.external_broken),
                style_class="error" if result.external_broken > 0 else "muted",
            )

        # Broken links list
        if result.broken_links_list:
            descriptor.add_row(
                section_name="Broken Links",
                section_type="heading",
            )

            for link in result.broken_links_list[:20]:  # Limit to 20 in output
                # Determine error description
                if link.status_code:
                    error_desc = f"HTTP {link.status_code}"
                elif link.error_type:
                    error_desc = link.error_message or link.error_type.title()
                else:
                    error_desc = "Unknown error"

                # Format link info
                link_type = "internal" if link.is_internal else "external"
                label_text = link.link_text if link.link_text else "(no text)"
                
                descriptor.add_row(
                    label=f"[{link_type}] {error_desc}",
                    value=link.url,
                    style_class="error",
                    icon="cross",
                    verbosity=VerbosityLevel.NORMAL,
                )
                
                if link.source_page:
                    descriptor.add_row(
                        value=f"  Found on: {link.source_page}",
                        style_class="muted",
                        verbosity=VerbosityLevel.VERBOSE,
                    )
                    if link.link_text:
                        descriptor.add_row(
                            value=f"  Link text: \"{label_text}\"",
                            style_class="muted",
                            verbosity=VerbosityLevel.DEBUG,
                        )

            if len(result.broken_links_list) > 20:
                descriptor.add_row(
                    value=f"  ... and {len(result.broken_links_list) - 20} more broken links",
                    style_class="muted",
                    verbosity=VerbosityLevel.NORMAL,
                )

        # Crawl stats (verbose)
        if result.crawl_stats:
            descriptor.add_row(
                section_name="Crawl Statistics",
                section_type="heading",
                verbosity=VerbosityLevel.VERBOSE,
            )
            descriptor.add_row(
                label="Crawl Time",
                value=f"{result.crawl_stats.crawl_time_seconds:.2f}s",
                verbosity=VerbosityLevel.VERBOSE,
            )
            descriptor.add_row(
                label="Total Links Found",
                value=str(result.crawl_stats.total_links_found),
                verbosity=VerbosityLevel.VERBOSE,
            )
            descriptor.add_row(
                label="Links Skipped",
                value=str(result.crawl_stats.links_skipped),
                verbosity=VerbosityLevel.VERBOSE,
            )

        # Warnings and errors
        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                icon="warning",
            )

        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
            )

        return descriptor

    def to_dict(self, result: BrokenLinksResult) -> dict:
        """Serialize result to JSON-compatible dictionary."""
        return {
            "analyzer": "broken_links",
            "timestamp": result.timestamp,
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "summary": {
                "total_links": result.total_links,
                "broken_links": result.broken_links_count,
                "internal_broken": result.internal_broken,
                "external_broken": result.external_broken,
                "redirects_found": result.redirects_found,
            },
            "details": {
                "pages_crawled": result.pages_crawled,
                "links_checked": result.links_checked,
                "broken_links_list": [
                    {
                        "url": link.url,
                        "status_code": link.status_code,
                        "error_type": link.error_type,
                        "error_message": link.error_message,
                        "link_text": link.link_text,
                        "source_page": link.source_page,
                        "is_internal": link.is_internal,
                    }
                    for link in result.broken_links_list
                ],
            },
            "crawl_stats": {
                "pages_crawled": result.crawl_stats.pages_crawled if result.crawl_stats else 0,
                "total_links_found": result.crawl_stats.total_links_found if result.crawl_stats else 0,
                "links_checked": result.crawl_stats.links_checked if result.crawl_stats else 0,
                "links_skipped": result.crawl_stats.links_skipped if result.crawl_stats else 0,
                "crawl_time_seconds": round(result.crawl_stats.crawl_time_seconds, 2) if result.crawl_stats else 0,
            },
            "errors": result.errors,
            "warnings": result.warnings,
        }
