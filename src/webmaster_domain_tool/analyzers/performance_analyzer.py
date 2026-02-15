"""Performance analysis module.

Measures page load performance, resource sizes, and optimization opportunities.
"""

import logging
import time
from dataclasses import dataclass, field

import httpx
from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class PerformanceConfig(AnalyzerConfig):
    """Performance analyzer configuration."""

    timeout: float = Field(default=30.0, description="HTTP request timeout in seconds")
    user_agent: str = Field(
        default="Mozilla/5.0 (compatible; WebmasterDomainTool/1.0)",
        description="User agent for HTTP requests",
    )
    check_http2: bool = Field(default=True, description="Check HTTP/2 support")
    check_http3: bool = Field(default=True, description="Check HTTP/3 support")
    measure_ttfb: bool = Field(default=True, description="Measure Time to First Byte")
    analyze_resources: bool = Field(default=True, description="Analyze resource sizes")
    max_resources: int = Field(default=50, description="Maximum resources to analyze")


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class ResourceInfo:
    """Information about a loaded resource."""

    url: str
    resource_type: str  # html, css, js, image, font, other
    size_bytes: int = 0
    load_time_ms: float = 0.0
    status_code: int = 0
    from_cache: bool = False


@dataclass
class PerformanceResult:
    """Results from performance analysis."""

    domain: str
    url: str = ""
    success: bool = False

    # Core metrics
    ttfb_ms: float = 0.0  # Time to First Byte
    total_load_time_ms: float = 0.0
    html_size_bytes: int = 0

    # HTTP protocol
    http_version: str = ""  # HTTP/1.1, HTTP/2, HTTP/3
    supports_http2: bool = False
    supports_http3: bool = False

    # Resources
    total_requests: int = 0
    resources: list[ResourceInfo] = field(default_factory=list)

    # Size breakdown
    total_size_bytes: int = 0
    html_size: int = 0
    css_size: int = 0
    js_size: int = 0
    image_size: int = 0
    font_size: int = 0
    other_size: int = 0

    # Performance score (0-100)
    performance_score: int = 0

    # Issues
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class PerformanceAnalyzer:
    """
    Performance Analyzer.

    Measures page load performance, resource sizes, and identifies
    optimization opportunities.

    Features:
    - Time to First Byte (TTFB) measurement
    - HTTP/2 and HTTP/3 support detection
    - Resource size breakdown (HTML, CSS, JS, images, fonts)
    - Performance scoring

    Dependencies:
    - http: Needs HTTP analyzer to determine preferred URL
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "performance"
    name = "Performance Analysis"
    description = "Page load performance and resource analysis"
    category = "performance"
    icon = "gauge"
    config_class = PerformanceConfig
    depends_on = ["http"]

    # ========================================================================
    # Protocol Methods
    # ========================================================================

    def analyze(
        self,
        domain: str,
        config: PerformanceConfig,
        context: dict[str, object] | None = None,
    ) -> PerformanceResult:
        """
        Analyze page performance.

        Args:
            domain: Domain to analyze
            config: Performance analyzer configuration
            context: Context from previous analyzers

        Returns:
            PerformanceResult with performance metrics
        """
        url = self._get_url_to_analyze(domain, context)
        result = PerformanceResult(domain=domain, url=url)

        try:
            # Measure TTFB and load HTML
            self._measure_performance(url, config, result)

            if result.success and config.analyze_resources:
                # Parse HTML and find linked resources
                self._analyze_resources(url, config, result)

            # Calculate performance score
            self._calculate_score(result)

        except httpx.HTTPError as e:
            logger.error(f"HTTP error analyzing {url}: {e}")
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"Performance analysis failed for {domain}: {e}", exc_info=True)
            result.errors.append(f"Analysis failed: {e}")

        return result

    def _get_url_to_analyze(self, domain: str, context: dict[str, object] | None) -> str:
        """Get URL to analyze from context or fallback."""
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "preferred_final_url") and http_result.preferred_final_url:
                return http_result.preferred_final_url
        return f"https://{domain}"

    def _measure_performance(
        self, url: str, config: PerformanceConfig, result: PerformanceResult
    ) -> None:
        """Measure TTFB and initial page load."""
        start_time = time.time()

        try:
            with httpx.Client(
                timeout=config.timeout,
                follow_redirects=True,
                verify=True,
                http2=config.check_http2,
            ) as client:
                # Measure TTFB
                with client.stream("GET", url, headers={"User-Agent": config.user_agent}) as response:
                    # TTFB is when we start receiving response
                    ttfb_time = time.time()
                    result.ttfb_ms = (ttfb_time - start_time) * 1000

                    # Get HTTP version
                    result.http_version = getattr(response, "http_version", "HTTP/1.1")
                    result.supports_http2 = result.http_version == "HTTP/2"

                    # Read content
                    content = response.read()
                    result.total_load_time_ms = (time.time() - start_time) * 1000
                    result.html_size_bytes = len(content)
                    result.html_size = len(content)
                    result.total_size_bytes = len(content)
                    result.total_requests = 1
                    result.success = True

                    # Add HTML as a resource
                    result.resources.append(ResourceInfo(
                        url=url,
                        resource_type="html",
                        size_bytes=len(content),
                        load_time_ms=result.total_load_time_ms,
                        status_code=response.status_code,
                    ))

                    # Check headers for optimization hints
                    self._check_headers(response.headers, result)

        except Exception as e:
            logger.error(f"Failed to measure performance: {e}")
            raise

    def _check_headers(self, headers: dict, result: PerformanceResult) -> None:
        """Check response headers for performance hints."""
        # Check compression
        content_encoding = headers.get("content-encoding", "").lower()
        if content_encoding in ("gzip", "br", "deflate"):
            pass  # Good - compression enabled
        else:
            result.warnings.append("No compression detected (Content-Encoding header missing)")

        # Check caching
        cache_control = headers.get("cache-control", "")
        if not cache_control:
            result.warnings.append("No Cache-Control header - resources won't be cached efficiently")

        # Check for server timing
        server_timing = headers.get("server-timing", "")
        if server_timing:
            logger.debug(f"Server timing: {server_timing}")

    def _analyze_resources(
        self, url: str, config: PerformanceConfig, result: PerformanceResult
    ) -> None:
        """Analyze linked resources (CSS, JS, images)."""
        try:
            # Fetch HTML content
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(url, headers={"User-Agent": config.user_agent})
                html_content = response.text

            # Simple regex-based resource extraction (avoid full HTML parsing)
            import re

            base_url = url.rsplit("/", 1)[0] if "/" in url.split("//", 1)[1] else url

            # Find CSS files
            css_pattern = r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']'
            css_urls = re.findall(css_pattern, html_content, re.IGNORECASE)

            # Find JS files
            js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
            js_urls = re.findall(js_pattern, html_content, re.IGNORECASE)

            # Find images
            img_pattern = r'<img[^>]+src=["\']([^"\']+\.(jpg|jpeg|png|gif|webp|svg|ico)[^"\']*)["\']'
            img_matches = re.findall(img_pattern, html_content, re.IGNORECASE)
            img_urls = [m[0] for m in img_matches]

            # Limit resources to check
            all_resources = (
                [(u, "css") for u in css_urls[:config.max_resources]] +
                [(u, "js") for u in js_urls[:config.max_resources]] +
                [(u, "image") for u in img_urls[:config.max_resources]]
            )

            # Check each resource
            for resource_url, res_type in all_resources[:config.max_resources]:
                # Convert relative URLs to absolute
                if resource_url.startswith("//"):
                    resource_url = "https:" + resource_url
                elif resource_url.startswith("/"):
                    resource_url = base_url + resource_url
                elif not resource_url.startswith(("http://", "https://")):
                    resource_url = base_url + "/" + resource_url

                # Skip data URLs and inline resources
                if resource_url.startswith(("data:", "javascript:", "#")):
                    continue

                try:
                    start = time.time()
                    head_response = client.head(
                        resource_url,
                        headers={"User-Agent": config.user_agent},
                        timeout=5.0,
                        follow_redirects=True,
                    )
                    load_time = (time.time() - start) * 1000

                    size = 0
                    if "content-length" in head_response.headers:
                        try:
                            size = int(head_response.headers["content-length"])
                        except ValueError:
                            pass

                    result.resources.append(ResourceInfo(
                        url=resource_url,
                        resource_type=res_type,
                        size_bytes=size,
                        load_time_ms=load_time,
                        status_code=head_response.status_code,
                    ))

                    # Update size totals
                    if res_type == "css":
                        result.css_size += size
                    elif res_type == "js":
                        result.js_size += size
                    elif res_type == "image":
                        result.image_size += size

                    result.total_size_bytes += size
                    result.total_requests += 1

                except Exception as e:
                    logger.debug(f"Failed to check resource {resource_url}: {e}")

        except Exception as e:
            logger.warning(f"Failed to analyze resources: {e}")

    def _calculate_score(self, result: PerformanceResult) -> None:
        """Calculate overall performance score (0-100)."""
        score = 100

        # TTFB scoring (ideal: <200ms, acceptable: <500ms, slow: <1000ms)
        if result.ttfb_ms > 1000:
            score -= 25
        elif result.ttfb_ms > 500:
            score -= 15
        elif result.ttfb_ms > 200:
            score -= 5

        # Total load time scoring (ideal: <1s, acceptable: <3s, slow: <5s)
        if result.total_load_time_ms > 5000:
            score -= 25
        elif result.total_load_time_ms > 3000:
            score -= 15
        elif result.total_load_time_ms > 1000:
            score -= 5

        # Page size scoring (ideal: <500KB, acceptable: <1MB, large: <2MB)
        total_kb = result.total_size_bytes / 1024
        if total_kb > 2048:  # 2MB
            score -= 20
        elif total_kb > 1024:  # 1MB
            score -= 10
        elif total_kb > 512:  # 512KB
            score -= 5

        # HTTP/2 bonus
        if result.supports_http2:
            score += 5  # Bonus, can exceed 100

        # Too many requests penalty
        if result.total_requests > 50:
            score -= 10
        elif result.total_requests > 30:
            score -= 5

        # Clamp score
        result.performance_score = max(0, min(100, score))

        # Add warnings based on score
        if result.performance_score < 50:
            result.warnings.append(f"Performance score is poor ({result.performance_score}/100)")
        elif result.performance_score < 75:
            result.warnings.append(f"Performance score could be improved ({result.performance_score}/100)")

        # Specific warnings
        if result.ttfb_ms > 1000:
            result.warnings.append(f"Slow Time to First Byte: {result.ttfb_ms:.0f}ms (should be <500ms)")

        if result.total_size_bytes > 2 * 1024 * 1024:
            result.warnings.append(f"Large page size: {result.total_size_bytes / (1024*1024):.1f}MB")

        if result.js_size > 500 * 1024:
            result.warnings.append(f"Large JavaScript bundle: {result.js_size / 1024:.0f}KB")

    def describe_output(self, result: PerformanceResult) -> OutputDescriptor:
        """Describe how to render performance results."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        descriptor.quiet_summary = lambda r: f"Performance: {result.performance_score}/100"

        # Overall score
        score_style = (
            "error" if result.performance_score < 50
            else "warning" if result.performance_score < 75
            else "success"
        )
        score_icon = (
            "cross" if result.performance_score < 50
            else "warning" if result.performance_score < 75
            else "check"
        )

        descriptor.add_row(
            label="Performance Score",
            value=f"{result.performance_score}/100",
            style_class=score_style,
            icon=score_icon,
            severity="info",
        )

        if not result.success:
            descriptor.add_row(
                value="Failed to analyze performance",
                style_class="error",
                severity="error",
            )
            return descriptor

        # Core Metrics
        descriptor.add_row(
            section_name="Core Metrics",
            section_type="heading",
            verbosity=VerbosityLevel.NORMAL,
        )

        # TTFB
        ttfb_style = (
            "error" if result.ttfb_ms > 1000
            else "warning" if result.ttfb_ms > 500
            else "success"
        )
        descriptor.add_row(
            label="Time to First Byte",
            value=f"{result.ttfb_ms:.0f}ms",
            style_class=ttfb_style,
            icon="timer",
        )

        # Total load time
        load_style = (
            "error" if result.total_load_time_ms > 3000
            else "warning" if result.total_load_time_ms > 1000
            else "success"
        )
        descriptor.add_row(
            label="Total Load Time",
            value=f"{result.total_load_time_ms:.0f}ms",
            style_class=load_style,
        )

        # HTTP Version
        descriptor.add_row(
            label="HTTP Version",
            value=result.http_version or "HTTP/1.1",
            style_class="success" if result.supports_http2 else "warning",
        )

        # Resource Summary
        descriptor.add_row(
            section_name="Resources",
            section_type="heading",
            verbosity=VerbosityLevel.NORMAL,
        )

        descriptor.add_row(
            label="Total Requests",
            value=str(result.total_requests),
        )

        # Size breakdown
        total_kb = result.total_size_bytes / 1024
        descriptor.add_row(
            label="Total Size",
            value=f"{total_kb:.1f}KB" if total_kb < 1024 else f"{total_kb/1024:.1f}MB",
        )

        # Detailed size breakdown (verbose)
        if result.css_size > 0:
            descriptor.add_row(
                label="CSS",
                value=f"{result.css_size/1024:.1f}KB",
                verbosity=VerbosityLevel.VERBOSE,
            )
        if result.js_size > 0:
            descriptor.add_row(
                label="JavaScript",
                value=f"{result.js_size/1024:.1f}KB",
                verbosity=VerbosityLevel.VERBOSE,
            )
        if result.image_size > 0:
            descriptor.add_row(
                label="Images",
                value=f"{result.image_size/1024:.1f}KB",
                verbosity=VerbosityLevel.VERBOSE,
            )

        # Resource list (debug)
        for res in result.resources[:10]:
            res_size = f"{res.size_bytes/1024:.1f}KB" if res.size_bytes > 0 else "unknown"
            descriptor.add_row(
                value=f"  • [{res.resource_type}] {res.url[:60]}... ({res_size})",
                verbosity=VerbosityLevel.DEBUG,
                style_class="muted",
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

    def to_dict(self, result: PerformanceResult) -> dict:
        """Serialize result to JSON-compatible dictionary."""
        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "performance_score": result.performance_score,
            "core_metrics": {
                "ttfb_ms": round(result.ttfb_ms, 2),
                "total_load_time_ms": round(result.total_load_time_ms, 2),
                "http_version": result.http_version,
                "supports_http2": result.supports_http2,
            },
            "resources": {
                "total_requests": result.total_requests,
                "total_size_bytes": result.total_size_bytes,
                "breakdown": {
                    "html_bytes": result.html_size,
                    "css_bytes": result.css_size,
                    "js_bytes": result.js_size,
                    "image_bytes": result.image_size,
                },
            },
            "resource_list": [
                {
                    "url": r.url,
                    "type": r.resource_type,
                    "size_bytes": r.size_bytes,
                    "load_time_ms": round(r.load_time_ms, 2),
                    "status_code": r.status_code,
                }
                for r in result.resources
            ],
            "errors": result.errors,
            "warnings": result.warnings,
        }
