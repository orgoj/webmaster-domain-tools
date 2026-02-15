"""Core Web Vitals analysis module.

Analyzes Core Web Vitals metrics using Google PageSpeed Insights API:
- LCP (Largest Contentful Paint)
- INP (Interaction to Next Paint) - replaces FID
- CLS (Cumulative Layout Shift)

Also includes additional performance metrics from PageSpeed.
"""

import logging
import time
from dataclasses import dataclass, field

import httpx
from pydantic import Field, field_validator

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)

# Google PageSpeed Insights API endpoint (free, no API key required for basic usage)
PAGESPEED_API_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"


# ============================================================================
# Configuration
# ============================================================================


class CoreWebVitalsConfig(AnalyzerConfig):
    """Core Web Vitals analyzer configuration."""

    timeout: float = Field(default=30.0, description="API request timeout in seconds")
    api_key: str | None = Field(
        default=None,
        description="Google API key (optional, increases quota)",
    )
    strategy: str = Field(
        default="desktop",
        description="Analysis strategy: desktop or mobile",
    )
    locale: str = Field(
        default="en",
        description="Locale for results",
    )

    @field_validator("strategy")
    @classmethod
    def validate_strategy(cls, v: str) -> str:
        """Validate that strategy is either 'desktop' or 'mobile'."""
        if v not in ("desktop", "mobile"):
            raise ValueError("strategy must be 'desktop' or 'mobile'")
        return v


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class MetricResult:
    """Individual metric result."""

    name: str
    display_name: str
    value: float
    unit: str = "ms"
    score: float | None = None  # 0-1 normalized score
    rating: str = "unknown"  # good, needs-improvement, poor
    threshold_good: float | None = None
    threshold_bad: float | None = None


@dataclass
class CoreWebVitalsResult:
    """Results from Core Web Vitals analysis."""

    domain: str
    url: str = ""
    success: bool = False
    api_response_time_ms: float = 0.0

    # Core Web Vitals (field data from CrUX)
    lcp: MetricResult | None = None  # Largest Contentful Paint
    inp: MetricResult | None = None  # Interaction to Next Paint (replaces FID)
    cls: MetricResult | None = None  # Cumulative Layout Shift
    fid: MetricResult | None = None  # First Input Delay (legacy, still reported)
    ttfb: MetricResult | None = None  # Time to First Byte
    fcp: MetricResult | None = None  # First Contentful Paint

    # Lab data (Lighthouse)
    lab_data: dict = field(default_factory=dict)

    # Performance score (0-100)
    performance_score: int | None = None

    # Opportunities and diagnostics
    opportunities: list[dict] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)

    # Issues
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class CoreWebVitalsAnalyzer:
    """
    Core Web Vitals Analyzer.

    Uses Google PageSpeed Insights API to measure Core Web Vitals:
    - LCP (Largest Contentful Paint): Load time of largest content
    - INP (Interaction to Next Paint): Responsiveness metric
    - CLS (Cumulative Layout Shift): Visual stability

    Features:
    - Field data from Chrome User Experience Report (CrUX)
    - Lab data from Lighthouse
    - Performance optimization opportunities
    - Desktop and mobile analysis

    Dependencies:
    - http: Optional, uses HTTP analyzer to determine URL
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "core-web-vitals"
    name = "Core Web Vitals"
    description = "Google Core Web Vitals performance metrics (LCP, INP, CLS)"
    category = "performance"
    icon = "speed"
    config_class = CoreWebVitalsConfig
    depends_on = []

    # ========================================================================
    # Protocol Methods
    # ========================================================================

    def analyze(
        self,
        domain: str,
        config: CoreWebVitalsConfig,
        context: dict[str, object] | None = None,
    ) -> CoreWebVitalsResult:
        """
        Analyze Core Web Vitals using PageSpeed Insights API.

        Args:
            domain: Domain to analyze
            config: Core Web Vitals analyzer configuration
            context: Context from previous analyzers

        Returns:
            CoreWebVitalsResult with performance metrics
        """
        url = self._get_url_to_analyze(domain, context)
        result = CoreWebVitalsResult(domain=domain, url=url)

        try:
            # Fetch data from PageSpeed API
            pagespeed_data = self._fetch_pagespeed_data(url, config, result)

            if pagespeed_data:
                result.success = True
                # Parse Core Web Vitals from CrUX data
                self._parse_field_data(pagespeed_data, result)
                # Parse Lighthouse lab data
                self._parse_lab_data(pagespeed_data, result)
                # Parse opportunities and diagnostics
                self._parse_opportunities(pagespeed_data, result)

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error from PageSpeed API for {url}: {e}")
            result.errors.append(f"PageSpeed API error: {e.response.status_code}")
        except httpx.HTTPError as e:
            logger.error(f"HTTP error analyzing {url}: {e}")
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"Core Web Vitals analysis failed for {domain}: {e}", exc_info=True)
            result.errors.append(f"Analysis failed: {e}")

        return result

    def _get_url_to_analyze(self, domain: str, context: dict[str, object] | None) -> str:
        """Get URL to analyze from context or fallback."""
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "preferred_final_url") and http_result.preferred_final_url:
                return http_result.preferred_final_url
        return f"https://{domain}"

    def _fetch_pagespeed_data(
        self,
        url: str,
        config: CoreWebVitalsConfig,
        result: CoreWebVitalsResult,
    ) -> dict | None:
        """Fetch data from Google PageSpeed Insights API."""
        params = {
            "url": url,
            "strategy": config.strategy,
            "locale": config.locale,
            "category": "performance",
        }

        # Add API key if available
        if config.api_key:
            params["key"] = config.api_key

        start_time = time.time()

        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(PAGESPEED_API_URL, params=params)
                response.raise_for_status()
                result.api_response_time_ms = (time.time() - start_time) * 1000
                return response.json()

        except httpx.HTTPStatusError as e:
            # Handle quota exceeded
            if e.response.status_code == 429:
                result.warnings.append("PageSpeed API quota exceeded. Try again later or use an API key.")
            raise

    def _parse_field_data(self, data: dict, result: CoreWebVitalsResult) -> None:
        """Parse Core Web Vitals field data from CrUX."""
        try:
            # Navigate to loadingExperience (CrUX field data)
            loading_exp = data.get("loadingExperience", {})
            metrics = loading_exp.get("metrics", {})

            if not metrics:
                result.warnings.append("No field data available (CrUX) - site may have insufficient traffic")
                return

            # Parse LCP
            result.lcp = self._parse_metric(metrics, "LARGEST_CONTENTFUL_PAINT_MS", "LCP", "ms")

            # Parse INP (new metric, may not be available for all sites)
            inp_metric = metrics.get("INTERACTION_TO_NEXT_PAINT")
            if inp_metric:
                result.inp = self._parse_metric(metrics, "INTERACTION_TO_NEXT_PAINT", "INP", "ms")
            else:
                # Fall back to FID if INP is not available
                result.fid = self._parse_metric(metrics, "FIRST_INPUT_DELAY_MS", "FID", "ms")
                if result.fid:
                    result.warnings.append("Using legacy FID metric (INP not available)")

            # Parse CLS
            result.cls = self._parse_metric(metrics, "CUMULATIVE_LAYOUT_SHIFT_SCORE", "CLS", "")

            # Parse FCP
            result.fcp = self._parse_metric(metrics, "FIRST_CONTENTFUL_PAINT_MS", "FCP", "ms")

            # Parse TTFB
            result.ttfb = self._parse_metric(metrics, "EXPERIMENTAL_TIME_TO_FIRST_BYTE_MS", "TTFB", "ms")

        except Exception as e:
            logger.warning(f"Failed to parse field data: {e}")
            result.warnings.append(f"Could not parse field data: {e}")

    def _parse_metric(
        self,
        metrics: dict,
        metric_key: str,
        display_name: str,
        unit: str,
    ) -> MetricResult | None:
        """Parse a single metric from the metrics dict."""
        try:
            metric = metrics.get(metric_key, {})
            if not metric:
                return None

            # Get percentile value (usually p75)
            percentile = metric.get("percentile", {})
            value = percentile.get("percentile", 0)

            # Get category/rating
            category = metric.get("category", "UNKNOWN").lower().replace("_", "-")

            # Get thresholds
            distributions = metric.get("distributions", [])
            thresholds = self._extract_thresholds(distributions)

            return MetricResult(
                name=metric_key,
                display_name=display_name,
                value=float(value),
                unit=unit,
                rating=category,
                threshold_good=thresholds.get("good"),
                threshold_bad=thresholds.get("bad"),
            )

        except Exception as e:
            logger.debug(f"Failed to parse metric {metric_key}: {e}")
            return None

    def _extract_thresholds(self, distributions: list) -> dict:
        """Extract good/bad thresholds from distributions."""
        thresholds = {}
        try:
            if len(distributions) >= 2:
                # First distribution min is usually the good threshold
                thresholds["good"] = distributions[0].get("min")
                # Second distribution min is usually the bad threshold
                if len(distributions) >= 3:
                    thresholds["bad"] = distributions[2].get("min")
        except Exception:
            pass
        return thresholds

    def _parse_lab_data(self, data: dict, result: CoreWebVitalsResult) -> None:
        """Parse Lighthouse lab data."""
        try:
            lighthouse = data.get("lighthouseResult", {})
            if not lighthouse:
                return

            # Performance score
            categories = lighthouse.get("categories", {})
            perf_category = categories.get("performance", {})
            if perf_category:
                score = perf_category.get("score")
                if score is not None:
                    result.performance_score = int(score * 100)

            # Audits (detailed metrics)
            audits = lighthouse.get("audits", {})

            # Extract key lab metrics
            lab_metrics = [
                ("largest-contentful-paint", "lcp"),
                ("total-blocking-time", "tbt"),
                ("cumulative-layout-shift", "cls"),
                ("first-contentful-paint", "fcp"),
                ("speed-index", "speed-index"),
                ("interactive", "tti"),
            ]

            for audit_id, metric_name in lab_metrics:
                audit = audits.get(audit_id, {})
                if audit:
                    result.lab_data[metric_name] = {
                        "value": audit.get("numericValue"),
                        "score": audit.get("score"),
                        "display_value": audit.get("displayValue"),
                    }

        except Exception as e:
            logger.warning(f"Failed to parse lab data: {e}")

    def _parse_opportunities(self, data: dict, result: CoreWebVitalsResult) -> None:
        """Parse optimization opportunities and diagnostics."""
        try:
            lighthouse = data.get("lighthouseResult", {})
            audits = lighthouse.get("audits", {})

            # Find opportunities (savings available)
            for audit_id, audit in audits.items():
                details = audit.get("details", {})
                if details.get("type") == "opportunity":
                    savings = audit.get("numericValue", 0)
                    if savings > 0:
                        result.opportunities.append({
                            "id": audit_id,
                            "title": audit.get("title", audit_id),
                            "description": audit.get("description", ""),
                            "savings_ms": savings,
                            "display_value": audit.get("displayValue", ""),
                        })

                # Diagnostics
                elif details.get("type") == "table" and audit.get("score") is not None:
                    if audit.get("score") < 1:  # Not perfect
                        result.diagnostics.append({
                            "id": audit_id,
                            "title": audit.get("title", audit_id),
                            "description": audit.get("description", ""),
                            "score": audit.get("score"),
                        })

        except Exception as e:
            logger.warning(f"Failed to parse opportunities: {e}")

    def describe_output(self, result: CoreWebVitalsResult) -> OutputDescriptor:
        """Describe how to render Core Web Vitals results."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        descriptor.quiet_summary = lambda r: f"Core Web Vitals: {'✓' if self._all_vitals_good(r) else '✗'}"

        if not result.success:
            descriptor.add_row(
                value="Failed to analyze Core Web Vitals",
                style_class="error",
                severity="error",
            )
            return descriptor

        # Core Web Vitals Header
        descriptor.add_row(
            section_name="Core Web Vitals (Field Data)",
            section_type="heading",
            verbosity=VerbosityLevel.NORMAL,
        )

        # LCP
        if result.lcp:
            descriptor.add_row(
                label="LCP (Largest Contentful Paint)",
                value=self._format_metric(result.lcp),
                style_class=self._get_rating_style(result.lcp.rating),
                icon=self._get_rating_icon(result.lcp.rating) if result.lcp else "timer",
            )
            descriptor.add_row(
                value=f"  Target: ≤2.5s (good), ≤4.0s (needs improvement)",
                style_class="muted",
                verbosity=VerbosityLevel.VERBOSE,
            )

        # INP or FID
        if result.inp:
            descriptor.add_row(
                label="INP (Interaction to Next Paint)",
                value=self._format_metric(result.inp),
                style_class=self._get_rating_style(result.inp.rating),
                icon=self._get_rating_icon(result.inp.rating),
            )
            descriptor.add_row(
                value=f"  Target: ≤200ms (good), ≤500ms (needs improvement)",
                style_class="muted",
                verbosity=VerbosityLevel.VERBOSE,
            )
        elif result.fid:
            descriptor.add_row(
                label="FID (First Input Delay)",
                value=self._format_metric(result.fid),
                style_class=self._get_rating_style(result.fid.rating),
                icon="timer",
            )
            descriptor.add_row(
                value=f"  Legacy metric (INP preferred)",
                style_class="muted",
                verbosity=VerbosityLevel.VERBOSE,
            )

        # CLS
        if result.cls:
            descriptor.add_row(
                label="CLS (Cumulative Layout Shift)",
                value=f"{result.cls.value:.3f}" if result.cls.unit == "" else self._format_metric(result.cls),
                style_class=self._get_rating_style(result.cls.rating),
                icon=self._get_rating_icon(result.cls.rating),
            )
            descriptor.add_row(
                value=f"  Target: ≤0.1 (good), ≤0.25 (needs improvement)",
                style_class="muted",
                verbosity=VerbosityLevel.VERBOSE,
            )

        # Performance Score
        if result.performance_score is not None:
            descriptor.add_row(
                section_name="Performance Score",
                section_type="heading",
                verbosity=VerbosityLevel.NORMAL,
            )

            score_style = (
                "error" if result.performance_score < 50
                else "warning" if result.performance_score < 90
                else "success"
            )
            descriptor.add_row(
                label="Lighthouse Score",
                value=f"{result.performance_score}/100",
                style_class=score_style,
                icon="gauge",
            )

        # Lab Data (Verbose)
        if result.lab_data:
            descriptor.add_row(
                section_name="Lab Data (Lighthouse)",
                section_type="heading",
                verbosity=VerbosityLevel.VERBOSE,
            )

            for metric_name, data in result.lab_data.items():
                display_value = data.get("display_value", "")
                if display_value:
                    descriptor.add_row(
                        label=metric_name.replace("-", " ").title(),
                        value=display_value,
                        verbosity=VerbosityLevel.VERBOSE,
                    )

        # Top Opportunities (if any)
        if result.opportunities:
            descriptor.add_row(
                section_name="Optimization Opportunities",
                section_type="heading",
                verbosity=VerbosityLevel.NORMAL,
            )

            # Sort by savings
            sorted_opps = sorted(result.opportunities, key=lambda x: x.get("savings_ms", 0), reverse=True)

            for opp in sorted_opps[:5]:  # Top 5
                savings = opp.get("display_value", "")
                descriptor.add_row(
                    label=opp.get("title", ""),
                    value=f"Save {savings}" if savings else "",
                    style_class="info",
                    icon="lightning",
                )

        # Diagnostics (Debug)
        if result.diagnostics:
            descriptor.add_row(
                section_name="Diagnostics",
                section_type="heading",
                verbosity=VerbosityLevel.DEBUG,
            )

            for diag in result.diagnostics[:5]:
                descriptor.add_row(
                    value=f"• {diag.get('title', '')}",
                    style_class="muted",
                    verbosity=VerbosityLevel.DEBUG,
                )

        # API info (Debug)
        descriptor.add_row(
            section_name="API Info",
            section_type="heading",
            verbosity=VerbosityLevel.DEBUG,
        )
        descriptor.add_row(
            label="API Response Time",
            value=f"{result.api_response_time_ms:.0f}ms",
            verbosity=VerbosityLevel.DEBUG,
        )
        descriptor.add_row(
            label="Source",
            value="Google PageSpeed Insights API",
            verbosity=VerbosityLevel.DEBUG,
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

    def _format_metric(self, metric: MetricResult) -> str:
        """Format a metric value with rating indicator."""
        rating_icon = {
            "good": "✓",
            "needs-improvement": "⚠",
            "poor": "✗",
            "unknown": "?",
        }.get(metric.rating, "?")

        if metric.unit == "ms":
            value_str = f"{metric.value:.0f}ms"
        elif metric.unit == "":
            value_str = f"{metric.value:.3f}"
        else:
            value_str = f"{metric.value}{metric.unit}"

        return f"{rating_icon} {value_str}"

    def _get_rating_style(self, rating: str) -> str:
        """Get style class for rating."""
        return {
            "good": "success",
            "needs-improvement": "warning",
            "poor": "error",
            "unknown": "muted",
        }.get(rating, "muted")

    def _get_rating_icon(self, rating: str) -> str:
        """Get icon for rating."""
        return {
            "good": "check",
            "needs-improvement": "warning",
            "poor": "cross",
            "unknown": "question",
        }.get(rating, "question")

    def _all_vitals_good(self, result: CoreWebVitalsResult) -> bool:
        """Check if all Core Web Vitals are good."""
        vitals = [result.lcp, result.inp or result.fid, result.cls]
        for vital in vitals:
            if vital is None or vital.rating != "good":
                return False
        return True

    def to_dict(self, result: CoreWebVitalsResult) -> dict:
        """Serialize result to JSON-compatible dictionary."""
        def metric_to_dict(m: MetricResult | None) -> dict | None:
            if m is None:
                return None
            return {
                "name": m.name,
                "display_name": m.display_name,
                "value": m.value,
                "unit": m.unit,
                "score": m.score,
                "rating": m.rating,
            }

        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "performance_score": result.performance_score,
            "core_web_vitals": {
                "lcp": metric_to_dict(result.lcp),
                "inp": metric_to_dict(result.inp),
                "fid": metric_to_dict(result.fid),
                "cls": metric_to_dict(result.cls),
                "fcp": metric_to_dict(result.fcp),
                "ttfb": metric_to_dict(result.ttfb),
            },
            "lab_data": result.lab_data,
            "opportunities": result.opportunities,
            "diagnostics": result.diagnostics,
            "api_response_time_ms": round(result.api_response_time_ms, 2),
            "errors": result.errors,
            "warnings": result.warnings,
        }
