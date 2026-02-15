"""Lighthouse analyzer module.

Comprehensive website analysis using Google Lighthouse via PageSpeed Insights API:
- Performance score
- Accessibility score
- Best Practices score
- SEO score

Provides detailed audit results and recommendations for improvement.
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


class LighthouseConfig(AnalyzerConfig):
    """Lighthouse analyzer configuration."""

    timeout: float = Field(default=60.0, description="API request timeout in seconds")
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
    categories: list[str] = Field(
        default=["performance", "accessibility", "best-practices", "seo"],
        description="Categories to analyze",
    )

    @field_validator("strategy")
    @classmethod
    def validate_strategy(cls, v: str) -> str:
        """Validate that strategy is either 'desktop' or 'mobile'."""
        if v not in ("desktop", "mobile"):
            raise ValueError("strategy must be 'desktop' or 'mobile'")
        return v

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, v: list[str]) -> list[str]:
        """Validate categories."""
        valid = {"performance", "accessibility", "best-practices", "seo"}
        for cat in v:
            if cat not in valid:
                raise ValueError(f"Invalid category: {cat}. Must be one of {valid}")
        return v


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class CategoryScore:
    """Score for a single Lighthouse category."""

    name: str
    display_name: str
    score: float  # 0-1 normalized
    score_int: int  # 0-100
    rating: str  # good, needs-improvement, poor
    audit_count: int = 0
    passed_audits: int = 0
    failed_audits: int = 0


@dataclass
class AuditResult:
    """Individual audit result."""

    id: str
    title: str
    description: str
    score: float | None
    score_display_mode: str = "binary"
    display_value: str | None = None
    numeric_value: float | None = None
    is_passed: bool = False
    is_failed: bool = False
    is_informative: bool = False
    details: dict = field(default_factory=dict)


@dataclass
class LighthouseResult:
    """Results from Lighthouse analysis."""

    domain: str
    url: str = ""
    success: bool = False
    api_response_time_ms: float = 0.0
    strategy: str = "desktop"

    # Category scores
    performance: CategoryScore | None = None
    accessibility: CategoryScore | None = None
    best_practices: CategoryScore | None = None
    seo: CategoryScore | None = None

    # Overall score (average of all categories)
    overall_score: int | None = None

    # Audits by category
    performance_audits: list[AuditResult] = field(default_factory=list)
    accessibility_audits: list[AuditResult] = field(default_factory=list)
    best_practices_audits: list[AuditResult] = field(default_factory=list)
    seo_audits: list[AuditResult] = field(default_factory=list)

    # Key metrics (for performance)
    metrics: dict = field(default_factory=dict)

    # Issues
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class LighthouseAnalyzer:
    """
    Lighthouse Analyzer.

    Uses Google PageSpeed Insights API to run comprehensive Lighthouse audits:
    - Performance: Page load speed and optimization
    - Accessibility: WCAG compliance and screen reader support
    - Best Practices: Modern web development practices
    - SEO: Search engine optimization

    Features:
    - Desktop and mobile analysis
    - Detailed audit results with recommendations
    - Key performance metrics (LCP, FID, CLS, etc.)
    - Actionable improvement suggestions

    Dependencies:
    - http: Optional, uses HTTP analyzer to determine URL
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "lighthouse"
    name = "Lighthouse Audit"
    description = "Google Lighthouse analysis (Performance, Accessibility, Best Practices, SEO)"
    category = "performance"
    icon = "lighthouse"
    config_class = LighthouseConfig
    depends_on = []

    # ========================================================================
    # Protocol Methods
    # ========================================================================

    def analyze(
        self,
        domain: str,
        config: LighthouseConfig,
        context: dict[str, object] | None = None,
    ) -> LighthouseResult:
        """
        Analyze website using Lighthouse via PageSpeed Insights API.

        Args:
            domain: Domain to analyze
            config: Lighthouse analyzer configuration
            context: Context from previous analyzers

        Returns:
            LighthouseResult with category scores and audit details
        """
        url = self._get_url_to_analyze(domain, context)
        result = LighthouseResult(domain=domain, url=url, strategy=config.strategy)

        try:
            # Fetch data from PageSpeed API for each category
            all_data = self._fetch_all_categories(url, config, result)

            if all_data:
                result.success = True
                self._parse_all_categories(all_data, result)
                self._calculate_overall_score(result)
                self._extract_key_metrics(all_data, result)

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error from PageSpeed API for {url}: {e}")
            result.errors.append(f"PageSpeed API error: {e.response.status_code}")
        except httpx.HTTPError as e:
            logger.error(f"HTTP error analyzing {url}: {e}")
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"Lighthouse analysis failed for {domain}: {e}", exc_info=True)
            result.errors.append(f"Analysis failed: {e}")

        return result

    def _get_url_to_analyze(self, domain: str, context: dict[str, object] | None) -> str:
        """Get URL to analyze from context or fallback."""
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "preferred_final_url") and http_result.preferred_final_url:
                return http_result.preferred_final_url
        return f"https://{domain}"

    def _fetch_all_categories(
        self,
        url: str,
        config: LighthouseConfig,
        result: LighthouseResult,
    ) -> dict | None:
        """Fetch Lighthouse data from PageSpeed Insights API."""
        # Build params with all categories
        params = {
            "url": url,
            "strategy": config.strategy,
            "locale": config.locale,
        }

        # Add categories as separate parameters
        for cat in config.categories:
            params.setdefault("category", [])
            if isinstance(params["category"], str):
                params["category"] = [params["category"]]
            params["category"].append(cat)

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

    def _parse_all_categories(self, data: dict, result: LighthouseResult) -> None:
        """Parse all category scores and audits from Lighthouse result."""
        try:
            lighthouse = data.get("lighthouseResult", {})
            if not lighthouse:
                result.warnings.append("No Lighthouse result in API response")
                return

            categories = lighthouse.get("categories", {})
            audits = lighthouse.get("audits", {})

            # Parse each category
            if "performance" in categories:
                result.performance = self._parse_category("performance", categories, audits)
                result.performance_audits = self._parse_category_audits("performance", categories, audits)
                self._check_score_warning(result.performance, "Performance", result)

            if "accessibility" in categories:
                result.accessibility = self._parse_category("accessibility", categories, audits)
                result.accessibility_audits = self._parse_category_audits("accessibility", categories, audits)
                self._check_score_warning(result.accessibility, "Accessibility", result)

            if "best-practices" in categories:
                result.best_practices = self._parse_category("best-practices", categories, audits)
                result.best_practices_audits = self._parse_category_audits("best-practices", categories, audits)
                self._check_score_warning(result.best_practices, "Best Practices", result)

            if "seo" in categories:
                result.seo = self._parse_category("seo", categories, audits)
                result.seo_audits = self._parse_category_audits("seo", categories, audits)
                self._check_score_warning(result.seo, "SEO", result)

        except Exception as e:
            logger.warning(f"Failed to parse Lighthouse data: {e}")
            result.warnings.append(f"Could not parse some Lighthouse data: {e}")

    def _parse_category(
        self,
        category_id: str,
        categories: dict,
        audits: dict,
    ) -> CategoryScore:
        """Parse a single category score."""
        cat = categories.get(category_id, {})
        score = cat.get("score", 0) or 0
        score_int = int(score * 100)

        # Determine rating
        if score_int >= 90:
            rating = "good"
        elif score_int >= 50:
            rating = "needs-improvement"
        else:
            rating = "poor"

        # Count audits
        audit_refs = cat.get("auditRefs", [])
        audit_count = len(audit_refs)
        passed = 0
        failed = 0

        for ref in audit_refs:
            audit_id = ref.get("id", "")
            audit = audits.get(audit_id, {})
            audit_score = audit.get("score")

            if audit_score is not None:
                if audit_score >= 0.9:
                    passed += 1
                elif audit_score is not None and audit_score < 0.9:
                    failed += 1

        display_names = {
            "performance": "Performance",
            "accessibility": "Accessibility",
            "best-practices": "Best Practices",
            "seo": "SEO",
        }

        return CategoryScore(
            name=category_id,
            display_name=display_names.get(category_id, category_id.title()),
            score=score,
            score_int=score_int,
            rating=rating,
            audit_count=audit_count,
            passed_audits=passed,
            failed_audits=failed,
        )

    def _parse_category_audits(
        self,
        category_id: str,
        categories: dict,
        audits: dict,
    ) -> list[AuditResult]:
        """Parse audits for a specific category."""
        results = []
        cat = categories.get(category_id, {})
        audit_refs = cat.get("auditRefs", [])

        for ref in audit_refs:
            audit_id = ref.get("id", "")
            audit = audits.get(audit_id, {})
            if not audit:
                continue

            score = audit.get("score")
            score_mode = audit.get("scoreDisplayMode", "binary")

            # Determine audit status
            is_passed = False
            is_failed = False
            is_informative = False

            if score_mode in ("informative", "notApplicable", "manual"):
                is_informative = True
            elif score is not None:
                is_passed = score >= 0.9
                is_failed = score is not None and score < 0.9

            results.append(AuditResult(
                id=audit_id,
                title=audit.get("title", audit_id),
                description=audit.get("description", ""),
                score=score,
                score_display_mode=score_mode,
                display_value=audit.get("displayValue"),
                numeric_value=audit.get("numericValue"),
                is_passed=is_passed,
                is_failed=is_failed,
                is_informative=is_informative,
                details=audit.get("details", {}),
            ))

        return results

    def _check_score_warning(self, score: CategoryScore | None, name: str, result: LighthouseResult) -> None:
        """Add warning for low scores."""
        if score and score.score_int < 50:
            result.warnings.append(f"{name} score is poor ({score.score_int}/100)")

    def _calculate_overall_score(self, result: LighthouseResult) -> None:
        """Calculate overall score as average of all category scores."""
        scores = []
        if result.performance:
            scores.append(result.performance.score_int)
        if result.accessibility:
            scores.append(result.accessibility.score_int)
        if result.best_practices:
            scores.append(result.best_practices.score_int)
        if result.seo:
            scores.append(result.seo.score_int)

        if scores:
            result.overall_score = int(sum(scores) / len(scores))

    def _extract_key_metrics(self, data: dict, result: LighthouseResult) -> None:
        """Extract key performance metrics."""
        try:
            lighthouse = data.get("lighthouseResult", {})
            audits = lighthouse.get("audits", {})

            # Key metrics to extract
            metric_ids = [
                "largest-contentful-paint",
                "total-blocking-time",
                "cumulative-layout-shift",
                "first-contentful-paint",
                "speed-index",
                "interactive",
                "max-potential-fid",
                "server-response-time",
            ]

            for metric_id in metric_ids:
                audit = audits.get(metric_id, {})
                if audit:
                    result.metrics[metric_id] = {
                        "value": audit.get("numericValue"),
                        "display_value": audit.get("displayValue"),
                        "score": audit.get("score"),
                    }

        except Exception as e:
            logger.debug(f"Failed to extract metrics: {e}")

    def describe_output(self, result: LighthouseResult) -> OutputDescriptor:
        """Describe how to render Lighthouse results."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        if result.overall_score is not None:
            descriptor.quiet_summary = lambda r: f"Lighthouse: {result.overall_score}/100"
        else:
            descriptor.quiet_summary = lambda r: "Lighthouse: N/A"

        if not result.success:
            descriptor.add_row(
                value="Failed to run Lighthouse analysis",
                style_class="error",
                severity="error",
            )
            return descriptor

        # Overall Score
        descriptor.add_row(
            section_name="Overall Score",
            section_type="heading",
        )

        if result.overall_score is not None:
            score_style = (
                "error" if result.overall_score < 50
                else "warning" if result.overall_score < 90
                else "success"
            )
            descriptor.add_row(
                label="Lighthouse Score",
                value=f"{result.overall_score}/100",
                style_class=score_style,
                icon="gauge",
            )

        # Category Scores
        descriptor.add_row(
            section_name="Category Scores",
            section_type="heading",
        )

        for score in [result.performance, result.accessibility, result.best_practices, result.seo]:
            if score:
                descriptor.add_row(
                    label=score.display_name,
                    value=f"{score.score_int}/100",
                    style_class=self._get_rating_style(score.rating),
                    icon=self._get_rating_icon(score.rating),
                )

        # Key Metrics (Verbose)
        if result.metrics:
            descriptor.add_row(
                section_name="Key Metrics",
                section_type="heading",
                verbosity=VerbosityLevel.VERBOSE,
            )

            metric_labels = {
                "largest-contentful-paint": ("LCP", "Largest Contentful Paint"),
                "first-contentful-paint": ("FCP", "First Contentful Paint"),
                "total-blocking-time": ("TBT", "Total Blocking Time"),
                "cumulative-layout-shift": ("CLS", "Cumulative Layout Shift"),
                "speed-index": ("SI", "Speed Index"),
                "interactive": ("TTI", "Time to Interactive"),
                "server-response-time": ("TTFB", "Server Response Time"),
            }

            for metric_id, (short, label) in metric_labels.items():
                if metric_id in result.metrics:
                    data = result.metrics[metric_id]
                    display = data.get("display_value", "")
                    if display:
                        descriptor.add_row(
                            label=label,
                            value=display,
                            verbosity=VerbosityLevel.VERBOSE,
                        )

        # Failed Audits by Category
        for score, audits, cat_name in [
            (result.performance, result.performance_audits, "Performance"),
            (result.accessibility, result.accessibility_audits, "Accessibility"),
            (result.best_practices, result.best_practices_audits, "Best Practices"),
            (result.seo, result.seo_audits, "SEO"),
        ]:
            failed_audits = [a for a in audits if a.is_failed and a.score_display_mode not in ("informative", "manual")]
            if failed_audits:
                descriptor.add_row(
                    section_name=f"{cat_name} Issues ({len(failed_audits)})",
                    section_type="heading",
                    verbosity=VerbosityLevel.NORMAL,
                )

                for audit in failed_audits[:5]:  # Top 5
                    descriptor.add_row(
                        value=f"• {audit.title}",
                        style_class="warning",
                        verbosity=VerbosityLevel.NORMAL,
                    )
                    if audit.display_value:
                        descriptor.add_row(
                            value=f"  {audit.display_value}",
                            style_class="muted",
                            verbosity=VerbosityLevel.VERBOSE,
                        )

        # Passed Audits Summary (Debug)
        for score, audits, cat_name in [
            (result.performance, result.performance_audits, "Performance"),
            (result.accessibility, result.accessibility_audits, "Accessibility"),
            (result.best_practices, result.best_practices_audits, "Best Practices"),
            (result.seo, result.seo_audits, "SEO"),
        ]:
            if score:
                descriptor.add_row(
                    section_name=f"{cat_name} Audits",
                    section_type="heading",
                    verbosity=VerbosityLevel.DEBUG,
                )
                descriptor.add_row(
                    label="Passed",
                    value=f"{score.passed_audits}/{score.audit_count}",
                    style_class="success",
                    verbosity=VerbosityLevel.DEBUG,
                )
                descriptor.add_row(
                    label="Failed",
                    value=f"{score.failed_audits}/{score.audit_count}",
                    style_class="warning" if score.failed_audits > 0 else "success",
                    verbosity=VerbosityLevel.DEBUG,
                )

        # API Info (Debug)
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
            label="Strategy",
            value=result.strategy,
            verbosity=VerbosityLevel.DEBUG,
        )
        descriptor.add_row(
            label="URL Analyzed",
            value=result.url,
            verbosity=VerbosityLevel.DEBUG,
        )
        descriptor.add_row(
            label="Source",
            value="Google PageSpeed Insights API (Lighthouse)",
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

    def to_dict(self, result: LighthouseResult) -> dict:
        """Serialize result to JSON-compatible dictionary."""
        def score_to_dict(s: CategoryScore | None) -> dict | None:
            if s is None:
                return None
            return {
                "name": s.name,
                "display_name": s.display_name,
                "score": s.score,
                "score_int": s.score_int,
                "rating": s.rating,
                "audit_count": s.audit_count,
                "passed_audits": s.passed_audits,
                "failed_audits": s.failed_audits,
            }

        def audits_to_list(audits: list[AuditResult]) -> list[dict]:
            return [
                {
                    "id": a.id,
                    "title": a.title,
                    "description": a.description,
                    "score": a.score,
                    "display_value": a.display_value,
                    "numeric_value": a.numeric_value,
                    "is_passed": a.is_passed,
                    "is_failed": a.is_failed,
                }
                for a in audits
            ]

        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "strategy": result.strategy,
            "overall_score": result.overall_score,
            "categories": {
                "performance": score_to_dict(result.performance),
                "accessibility": score_to_dict(result.accessibility),
                "best_practices": score_to_dict(result.best_practices),
                "seo": score_to_dict(result.seo),
            },
            "metrics": result.metrics,
            "audits": {
                "performance": audits_to_list(result.performance_audits),
                "accessibility": audits_to_list(result.accessibility_audits),
                "best_practices": audits_to_list(result.best_practices_audits),
                "seo": audits_to_list(result.seo_audits),
            },
            "api_response_time_ms": round(result.api_response_time_ms, 2),
            "errors": result.errors,
            "warnings": result.warnings,
        }
