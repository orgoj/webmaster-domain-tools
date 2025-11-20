"""CDN detection analyzer - identify CDN providers.

This analyzer detects CDN usage from HTTP headers and DNS CNAME records.
Completely self-contained with config, logic, and output formatting.
"""

import logging
from dataclasses import dataclass, field

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


class CDNConfig(AnalyzerConfig):
    """CDN detector configuration."""

    check_headers: bool = Field(default=True, description="Check HTTP headers for CDN signatures")
    check_cname: bool = Field(default=True, description="Check DNS CNAME for CDN providers")


# ============================================================================
# Result Model
# ============================================================================


@dataclass
class CDNDetectionResult:
    """Results from CDN detection."""

    domain: str
    cdn_detected: bool = False
    cdn_provider: str | None = None
    detection_method: str | None = None  # "headers", "cname", "both"
    confidence: str = "unknown"  # "high", "medium", "low"
    evidence: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class CDNDetector:
    """
    Detects CDN usage from HTTP headers and DNS CNAME records.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (CDNConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "cdn"
    name = "CDN Detection"
    description = "Detect Content Delivery Network usage"
    category = "advanced"
    icon = "cloud"
    config_class = CDNConfig
    depends_on = ["http", "dns"]  # Needs HTTP headers and DNS CNAME records

    # ========================================================================
    # CDN Detection Patterns
    # ========================================================================

    # CDN detection patterns for HTTP headers
    HEADER_PATTERNS = {
        "Cloudflare": {
            "headers": ["CF-RAY", "CF-Cache-Status", "__cfduid"],
            "server_patterns": ["cloudflare"],
        },
        "Fastly": {
            "headers": ["Fastly-Debug-Digest", "X-Fastly-Request-ID"],
            "server_patterns": ["fastly"],
        },
        "Akamai": {
            "headers": ["X-Akamai-Transformed", "X-Akamai-Staging"],
            "server_patterns": ["akamaighost"],
        },
        "Amazon CloudFront": {
            "headers": ["X-Amz-Cf-Id", "X-Amz-Cf-Pop"],
            "server_patterns": ["cloudfront"],
        },
        "Google Cloud CDN": {
            "headers": ["X-Google-Cache", "X-Goog-Generation"],
            "server_patterns": [],
        },
        "Microsoft Azure CDN": {
            "headers": ["X-Azure-Ref", "X-Cache"],
            "server_patterns": ["azureedge"],
        },
        "KeyCDN": {
            "headers": ["X-Edge-Location"],
            "server_patterns": ["keycdn"],
        },
        "StackPath": {
            "headers": ["X-SP-Cache-Status"],
            "server_patterns": ["stackpath"],
        },
        "BunnyCDN": {
            "headers": ["CDN-PullZone", "CDN-Uid"],
            "server_patterns": ["bunnycdn"],
        },
        "Netlify": {
            "headers": ["X-NF-Request-ID"],
            "server_patterns": ["netlify"],
        },
        "Vercel": {
            "headers": ["X-Vercel-Id", "X-Vercel-Cache"],
            "server_patterns": ["vercel"],
        },
    }

    # CNAME patterns for CDN detection
    CNAME_PATTERNS = {
        "Cloudflare": ["cloudflare.net", "cloudflare.com"],
        "Fastly": ["fastly.net", "fastlylb.net"],
        "Akamai": ["akamai.net", "akamaiedge.net", "akadns.net"],
        "Amazon CloudFront": ["cloudfront.net"],
        "Google Cloud CDN": ["googleusercontent.com"],
        "Microsoft Azure CDN": ["azureedge.net", "azurefd.net"],
        "KeyCDN": ["kxcdn.com"],
        "StackPath": ["stackpathcdn.com"],
        "BunnyCDN": ["b-cdn.net"],
        "Netlify": ["netlify.app", "netlify.com"],
        "Vercel": ["vercel.app", "vercel-dns.com"],
        "Cloudflare Pages": ["pages.dev"],
    }

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: CDNConfig) -> CDNDetectionResult:
        """
        Perform CDN detection.

        Note: This method receives data from http and dns analyzers via
        the execution context. For now, it returns placeholder data.
        Full integration happens in CLI orchestration.

        Args:
            domain: Domain to analyze
            config: CDN detector configuration

        Returns:
            CDNDetectionResult with detection information
        """
        result = CDNDetectionResult(domain=domain)

        # TODO: Get HTTP headers and DNS CNAME from context
        # For now, return placeholder
        result.cdn_detected = False
        result.evidence.append("CDN detection requires HTTP and DNS analysis first")

        return result

    def detect_from_headers(self, headers: dict[str, str]) -> CDNDetectionResult:
        """
        Detect CDN from HTTP headers.

        Args:
            headers: Dictionary of HTTP headers (case-insensitive)

        Returns:
            CDNDetectionResult with detection information
        """
        result = CDNDetectionResult(domain="")

        # Normalize headers to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check each CDN provider
        for provider, patterns in self.HEADER_PATTERNS.items():
            # Check specific CDN headers
            for header in patterns["headers"]:
                if header.lower() in headers_lower:
                    result.cdn_detected = True
                    result.cdn_provider = provider
                    result.detection_method = "headers"
                    result.confidence = "high"
                    result.evidence.append(f"Header: {header} = {headers_lower[header.lower()]}")
                    logger.info(f"CDN detected from headers: {provider} ({header})")
                    return result

            # Check Server header patterns
            server_header = headers_lower.get("server", "").lower()
            for pattern in patterns["server_patterns"]:
                if pattern.lower() in server_header:
                    result.cdn_detected = True
                    result.cdn_provider = provider
                    result.detection_method = "headers"
                    result.confidence = "high"
                    result.evidence.append(f"Server header: {server_header}")
                    logger.info(f"CDN detected from Server header: {provider}")
                    return result

        # Check for generic CDN indicators
        via_header = headers_lower.get("via", "")
        if via_header:
            result.evidence.append(f"Via header present: {via_header}")
            # Check if Via header contains known CDN patterns
            via_lower = via_header.lower()
            for provider, patterns in self.HEADER_PATTERNS.items():
                for pattern in patterns["server_patterns"]:
                    if pattern.lower() in via_lower:
                        result.cdn_detected = True
                        result.cdn_provider = provider
                        result.detection_method = "headers"
                        result.confidence = "medium"
                        result.evidence.append("CDN pattern in Via header")
                        return result

        # Check X-Cache headers (generic CDN indicator)
        x_cache = headers_lower.get("x-cache")
        if x_cache:
            result.evidence.append(f"X-Cache header: {x_cache}")
            if any(word in x_cache.lower() for word in ["hit", "miss", "expired"]):
                result.cdn_detected = True
                result.cdn_provider = "Unknown CDN"
                result.detection_method = "headers"
                result.confidence = "low"
                result.evidence.append("Generic CDN caching detected")

        return result

    def detect_from_cname(self, cname_records: list[str]) -> CDNDetectionResult:
        """
        Detect CDN from CNAME DNS records.

        Args:
            cname_records: List of CNAME values

        Returns:
            CDNDetectionResult with detection information
        """
        result = CDNDetectionResult(domain="")

        for cname in cname_records:
            cname_lower = cname.lower()

            # Check each CDN provider's CNAME patterns
            for provider, patterns in self.CNAME_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in cname_lower:
                        result.cdn_detected = True
                        result.cdn_provider = provider
                        result.detection_method = "cname"
                        result.confidence = "high"
                        result.evidence.append(f"CNAME: {cname}")
                        logger.info(f"CDN detected from CNAME: {provider} ({cname})")
                        return result

        return result

    def combine_results(
        self,
        domain: str,
        header_result: CDNDetectionResult,
        cname_result: CDNDetectionResult,
    ) -> CDNDetectionResult:
        """
        Combine results from header and CNAME detection.

        Args:
            domain: Domain being analyzed
            header_result: Result from header detection
            cname_result: Result from CNAME detection

        Returns:
            Combined CDNDetectionResult
        """
        result = CDNDetectionResult(domain=domain)

        # Both detected - check if they match
        if header_result.cdn_detected and cname_result.cdn_detected:
            if header_result.cdn_provider == cname_result.cdn_provider:
                result.cdn_detected = True
                result.cdn_provider = header_result.cdn_provider
                result.detection_method = "both"
                result.confidence = "high"
                result.evidence.extend(header_result.evidence)
                result.evidence.extend(cname_result.evidence)
            else:
                # Conflict - prefer header detection as it's more definitive
                result.cdn_detected = True
                result.cdn_provider = header_result.cdn_provider
                result.detection_method = "both"
                result.confidence = "medium"
                result.evidence.extend(header_result.evidence)
                result.evidence.extend(cname_result.evidence)
                result.warnings.append(
                    f"CDN mismatch: headers suggest {header_result.cdn_provider}, "
                    f"CNAME suggests {cname_result.cdn_provider}"
                )

        # Only header detected
        elif header_result.cdn_detected:
            result.cdn_detected = True
            result.cdn_provider = header_result.cdn_provider
            result.detection_method = header_result.detection_method
            result.confidence = header_result.confidence
            result.evidence.extend(header_result.evidence)

        # Only CNAME detected
        elif cname_result.cdn_detected:
            result.cdn_detected = True
            result.cdn_provider = cname_result.cdn_provider
            result.detection_method = cname_result.detection_method
            result.confidence = cname_result.confidence
            result.evidence.extend(cname_result.evidence)

        # Nothing detected
        else:
            result.cdn_detected = False
            result.evidence.append("No CDN detected")

        return result

    def describe_output(self, result: CDNDetectionResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: CDN detection result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        descriptor.quiet_summary = lambda r: (
            f"CDN: {r.cdn_provider}" if r.cdn_detected else "CDN: None"
        )

        # Normal verbosity
        if result.cdn_detected:
            descriptor.add_row(
                label="CDN Provider",
                value=result.cdn_provider,
                style_class="success",  # Semantic style (not color)
                icon="check",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            # Confidence with semantic styling
            confidence_style = {
                "high": "success",
                "medium": "warning",
                "low": "muted",
            }.get(result.confidence, "neutral")

            descriptor.add_row(
                label="Confidence",
                value=result.confidence.capitalize(),
                style_class=confidence_style,
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            descriptor.add_row(
                label="Detection Method",
                value=(
                    result.detection_method.capitalize() if result.detection_method else "Unknown"
                ),
                style_class="info",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )
        else:
            descriptor.add_row(
                label="CDN",
                value="Not detected",
                style_class="muted",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Verbose - show evidence
        if result.evidence:
            descriptor.add_row(
                label="Evidence",
                value=result.evidence,
                section_type="list",
                style_class="info",
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

    def to_dict(self, result: CDNDetectionResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: CDN detection result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "cdn_detected": result.cdn_detected,
            "cdn_provider": result.cdn_provider,
            "detection_method": result.detection_method,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "errors": result.errors,
            "warnings": result.warnings,
        }
