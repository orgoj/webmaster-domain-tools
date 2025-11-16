"""CDN detection analyzer - identify CDN providers."""

import logging
from dataclasses import dataclass, field

from .base import BaseAnalysisResult, BaseAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class CDNDetectionResult(BaseAnalysisResult):
    """Results from CDN detection."""

    cdn_detected: bool = False
    cdn_provider: str | None = None
    detection_method: str | None = None  # "headers", "cname", "both"
    confidence: str = "unknown"  # "high", "medium", "low"
    evidence: list[str] = field(default_factory=list)


class CDNDetector(BaseAnalyzer[CDNDetectionResult]):
    """Detects CDN usage from headers and DNS records."""

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
                        result.evidence.append(f"CDN pattern in Via header")
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
