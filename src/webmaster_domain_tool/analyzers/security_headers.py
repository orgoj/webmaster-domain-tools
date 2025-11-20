"""Security headers analysis module.

This analyzer checks HTTP security headers and provides a security score.
Completely self-contained with config, logic, and output formatting.
"""

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

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


class SecurityHeadersConfig(AnalyzerConfig):
    """Security headers analyzer configuration."""

    check_strict_transport_security: bool = Field(default=True, description="Check HSTS header")
    check_content_security_policy: bool = Field(default=True, description="Check CSP header")
    check_x_frame_options: bool = Field(default=True, description="Check X-Frame-Options header")
    check_x_content_type_options: bool = Field(
        default=True, description="Check X-Content-Type-Options header"
    )
    check_referrer_policy: bool = Field(default=True, description="Check Referrer-Policy header")
    check_permissions_policy: bool = Field(
        default=True, description="Check Permissions-Policy header"
    )
    check_x_xss_protection: bool = Field(default=True, description="Check X-XSS-Protection header")
    check_content_type: bool = Field(default=True, description="Check Content-Type header")
    check_cors: bool = Field(default=True, description="Check CORS headers")


# ============================================================================
# Result Model
# ============================================================================


@dataclass
class SecurityHeaderCheck:
    """Represents a security header check result."""

    header_name: str
    present: bool
    value: str | None = None
    is_valid: bool = True
    recommendation: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SecurityHeadersResult:
    """Results from security headers analysis."""

    domain: str
    url: str = ""
    headers: dict[str, SecurityHeaderCheck] = field(default_factory=dict)
    score: int = 0  # Score out of 100
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class SecurityHeadersAnalyzer:
    """
    Analyzes HTTP security headers.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (SecurityHeadersConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "headers"
    name = "Security Headers"
    description = "Analyze HTTP security headers"
    category = "security"
    icon = "shield"
    config_class = SecurityHeadersConfig
    depends_on = ["http"]  # Needs HTTP headers

    # ========================================================================
    # Security Headers Definitions
    # ========================================================================

    # Security headers to check with their recommendations
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "HSTS - Forces HTTPS connections",
            "recommendation": "max-age=31536000; includeSubDomains; preload",
            "weight": 15,
            "config_key": "check_strict_transport_security",
        },
        "Content-Security-Policy": {
            "description": "CSP - Prevents XSS and injection attacks",
            "recommendation": "default-src 'self'; script-src 'self'; object-src 'none'",
            "weight": 20,
            "config_key": "check_content_security_policy",
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking",
            "recommendation": "DENY or SAMEORIGIN",
            "weight": 10,
            "config_key": "check_x_frame_options",
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME sniffing",
            "recommendation": "nosniff",
            "weight": 10,
            "config_key": "check_x_content_type_options",
        },
        "Referrer-Policy": {
            "description": "Controls referrer information",
            "recommendation": "strict-origin-when-cross-origin or no-referrer",
            "weight": 10,
            "config_key": "check_referrer_policy",
        },
        "Permissions-Policy": {
            "description": "Controls browser features",
            "recommendation": "geolocation=(), microphone=(), camera=()",
            "weight": 10,
            "config_key": "check_permissions_policy",
        },
        "X-XSS-Protection": {
            "description": "Legacy XSS protection (deprecated, use CSP instead)",
            "recommendation": "0 (disabled, use CSP instead)",
            "weight": 5,
            "config_key": "check_x_xss_protection",
        },
        "Content-Type": {
            "description": "Specifies content MIME type",
            "recommendation": "text/html; charset=utf-8",
            "weight": 5,
            "config_key": "check_content_type",
        },
        "Access-Control-Allow-Origin": {
            "description": "CORS - Controls which origins can access resources",
            "recommendation": "Specific origin or 'null' (avoid '*' for sensitive data)",
            "weight": 10,
            "config_key": "check_cors",
        },
        "Access-Control-Allow-Credentials": {
            "description": "CORS - Allows credentials in cross-origin requests",
            "recommendation": "true (only if needed)",
            "weight": 5,
            "config_key": "check_cors",
        },
    }

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: SecurityHeadersConfig) -> SecurityHeadersResult:
        """
        Perform security headers analysis.

        Note: This method receives HTTP headers from the http analyzer via
        the execution context. For now, it returns placeholder data.
        Full integration happens in CLI orchestration.

        Args:
            domain: Domain to analyze
            config: Security headers configuration

        Returns:
            SecurityHeadersResult with header analysis
        """
        # TODO: Get HTTP headers from context
        # For now, return placeholder
        result = SecurityHeadersResult(domain=domain)
        result.warnings.append("Security headers analysis requires HTTP analysis first")
        return result

    def analyze_headers(
        self, url: str, headers: dict[str, str], config: SecurityHeadersConfig
    ) -> SecurityHeadersResult:
        """
        Analyze security headers from HTTP response.

        Args:
            url: The URL that was checked
            headers: Dictionary of HTTP headers
            config: Configuration for header checks

        Returns:
            SecurityHeadersResult with analysis
        """
        logger.info(f"Analyzing security headers for {url}")
        # Extract domain from URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path  # fallback to path if no netloc
        result = SecurityHeadersResult(domain=domain, url=url)

        # Normalize header names (case-insensitive)
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # Build enabled checks dict from config
        enabled_checks = {
            "check_strict_transport_security": config.check_strict_transport_security,
            "check_content_security_policy": config.check_content_security_policy,
            "check_x_frame_options": config.check_x_frame_options,
            "check_x_content_type_options": config.check_x_content_type_options,
            "check_referrer_policy": config.check_referrer_policy,
            "check_permissions_policy": config.check_permissions_policy,
            "check_x_xss_protection": config.check_x_xss_protection,
            "check_content_type": config.check_content_type,
            "check_cors": config.check_cors,
        }

        total_weight = sum(h["weight"] for h in self.SECURITY_HEADERS.values())
        score = 0

        # Check each security header
        for header_name, header_info in self.SECURITY_HEADERS.items():
            # Skip if disabled in config
            config_key = header_info.get("config_key")
            if config_key and not enabled_checks.get(config_key, True):
                logger.debug(f"Skipping {header_name} check (disabled in config)")
                continue

            header_lower = header_name.lower()
            check = SecurityHeaderCheck(
                header_name=header_name,
                present=header_lower in normalized_headers,
                recommendation=header_info["recommendation"],
            )

            if check.present:
                check.value = normalized_headers[header_lower]

                # Validate specific headers
                if header_name == "Strict-Transport-Security":
                    score += self._validate_hsts(check, header_info["weight"])
                elif header_name == "Content-Security-Policy":
                    score += self._validate_csp(check, header_info["weight"])
                elif header_name == "X-Frame-Options":
                    score += self._validate_x_frame_options(check, header_info["weight"])
                elif header_name == "X-Content-Type-Options":
                    score += self._validate_x_content_type_options(check, header_info["weight"])
                elif header_name == "Referrer-Policy":
                    score += self._validate_referrer_policy(check, header_info["weight"])
                elif header_name == "Permissions-Policy":
                    score += self._validate_permissions_policy(check, header_info["weight"])
                elif header_name == "X-XSS-Protection":
                    score += self._validate_x_xss_protection(check, header_info["weight"])
                elif header_name == "Content-Type":
                    score += self._validate_content_type(check, header_info["weight"])
                else:
                    # Header present, give full points
                    score += header_info["weight"]
            else:
                check.warnings.append(
                    f"{header_name} header not present. "
                    f"Recommended: {header_info['recommendation']}"
                )

            result.headers[header_name] = check

            # Add warnings to main result
            result.warnings.extend(check.warnings)
            result.errors.extend(check.errors)

        # Calculate final score (0-100)
        result.score = int((score / total_weight) * 100)

        # Add overall warnings based on score
        if result.score < 50:
            result.warnings.append(
                f"Security score is low ({result.score}/100). Multiple security headers are missing."
            )
        elif result.score < 75:
            result.warnings.append(
                f"Security score could be improved ({result.score}/100). Consider adding more security headers."
            )

        return result

    def describe_output(self, result: SecurityHeadersResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: Security headers analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        descriptor.quiet_summary = lambda r: f"Security Score: {r.score}/100"

        # Overall score with semantic styling
        score_style = (
            "error" if result.score < 50 else "warning" if result.score < 75 else "success"
        )
        score_icon = "cross" if result.score < 50 else "warning" if result.score < 75 else "check"

        descriptor.add_row(
            label="Security Score",
            value=f"{result.score}/100",
            style_class=score_style,
            icon=score_icon,
            severity="info",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Normal verbosity - show header summary
        present_headers = [name for name, check in result.headers.items() if check.present]

        if present_headers:
            descriptor.add_row(
                label="Headers Present",
                value=f"{len(present_headers)}/{len(result.headers)}",
                style_class="info",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Verbose - show detailed header information
        for header_name, check in result.headers.items():
            if check.present:
                # Determine style based on warnings
                header_style = "warning" if check.warnings else "success"
                header_icon = "warning" if check.warnings else "check"

                descriptor.add_row(
                    label=header_name,
                    value=check.value if check.value else "Present",
                    style_class=header_style,
                    icon=header_icon,
                    severity="info",
                    verbosity=VerbosityLevel.VERBOSE,
                )

                # Show warnings for this header
                for warning in check.warnings:
                    descriptor.add_row(
                        value=f"  └─ {warning}",
                        style_class="warning",
                        severity="warning",
                        verbosity=VerbosityLevel.VERBOSE,
                    )
            else:
                descriptor.add_row(
                    label=header_name,
                    value="Not present",
                    style_class="muted",
                    icon="cross",
                    severity="info",
                    verbosity=VerbosityLevel.VERBOSE,
                )

                # Show recommendation
                if check.recommendation:
                    descriptor.add_row(
                        value=f"  └─ Recommended: {check.recommendation}",
                        style_class="muted",
                        severity="info",
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

        # Warnings (overall warnings, not per-header)
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

    def to_dict(self, result: SecurityHeadersResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Security headers analysis result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "url": result.url,
            "score": result.score,
            "headers": {
                name: {
                    "header_name": check.header_name,
                    "present": check.present,
                    "value": check.value,
                    "is_valid": check.is_valid,
                    "recommendation": check.recommendation,
                    "errors": check.errors,
                    "warnings": check.warnings,
                }
                for name, check in result.headers.items()
            },
            "errors": result.errors,
            "warnings": result.warnings,
        }

    # ========================================================================
    # Header Validation Methods (preserved from original)
    # ========================================================================

    def _validate_hsts(self, check: SecurityHeaderCheck, max_score: int) -> int:
        """Validate Strict-Transport-Security header."""
        if not check.value:
            return 0

        score = max_score
        value_lower = check.value.lower()

        # Check max-age
        if "max-age=" in value_lower:
            try:
                max_age_str = value_lower.split("max-age=")[1].split(";")[0].strip()
                max_age = int(max_age_str)

                if max_age < 31536000:  # Less than 1 year
                    check.warnings.append(
                        f"HSTS max-age is {max_age}s (recommend at least 31536000s / 1 year)"
                    )
                    score = max_score // 2
            except (ValueError, IndexError):
                check.warnings.append("HSTS max-age value is invalid")
                score = max_score // 2
        else:
            check.warnings.append("HSTS missing max-age directive")
            score = max_score // 2

        # Check includeSubDomains
        if "includesubdomains" not in value_lower:
            check.warnings.append("HSTS missing includeSubDomains (recommended)")

        # Check preload
        if "preload" not in value_lower:
            check.warnings.append("HSTS missing preload (recommended for production sites)")

        return score

    def _validate_csp(self, check: SecurityHeaderCheck, max_score: int) -> int:
        """Validate Content-Security-Policy header."""
        if not check.value:
            return 0

        score = max_score
        value_lower = check.value.lower()

        # Check for unsafe directives
        if "'unsafe-inline'" in value_lower:
            check.warnings.append("CSP allows 'unsafe-inline' (reduces protection against XSS)")
            score = max(score - 5, max_score // 2)

        if "'unsafe-eval'" in value_lower:
            check.warnings.append("CSP allows 'unsafe-eval' (reduces protection against XSS)")
            score = max(score - 5, max_score // 2)

        # Check for default-src
        if "default-src" not in value_lower:
            check.warnings.append("CSP missing 'default-src' directive (recommended)")

        # Check for common directives
        if "script-src" not in value_lower:
            check.warnings.append("CSP missing 'script-src' directive (recommended)")

        return score

    def _validate_x_frame_options(self, check: SecurityHeaderCheck, max_score: int) -> int:
        """Validate X-Frame-Options header."""
        if not check.value:
            return 0

        value_upper = check.value.upper()
        if value_upper in ("DENY", "SAMEORIGIN"):
            return max_score
        elif value_upper.startswith("ALLOW-FROM"):
            check.warnings.append(
                "X-Frame-Options uses ALLOW-FROM (deprecated, use CSP frame-ancestors instead)"
            )
            return max_score // 2
        else:
            check.warnings.append(f"X-Frame-Options has invalid value: {check.value}")
            return max_score // 2

    def _validate_x_content_type_options(self, check: SecurityHeaderCheck, max_score: int) -> int:
        """Validate X-Content-Type-Options header."""
        if not check.value:
            return 0

        if check.value.lower() == "nosniff":
            return max_score
        else:
            check.warnings.append(f"X-Content-Type-Options has unexpected value: {check.value}")
            return max_score // 2

    def _validate_referrer_policy(self, check: SecurityHeaderCheck, max_score: int) -> int:
        """Validate Referrer-Policy header."""
        if not check.value:
            return 0

        valid_policies = [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        ]

        value_lower = check.value.lower()
        if value_lower in valid_policies:
            if value_lower == "unsafe-url":
                check.warnings.append(
                    "Referrer-Policy is 'unsafe-url' (sends full URL, not recommended)"
                )
                return max_score // 2
            elif value_lower == "no-referrer-when-downgrade":
                check.warnings.append(
                    "Referrer-Policy is 'no-referrer-when-downgrade' (consider stricter policy)"
                )
            return max_score
        else:
            check.warnings.append(f"Referrer-Policy has invalid value: {check.value}")
            return max_score // 2

    def _validate_permissions_policy(self, check: SecurityHeaderCheck, max_score: int) -> int:
        """Validate Permissions-Policy header."""
        if not check.value:
            return 0

        # Just having it is good
        return max_score

    def _validate_x_xss_protection(self, check: SecurityHeaderCheck, max_score: int) -> int:
        """Validate X-XSS-Protection header."""
        if not check.value:
            return 0

        # This header is deprecated, "0" is actually the recommended value
        if check.value == "0":
            return max_score
        else:
            check.warnings.append(
                "X-XSS-Protection is deprecated. Use Content-Security-Policy instead. "
                "Set to '0' to disable."
            )
            return max_score // 2

    def _validate_content_type(self, check: SecurityHeaderCheck, max_score: int) -> int:
        """Validate Content-Type header."""
        if not check.value:
            return 0

        value_lower = check.value.lower()

        # Check if charset is specified
        if "charset=" not in value_lower:
            check.warnings.append("Content-Type missing charset specification")
            return max_score // 2

        return max_score
