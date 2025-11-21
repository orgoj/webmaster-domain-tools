"""Domain configuration validator - validates domains against infrastructure profiles.

This analyzer checks if a domain is correctly configured for specific infrastructure
by validating IP addresses, CDN usage, verification files, and email security settings.
Disabled by default - requires explicit profile activation.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import BaseModel, Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class DomainValidationProfile(BaseModel):
    """Single validation profile for specific infrastructure."""

    name: str = Field(description="Profile display name")
    description: str = Field(default="", description="Profile description")

    # IP/CDN validation (mutually exclusive - use IPs OR CDN, not both)
    expected_ips: list[str] = Field(
        default_factory=list, description="Expected IPv4 addresses (A records)"
    )
    expected_ipv6: list[str] = Field(
        default_factory=list, description="Expected IPv6 addresses (AAAA records)"
    )
    expected_cdn: str = Field(
        default="", description="Expected CDN provider name (e.g., 'cloudflare', 'fastly')"
    )
    allow_cname_redirect: bool = Field(
        default=True, description="Allow CNAME chain before reaching expected IPs"
    )
    ip_match_mode: str = Field(
        default="any",
        description="IP matching mode: 'any' (at least one matches) or 'all' (all must match)",
    )

    # Verification file check
    verification_path: str = Field(
        default="", description="Path to verification file (e.g., '/.well-known/verification.txt')"
    )
    verification_content: str = Field(
        default="",
        description="Expected content in verification file (optional - just checks existence if empty)",
    )
    verification_method: str = Field(
        default="GET", description="HTTP method for verification check (GET or HEAD)"
    )

    # SPF validation
    spf_includes: list[str] = Field(
        default_factory=list,
        description="Required SPF include mechanisms (e.g., ['include:_spf.google.com'])",
    )
    spf_ip4: list[str] = Field(
        default_factory=list,
        description="Required SPF ip4 mechanisms (e.g., ['ip4:203.0.113.0/24'])",
    )
    spf_ip6: list[str] = Field(default_factory=list, description="Required SPF ip6 mechanisms")
    spf_match_mode: str = Field(
        default="all", description="SPF matching: 'all' (must contain all) or 'any' (at least one)"
    )

    # DKIM validation
    dkim_selectors: list[str] = Field(
        default_factory=list,
        description="Required DKIM selectors that must exist (e.g., ['default', 'google'])",
    )
    dkim_match_mode: str = Field(
        default="all", description="DKIM matching: 'all' (all must exist) or 'any' (at least one)"
    )

    # DMARC validation
    dmarc_policy: str = Field(
        default="",
        description="Required DMARC policy ('none', 'quarantine', 'reject', or '' for any)",
    )
    dmarc_subdomain_policy: str = Field(
        default="", description="Required subdomain policy ('' for don't care)"
    )
    dmarc_percentage: int = Field(
        default=0, description="Minimum DMARC percentage (0 = don't check)"
    )


class DomainValidatorConfig(AnalyzerConfig):
    """Domain validator configuration."""

    # Active profile selection
    active_profile: str = Field(
        default="", description="Name of active profile to use (empty = skip validation)"
    )

    # Profile definitions
    profiles: dict[str, DomainValidationProfile] = Field(
        default_factory=dict, description="Map of profile_id -> profile config"
    )

    # Behavior
    strict_mode: bool = Field(
        default=True, description="Strict mode: all checks must pass (vs. warnings for failures)"
    )
    hide_expected_values: bool = Field(
        default=True,
        description="Hide expected values in error messages (security best practice - prevents infrastructure disclosure)",
    )


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class ValidationCheck:
    """Single validation check result."""

    check_type: str  # "ip", "ipv6", "cdn", "verification_file", "spf", "dkim", "dmarc"
    check_name: str  # Human-readable check name
    passed: bool
    expected: str | list[str]  # What was expected
    actual: str | list[str]  # What was found
    details: str = ""  # Additional context
    severity: str = "error"  # "error" or "warning" (based on strict_mode)


@dataclass
class DomainValidatorResult:
    """Domain validation results."""

    domain: str

    # Profile info
    profile_id: str = ""
    profile_name: str = ""
    profile_active: bool = False  # Was a profile actually used?

    # Overall result
    overall_passed: bool = False
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0

    # Individual checks
    checks: list[ValidationCheck] = field(default_factory=list)

    # Standard error/warning lists
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # Dependency failures (if dns/http/email analyzers failed)
    dependency_errors: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class DomainConfigValidator:
    """
    Validates domain configuration against infrastructure profiles.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (DomainValidatorConfig with nested profiles)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Profile-based validation allows checking if a domain is correctly
    configured for specific server infrastructure by validating:
    - IP addresses (with any/all matching modes)
    - CDN provider detection
    - Verification file existence and content
    - Email security (SPF, DKIM, DMARC)
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "domain-validator"
    name = "Domain Configuration Validator"
    description = "Validate domain configuration against infrastructure profiles"
    category = "advanced"
    icon = "check-circle"
    config_class = DomainValidatorConfig
    depends_on = ["dns", "http", "email", "cdn"]

    # ========================================================================
    # Core Analysis Logic
    # ========================================================================

    def _validate_domain_safe(self, domain: str) -> None:
        """
        Validate domain is safe for SSRF protection.

        Rejects:
        - IP addresses (IPv4/IPv6)
        - Localhost/loopback
        - Private IP ranges (10.x, 172.16.x, 192.168.x)
        - Link-local addresses (169.254.x.x - AWS metadata!)
        - Invalid formats

        Raises:
            ValueError: If domain is unsafe
        """
        import re

        # Reject IP addresses (IPv4)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            raise ValueError("IP addresses not allowed for security reasons")

        # Reject localhost/internal
        if domain.lower() in ["localhost", "127.0.0.1", "::1"]:
            raise ValueError("Localhost not allowed")

        # Reject private IP ranges
        if any(domain.startswith(prefix) for prefix in ["10.", "172.16.", "192.168."]):
            raise ValueError("Private IP ranges not allowed")

        # Reject link-local (AWS metadata, etc.)
        if domain.startswith("169.254."):
            raise ValueError("Link-local addresses not allowed")

        # Validate domain format
        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        if not domain_pattern.match(domain):
            raise ValueError(f"Invalid domain format: {domain}")

    def analyze(
        self, domain: str, config: DomainValidatorConfig, context: dict[str, Any] | None = None
    ) -> DomainValidatorResult:
        """
        Perform domain validation against active profile.

        Args:
            domain: Domain to validate
            config: Validator configuration with profiles
            context: Results from dependency analyzers (dns, http, email, cdn)

        Returns:
            DomainValidatorResult with validation status
        """
        result = DomainValidatorResult(domain=domain)

        # SSRF protection - validate domain is safe
        try:
            self._validate_domain_safe(domain)
        except ValueError as e:
            result.errors.append(f"Domain validation failed: {e}")
            logger.error(f"Domain validation failed for {domain}: {e}")
            return result

        # 1. Check if profile is active
        if not config.active_profile:
            logger.info("No active profile - skipping domain validation")
            result.profile_active = False
            return result

        # 2. Get profile config
        if config.active_profile not in config.profiles:
            result.errors.append(f"Active profile '{config.active_profile}' not found in profiles")
            return result

        profile = config.profiles[config.active_profile]
        result.profile_id = config.active_profile
        result.profile_name = profile.name
        result.profile_active = True

        # 3. Get dependency results
        if not context:
            result.dependency_errors.append(
                "No context provided - cannot access dependency results"
            )
            result.errors.extend(result.dependency_errors)
            return result

        dns_result = context.get("dns")
        http_result = context.get("http")
        email_result = context.get("email")
        cdn_result = context.get("cdn")

        # Check if dependencies succeeded
        if not dns_result or getattr(dns_result, "errors", []):
            result.dependency_errors.append("DNS analyzer failed - cannot validate IPs")

        if not http_result or getattr(http_result, "errors", []):
            # HTTP errors are only critical if we need to validate verification file
            if profile.verification_path:
                result.dependency_errors.append(
                    "HTTP analyzer failed - cannot validate verification file"
                )

        if not email_result or getattr(email_result, "errors", []):
            # Email errors are only critical if we need to validate email
            if profile.spf_includes or profile.spf_ip4 or profile.spf_ip6 or profile.dkim_selectors:
                result.dependency_errors.append(
                    "Email analyzer failed - cannot validate SPF/DKIM/DMARC"
                )

        # Stop if critical dependencies failed
        if result.dependency_errors:
            result.errors.extend(result.dependency_errors)
            return result

        # 4. Perform validation checks
        severity = "error" if config.strict_mode else "warning"

        # IP validation
        if profile.expected_ips or profile.expected_ipv6:
            self._validate_ips(result, dns_result, profile, severity)

        # CDN validation
        if profile.expected_cdn:
            self._validate_cdn(result, cdn_result, profile, severity)

        # Verification file
        if profile.verification_path:
            self._validate_verification_file(result, domain, profile, severity, config)

        # SPF validation
        if profile.spf_includes or profile.spf_ip4 or profile.spf_ip6:
            self._validate_spf(result, email_result, profile, severity)

        # DKIM validation
        if profile.dkim_selectors:
            self._validate_dkim(result, email_result, profile, severity)

        # DMARC validation
        if profile.dmarc_policy or profile.dmarc_percentage > 0:
            self._validate_dmarc(result, email_result, profile, severity)

        # 5. Calculate overall status
        result.total_checks = len(result.checks)
        result.passed_checks = sum(1 for c in result.checks if c.passed)
        result.failed_checks = result.total_checks - result.passed_checks
        result.overall_passed = result.failed_checks == 0

        # 6. Populate errors/warnings lists
        for check in result.checks:
            if not check.passed:
                # Sanitize message based on config
                if config.hide_expected_values:
                    # Secure mode - don't leak expected infrastructure details
                    message = f"{check.check_name}: Validation failed"
                    if check.details:
                        message += f" - {check.details}"
                else:
                    # Debug mode - show full details
                    expected_str = (
                        check.expected
                        if isinstance(check.expected, str)
                        else ", ".join(str(e) for e in check.expected)
                    )
                    actual_str = (
                        check.actual
                        if isinstance(check.actual, str)
                        else ", ".join(str(a) for a in check.actual)
                    )
                    message = f"{check.check_name}: Expected {expected_str}, got {actual_str}"

                if check.severity == "error":
                    result.errors.append(message)
                else:
                    result.warnings.append(message)

        return result

    # ========================================================================
    # Validation Helper Methods
    # ========================================================================

    def _sanitize_verification_path(self, path: str) -> str:
        """
        Sanitize verification path to prevent traversal attacks.

        Args:
            path: Verification file path

        Returns:
            Sanitized path

        Raises:
            ValueError: If path contains dangerous patterns
        """
        import re

        # Remove dangerous patterns
        path = path.replace("..", "").replace("//", "/")

        # Ensure starts with /
        if not path.startswith("/"):
            path = "/" + path

        # Validate only contains safe characters
        if not re.match(r"^/[a-zA-Z0-9/_.-]+$", path):
            raise ValueError(f"Invalid verification path characters: {path}")

        return path

    def _validate_ips(
        self,
        result: DomainValidatorResult,
        dns_result: Any,
        profile: DomainValidationProfile,
        severity: str,
    ) -> None:
        """Validate IP addresses from DNS A/AAAA records."""
        # Get actual IPs from DNS result
        actual_ips = []
        actual_ipv6 = []

        # Extract A records
        if hasattr(dns_result, "a_records"):
            a_records = getattr(dns_result, "a_records", [])
            actual_ips = [r.address for r in a_records if hasattr(r, "address")]

        # Extract AAAA records
        if hasattr(dns_result, "aaaa_records"):
            aaaa_records = getattr(dns_result, "aaaa_records", [])
            actual_ipv6 = [r.address for r in aaaa_records if hasattr(r, "address")]

        # Validate IPv4
        if profile.expected_ips:
            if profile.ip_match_mode == "any":
                # At least one expected IP must be in actual IPs
                passed = any(ip in actual_ips for ip in profile.expected_ips)
            else:  # all
                # All expected IPs must be in actual IPs
                passed = all(ip in actual_ips for ip in profile.expected_ips)

            result.checks.append(
                ValidationCheck(
                    check_type="ip",
                    check_name="IPv4 Addresses",
                    passed=passed,
                    expected=profile.expected_ips,
                    actual=actual_ips,
                    details=f"Match mode: {profile.ip_match_mode}",
                    severity=severity,
                )
            )

        # Validate IPv6
        if profile.expected_ipv6:
            if profile.ip_match_mode == "any":
                passed = any(ip in actual_ipv6 for ip in profile.expected_ipv6)
            else:  # all
                passed = all(ip in actual_ipv6 for ip in profile.expected_ipv6)

            result.checks.append(
                ValidationCheck(
                    check_type="ipv6",
                    check_name="IPv6 Addresses",
                    passed=passed,
                    expected=profile.expected_ipv6,
                    actual=actual_ipv6,
                    details=f"Match mode: {profile.ip_match_mode}",
                    severity=severity,
                )
            )

    def _validate_cdn(
        self,
        result: DomainValidatorResult,
        cdn_result: Any,
        profile: DomainValidationProfile,
        severity: str,
    ) -> None:
        """Validate CDN provider."""
        if not cdn_result:
            # CDN analyzer not available or disabled
            result.checks.append(
                ValidationCheck(
                    check_type="cdn",
                    check_name="CDN Provider",
                    passed=False,
                    expected=profile.expected_cdn,
                    actual="CDN analyzer not available",
                    severity=severity,
                )
            )
            return

        actual_cdn = getattr(cdn_result, "cdn_provider", None)
        passed = actual_cdn and actual_cdn.lower() == profile.expected_cdn.lower()

        result.checks.append(
            ValidationCheck(
                check_type="cdn",
                check_name="CDN Provider",
                passed=passed,
                expected=profile.expected_cdn,
                actual=actual_cdn or "None",
                severity=severity,
            )
        )

    def _validate_verification_file(
        self,
        result: DomainValidatorResult,
        domain: str,
        profile: DomainValidationProfile,
        severity: str,
        config: DomainValidatorConfig,
    ) -> None:
        """Validate verification file exists (and optionally check content)."""
        # Sanitize path
        try:
            path = self._sanitize_verification_path(profile.verification_path)
        except ValueError as e:
            result.checks.append(
                ValidationCheck(
                    check_type="verification_file",
                    check_name="Verification File",
                    passed=False,
                    expected=[profile.verification_path],
                    actual=[],
                    details=f"Invalid path: {e}",
                    severity=severity,
                )
            )
            logger.error(f"Path validation failed: {e}")
            return

        # Construct URL - try HTTPS first
        full_url = f"https://{domain}{path}"

        try:
            # Make HTTP request to check file with size limits
            with httpx.Client(
                timeout=config.timeout,
                follow_redirects=True,
                verify=True,
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            ) as client:
                response = client.get(full_url)

            status_code = response.status_code
            passed = status_code == 200

            # Check content length before reading (prevent memory exhaustion)
            content_length = response.headers.get("content-length")
            max_size = 1048576  # 1MB limit

            if content_length and int(content_length) > max_size:
                result.checks.append(
                    ValidationCheck(
                        check_type="verification_file",
                        check_name="Verification File",
                        passed=False,
                        expected=[f"{path} (status 200)"],
                        actual=[f"Response too large: {content_length} bytes (max {max_size})"],
                        details=f"File at {path} response exceeds size limit",
                        severity=severity,
                    )
                )
                logger.warning(f"Verification file too large: {content_length} bytes")
                return

            # Read with streaming for safety
            actual_content = ""
            bytes_read = 0
            for chunk in response.iter_text():
                bytes_read += len(chunk.encode("utf-8"))
                if bytes_read > max_size:
                    result.checks.append(
                        ValidationCheck(
                            check_type="verification_file",
                            check_name="Verification File",
                            passed=False,
                            expected=[f"{path} (status 200)"],
                            actual=[f"Response exceeded {max_size} bytes during streaming"],
                            details=f"File at {path} response exceeds size limit",
                            severity=severity,
                        )
                    )
                    logger.warning("Verification file exceeded size limit during read")
                    return
                actual_content += chunk

            # If content validation required
            if passed and profile.verification_content:
                if profile.verification_content not in actual_content:
                    passed = False
                    details = f"Expected content not found: '{profile.verification_content}'"
                else:
                    details = "Content matched"
            else:
                details = ""

            result.checks.append(
                ValidationCheck(
                    check_type="verification_file",
                    check_name="Verification File",
                    passed=passed,
                    expected=f"{profile.verification_path} (status 200)",
                    actual=f"Status {status_code}",
                    details=details,
                    severity=severity,
                )
            )

        except httpx.RequestError as e:
            # Connection error, timeout, etc.
            # Sanitize URL in logs
            from urllib.parse import urlparse

            parsed = urlparse(full_url)
            safe_url = f"{parsed.scheme}://{parsed.netloc}[REDACTED]"

            result.checks.append(
                ValidationCheck(
                    check_type="verification_file",
                    check_name="Verification File",
                    passed=False,
                    expected=f"{profile.verification_path} (status 200)",
                    actual=f"Error: {type(e).__name__}",
                    severity=severity,
                )
            )
            logger.debug(f"Verification file check failed for {safe_url}: {type(e).__name__}")

    def _validate_spf(
        self,
        result: DomainValidatorResult,
        email_result: Any,
        profile: DomainValidationProfile,
        severity: str,
    ) -> None:
        """Validate SPF record contains required mechanisms."""
        spf_record = getattr(email_result, "spf", None)
        if not spf_record:
            result.checks.append(
                ValidationCheck(
                    check_type="spf",
                    check_name="SPF Record",
                    passed=False,
                    expected="SPF record exists",
                    actual="No SPF record found",
                    severity=severity,
                )
            )
            return

        mechanisms = getattr(spf_record, "mechanisms", [])

        # Check includes
        if profile.spf_includes:
            if profile.spf_match_mode == "all":
                passed = all(inc in mechanisms for inc in profile.spf_includes)
            else:  # any
                passed = any(inc in mechanisms for inc in profile.spf_includes)

            actual_includes = [m for m in mechanisms if m.startswith("include:")]

            result.checks.append(
                ValidationCheck(
                    check_type="spf",
                    check_name="SPF Includes",
                    passed=passed,
                    expected=profile.spf_includes,
                    actual=actual_includes,
                    details=f"Match mode: {profile.spf_match_mode}",
                    severity=severity,
                )
            )

        # Check ip4
        if profile.spf_ip4:
            if profile.spf_match_mode == "all":
                passed = all(ip in mechanisms for ip in profile.spf_ip4)
            else:
                passed = any(ip in mechanisms for ip in profile.spf_ip4)

            actual_ip4 = [m for m in mechanisms if m.startswith("ip4:")]

            result.checks.append(
                ValidationCheck(
                    check_type="spf",
                    check_name="SPF IPv4",
                    passed=passed,
                    expected=profile.spf_ip4,
                    actual=actual_ip4,
                    details=f"Match mode: {profile.spf_match_mode}",
                    severity=severity,
                )
            )

        # Check ip6
        if profile.spf_ip6:
            if profile.spf_match_mode == "all":
                passed = all(ip in mechanisms for ip in profile.spf_ip6)
            else:
                passed = any(ip in mechanisms for ip in profile.spf_ip6)

            actual_ip6 = [m for m in mechanisms if m.startswith("ip6:")]

            result.checks.append(
                ValidationCheck(
                    check_type="spf",
                    check_name="SPF IPv6",
                    passed=passed,
                    expected=profile.spf_ip6,
                    actual=actual_ip6,
                    details=f"Match mode: {profile.spf_match_mode}",
                    severity=severity,
                )
            )

    def _validate_dkim(
        self,
        result: DomainValidatorResult,
        email_result: Any,
        profile: DomainValidationProfile,
        severity: str,
    ) -> None:
        """Validate DKIM selectors exist."""
        dkim_records = getattr(email_result, "dkim", {})
        found_selectors = list(dkim_records.keys()) if dkim_records else []

        if profile.dkim_match_mode == "all":
            passed = all(sel in found_selectors for sel in profile.dkim_selectors)
        else:  # any
            passed = any(sel in found_selectors for sel in profile.dkim_selectors)

        result.checks.append(
            ValidationCheck(
                check_type="dkim",
                check_name="DKIM Selectors",
                passed=passed,
                expected=profile.dkim_selectors,
                actual=found_selectors,
                details=f"Match mode: {profile.dkim_match_mode}",
                severity=severity,
            )
        )

    def _validate_dmarc(
        self,
        result: DomainValidatorResult,
        email_result: Any,
        profile: DomainValidationProfile,
        severity: str,
    ) -> None:
        """Validate DMARC policy."""
        dmarc_record = getattr(email_result, "dmarc", None)
        if not dmarc_record:
            result.checks.append(
                ValidationCheck(
                    check_type="dmarc",
                    check_name="DMARC Record",
                    passed=False,
                    expected="DMARC record exists",
                    actual="No DMARC record found",
                    severity=severity,
                )
            )
            return

        # Check policy
        if profile.dmarc_policy:
            actual_policy = getattr(dmarc_record, "policy", "")
            passed = actual_policy == profile.dmarc_policy

            result.checks.append(
                ValidationCheck(
                    check_type="dmarc",
                    check_name="DMARC Policy",
                    passed=passed,
                    expected=profile.dmarc_policy,
                    actual=actual_policy,
                    severity=severity,
                )
            )

        # Check percentage
        if profile.dmarc_percentage > 0:
            actual_percentage = getattr(dmarc_record, "percentage", 100)
            passed = actual_percentage >= profile.dmarc_percentage

            result.checks.append(
                ValidationCheck(
                    check_type="dmarc",
                    check_name="DMARC Percentage",
                    passed=passed,
                    expected=f">= {profile.dmarc_percentage}%",
                    actual=f"{actual_percentage}%",
                    severity=severity,
                )
            )

        # Check subdomain policy if specified
        if profile.dmarc_subdomain_policy:
            actual_subdomain_policy = getattr(dmarc_record, "subdomain_policy", "")
            passed = actual_subdomain_policy == profile.dmarc_subdomain_policy

            result.checks.append(
                ValidationCheck(
                    check_type="dmarc",
                    check_name="DMARC Subdomain Policy",
                    passed=passed,
                    expected=profile.dmarc_subdomain_policy,
                    actual=actual_subdomain_policy or "Not set",
                    severity=severity,
                )
            )

    # ========================================================================
    # Output Formatting
    # ========================================================================

    def describe_output(self, result: DomainValidatorResult) -> OutputDescriptor:
        """
        Describe how to render validation results.

        Uses semantic styling - renderers decide colors/icons.

        Args:
            result: Validation result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        if result.profile_active:
            descriptor.quiet_summary = lambda r: (
                f"Validation: {r.passed_checks}/{r.total_checks} checks passed"
            )
        else:
            descriptor.quiet_summary = lambda r: "Validation: No active profile"

        # If no profile active, show info message
        if not result.profile_active:
            descriptor.add_row(
                value="No active profile - validation skipped",
                section_type="text",
                style_class="muted",
                icon="info",
                verbosity=VerbosityLevel.NORMAL,
            )
            return descriptor

        # Profile header
        descriptor.add_row(
            label="Profile",
            value=f"{result.profile_name} ({result.profile_id})",
            style_class="info",
            icon="settings",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Overall status (prominent)
        overall_style = "success" if result.overall_passed else "error"
        overall_icon = "check" if result.overall_passed else "cross"
        overall_text = (
            "All checks passed"
            if result.overall_passed
            else f"{result.failed_checks} check(s) failed"
        )

        descriptor.add_row(
            label="Overall Status",
            value=overall_text,
            style_class=overall_style,
            icon=overall_icon,
            severity="info" if result.overall_passed else "error",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Summary counts
        descriptor.add_row(
            label="Checks Summary",
            value=f"{result.passed_checks} passed, {result.failed_checks} failed (total: {result.total_checks})",
            style_class="info",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Individual checks (verbose mode)
        if result.checks:
            descriptor.add_row(
                value="Validation Details",
                section_type="heading",
                verbosity=VerbosityLevel.VERBOSE,
            )

            for check in result.checks:
                check_style = (
                    "success"
                    if check.passed
                    else ("error" if check.severity == "error" else "warning")
                )
                check_icon = (
                    "check"
                    if check.passed
                    else ("cross" if check.severity == "error" else "warning")
                )

                # Format expected/actual for display
                expected_str = (
                    check.expected
                    if isinstance(check.expected, str)
                    else ", ".join(str(e) for e in check.expected)
                )
                actual_str = (
                    check.actual
                    if isinstance(check.actual, str)
                    else ", ".join(str(a) for a in check.actual)
                )

                descriptor.add_row(
                    label=check.check_name,
                    value="Pass" if check.passed else "Fail",
                    style_class=check_style,
                    icon=check_icon,
                    severity=check.severity,
                    verbosity=VerbosityLevel.VERBOSE,
                )

                # Show details for failed checks or in debug mode
                if not check.passed:
                    descriptor.add_row(
                        label="  Expected",
                        value=expected_str,
                        style_class="muted",
                        verbosity=VerbosityLevel.VERBOSE,
                    )
                    descriptor.add_row(
                        label="  Actual",
                        value=actual_str,
                        style_class="muted",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

                if check.details:
                    descriptor.add_row(
                        label="  Details",
                        value=check.details,
                        style_class="muted",
                        verbosity=VerbosityLevel.DEBUG,
                    )

        # Dependency errors
        for error in result.dependency_errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Standard errors
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Standard warnings
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

    def to_dict(self, result: DomainValidatorResult) -> dict[str, Any]:
        """
        Serialize to JSON-compatible dictionary.

        Args:
            result: Validation result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "profile": {
                "id": result.profile_id,
                "name": result.profile_name,
                "active": result.profile_active,
            },
            "overall_passed": result.overall_passed,
            "summary": {
                "total": result.total_checks,
                "passed": result.passed_checks,
                "failed": result.failed_checks,
            },
            "checks": [
                {
                    "type": c.check_type,
                    "name": c.check_name,
                    "passed": c.passed,
                    "expected": c.expected,
                    "actual": c.actual,
                    "details": c.details,
                    "severity": c.severity,
                }
                for c in result.checks
            ],
            "errors": result.errors,
            "warnings": result.warnings,
            "dependency_errors": result.dependency_errors,
        }
