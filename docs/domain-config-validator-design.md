# DomainConfigValidator Analyzer - Design Document

## Overview

**Purpose**: Validate that a domain is correctly configured for specific server infrastructure.

**Key Features**:
- Profile-based validation (multiple infrastructure configurations)
- IP/CDN validation
- Verification file checking
- Email security validation (SPF, DKIM, DMARC)
- Disabled by default (opt-in)
- Graceful skipping when no profile active

---

## 1. Pydantic Config Schema

### Structure

```python
"""Domain configuration validator - validates domains against infrastructure profiles.

This analyzer checks if a domain is correctly configured for specific infrastructure
by validating IP addresses, CDN usage, verification files, and email security settings.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from pydantic import Field

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
        default_factory=list,
        description="Expected IPv4 addresses (A records)"
    )
    expected_ipv6: list[str] = Field(
        default_factory=list,
        description="Expected IPv6 addresses (AAAA records)"
    )
    expected_cdn: str = Field(
        default="",
        description="Expected CDN provider name (e.g., 'cloudflare', 'fastly')"
    )
    allow_cname_redirect: bool = Field(
        default=True,
        description="Allow CNAME chain before reaching expected IPs"
    )
    ip_match_mode: str = Field(
        default="any",
        description="IP matching mode: 'any' (at least one matches) or 'all' (all must match)"
    )

    # Verification file check
    verification_path: str = Field(
        default="",
        description="Path to verification file (e.g., '/.well-known/verification.txt')"
    )
    verification_content: str = Field(
        default="",
        description="Expected content in verification file (optional - just checks existence if empty)"
    )
    verification_method: str = Field(
        default="GET",
        description="HTTP method for verification check (GET or HEAD)"
    )

    # SPF validation
    spf_includes: list[str] = Field(
        default_factory=list,
        description="Required SPF include mechanisms (e.g., ['include:_spf.google.com'])"
    )
    spf_ip4: list[str] = Field(
        default_factory=list,
        description="Required SPF ip4 mechanisms (e.g., ['ip4:203.0.113.0/24'])"
    )
    spf_ip6: list[str] = Field(
        default_factory=list,
        description="Required SPF ip6 mechanisms"
    )
    spf_match_mode: str = Field(
        default="all",
        description="SPF matching: 'all' (must contain all) or 'any' (at least one)"
    )

    # DKIM validation
    dkim_selectors: list[str] = Field(
        default_factory=list,
        description="Required DKIM selectors that must exist (e.g., ['default', 'google'])"
    )
    dkim_match_mode: str = Field(
        default="all",
        description="DKIM matching: 'all' (all must exist) or 'any' (at least one)"
    )

    # DMARC validation
    dmarc_policy: str = Field(
        default="",
        description="Required DMARC policy ('none', 'quarantine', 'reject', or '' for any)"
    )
    dmarc_subdomain_policy: str = Field(
        default="",
        description="Required subdomain policy ('' for don't care)"
    )
    dmarc_percentage: int = Field(
        default=0,
        description="Minimum DMARC percentage (0 = don't check)"
    )


class DomainValidatorConfig(AnalyzerConfig):
    """Domain validator configuration."""

    # Active profile selection
    active_profile: str = Field(
        default="",
        description="Name of active profile to use (empty = skip validation)"
    )

    # Profile definitions
    profiles: dict[str, DomainValidationProfile] = Field(
        default_factory=dict,
        description="Map of profile_id -> profile config"
    )

    # Behavior
    strict_mode: bool = Field(
        default=True,
        description="Strict mode: all checks must pass (vs. warnings for failures)"
    )
```

---

## 2. TOML Configuration Examples

### Example 1: Web Server Infrastructure

```toml
[domain-validator]
enabled = true
active_profile = "web-server-1"
strict_mode = true

[domain-validator.profiles.web-server-1]
name = "Production Web Server"
description = "Main web infrastructure on dedicated server"

# IP validation - domain must resolve to one of these IPs
expected_ips = ["203.0.113.10", "203.0.113.11"]
expected_ipv6 = ["2001:db8::1"]
ip_match_mode = "any"  # At least one IP must match
allow_cname_redirect = true

# Verification file must exist
verification_path = "/.well-known/server-verification.txt"
verification_content = "web-server-1-token-abc123"

# SPF must include our mail server
spf_includes = ["include:_spf.example.com"]
spf_ip4 = ["ip4:203.0.113.10"]
spf_match_mode = "all"

# DKIM selectors must exist
dkim_selectors = ["default", "backup"]
dkim_match_mode = "all"

# DMARC must be quarantine or reject
dmarc_policy = "quarantine"
dmarc_percentage = 100
```

### Example 2: Cloudflare CDN Setup

```toml
[domain-validator]
enabled = true
active_profile = "cloudflare-cdn"

[domain-validator.profiles.cloudflare-cdn]
name = "Cloudflare CDN Setup"
description = "Domain proxied through Cloudflare"

# CDN validation (not specific IPs)
expected_cdn = "cloudflare"

# No verification file needed for CDN
verification_path = ""

# Email through Google Workspace
spf_includes = ["include:_spf.google.com"]
dkim_selectors = ["google"]
dmarc_policy = ""  # Any policy is acceptable
```

### Example 3: Email-Only Server

```toml
[domain-validator]
enabled = true
active_profile = "email-only"
strict_mode = false  # Warnings instead of errors

[domain-validator.profiles.email-only]
name = "Email-Only Server"
description = "Email server without web hosting"

# No IP/CDN validation
expected_ips = []
expected_cdn = ""

# No verification file
verification_path = ""

# Multiple email providers
spf_includes = ["include:_spf.google.com", "include:mailgun.org"]
spf_ip4 = ["ip4:198.51.100.50"]
spf_match_mode = "all"

dkim_selectors = ["google", "mailgun"]
dkim_match_mode = "all"

dmarc_policy = "reject"
dmarc_percentage = 100
```

### Example 4: Disabled (Default)

```toml
[domain-validator]
enabled = true
active_profile = ""  # No active profile = skip validation

# Profiles can be defined but not active
[domain-validator.profiles.future-migration]
name = "Future Server"
expected_ips = ["192.0.2.1"]
```

---

## 3. Dataclass Result Structure

```python
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
```

---

## 4. Analyzer Logic Flow (Pseudo-code)

```python
@registry.register
class DomainConfigValidator:
    """
    Validates domain configuration against infrastructure profiles.
    """

    analyzer_id = "domain-validator"
    name = "Domain Configuration Validator"
    description = "Validate domain configuration against infrastructure profiles"
    category = "advanced"
    icon = "check-circle"
    config_class = DomainValidatorConfig
    depends_on = ["dns", "http", "email"]

    def analyze(
        self,
        domain: str,
        config: DomainValidatorConfig,
        context: dict[str, Any] | None = None
    ) -> DomainValidatorResult:
        """
        Perform domain validation against active profile.

        Args:
            domain: Domain to validate
            config: Validator configuration
            context: Results from dependency analyzers (dns, http, email)

        Returns:
            DomainValidatorResult with validation status
        """
        result = DomainValidatorResult(domain=domain)

        # 1. Check if profile is active
        if not config.active_profile:
            logger.info("No active profile - skipping domain validation")
            result.profile_active = False
            return result

        # 2. Get profile config
        if config.active_profile not in config.profiles:
            result.errors.append(
                f"Active profile '{config.active_profile}' not found in profiles"
            )
            return result

        profile = config.profiles[config.active_profile]
        result.profile_id = config.active_profile
        result.profile_name = profile.name
        result.profile_active = True

        # 3. Get dependency results
        if not context:
            result.dependency_errors.append("No context provided - cannot access dependency results")
            return result

        dns_result = context.get("dns")
        http_result = context.get("http")
        email_result = context.get("email")

        # Check if dependencies succeeded
        if not dns_result or getattr(dns_result, "errors", []):
            result.dependency_errors.append("DNS analyzer failed - cannot validate IPs")

        if not email_result or getattr(email_result, "errors", []):
            result.dependency_errors.append("Email analyzer failed - cannot validate SPF/DKIM/DMARC")

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
            self._validate_cdn(result, context.get("cdn"), profile, severity)

        # Verification file
        if profile.verification_path:
            self._validate_verification_file(
                result, domain, http_result, profile, severity, config
            )

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
                message = f"{check.check_name}: Expected {check.expected}, got {check.actual}"
                if check.severity == "error":
                    result.errors.append(message)
                else:
                    result.warnings.append(message)

        return result

    # ========================================================================
    # Validation Helper Methods
    # ========================================================================

    def _validate_ips(
        self,
        result: DomainValidatorResult,
        dns_result: Any,
        profile: DomainValidationProfile,
        severity: str
    ) -> None:
        """Validate IP addresses from DNS A/AAAA records."""

        # Get actual IPs from DNS result
        actual_ips = []
        actual_ipv6 = []

        # Extract A records
        a_records = getattr(dns_result, "a_records", [])
        actual_ips = [r.address for r in a_records]

        # Extract AAAA records
        aaaa_records = getattr(dns_result, "aaaa_records", [])
        actual_ipv6 = [r.address for r in aaaa_records]

        # Validate IPv4
        if profile.expected_ips:
            if profile.ip_match_mode == "any":
                passed = any(ip in profile.expected_ips for ip in actual_ips)
            else:  # all
                passed = all(ip in actual_ips for ip in profile.expected_ips)

            result.checks.append(ValidationCheck(
                check_type="ip",
                check_name="IPv4 Addresses",
                passed=passed,
                expected=profile.expected_ips,
                actual=actual_ips,
                details=f"Match mode: {profile.ip_match_mode}",
                severity=severity
            ))

        # Validate IPv6
        if profile.expected_ipv6:
            if profile.ip_match_mode == "any":
                passed = any(ip in profile.expected_ipv6 for ip in actual_ipv6)
            else:  # all
                passed = all(ip in actual_ipv6 for ip in profile.expected_ipv6)

            result.checks.append(ValidationCheck(
                check_type="ipv6",
                check_name="IPv6 Addresses",
                passed=passed,
                expected=profile.expected_ipv6,
                actual=actual_ipv6,
                details=f"Match mode: {profile.ip_match_mode}",
                severity=severity
            ))

    def _validate_cdn(
        self,
        result: DomainValidatorResult,
        cdn_result: Any,
        profile: DomainValidationProfile,
        severity: str
    ) -> None:
        """Validate CDN provider."""

        actual_cdn = getattr(cdn_result, "cdn_provider", None) if cdn_result else None
        passed = actual_cdn and actual_cdn.lower() == profile.expected_cdn.lower()

        result.checks.append(ValidationCheck(
            check_type="cdn",
            check_name="CDN Provider",
            passed=passed,
            expected=profile.expected_cdn,
            actual=actual_cdn or "None",
            severity=severity
        ))

    def _validate_verification_file(
        self,
        result: DomainValidatorResult,
        domain: str,
        http_result: Any,
        profile: DomainValidationProfile,
        severity: str,
        config: DomainValidatorConfig
    ) -> None:
        """Validate verification file exists (and optionally check content)."""

        from .http_analyzer import HTTPAnalyzer, HTTPConfig

        # Use HTTP analyzer to check path
        http_analyzer = HTTPAnalyzer()
        http_config = HTTPConfig(timeout=config.timeout)

        # Construct URL
        base_url = f"https://{domain}"
        path_result = http_analyzer.check_path(base_url, profile.verification_path, http_config)

        passed = path_result.status_code == 200

        # If content validation required
        if passed and profile.verification_content:
            actual_content = getattr(path_result, "content", "")
            passed = profile.verification_content in actual_content

        result.checks.append(ValidationCheck(
            check_type="verification_file",
            check_name="Verification File",
            passed=passed,
            expected=f"{profile.verification_path} (status 200)",
            actual=f"Status {path_result.status_code if path_result else 'N/A'}",
            details=profile.verification_content if profile.verification_content else "",
            severity=severity
        ))

    def _validate_spf(
        self,
        result: DomainValidatorResult,
        email_result: Any,
        profile: DomainValidationProfile,
        severity: str
    ) -> None:
        """Validate SPF record contains required mechanisms."""

        spf_record = getattr(email_result, "spf", None)
        if not spf_record:
            result.checks.append(ValidationCheck(
                check_type="spf",
                check_name="SPF Record",
                passed=False,
                expected="SPF record exists",
                actual="No SPF record found",
                severity=severity
            ))
            return

        mechanisms = getattr(spf_record, "mechanisms", [])

        # Check includes
        if profile.spf_includes:
            if profile.spf_match_mode == "all":
                passed = all(inc in mechanisms for inc in profile.spf_includes)
            else:  # any
                passed = any(inc in mechanisms for inc in profile.spf_includes)

            result.checks.append(ValidationCheck(
                check_type="spf",
                check_name="SPF Includes",
                passed=passed,
                expected=profile.spf_includes,
                actual=[m for m in mechanisms if m.startswith("include:")],
                details=f"Match mode: {profile.spf_match_mode}",
                severity=severity
            ))

        # Check ip4
        if profile.spf_ip4:
            if profile.spf_match_mode == "all":
                passed = all(ip in mechanisms for ip in profile.spf_ip4)
            else:
                passed = any(ip in mechanisms for ip in profile.spf_ip4)

            result.checks.append(ValidationCheck(
                check_type="spf",
                check_name="SPF IPv4",
                passed=passed,
                expected=profile.spf_ip4,
                actual=[m for m in mechanisms if m.startswith("ip4:")],
                severity=severity
            ))

        # Similar for ip6...

    def _validate_dkim(
        self,
        result: DomainValidatorResult,
        email_result: Any,
        profile: DomainValidationProfile,
        severity: str
    ) -> None:
        """Validate DKIM selectors exist."""

        dkim_records = getattr(email_result, "dkim", {})
        found_selectors = list(dkim_records.keys())

        if profile.dkim_match_mode == "all":
            passed = all(sel in found_selectors for sel in profile.dkim_selectors)
        else:  # any
            passed = any(sel in found_selectors for sel in profile.dkim_selectors)

        result.checks.append(ValidationCheck(
            check_type="dkim",
            check_name="DKIM Selectors",
            passed=passed,
            expected=profile.dkim_selectors,
            actual=found_selectors,
            details=f"Match mode: {profile.dkim_match_mode}",
            severity=severity
        ))

    def _validate_dmarc(
        self,
        result: DomainValidatorResult,
        email_result: Any,
        profile: DomainValidationProfile,
        severity: str
    ) -> None:
        """Validate DMARC policy."""

        dmarc_record = getattr(email_result, "dmarc", None)
        if not dmarc_record:
            result.checks.append(ValidationCheck(
                check_type="dmarc",
                check_name="DMARC Record",
                passed=False,
                expected="DMARC record exists",
                actual="No DMARC record found",
                severity=severity
            ))
            return

        actual_policy = getattr(dmarc_record, "policy", "")

        # Check policy
        if profile.dmarc_policy:
            passed = actual_policy == profile.dmarc_policy

            result.checks.append(ValidationCheck(
                check_type="dmarc",
                check_name="DMARC Policy",
                passed=passed,
                expected=profile.dmarc_policy,
                actual=actual_policy,
                severity=severity
            ))

        # Check percentage
        if profile.dmarc_percentage > 0:
            actual_percentage = getattr(dmarc_record, "percentage", 100)
            passed = actual_percentage >= profile.dmarc_percentage

            result.checks.append(ValidationCheck(
                check_type="dmarc",
                check_name="DMARC Percentage",
                passed=passed,
                expected=f">= {profile.dmarc_percentage}%",
                actual=f"{actual_percentage}%",
                severity=severity
            ))
```

---

## 5. Output Descriptor Design

```python
def describe_output(self, result: DomainValidatorResult) -> OutputDescriptor:
    """
    Describe how to render validation results.

    Uses semantic styling - renderers decide colors/icons.
    """
    descriptor = OutputDescriptor(
        title=self.name,
        category=self.category
    )

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
            verbosity=VerbosityLevel.NORMAL
        )
        return descriptor

    # Profile header
    descriptor.add_row(
        label="Profile",
        value=f"{result.profile_name} ({result.profile_id})",
        style_class="info",
        icon="settings",
        verbosity=VerbosityLevel.NORMAL
    )

    # Overall status (prominent)
    overall_style = "success" if result.overall_passed else "error"
    overall_icon = "check" if result.overall_passed else "cross"
    overall_text = "All checks passed" if result.overall_passed else f"{result.failed_checks} check(s) failed"

    descriptor.add_row(
        label="Overall Status",
        value=overall_text,
        style_class=overall_style,
        icon=overall_icon,
        severity="info" if result.overall_passed else "error",
        verbosity=VerbosityLevel.NORMAL
    )

    # Summary counts
    descriptor.add_row(
        label="Checks Summary",
        value=f"{result.passed_checks} passed, {result.failed_checks} failed (total: {result.total_checks})",
        style_class="info",
        verbosity=VerbosityLevel.NORMAL
    )

    # Individual checks (verbose mode)
    descriptor.add_row(
        value="Validation Details",
        section_type="heading",
        verbosity=VerbosityLevel.VERBOSE
    )

    for check in result.checks:
        check_style = "success" if check.passed else "error"
        check_icon = "check" if check.passed else "cross"

        # Format expected/actual for display
        expected_str = check.expected if isinstance(check.expected, str) else ", ".join(check.expected)
        actual_str = check.actual if isinstance(check.actual, str) else ", ".join(check.actual)

        descriptor.add_row(
            label=check.check_name,
            value="Pass" if check.passed else "Fail",
            style_class=check_style,
            icon=check_icon,
            severity=check.severity,
            verbosity=VerbosityLevel.VERBOSE
        )

        # Show details in debug mode
        if not check.passed or True:  # Always show for failed checks
            descriptor.add_row(
                label="  Expected",
                value=expected_str,
                style_class="muted",
                verbosity=VerbosityLevel.VERBOSE
            )
            descriptor.add_row(
                label="  Actual",
                value=actual_str,
                style_class="muted",
                verbosity=VerbosityLevel.VERBOSE
            )
            if check.details:
                descriptor.add_row(
                    label="  Details",
                    value=check.details,
                    style_class="muted",
                    verbosity=VerbosityLevel.DEBUG
                )

    # Dependency errors
    for error in result.dependency_errors:
        descriptor.add_row(
            value=error,
            section_type="text",
            style_class="error",
            severity="error",
            icon="warning",
            verbosity=VerbosityLevel.NORMAL
        )

    # Standard errors
    for error in result.errors:
        descriptor.add_row(
            value=error,
            section_type="text",
            style_class="error",
            severity="error",
            icon="cross",
            verbosity=VerbosityLevel.NORMAL
        )

    # Standard warnings
    for warning in result.warnings:
        descriptor.add_row(
            value=warning,
            section_type="text",
            style_class="warning",
            severity="warning",
            icon="warning",
            verbosity=VerbosityLevel.NORMAL
        )

    return descriptor


def to_dict(self, result: DomainValidatorResult) -> dict[str, Any]:
    """Serialize to JSON."""
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
```

---

## 6. Edge Cases & Error Handling

### Edge Case 1: No Active Profile

**Scenario**: `active_profile = ""`

**Handling**:
- Return result with `profile_active = False`
- No validation performed
- Output shows "No active profile - validation skipped"
- Analyzer succeeds (not an error)

```python
if not config.active_profile:
    result.profile_active = False
    return result  # Success - just nothing to do
```

### Edge Case 2: Invalid Profile ID

**Scenario**: `active_profile = "nonexistent"`

**Handling**:
- Add error to `result.errors`
- Return early
- Output shows clear error message

```python
if config.active_profile not in config.profiles:
    result.errors.append(f"Profile '{config.active_profile}' not found")
    return result
```

### Edge Case 3: Dependency Analyzer Failed

**Scenario**: DNS analyzer failed (timeout, NXDOMAIN, etc.)

**Handling**:
- Check for errors in dependency results
- Populate `result.dependency_errors`
- Cannot perform validation - return early
- Clear error message about which dependency failed

```python
if not dns_result or dns_result.errors:
    result.dependency_errors.append("DNS analyzer failed - cannot validate IPs")

if result.dependency_errors:
    result.errors.extend(result.dependency_errors)
    return result
```

### Edge Case 4: Multiple IPs - Match Mode "any" vs "all"

**Scenario**: Profile expects `["203.0.113.10", "203.0.113.11"]`, domain has `["203.0.113.10"]`

**Handling**:
- `ip_match_mode = "any"`: PASS (at least one matches)
- `ip_match_mode = "all"`: FAIL (not all expected IPs present)

```python
if profile.ip_match_mode == "any":
    passed = any(ip in profile.expected_ips for ip in actual_ips)
else:  # all
    passed = all(ip in actual_ips for ip in profile.expected_ips)
```

### Edge Case 5: CDN Detection Not Available

**Scenario**: Profile expects CDN, but CDN analyzer is disabled/skipped

**Handling**:
- Check if `context.get("cdn")` is None
- Mark check as failed with clear message
- Don't crash - graceful degradation

```python
cdn_result = context.get("cdn")
if not cdn_result:
    result.checks.append(ValidationCheck(
        check_type="cdn",
        check_name="CDN Provider",
        passed=False,
        expected=profile.expected_cdn,
        actual="CDN analyzer not available",
        severity=severity
    ))
```

### Edge Case 6: Verification File - Content Check

**Scenario**: File exists (200) but content doesn't match

**Handling**:
- First check: status code 200
- If passed AND content validation required, check content
- Clear distinction in output between "file not found" vs "wrong content"

```python
passed = path_result.status_code == 200

if passed and profile.verification_content:
    actual_content = path_result.content or ""
    if profile.verification_content not in actual_content:
        passed = False
        details = f"Expected content not found: '{profile.verification_content}'"
```

### Edge Case 7: Strict Mode vs Warning Mode

**Scenario**: Check fails, but `strict_mode = false`

**Handling**:
- Set `severity = "warning"` instead of `"error"`
- Check still marked as `passed = False`
- Goes to `result.warnings` instead of `result.errors`
- `overall_passed` still requires all checks to pass

```python
severity = "error" if config.strict_mode else "warning"

# Later...
if not check.passed:
    if check.severity == "error":
        result.errors.append(message)
    else:
        result.warnings.append(message)
```

### Edge Case 8: Optional Checks (Empty Values)

**Scenario**: Profile has `verification_path = ""` (no verification needed)

**Handling**:
- Skip that validation check entirely
- Don't add to `result.checks`
- No "N/A" or "skipped" entries

```python
if profile.verification_path:  # Only if configured
    self._validate_verification_file(...)

# NOT this:
# if not profile.verification_path:
#     result.checks.append(... skipped ...)
```

### Edge Case 9: Empty Expected Lists

**Scenario**: `expected_ips = []` AND `expected_cdn = ""`

**Handling**:
- No IP/CDN validation performed
- Valid use case (e.g., email-only profile)
- No warning or error

```python
if profile.expected_ips or profile.expected_ipv6:
    self._validate_ips(...)

if profile.expected_cdn:
    self._validate_cdn(...)
```

### Edge Case 10: Context Not Provided

**Scenario**: `context = None` (should never happen in normal usage)

**Handling**:
- Guard check at start
- Add to `dependency_errors`
- Return early with clear error

```python
if not context:
    result.dependency_errors.append("No context provided")
    result.errors.extend(result.dependency_errors)
    return result
```

---

## 7. CLI Output Examples

### Example: All Checks Pass

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Domain Configuration Validator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Profile            Production Web Server (web-server-1)
Overall Status     ✓ All checks passed
Checks Summary     6 passed, 0 failed (total: 6)

# Verbose mode shows:
Validation Details
  IPv4 Addresses   ✓ Pass
  Verification File ✓ Pass
  SPF Includes     ✓ Pass
  SPF IPv4         ✓ Pass
  DKIM Selectors   ✓ Pass
  DMARC Policy     ✓ Pass
```

### Example: Some Checks Fail (Strict Mode)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Domain Configuration Validator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Profile            Production Web Server (web-server-1)
Overall Status     ✗ 2 check(s) failed
Checks Summary     4 passed, 2 failed (total: 6)

# Verbose mode:
Validation Details
  IPv4 Addresses   ✗ Fail
    Expected       203.0.113.10, 203.0.113.11
    Actual         198.51.100.50
  Verification File ✗ Fail
    Expected       /.well-known/server-verification.txt (status 200)
    Actual         Status 404
  SPF Includes     ✓ Pass
  DKIM Selectors   ✓ Pass
  DMARC Policy     ✓ Pass

Errors:
  ✗ IPv4 Addresses: Expected ['203.0.113.10', '203.0.113.11'], got ['198.51.100.50']
  ✗ Verification File: Expected /.well-known/server-verification.txt (status 200), got Status 404
```

### Example: No Active Profile

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Domain Configuration Validator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

No active profile - validation skipped
```

---

## 8. Implementation Checklist

- [ ] Create `src/webmaster_domain_tool/analyzers/domain_config_validator.py`
- [ ] Implement `DomainValidationProfile` Pydantic model
- [ ] Implement `DomainValidatorConfig` Pydantic model
- [ ] Implement `ValidationCheck` dataclass
- [ ] Implement `DomainValidatorResult` dataclass
- [ ] Implement `DomainConfigValidator` class with `@registry.register`
- [ ] Implement `analyze()` method with context parameter
- [ ] Implement validation helper methods:
  - [ ] `_validate_ips()`
  - [ ] `_validate_cdn()`
  - [ ] `_validate_verification_file()`
  - [ ] `_validate_spf()`
  - [ ] `_validate_dkim()`
  - [ ] `_validate_dmarc()`
- [ ] Implement `describe_output()` with semantic styling
- [ ] Implement `to_dict()` for JSON serialization
- [ ] Add example profiles to `default_config.toml` (commented out by default)
- [ ] Write unit tests:
  - [ ] Test with no active profile (should skip)
  - [ ] Test with invalid profile ID
  - [ ] Test IP validation (any/all modes)
  - [ ] Test CDN validation
  - [ ] Test verification file (existence + content)
  - [ ] Test SPF validation
  - [ ] Test DKIM validation
  - [ ] Test DMARC validation
  - [ ] Test strict vs warning mode
  - [ ] Test dependency failures
- [ ] Update README.md with domain validator documentation
- [ ] Update CHANGELOG.md
- [ ] Bump version in pyproject.toml

---

## 9. Design Benefits

### Universal & Flexible
- ✓ Profile-based: Easy to define multiple infrastructure setups
- ✓ Mix-and-match: Can validate any combination of IP/CDN/files/email
- ✓ Match modes: Configurable "any" vs "all" matching

### Clear & Debugged
- ✓ Granular checks: Each validation is separate
- ✓ Detailed output: Shows expected vs actual for failures
- ✓ Verbosity levels: Summary vs detailed view

### Safe & Explicit
- ✓ Disabled by default: Requires explicit profile activation
- ✓ Graceful degradation: Handles missing dependencies
- ✓ Strict mode: Can be warnings instead of errors

### Maintainable
- ✓ Self-contained: Single file analyzer
- ✓ Zero coupling: Uses protocol, context, semantic styling
- ✓ Well-documented: Clear edge case handling

---

## 10. Future Enhancements (Out of Scope)

- Profile inheritance (base + override)
- Regular expression matching for verification content
- Custom DNS nameservers per profile
- Timeout configuration per check type
- Profile templates (web-server, email-server, cdn-proxy)
- Multiple active profiles (validate against all)
- Profile validation warnings (e.g., "Both IPs and CDN configured")
