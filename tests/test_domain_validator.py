"""Tests for domain configuration validator analyzer."""

import pytest

from src.webmaster_domain_tool.analyzers.domain_config_validator import (
    DomainConfigValidator,
    DomainValidationProfile,
    DomainValidatorConfig,
    DomainValidatorResult,
    ValidationCheck,
)


def test_analyzer_import():
    """Test that the analyzer can be imported."""
    assert DomainConfigValidator is not None
    assert DomainConfigValidator.analyzer_id == "domain-validator"
    assert DomainConfigValidator.name == "Domain Configuration Validator"


def test_analyzer_metadata():
    """Test analyzer metadata."""
    assert DomainConfigValidator.category == "advanced"
    assert DomainConfigValidator.icon == "check-circle"
    assert DomainConfigValidator.depends_on == ["dns", "http", "email", "cdn"]
    assert DomainConfigValidator.config_class == DomainValidatorConfig


def test_no_active_profile():
    """Test that validation is skipped when no active profile."""
    analyzer = DomainConfigValidator()
    config = DomainValidatorConfig(active_profile="")

    result = analyzer.analyze("example.com", config, context={})

    assert isinstance(result, DomainValidatorResult)
    assert result.domain == "example.com"
    assert result.profile_active is False
    assert result.total_checks == 0
    assert len(result.errors) == 0
    assert len(result.warnings) == 0


def test_invalid_profile_id():
    """Test error when active profile doesn't exist."""
    analyzer = DomainConfigValidator()
    config = DomainValidatorConfig(active_profile="nonexistent")

    result = analyzer.analyze("example.com", config, context={})

    assert result.profile_active is False
    assert len(result.errors) == 1
    assert "not found" in result.errors[0].lower()


def test_no_context_provided():
    """Test error when context is None."""
    analyzer = DomainConfigValidator()

    # Create a profile
    profile = DomainValidationProfile(
        name="Test Profile", description="Test", expected_ips=["1.2.3.4"]
    )

    config = DomainValidatorConfig(
        active_profile="test", profiles={"test": profile}, strict_mode=True
    )

    result = analyzer.analyze("example.com", config, context=None)

    assert len(result.dependency_errors) > 0
    assert "No context provided" in result.dependency_errors[0]


def test_ip_validation_any_mode():
    """Test IP validation with 'any' match mode."""
    analyzer = DomainConfigValidator()

    # Mock DNS result with A records
    class MockARecord:
        def __init__(self, address):
            self.address = address

    class MockDNSResult:
        def __init__(self):
            self.a_records = [MockARecord("1.2.3.4"), MockARecord("5.6.7.8")]
            self.aaaa_records = []
            self.errors = []

    # Create profile expecting one of the IPs
    profile = DomainValidationProfile(
        name="Test Profile",
        description="Test",
        expected_ips=["1.2.3.4", "9.9.9.9"],  # One matches, one doesn't
        ip_match_mode="any",
    )

    config = DomainValidatorConfig(active_profile="test", profiles={"test": profile})

    dns_result = MockDNSResult()
    context = {"dns": dns_result, "http": None, "email": None, "cdn": None}

    result = analyzer.analyze("example.com", config, context=context)

    assert result.profile_active is True
    assert result.total_checks == 1
    assert result.passed_checks == 1  # Should pass because at least one IP matches
    assert result.overall_passed is True


def test_ip_validation_all_mode():
    """Test IP validation with 'all' match mode."""
    analyzer = DomainConfigValidator()

    class MockARecord:
        def __init__(self, address):
            self.address = address

    class MockDNSResult:
        def __init__(self):
            self.a_records = [MockARecord("1.2.3.4")]  # Only one IP
            self.aaaa_records = []
            self.errors = []

    # Create profile expecting multiple IPs with 'all' mode
    profile = DomainValidationProfile(
        name="Test Profile",
        description="Test",
        expected_ips=["1.2.3.4", "5.6.7.8"],  # Expects both
        ip_match_mode="all",
    )

    config = DomainValidatorConfig(active_profile="test", profiles={"test": profile})

    dns_result = MockDNSResult()
    context = {"dns": dns_result, "http": None, "email": None, "cdn": None}

    result = analyzer.analyze("example.com", config, context=context)

    assert result.profile_active is True
    assert result.total_checks == 1
    assert result.passed_checks == 0  # Should fail because not all IPs present
    assert result.failed_checks == 1
    assert result.overall_passed is False
    assert len(result.errors) == 1  # In strict mode, should be error


def test_strict_mode_vs_warning_mode():
    """Test difference between strict mode and warning mode."""
    analyzer = DomainConfigValidator()

    class MockARecord:
        def __init__(self, address):
            self.address = address

    class MockDNSResult:
        def __init__(self):
            self.a_records = [MockARecord("1.2.3.4")]
            self.aaaa_records = []
            self.errors = []

    # Profile with IP that doesn't match
    profile = DomainValidationProfile(
        name="Test Profile", description="Test", expected_ips=["9.9.9.9"], ip_match_mode="any"
    )

    # Test with strict mode
    config_strict = DomainValidatorConfig(
        active_profile="test", profiles={"test": profile}, strict_mode=True
    )

    dns_result = MockDNSResult()
    context = {"dns": dns_result, "http": None, "email": None, "cdn": None}

    result_strict = analyzer.analyze("example.com", config_strict, context=context)
    assert len(result_strict.errors) == 1
    assert len(result_strict.warnings) == 0

    # Test with warning mode
    config_warning = DomainValidatorConfig(
        active_profile="test", profiles={"test": profile}, strict_mode=False
    )

    result_warning = analyzer.analyze("example.com", config_warning, context=context)
    assert len(result_warning.errors) == 0
    assert len(result_warning.warnings) == 1


def test_describe_output_no_profile():
    """Test output descriptor when no profile is active."""
    analyzer = DomainConfigValidator()
    result = DomainValidatorResult(domain="example.com", profile_active=False)

    descriptor = analyzer.describe_output(result)

    assert descriptor.title == "Domain Configuration Validator"
    assert descriptor.category == "advanced"
    assert len(descriptor.rows) > 0


def test_describe_output_with_checks():
    """Test output descriptor with validation checks."""
    analyzer = DomainConfigValidator()
    result = DomainValidatorResult(
        domain="example.com",
        profile_active=True,
        profile_id="test",
        profile_name="Test Profile",
        total_checks=2,
        passed_checks=1,
        failed_checks=1,
        overall_passed=False,
    )

    # Add some checks
    result.checks.append(
        ValidationCheck(
            check_type="ip",
            check_name="IPv4 Addresses",
            passed=True,
            expected=["1.2.3.4"],
            actual=["1.2.3.4"],
            severity="info",
        )
    )
    result.checks.append(
        ValidationCheck(
            check_type="cdn",
            check_name="CDN Provider",
            passed=False,
            expected="cloudflare",
            actual="None",
            severity="error",
        )
    )

    descriptor = analyzer.describe_output(result)

    assert descriptor.title == "Domain Configuration Validator"
    assert len(descriptor.rows) > 0


def test_to_dict():
    """Test JSON serialization."""
    analyzer = DomainConfigValidator()
    result = DomainValidatorResult(
        domain="example.com",
        profile_active=True,
        profile_id="test",
        profile_name="Test Profile",
        total_checks=1,
        passed_checks=1,
        failed_checks=0,
        overall_passed=True,
    )

    result.checks.append(
        ValidationCheck(
            check_type="ip",
            check_name="IPv4 Addresses",
            passed=True,
            expected=["1.2.3.4"],
            actual=["1.2.3.4"],
            details="Match mode: any",
            severity="info",
        )
    )

    output = analyzer.to_dict(result)

    assert output["domain"] == "example.com"
    assert output["profile"]["active"] is True
    assert output["profile"]["id"] == "test"
    assert output["profile"]["name"] == "Test Profile"
    assert output["overall_passed"] is True
    assert output["summary"]["total"] == 1
    assert output["summary"]["passed"] == 1
    assert output["summary"]["failed"] == 0
    assert len(output["checks"]) == 1
    assert output["checks"][0]["type"] == "ip"
    assert output["checks"][0]["passed"] is True


# ============================================================================
# Security Tests
# ============================================================================


def test_ssrf_protection_rejects_ipv4():
    """Test that IPv4 addresses are rejected (SSRF protection)."""
    analyzer = DomainConfigValidator()
    config = DomainValidatorConfig()

    # Try to analyze an IP address
    result = analyzer.analyze("192.168.1.1", config)

    assert result.profile_active is False
    assert len(result.errors) > 0
    assert "validation failed" in result.errors[0].lower()
    assert "ip addresses not allowed" in result.errors[0].lower()


def test_ssrf_protection_rejects_localhost():
    """Test that localhost is rejected (SSRF protection)."""
    analyzer = DomainConfigValidator()
    config = DomainValidatorConfig()

    result = analyzer.analyze("localhost", config)

    assert result.profile_active is False
    assert len(result.errors) > 0
    assert "localhost not allowed" in result.errors[0].lower()


def test_ssrf_protection_rejects_private_network():
    """Test that private IP ranges are rejected (SSRF protection)."""
    analyzer = DomainConfigValidator()
    config = DomainValidatorConfig()

    # Test various private ranges
    for ip in ["10.0.0.1", "172.16.0.1", "192.168.0.1"]:
        result = analyzer.analyze(ip, config)
        assert result.profile_active is False
        assert len(result.errors) > 0
        assert "ip addresses not allowed" in result.errors[0].lower()


def test_ssrf_protection_rejects_linklocal():
    """Test that link-local addresses are rejected (AWS metadata protection)."""
    analyzer = DomainConfigValidator()
    config = DomainValidatorConfig()

    # AWS metadata service address
    result = analyzer.analyze("169.254.169.254", config)

    assert result.profile_active is False
    assert len(result.errors) > 0
    assert "ip addresses not allowed" in result.errors[0].lower()


def test_hide_expected_values_enabled():
    """Test that expected values are hidden when hide_expected_values=True."""
    analyzer = DomainConfigValidator()

    # Create profile with expected IPs
    profile = DomainValidationProfile(
        name="Test Profile",
        expected_ips=["203.0.113.5", "203.0.113.6"],  # These should be hidden!
    )

    config = DomainValidatorConfig(
        profiles={"test": profile},
        active_profile="test",
        hide_expected_values=True,  # SECURE MODE
    )

    # Mock DNS result with different IPs
    class MockARecord:
        def __init__(self, address):
            self.address = address

    class MockDNSResult:
        def __init__(self):
            self.a_records = [MockARecord("198.51.100.1")]
            self.aaaa_records = []
            self.errors = []

    dns_result = MockDNSResult()
    context = {"dns": dns_result, "http": None, "email": None, "cdn": None}

    result = analyzer.analyze("example.com", config, context)

    # Check that error message doesn't contain expected IP addresses
    assert len(result.errors) > 0
    error_msg = " ".join(result.errors)
    assert "203.0.113.5" not in error_msg  # Expected IP should NOT be in message
    assert "203.0.113.6" not in error_msg  # Expected IP should NOT be in message
    assert "validation failed" in error_msg.lower()  # Generic message should be present


def test_hide_expected_values_disabled():
    """Test that expected values are shown when hide_expected_values=False."""
    analyzer = DomainConfigValidator()

    profile = DomainValidationProfile(
        name="Test Profile",
        expected_ips=["203.0.113.5"],
    )

    config = DomainValidatorConfig(
        profiles={"test": profile},
        active_profile="test",
        hide_expected_values=False,  # DEBUG MODE
    )

    # Mock DNS result with different IPs
    class MockARecord:
        def __init__(self, address):
            self.address = address

    class MockDNSResult:
        def __init__(self):
            self.a_records = [MockARecord("198.51.100.1")]
            self.aaaa_records = []
            self.errors = []

    dns_result = MockDNSResult()
    context = {"dns": dns_result, "http": None, "email": None, "cdn": None}

    result = analyzer.analyze("example.com", config, context)

    # Check that error message DOES contain expected values (debug mode)
    assert len(result.errors) > 0
    error_msg = " ".join(result.errors)
    assert "203.0.113.5" in error_msg  # Expected IP SHOULD be in message


def test_path_traversal_protection():
    """Test that path traversal attempts are sanitized and invalid chars rejected."""
    analyzer = DomainConfigValidator()

    # Paths with .. and // are sanitized (removed)
    # The method removes these patterns rather than rejecting them
    result1 = analyzer._sanitize_verification_path("/../../../etc/passwd")
    assert ".." not in result1  # .. should be removed

    result2 = analyzer._sanitize_verification_path("/path//with//double//slashes")
    assert "//" not in result2  # // should be removed

    # But invalid characters should raise ValueError
    with pytest.raises(ValueError, match="Invalid verification path characters"):
        analyzer._sanitize_verification_path("/path/with spaces/file.txt")

    with pytest.raises(ValueError, match="Invalid verification path characters"):
        analyzer._sanitize_verification_path("/path/with@special#chars.txt")


def test_path_sanitization_valid():
    """Test that valid paths pass sanitization."""
    analyzer = DomainConfigValidator()

    # Valid paths should work
    assert analyzer._sanitize_verification_path("/valid/path.txt") == "/valid/path.txt"
    assert analyzer._sanitize_verification_path("valid/path.txt") == "/valid/path.txt"
    assert (
        analyzer._sanitize_verification_path("/.well-known/verify.txt") == "/.well-known/verify.txt"
    )


def test_cdn_dependency_declared():
    """Test that CDN is properly declared as dependency."""
    analyzer = DomainConfigValidator()

    assert "cdn" in analyzer.depends_on
    assert "dns" in analyzer.depends_on
    assert "http" in analyzer.depends_on
    assert "email" in analyzer.depends_on
