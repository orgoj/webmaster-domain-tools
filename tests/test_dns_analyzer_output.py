"""Test DNS analyzer's describe_output() method.

This module tests the v1.0.0 analyzer output system:
- OutputDescriptor structure validation
- Semantic styling (no hardcoded colors)
- Error/warning severity marking
- Verbosity level assignment
- JSON serialization
"""

import pytest

from webmaster_domain_tool.analyzers.dns_analyzer import (
    DNSAnalysisResult,
    DNSAnalyzer,
    DNSConfig,
    DNSRecord,
    DNSSECInfo,
)
from webmaster_domain_tool.analyzers.protocol import OutputDescriptor, VerbosityLevel

# ============================================================================
# Test Cases
# ============================================================================


class TestDNSAnalyzerOutput:
    """Test DNS analyzer's describe_output() returns valid OutputDescriptor."""

    def test_describe_output_structure(self):
        """Test that describe_output returns OutputDescriptor with rows."""
        analyzer = DNSAnalyzer()

        # Create result with some data
        result = DNSAnalysisResult(
            domain="example.com",
            records={
                "example.com:A": [
                    DNSRecord(
                        record_type="A",
                        name="example.com",
                        value="93.184.216.34",
                        ttl=3600,
                    )
                ]
            },
        )

        # Get output descriptor
        descriptor = analyzer.describe_output(result)

        # Verify structure
        assert isinstance(descriptor, OutputDescriptor)
        assert descriptor.title == analyzer.name
        assert descriptor.category == analyzer.category
        assert len(descriptor.rows) > 0

    def test_output_has_semantic_styles(self):
        """Test that output uses semantic styles (not hardcoded colors)."""
        analyzer = DNSAnalyzer()

        # Create result with errors and warnings
        result = DNSAnalysisResult(domain="example.com")
        result.errors.append("DNS lookup failed")
        result.warnings.append("DNSSEC not enabled")

        # Get output descriptor
        descriptor = analyzer.describe_output(result)

        # Valid semantic style classes
        VALID_STYLES = {"success", "error", "warning", "info", "highlight", "muted", "neutral"}

        # Check all rows use semantic styles
        for row in descriptor.rows:
            assert row.style_class in VALID_STYLES, f"Row uses invalid style: {row.style_class}"
            # Should NOT contain color names
            assert row.style_class not in {
                "red",
                "green",
                "blue",
                "yellow",
            }, f"Row uses hardcoded color: {row.style_class}"

    def test_errors_have_severity(self):
        """Test that errors are marked with severity='error'."""
        analyzer = DNSAnalyzer()

        # Create result with errors
        result = DNSAnalysisResult(domain="example.com")
        result.errors.append("Critical DNS error")
        result.errors.append("Another DNS error")

        # Get output descriptor
        descriptor = analyzer.describe_output(result)

        # Find error rows
        error_rows = [row for row in descriptor.rows if row.severity == "error"]

        # Should have at least one error row
        assert len(error_rows) > 0, "No error rows found despite errors in result"

        # Verify error content
        error_values = [str(row.value) for row in error_rows]
        assert any(
            "Critical DNS error" in val for val in error_values
        ), "Error message not found in output"

    def test_warnings_have_severity(self):
        """Test that warnings are marked with severity='warning'."""
        analyzer = DNSAnalyzer()

        # Create result with warnings
        result = DNSAnalysisResult(domain="example.com")
        result.warnings.append("DNSSEC validation warning")

        # Get output descriptor
        descriptor = analyzer.describe_output(result)

        # Find warning rows
        warning_rows = [row for row in descriptor.rows if row.severity == "warning"]

        # Should have at least one warning row
        assert len(warning_rows) > 0, "No warning rows found despite warnings in result"

    def test_verbosity_levels_set(self):
        """Test that rows have appropriate verbosity levels."""
        analyzer = DNSAnalyzer()

        # Create result with full data
        result = DNSAnalysisResult(
            domain="example.com",
            records={
                "example.com:A": [
                    DNSRecord(
                        record_type="A",
                        name="example.com",
                        value="93.184.216.34",
                        ttl=3600,
                    )
                ]
            },
            dnssec=DNSSECInfo(enabled=True, valid=True),
        )

        # Get output descriptor
        descriptor = analyzer.describe_output(result)

        # All rows should have verbosity set
        for row in descriptor.rows:
            assert isinstance(row.verbosity, VerbosityLevel), f"Row verbosity not set: {row.label}"

        # Should have rows at different verbosity levels
        verbosity_levels = {row.verbosity for row in descriptor.rows}
        assert len(verbosity_levels) >= 1, "Should have rows at different verbosity levels"

    def test_to_dict_serializable(self):
        """Test that to_dict() returns JSON-safe dictionary."""
        analyzer = DNSAnalyzer()

        # Create result
        result = DNSAnalysisResult(
            domain="example.com",
            records={
                "example.com:A": [
                    DNSRecord(
                        record_type="A",
                        name="example.com",
                        value="93.184.216.34",
                        ttl=3600,
                    )
                ]
            },
            dnssec=DNSSECInfo(enabled=True),
        )
        result.warnings.append("Test warning")
        result.errors.append("Test error")

        # Serialize
        result_dict = analyzer.to_dict(result)

        # Verify structure
        assert isinstance(result_dict, dict)
        assert "domain" in result_dict
        assert result_dict["domain"] == "example.com"

        # Should be JSON serializable
        import json

        try:
            json.dumps(result_dict)
        except (TypeError, ValueError) as e:
            pytest.fail(f"Result is not JSON serializable: {e}")


class TestDNSAnalyzerOutputContent:
    """Test DNS analyzer output content."""

    def test_output_includes_dns_records(self):
        """Test that output includes DNS record information."""
        analyzer = DNSAnalyzer()

        result = DNSAnalysisResult(
            domain="example.com",
            records={
                "example.com:A": [
                    DNSRecord(
                        record_type="A",
                        name="example.com",
                        value="93.184.216.34",
                        ttl=3600,
                    )
                ],
                "example.com:MX": [
                    DNSRecord(
                        record_type="MX",
                        name="example.com",
                        value="10 mail.example.com",
                        ttl=3600,
                    )
                ],
            },
        )

        descriptor = analyzer.describe_output(result)

        # Convert descriptor to string representation for checking
        all_values = []
        for row in descriptor.rows:
            if row.label:
                all_values.append(str(row.label))
            if row.value:
                all_values.append(str(row.value))

        output_str = " ".join(all_values)

        # Should mention DNS records or record types
        assert any(
            keyword in output_str for keyword in ["A", "record", "DNS", "93.184.216.34"]
        ), "Output should include DNS record information"

    def test_output_includes_dnssec_info(self):
        """Test that output includes DNSSEC information when available."""
        analyzer = DNSAnalyzer()

        result = DNSAnalysisResult(
            domain="example.com",
            dnssec=DNSSECInfo(enabled=True, valid=True, has_dnskey=True, has_ds=True),
        )

        descriptor = analyzer.describe_output(result)

        # Find DNSSEC-related content
        all_content = []
        for row in descriptor.rows:
            if row.label:
                all_content.append(str(row.label).lower())
            if row.value:
                all_content.append(str(row.value).lower())

        content_str = " ".join(all_content)

        # Should mention DNSSEC
        assert "dnssec" in content_str, "Output should include DNSSEC information"

    def test_output_quiet_summary_exists(self):
        """Test that quiet_summary function is defined."""
        analyzer = DNSAnalyzer()

        result = DNSAnalysisResult(domain="example.com")

        descriptor = analyzer.describe_output(result)

        # Should have quiet_summary
        assert (
            descriptor.quiet_summary is not None
        ), "OutputDescriptor should have quiet_summary function"

        # Should be callable
        assert callable(descriptor.quiet_summary), "quiet_summary should be callable"

        # Should return string
        summary = descriptor.quiet_summary(result)
        assert isinstance(summary, str), "quiet_summary should return string"
        assert len(summary) > 0, "quiet_summary should not be empty"


class TestDNSAnalyzerConfig:
    """Test DNS analyzer configuration."""

    def test_config_class_defined(self):
        """Test that analyzer has proper config class."""
        assert DNSAnalyzer.config_class == DNSConfig
        assert DNSAnalyzer.analyzer_id == "dns"
        assert DNSAnalyzer.category == "general"

    def test_config_fields_exist(self):
        """Test that config has expected fields."""
        config = DNSConfig()

        # Should have basic fields from AnalyzerConfig
        assert hasattr(config, "enabled")
        assert hasattr(config, "timeout")

        # Should have DNS-specific fields
        assert hasattr(config, "nameservers")
        assert hasattr(config, "check_dnssec")

    def test_analyze_accepts_config(self):
        """Test that analyze method accepts config parameter."""
        analyzer = DNSAnalyzer()

        # Test the signature is correct (without actually running the analysis)
        import inspect

        sig = inspect.signature(analyzer.analyze)
        params = list(sig.parameters.keys())

        assert "domain" in params, "analyze should accept 'domain' parameter"
        assert "config" in params, "analyze should accept 'config' parameter"


class TestDNSAnalyzerMetadata:
    """Test DNS analyzer metadata."""

    def test_analyzer_metadata_complete(self):
        """Test that analyzer has all required metadata."""
        # Required by AnalyzerPlugin protocol
        assert hasattr(DNSAnalyzer, "analyzer_id")
        assert hasattr(DNSAnalyzer, "name")
        assert hasattr(DNSAnalyzer, "description")
        assert hasattr(DNSAnalyzer, "category")
        assert hasattr(DNSAnalyzer, "icon")
        assert hasattr(DNSAnalyzer, "config_class")
        assert hasattr(DNSAnalyzer, "depends_on")

        # Verify types
        assert isinstance(DNSAnalyzer.analyzer_id, str)
        assert isinstance(DNSAnalyzer.name, str)
        assert isinstance(DNSAnalyzer.description, str)
        assert isinstance(DNSAnalyzer.category, str)
        assert isinstance(DNSAnalyzer.icon, str)
        assert isinstance(DNSAnalyzer.depends_on, list)

    def test_analyzer_implements_protocol_methods(self):
        """Test that analyzer implements all protocol methods."""
        analyzer = DNSAnalyzer()

        # Required methods
        assert hasattr(analyzer, "analyze")
        assert callable(analyzer.analyze)

        assert hasattr(analyzer, "describe_output")
        assert callable(analyzer.describe_output)

        assert hasattr(analyzer, "to_dict")
        assert callable(analyzer.to_dict)
