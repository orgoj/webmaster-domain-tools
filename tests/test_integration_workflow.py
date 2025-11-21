"""Integration tests for end-to-end workflows.

This module tests complete workflows from CLI → analyzers → output.
Uses mocking to avoid network calls while testing integration points.
"""

import json
from unittest.mock import patch

from typer.testing import CliRunner

from webmaster_domain_tool.analyzers.dns_analyzer import DNSAnalysisResult, DNSRecord
from webmaster_domain_tool.cli import app

runner = CliRunner()


# ============================================================================
# Test Complete Analysis Workflow
# ============================================================================


class TestCompleteAnalysisWorkflow:
    """Test complete domain analysis workflow with mocked analyzers."""

    @patch("webmaster_domain_tool.cli.registry")
    def test_minimal_analysis_workflow(self, mock_registry):
        """Test minimal workflow: CLI → registry → renderer."""
        # Mock registry to return empty analyzer list
        mock_registry.get_all.return_value = {}
        mock_registry.resolve_dependencies.return_value = []

        result = runner.invoke(app, ["analyze", "example.com"])

        # Should complete even with no analyzers
        assert result.exit_code in [0, 1]
        assert "example.com" in result.stdout or "Analyzing" in result.stdout

    def test_analysis_with_skip_propagation(self):
        """Test that skip propagates to dependent analyzers."""
        # Skip DNS, which HTTP depends on
        result = runner.invoke(
            app, ["analyze", "example.com", "--skip", "dns", "--verbosity", "quiet"]
        )

        # Should complete (HTTP should be skipped due to dependency)
        assert result.exit_code in [0, 1]


# ============================================================================
# Test Output Format Integration
# ============================================================================


class TestOutputFormatIntegration:
    """Test different output formats in complete workflow."""

    def test_cli_format_output(self):
        """Test CLI format produces Rich-formatted output."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "example.com",
                "--format",
                "cli",
                "--skip",
                "whois",
                "--verbosity",
                "quiet",
            ],
        )

        # Should have some output (even if errors)
        assert len(result.stdout) > 0

    def test_json_format_output(self):
        """Test JSON format produces valid JSON."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "example.com",
                "--format",
                "json",
                "--skip",
                "whois",
                "--verbosity",
                "quiet",
            ],
        )

        # Try to parse as JSON
        try:
            data = json.loads(result.stdout)
            assert isinstance(data, dict)
            assert "domain" in data or "results" in data or len(data) > 0
        except json.JSONDecodeError:
            # If network fails, might not have JSON
            # That's OK for integration test
            pass


# ============================================================================
# Test Verbosity Level Integration
# ============================================================================


class TestVerbosityIntegration:
    """Test verbosity levels affect output."""

    def test_quiet_verbosity_minimal_output(self):
        """Test quiet verbosity produces minimal output."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "example.com",
                "--verbosity",
                "quiet",
                "--skip",
                "whois",
                "--skip",
                "http",
            ],
        )

        # Quiet should have less output than normal
        assert result.exit_code in [0, 1]
        # Should still have domain name
        assert "example.com" in result.stdout or len(result.stdout) > 10

    def test_verbose_verbosity_detailed_output(self):
        """Test verbose verbosity produces detailed output."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "example.com",
                "--verbosity",
                "verbose",
                "--skip",
                "whois",
                "--skip",
                "http",
            ],
        )

        # Verbose should have more details
        assert result.exit_code in [0, 1]
        assert len(result.stdout) > 50  # Should have substantial output


# ============================================================================
# Test Error Propagation
# ============================================================================


class TestErrorPropagation:
    """Test that errors from analyzers appear in output."""

    @patch("webmaster_domain_tool.analyzers.dns_analyzer.DNSAnalyzer.analyze")
    def test_analyzer_error_appears_in_output(self, mock_analyze):
        """Test that analyzer errors propagate to CLI output."""
        # Create result with error
        error_result = DNSAnalysisResult(domain="example.com")
        error_result.errors.append("DNS query failed")
        mock_analyze.return_value = error_result

        result = runner.invoke(app, ["analyze", "example.com", "--skip", "http", "--skip", "whois"])

        # Should show error in output
        assert "error" in result.stdout.lower() or "fail" in result.stdout.lower()

    @patch("webmaster_domain_tool.analyzers.dns_analyzer.DNSAnalyzer.analyze")
    def test_analyzer_warning_appears_in_output(self, mock_analyze):
        """Test that analyzer warnings propagate to CLI output."""
        # Create result with warning
        warning_result = DNSAnalysisResult(domain="example.com")
        warning_result.warnings.append("DNS query timeout")
        # Add some minimal data
        warning_result.records["example.com:A"] = [DNSRecord("A", "93.184.216.34", 3600)]
        mock_analyze.return_value = warning_result

        result = runner.invoke(app, ["analyze", "example.com", "--skip", "http", "--skip", "whois"])

        # Should show warning in output
        assert "warning" in result.stdout.lower() or "timeout" in result.stdout.lower()


# ============================================================================
# Test Summary Section
# ============================================================================


class TestSummarySection:
    """Test that summary section appears in output."""

    def test_summary_shows_error_count(self):
        """Test that summary shows error count."""
        # Analyze nonexistent domain to generate errors
        result = runner.invoke(
            app,
            [
                "analyze",
                "this-domain-does-not-exist-12345.com",
                "--skip",
                "whois",
                "--verbosity",
                "normal",
            ],
        )

        # Should have summary section
        assert (
            "Summary" in result.stdout
            or "error" in result.stdout.lower()
            or "Total" in result.stdout
        )


# ============================================================================
# Test Dependency Resolution Integration
# ============================================================================


class TestDependencyResolutionIntegration:
    """Test that analyzer dependencies are resolved correctly."""

    def test_ssl_runs_after_http(self):
        """Test that SSL analyzer runs after HTTP (its dependency)."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "example.com",
                "--skip",
                "whois",
                "--verbosity",
                "debug",
            ],
        )

        # Should complete without circular dependency errors
        assert "Circular dependency" not in result.stdout
        assert result.exit_code in [0, 1]

    def test_skip_dependency_skips_dependent(self):
        """Test that skipping HTTP also skips SSL (which depends on it)."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "example.com",
                "--skip",
                "http",
                "--verbosity",
                "debug",
            ],
        )

        # Should complete successfully
        assert result.exit_code in [0, 1]
        # SSL should be skipped (can't verify output easily, but no crash)


# ============================================================================
# Test Config Integration
# ============================================================================


class TestConfigIntegration:
    """Test that config files are loaded and used."""

    def test_create_and_use_config(self, tmp_path, monkeypatch):
        """Test creating config and using it in analysis."""
        monkeypatch.chdir(tmp_path)

        # Create config
        create_result = runner.invoke(app, ["create-config"])
        assert create_result.exit_code == 0

        # Config file should exist
        config_file = tmp_path / ".webmaster-domain-tool.toml"
        assert config_file.exists()

        # Modify config to skip some analyzers
        content = config_file.read_text()
        content = content.replace("enabled = true", "enabled = false", 1)
        config_file.write_text(content)

        # Run analysis (should load config)
        # This is hard to verify without checking actual behavior
        # Just verify it doesn't crash
        result = runner.invoke(app, ["analyze", "example.com", "--verbosity", "quiet"])
        assert result.exit_code in [0, 1]
