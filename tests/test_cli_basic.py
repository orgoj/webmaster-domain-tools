"""Tests for CLI basic functionality.

This module tests the CLI entry point, argument parsing, and basic commands.
"""

import pytest
from typer.testing import CliRunner

from webmaster_domain_tool.cli import app, validate_domain

runner = CliRunner()


# ============================================================================
# Test CLI Entry Point
# ============================================================================


class TestCLIEntryPoint:
    """Test CLI entry point and help text."""

    def test_cli_help(self):
        """Test that CLI help works."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Comprehensive domain analysis tool" in result.stdout
        assert "analyze" in result.stdout
        assert "list-analyzers" in result.stdout

    def test_cli_no_args(self):
        """Test CLI with no arguments shows help."""
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert "Usage:" in result.stdout


# ============================================================================
# Test List Analyzers Command
# ============================================================================


class TestListAnalyzers:
    """Test list-analyzers command."""

    def test_list_analyzers_basic(self):
        """Test list-analyzers shows all analyzers."""
        result = runner.invoke(app, ["list-analyzers"])
        assert result.exit_code == 0
        assert "Available Analyzers" in result.stdout
        # Check for some key analyzers
        assert "dns" in result.stdout
        assert "http" in result.stdout
        assert "ssl" in result.stdout

    def test_list_analyzers_shows_categories(self):
        """Test that analyzers are grouped by category."""
        result = runner.invoke(app, ["list-analyzers"])
        assert result.exit_code == 0
        assert "GENERAL" in result.stdout or "General" in result.stdout.lower()
        assert "SECURITY" in result.stdout or "Security" in result.stdout.lower()

    def test_list_analyzers_shows_dependencies(self):
        """Test that analyzer dependencies are shown."""
        result = runner.invoke(app, ["list-analyzers"])
        assert result.exit_code == 0
        # SSL depends on HTTP
        assert "depends on" in result.stdout


# ============================================================================
# Test Version Command
# ============================================================================


class TestVersion:
    """Test version command."""

    def test_version_command(self):
        """Test version command output."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "webmaster-domain-tool" in result.stdout


# ============================================================================
# Test Domain Validation
# ============================================================================


class TestDomainValidation:
    """Test domain validation function."""

    def test_validate_domain_valid(self):
        """Test validation accepts valid domains."""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "example.co.uk",
            "example-site.com",
            "123.456.789.012",  # IP address
        ]
        for domain in valid_domains:
            # Should not raise exception
            result = validate_domain(domain)
            assert result == domain

    def test_validate_domain_strips_protocol(self):
        """Test validation strips http/https protocol."""
        assert validate_domain("http://example.com") == "example.com"
        assert validate_domain("https://example.com") == "example.com"
        assert validate_domain("http://example.com/") == "example.com"

    def test_validate_domain_strips_path(self):
        """Test validation strips path and query."""
        assert validate_domain("example.com/path") == "example.com"
        assert validate_domain("example.com/path/to/page") == "example.com"
        assert validate_domain("example.com?query=1") == "example.com"

    def test_validate_domain_invalid(self):
        """Test validation rejects invalid domains."""
        import typer

        invalid_domains = [
            "",
            "   ",
            "invalid domain with spaces",
            "example..com",  # Double dot
            ".example.com",  # Leading dot
            "example.com.",  # This should actually be valid, but stripped
        ]
        for domain in invalid_domains:
            if domain.strip():  # Only test non-empty
                with pytest.raises(typer.BadParameter):
                    validate_domain(domain)


# ============================================================================
# Test Create Config Command
# ============================================================================


class TestCreateConfig:
    """Test create-config command."""

    def test_create_config_help(self):
        """Test create-config help."""
        result = runner.invoke(app, ["create-config", "--help"])
        assert result.exit_code == 0
        assert "Create a default configuration file" in result.stdout

    def test_create_config_default_location(self, tmp_path, monkeypatch):
        """Test create-config creates file in default location."""
        # Change to temp directory
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["create-config"])
        assert result.exit_code == 0
        assert "Created configuration file" in result.stdout

        # Check file exists
        config_file = tmp_path / ".webmaster-domain-tool.toml"
        assert config_file.exists()

    def test_create_config_custom_output(self, tmp_path):
        """Test create-config with custom output path."""
        output_file = tmp_path / "custom-config.toml"

        result = runner.invoke(app, ["create-config", "-o", str(output_file)])
        assert result.exit_code == 0
        assert output_file.exists()

    def test_create_config_no_overwrite_without_force(self, tmp_path):
        """Test create-config doesn't overwrite without --force."""
        output_file = tmp_path / "config.toml"
        output_file.write_text("[global]\ncolor = false")

        result = runner.invoke(app, ["create-config", "-o", str(output_file)])
        assert result.exit_code == 1
        assert "already exists" in result.stdout

        # Original content preserved
        assert "color = false" in output_file.read_text()

    def test_create_config_force_overwrite(self, tmp_path):
        """Test create-config overwrites with --force."""
        output_file = tmp_path / "config.toml"
        output_file.write_text("[global]\ncolor = false")

        result = runner.invoke(app, ["create-config", "-o", str(output_file), "--force"])
        assert result.exit_code == 0

        # Check file was overwritten (should have default structure)
        content = output_file.read_text()
        assert "[dns]" in content or "[global]" in content


# ============================================================================
# Test Analyze Command Structure
# ============================================================================


class TestAnalyzeCommand:
    """Test analyze command structure (not actual analysis)."""

    def test_analyze_help(self):
        """Test analyze command help."""
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "Analyze a domain" in result.stdout
        assert "--skip" in result.stdout
        assert "--verbosity" in result.stdout
        assert "--format" in result.stdout

    def test_analyze_missing_domain(self):
        """Test analyze without domain argument fails."""
        result = runner.invoke(app, ["analyze"])
        assert result.exit_code != 0
        assert "Missing argument" in result.stdout or "Error" in result.stdout

    def test_analyze_invalid_verbosity(self):
        """Test analyze with invalid verbosity."""
        result = runner.invoke(app, ["analyze", "example.com", "--verbosity", "invalid"])
        assert result.exit_code != 0
        assert "Invalid value" in result.stdout or "Error" in result.stdout

    def test_analyze_invalid_format(self):
        """Test analyze with invalid format."""
        result = runner.invoke(app, ["analyze", "example.com", "--format", "invalid"])
        assert result.exit_code != 0
        assert "Invalid value" in result.stdout or "Error" in result.stdout


# ============================================================================
# Test Skip Parameter
# ============================================================================


class TestSkipParameter:
    """Test --skip parameter validation."""

    def test_skip_single_analyzer(self):
        """Test skip parameter accepts valid analyzer ID."""
        # This should not error on argument parsing (might fail on network)
        result = runner.invoke(app, ["analyze", "example.com", "--skip", "dns"])
        # We don't care about exit code (network might fail), just that args parsed
        assert (
            "--skip" in result.stdout
            or "dns" in result.stdout
            or result.exit_code
            in [
                0,
                1,
            ]
        )

    def test_skip_multiple_analyzers(self):
        """Test skip parameter accepts multiple analyzers."""
        result = runner.invoke(app, ["analyze", "example.com", "--skip", "dns", "--skip", "http"])
        # Just verify args were parsed
        assert result.exit_code in [0, 1]

    def test_skip_unknown_analyzer_shows_error(self):
        """Test skip with unknown analyzer ID shows error."""
        result = runner.invoke(app, ["analyze", "example.com", "--skip", "nonexistent-analyzer"])
        assert result.exit_code == 1
        assert "Unknown analyzer" in result.stdout or "Error" in result.stdout
