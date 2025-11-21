"""Tests for CLI error handling.

This module tests how the CLI handles various error conditions:
- Invalid domains
- Network failures
- Missing dependencies
- Invalid configurations
"""

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from webmaster_domain_tool.cli import app

runner = CliRunner()


# ============================================================================
# Test Invalid Domain Handling
# ============================================================================


class TestInvalidDomainHandling:
    """Test CLI handling of invalid domains."""

    def test_empty_domain(self):
        """Test analyze with empty domain."""
        result = runner.invoke(app, ["analyze", ""])
        assert result.exit_code != 0

    def test_domain_with_spaces(self):
        """Test analyze with domain containing spaces."""
        result = runner.invoke(app, ["analyze", "invalid domain"])
        assert result.exit_code != 0
        assert "Invalid domain" in result.stdout or "Error" in result.stdout

    def test_domain_with_double_dots(self):
        """Test analyze with domain containing double dots."""
        result = runner.invoke(app, ["analyze", "example..com"])
        assert result.exit_code != 0


# ============================================================================
# Test Network Error Handling
# ============================================================================


class TestNetworkErrorHandling:
    """Test CLI handling of network errors."""

    def test_nonexistent_domain(self):
        """Test analyze with nonexistent domain (NXDOMAIN)."""
        # Use a domain that definitely doesn't exist
        result = runner.invoke(
            app,
            [
                "analyze",
                "this-domain-definitely-does-not-exist-12345678.com",
                "--skip",
                "whois",  # Skip whois to speed up
            ],
        )
        # Should complete but show errors
        assert result.exit_code in [0, 1]
        # Should show error messages
        assert "error" in result.stdout.lower() or "not found" in result.stdout.lower()

    @patch("webmaster_domain_tool.analyzers.dns_analyzer.dns.resolver.resolve")
    def test_dns_timeout_handling(self, mock_resolve):
        """Test handling of DNS timeout."""
        import dns.exception

        mock_resolve.side_effect = dns.exception.Timeout()

        result = runner.invoke(app, ["analyze", "example.com", "--skip", "http", "--skip", "whois"])
        # Should complete despite timeout
        assert result.exit_code in [0, 1]


# ============================================================================
# Test Configuration Error Handling
# ============================================================================


class TestConfigErrorHandling:
    """Test CLI handling of configuration errors."""

    def test_invalid_config_file(self, tmp_path):
        """Test handling of invalid TOML config file."""
        config_file = tmp_path / "invalid.toml"
        config_file.write_text("this is not valid TOML ][")

        # CLI should handle gracefully (use defaults)
        # We can't easily test this without modifying config path logic
        # This is a placeholder for integration testing
        pass

    def test_missing_config_directory(self, tmp_path, monkeypatch):
        """Test handling when config directory doesn't exist."""
        # Should create default config without error
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["create-config"])
        assert result.exit_code == 0


# ============================================================================
# Test Keyboard Interrupt Handling
# ============================================================================


class TestKeyboardInterrupt:
    """Test CLI handling of keyboard interrupt (Ctrl+C)."""

    @patch("webmaster_domain_tool.cli.app")
    def test_keyboard_interrupt_clean_exit(self, mock_app):
        """Test that KeyboardInterrupt results in clean exit."""
        from webmaster_domain_tool.cli import main

        mock_app.side_effect = KeyboardInterrupt()

        with pytest.raises(SystemExit) as exc_info:
            main()

        # Should exit with code 130 (standard for SIGINT)
        assert exc_info.value.code == 130


# ============================================================================
# Test Unknown Analyzer Validation
# ============================================================================


class TestUnknownAnalyzerValidation:
    """Test validation of unknown analyzer IDs."""

    def test_skip_unknown_analyzer(self):
        """Test --skip with unknown analyzer shows error."""
        result = runner.invoke(
            app, ["analyze", "example.com", "--skip", "this-analyzer-does-not-exist"]
        )
        assert result.exit_code == 1
        assert "Unknown analyzer" in result.stdout

    def test_skip_multiple_with_one_unknown(self):
        """Test --skip with mix of valid and invalid analyzers."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "example.com",
                "--skip",
                "dns",
                "--skip",
                "invalid-analyzer",
            ],
        )
        assert result.exit_code == 1
        assert "Unknown analyzer" in result.stdout or "invalid-analyzer" in result.stdout


# ============================================================================
# Test Error Exit Codes
# ============================================================================


class TestErrorExitCodes:
    """Test that errors result in appropriate exit codes."""

    def test_invalid_argument_exit_code(self):
        """Test invalid argument results in non-zero exit."""
        result = runner.invoke(app, ["analyze", "example.com", "--invalid-option"])
        assert result.exit_code != 0

    def test_missing_required_argument_exit_code(self):
        """Test missing required argument results in non-zero exit."""
        result = runner.invoke(app, ["analyze"])
        assert result.exit_code != 0


# ============================================================================
# Test Output Error Messages
# ============================================================================


class TestOutputErrorMessages:
    """Test that error messages are user-friendly."""

    def test_invalid_domain_shows_helpful_message(self):
        """Test invalid domain shows helpful error message."""
        result = runner.invoke(app, ["analyze", "invalid..domain"])
        assert result.exit_code != 0
        # Should have some error indication
        assert "Invalid" in result.stdout or "Error" in result.stdout or "error" in result.stdout

    def test_unknown_command_shows_help(self):
        """Test unknown command suggests help."""
        result = runner.invoke(app, ["unknown-command"])
        assert result.exit_code != 0
        # Typer usually shows available commands
        assert "Error" in result.stdout or "Usage" in result.stdout
