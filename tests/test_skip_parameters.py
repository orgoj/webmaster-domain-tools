"""Tests for skip parameters in configuration.

This test file ensures all analyzers have corresponding
skip fields in their config sections.
"""

from webmaster_domain_tool.config import Config, load_config
from webmaster_domain_tool.core.analyzer import run_domain_analysis


class TestSkipParameters:
    """Test skip parameters for all analyzers."""

    def test_all_config_sections_have_skip(self):
        """Test that all analyzer config sections have skip field.

        This ensures the standardized config pattern where each analyzer
        has its own skip flag in its config section.
        """
        config = Config()

        # All analyzer sections should have skip field
        assert hasattr(config.dns, "skip")
        assert hasattr(config.http, "skip")
        assert hasattr(config.ssl, "skip")
        assert hasattr(config.email, "skip")
        assert hasattr(config.security_headers, "skip")
        assert hasattr(config.seo, "skip")
        assert hasattr(config.favicon, "skip")
        assert hasattr(config.whois, "skip")
        assert hasattr(config.site_verification, "skip")

        # All should default to False (enabled)
        assert config.dns.skip is False
        assert config.http.skip is False
        assert config.ssl.skip is False
        assert config.email.skip is False
        assert config.security_headers.skip is False
        assert config.seo.skip is False
        assert config.favicon.skip is False
        assert config.whois.skip is False
        assert config.site_verification.skip is False

    def test_skip_seo_via_config(self):
        """Test that skip_seo via config works."""
        config = load_config()

        # Set all skips via config
        config.dns.skip = True
        config.http.skip = True
        config.ssl.skip = True
        config.email.skip = True
        config.security_headers.skip = True
        config.site_verification.skip = True
        config.whois.skip = True
        config.seo.skip = True

        result = run_domain_analysis("example.com", config)

        assert result is not None
        assert result.seo is None  # Should be None when skipped

    def test_skip_favicon_via_config(self):
        """Test that skip_favicon via config works."""
        config = load_config()

        # Set all skips via config
        config.dns.skip = True
        config.http.skip = True
        config.ssl.skip = True
        config.email.skip = True
        config.security_headers.skip = True
        config.site_verification.skip = True
        config.whois.skip = True
        config.favicon.skip = True

        result = run_domain_analysis("example.com", config)

        assert result is not None
        assert result.favicon is None  # Should be None when skipped

    def test_skip_all_analyzers_via_config(self):
        """Test that all analyzers can be skipped via config."""
        config = load_config()

        # Skip all analyzers
        config.dns.skip = True
        config.http.skip = True
        config.ssl.skip = True
        config.email.skip = True
        config.security_headers.skip = True
        config.site_verification.skip = True
        config.whois.skip = True
        config.seo.skip = True
        config.favicon.skip = True

        result = run_domain_analysis("example.com", config)

        assert result is not None
        assert result.domain == "example.com"

        # All results should be None when skipped
        assert result.dns is None
        assert result.http is None
        assert result.ssl is None
        assert result.email is None
        assert result.headers is None
        assert result.site_verification is None
        assert result.whois is None
        assert result.seo is None
        assert result.favicon is None
