"""Tests for progress callback functionality in run_domain_analysis."""

from webmaster_domain_tool.config import load_config
from webmaster_domain_tool.core.analyzer import run_domain_analysis


class TestProgressCallback:
    """Test progress callback functionality."""

    def test_import_analyzer_module(self):
        """Test that analyzer module can be imported (regression test for type hint error)."""
        # This test would fail if there's a syntax error in type hints
        from webmaster_domain_tool.core import analyzer

        assert analyzer is not None
        assert hasattr(analyzer, "run_domain_analysis")

    def test_progress_callback_called(self):
        """Test that progress callback is called during analysis."""
        config = load_config()
        progress_messages = []

        def progress_callback(message: str) -> None:
            progress_messages.append(message)

        # Run analysis with all checks disabled except WHOIS (fastest)
        config.dns.skip = True
        config.http.skip = True
        config.ssl.skip = True
        config.email.skip = True
        config.security_headers.skip = True
        config.site_verification.skip = True
        config.seo.skip = True
        config.favicon.skip = True

        run_domain_analysis(
            "example.com",
            config,
            progress_callback=progress_callback,
        )

        # Should have called progress callback for WHOIS
        assert len(progress_messages) > 0
        assert any("WHOIS" in msg for msg in progress_messages)

    def test_progress_callback_none(self):
        """Test that analysis works when progress_callback is None."""
        config = load_config()

        # Skip most analyzers for speed
        config.dns.skip = True
        config.http.skip = True
        config.ssl.skip = True
        config.email.skip = True
        config.security_headers.skip = True
        config.site_verification.skip = True
        config.seo.skip = True
        config.favicon.skip = True

        # Should not raise any errors
        result = run_domain_analysis(
            "example.com",
            config,
            progress_callback=None,  # Explicitly None
        )

        assert result is not None
        assert result.domain == "example.com"

    def test_progress_callback_all_analyzers(self):
        """Test that progress callback is called for all enabled analyzers."""
        config = load_config()
        progress_messages = []

        def progress_callback(message: str) -> None:
            progress_messages.append(message)

        # Run with just a few analyzers to keep test fast
        config.http.skip = True  # Skip slow ones
        config.ssl.skip = True
        config.security_headers.skip = True
        config.site_verification.skip = True
        config.seo.skip = True
        config.favicon.skip = True

        run_domain_analysis(
            "example.com",
            config,
            progress_callback=progress_callback,
        )

        # Should see messages for enabled analyzers
        assert any("WHOIS" in msg for msg in progress_messages)
        assert any("DNS" in msg for msg in progress_messages)
        assert any("email" in msg.lower() for msg in progress_messages)
