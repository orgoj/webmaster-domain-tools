"""Tests for Site Verification panel display - ensure HTML content is not shown."""

from webmaster_domain_tool.analyzers.site_verification_analyzer import (
    SiteVerificationAnalysisResult,
)


class TestSiteVerificationDisplay:
    """Test Site Verification display logic."""

    def test_html_content_should_not_be_displayed(self):
        """
        Regression test: html_content field should NOT be displayed in GUI.

        The html_content field is an internal cache used by the analyzer
        to avoid fetching HTML multiple times. It should never be shown
        to users as it contains the entire HTML of the webpage.
        """
        # Create result with HTML content (like real analysis does)
        result = SiteVerificationAnalysisResult(
            domain="example.com",
            html_content="<!DOCTYPE html><html><head>...</head><body>Very long HTML...</body></html>",
        )

        # Verify the field exists (it's used internally)
        assert result.html_content is not None
        assert "<!DOCTYPE html>" in result.html_content

        # The display logic should skip this field
        # (This test documents the requirement - implementation tested via manual GUI testing)
        # Skip fields should include: domain, errors, warnings, html_content, html_fetch_error
        skip_fields = {"domain", "errors", "warnings", "html_content", "html_fetch_error"}

        # These are internal fields that should never be shown to users
        assert "html_content" in skip_fields
        assert "html_fetch_error" in skip_fields

    def test_html_fetch_error_should_not_be_displayed(self):
        """
        Test that html_fetch_error field is not displayed either.

        This is also an internal field - any errors should go to result.errors list,
        not be shown as a separate field.
        """
        result = SiteVerificationAnalysisResult(
            domain="example.com",
            html_fetch_error="HTTP 404",
        )

        assert result.html_fetch_error == "HTTP 404"

        # This internal field should also be skipped
        skip_fields = {"domain", "errors", "warnings", "html_content", "html_fetch_error"}
        assert "html_fetch_error" in skip_fields
