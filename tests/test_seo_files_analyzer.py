"""Tests for SEO Files Analyzer."""

from unittest.mock import Mock, patch

from webmaster_domain_tool.analyzers.seo_files_analyzer import SEOFilesAnalyzer


class TestSEOFilesAnalyzer:
    """Test SEOFilesAnalyzer class."""

    def test_create_analyzer(self):
        """Test creating analyzer instance."""
        analyzer = SEOFilesAnalyzer(timeout=10.0)
        assert analyzer is not None
        assert analyzer.timeout == 10.0

    @patch("webmaster_domain_tool.analyzers.seo_files_analyzer.httpx.Client")
    def test_empty_sitemap_is_error(self, mock_client):
        """Test that empty sitemap (0 URLs) is reported as error."""
        # Mock response with empty but valid sitemap XML
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
</urlset>"""
        mock_response.content = mock_response.text.encode("utf-8")

        # Mock the context manager
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance
        mock_client.return_value.__exit__.return_value = False

        analyzer = SEOFilesAnalyzer(
            timeout=10.0, check_sitemap=True, check_robots=False, check_llms_txt=False
        )
        result = analyzer.analyze("https://example.com")

        # Should have error about empty sitemap
        assert any("empty" in error.lower() and "0" in error for error in result.errors)
        assert len(result.sitemaps) > 0
        assert result.sitemaps[0].url_count == 0

    @patch("webmaster_domain_tool.analyzers.seo_files_analyzer.httpx.Client")
    def test_sitemap_with_urls_success(self, mock_client):
        """Test that sitemap with URLs is successful."""
        # Mock response with valid sitemap containing URLs
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://example.com/page1</loc>
    </url>
    <url>
        <loc>https://example.com/page2</loc>
    </url>
</urlset>"""
        mock_response.content = mock_response.text.encode("utf-8")

        # Mock the context manager
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance
        mock_client.return_value.__exit__.return_value = False

        analyzer = SEOFilesAnalyzer(
            timeout=10.0, check_sitemap=True, check_robots=False, check_llms_txt=False
        )
        result = analyzer.analyze("https://example.com")

        # Should NOT have error about empty sitemap
        assert not any("empty" in error.lower() for error in result.errors)
        assert len(result.sitemaps) > 0
        assert result.sitemaps[0].url_count == 2

    @patch("webmaster_domain_tool.analyzers.seo_files_analyzer.httpx.Client")
    def test_invalid_sitemap_xml_is_error(self, mock_client):
        """Test that invalid XML in sitemap is reported as error."""
        # Mock response with invalid XML
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "not valid xml"
        mock_response.content = mock_response.text.encode("utf-8")

        # Mock the context manager
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance
        mock_client.return_value.__exit__.return_value = False

        analyzer = SEOFilesAnalyzer(
            timeout=10.0, check_sitemap=True, check_robots=False, check_llms_txt=False
        )
        result = analyzer.analyze("https://example.com")

        # Should have parse error (aggregated from sitemap errors)
        assert any("parse" in error.lower() or "xml" in error.lower() for error in result.errors)

    @patch("webmaster_domain_tool.analyzers.seo_files_analyzer.httpx.Client")
    def test_large_sitemap_warning(self, mock_client):
        """Test that large sitemap (>50k URLs) triggers warning."""
        # Mock response with sitemap containing many URLs
        urls = "\n".join(
            [f"<url><loc>https://example.com/page{i}</loc></url>" for i in range(50001)]
        )
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}
</urlset>"""
        mock_response.content = mock_response.text.encode("utf-8")

        # Mock the context manager
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance
        mock_client.return_value.__exit__.return_value = False

        analyzer = SEOFilesAnalyzer(
            timeout=10.0, check_sitemap=True, check_robots=False, check_llms_txt=False
        )
        result = analyzer.analyze("https://example.com")

        # Should have warning about large sitemap (aggregated from sitemap warnings)
        assert any("50" in warning and "000" in warning for warning in result.warnings)
        assert len(result.sitemaps) > 0
        assert result.sitemaps[0].url_count == 50001
