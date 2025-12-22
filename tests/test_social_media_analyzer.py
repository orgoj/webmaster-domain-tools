"""Tests for social media analyzer."""

from bs4 import BeautifulSoup

from webmaster_domain_tool.analyzers.social_media_analyzer import (
    OpenGraphData,
    SocialMediaAnalyzer,
    SocialMediaConfig,
    SocialMediaResult,
    TwitterCardData,
)


class TestImport:
    """Test module import (catches type hint errors)."""

    def test_import_analyzer_module(self):
        """Test that analyzer module can be imported."""
        from webmaster_domain_tool.analyzers import social_media_analyzer

        assert social_media_analyzer is not None


class TestOpenGraphData:
    """Test Open Graph data dataclass."""

    def test_create_og_data(self):
        """Test creating Open Graph data."""
        og = OpenGraphData(
            title="Test Title",
            type="website",
            image="https://example.com/image.jpg",
            url="https://example.com",
        )
        assert og.title == "Test Title"
        assert og.type == "website"
        assert og.image == "https://example.com/image.jpg"
        assert og.url == "https://example.com"

    def test_og_data_defaults(self):
        """Test Open Graph data defaults."""
        og = OpenGraphData()
        assert og.title is None
        assert og.type is None
        assert og.image is None
        assert og.url is None
        assert og.description is None
        assert len(og.article_tag) == 0


class TestTwitterCardData:
    """Test Twitter Card data dataclass."""

    def test_create_twitter_card(self):
        """Test creating Twitter Card data."""
        twitter = TwitterCardData(
            card="summary_large_image",
            site="@example",
            title="Test Title",
        )
        assert twitter.card == "summary_large_image"
        assert twitter.site == "@example"
        assert twitter.title == "Test Title"

    def test_twitter_card_defaults(self):
        """Test Twitter Card data defaults."""
        twitter = TwitterCardData()
        assert twitter.card is None
        assert twitter.site is None
        assert twitter.creator is None


class TestSocialMediaResult:
    """Test social media result dataclass."""

    def test_social_media_result_defaults(self):
        """Test social media result defaults."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        assert result.domain == "example.com"
        assert result.url == "https://example.com"
        assert result.success is False
        assert result.has_og_required is False
        assert result.has_twitter_card is False
        assert len(result.errors) == 0
        assert len(result.warnings) == 0
        assert len(result.recommendations) == 0


class TestSocialMediaAnalyzer:
    """Test social media analyzer."""

    def test_create_analyzer(self):
        """Test creating social media analyzer."""
        analyzer = SocialMediaAnalyzer()
        assert analyzer.analyzer_id == "social-media"
        assert analyzer.name == "Social Media"
        assert analyzer.config_class == SocialMediaConfig
        assert analyzer.category == "seo"

    def test_config_defaults(self):
        """Test analyzer config defaults."""
        config = SocialMediaConfig()
        assert config.enabled is True
        assert config.timeout == 10.0
        assert config.check_image_dimensions is False

    def test_extract_open_graph(self):
        """Test extracting Open Graph tags from HTML."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta property="og:title" content="Test Title">
            <meta property="og:type" content="website">
            <meta property="og:image" content="https://example.com/image.jpg">
            <meta property="og:url" content="https://example.com">
            <meta property="og:description" content="Test description">
            <meta property="og:site_name" content="Example Site">
        </head>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        analyzer = SocialMediaAnalyzer()

        analyzer._extract_open_graph(soup, result)

        assert result.og.title == "Test Title"
        assert result.og.type == "website"
        assert result.og.image == "https://example.com/image.jpg"
        assert result.og.url == "https://example.com"
        assert result.og.description == "Test description"
        assert result.og.site_name == "Example Site"
        assert result.has_og_required is True

    def test_extract_open_graph_missing_required(self):
        """Test extracting incomplete Open Graph tags."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta property="og:title" content="Test Title">
            <meta property="og:description" content="Test description">
        </head>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        analyzer = SocialMediaAnalyzer()

        analyzer._extract_open_graph(soup, result)

        assert result.og.title == "Test Title"
        assert result.og.description == "Test description"
        assert result.og.type is None
        assert result.og.image is None
        assert result.has_og_required is False

    def test_extract_twitter_card(self):
        """Test extracting Twitter Card tags from HTML."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="twitter:card" content="summary_large_image">
            <meta name="twitter:site" content="@example">
            <meta name="twitter:creator" content="@author">
            <meta name="twitter:title" content="Test Title">
            <meta name="twitter:description" content="Test description">
            <meta name="twitter:image" content="https://example.com/image.jpg">
        </head>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        analyzer = SocialMediaAnalyzer()

        analyzer._extract_twitter_card(soup, result)

        assert result.twitter.card == "summary_large_image"
        assert result.twitter.site == "@example"
        assert result.twitter.creator == "@author"
        assert result.twitter.title == "Test Title"
        assert result.twitter.description == "Test description"
        assert result.twitter.image == "https://example.com/image.jpg"
        assert result.has_twitter_card is True

    def test_extract_twitter_card_missing(self):
        """Test extracting when no Twitter Card is present."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test</title>
        </head>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        analyzer = SocialMediaAnalyzer()

        analyzer._extract_twitter_card(soup, result)

        assert result.twitter.card is None
        assert result.has_twitter_card is False

    def test_validate_complete_og(self):
        """Test validation with complete Open Graph tags."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        result.og.title = "This is a good title for social media"
        result.og.type = "website"
        result.og.image = "https://example.com/image.jpg"
        result.og.url = "https://example.com"
        result.og.description = (
            "This is a good description for social media sharing with enough length"
        )
        result.og.site_name = "Example Site"
        result.has_og_required = True

        config = SocialMediaConfig()
        analyzer = SocialMediaAnalyzer()
        analyzer._validate(result, config)

        # Should have no errors
        assert len(result.errors) == 0

    def test_validate_missing_og_required(self):
        """Test validation with missing required OG tags."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        result.og.title = "Test"
        result.has_og_required = False

        config = SocialMediaConfig()
        analyzer = SocialMediaAnalyzer()
        analyzer._validate(result, config)

        # Should have error about missing required tags
        assert len(result.errors) > 0
        assert any("Missing required Open Graph tags" in e for e in result.errors)

    def test_validate_title_length_warnings(self):
        """Test validation warnings for title length."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        result.og.title = "Short"  # Too short
        result.og.type = "website"
        result.og.image = "https://example.com/image.jpg"
        result.og.url = "https://example.com"
        result.has_og_required = True

        config = SocialMediaConfig()
        analyzer = SocialMediaAnalyzer()
        analyzer._validate(result, config)

        # Should have warning about short title
        assert any("og:title too short" in w for w in result.warnings)

    def test_validate_description_length_warnings(self):
        """Test validation warnings for description length."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        result.og.title = "Good title for social media"
        result.og.type = "website"
        result.og.image = "https://example.com/image.jpg"
        result.og.url = "https://example.com"
        result.og.description = "Too short"  # Too short
        result.has_og_required = True

        config = SocialMediaConfig()
        analyzer = SocialMediaAnalyzer()
        analyzer._validate(result, config)

        # Should have warning about short description
        assert any("og:description too short" in w for w in result.warnings)

    def test_validate_twitter_card_type(self):
        """Test validation of Twitter Card type."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        result.twitter.card = "invalid_type"
        result.has_twitter_card = True
        result.has_og_required = True

        config = SocialMediaConfig()
        analyzer = SocialMediaAnalyzer()
        analyzer._validate(result, config)

        # Should have warning about invalid card type
        assert any("Invalid twitter:card type" in w for w in result.warnings)

    def test_validate_http_image_warning(self):
        """Test warning for HTTP images instead of HTTPS."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        result.og.title = "Good title for social media"
        result.og.type = "website"
        result.og.image = "http://example.com/image.jpg"  # HTTP not HTTPS
        result.og.url = "https://example.com"
        result.has_og_required = True

        config = SocialMediaConfig()
        analyzer = SocialMediaAnalyzer()
        analyzer._validate(result, config)

        # Should have warning about HTTP image
        assert any("og:image uses HTTP instead of HTTPS" in w for w in result.warnings)

    def test_to_dict(self):
        """Test serialization to dictionary."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        result.success = True
        result.og.title = "Test Title"
        result.og.type = "website"
        result.twitter.card = "summary"
        result.has_og_required = False
        result.has_twitter_card = True

        analyzer = SocialMediaAnalyzer()
        data = analyzer.to_dict(result)

        assert data["domain"] == "example.com"
        assert data["url"] == "https://example.com"
        assert data["success"] is True
        assert data["open_graph"]["title"] == "Test Title"
        assert data["open_graph"]["type"] == "website"
        assert data["twitter_card"]["card"] == "summary"
        assert data["validation"]["has_og_required"] is False
        assert data["validation"]["has_twitter_card"] is True

    def test_describe_output(self):
        """Test output descriptor generation."""
        result = SocialMediaResult(domain="example.com", url="https://example.com")
        result.success = True
        result.has_og_required = True
        result.has_twitter_card = True

        analyzer = SocialMediaAnalyzer()
        descriptor = analyzer.describe_output(result)

        assert descriptor.title == "Social Media"
        assert descriptor.category == "seo"
        assert len(descriptor.rows) > 0
