"""Tests for the Cookies & Consent analyzer."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from webmaster_domain_tool.analyzers.cookies_consent import (
    CookiesConsentAnalyzer,
    CookiesConsentConfig,
    CookiesConsentResult,
    CMPInfo,
    BannerInfo,
    CookiePolicyInfo,
    ComplianceIndicators,
    KNOWN_CMPS,
)
from webmaster_domain_tool.core.registry import registry


class TestCookiesConsentAnalyzer:
    """Test the CookiesConsentAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return CookiesConsentAnalyzer()

    @pytest.fixture
    def config(self):
        """Create default config."""
        return CookiesConsentConfig()

    def test_analyzer_registered(self):
        """Test that analyzer is registered."""
        metadata = registry.get("cookies_consent")
        assert metadata is not None
        assert metadata.analyzer_id == "cookies_consent"
        assert metadata.name == "Cookies & Consent"
        assert metadata.category == "compliance"
        assert metadata.icon == "cookie"

    def test_analyzer_metadata(self, analyzer):
        """Test analyzer metadata attributes."""
        assert analyzer.analyzer_id == "cookies_consent"
        assert analyzer.name == "Cookies & Consent"
        assert "GDPR" in analyzer.description
        assert analyzer.category == "compliance"
        assert analyzer.icon == "cookie"
        assert analyzer.config_class == CookiesConsentConfig
        assert "http" in analyzer.depends_on

    def test_config_defaults(self, config):
        """Test default configuration values."""
        assert config.timeout == 15.0
        assert config.check_cookie_policy is True
        assert config.detect_cmp is True
        assert config.check_banner_presence is True
        assert config.enabled is True

    def test_known_cmps_defined(self):
        """Test that known CMPs are defined."""
        assert len(KNOWN_CMPS) >= 15
        assert "onetrust" in KNOWN_CMPS
        assert "cookiebot" in KNOWN_CMPS
        assert "quantcast" in KNOWN_CMPS

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_analyze_no_consent_banner(self, mock_client, analyzer, config):
        """Test analysis when no consent banner is present."""
        # Mock HTTP response with no consent elements
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test Site</title></head>
        <body>
            <h1>Welcome</h1>
            <p>No consent banner here.</p>
        </body>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)

        result = analyzer.analyze("example.com", config)

        assert result.success is True
        assert result.banner is not None
        assert result.banner.detected is False
        assert result.compliance is not None
        assert result.compliance.compliance_score < 50
        assert result.compliance.has_consent_mechanism is False

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_analyze_with_oneTrust_cmp(self, mock_client, analyzer, config):
        """Test detection of OneTrust CMP."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>
        </head>
        <body>
            <div id="onetrust-banner-sdk" class="cookie-banner">
                <p>We use cookies!</p>
                <button id="onetrust-accept-btn-handler">Accept All</button>
                <button id="onetrust-reject-all-handler">Reject All</button>
                <button id="onetrust-pc-btn-handler">Cookie Settings</button>
            </div>
        </body>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)

        result = analyzer.analyze("example.com", config)

        assert result.success is True
        assert result.cmp_detected is not None
        assert result.cmp_detected.name == "OneTrust"
        assert result.banner is not None
        assert result.banner.detected is True
        assert result.banner.has_accept_button is True
        assert result.banner.has_reject_button is True
        assert result.banner.has_customize_button is True
        assert result.compliance.compliance_score >= 80

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_analyze_with_cookiebot_cmp(self, mock_client, analyzer, config):
        """Test detection of Cookiebot CMP."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="https://consent.cookiebot.com/uc.js"></script>
        </head>
        <body>
            <div id="CybotCookiebotDialog">
                <p>Cookie consent dialog</p>
            </div>
        </body>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)

        result = analyzer.analyze("example.com", config)

        assert result.success is True
        assert result.cmp_detected is not None
        assert result.cmp_detected.name == "Cookiebot"

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_analyze_with_cookie_policy(self, mock_client, analyzer, config):
        """Test detection of cookie policy link."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test Site</title></head>
        <body>
            <footer>
                <a href="/cookie-policy">Cookie Policy</a>
                <a href="/privacy">Privacy Policy</a>
            </footer>
        </body>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        # Mock for main page and policy check
        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_get = Mock(return_value=mock_response)
        mock_client.return_value.__enter__.return_value.get = mock_get
        mock_client.return_value.__enter__.return_value.head = Mock(
            return_value=Mock(status_code=200)
        )

        result = analyzer.analyze("example.com", config)

        assert result.success is True
        assert result.cookie_policy is not None
        assert result.cookie_policy.found is True
        assert "cookie-policy" in result.cookie_policy.url

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_analyze_generic_banner(self, mock_client, analyzer, config):
        """Test detection of generic consent banner."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test Site</title></head>
        <body>
            <div id="cookie-consent-banner" class="gdpr-notice">
                <p>This site uses cookies.</p>
                <button class="accept">I Accept</button>
                <button class="decline">Decline</button>
            </div>
        </body>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)

        result = analyzer.analyze("example.com", config)

        assert result.success is True
        assert result.banner is not None
        assert result.banner.detected is True
        assert result.banner.has_accept_button is True
        assert result.banner.has_reject_button is True

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_compliance_score_calculation(self, mock_client, analyzer, config):
        """Test compliance score calculation."""
        # Full compliance scenario
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>
        </head>
        <body>
            <div id="cookie-consent">
                <button>Accept</button>
                <button>Reject</button>
                <button>Settings</button>
            </div>
            <footer>
                <a href="/cookie-policy">Cookie Policy</a>
            </footer>
        </body>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)
        mock_client.return_value.__enter__.return_value.head = Mock(
            return_value=Mock(status_code=200)
        )

        result = analyzer.analyze("example.com", config)

        assert result.success is True
        assert result.compliance is not None
        # Should have high score: 30 (consent) + 25 (CMP) + 20 (policy) + 15 (reject) + 10 (customize)
        assert result.compliance.compliance_score >= 70
        assert result.likely_gdpr_compliant is True

    def test_describe_output(self, analyzer):
        """Test output descriptor generation."""
        result = CookiesConsentResult(
            domain="example.com",
            url="https://example.com",
            success=True,
            cmp_detected=CMPInfo(
                cmp_id="onetrust",
                name="OneTrust",
                gdpr_compliant=True,
                detection_method="script",
                confidence="high",
            ),
            banner=BannerInfo(
                detected=True,
                has_accept_button=True,
                has_reject_button=True,
                has_customize_button=True,
                detection_method="dom",
            ),
            cookie_policy=CookiePolicyInfo(
                found=True,
                url="https://example.com/cookie-policy",
                link_text="Cookie Policy",
                accessible=True,
            ),
            compliance=ComplianceIndicators(
                has_consent_mechanism=True,
                has_cookie_policy=True,
                uses_known_cmp=True,
                provides_reject_option=True,
                provides_customize_option=True,
                compliance_score=100,
            ),
            has_consent_solution=True,
            likely_gdpr_compliant=True,
        )

        descriptor = analyzer.describe_output(result)

        assert descriptor.title == "Cookies & Consent"
        assert descriptor.category == "compliance"
        assert len(descriptor.rows) > 0

    def test_to_dict(self, analyzer):
        """Test result serialization."""
        result = CookiesConsentResult(
            domain="example.com",
            url="https://example.com",
            success=True,
            has_consent_solution=True,
            likely_gdpr_compliant=True,
            compliance=ComplianceIndicators(
                has_consent_mechanism=True,
                compliance_score=85,
            ),
        )

        data = analyzer.to_dict(result)

        assert data["domain"] == "example.com"
        assert data["success"] is True
        assert data["has_consent_solution"] is True
        assert data["likely_gdpr_compliant"] is True
        assert data["compliance"]["compliance_score"] == 85

    def test_analyze_with_http_context(self, analyzer, config):
        """Test that HTTP context is used for URL resolution."""
        context = {
            "http": Mock(
                preferred_final_url="https://www.example.com"
            )
        }

        with patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client") as mock_client:
            mock_response = Mock()
            mock_response.text = "<html><body>Test</body></html>"
            mock_response.headers = {}
            mock_response.raise_for_status = Mock()

            mock_client.return_value.__enter__ = Mock(return_value=Mock())
            mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)

            result = analyzer.analyze("example.com", config, context)

            assert result.url == "https://www.example.com"

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_recommendations_generated(self, mock_client, analyzer, config):
        """Test that recommendations are generated for missing features."""
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <div id="cookie-banner">
                <button>Accept</button>
            </div>
        </body>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)

        result = analyzer.analyze("example.com", config)

        assert result.success is True
        # Should have recommendations for missing features
        assert result.compliance is not None
        # Should recommend reject option and cookie policy
        assert len(result.compliance.recommendations) > 0


class TestCMPDetection:
    """Tests specifically for CMP detection logic."""

    @pytest.fixture
    def analyzer(self):
        return CookiesConsentAnalyzer()

    def test_all_known_cmps_have_required_fields(self):
        """Test that all known CMPs have required fields."""
        for cmp_id, cmp_info in KNOWN_CMPS.items():
            assert "name" in cmp_info, f"CMP {cmp_id} missing 'name'"
            assert "patterns" in cmp_info, f"CMP {cmp_id} missing 'patterns'"
            assert "gdpr_compliant" in cmp_info, f"CMP {cmp_id} missing 'gdpr_compliant'"
            assert len(cmp_info["patterns"]) > 0, f"CMP {cmp_id} has no patterns"

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_detect_quantcast(self, mock_client, analyzer):
        """Test Quantcast CMP detection."""
        html = """
        <html>
        <script src="https://cmp.quantcast.com/v2/"></script>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)

        result = analyzer.analyze("example.com", CookiesConsentConfig())
        assert result.cmp_detected.name == "Quantcast Choice"

    @patch("webmaster_domain_tool.analyzers.cookies_consent.httpx.Client")
    def test_detect_didomi(self, mock_client, analyzer):
        """Test Didomi CMP detection."""
        html = """
        <html>
        <script>
            window.didomiConfig = { ... };
        </script>
        </html>
        """
        mock_response = Mock()
        mock_response.text = html
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()

        mock_client.return_value.__enter__ = Mock(return_value=Mock())
        mock_client.return_value.__enter__.return_value.get = Mock(return_value=mock_response)

        result = analyzer.analyze("example.com", CookiesConsentConfig())
        assert result.cmp_detected.name == "Didomi"
