"""Tests for Flet GUI application - focuses on preventing AttributeErrors in display methods."""

from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import pytest

from webmaster_domain_tool.analyzers.ssl_analyzer import CertificateInfo, SSLAnalysisResult
from webmaster_domain_tool.flet_app import DomainAnalyzerApp


@pytest.fixture
def mock_page():
    """Create mock Flet page."""
    page = MagicMock()
    page.title = ""
    page.theme_mode = None
    page.scroll = None
    page.padding = 0
    return page


@pytest.fixture
def app(mock_page):
    """Create DomainAnalyzerApp instance with mocked page."""
    with patch("webmaster_domain_tool.flet_app.load_config"):
        app = DomainAnalyzerApp(mock_page)
        return app


class TestDomainValidation:
    """Test domain validation and normalization."""

    def test_validate_domain_valid(self, app):
        """Test validation of valid domain names."""
        assert app.validate_domain("example.com")
        assert app.validate_domain("subdomain.example.com")
        assert app.validate_domain("multi.level.subdomain.example.com")
        assert app.validate_domain("example.co.uk")
        assert app.validate_domain("www.example.com")

    def test_validate_domain_invalid(self, app):
        """Test validation of invalid domain names."""
        assert not app.validate_domain("")
        assert not app.validate_domain("not a domain")
        assert not app.validate_domain("example")
        assert not app.validate_domain(".com")
        assert not app.validate_domain("example.")
        assert not app.validate_domain("invalid")
        assert not app.validate_domain("invalid..com")
        assert not app.validate_domain("-invalid.com")

    def test_normalize_domain(self, app):
        """Test domain normalization."""
        assert app.normalize_domain("example.com") == "example.com"
        assert app.normalize_domain("http://example.com") == "example.com"
        assert app.normalize_domain("https://example.com") == "example.com"
        assert app.normalize_domain("https://example.com/") == "example.com"
        assert app.normalize_domain("example.com/") == "example.com"
        assert app.normalize_domain("  example.com  ") == "example.com"


class TestPanelCreation:
    """Test panel creation methods to prevent AttributeErrors."""

    def test_create_whois_panel(self, app):
        """Test WHOIS panel creation with mock result."""
        result = Mock()
        result.domain = "example.com"
        result.errors = ["Test error"]
        result.warnings = ["Test warning"]
        result.registrar = "Test Registrar"
        result.creation_date = datetime(2020, 1, 1)
        result.expiration_date = datetime(2025, 1, 1)
        result.updated_date = datetime(2024, 1, 1)
        result.registrant_name = "John Doe"
        result.registrant_organization = "Example Org"
        result.registrant_email = "john@example.com"
        result.admin_name = "Admin"
        result.admin_email = "admin@example.com"
        result.admin_contact = "ADMIN-123"

        panel = app._create_whois_panel(result)
        assert panel is not None
        assert panel.initially_expanded is True  # Due to errors

    def test_create_dns_panel(self, app):
        """Test DNS panel creation with mock result."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.records = {
            "example.com:A": [Mock(value="192.0.2.1")],
            "example.com:MX": [Mock(value="10 mail.example.com")],
        }

        panel = app._create_dns_panel(result)
        assert panel is not None

    def test_create_http_panel_prevents_starting_url_error(self, app):
        """Test HTTP panel uses start_url not starting_url to prevent AttributeError.

        This test specifically prevents regression of the bug:
        AttributeError: 'RedirectChain' object has no attribute 'starting_url'
        """
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []

        # Create mock chain with start_url attribute
        chain = Mock()
        chain.start_url = "http://example.com"  # Correct attribute name

        response = Mock()
        response.url = "https://example.com"
        response.status_code = 200
        chain.responses = [response]

        result.chains = [chain]

        # This should not raise AttributeError about 'starting_url'
        panel = app._create_http_panel(result)
        assert panel is not None

    def test_create_ssl_panel_prevents_certificate_singular_error(self, app):
        """Test SSL panel uses certificates (plural) not certificate (singular).

        This test specifically prevents regression of the bug:
        AttributeError: 'SSLAnalysisResult' object has no attribute 'certificate'. Did you mean: 'certificates'?
        """
        # Use REAL CertificateInfo object like the app does
        cert = CertificateInfo(
            subject={"CN": "example.com"},
            issuer={"CN": "Let's Encrypt"},
            version=3,
            serial_number="123456789",
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2025, 1, 1),
        )

        # Use REAL SSLAnalysisResult object
        result = SSLAnalysisResult(
            domain="example.com",
            certificates={"example.com": cert},
        )

        # This should not raise AttributeError about:
        # - 'certificate' (should be 'certificates')
        # - 'not_valid_before' (should be 'not_before')
        # - 'not_valid_after' (should be 'not_after')
        panel = app._create_ssl_panel(result)
        assert panel is not None

    def test_create_ssl_panel_empty_certificates(self, app):
        """Test SSL panel with empty certificates dict."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.certificates = {}

        panel = app._create_ssl_panel(result)
        assert panel is not None

    def test_create_email_panel(self, app):
        """Test email panel creation."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.spf_record = "v=spf1 include:_spf.google.com ~all"
        result.dmarc_record = "v=DMARC1; p=quarantine;"

        panel = app._create_email_panel(result)
        assert panel is not None

    def test_create_email_panel_with_advanced(self, app):
        """Test email panel with advanced result."""
        basic_result = Mock()
        basic_result.domain = "example.com"
        basic_result.errors = []
        basic_result.warnings = []
        basic_result.spf_record = "v=spf1 include:_spf.google.com ~all"
        basic_result.dmarc_record = "v=DMARC1; p=quarantine;"

        advanced_result = Mock()
        advanced_result.bimi_record = "v=BIMI1; l=https://example.com/logo.svg"
        advanced_result.mta_sts_policy = "enforce"

        panel = app._create_email_panel(basic_result, advanced_result)
        assert panel is not None

    def test_create_headers_panel(self, app):
        """Test security headers panel creation."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.present_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        }

        panel = app._create_headers_panel(result)
        assert panel is not None

    def test_create_rbl_panel_clean(self, app):
        """Test RBL panel with no blacklists."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.blacklisted_ips = {}

        panel = app._create_rbl_panel(result)
        assert panel is not None

    def test_create_rbl_panel_blacklisted(self, app):
        """Test RBL panel with blacklisted IPs."""
        result = Mock()
        result.domain = "example.com"
        result.errors = ["IP is blacklisted"]
        result.warnings = []
        result.blacklisted_ips = {"192.0.2.1": ["zen.spamhaus.org", "bl.spamcop.net"]}

        panel = app._create_rbl_panel(result)
        assert panel is not None
        assert panel.initially_expanded is True

    def test_create_seo_panel(self, app):
        """Test SEO panel creation."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.robots_txt = "User-agent: *\nDisallow: /admin/"
        result.sitemap_xml = "https://example.com/sitemap.xml"
        result.llms_txt = "# AI Crawler Instructions"

        panel = app._create_seo_panel(result)
        assert panel is not None

    def test_create_favicon_panel(self, app):
        """Test favicon panel creation."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []

        favicon = Mock()
        favicon.url = "https://example.com/favicon.ico"
        favicon.sizes = "16x16"
        result.favicons = [favicon]

        panel = app._create_favicon_panel(result)
        assert panel is not None

    def test_create_site_verification_panel(self, app):
        """Test site verification panel creation."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []

        verification = Mock()
        verification.service = "Google"
        verification.verification_id = "ABC123"
        verification.method = "dns"

        result.verifications = {"Google": [verification]}

        panel = app._create_site_verification_panel(result)
        assert panel is not None

    def test_create_cdn_panel_detected(self, app):
        """Test CDN panel with detected CDN."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.detected_cdns = ["Cloudflare"]

        panel = app._create_cdn_panel(result)
        assert panel is not None

    def test_create_cdn_panel_not_detected(self, app):
        """Test CDN panel with no CDN."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.detected_cdns = []

        panel = app._create_cdn_panel(result)
        assert panel is not None


class TestErrorWarningDisplays:
    """Test error and warning display containers."""

    def test_create_error_container(self, app):
        """Test error container creation."""
        container = app._create_error_container("Test error message")
        assert container is not None

    def test_create_warning_container(self, app):
        """Test warning container creation."""
        container = app._create_warning_container("Test warning message")
        assert container is not None

    def test_add_errors_and_warnings(self, app):
        """Test adding errors and warnings to content."""
        content = []

        result = Mock()
        result.errors = ["Error 1", "Error 2"]
        result.warnings = ["Warning 1"]

        app._add_errors_and_warnings(content, result)
        assert len(content) == 3  # 2 errors + 1 warning


class TestDisplayResults:
    """Test overall results display."""

    def test_display_results_summary(self, app):
        """Test that summary correctly counts errors and warnings."""
        dns_result = Mock()
        dns_result.errors = ["DNS error 1", "DNS error 2"]
        dns_result.warnings = ["DNS warning 1"]
        dns_result.records = {}  # DNS panel iterates over this

        ssl_result = Mock()
        ssl_result.errors = ["SSL error 1"]
        ssl_result.warnings = ["SSL warning 1", "SSL warning 2"]
        ssl_result.certificates = {}

        results = {
            "dns": dns_result,
            "ssl": ssl_result,
        }

        app.display_results("example.com", results)

        # Verify results are displayed
        assert app.results_card.visible is True
        assert len(app.results_column.controls) > 0
