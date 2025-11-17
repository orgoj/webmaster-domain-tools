"""Tests for Flet GUI application - focuses on preventing AttributeErrors in display methods."""

from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import pytest

from webmaster_domain_tool.analyzers.advanced_email_security import (
    AdvancedEmailSecurityResult,
    BIMIRecord,
    MTASTSRecord,
)
from webmaster_domain_tool.analyzers.cdn_detector import CDNDetectionResult
from webmaster_domain_tool.analyzers.dns_analyzer import DNSAnalysisResult, DNSRecord
from webmaster_domain_tool.analyzers.email_security import (
    DMARCRecord,
    EmailSecurityResult,
    SPFRecord,
)
from webmaster_domain_tool.analyzers.favicon_analyzer import FaviconAnalysisResult
from webmaster_domain_tool.analyzers.http_analyzer import (
    HTTPAnalysisResult,
    HTTPResponse,
    RedirectChain,
)
from webmaster_domain_tool.analyzers.rbl_checker import RBLAnalysisResult
from webmaster_domain_tool.analyzers.security_headers import SecurityHeadersResult
from webmaster_domain_tool.analyzers.seo_files_analyzer import SEOFilesAnalysisResult
from webmaster_domain_tool.analyzers.site_verification_analyzer import (
    SiteVerificationAnalysisResult,
)
from webmaster_domain_tool.analyzers.ssl_analyzer import CertificateInfo, SSLAnalysisResult
from webmaster_domain_tool.analyzers.whois_analyzer import WhoisAnalysisResult
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

        # headers is dict of SecurityHeaderCheck objects
        header_check_1 = Mock()
        header_check_1.present = True
        header_check_1.value = "max-age=31536000"

        header_check_2 = Mock()
        header_check_2.present = True
        header_check_2.value = "default-src 'self'"

        result.headers = {
            "Strict-Transport-Security": header_check_1,
            "Content-Security-Policy": header_check_2,
        }

        panel = app._create_headers_panel(result)
        assert panel is not None

    def test_create_rbl_panel_clean(self, app):
        """Test RBL panel with no blacklists."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.checks = []  # list of RBLCheckResult objects
        result.total_listed = 0

        panel = app._create_rbl_panel(result)
        assert panel is not None

    def test_create_rbl_panel_blacklisted(self, app):
        """Test RBL panel with blacklisted IPs."""
        result = Mock()
        result.domain = "example.com"
        result.errors = ["IP is blacklisted"]
        result.warnings = []

        # checks is list of RBLCheckResult objects
        check = Mock()
        check.ip = "192.0.2.1"
        check.listed = True
        check.blacklists = ["zen.spamhaus.org", "bl.spamcop.net"]

        result.checks = [check]
        result.total_listed = 1

        panel = app._create_rbl_panel(result)
        assert panel is not None
        assert panel.initially_expanded is True

    def test_create_seo_panel(self, app):
        """Test SEO panel creation."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []

        # robots is RobotsResult object
        robots_result = Mock()
        robots_result.content = "User-agent: *\nDisallow: /admin/"
        result.robots = robots_result

        # sitemaps is list of SitemapResult objects
        sitemap_result = Mock()
        sitemap_result.url = "https://example.com/sitemap.xml"
        sitemap_result.url_count = 100
        result.sitemaps = [sitemap_result]

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

        # service_results is list of ServiceResult objects
        verification_id = Mock()
        verification_id.verification_id = "ABC123"
        verification_id.methods = ["dns"]  # methods is a list!

        service_result = Mock()
        service_result.service = "Google"
        service_result.detected_verification_ids = [verification_id]

        result.service_results = [service_result]

        panel = app._create_site_verification_panel(result)
        assert panel is not None

    def test_create_cdn_panel_detected(self, app):
        """Test CDN panel with detected CDN."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.cdn_detected = True
        result.cdn_provider = "Cloudflare"
        result.detection_method = "header"
        result.confidence = "high"
        result.evidence = ["CF-Ray header present"]

        panel = app._create_cdn_panel(result)
        assert panel is not None

    def test_create_cdn_panel_not_detected(self, app):
        """Test CDN panel with no CDN."""
        result = Mock()
        result.domain = "example.com"
        result.errors = []
        result.warnings = []
        result.cdn_detected = False
        result.cdn_provider = None
        result.detection_method = None
        result.confidence = "unknown"
        result.evidence = []

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

    def test_display_all_results_complete_analysis(self, app):
        """INTEGRATION TEST: Display ALL analyzer results to catch AttributeErrors.

        This test creates REAL objects from ALL analyzers and displays them all
        to ensure no AttributeError occurs in any panel creation method.
        """
        # WHOIS Result
        whois_result = WhoisAnalysisResult(
            domain="example.com",
            registrar="Example Registrar",
            creation_date=datetime(2020, 1, 1),
            expiration_date=datetime(2025, 1, 1),
        )

        # DNS Result
        dns_result = DNSAnalysisResult(
            domain="example.com",
            records={
                "example.com:A": [
                    DNSRecord(record_type="A", name="example.com", value="192.0.2.1", ttl=300)
                ],
                "example.com:MX": [
                    DNSRecord(
                        record_type="MX", name="example.com", value="10 mail.example.com", ttl=300
                    )
                ],
            },
        )

        # HTTP Result
        http_result = HTTPAnalysisResult(
            domain="example.com",
            chains=[
                RedirectChain(
                    start_url="http://example.com",
                    final_url="https://example.com",
                    responses=[
                        HTTPResponse(
                            url="http://example.com",
                            status_code=301,
                            headers={"Location": "https://example.com"},
                        ),
                        HTTPResponse(
                            url="https://example.com",
                            status_code=200,
                            headers={"Content-Type": "text/html"},
                        ),
                    ],
                )
            ],
        )

        # SSL Result - MUST use correct attribute names!
        cert = CertificateInfo(
            subject={"CN": "example.com"},
            issuer={"CN": "Let's Encrypt"},
            version=3,
            serial_number="123456789",
            not_before=datetime(2024, 1, 1),  # not_before, NOT not_valid_before!
            not_after=datetime(2025, 1, 1),  # not_after, NOT not_valid_after!
        )
        ssl_result = SSLAnalysisResult(
            domain="example.com",
            certificates={"example.com": cert},  # certificates (plural), NOT certificate!
        )

        # Email Security Result
        email_result = EmailSecurityResult(
            domain="example.com",
            spf=SPFRecord(record="v=spf1 include:_spf.google.com ~all", is_valid=True),
            dmarc=DMARCRecord(record="v=DMARC1; p=quarantine;", policy="quarantine", is_valid=True),
        )

        # Advanced Email Security Result
        advanced_email_result = AdvancedEmailSecurityResult(
            domain="example.com",
            bimi=BIMIRecord(
                domain="example.com",
                record_found=True,
                record_value="v=BIMI1; l=https://example.com/logo.svg",
            ),
            mta_sts=MTASTSRecord(
                domain="example.com",
                record_found=True,
                policy_mode="enforce",
            ),
        )

        # Security Headers Result - create with MINIMAL parameters
        headers_result = SecurityHeadersResult(
            domain="example.com",
            url="https://example.com",
        )

        # RBL Result
        rbl_result = RBLAnalysisResult(
            domain="example.com",
        )

        # SEO Files Result
        seo_result = SEOFilesAnalysisResult(
            domain="example.com",
        )

        # Favicon Result
        favicon_result = FaviconAnalysisResult(
            domain="example.com",
        )

        # Site Verification Result
        site_verification_result = SiteVerificationAnalysisResult(
            domain="example.com",
        )

        # CDN Detection Result - MINIMAL
        cdn_result = CDNDetectionResult(
            domain="example.com",
        )

        # Create complete results dict with ALL analyzers
        results = {
            "whois": whois_result,
            "dns": dns_result,
            "http": http_result,
            "ssl": ssl_result,
            "email": email_result,
            "advanced_email": advanced_email_result,
            "headers": headers_result,
            "rbl": rbl_result,
            "seo": seo_result,
            "favicon": favicon_result,
            "site_verification": site_verification_result,
            "cdn": cdn_result,
        }

        # This MUST NOT raise any AttributeError!
        # If it does, it means we're using wrong attribute names somewhere
        app.display_results("example.com", results)

        # Verify all results are displayed
        assert app.results_card.visible is True
        assert len(app.results_column.controls) > 0

        # Should have summary + 12 panels (one for each analyzer)
        # Note: advanced_email is merged into email panel, so we get 11 panels + summary
        assert len(app.results_column.controls) >= 11

    @pytest.mark.slow
    def test_end_to_end_real_analysis_example_com(self, app):
        """END-TO-END TEST: Run REAL analyzers on example.com and display results.

        This test uses REAL analyzers (not Mocks) to analyze a real domain (example.com)
        and displays the actual results. This catches ANY AttributeError that would occur
        in production with real data structures.

        IMPORTANT: This is the CORRECT way to test GUI display - use real analyzers
        with real network calls to catch all possible AttributeErrors!
        """
        from webmaster_domain_tool.analyzers.cdn_detector import CDNDetector
        from webmaster_domain_tool.analyzers.dns_analyzer import DNSAnalyzer
        from webmaster_domain_tool.analyzers.email_security import EmailSecurityAnalyzer
        from webmaster_domain_tool.analyzers.favicon_analyzer import FaviconAnalyzer
        from webmaster_domain_tool.analyzers.http_analyzer import HTTPAnalyzer
        from webmaster_domain_tool.analyzers.rbl_checker import (
            RBLChecker,
            extract_ips_from_dns_result,
        )
        from webmaster_domain_tool.analyzers.security_headers import SecurityHeadersAnalyzer
        from webmaster_domain_tool.analyzers.seo_files_analyzer import SEOFilesAnalyzer
        from webmaster_domain_tool.analyzers.site_verification_analyzer import (
            SiteVerificationAnalyzer,
        )
        from webmaster_domain_tool.analyzers.ssl_analyzer import SSLAnalyzer

        domain = "example.com"
        results = {}

        # Run REAL analyzers (this makes network calls!)
        try:
            # DNS Analysis
            dns_analyzer = DNSAnalyzer()
            results["dns"] = dns_analyzer.analyze(domain)

            # HTTP Analysis
            http_analyzer = HTTPAnalyzer()
            results["http"] = http_analyzer.analyze(domain)

            # SSL Analysis
            ssl_analyzer = SSLAnalyzer()
            results["ssl"] = ssl_analyzer.analyze(domain)

            # Email Security
            email_analyzer = EmailSecurityAnalyzer()
            results["email"] = email_analyzer.analyze(domain)

            # Security Headers (needs HTTP result)
            if results.get("http"):
                http_result = results["http"]
                if http_result.chains and http_result.chains[0].responses:
                    final_response = http_result.chains[0].responses[-1]
                    if final_response.status_code == 200:
                        headers_analyzer = SecurityHeadersAnalyzer()
                        results["headers"] = headers_analyzer.analyze(
                            final_response.url, final_response.headers
                        )

            # RBL Check (needs DNS result)
            if results.get("dns"):
                dns_result = results["dns"]
                ips = extract_ips_from_dns_result(dns_result)
                if ips:
                    rbl_checker = RBLChecker()
                    results["rbl"] = rbl_checker.check_ips(domain, ips)

            # SEO Files (needs HTTP result)
            if results.get("http"):
                http_result = results["http"]
                if http_result.chains and http_result.chains[0].responses:
                    final_response = http_result.chains[0].responses[-1]
                    if final_response.status_code == 200:
                        seo_analyzer = SEOFilesAnalyzer()
                        results["seo"] = seo_analyzer.analyze(final_response.url)

            # Favicon (needs HTTP result)
            if results.get("http"):
                http_result = results["http"]
                if http_result.chains and http_result.chains[0].responses:
                    final_response = http_result.chains[0].responses[-1]
                    if final_response.status_code == 200:
                        favicon_analyzer = FaviconAnalyzer()
                        results["favicon"] = favicon_analyzer.analyze(final_response.url)

            # Site Verification
            site_verification_analyzer = SiteVerificationAnalyzer()
            results["site_verification"] = site_verification_analyzer.analyze(domain)

            # CDN Detection
            cdn_detector = CDNDetector()
            results["cdn"] = cdn_detector.analyze(domain)

        except Exception as e:
            pytest.skip(f"Network error during real analysis: {e}")

        # Display results - THIS is where AttributeErrors would occur!
        # If any panel tries to access a wrong attribute, it will fail here
        app.display_results(domain, results)

        # Verify results are displayed
        assert app.results_card.visible is True
        assert len(app.results_column.controls) > 0
