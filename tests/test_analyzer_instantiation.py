"""Test that all analyzers can be properly instantiated and have correct interfaces."""


class TestAnalyzerInstantiation:
    """Test instantiation of all analyzers."""

    def test_dns_analyzer(self):
        """Test DNSAnalyzer instantiation and interface."""
        from webmaster_domain_tool.analyzers.dns_analyzer import DNSAnalyzer

        analyzer = DNSAnalyzer()
        assert hasattr(analyzer, "analyze"), "DNSAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

    def test_http_analyzer(self):
        """Test HTTPAnalyzer instantiation and interface."""
        from webmaster_domain_tool.analyzers.http_analyzer import HTTPAnalyzer

        analyzer = HTTPAnalyzer()
        assert hasattr(analyzer, "analyze"), "HTTPAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

    def test_ssl_analyzer(self):
        """Test SSLAnalyzer instantiation and interface."""
        from webmaster_domain_tool.analyzers.ssl_analyzer import SSLAnalyzer

        analyzer = SSLAnalyzer()
        assert hasattr(analyzer, "analyze"), "SSLAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

    def test_email_security_analyzer(self):
        """Test EmailSecurityAnalyzer instantiation and interface (includes BIMI, MTA-STS, TLS-RPT)."""
        from webmaster_domain_tool.analyzers.email_security import (
            EmailConfig,
            EmailSecurityAnalyzer,
        )

        # New modular protocol - class has metadata and methods, no __init__
        analyzer = EmailSecurityAnalyzer()
        assert hasattr(analyzer, "analyze"), "EmailSecurityAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"
        assert hasattr(
            analyzer, "describe_output"
        ), "EmailSecurityAnalyzer must have describe_output() method"
        assert hasattr(analyzer, "to_dict"), "EmailSecurityAnalyzer must have to_dict() method"

        # Check metadata
        assert hasattr(EmailSecurityAnalyzer, "analyzer_id")
        assert EmailSecurityAnalyzer.analyzer_id == "email"
        assert hasattr(EmailSecurityAnalyzer, "name")
        assert hasattr(EmailSecurityAnalyzer, "config_class")
        assert EmailSecurityAnalyzer.config_class == EmailConfig

    def test_rbl_checker(self):
        """Test RBLChecker instantiation and interface."""
        from webmaster_domain_tool.analyzers.rbl_checker import RBLChecker

        analyzer = RBLChecker()
        assert hasattr(analyzer, "analyze"), "RBLChecker must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

    def test_favicon_analyzer(self):
        """Test FaviconAnalyzer instantiation and interface."""
        from webmaster_domain_tool.analyzers.favicon_analyzer import FaviconAnalyzer

        analyzer = FaviconAnalyzer()
        assert hasattr(analyzer, "analyze"), "FaviconAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

    def test_seo_files_analyzer(self):
        """Test SEOFilesAnalyzer instantiation and interface."""
        from webmaster_domain_tool.analyzers.seo_files_analyzer import SEOFilesAnalyzer

        analyzer = SEOFilesAnalyzer()
        assert hasattr(analyzer, "analyze"), "SEOFilesAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

    def test_site_verification_analyzer(self):
        """Test SiteVerificationAnalyzer instantiation and interface."""
        from webmaster_domain_tool.analyzers.site_verification_analyzer import (
            SiteVerificationAnalyzer,
        )

        analyzer = SiteVerificationAnalyzer()
        assert hasattr(analyzer, "analyze"), "SiteVerificationAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

    def test_whois_analyzer(self):
        """Test WhoisAnalyzer instantiation and interface."""
        from webmaster_domain_tool.analyzers.whois_analyzer import WhoisAnalyzer

        analyzer = WhoisAnalyzer()
        assert hasattr(analyzer, "analyze"), "WhoisAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

    def test_security_headers_analyzer(self):
        """Test SecurityHeadersAnalyzer instantiation and interface."""
        from webmaster_domain_tool.analyzers.security_headers import SecurityHeadersAnalyzer

        analyzer = SecurityHeadersAnalyzer()
        assert hasattr(analyzer, "analyze"), "SecurityHeadersAnalyzer must have analyze() method"
        assert callable(analyzer.analyze), "analyze() must be callable"

        # Test that analyze() works with URL parameter
        result = analyzer.analyze("https://example.com", {"Server": "nginx"})
        assert result.domain == "example.com", "domain should be extracted from URL"
        assert result.url == "https://example.com", "url should be preserved"

    def test_cdn_detector(self):
        """Test CDNDetector instantiation."""
        from webmaster_domain_tool.analyzers.cdn_detector import CDNDetector

        # CDNDetector has different API (not BaseAnalyzer)
        analyzer = CDNDetector()
        assert hasattr(
            analyzer, "detect_from_headers"
        ), "CDNDetector must have detect_from_headers() method"
        assert hasattr(
            analyzer, "detect_from_cname"
        ), "CDNDetector must have detect_from_cname() method"
        assert hasattr(
            analyzer, "combine_results"
        ), "CDNDetector must have combine_results() method"
