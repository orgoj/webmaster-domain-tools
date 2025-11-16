"""Tests for DNS analyzer."""


from webmaster_domain_tool.analyzers.dns_analyzer import (
    DNSAnalysisResult,
    DNSAnalyzer,
    DNSRecord,
    DNSSECInfo,
)


class TestDNSRecord:
    """Test DNS record dataclass."""

    def test_create_dns_record(self):
        """Test creating a DNS record."""
        record = DNSRecord(
            record_type="A",
            name="example.com",
            value="93.184.216.34",
            ttl=3600,
        )
        assert record.record_type == "A"
        assert record.name == "example.com"
        assert record.value == "93.184.216.34"
        assert record.ttl == 3600


class TestDNSSECInfo:
    """Test DNSSEC info dataclass."""

    def test_dnssec_info_defaults(self):
        """Test DNSSEC info defaults."""
        info = DNSSECInfo()
        assert info.enabled is False
        assert info.valid is False
        assert info.has_dnskey is False
        assert info.has_ds is False
        assert len(info.errors) == 0
        assert len(info.warnings) == 0


class TestDNSAnalysisResult:
    """Test DNS analysis result dataclass."""

    def test_dns_analysis_result_defaults(self):
        """Test DNS analysis result defaults."""
        result = DNSAnalysisResult(domain="example.com")
        assert result.domain == "example.com"
        assert len(result.records) == 0
        assert len(result.ptr_records) == 0
        assert result.dnssec is None
        assert len(result.errors) == 0
        assert len(result.warnings) == 0
        assert len(result.info_messages) == 0


class TestDNSAnalyzer:
    """Test DNS analyzer."""

    def test_create_analyzer(self):
        """Test creating DNS analyzer."""
        analyzer = DNSAnalyzer()
        assert analyzer.check_dnssec is True
        assert len(analyzer.resolver.nameservers) > 0

    def test_create_analyzer_custom_nameservers(self):
        """Test creating analyzer with custom nameservers."""
        analyzer = DNSAnalyzer(nameservers=["8.8.8.8", "1.1.1.1"])
        assert "8.8.8.8" in analyzer.resolver.nameservers
        assert "1.1.1.1" in analyzer.resolver.nameservers

    def test_create_analyzer_no_dnssec(self):
        """Test creating analyzer without DNSSEC check."""
        analyzer = DNSAnalyzer(check_dnssec=False)
        assert analyzer.check_dnssec is False

    def test_analyze_domain_basic(self):
        """Test analyzing a real domain (example.com)."""
        analyzer = DNSAnalyzer(check_dnssec=False)
        result = analyzer.analyze("example.com")

        assert result.domain == "example.com"
        assert len(result.records) > 0
        # example.com should have A records
        a_records = [k for k in result.records.keys() if ":A" in k]
        assert len(a_records) > 0

    def test_analyze_nonexistent_domain(self):
        """Test analyzing nonexistent domain."""
        analyzer = DNSAnalyzer(check_dnssec=False)
        result = analyzer.analyze("this-domain-definitely-does-not-exist-12345.com")

        assert len(result.errors) > 0
        assert any("NXDOMAIN" in err or "does not exist" in err for err in result.errors)

    def test_normalize_domain_trailing_dot(self):
        """Test domain normalization removes trailing dot."""
        analyzer = DNSAnalyzer(check_dnssec=False)
        result = analyzer.analyze("example.com.")
        assert result.domain == "example.com"
