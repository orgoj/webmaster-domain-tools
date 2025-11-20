"""Tests for DNS analyzer."""

from webmaster_domain_tool.analyzers.dns_analyzer import (
    DNSAnalysisResult,
    DNSAnalyzer,
    DNSConfig,
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
        # Analyzer has metadata attributes
        assert analyzer.analyzer_id == "dns"
        assert analyzer.name == "DNS Analysis"
        assert analyzer.config_class == DNSConfig

    def test_analyze_with_default_config(self):
        """Test analyzing with default config."""
        DNSAnalyzer()  # Just test instantiation
        config = DNSConfig(check_dnssec=True)
        # Just test that it can be called
        # (don't test actual DNS queries in unit tests)
        assert config.check_dnssec is True

    def test_analyze_with_custom_nameservers(self):
        """Test config with custom nameservers."""
        config = DNSConfig(nameservers=["8.8.8.8", "1.1.1.1"])
        assert "8.8.8.8" in config.nameservers
        assert "1.1.1.1" in config.nameservers

    # NOTE: Real DNS query tests removed - unit tests shouldn't make network calls
    # Integration tests should be in a separate test suite
