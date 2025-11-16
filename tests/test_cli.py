"""Tests for CLI interface and validation."""

import pytest
import typer

from webmaster_domain_tool.cli import (
    validate_domain,
    validate_timeout,
    validate_max_redirects,
    validate_nameservers,
    validate_config_file,
    get_preferred_final_url,
)
from webmaster_domain_tool.analyzers.http_analyzer import (
    HTTPAnalysisResult,
    HTTPResponse,
    RedirectChain,
)


class TestDomainValidation:
    """Test domain validation."""

    def test_valid_domain(self):
        """Test valid domain names."""
        assert validate_domain("example.com") == "example.com"
        assert validate_domain("sub.example.com") == "sub.example.com"
        assert validate_domain("example.co.uk") == "example.co.uk"

    def test_domain_with_protocol(self):
        """Test domain with protocol is normalized."""
        assert validate_domain("http://example.com") == "example.com"
        assert validate_domain("https://example.com") == "example.com"
        assert validate_domain("https://example.com/") == "example.com"

    def test_invalid_domain(self):
        """Test invalid domain names."""
        with pytest.raises(typer.BadParameter):
            validate_domain("invalid")
        with pytest.raises(typer.BadParameter):
            validate_domain("invalid_domain")
        with pytest.raises(typer.BadParameter):
            validate_domain("192.168.1.1")  # IP addresses not allowed


class TestTimeoutValidation:
    """Test timeout validation."""

    def test_valid_timeout(self):
        """Test valid timeout values."""
        assert validate_timeout(1.0) == 1.0
        assert validate_timeout(10.0) == 10.0
        assert validate_timeout(300.0) == 300.0

    def test_invalid_timeout_negative(self):
        """Test negative timeout is rejected."""
        with pytest.raises(typer.BadParameter):
            validate_timeout(-1.0)
        with pytest.raises(typer.BadParameter):
            validate_timeout(0.0)

    def test_invalid_timeout_too_large(self):
        """Test too large timeout is rejected."""
        with pytest.raises(typer.BadParameter):
            validate_timeout(301.0)
        with pytest.raises(typer.BadParameter):
            validate_timeout(1000.0)


class TestMaxRedirectsValidation:
    """Test max redirects validation."""

    def test_valid_max_redirects(self):
        """Test valid max redirects values."""
        assert validate_max_redirects(0) == 0
        assert validate_max_redirects(10) == 10
        assert validate_max_redirects(50) == 50

    def test_invalid_max_redirects_negative(self):
        """Test negative max redirects is rejected."""
        with pytest.raises(typer.BadParameter):
            validate_max_redirects(-1)

    def test_invalid_max_redirects_too_large(self):
        """Test too large max redirects is rejected."""
        with pytest.raises(typer.BadParameter):
            validate_max_redirects(51)
        with pytest.raises(typer.BadParameter):
            validate_max_redirects(100)


class TestNameserversValidation:
    """Test nameservers validation."""

    def test_valid_nameservers(self):
        """Test valid nameserver IPs."""
        assert validate_nameservers("8.8.8.8") == "8.8.8.8"
        assert validate_nameservers("8.8.8.8,1.1.1.1") == "8.8.8.8,1.1.1.1"
        assert validate_nameservers("8.8.8.8, 1.1.1.1") == "8.8.8.8, 1.1.1.1"  # with spaces

    def test_none_nameservers(self):
        """Test None is accepted (use defaults)."""
        assert validate_nameservers(None) is None

    def test_invalid_nameservers(self):
        """Test invalid nameserver IPs are rejected."""
        with pytest.raises(typer.BadParameter):
            validate_nameservers("invalid")
        with pytest.raises(typer.BadParameter):
            validate_nameservers("256.256.256.256")
        with pytest.raises(typer.BadParameter):
            validate_nameservers("8.8.8.8,invalid")


class TestConfigFileValidation:
    """Test config file validation."""

    def test_none_config_file(self):
        """Test None is accepted (no custom config)."""
        assert validate_config_file(None) is None

    def test_nonexistent_config_file(self):
        """Test nonexistent file is rejected."""
        with pytest.raises(typer.BadParameter):
            validate_config_file("/nonexistent/path/config.toml")

    def test_directory_as_config_file(self):
        """Test directory path is rejected."""
        with pytest.raises(typer.BadParameter):
            validate_config_file("/tmp")


class TestGetPreferredFinalUrl:
    """Test get_preferred_final_url function."""

    def test_all_chains_same_url(self):
        """Test when all redirect chains lead to the same URL."""
        # Create HTTP result with multiple chains ending at same URL
        http_result = HTTPAnalysisResult(domain="example.com")

        # Chain 1: http://example.com -> https://www.example.com/
        http_result.chains.append(RedirectChain(
            start_url="http://example.com",
            final_url="https://www.example.com/",
            responses=[
                HTTPResponse(url="https://www.example.com/", status_code=200, headers={})
            ]
        ))

        # Chain 2: https://example.com -> https://www.example.com/
        http_result.chains.append(RedirectChain(
            start_url="https://example.com",
            final_url="https://www.example.com/",
            responses=[
                HTTPResponse(url="https://www.example.com/", status_code=200, headers={})
            ]
        ))

        final_url, final_response, warnings, errors = get_preferred_final_url(http_result)

        assert final_url == "https://www.example.com/"
        assert final_response is not None
        assert final_response.status_code == 200
        assert len(warnings) == 0  # No warnings when all chains match
        assert len(errors) == 0  # No errors when all chains match

    def test_different_final_urls_prefers_https_www(self):
        """Test when chains lead to different URLs, prefer HTTPS with www."""
        http_result = HTTPAnalysisResult(domain="example.com")

        # Chain 1: ends at http://example.com
        http_result.chains.append(RedirectChain(
            start_url="http://example.com",
            final_url="http://example.com/",
            responses=[
                HTTPResponse(url="http://example.com/", status_code=200, headers={})
            ]
        ))

        # Chain 2: ends at https://www.example.com (should be preferred)
        http_result.chains.append(RedirectChain(
            start_url="https://example.com",
            final_url="https://www.example.com/",
            responses=[
                HTTPResponse(url="https://www.example.com/", status_code=200, headers={})
            ]
        ))

        final_url, final_response, warnings, errors = get_preferred_final_url(http_result)

        assert final_url == "https://www.example.com/"
        assert len(errors) == 1  # Should ERROR about inconsistent chains
        assert "different final URLs" in errors[0]
        assert len(warnings) == 1  # Also added as warning
        assert "different final URLs" in warnings[0]

    def test_different_final_urls_prefers_https_no_www(self):
        """Test HTTPS without www is preferred over HTTP."""
        http_result = HTTPAnalysisResult(domain="example.com")

        # Chain 1: ends at http://example.com
        http_result.chains.append(RedirectChain(
            start_url="http://example.com",
            final_url="http://example.com/",
            responses=[
                HTTPResponse(url="http://example.com/", status_code=200, headers={})
            ]
        ))

        # Chain 2: ends at https://example.com (should be preferred)
        http_result.chains.append(RedirectChain(
            start_url="https://example.com",
            final_url="https://example.com/",
            responses=[
                HTTPResponse(url="https://example.com/", status_code=200, headers={})
            ]
        ))

        final_url, final_response, warnings, errors = get_preferred_final_url(http_result)

        assert final_url == "https://example.com/"
        assert len(errors) == 1  # Should ERROR about inconsistent chains
        assert len(warnings) == 1  # Also added as warning

    def test_url_normalization_trailing_slash(self):
        """Test URLs with/without trailing slash are treated as same."""
        http_result = HTTPAnalysisResult(domain="example.com")

        # Chain 1: with trailing slash
        http_result.chains.append(RedirectChain(
            start_url="http://example.com",
            final_url="https://www.example.com/",
            responses=[
                HTTPResponse(url="https://www.example.com/", status_code=200, headers={})
            ]
        ))

        # Chain 2: without trailing slash (should be treated as same)
        http_result.chains.append(RedirectChain(
            start_url="https://example.com",
            final_url="https://www.example.com",
            responses=[
                HTTPResponse(url="https://www.example.com", status_code=200, headers={})
            ]
        ))

        final_url, final_response, warnings, errors = get_preferred_final_url(http_result)

        # Should recognize both as same URL
        assert final_url in ["https://www.example.com/", "https://www.example.com"]
        assert len(warnings) == 0  # No warning since URLs are same after normalization
        assert len(errors) == 0  # No errors since URLs are same after normalization

    def test_no_successful_chains(self):
        """Test when no chains have successful (200) responses."""
        http_result = HTTPAnalysisResult(domain="example.com")

        # Chain with error response
        http_result.chains.append(RedirectChain(
            start_url="http://example.com",
            final_url="http://example.com/",
            responses=[
                HTTPResponse(url="http://example.com/", status_code=404, headers={})
            ]
        ))

        final_url, final_response, warnings, errors = get_preferred_final_url(http_result)

        assert final_url is None
        assert final_response is None
        assert len(warnings) == 0
        assert len(errors) == 0

    def test_empty_chains(self):
        """Test when HTTP result has no chains."""
        http_result = HTTPAnalysisResult(domain="example.com")

        final_url, final_response, warnings, errors = get_preferred_final_url(http_result)

        assert final_url is None
        assert final_response is None
        assert len(warnings) == 0
        assert len(errors) == 0
