"""Tests for CLI interface and validation."""

import pytest
import typer

from webmaster_domain_tool.cli import (
    validate_config_file,
    validate_domain,
    validate_max_redirects,
    validate_nameservers,
    validate_timeout,
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
