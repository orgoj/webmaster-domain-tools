"""Tests for configuration management."""

import tempfile
from pathlib import Path

import pytest

from webmaster_domain_tool.config import (
    Config,
    DNSConfig,
    HTTPConfig,
    EmailConfig,
    OutputConfig,
    AnalysisConfig,
    _merge_configs,
    load_config,
)


def test_dns_config_defaults():
    """Test DNS config has correct defaults."""
    config = DNSConfig()
    assert len(config.nameservers) > 0
    assert config.timeout == 5.0
    assert config.check_dnssec is True


def test_http_config_defaults():
    """Test HTTP config has correct defaults."""
    config = HTTPConfig()
    assert config.timeout == 10.0
    assert config.max_redirects == 10
    assert config.user_agent is None


def test_email_config_defaults():
    """Test Email config has correct defaults."""
    config = EmailConfig()
    assert len(config.dkim_selectors) > 0
    assert config.check_rbl is True
    assert len(config.rbl_servers) > 0


def test_output_config_defaults():
    """Test Output config has correct defaults."""
    config = OutputConfig()
    assert config.color is True
    assert config.verbosity == "normal"


def test_analysis_config_defaults():
    """Test Analysis config has correct defaults."""
    config = AnalysisConfig()
    assert config.skip_dns is False
    assert config.skip_http is False
    assert config.skip_ssl is False
    assert config.skip_email is False
    assert config.skip_headers is False


def test_main_config_defaults():
    """Test main Config has all sub-configs."""
    config = Config()
    assert isinstance(config.dns, DNSConfig)
    assert isinstance(config.http, HTTPConfig)
    assert isinstance(config.email, EmailConfig)
    assert isinstance(config.output, OutputConfig)
    assert isinstance(config.analysis, AnalysisConfig)


def test_merge_configs_simple():
    """Test merging two simple configs."""
    base = {"a": 1, "b": 2}
    override = {"b": 3, "c": 4}
    result = _merge_configs(base, override)
    assert result == {"a": 1, "b": 3, "c": 4}


def test_merge_configs_nested():
    """Test merging nested configs."""
    base = {"dns": {"timeout": 5.0, "nameservers": ["8.8.8.8"]}}
    override = {"dns": {"timeout": 10.0}}
    result = _merge_configs(base, override)
    assert result["dns"]["timeout"] == 10.0
    assert result["dns"]["nameservers"] == ["8.8.8.8"]


def test_merge_configs_deep_override():
    """Test deep override doesn't affect base."""
    base = {"dns": {"nameservers": ["8.8.8.8"]}}
    override = {"dns": {"timeout": 10.0}}
    result = _merge_configs(base, override)
    # Base should not be modified
    assert "timeout" not in base["dns"]
    # Result should have both
    assert result["dns"]["timeout"] == 10.0
    assert result["dns"]["nameservers"] == ["8.8.8.8"]


def test_load_config_default():
    """Test loading default config."""
    config = load_config()
    assert isinstance(config, Config)
    assert isinstance(config.dns, DNSConfig)
