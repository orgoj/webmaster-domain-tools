"""Test HTTP config validation."""

from webmaster_domain_tool.analyzers.http_analyzer import HTTPConfig
from webmaster_domain_tool.constants import DEFAULT_USER_AGENT


def test_user_agent_none_uses_default():
    """Test that None user_agent is replaced with default."""
    config = HTTPConfig(user_agent=None)
    assert config.user_agent == DEFAULT_USER_AGENT


def test_user_agent_empty_string_uses_default():
    """Test that empty user_agent string is replaced with default."""
    config = HTTPConfig(user_agent="")
    assert config.user_agent == DEFAULT_USER_AGENT


def test_user_agent_whitespace_uses_default():
    """Test that whitespace-only user_agent is replaced with default."""
    config = HTTPConfig(user_agent="   ")
    assert config.user_agent == DEFAULT_USER_AGENT


def test_user_agent_custom_value():
    """Test that custom user_agent is preserved."""
    custom_ua = "CustomBot/1.0"
    config = HTTPConfig(user_agent=custom_ua)
    assert config.user_agent == custom_ua


def test_user_agent_from_dict_with_none():
    """Test loading config from dict with None user_agent."""
    config_dict = {
        "enabled": True,
        "timeout": 5.0,
        "max_redirects": 10,
        "user_agent": None,
        "skip_www": False,
    }
    config = HTTPConfig(**config_dict)
    assert config.user_agent == DEFAULT_USER_AGENT
