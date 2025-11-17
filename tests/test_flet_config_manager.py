"""Tests for Flet client storage config profile manager."""

from unittest.mock import MagicMock

import pytest

from webmaster_domain_tool.config import Config
from webmaster_domain_tool.flet_config_manager import FletConfigProfileManager


@pytest.fixture
def mock_page():
    """Create a mock Flet page with client_storage."""
    page = MagicMock()
    page.client_storage = MagicMock()

    # Storage dictionary to simulate client storage
    storage = {}

    def set_value(key: str, value: str) -> None:
        storage[key] = value

    def get_value(key: str) -> str | None:
        return storage.get(key)

    def contains(key: str) -> bool:
        return key in storage

    def remove_key(key: str) -> None:
        if key in storage:
            del storage[key]

    page.client_storage.set = MagicMock(side_effect=set_value)
    page.client_storage.get = MagicMock(side_effect=get_value)
    page.client_storage.contains_key = MagicMock(side_effect=contains)
    page.client_storage.remove = MagicMock(side_effect=remove_key)

    return page


@pytest.fixture
def profile_manager(mock_page):
    """Create profile manager with mock page."""
    return FletConfigProfileManager(mock_page)


def test_init(mock_page):
    """Test manager initialization."""
    manager = FletConfigProfileManager(mock_page)
    assert manager.page == mock_page


def test_save_and_load_profile(profile_manager):
    """Test saving and loading a profile."""
    config = Config()
    config.dns.timeout = 10.0
    config.http.timeout = 20.0

    # Save profile
    profile_manager.save_profile("test", config)

    # Load profile
    loaded_config = profile_manager.load_profile("test")

    assert loaded_config.dns.timeout == 10.0
    assert loaded_config.http.timeout == 20.0


def test_list_profiles(profile_manager):
    """Test listing profiles."""
    # Initially empty
    assert profile_manager.list_profiles() == []

    # Save profiles
    config1 = Config()
    config2 = Config()
    profile_manager.save_profile("profile1", config1)
    profile_manager.save_profile("profile2", config2)

    # List should be sorted
    profiles = profile_manager.list_profiles()
    assert profiles == ["profile1", "profile2"]


def test_delete_profile(profile_manager):
    """Test deleting a profile."""
    config = Config()
    profile_manager.save_profile("to_delete", config)

    assert profile_manager.profile_exists("to_delete")

    profile_manager.delete_profile("to_delete")

    assert not profile_manager.profile_exists("to_delete")
    assert "to_delete" not in profile_manager.list_profiles()


def test_profile_exists(profile_manager):
    """Test checking if profile exists."""
    assert not profile_manager.profile_exists("nonexistent")

    config = Config()
    profile_manager.save_profile("exists", config)

    assert profile_manager.profile_exists("exists")


def test_get_or_create_default(profile_manager):
    """Test getting or creating default profile."""
    # Should create default if doesn't exist
    config = profile_manager.get_or_create_default()
    assert config is not None
    assert profile_manager.profile_exists("default")

    # Should load existing default
    config2 = profile_manager.get_or_create_default()
    assert config2 is not None


def test_invalid_profile_name(profile_manager):
    """Test that invalid profile names are rejected."""
    config = Config()

    with pytest.raises(ValueError):
        profile_manager.save_profile("invalid/name", config)

    with pytest.raises(ValueError):
        profile_manager.save_profile("invalid\\name", config)

    with pytest.raises(ValueError):
        profile_manager.save_profile("invalid.name", config)


def test_load_nonexistent_profile(profile_manager):
    """Test loading a profile that doesn't exist."""
    with pytest.raises(FileNotFoundError):
        profile_manager.load_profile("nonexistent")


def test_delete_nonexistent_profile(profile_manager):
    """Test deleting a profile that doesn't exist."""
    with pytest.raises(FileNotFoundError):
        profile_manager.delete_profile("nonexistent")


def test_profile_data_integrity(profile_manager):
    """Test that profile data is correctly serialized and deserialized."""
    # Create config with various settings
    config = Config()
    config.dns.nameservers = ["1.1.1.1", "8.8.8.8"]
    config.dns.timeout = 7.5
    config.dns.check_dnssec = False
    config.http.max_redirects = 20
    config.ssl.cert_expiry_warning_days = 30
    config.email.dkim_selectors = ["custom1", "custom2"]
    config.seo.check_robots = False

    # Save and load
    profile_manager.save_profile("complex", config)
    loaded_config = profile_manager.load_profile("complex")

    # Verify all fields
    assert loaded_config.dns.nameservers == ["1.1.1.1", "8.8.8.8"]
    assert loaded_config.dns.timeout == 7.5
    assert loaded_config.dns.check_dnssec is False
    assert loaded_config.http.max_redirects == 20
    assert loaded_config.ssl.cert_expiry_warning_days == 30
    assert loaded_config.email.dkim_selectors == ["custom1", "custom2"]
    assert loaded_config.seo.check_robots is False


def test_profile_list_persistence(profile_manager):
    """Test that profile list is maintained correctly."""
    # Save multiple profiles
    for i in range(5):
        config = Config()
        profile_manager.save_profile(f"profile{i}", config)

    # List should contain all profiles
    profiles = profile_manager.list_profiles()
    assert len(profiles) == 5
    assert all(f"profile{i}" in profiles for i in range(5))

    # Delete one profile
    profile_manager.delete_profile("profile2")

    # List should be updated
    profiles = profile_manager.list_profiles()
    assert len(profiles) == 4
    assert "profile2" not in profiles


def test_key_namespacing(profile_manager, mock_page):
    """Test that keys are properly namespaced."""
    config = Config()
    profile_manager.save_profile("test", config)

    # Check that storage keys use correct prefix
    set_calls = mock_page.client_storage.set.call_args_list
    assert any("wdt.profile.test" in str(call) for call in set_calls)
    assert any("wdt.profiles.list" in str(call) for call in set_calls)
