"""Tests for Flet client storage config profile manager."""

from unittest.mock import MagicMock

import pytest

# Import analyzers to register them
from webmaster_domain_tool.analyzers import cdn_detector  # noqa: F401
from webmaster_domain_tool.flet_config_manager import FletConfigProfileManager
from webmaster_domain_tool.gui_config_adapter import GUIConfigAdapter


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
    config = GUIConfigAdapter()
    dns_config = config.get_analyzer_config("dns")
    dns_config.timeout = 10.0
    config.set_analyzer_config("dns", dns_config)

    http_config = config.get_analyzer_config("http")
    http_config.timeout = 20.0
    config.set_analyzer_config("http", http_config)

    # Save profile
    profile_manager.save_profile("test", config)

    # Load profile
    loaded_config = profile_manager.load_profile("test")

    assert loaded_config.get_analyzer_config("dns").timeout == 10.0
    assert loaded_config.get_analyzer_config("http").timeout == 20.0


def test_list_profiles(profile_manager):
    """Test listing profiles."""
    # Initially empty
    assert profile_manager.list_profiles() == []

    # Save profiles
    config1 = GUIConfigAdapter()
    config2 = GUIConfigAdapter()
    profile_manager.save_profile("profile1", config1)
    profile_manager.save_profile("profile2", config2)

    # List should be sorted
    profiles = profile_manager.list_profiles()
    assert profiles == ["profile1", "profile2"]


def test_delete_profile(profile_manager):
    """Test deleting a profile."""
    config = GUIConfigAdapter()
    profile_manager.save_profile("to_delete", config)

    assert profile_manager.profile_exists("to_delete")

    profile_manager.delete_profile("to_delete")

    assert not profile_manager.profile_exists("to_delete")
    assert "to_delete" not in profile_manager.list_profiles()


def test_profile_exists(profile_manager):
    """Test checking if profile exists."""
    assert not profile_manager.profile_exists("nonexistent")

    config = GUIConfigAdapter()
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
    config = GUIConfigAdapter()

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
    config = GUIConfigAdapter()

    # Update DNS config
    dns_config = config.get_analyzer_config("dns")
    dns_config.nameservers = ["1.1.1.1", "8.8.8.8"]
    dns_config.timeout = 7.5
    dns_config.check_dnssec = False
    config.set_analyzer_config("dns", dns_config)

    # Update HTTP config
    http_config = config.get_analyzer_config("http")
    http_config.max_redirects = 20
    config.set_analyzer_config("http", http_config)

    # Update SSL config
    ssl_config = config.get_analyzer_config("ssl")
    ssl_config.cert_expiry_warning_days = 30
    config.set_analyzer_config("ssl", ssl_config)

    # Update Email config
    email_config = config.get_analyzer_config("email")
    email_config.dkim_selectors = ["custom1", "custom2"]
    config.set_analyzer_config("email", email_config)

    # Update SEO config
    seo_config = config.get_analyzer_config("seo")
    seo_config.check_robots = False
    config.set_analyzer_config("seo", seo_config)

    # Save and load
    profile_manager.save_profile("complex", config)
    loaded_config = profile_manager.load_profile("complex")

    # Verify all fields
    assert loaded_config.get_analyzer_config("dns").nameservers == ["1.1.1.1", "8.8.8.8"]
    assert loaded_config.get_analyzer_config("dns").timeout == 7.5
    assert loaded_config.get_analyzer_config("dns").check_dnssec is False
    assert loaded_config.get_analyzer_config("http").max_redirects == 20
    assert loaded_config.get_analyzer_config("ssl").cert_expiry_warning_days == 30
    assert loaded_config.get_analyzer_config("email").dkim_selectors == ["custom1", "custom2"]
    assert loaded_config.get_analyzer_config("seo").check_robots is False


def test_profile_list_persistence(profile_manager):
    """Test that profile list is maintained correctly."""
    # Save multiple profiles
    for i in range(5):
        config = GUIConfigAdapter()
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
    config = GUIConfigAdapter()
    profile_manager.save_profile("test", config)

    # Check that storage keys use correct prefix
    set_calls = mock_page.client_storage.set.call_args_list
    assert any("wdt.profile.test" in str(call) for call in set_calls)
    assert any("wdt.profiles.list" in str(call) for call in set_calls)


def test_set_and_get_last_selected_profile(profile_manager):
    """Test saving and retrieving last selected profile."""
    # Create a profile first
    config = GUIConfigAdapter()
    profile_manager.save_profile("my_profile", config)

    # Set as last selected
    profile_manager.set_last_selected_profile("my_profile")

    # Retrieve it
    last = profile_manager.get_last_selected_profile()
    assert last == "my_profile"


def test_get_last_selected_profile_default(profile_manager):
    """Test that default is returned when no last profile saved."""
    # Ensure default profile exists
    profile_manager.get_or_create_default()

    # Should return "default" when nothing saved
    last = profile_manager.get_last_selected_profile()
    assert last == "default"


def test_get_last_selected_profile_nonexistent(profile_manager):
    """Test that default is returned when last profile doesn't exist."""
    # Set a profile that will be deleted
    config = GUIConfigAdapter()
    profile_manager.save_profile("temp", config)
    profile_manager.set_last_selected_profile("temp")

    # Delete the profile
    profile_manager.delete_profile("temp")

    # Ensure default exists
    profile_manager.get_or_create_default()

    # Should return "default" since "temp" no longer exists
    last = profile_manager.get_last_selected_profile()
    assert last == "default"
