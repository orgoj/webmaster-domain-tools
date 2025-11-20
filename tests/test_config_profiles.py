"""Tests for configuration profiles management."""

import json

import pytest

# Import analyzers to register them
from webmaster_domain_tool.analyzers import cdn_detector  # noqa: F401
from webmaster_domain_tool.config_profiles import ConfigProfileManager
from webmaster_domain_tool.gui_config_adapter import GUIConfigAdapter


@pytest.fixture
def temp_profiles_dir(tmp_path):
    """Create temporary profiles directory."""
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    return profiles_dir


@pytest.fixture
def profile_manager(temp_profiles_dir):
    """Create ConfigProfileManager with temporary directory."""
    return ConfigProfileManager(profiles_dir=temp_profiles_dir)


@pytest.fixture
def sample_config():
    """Create sample configuration adapter."""
    return GUIConfigAdapter()


def test_list_profiles_empty(profile_manager):
    """Test listing profiles when none exist."""
    profiles = profile_manager.list_profiles()
    assert profiles == []


def test_save_and_list_profile(profile_manager, sample_config):
    """Test saving profile and listing it."""
    profile_manager.save_profile("test-profile", sample_config)

    profiles = profile_manager.list_profiles()
    assert "test-profile" in profiles


def test_save_and_load_profile(profile_manager, sample_config):
    """Test saving and loading a profile."""
    # Modify config
    dns_config = sample_config.get_analyzer_config("dns")
    dns_config.nameservers = ["1.1.1.1", "8.8.8.8"]
    sample_config.set_analyzer_config("dns", dns_config)

    http_config = sample_config.get_analyzer_config("http")
    http_config.timeout = 15.0
    sample_config.set_analyzer_config("http", http_config)

    # Save
    profile_manager.save_profile("custom", sample_config)

    # Load
    loaded = profile_manager.load_profile("custom")

    assert loaded.get_analyzer_config("dns").nameservers == ["1.1.1.1", "8.8.8.8"]
    assert loaded.get_analyzer_config("http").timeout == 15.0


def test_load_nonexistent_profile(profile_manager):
    """Test loading profile that doesn't exist."""
    with pytest.raises(FileNotFoundError):
        profile_manager.load_profile("nonexistent")


def test_save_invalid_profile_name(profile_manager, sample_config):
    """Test saving profile with invalid name."""
    with pytest.raises(ValueError):
        profile_manager.save_profile("invalid/name", sample_config)

    with pytest.raises(ValueError):
        profile_manager.save_profile("invalid\\name", sample_config)

    with pytest.raises(ValueError):
        profile_manager.save_profile("", sample_config)


def test_delete_profile(profile_manager, sample_config):
    """Test deleting a profile."""
    profile_manager.save_profile("to-delete", sample_config)
    assert "to-delete" in profile_manager.list_profiles()

    profile_manager.delete_profile("to-delete")
    assert "to-delete" not in profile_manager.list_profiles()


def test_delete_nonexistent_profile(profile_manager):
    """Test deleting profile that doesn't exist."""
    with pytest.raises(FileNotFoundError):
        profile_manager.delete_profile("nonexistent")


def test_profile_exists(profile_manager, sample_config):
    """Test checking if profile exists."""
    assert not profile_manager.profile_exists("test")

    profile_manager.save_profile("test", sample_config)
    assert profile_manager.profile_exists("test")


def test_get_or_create_default(profile_manager):
    """Test getting or creating default profile."""
    # First call creates default
    config1 = profile_manager.get_or_create_default()
    assert config1 is not None
    assert "default" in profile_manager.list_profiles()

    # Second call loads existing
    config2 = profile_manager.get_or_create_default()
    assert (
        config2.get_analyzer_config("dns").nameservers
        == config1.get_analyzer_config("dns").nameservers
    )


def test_multiple_profiles(profile_manager, sample_config):
    """Test managing multiple profiles."""
    # Create multiple profiles
    config1 = GUIConfigAdapter()
    dns_config1 = config1.get_analyzer_config("dns")
    dns_config1.nameservers = ["1.1.1.1"]
    config1.set_analyzer_config("dns", dns_config1)
    profile_manager.save_profile("profile1", config1)

    config2 = GUIConfigAdapter()
    dns_config2 = config2.get_analyzer_config("dns")
    dns_config2.nameservers = ["8.8.8.8"]
    config2.set_analyzer_config("dns", dns_config2)
    profile_manager.save_profile("profile2", config2)

    config3 = GUIConfigAdapter()
    dns_config3 = config3.get_analyzer_config("dns")
    dns_config3.nameservers = ["9.9.9.9"]
    config3.set_analyzer_config("dns", dns_config3)
    profile_manager.save_profile("profile3", config3)

    # List all
    profiles = profile_manager.list_profiles()
    assert len(profiles) == 3
    assert "profile1" in profiles
    assert "profile2" in profiles
    assert "profile3" in profiles

    # Load and verify
    loaded1 = profile_manager.load_profile("profile1")
    assert loaded1.get_analyzer_config("dns").nameservers == ["1.1.1.1"]

    loaded2 = profile_manager.load_profile("profile2")
    assert loaded2.get_analyzer_config("dns").nameservers == ["8.8.8.8"]


def test_profile_persistence(temp_profiles_dir, sample_config):
    """Test that profiles persist across manager instances."""
    # Save with first manager
    manager1 = ConfigProfileManager(profiles_dir=temp_profiles_dir)
    dns_config = sample_config.get_analyzer_config("dns")
    dns_config.nameservers = ["1.1.1.1"]
    sample_config.set_analyzer_config("dns", dns_config)
    manager1.save_profile("persistent", sample_config)

    # Load with second manager
    manager2 = ConfigProfileManager(profiles_dir=temp_profiles_dir)
    loaded = manager2.load_profile("persistent")
    assert loaded.get_analyzer_config("dns").nameservers == ["1.1.1.1"]


def test_profile_json_format(profile_manager, sample_config, temp_profiles_dir):
    """Test that saved profile is valid JSON."""
    profile_manager.save_profile("json-test", sample_config)

    profile_path = temp_profiles_dir / "json-test.json"
    assert profile_path.exists()

    # Verify it's valid JSON
    with open(profile_path) as f:
        data = json.load(f)
        assert isinstance(data, dict)
        assert "dns" in data
        assert "http" in data
        assert "ssl" in data
