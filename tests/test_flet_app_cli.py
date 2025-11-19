"""Tests for Flet app CLI argument parsing."""

import sys
from unittest.mock import MagicMock, patch


def test_parse_cli_args_empty():
    """Test parse_cli_args with no arguments returns defaults."""
    from webmaster_domain_tool.flet_app import parse_cli_args

    with patch.object(sys, "argv", ["wdt-app"]):
        args = parse_cli_args()
        assert args.config is None
        assert args.domain is None


def test_parse_cli_args_domain_only():
    """Test parse_cli_args with domain only."""
    from webmaster_domain_tool.flet_app import parse_cli_args

    with patch.object(sys, "argv", ["wdt-app", "example.com"]):
        args = parse_cli_args()
        assert args.config is None
        assert args.domain == "example.com"


def test_parse_cli_args_config_and_domain():
    """Test parse_cli_args with --config and domain."""
    from webmaster_domain_tool.flet_app import parse_cli_args

    with patch.object(sys, "argv", ["wdt-app", "--config", "heca", "heca.cz"]):
        args = parse_cli_args()
        assert args.config == "heca"
        assert args.domain == "heca.cz"


def test_parse_cli_args_short_config():
    """Test parse_cli_args with -c short option."""
    from webmaster_domain_tool.flet_app import parse_cli_args

    with patch.object(sys, "argv", ["wdt-app", "-c", "myprofile", "test.org"]):
        args = parse_cli_args()
        assert args.config == "myprofile"
        assert args.domain == "test.org"


def test_parse_cli_args_config_only():
    """Test parse_cli_args with --config but no domain."""
    from webmaster_domain_tool.flet_app import parse_cli_args

    with patch.object(sys, "argv", ["wdt-app", "--config", "production"]):
        args = parse_cli_args()
        assert args.config == "production"
        assert args.domain is None


def test_domain_analyzer_app_initialization_with_defaults():
    """Test DomainAnalyzerApp can be initialized with default parameters."""
    from webmaster_domain_tool.flet_app import DomainAnalyzerApp

    # Create a mock page
    page = MagicMock()
    page.client_storage = MagicMock()
    page.client_storage.get.return_value = None
    page.client_storage.contains_key.return_value = False

    # Initialize with default parameters (no initial profile or domain)
    app = DomainAnalyzerApp(page)

    # Verify domain_input is empty
    assert app.domain_input.value == "" or app.domain_input.value is None


def test_domain_analyzer_app_initialization_with_initial_domain():
    """Test DomainAnalyzerApp pre-fills domain when provided."""
    from webmaster_domain_tool.flet_app import DomainAnalyzerApp

    # Create a mock page
    page = MagicMock()
    page.client_storage = MagicMock()
    page.client_storage.get.return_value = None
    page.client_storage.contains_key.return_value = False

    # Initialize with initial domain
    app = DomainAnalyzerApp(page, initial_domain="example.com")

    # Verify domain_input is pre-filled
    assert app.domain_input.value == "example.com"


def test_domain_analyzer_app_initialization_with_initial_profile():
    """Test DomainAnalyzerApp selects profile when provided."""
    import json

    from webmaster_domain_tool.flet_app import DomainAnalyzerApp

    # Create a mock page with a profile
    page = MagicMock()
    page.client_storage = MagicMock()

    # Mock profile "testprofile" exists
    def mock_get(key):
        if key == "wdt.profile.testprofile":
            return json.dumps({})  # Empty config dict (will use defaults)
        if key == "wdt.profiles.list":
            return json.dumps(["testprofile"])
        return None

    def mock_contains_key(key):
        return key in [
            "wdt.profile.testprofile",
            "wdt.profiles.list",
        ]

    page.client_storage.get.side_effect = mock_get
    page.client_storage.contains_key.side_effect = mock_contains_key

    # Initialize with initial profile
    app = DomainAnalyzerApp(page, initial_profile="testprofile")

    # Verify profile was selected
    assert app.current_profile_name == "testprofile"


def test_domain_analyzer_app_initialization_with_nonexistent_profile():
    """Test DomainAnalyzerApp falls back to default if profile doesn't exist."""
    from webmaster_domain_tool.flet_app import DomainAnalyzerApp

    # Create a mock page
    page = MagicMock()
    page.client_storage = MagicMock()
    page.client_storage.get.return_value = None
    page.client_storage.contains_key.return_value = False

    # Initialize with non-existent profile
    app = DomainAnalyzerApp(page, initial_profile="nonexistent")

    # Should fall back to "default"
    assert app.current_profile_name == "default"
