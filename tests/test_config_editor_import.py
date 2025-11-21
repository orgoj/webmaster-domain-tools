"""Test config editor view can be imported (catches type hint errors)."""


def test_import_config_editor_view():
    """Test that config_editor_view module can be imported without errors."""
    from webmaster_domain_tool.config_editor_view import ConfigEditorView

    assert ConfigEditorView is not None


def test_import_flet_config_manager():
    """Test that flet_config_manager module can be imported without errors."""
    from webmaster_domain_tool.flet_config_manager import FletConfigProfileManager

    assert FletConfigProfileManager is not None
