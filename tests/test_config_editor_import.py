"""Test config editor dialog can be imported (catches type hint errors)."""


def test_import_config_editor_dialog():
    """Test that config_editor_dialog module can be imported without errors."""
    from webmaster_domain_tool.config_editor_dialog import ConfigEditorDialog

    assert ConfigEditorDialog is not None


def test_import_flet_config_manager():
    """Test that flet_config_manager module can be imported without errors."""
    from webmaster_domain_tool.flet_config_manager import FletConfigProfileManager

    assert FletConfigProfileManager is not None
