"""Configuration editor dialog for Flet GUI - Migrated to new modular architecture."""

import logging
from collections.abc import Callable
from typing import Any

import flet as ft

from .core.registry import registry
from .gui_config_adapter import GUIConfigAdapter

logger = logging.getLogger(__name__)


class ConfigEditorDialog:
    """
    Configuration editor dialog with dynamic tabs based on analyzer registry.

    Automatically generates editor UI for all registered analyzers.
    """

    def __init__(
        self,
        page: ft.Page,
        config_adapter: GUIConfigAdapter,
        on_save: Callable[[GUIConfigAdapter], None],
    ) -> None:
        """
        Initialize config editor dialog.

        Args:
            page: Flet page
            config_adapter: Current configuration adapter to edit
            on_save: Callback when config is saved
        """
        self.page = page
        # Work on a copy
        temp_dict = config_adapter.to_dict()
        self.config_adapter = GUIConfigAdapter()
        self.config_adapter.from_dict(temp_dict)
        self.on_save = on_save

        # UI field references (analyzer_id -> field_name -> control)
        self.analyzer_fields: dict[str, dict[str, ft.Control]] = {}

        # Build dialog
        self.dialog = self._build_dialog()

    def _build_dialog(self) -> ft.AlertDialog:
        """Build the main dialog with tabs."""
        # Build tabs dynamically from registry
        tabs_list = []

        # Add global settings tab first
        tabs_list.append(self._create_global_tab())

        # Add tabs for each analyzer
        for analyzer_id, metadata in sorted(
            registry.get_all().items(), key=lambda x: (x[1].category, x[1].name)
        ):
            tab = self._create_analyzer_tab(analyzer_id, metadata)
            if tab:
                tabs_list.append(tab)

        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=tabs_list,
            expand=1,
            scrollable=True,
        )

        return ft.AlertDialog(
            modal=True,
            title=ft.Text("Configuration Editor", size=20, weight="bold"),
            content=ft.Container(
                content=tabs,
                width=700,
                height=500,
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda _: self._close_dialog()),
                ft.ElevatedButton("Save", on_click=lambda _: self._save_and_close()),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

    def _create_global_tab(self) -> ft.Tab:
        """Create global settings tab."""
        global_config = self.config_adapter.config_manager.global_config

        self.analyzer_fields["global"] = {}
        self.analyzer_fields["global"]["verbosity"] = ft.Dropdown(
            label="Verbosity Level",
            value=global_config.verbosity,
            options=[
                ft.dropdown.Option("quiet"),
                ft.dropdown.Option("normal"),
                ft.dropdown.Option("verbose"),
                ft.dropdown.Option("debug"),
            ],
        )
        self.analyzer_fields["global"]["color"] = ft.Checkbox(
            label="Enable colored output",
            value=global_config.color,
        )
        self.analyzer_fields["global"]["parallel"] = ft.Checkbox(
            label="Run independent analyzers in parallel",
            value=global_config.parallel,
        )

        return ft.Tab(
            text="Global",
            icon=ft.Icons.SETTINGS,
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Global Settings", weight=ft.FontWeight.BOLD),
                        self.analyzer_fields["global"]["verbosity"],
                        self.analyzer_fields["global"]["color"],
                        self.analyzer_fields["global"]["parallel"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_analyzer_tab(self, analyzer_id: str, metadata: Any) -> ft.Tab | None:
        """
        Create tab for analyzer configuration.

        Args:
            analyzer_id: Analyzer ID
            metadata: Analyzer metadata

        Returns:
            Tab for this analyzer
        """
        try:
            config = self.config_adapter.get_analyzer_config(analyzer_id)
            fields = {}

            # Enabled checkbox (all analyzers have this)
            fields["enabled"] = ft.Checkbox(
                label=f"Enable {metadata.name}",
                value=config.enabled,
            )

            controls = [
                fields["enabled"],
                ft.Divider(),
            ]

            # Add fields for each config property
            config_dict = config.model_dump()
            for field_name, value in config_dict.items():
                if field_name == "enabled":
                    continue  # Already added

                # Create appropriate control based on type
                if isinstance(value, bool):
                    field = ft.Checkbox(
                        label=field_name.replace("_", " ").title(),
                        value=value,
                    )
                    fields[field_name] = field
                    controls.append(field)
                elif isinstance(value, (int, float)):
                    field = ft.TextField(
                        label=field_name.replace("_", " ").title(),
                        value=str(value),
                        keyboard_type=ft.KeyboardType.NUMBER,
                    )
                    fields[field_name] = field
                    controls.append(field)
                elif isinstance(value, str):
                    field = ft.TextField(
                        label=field_name.replace("_", " ").title(),
                        value=value,
                    )
                    fields[field_name] = field
                    controls.append(field)
                elif isinstance(value, list) and value and isinstance(value[0], str):
                    # List of strings - show as comma-separated
                    field = ft.TextField(
                        label=field_name.replace("_", " ").title() + " (comma-separated)",
                        value=", ".join(value),
                        multiline=True,
                        min_lines=2,
                        max_lines=4,
                    )
                    fields[field_name] = field
                    controls.append(field)
                elif value is None:
                    # Optional field that's None
                    field = ft.TextField(
                        label=field_name.replace("_", " ").title() + " (optional)",
                        value="",
                    )
                    fields[field_name] = field
                    controls.append(field)

            self.analyzer_fields[analyzer_id] = fields

            # Get appropriate icon
            icon_name = getattr(ft.Icons, metadata.icon.upper(), ft.Icons.SETTINGS)

            return ft.Tab(
                text=metadata.name,
                icon=icon_name,
                content=ft.Container(
                    content=ft.Column(
                        controls,
                        spacing=10,
                        scroll=ft.ScrollMode.AUTO,
                    ),
                    padding=20,
                ),
            )

        except Exception as e:
            logger.error(f"Failed to create tab for {analyzer_id}: {e}")
            return None

    def _validate_and_save(self) -> bool:
        """
        Validate all fields and save to config adapter.

        Returns:
            True if validation passed, False otherwise
        """
        try:
            # Update global config
            if "global" in self.analyzer_fields:
                global_fields = self.analyzer_fields["global"]
                self.config_adapter.config_manager.global_config.verbosity = global_fields[
                    "verbosity"
                ].value
                self.config_adapter.config_manager.global_config.color = global_fields[
                    "color"
                ].value
                self.config_adapter.config_manager.global_config.parallel = global_fields[
                    "parallel"
                ].value

            # Update analyzer configs
            for analyzer_id, fields in self.analyzer_fields.items():
                if analyzer_id == "global":
                    continue

                metadata = registry.get(analyzer_id)
                if not metadata:
                    continue

                # Build config dict from UI fields
                config_dict = {}
                current_config = self.config_adapter.get_analyzer_config(analyzer_id)

                for field_name, control in fields.items():
                    if isinstance(control, ft.Checkbox):
                        config_dict[field_name] = control.value
                    elif isinstance(control, ft.TextField):
                        value_str = control.value.strip()

                        # Get original type from current config
                        original_value = getattr(current_config, field_name, None)

                        if original_value is None:
                            # Optional field
                            config_dict[field_name] = value_str if value_str else None
                        elif isinstance(original_value, list):
                            # List of strings
                            config_dict[field_name] = [
                                s.strip() for s in value_str.split(",") if s.strip()
                            ]
                        elif isinstance(original_value, int):
                            config_dict[field_name] = int(value_str) if value_str else 0
                        elif isinstance(original_value, float):
                            config_dict[field_name] = float(value_str) if value_str else 0.0
                        else:
                            config_dict[field_name] = value_str
                    elif isinstance(control, ft.Dropdown):
                        config_dict[field_name] = control.value

                # Create new config instance
                new_config = metadata.config_class(**config_dict)
                self.config_adapter.set_analyzer_config(analyzer_id, new_config)

            return True

        except Exception as e:
            logger.error(f"Config validation failed: {e}", exc_info=True)
            self._show_error(f"Invalid configuration: {e}")
            return False

    def _show_error(self, message: str) -> None:
        """Show error snackbar."""
        snackbar = ft.SnackBar(
            content=ft.Text(message, color="white"),
            bgcolor="red",
        )
        self.page.overlay.append(snackbar)
        snackbar.open = True
        self.page.update()

    def _save_and_close(self) -> None:
        """Validate, save, and close dialog."""
        if self._validate_and_save():
            self.on_save(self.config_adapter)
            self._close_dialog()

    def _close_dialog(self) -> None:
        """Close the dialog."""
        self.dialog.open = False
        self.page.update()

    def show(self) -> None:
        """Show the config editor dialog."""
        self.page.overlay.append(self.dialog)
        self.dialog.open = True
        self.page.update()
