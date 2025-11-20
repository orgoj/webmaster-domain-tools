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
    Configuration editor dialog with sidebar navigation.

    Automatically generates editor UI for all registered analyzers.
    Uses left sidebar with icons for navigation.
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

        # Build analyzer sections (id -> {name, icon, content})
        self.sections: list[dict[str, Any]] = []
        self._build_sections()

        # Current selected index
        self.current_index = 0

        # Content container (will be updated when selecting different section)
        self.content_container = ft.Container(
            content=self.sections[0]["content"] if self.sections else ft.Text("No config"),
            padding=20,
            expand=True,
        )

        # Build dialog
        self.dialog = self._build_dialog()

    def _build_sections(self) -> None:
        """Build all configuration sections (global + analyzers)."""
        # Add global settings first
        global_content = self._create_global_content()
        self.sections.append(
            {
                "id": "global",
                "name": "Global Settings",
                "icon": ft.Icons.SETTINGS,
                "content": global_content,
            }
        )

        # Add analyzer sections
        for analyzer_id, metadata in sorted(
            registry.get_all().items(), key=lambda x: (x[1].category, x[1].name)
        ):
            content = self._create_analyzer_content(analyzer_id, metadata)
            if content:
                icon_name = getattr(ft.Icons, metadata.icon.upper(), ft.Icons.SETTINGS)
                self.sections.append(
                    {
                        "id": analyzer_id,
                        "name": metadata.name,
                        "icon": icon_name,
                        "content": content,
                    }
                )

    def _build_dialog(self) -> ft.AlertDialog:
        """Build the main dialog with sidebar navigation."""
        # Build navigation rail (left sidebar)
        nav_rail_destinations = []
        for section in self.sections:
            nav_rail_destinations.append(
                ft.NavigationRailDestination(
                    icon=section["icon"],
                    label=section["name"],
                )
            )

        nav_rail = ft.NavigationRail(
            selected_index=self.current_index,
            label_type=ft.NavigationRailLabelType.ALL,
            min_width=100,
            min_extended_width=200,
            destinations=nav_rail_destinations,
            on_change=self._on_nav_change,
            bgcolor=ft.colors.SURFACE_VARIANT,
        )

        # Main layout: Row with nav rail on left, content on right
        main_content = ft.Row(
            [
                nav_rail,
                ft.VerticalDivider(width=1),
                self.content_container,
            ],
            spacing=0,
            expand=True,
        )

        return ft.AlertDialog(
            modal=True,
            title=ft.Text("Configuration Editor", size=20, weight="bold"),
            content=ft.Container(
                content=main_content,
                width=1100,  # Larger width
                height=700,  # Larger height
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda _: self._close_dialog()),
                ft.ElevatedButton("Save", on_click=lambda _: self._save_and_close()),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

    def _on_nav_change(self, e: ft.ControlEvent) -> None:
        """Handle navigation rail selection change."""
        self.current_index = e.control.selected_index

        # Update content container
        if 0 <= self.current_index < len(self.sections):
            self.content_container.content = self.sections[self.current_index]["content"]
            self.page.update()

    def _create_global_content(self) -> ft.Column:
        """Create global settings content."""
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

        return ft.Column(
            [
                ft.Text("Global Settings", size=18, weight=ft.FontWeight.BOLD),
                ft.Divider(),
                self.analyzer_fields["global"]["verbosity"],
                self.analyzer_fields["global"]["color"],
                self.analyzer_fields["global"]["parallel"],
            ],
            spacing=10,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )

    def _create_analyzer_content(self, analyzer_id: str, metadata: Any) -> ft.Column | None:
        """
        Create content for analyzer configuration.

        Args:
            analyzer_id: Analyzer ID
            metadata: Analyzer metadata

        Returns:
            Column with analyzer config controls
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
                ft.Text(metadata.name, size=18, weight=ft.FontWeight.BOLD),
                ft.Text(
                    metadata.description,
                    size=12,
                    color=ft.Colors.SECONDARY,
                    italic=True,
                ),
                ft.Divider(),
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

            return ft.Column(
                controls,
                spacing=10,
                scroll=ft.ScrollMode.AUTO,
                expand=True,
            )

        except Exception as e:
            logger.error(f"Failed to create content for {analyzer_id}: {e}")
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
