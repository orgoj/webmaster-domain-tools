"""Configuration editor view for Flet GUI - Full-page view (not dialog)."""

import logging
from collections.abc import Callable
from typing import Any

import flet as ft

from .core.registry import registry
from .gui_config_adapter import GUIConfigAdapter

logger = logging.getLogger(__name__)


class ConfigEditorView:
    """
    Configuration editor as full-page view with sidebar navigation.

    Automatically generates editor UI for all registered analyzers.
    Uses left sidebar with icons for navigation.
    """

    def __init__(
        self,
        page: ft.Page,
        config_adapter: GUIConfigAdapter,
        on_save: Callable[[GUIConfigAdapter], None],
        on_cancel: Callable[[], None],
        theme: Any,
    ) -> None:
        """
        Initialize config editor view.

        Args:
            page: Flet page
            config_adapter: Current configuration adapter to edit
            on_save: Callback when config is saved
            on_cancel: Callback when cancel/back is clicked
            theme: UITheme instance
        """
        self.page = page
        # Work on a copy
        temp_dict = config_adapter.to_dict()
        self.config_adapter = GUIConfigAdapter()
        self.config_adapter.from_dict(temp_dict)
        self.on_save = on_save
        self.on_cancel = on_cancel
        self.theme = theme

        # UI field references (analyzer_id -> field_name -> control)
        self.analyzer_fields: dict[str, dict[str, ft.Control]] = {}

        # Build analyzer sections (id -> {name, icon, content})
        self.sections: list[dict[str, Any]] = []
        self._build_sections()

        # Current selected index
        self.current_index = 0

        # Content container (will be updated when selecting different section)
        # No expand here - it's inside a scrollable Column
        self.content_container = ft.Container(
            content=self.sections[0]["content"] if self.sections else ft.Text("No config"),
            padding=20,
        )

    def _is_nested_dict_of_models(self, value: Any, field_info: Any) -> bool:
        """Check if field is dict[str, BaseModel]."""
        if not isinstance(value, dict):
            return False

        # Check if dict values are Pydantic models
        if value:
            first_value = next(iter(value.values()))
            return hasattr(first_value, "model_dump")  # Pydantic model

        # Empty dict - check type hints if available from field_info
        if field_info and hasattr(field_info, "annotation"):
            # Check if annotation looks like dict[str, SomeModel]
            annotation_str = str(field_info.annotation)
            # Simple heuristic: contains "dict" and doesn't end with basic types
            if "dict" in annotation_str.lower() and not any(
                t in annotation_str for t in ["str]", "int]", "float]", "bool]", "list]"]
            ):
                return True

        return False

    def _is_nested_list_of_dicts(self, value: Any) -> bool:
        """Check if field is list[dict] or list[BaseModel]."""
        if not isinstance(value, list):
            return False

        if value:
            first_item = value[0]
            return isinstance(first_item, dict) or hasattr(first_item, "model_dump")

        return False

    def _create_nested_dict_manager(
        self,
        analyzer_id: str,
        field_name: str,
        profiles_dict: dict[str, Any],
        item_class: type,
    ) -> ft.Container:
        """
        Create UI for managing dict[str, BaseModel] (e.g., profiles).

        Args:
            analyzer_id: Analyzer ID
            field_name: Field name (e.g., "profiles")
            profiles_dict: Current dict of items
            item_class: BaseModel class for items

        Returns:
            Container with profile management UI
        """
        # Store reference for later access
        if analyzer_id not in self.analyzer_fields:
            self.analyzer_fields[analyzer_id] = {}

        # Create storage for this nested field
        nested_key = f"_nested_{field_name}"
        if nested_key not in self.analyzer_fields[analyzer_id]:
            self.analyzer_fields[analyzer_id][nested_key] = {}

        # Profile list container (will be updated dynamically)
        profiles_container = ft.Column(spacing=10)

        def refresh_profiles():
            """Refresh the profiles list display."""
            profiles_container.controls.clear()

            current_profiles = self.analyzer_fields[analyzer_id][nested_key]

            if not current_profiles:
                profiles_container.controls.append(
                    ft.Text("No profiles configured", italic=True, color=ft.Colors.GREY_700)
                )
            else:
                for profile_id, profile_data in current_profiles.items():
                    # Get profile name
                    profile_name = (
                        profile_data.get("name", profile_id)
                        if isinstance(profile_data, dict)
                        else getattr(profile_data, "name", profile_id)
                    )

                    # Create profile card with edit/delete buttons
                    profile_card = ft.Card(
                        content=ft.Container(
                            content=ft.Row(
                                [
                                    ft.Icon(ft.Icons.FOLDER, color=ft.Colors.BLUE_700),
                                    ft.Column(
                                        [
                                            ft.Text(profile_name, weight=ft.FontWeight.BOLD),
                                            ft.Text(
                                                f"ID: {profile_id}",
                                                size=11,
                                                color=ft.Colors.GREY_700,
                                            ),
                                        ],
                                        spacing=2,
                                    ),
                                    ft.Row(
                                        [
                                            ft.IconButton(
                                                icon=ft.Icons.EDIT,
                                                tooltip="Edit profile",
                                                on_click=lambda e, pid=profile_id: edit_profile(
                                                    pid
                                                ),
                                            ),
                                            ft.IconButton(
                                                icon=ft.Icons.DELETE,
                                                tooltip="Delete profile",
                                                icon_color=ft.Colors.RED_700,
                                                on_click=lambda e, pid=profile_id: delete_profile(
                                                    pid
                                                ),
                                            ),
                                        ],
                                        spacing=5,
                                    ),
                                ],
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            ),
                            padding=10,
                        )
                    )
                    profiles_container.controls.append(profile_card)

            self.page.update()

        def add_profile(e):
            """Show dialog to add new profile."""
            profile_id_field = ft.TextField(label="Profile ID", hint_text="e.g., web-server-1")

            # Get all fields from item_class
            fields_dict = {}
            if hasattr(item_class, "model_fields"):
                for fname, finfo in item_class.model_fields.items():
                    default_val = finfo.default if finfo.default is not None else ""
                    if isinstance(default_val, list):
                        default_val = ""
                    fields_dict[fname] = ft.TextField(
                        label=fname.replace("_", " ").title(),
                        value=str(default_val),
                        multiline=True if fname in ["description"] else False,
                    )

            def save_new_profile(e):
                pid = profile_id_field.value.strip()
                if not pid:
                    return

                # Collect field values
                new_profile = {}
                for fname, field in fields_dict.items():
                    val = field.value.strip()
                    # Try to parse lists
                    if "[" in str(item_class.model_fields[fname].annotation):
                        new_profile[fname] = [v.strip() for v in val.split(",") if v.strip()]
                    else:
                        new_profile[fname] = val

                # Add to storage
                self.analyzer_fields[analyzer_id][nested_key][pid] = new_profile
                refresh_profiles()
                dialog.open = False
                self.page.update()

            dialog = ft.AlertDialog(
                title=ft.Text("Add New Profile"),
                content=ft.Column(
                    [
                        profile_id_field,
                        ft.Divider(),
                        *fields_dict.values(),
                    ],
                    tight=True,
                    scroll=ft.ScrollMode.AUTO,
                    height=400,
                ),
                actions=[
                    ft.TextButton(
                        "Cancel",
                        on_click=lambda e: setattr(dialog, "open", False) or self.page.update(),
                    ),
                    ft.TextButton("Add", on_click=save_new_profile),
                ],
            )

            self.page.overlay.append(dialog)
            dialog.open = True
            self.page.update()

        def edit_profile(profile_id: str):
            """Edit existing profile."""
            current_data = self.analyzer_fields[analyzer_id][nested_key][profile_id]

            # Create fields pre-filled with current values
            fields_dict = {}
            for fname in current_data.keys():
                val = current_data[fname]
                if isinstance(val, list):
                    val = ", ".join(val)
                fields_dict[fname] = ft.TextField(
                    label=fname.replace("_", " ").title(),
                    value=str(val),
                    multiline=True if fname in ["description"] else False,
                )

            def save_edited_profile(e):
                # Update storage
                for fname, field in fields_dict.items():
                    val = field.value.strip()
                    # Parse lists
                    if isinstance(current_data[fname], list):
                        self.analyzer_fields[analyzer_id][nested_key][profile_id][fname] = [
                            v.strip() for v in val.split(",") if v.strip()
                        ]
                    else:
                        self.analyzer_fields[analyzer_id][nested_key][profile_id][fname] = val

                refresh_profiles()
                dialog.open = False
                self.page.update()

            dialog = ft.AlertDialog(
                title=ft.Text(f"Edit Profile: {profile_id}"),
                content=ft.Column(
                    [
                        *fields_dict.values(),
                    ],
                    tight=True,
                    scroll=ft.ScrollMode.AUTO,
                    height=400,
                ),
                actions=[
                    ft.TextButton(
                        "Cancel",
                        on_click=lambda e: setattr(dialog, "open", False) or self.page.update(),
                    ),
                    ft.TextButton("Save", on_click=save_edited_profile),
                ],
            )

            self.page.overlay.append(dialog)
            dialog.open = True
            self.page.update()

        def delete_profile(profile_id: str):
            """Delete profile with confirmation."""

            def confirm_delete(e):
                del self.analyzer_fields[analyzer_id][nested_key][profile_id]
                refresh_profiles()
                dialog.open = False
                self.page.update()

            dialog = ft.AlertDialog(
                title=ft.Text("Confirm Delete"),
                content=ft.Text(f"Delete profile '{profile_id}'?"),
                actions=[
                    ft.TextButton(
                        "Cancel",
                        on_click=lambda e: setattr(dialog, "open", False) or self.page.update(),
                    ),
                    ft.TextButton("Delete", on_click=confirm_delete),
                ],
            )

            self.page.overlay.append(dialog)
            dialog.open = True
            self.page.update()

        # Initialize with current profiles
        self.analyzer_fields[analyzer_id][nested_key] = dict(profiles_dict)

        # Build UI
        add_button = ft.ElevatedButton(
            "Add Profile",
            icon=ft.Icons.ADD,
            on_click=add_profile,
        )

        # Initial refresh
        refresh_profiles()

        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        field_name.replace("_", " ").title(),
                        size=14,
                        weight=ft.FontWeight.BOLD,
                    ),
                    add_button,
                    profiles_container,
                ],
                spacing=10,
            ),
            padding=10,
            border=ft.border.all(1, ft.Colors.GREY_400),
            border_radius=5,
        )

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

    def build(self) -> ft.Column:
        """Build the full-page view with sidebar navigation."""
        # Build navigation rail destinations
        nav_rail_destinations = []
        for section in self.sections:
            nav_rail_destinations.append(
                ft.NavigationRailDestination(
                    icon=section["icon"],
                    label=section["name"],
                )
            )

        # Sidebar - scrollable navigation with icons and labels below
        sidebar = ft.Container(
            bgcolor=ft.Colors.GREY_300,
            content=ft.Column(
                [
                    ft.NavigationRail(
                        selected_index=self.current_index,
                        label_type=ft.NavigationRailLabelType.SELECTED,  # Show label only for selected item
                        min_width=72,  # Minimum width for rail
                        destinations=nav_rail_destinations,
                        on_change=self._on_nav_change,
                        bgcolor=ft.Colors.GREY_300,
                    ),
                ],
                scroll=ft.ScrollMode.AUTO,  # Enable scroll when many items
                alignment=ft.MainAxisAlignment.START,
            ),
        )

        # Content area - full height with scroll
        # Content container has scroll so it always starts from top
        content_area = ft.Container(
            content=ft.Column(
                [
                    self.content_container,
                ],
                scroll=ft.ScrollMode.AUTO,  # Enable scroll for long configs
                alignment=ft.MainAxisAlignment.START,  # Always start from top
            ),
        )

        # Main content row - sidebar + content (full height)
        content_row = ft.Row(
            [
                sidebar,
                ft.VerticalDivider(width=1),
                content_area,
            ],
            spacing=0,
            expand=True,  # Full height available - CRITICAL!
        )

        # Header with Back and Save buttons
        header = ft.Row(
            [
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    tooltip="Back to main view",
                    on_click=lambda _: self._cancel(),
                ),
                ft.Text(
                    "Configuration Editor",
                    size=20,
                    weight=ft.FontWeight.BOLD,
                    color=self.theme.primary_color,
                ),
                ft.Container(expand=True),  # Spacer
                ft.TextButton(
                    "Cancel",
                    icon=ft.Icons.CANCEL,
                    on_click=lambda _: self._cancel(),
                ),
                ft.ElevatedButton(
                    "Save",
                    icon=ft.Icons.SAVE,
                    on_click=lambda _: self._save(),
                    style=ft.ButtonStyle(
                        color=self.theme.primary_bg,
                        bgcolor=self.theme.primary_color,
                    ),
                ),
            ],
            alignment=ft.MainAxisAlignment.START,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

        # Full-page layout - header + content row
        # This Column MUST have expand=True to fill page and give bounded height to children
        return ft.Column(
            [
                header,
                ft.Divider(),
                content_row,
            ],
            spacing=10,
            expand=True,  # Fill page height - CRITICAL!
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
            # No scroll/expand - parent content_area handles scrolling
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

                # Get field info from config class for type checking
                field_info = None
                if hasattr(metadata.config_class, "model_fields"):
                    field_info = metadata.config_class.model_fields.get(field_name)

                # Get original value from config object (not dumped)
                original_value = getattr(config, field_name, value)

                # Check for nested dict of models (check original, not dumped)
                if self._is_nested_dict_of_models(original_value, field_info):
                    # Get item class from annotation (more reliable)
                    item_class = None
                    if field_info and hasattr(field_info, "annotation"):
                        # Try to extract item class from annotation
                        annotation = field_info.annotation
                        # Get the value type from dict[str, ValueType]
                        if hasattr(annotation, "__args__") and len(annotation.__args__) > 1:
                            item_class = annotation.__args__[1]

                    if not item_class and original_value:
                        # Fallback: get from first item
                        item_class = type(next(iter(original_value.values())))

                    if item_class:
                        nested_ui = self._create_nested_dict_manager(
                            analyzer_id, field_name, value, item_class
                        )
                        controls.append(nested_ui)
                        continue

                # Check for nested list
                if self._is_nested_list_of_dicts(value):
                    # For now, show as JSON text area (simpler than full list manager)
                    import json

                    field = ft.TextField(
                        label=field_name.replace("_", " ").title() + " (JSON)",
                        value=json.dumps(value, indent=2),
                        multiline=True,
                        min_lines=5,
                        max_lines=10,
                    )
                    fields[field_name] = field
                    controls.append(field)
                    continue

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
                # No scroll/expand - parent content_area handles scrolling
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
                    # Check for nested dict storage (skip the _nested_ keys themselves)
                    if field_name.startswith("_nested_"):
                        continue

                    # Check if there's a nested dict for this field
                    nested_key = f"_nested_{field_name}"
                    if nested_key in fields:
                        # This is a nested dict - get from storage
                        config_dict[field_name] = fields[nested_key]
                        continue

                    if isinstance(control, ft.Checkbox):
                        config_dict[field_name] = control.value
                    elif isinstance(control, ft.TextField):
                        value_str = control.value.strip()

                        # Get original type from current config
                        original_value = getattr(current_config, field_name, None)

                        # Check if this is a JSON field (nested list)
                        if "(JSON)" in control.label:
                            import json

                            try:
                                config_dict[field_name] = json.loads(value_str) if value_str else []
                            except json.JSONDecodeError:
                                logger.warning(f"Invalid JSON for {field_name}, using empty list")
                                config_dict[field_name] = []
                        elif original_value is None:
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

    def _save(self) -> None:
        """Validate and save configuration."""
        if self._validate_and_save():
            # Show confirmation snackbar
            snackbar = ft.SnackBar(
                content=ft.Text("Configuration saved successfully"),
                bgcolor=ft.Colors.GREEN,
            )
            self.page.overlay.append(snackbar)
            snackbar.open = True
            self.page.update()

            # Call save callback
            self.on_save(self.config_adapter)

    def _cancel(self) -> None:
        """Cancel editing and go back."""
        self.on_cancel()
