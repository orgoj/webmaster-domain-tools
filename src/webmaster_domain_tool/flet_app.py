"""Flet multiplatform GUI application for webmaster-domain-tool."""

import argparse
import ipaddress
import logging
import re
import sys
import threading
from dataclasses import dataclass
from typing import Any

import flet as ft

# Import all analyzers so they register themselves
from .analyzers import dns_analyzer  # noqa: F401
from .config_editor_dialog import ConfigEditorDialog
from .core.registry import registry
from .flet_config_manager import FletConfigProfileManager
from .gui_config_adapter import GUIConfigAdapter

logger = logging.getLogger(__name__)


def parse_cli_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the GUI application.

    Returns:
        Parsed arguments with config and domain attributes
    """
    parser = argparse.ArgumentParser(
        description="Webmaster Domain Tool - GUI Application",
        prog="wdt-app",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=None,
        help="Configuration profile name to use",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default=None,
        help="Domain to analyze (e.g., example.com)",
    )

    return parser.parse_args()


@dataclass
class UITheme:
    """Centralized UI theme configuration for consistent styling."""

    # Primary colors
    primary_color: str = ft.Colors.BLUE_700
    primary_bg: str = ft.Colors.WHITE

    # Text colors
    text_primary: str = ft.Colors.BLUE_700
    text_secondary: str = ft.Colors.GREY_700

    # Status colors
    success_color: str = ft.Colors.GREEN
    success_bg: str = ft.Colors.GREEN_50
    error_color: str = ft.Colors.RED
    error_bg: str = ft.Colors.RED_50
    warning_color: str = ft.Colors.ORANGE
    warning_bg: str = ft.Colors.ORANGE_50
    # Specific warning orange shades (previously hardcoded as hex)
    warning_orange: str = "#FFA500"  # Orange for warnings
    warning_orange_bg: str = "#FFF3CD"  # Light orange/yellow background

    # Icon sizes
    icon_large: int = 40
    icon_medium: int = 30
    icon_small: int = 20

    # Text sizes
    text_title: int = 28
    text_heading: int = 18
    text_subheading: int = 16
    text_label: int = 14
    text_body: int = 12
    text_small: int = 11

    # Spacing
    spacing_large: int = 20
    spacing_medium: int = 15
    spacing_small: int = 10
    spacing_tiny: int = 5

    # Padding
    padding_large: int = 20
    padding_medium: int = 15
    padding_small: int = 10

    # Border radius
    border_radius_large: int = 10
    border_radius_small: int = 5

    # Display limits
    auto_display_max_items: int = 5  # Max items to show in auto-display lists/dicts


class DomainAnalyzerApp:
    """Main Flet application for domain analysis."""

    def __init__(
        self,
        page: ft.Page,
        initial_profile: str | None = None,
        initial_domain: str | None = None,
    ) -> None:
        """
        Initialize the application.

        Args:
            page: Flet page instance
            initial_profile: Optional profile name to load (overrides last selected)
            initial_domain: Optional domain to pre-fill in the input field
        """
        self.page = page
        self.page.title = "Webmaster Domain Tool"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.scroll = ft.ScrollMode.AUTO

        # Handle window close event to prevent Flutter embedder error
        self.page.on_window_event = self._on_window_event

        # Initialize theme
        self.theme = UITheme()
        self.page.padding = self.theme.padding_large

        # Initialize profile manager
        self.profile_manager = FletConfigProfileManager(self.page)

        # Determine which profile to load (CLI arg > last selected > default)
        if initial_profile and self.profile_manager.profile_exists(initial_profile):
            self.current_profile_name = initial_profile
        else:
            # Use last selected profile or fall back
            self.current_profile_name = self.profile_manager.get_last_selected_profile()

        # Load the profile (create default if needed)
        if self.profile_manager.profile_exists(self.current_profile_name):
            self.config_adapter = self.profile_manager.load_profile(self.current_profile_name)
        else:
            # Fallback to default if selected profile doesn't exist
            self.current_profile_name = "default"
            self.config_adapter = self.profile_manager.get_or_create_default()

        # Store initial domain for pre-filling input
        self._initial_domain = initial_domain

        # UI Components
        self.domain_input = ft.TextField(
            label="Domain name",
            hint_text="example.com",
            prefix_icon=ft.Icons.LANGUAGE,
            expand=True,
            autofocus=True,
            value=self._initial_domain or "",
            on_submit=lambda _: self.run_analysis(),
        )

        self.analyze_button = ft.ElevatedButton(
            "Analyze Domain",
            icon=ft.Icons.SEARCH,
            on_click=lambda _: self.run_analysis(),
            style=ft.ButtonStyle(
                color=self.theme.primary_bg,
                bgcolor=self.theme.primary_color,
            ),
        )

        self.progress_bar = ft.ProgressBar(visible=False)
        self.status_text = ft.Text(
            "",
            size=self.theme.text_label,
            color=self.theme.text_secondary,
            text_align=ft.TextAlign.LEFT,
        )

        # Profile management UI components
        self.profile_dropdown = ft.Dropdown(
            label="Config Profile",
            options=[],  # Populated in _load_profile_list()
            on_change=self._on_profile_changed,
            width=200,
        )

        self.config_editor_button = ft.IconButton(
            icon=ft.Icons.SETTINGS,
            tooltip="Edit configuration",
            on_click=self._show_config_editor,
        )

        self.save_profile_button = ft.IconButton(
            icon=ft.Icons.SAVE,
            tooltip="Save current config as new profile",
            on_click=self._show_save_profile_dialog,
        )

        self.delete_profile_button = ft.IconButton(
            icon=ft.Icons.DELETE,
            tooltip="Delete selected profile",
            on_click=self._delete_current_profile,
        )

        # Analysis options checkboxes - generated dynamically from registry (DRY!)
        # Uses registry as single source of truth
        self.analyzer_checkboxes: dict[str, ft.Checkbox] = {}
        for analyzer_id, metadata in registry.get_all().items():
            # Create checkbox for each analyzer
            config = self.config_adapter.get_analyzer_config(analyzer_id)
            self.analyzer_checkboxes[analyzer_id] = ft.Checkbox(
                label=metadata.name,
                value=config.enabled,  # Use enabled flag from config
            )

        # Results container (aligned left, not centered)
        self.results_column = ft.Column(
            spacing=self.theme.spacing_small,
            expand=True,
            horizontal_alignment=ft.CrossAxisAlignment.START,
        )

        # Build UI
        self._build_ui()

    def _create_section(
        self,
        title: str,
        controls: list[ft.Control],
        visible: bool = True,
        spacing: int | None = None,
    ) -> ft.Card:
        """
        Create a consistently styled section card with left alignment.

        This is a centralized helper to ensure all sections have proper
        left alignment and consistent styling (DRY principle).

        Args:
            title: Section heading text
            controls: List of controls to display in the section
            visible: Whether the section is initially visible
            spacing: Spacing between controls (uses theme default if None)

        Returns:
            Styled Card with left-aligned content
        """
        return ft.Card(
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.Text(
                            title,
                            size=self.theme.text_heading,
                            weight=ft.FontWeight.BOLD,
                            text_align=ft.TextAlign.LEFT,
                        ),
                        *controls,
                    ],
                    spacing=spacing or self.theme.spacing_small,
                    horizontal_alignment=ft.CrossAxisAlignment.START,
                ),
                padding=self.theme.padding_large,
                alignment=ft.alignment.top_left,  # ← KEY FIX: Container alignment
            ),
            elevation=2,
            visible=visible,
        )

    def _build_ui(self) -> None:
        """Build the user interface."""
        # Header with profile management controls
        header = ft.Container(
            content=ft.Column(
                [
                    # Profile management row
                    ft.Row(
                        [
                            self.profile_dropdown,
                            self.config_editor_button,
                            self.save_profile_button,
                            self.delete_profile_button,
                        ],
                        alignment=ft.MainAxisAlignment.START,
                        spacing=10,
                    ),
                    # Title row
                    ft.Row(
                        [
                            ft.Icon(
                                ft.Icons.DOMAIN,
                                size=self.theme.icon_large,
                                color=self.theme.primary_color,
                            ),
                            ft.Text(
                                "Webmaster Domain Tool",
                                size=self.theme.text_title,
                                weight=ft.FontWeight.BOLD,
                                color=self.theme.primary_color,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    ft.Text(
                        "Comprehensive domain analysis for webmasters",
                        size=self.theme.text_label,
                        color=self.theme.text_secondary,
                        text_align=ft.TextAlign.CENTER,
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=ft.padding.only(bottom=self.theme.padding_large),
        )

        # Input section - using centralized helper
        input_section = self._create_section(
            title="Enter Domain",
            controls=[
                ft.Row(
                    [
                        self.domain_input,
                        self.analyze_button,
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                self.progress_bar,
                self.status_text,
            ],
        )

        # Options section - using centralized helper with dynamic checkboxes (DRY!)
        # Build checkbox grid dynamically from registry
        checkbox_containers = [
            ft.Container(checkbox, col={"sm": 6, "md": 4, "xl": 3})
            for checkbox in self.analyzer_checkboxes.values()
        ]

        options_section = self._create_section(
            title="Analysis Options",
            controls=[ft.ResponsiveRow(checkbox_containers)],
            spacing=self.theme.spacing_medium,
        )

        # Results section - using centralized helper
        results_section = self._create_section(
            title="Results",
            controls=[self.results_column],
            visible=False,
        )

        self.results_card = results_section

        # Main layout
        main_column = ft.Column(
            [
                header,
                input_section,
                options_section,
                results_section,
            ],
            spacing=self.theme.spacing_large,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )

        self.page.add(main_column)

        # Load profile list after UI is built
        self._load_profile_list()

    def validate_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        domain = domain.strip()
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )

        return bool(domain_pattern.match(domain))

    def normalize_domain(self, domain: str) -> str:
        """Normalize domain name."""
        domain = domain.strip()
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")
        return domain

    def _get_enabled_analyzers(self) -> set[str]:
        """
        Get set of analyzer IDs that are enabled based on checkbox states.

        Returns:
            Set of enabled analyzer IDs
        """
        enabled = set()
        for analyzer_id, checkbox in self.analyzer_checkboxes.items():
            if checkbox.value:
                enabled.add(analyzer_id)
        return enabled

    def run_analysis(self) -> None:
        """Run domain analysis."""
        domain = self.domain_input.value

        if not domain:
            self.show_error("Please enter a domain name")
            return

        if not self.validate_domain(domain):
            self.show_error("Invalid domain format. Expected format: example.com")
            return

        domain = self.normalize_domain(domain)

        # Show progress
        self.progress_bar.visible = True
        self.analyze_button.disabled = True
        self.status_text.value = f"Analyzing {domain}..."
        self.results_column.controls.clear()
        self.results_card.visible = False
        self.page.update()

        # Run analysis in background thread
        thread = threading.Thread(target=self._run_analysis_sync, args=(domain,), daemon=True)
        thread.start()

    def _run_analysis_sync(self, domain: str) -> None:
        """Run analysis synchronously in background thread using new modular architecture."""
        try:
            # Update status for user
            self.update_status(f"Analyzing {domain}...")

            # Get enabled analyzers from checkboxes
            enabled_analyzers_set = self._get_enabled_analyzers()

            # Get all analyzer IDs
            all_analyzer_ids = list(registry.get_all_ids())

            # Filter to only enabled ones
            enabled_analyzers = [aid for aid in all_analyzer_ids if aid in enabled_analyzers_set]

            # Calculate skip set (inverse of enabled)
            skip_set = set(all_analyzer_ids) - enabled_analyzers_set

            # Resolve dependencies
            try:
                execution_order = registry.resolve_dependencies(enabled_analyzers, skip_set)
            except ValueError as e:
                self.show_error(f"Dependency error: {e}")
                return

            if not execution_order:
                self.show_error("No analyzers selected!")
                return

            # Execute analyzers in order
            results_dict: dict[str, Any] = {}

            for analyzer_id in execution_order:
                self.update_status(f"Running {analyzer_id}...")

                metadata = registry.get(analyzer_id)
                if not metadata:
                    logger.error(f"Analyzer not found: {analyzer_id}")
                    continue

                config = self.config_adapter.get_analyzer_config(analyzer_id)

                try:
                    # Instantiate analyzer
                    analyzer = metadata.plugin_class()

                    # Run analysis
                    result = analyzer.analyze(domain, config)

                    # Store result
                    results_dict[analyzer_id] = result

                except Exception as e:
                    logger.error(f"Analyzer '{analyzer_id}' failed: {e}", exc_info=True)
                    # Store None to indicate failure
                    results_dict[analyzer_id] = None

            # Display results
            self.display_results(domain, results_dict)

        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)
            self.show_error(f"Analysis failed: {str(e)}")
        finally:
            self.progress_bar.visible = False
            self.analyze_button.disabled = False
            self.status_text.value = ""
            self.page.update()

    def update_status(self, message: str) -> None:
        """Update status message."""
        self.status_text.value = message
        self.page.update()

    def _on_window_event(self, e: ft.ControlEvent) -> None:
        """Handle window events to prevent Flutter embedder error on close.

        Using sys.exit(0) instead of window_destroy() to avoid Flutter
        'FlutterEngineRemoveView' error when closing the window.
        """
        if e.data == "close":
            # Clean exit without calling window_destroy() which causes Flutter error
            sys.exit(0)

    def display_results(self, domain: str, results: dict[str, Any]) -> None:
        """Display analysis results."""
        self.results_column.controls.clear()

        # Summary
        total_errors = 0
        total_warnings = 0

        for result in results.values():
            if hasattr(result, "errors"):
                total_errors += len(result.errors)
            if hasattr(result, "warnings"):
                total_warnings += len(result.warnings)

        # Determine status icon and color based on errors/warnings
        if total_errors > 0:
            status_icon = ft.Icons.ERROR
            status_color = self.theme.error_color
            status_bg = self.theme.error_bg
            status_text = "Analysis completed with errors"
        elif total_warnings > 0:
            status_icon = ft.Icons.WARNING
            status_color = self.theme.warning_orange
            status_bg = self.theme.warning_orange_bg
            status_text = "Analysis completed with warnings"
        else:
            status_icon = ft.Icons.CHECK_CIRCLE
            status_color = self.theme.success_color
            status_bg = self.theme.success_bg
            status_text = "Analysis completed successfully"

        summary_card = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(
                        status_icon,
                        color=status_color,
                        size=self.theme.icon_medium,
                    ),
                    ft.Column(
                        [
                            ft.Text(
                                f"{status_text}: {domain}",
                                size=self.theme.text_subheading,
                                weight="bold",
                                text_align=ft.TextAlign.LEFT,
                            ),
                            ft.Text(
                                f"Errors: {total_errors} | Warnings: {total_warnings}",
                                size=self.theme.text_body,
                                color=self.theme.text_secondary,
                                text_align=ft.TextAlign.LEFT,
                            ),
                        ],
                        spacing=self.theme.spacing_tiny,
                        alignment=ft.MainAxisAlignment.START,
                    ),
                ],
                alignment=ft.MainAxisAlignment.START,
            ),
            bgcolor=status_bg,
            border_radius=self.theme.border_radius_large,
            padding=self.theme.padding_medium,
        )
        self.results_column.controls.append(summary_card)

        # Individual results - iterate through analyzer registry
        # Map analyzer_id to custom panel methods (GUI-specific rendering)
        custom_renderers = {
            "whois": self._create_whois_panel,
            "dns": self._create_dns_panel,
            "http": self._create_http_panel,
            "ssl": self._create_ssl_panel,
            "email": self._create_email_panel,
            "security-headers": self._create_headers_panel,
            "rbl": self._create_rbl_panel,
            "seo-files": self._create_seo_panel,
            "favicon": self._create_favicon_panel,
            "site-verification": self._create_site_verification_panel,
            "cdn": self._create_cdn_panel,
        }

        for analyzer_id in results.keys():
            metadata = registry.get(analyzer_id)
            if not metadata:
                continue

            # Skip if result is None (disabled)
            result = results.get(analyzer_id)
            if result is None:
                continue

            # Route to appropriate renderer
            if analyzer_id in custom_renderers:
                # Use custom GUI renderer
                panel = custom_renderers[analyzer_id](result)
                self.results_column.controls.append(panel)
            else:
                # Use default auto-display renderer
                panel = self._create_default_auto_display_panel(metadata, result)
                self.results_column.controls.append(panel)

        self.results_card.visible = True
        self.page.update()

    def _create_error_container(self, message: str) -> ft.Container:
        """Create a standardized error display container.

        Args:
            message: Error message to display

        Returns:
            Formatted Container widget with error styling
        """
        return ft.Container(
            content=self._row(
                [
                    ft.Icon(
                        ft.Icons.ERROR, color=self.theme.error_color, size=self.theme.icon_small
                    ),
                    self._text(message, color=self.theme.error_color),
                ],
            ),
            bgcolor=self.theme.error_bg,
            border_radius=self.theme.border_radius_small,
            padding=self.theme.padding_small,
        )

    def _create_warning_container(self, message: str) -> ft.Container:
        """Create a standardized warning display container.

        Args:
            message: Warning message to display

        Returns:
            Formatted Container widget with warning styling
        """
        return ft.Container(
            content=self._row(
                [
                    ft.Icon(
                        ft.Icons.WARNING, color=self.theme.warning_color, size=self.theme.icon_small
                    ),
                    self._text(message, color=self.theme.warning_color),
                ],
            ),
            bgcolor=self.theme.warning_bg,
            border_radius=self.theme.border_radius_small,
            padding=self.theme.padding_small,
        )

    def _add_errors_and_warnings(self, content: list[ft.Control], result: Any) -> None:
        """Add error and warning displays to content list.

        Args:
            content: List of controls to append to
            result: Analysis result object with errors and warnings attributes
        """
        if hasattr(result, "errors") and result.errors:
            for error in result.errors:
                content.append(self._create_error_container(error))

        if hasattr(result, "warnings") and result.warnings:
            for warning in result.warnings:
                content.append(self._create_warning_container(warning))

    def _text(self, text: str, **kwargs) -> ft.Text:
        """Create a left-aligned, selectable text widget with defaults.

        Args:
            text: Text content
            **kwargs: Additional Text properties (can override defaults)

        Returns:
            Text widget with left alignment and text selection enabled
        """
        # Set defaults (can be overridden by kwargs)
        if "text_align" not in kwargs:
            kwargs["text_align"] = ft.TextAlign.LEFT
        if "selectable" not in kwargs:
            kwargs["selectable"] = True  # ← ENABLE TEXT SELECTION for copy/paste
        return ft.Text(text, **kwargs)

    def _row(self, controls: list[ft.Control], **kwargs) -> ft.Row:
        """Create a left-aligned row widget with defaults.

        Args:
            controls: List of controls
            **kwargs: Additional Row properties

        Returns:
            Row widget with left alignment
        """
        if "alignment" not in kwargs:
            kwargs["alignment"] = ft.MainAxisAlignment.START
        return ft.Row(controls, **kwargs)

    def _create_clickable_url(self, url: str, display_text: str | None = None) -> ft.TextButton:
        """Create a clickable URL link.

        Args:
            url: URL to open
            display_text: Optional display text (defaults to url)

        Returns:
            Clickable TextButton
        """
        return ft.TextButton(
            text=display_text or url,
            url=url,
            style=ft.ButtonStyle(
                color=ft.Colors.BLUE,
                padding=0,
            ),
        )

    def _create_clickable_ip(self, ip: str) -> ft.TextButton:
        """Create a clickable IP address link to IP info service.

        Args:
            ip: IP address

        Returns:
            Clickable TextButton linking to IP lookup service
        """
        return ft.TextButton(
            text=ip,
            url=f"https://ipinfo.io/{ip}",
            style=ft.ButtonStyle(
                color=ft.Colors.BLUE,
                padding=0,
            ),
            tooltip=f"Lookup {ip} on ipinfo.io",
        )

    def _create_clickable_whois(self, domain: str) -> ft.TextButton:
        """Create a clickable WHOIS lookup link.

        Args:
            domain: Domain name

        Returns:
            Clickable TextButton linking to WHOIS service
        """
        return ft.TextButton(
            text="View full WHOIS",
            url=f"https://www.whois.com/whois/{domain}",
            icon=ft.Icons.OPEN_IN_NEW,
            style=ft.ButtonStyle(
                color=ft.Colors.BLUE,
                padding=0,
            ),
            tooltip=f"Open WHOIS lookup for {domain}",
        )

    def _create_ssl_labs_link(self, domain: str) -> ft.TextButton:
        """Create a clickable SSL Labs link.

        Args:
            domain: Domain name

        Returns:
            Clickable TextButton linking to SSL Labs
        """
        return ft.TextButton(
            text="Check on SSL Labs",
            url=f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}",
            icon=ft.Icons.OPEN_IN_NEW,
            style=ft.ButtonStyle(
                color=ft.Colors.BLUE,
                padding=0,
            ),
            tooltip=f"Analyze {domain} on SSL Labs",
        )

    def _is_ip_address(self, value: str) -> bool:
        """Check if a string is an IP address (IPv4 or IPv6).

        Args:
            value: String to check

        Returns:
            True if value is an IP address
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _create_expandable_panel(
        self,
        title: str,
        icon: str,
        content: list[ft.Control],
        error_count: int = 0,
        warning_count: int = 0,
    ) -> ft.ExpansionTile:
        """Create an expandable panel with multi-line text selection support."""
        # Build title with error/warning counts
        title_parts = [title]
        if error_count > 0:
            title_parts.append(f"({error_count} error{'s' if error_count > 1 else ''})")
        if warning_count > 0:
            title_parts.append(f"({warning_count} warning{'s' if warning_count > 1 else ''})")

        full_title = " ".join(title_parts)

        # Color based on severity: errors > warnings > normal
        if error_count > 0:
            title_color = self.theme.error_color
        elif warning_count > 0:
            title_color = self.theme.warning_orange
        else:
            title_color = self.theme.text_primary

        # Wrap content in SelectionArea to allow selecting across multiple lines
        # This enables drag-to-select across all text/controls in the panel
        selectable_content = ft.SelectionArea(
            content=ft.Column(
                controls=content,
                spacing=self.theme.spacing_small,
                horizontal_alignment=ft.CrossAxisAlignment.START,
            )
        )

        # Wrap title + icon in Container with gray background (only header, not expanded content)
        title_widget = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(icon, color=title_color, size=self.theme.icon_medium),
                    ft.Text(
                        full_title,
                        size=self.theme.text_subheading,
                        weight="bold",
                        color=title_color,
                    ),
                ],
                spacing=self.theme.spacing_small,
            ),
            bgcolor=ft.Colors.GREY_200,
            padding=self.theme.padding_small,
            border_radius=self.theme.border_radius_small,
        )

        return ft.ExpansionTile(
            title=title_widget,
            controls=[selectable_content],  # Wrap in list since it's now a single SelectionArea
            initially_expanded=error_count > 0,  # Auto-expand if errors
            # ← KEY FIX: ExpansionTile defaults to CENTER, must set to START!
            expanded_cross_axis_alignment=ft.CrossAxisAlignment.START,
        )

    def _create_whois_panel(self, result: Any) -> ft.ExpansionTile:
        """Create WHOIS results panel."""
        content: list[ft.Control] = []

        # Handle None result (WHOIS disabled)
        if result is None:
            content.append(
                self._text(
                    "WHOIS check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel("WHOIS Information", ft.Icons.INFO, content, 0, 0)

        self._add_errors_and_warnings(content, result)

        if result.registrar:
            content.append(self._text(f"Registrar: {result.registrar}"))
        if result.creation_date:
            content.append(self._text(f"Created: {result.creation_date}"))
        if result.expiration_date:
            content.append(self._text(f"Expires: {result.expiration_date}"))
        if result.updated_date:
            content.append(self._text(f"Updated: {result.updated_date}"))

        # Owner/Registrant information
        if result.registrant_name or result.registrant_organization or result.registrant_email:
            owner_parts = []
            if result.registrant_organization:
                owner_parts.append(result.registrant_organization)
            if result.registrant_name:
                owner_parts.append(result.registrant_name)
            if result.registrant_email:
                owner_parts.append(result.registrant_email)
            content.append(self._text(f"Owner: {' / '.join(owner_parts)}"))

        # Admin contact information
        if result.admin_name or result.admin_email or result.admin_contact:
            admin_parts = []
            if result.admin_contact:
                admin_parts.append(f"[{result.admin_contact}]")
            if result.admin_name:
                admin_parts.append(result.admin_name)
            if result.admin_email:
                admin_parts.append(result.admin_email)
            content.append(self._text(f"Admin: {' / '.join(admin_parts)}"))

        # Add clickable WHOIS lookup link
        content.append(ft.Divider())
        content.append(self._create_clickable_whois(result.domain))

        return self._create_expandable_panel(
            "WHOIS Information", ft.Icons.INFO, content, len(result.errors), len(result.warnings)
        )

    def _create_dns_panel(self, result: Any) -> ft.ExpansionTile:
        """Create DNS results panel."""
        content: list[ft.Control] = []

        # Handle None result (DNS disabled)
        if result is None:
            content.append(
                self._text(
                    "DNS check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel("DNS Analysis", ft.Icons.DNS, content, 0, 0)

        self._add_errors_and_warnings(content, result)

        # DNS records
        for record_key, records in result.records.items():
            if records:
                record_type = record_key.split(":")[-1]
                content.append(
                    self._text(
                        f"{record_type} Records:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                for record in records:
                    # Make IPs clickable
                    if self._is_ip_address(record.value):
                        content.append(
                            self._row(
                                [
                                    self._text("  • ", size=self.theme.text_body),
                                    self._create_clickable_ip(record.value),
                                ],
                                spacing=0,
                            )
                        )
                    else:
                        content.append(
                            self._text(
                                f"  • {record.value}",
                                size=self.theme.text_body,
                            )
                        )

        return self._create_expandable_panel(
            "DNS Analysis", ft.Icons.DNS, content, len(result.errors), len(result.warnings)
        )

    def _create_http_panel(self, result: Any) -> ft.ExpansionTile:
        """Create HTTP results panel."""
        content: list[ft.Control] = []

        # Handle None result (HTTP disabled)
        if result is None:
            content.append(
                self._text(
                    "HTTP check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel("HTTP/HTTPS", ft.Icons.HTTP, content, 0, 0)

        self._add_errors_and_warnings(content, result)

        # Redirect chains - format: URL (CODE) → URL (CODE) → URL (CODE)
        for chain in result.chains:
            if not chain.responses:
                continue

            # Build chain components
            chain_parts = []
            last_response = chain.responses[-1]

            # Determine overall status color
            if last_response.status_code == 200:
                status_color = self.theme.success_color
            else:
                status_color = self.theme.warning_color

            # Build each part: URL (CODE)
            for resp in chain.responses:
                url_button = self._create_clickable_url(resp.url)
                code_text = self._text(
                    f" ({resp.status_code})",
                    size=self.theme.text_body,
                    color=status_color,
                )
                chain_parts.append(url_button)
                chain_parts.append(code_text)

                # Add arrow between responses (but not after last one)
                if resp != chain.responses[-1]:
                    arrow = self._text(" → ", size=self.theme.text_body)
                    chain_parts.append(arrow)

            # Create single row with all parts
            content.append(self._row(chain_parts, spacing=0))

        return self._create_expandable_panel(
            "HTTP/HTTPS Analysis", ft.Icons.HTTP, content, len(result.errors), len(result.warnings)
        )

    def _create_ssl_panel(self, result: Any) -> ft.ExpansionTile:
        """Create SSL results panel."""
        content: list[ft.Control] = []

        # Handle None result (SSL disabled)
        if result is None:
            content.append(
                self._text(
                    "SSL check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel("SSL/TLS", ft.Icons.LOCK, content, 0, 0)

        self._add_errors_and_warnings(content, result)

        if result.certificates:
            for hostname, cert in result.certificates.items():
                content.append(
                    self._text(
                        f"Certificate for {hostname}:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(
                    self._text(
                        f"  Issuer: {cert.issuer}",
                        size=self.theme.text_body,
                    )
                )
                content.append(
                    self._text(
                        f"  Subject: {cert.subject}",
                        size=self.theme.text_body,
                    )
                )
                content.append(
                    self._text(
                        f"  Valid from: {cert.not_before}",
                        size=self.theme.text_body,
                    )
                )
                content.append(
                    self._text(
                        f"  Valid until: {cert.not_after}",
                        size=self.theme.text_body,
                    )
                )

            # Add SSL Labs check link
            content.append(ft.Divider())
            content.append(self._create_ssl_labs_link(result.domain))

        return self._create_expandable_panel(
            "SSL/TLS Analysis", ft.Icons.SECURITY, content, len(result.errors), len(result.warnings)
        )

    def _create_email_panel(self, result: Any, advanced_result: Any = None) -> ft.ExpansionTile:
        """Create email security results panel."""
        content: list[ft.Control] = []

        # Handle None result (email check disabled)
        if result is None:
            content.append(
                self._text(
                    "Email security check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel("Email Security", ft.Icons.EMAIL, content, 0, 0)

        self._add_errors_and_warnings(content, result)

        # SPF
        if result.spf:
            content.append(
                self._text(
                    "SPF Record:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            content.append(
                self._text(
                    f"  {result.spf.record}",
                    size=self.theme.text_body,
                )
            )

        # DMARC
        if result.dmarc:
            content.append(
                self._text(
                    "DMARC Record:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            content.append(
                self._text(
                    f"  {result.dmarc.record}",
                    size=self.theme.text_body,
                )
            )

        # Advanced email (BIMI, MTA-STS, TLS-RPT)
        if advanced_result:
            if advanced_result.bimi:
                content.append(
                    self._text(
                        "BIMI Record:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(
                    self._text(
                        f"  {advanced_result.bimi.record_value}",
                        size=self.theme.text_body,
                    )
                )

            if advanced_result.mta_sts:
                content.append(
                    self._text(
                        "MTA-STS:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(
                    self._text(
                        f"  Mode: {advanced_result.mta_sts.policy_mode}",
                        size=self.theme.text_body,
                    )
                )

        # Count warnings from both basic and advanced email results
        warning_count = len(result.warnings)
        if advanced_result and hasattr(advanced_result, "warnings"):
            warning_count += len(advanced_result.warnings)

        return self._create_expandable_panel(
            "Email Security",
            ft.Icons.EMAIL,
            content,
            len(result.errors),
            warning_count,
        )

    def _create_headers_panel(self, results: Any) -> ft.ExpansionTile:
        """Create security headers results panel."""
        content: list[ft.Control] = []

        # Handle list input (core returns list of results)
        if isinstance(results, list):
            if not results:
                return self._create_expandable_panel("Security Headers", ft.Icons.SHIELD, [], 0, 0)
            result = results[0]  # Usually just one result
        else:
            result = results

        self._add_errors_and_warnings(content, result)

        # Headers (dict of SecurityHeaderCheck objects)
        for header_name, header_check in result.headers.items():
            content.append(
                self._text(
                    f"{header_name}:",
                    size=self.theme.text_label,
                    weight="bold",
                )
            )
            if header_check.present:
                content.append(
                    self._text(
                        "  ✓ Present",
                        size=self.theme.text_body,
                        color="green",
                    )
                )
            else:
                content.append(
                    self._text(
                        "  ✗ Missing",
                        size=self.theme.text_body,
                        color="red",
                    )
                )

        return self._create_expandable_panel(
            "Security Headers", ft.Icons.SHIELD, content, len(result.errors), len(result.warnings)
        )

    def _create_rbl_panel(self, result: Any) -> ft.ExpansionTile:
        """Create RBL results panel."""
        content: list[ft.Control] = []

        # Handle None result (RBL check disabled)
        if result is None:
            content.append(
                self._text(
                    "RBL check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel(
                "RBL Check", ft.Icons.SHIELD_OUTLINED, content, 0, 0
            )

        self._add_errors_and_warnings(content, result)

        # Blacklist status
        for check in result.checks:
            if check.listed:
                content.append(
                    self._row(
                        [
                            self._text(
                                "IP: ",
                                size=self.theme.text_label,
                                weight="bold",
                                color=self.theme.error_color,
                            ),
                            self._create_clickable_ip(check.ip),
                        ],
                        spacing=0,
                    )
                )
                for blacklist in check.blacklists:
                    content.append(
                        self._text(
                            f"  • Listed on: {blacklist}",
                            size=self.theme.text_body,
                        )
                    )

        if result.total_listed == 0:
            content.append(
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            ft.Text(
                                "No blacklist listings found",
                                color=self.theme.success_color,
                                text_align=ft.TextAlign.LEFT,
                            ),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        return self._create_expandable_panel(
            "RBL Check", ft.Icons.BLOCK, content, len(result.errors), len(result.warnings)
        )

    def _create_seo_panel(self, result: Any) -> ft.ExpansionTile:
        """Create SEO files results panel."""
        content: list[ft.Control] = []

        # Handle None result (SEO check disabled)
        if result is None:
            content.append(
                self._text(
                    "SEO files check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel("SEO Files", ft.Icons.SEARCH, content, 0, 0)

        self._add_errors_and_warnings(content, result)

        # SEO files status
        if result.robots and result.robots.exists:
            content.append(
                ft.Container(
                    content=self._row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            self._text("robots.txt found: ", color=self.theme.success_color),
                            self._create_clickable_url(result.robots.url, "View"),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        # Filter sitemaps to only show ones that exist
        existing_sitemaps = [s for s in result.sitemaps if s.exists]
        if existing_sitemaps:
            content.append(
                ft.Container(
                    content=ft.Column(
                        [
                            self._row(
                                [
                                    ft.Icon(
                                        ft.Icons.CHECK_CIRCLE,
                                        color=self.theme.success_color,
                                        size=self.theme.icon_small,
                                    ),
                                    self._text(
                                        f"{len(existing_sitemaps)} sitemap(s) found:",
                                        color=self.theme.success_color,
                                    ),
                                ],
                            ),
                            *[
                                self._row(
                                    [
                                        self._text("  • "),
                                        self._create_clickable_url(sitemap.url),
                                    ],
                                    spacing=0,
                                )
                                for sitemap in existing_sitemaps
                            ],
                        ],
                        spacing=self.theme.spacing_tiny,
                        horizontal_alignment=ft.CrossAxisAlignment.START,
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        if result.llms_txt and result.llms_txt.exists:
            content.append(
                ft.Container(
                    content=self._row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            self._text("llms.txt found: ", color=self.theme.success_color),
                            self._create_clickable_url(result.llms_txt.url, "View"),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        return self._create_expandable_panel(
            "SEO Files", ft.Icons.SEARCH, content, len(result.errors), len(result.warnings)
        )

    def _create_favicon_panel(self, result: Any) -> ft.ExpansionTile:
        """Create favicon detection results panel."""
        content: list[ft.Control] = []

        # Handle None result (favicon check disabled)
        if result is None:
            content.append(
                self._text(
                    "Favicon check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel("Favicon", ft.Icons.IMAGE, content, 0, 0)

        self._add_errors_and_warnings(content, result)

        # Favicon findings
        if result.favicons:
            content.append(
                self._text(
                    "Found favicons:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            for favicon in result.favicons:
                content.append(
                    self._row(
                        [
                            self._text("  • ", size=self.theme.text_body),
                            self._create_clickable_url(favicon.url),
                        ],
                        spacing=0,
                    )
                )
                if favicon.sizes:
                    content.append(
                        self._text(
                            f"    Sizes: {favicon.sizes}",
                            size=self.theme.text_small,
                            color=self.theme.text_secondary,
                        )
                    )

        return self._create_expandable_panel(
            "Favicon Detection", ft.Icons.IMAGE, content, len(result.errors), len(result.warnings)
        )

    def _create_site_verification_panel(self, result: Any) -> ft.ExpansionTile:
        """Create site verification results panel."""
        content: list[ft.Control] = []

        # Handle None result (site verification check disabled)
        if result is None:
            content.append(
                self._text(
                    "Site verification check disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel(
                "Site Verification", ft.Icons.VERIFIED, content, 0, 0
            )

        self._add_errors_and_warnings(content, result)

        # Verification findings
        for service_result in result.service_results:
            if service_result.detected_verification_ids:
                content.append(
                    self._text(
                        f"{service_result.service}:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                for verification in service_result.detected_verification_ids:
                    methods_str = (
                        ", ".join(verification.methods) if verification.methods else "unknown"
                    )
                    content.append(
                        self._text(
                            f"  • {verification.verification_id} ({methods_str})",
                            size=self.theme.text_body,
                        )
                    )

        return self._create_expandable_panel(
            "Site Verification",
            ft.Icons.VERIFIED,
            content,
            len(result.errors),
            len(result.warnings),
        )

    def _create_cdn_panel(self, result: Any) -> ft.ExpansionTile:
        """Create CDN detection results panel."""
        content: list[ft.Control] = []

        # Handle None result (CDN check disabled)
        if result is None:
            content.append(
                self._text(
                    "CDN detection disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel("CDN Detection", ft.Icons.CLOUD, content, 0, 0)

        self._add_errors_and_warnings(content, result)

        # CDN detection
        if result.cdn_detected and result.cdn_provider:
            content.append(
                self._text(
                    "CDN Detected:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            content.append(
                self._text(
                    f"  Provider: {result.cdn_provider}",
                    size=self.theme.text_body,
                )
            )
            if result.detection_method:
                content.append(
                    self._text(
                        f"  Detection method: {result.detection_method}",
                        size=self.theme.text_body,
                    )
                )
            if result.confidence:
                content.append(
                    self._text(
                        f"  Confidence: {result.confidence}",
                        size=self.theme.text_body,
                    )
                )
            if result.evidence:
                content.append(
                    self._text(
                        "  Evidence:",
                        size=self.theme.text_body,
                    )
                )
                for evidence in result.evidence:
                    content.append(
                        self._text(
                            f"    • {evidence}",
                            size=self.theme.text_body,
                        )
                    )
        else:
            content.append(
                self._text(
                    "No CDN detected",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )

        return self._create_expandable_panel(
            "CDN Detection", ft.Icons.CLOUD, content, len(result.errors), len(result.warnings)
        )

    def _create_default_auto_display_panel(self, metadata: Any, result: Any) -> ft.ExpansionTile:
        """
        Default auto-display panel for any analyzer result.

        This is called when an analyzer doesn't have a custom renderer.
        It automatically displays all fields from the result object
        using reflection.

        Args:
            metadata: AnalyzerMetadata with display configuration
            result: Any analyzer result object (with errors/warnings)

        Returns:
            Expansion panel with auto-generated content
        """
        content: list[ft.Control] = []

        # Handle None result (analyzer disabled)
        if result is None:
            content.append(
                self._text(
                    f"{metadata.title} disabled",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )
            return self._create_expandable_panel(metadata.title, metadata.icon, content, 0, 0)

        # Add errors and warnings
        self._add_errors_and_warnings(content, result)

        # Auto-display all other fields (skip domain, errors, warnings)
        skip_fields = {"domain", "errors", "warnings"}

        if hasattr(result, "__dict__"):
            displayed_any = False
            for field_name, value in result.__dict__.items():
                if field_name in skip_fields or value is None:
                    continue

                # Format field name nicely
                field_label = field_name.replace("_", " ").title()

                # Display based on type
                if isinstance(value, bool):
                    # Boolean: show as ✓/✗ with color
                    icon = ft.Icons.CHECK_CIRCLE if value else ft.Icons.CANCEL
                    color = self.theme.success_color if value else self.theme.error_color
                    content.append(
                        self._row(
                            [
                                ft.Icon(icon, color=color, size=self.theme.icon_small),
                                self._text(field_label, color=color),
                            ]
                        )
                    )
                    displayed_any = True
                elif isinstance(value, (str, int, float)):
                    # Simple types: just display
                    content.append(self._text(f"{field_label}: {value}"))
                    displayed_any = True
                elif isinstance(value, list):
                    # Lists: show count and items
                    if value:
                        content.append(
                            self._text(
                                f"{field_label}: ({len(value)} items)",
                                weight="bold",
                                size=self.theme.text_label,
                            )
                        )
                        for item in value[: self.theme.auto_display_max_items]:
                            content.append(self._text(f"  • {item}", size=self.theme.text_body))
                        if len(value) > self.theme.auto_display_max_items:
                            content.append(
                                self._text(
                                    f"  ... and {len(value) - self.theme.auto_display_max_items} more",
                                    size=self.theme.text_small,
                                    color=self.theme.text_secondary,
                                )
                            )
                        displayed_any = True
                elif isinstance(value, dict):
                    # Dicts: show count and keys
                    if value:
                        content.append(
                            self._text(
                                f"{field_label}: ({len(value)} items)",
                                weight="bold",
                                size=self.theme.text_label,
                            )
                        )
                        for key, val in list(value.items())[: self.theme.auto_display_max_items]:
                            content.append(self._text(f"  {key}: {val}", size=self.theme.text_body))
                        if len(value) > self.theme.auto_display_max_items:
                            content.append(
                                self._text(
                                    f"  ... and {len(value) - self.theme.auto_display_max_items} more",
                                    size=self.theme.text_small,
                                    color=self.theme.text_secondary,
                                )
                            )
                        displayed_any = True
                else:
                    # Complex objects: try str()
                    content.append(
                        self._text(f"{field_label}: {str(value)}", size=self.theme.text_small)
                    )
                    displayed_any = True

            if not displayed_any and not result.errors and not result.warnings:
                content.append(
                    self._text(
                        "No data available",
                        color=self.theme.text_secondary,
                        size=self.theme.text_small,
                    )
                )

        # Get icon from metadata
        icon = getattr(ft.Icons, metadata.icon, ft.Icons.INFO)

        # Count errors and warnings
        error_count = len(result.errors) if hasattr(result, "errors") else 0
        warning_count = len(result.warnings) if hasattr(result, "warnings") else 0

        return self._create_expandable_panel(
            metadata.title, icon, content, error_count, warning_count
        )

    # ========== PROFILE MANAGEMENT METHODS ==========

    def _load_profile_list(self) -> None:
        """Load and populate profile dropdown."""
        profiles = self.profile_manager.list_profiles()

        # Ensure default profile exists
        if "default" not in profiles:
            self.profile_manager.save_profile("default", self.config_adapter)
            profiles = self.profile_manager.list_profiles()

        # Populate dropdown
        self.profile_dropdown.options = [ft.dropdown.Option(p) for p in profiles]
        self.profile_dropdown.value = self.current_profile_name
        self.page.update()

    def _on_profile_changed(self, e: ft.ControlEvent) -> None:
        """Handle profile selection change."""
        new_profile_name = e.data
        if not new_profile_name:
            return

        try:
            # Load the selected profile
            self.config_adapter = self.profile_manager.load_profile(new_profile_name)
            self.current_profile_name = new_profile_name

            # Save as last selected profile for next session
            self.profile_manager.set_last_selected_profile(new_profile_name)

            # Update analyzer checkboxes from new config
            # (Currently checkboxes don't reflect config, they're independent)
            # Future enhancement: sync checkboxes with config.analysis.skip_* values

            logger.info(f"Switched to profile: {new_profile_name}")

            # Show confirmation
            snackbar = ft.SnackBar(
                content=ft.Text(f"Loaded profile: {new_profile_name}"),
                bgcolor=ft.Colors.GREEN,
            )
            self.page.overlay.append(snackbar)
            snackbar.open = True
            self.page.update()

        except Exception as e:
            logger.error(f"Failed to load profile {new_profile_name}: {e}")
            self.show_error(f"Failed to load profile: {e}")

    def _show_config_editor(self, e: ft.ControlEvent) -> None:
        """Show configuration editor dialog."""

        def on_save(new_config_adapter: GUIConfigAdapter) -> None:
            """Callback when config is saved in editor."""
            self.config_adapter = new_config_adapter
            # Also save to current profile
            self.profile_manager.save_profile(self.current_profile_name, new_config_adapter)
            logger.info(f"Updated configuration for profile: {self.current_profile_name}")

            # Show confirmation
            snackbar = ft.SnackBar(
                content=ft.Text(f"Configuration saved to profile: {self.current_profile_name}"),
                bgcolor=ft.Colors.GREEN,
            )
            self.page.overlay.append(snackbar)
            snackbar.open = True
            self.page.update()

        editor = ConfigEditorDialog(self.page, self.config_adapter, on_save)
        editor.show()

    def _show_save_profile_dialog(self, e: ft.ControlEvent) -> None:
        """Show dialog to save current config as new profile."""
        profile_name_field = ft.TextField(
            label="Profile Name",
            hint_text="e.g., fast, full, security",
            autofocus=True,
        )

        def save_new_profile(dialog_e: ft.ControlEvent) -> None:
            """Save config as new profile."""
            name = profile_name_field.value.strip()
            if not name:
                return

            try:
                self.profile_manager.save_profile(name, self.config_adapter)
                logger.info(f"Saved new profile: {name}")

                # Reload profile list and select new profile
                self._load_profile_list()
                self.profile_dropdown.value = name
                self.current_profile_name = name

                # Save as last selected profile for next session
                self.profile_manager.set_last_selected_profile(name)

                # Close dialog
                dialog.open = False

                # Show confirmation
                snackbar = ft.SnackBar(
                    content=ft.Text(f"Profile saved: {name}"),
                    bgcolor=ft.Colors.GREEN,
                )
                self.page.overlay.append(snackbar)
                snackbar.open = True
                self.page.update()

            except ValueError as e:
                logger.error(f"Invalid profile name {name}: {e}")
                # Show error in dialog
                error_text = ft.Text(str(e), color=ft.Colors.RED, size=12)
                if error_text not in dialog.content.controls:
                    dialog.content.controls.append(error_text)
                    self.page.update()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Save Profile"),
            content=ft.Column([profile_name_field], tight=True, width=300),
            actions=[
                ft.TextButton(
                    "Cancel",
                    on_click=lambda _: setattr(dialog, "open", False) or self.page.update(),
                ),
                ft.ElevatedButton("Save", on_click=save_new_profile),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()

    def _delete_current_profile(self, e: ft.ControlEvent) -> None:
        """Delete currently selected profile with confirmation."""
        if self.current_profile_name == "default":
            self.show_error("Cannot delete the default profile")
            return

        def confirm_delete(dialog_e: ft.ControlEvent) -> None:
            """Confirm and delete profile."""
            try:
                self.profile_manager.delete_profile(self.current_profile_name)
                logger.info(f"Deleted profile: {self.current_profile_name}")

                # Switch to default profile
                self.current_profile_name = "default"
                self.config_adapter = self.profile_manager.load_profile("default")

                # Save default as last selected profile for next session
                self.profile_manager.set_last_selected_profile("default")

                # Reload profile list
                self._load_profile_list()

                # Close dialog
                dialog.open = False

                # Show confirmation
                snackbar = ft.SnackBar(
                    content=ft.Text("Profile deleted"),
                    bgcolor=ft.Colors.ORANGE,
                )
                self.page.overlay.append(snackbar)
                snackbar.open = True
                self.page.update()

            except Exception as e:
                logger.error(f"Failed to delete profile: {e}")
                dialog.open = False
                self.page.update()
                self.show_error(f"Failed to delete profile: {e}")

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Delete Profile"),
            content=ft.Text(
                f"Are you sure you want to delete profile '{self.current_profile_name}'?"
            ),
            actions=[
                ft.TextButton(
                    "Cancel",
                    on_click=lambda _: setattr(dialog, "open", False) or self.page.update(),
                ),
                ft.ElevatedButton(
                    "Delete",
                    on_click=confirm_delete,
                    style=ft.ButtonStyle(bgcolor=ft.Colors.RED, color=ft.Colors.WHITE),
                ),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

        self.page.overlay.append(dialog)
        dialog.open = True
        self.page.update()

    def show_error(self, message: str) -> None:
        """Show error message."""
        error_banner = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.ERROR, color=self.theme.error_color),
                    ft.Text(message, color=self.theme.error_color, text_align=ft.TextAlign.LEFT),
                ],
            ),
            bgcolor=self.theme.error_bg,
            border=ft.border.all(1, self.theme.error_color),
            border_radius=self.theme.border_radius_large,
            padding=self.theme.padding_medium,
        )

        self.results_column.controls.clear()
        self.results_column.controls.append(error_banner)
        self.results_card.visible = True
        self.page.update()


def main() -> None:
    """Main entry point for Flet app."""
    # Parse CLI arguments
    args = parse_cli_args()

    def create_app(page: ft.Page) -> None:
        """Create and initialize the app."""
        DomainAnalyzerApp(
            page,
            initial_profile=args.config,
            initial_domain=args.domain,
        )

    ft.app(target=create_app)


if __name__ == "__main__":
    main()
