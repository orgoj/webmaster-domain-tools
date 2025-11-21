"""CLI renderer using Rich library.

This renderer interprets semantic styles from OutputDescriptor and renders
them to terminal using the Rich library with appropriate colors and formatting.
"""

import json as json_module
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from ..analyzers.protocol import OutputDescriptor, OutputRow, VerbosityLevel
from .base import BaseRenderer


class CLIRenderer(BaseRenderer):
    """
    Renders output to CLI using Rich library.

    Maps semantic style classes to Rich markup:
    - success -> green
    - error -> red
    - warning -> yellow
    - info -> blue
    - highlight -> bold
    - muted -> dim
    - neutral -> default
    """

    # Semantic style class -> Rich markup color
    STYLE_MAP = {
        "success": "green",
        "error": "red",
        "warning": "yellow",
        "info": "blue",
        "highlight": "bold",
        "muted": "dim",
        "neutral": "",
    }

    # Semantic icon name -> Unicode character
    ICON_MAP = {
        "check": "✓",
        "cross": "✗",
        "warning": "⚠",
        "info": "ℹ",
        "arrow": "→",
        "globe": "🌐",
        "lock": "🔒",
        "search": "🔍",
        "shield": "🛡",
        "cloud": "☁",
        "envelope": "✉",
        "star": "★",
        "bullet": "•",
    }

    def __init__(self, verbosity: VerbosityLevel = VerbosityLevel.NORMAL, color: bool = True):
        """
        Initialize CLI renderer.

        Args:
            verbosity: Output verbosity level
            color: Enable colored output
        """
        super().__init__(verbosity)
        self.console = Console(color_system="auto" if color else None)

    def render(self, descriptor: OutputDescriptor, result: Any, analyzer_id: str) -> None:
        """
        Render analyzer output to CLI.

        Args:
            descriptor: Output structure description
            result: Analyzer result
            analyzer_id: Analyzer ID
        """
        # Collect errors/warnings for summary
        self.collect_errors_warnings(descriptor, descriptor.title)

        # Quiet mode: use custom summary function
        if self.verbosity == VerbosityLevel.QUIET:
            if descriptor.quiet_summary:
                summary = descriptor.quiet_summary(result)
                self.console.print(summary)
            return

        # Normal/Verbose/Debug: render all rows
        self.console.print(f"\n[bold blue]{descriptor.title}[/bold blue]")
        self.console.print()

        # Filter rows by verbosity
        rows = descriptor.filter_by_verbosity(self.verbosity)

        if not rows:
            self.console.print("  [dim]No data to display[/dim]")
            return

        # Group by section
        sections: dict[str, list] = {}
        for row in rows:
            section_key = row.section_name or "_default"
            if section_key not in sections:
                sections[section_key] = []
            sections[section_key].append(row)

        # Render each section
        for section_name, section_rows in sections.items():
            if section_name != "_default":
                self.console.print()  # Blank line BEFORE section name (separator)
                self.console.print(f"  [cyan]{section_name}[/cyan]")

            for row in section_rows:
                self._render_row(row)

    def _render_row(self, row: OutputRow) -> None:
        """
        Render a single output row.

        Args:
            row: OutputRow to render
        """
        indent = "  "

        # Section type handling
        if row.section_type == "heading":
            style = self.STYLE_MAP.get(row.style_class, "")
            text = row.value or row.label
            self.console.print(f"{indent}[{style} bold]{text}[/{style} bold]")
            self.console.print()
            return

        if row.section_type == "text":
            # Simple text output (e.g., errors, warnings, info)
            msg = str(row.value) if row.value else str(row.label)
            style = self.STYLE_MAP.get(row.style_class, "")
            icon = self.ICON_MAP.get(row.icon, "")
            icon_str = f"{icon} " if icon else ""

            if style:
                self.console.print(f"{indent}[{style}]{icon_str}{msg}[/{style}]")
            else:
                self.console.print(f"{indent}{icon_str}{msg}")
            return

        if row.section_type == "link":
            label = row.label or "Link"
            url = row.link_url or row.value
            text = row.link_text or url
            self.console.print(f"{indent}{label}: [link={url}]{text}[/link]")
            return

        if row.section_type == "badge":
            label = row.label or ""
            value = row.badge_value or row.value
            style = self.STYLE_MAP.get(row.badge_style, "")
            self.console.print(f"{indent}{label}: [{style}]{value}[/{style}]")
            return

        if row.section_type == "list":
            # List rendering
            if row.label:
                style = self.STYLE_MAP.get(row.style_class, "")
                if style:
                    self.console.print(f"{indent}[{style}]{row.label}:[/{style}]")
                else:
                    self.console.print(f"{indent}{row.label}:")

            items = row.value if isinstance(row.value, list) else [row.value]
            max_items = row.max_items or len(items)

            for i, item in enumerate(items[:max_items]):
                icon = self.ICON_MAP.get("bullet", "•")
                self.console.print(f"{indent}  {icon} {item}")

            if row.collapse_list and len(items) > max_items:
                remaining = len(items) - max_items
                self.console.print(f"{indent}  [dim]... and {remaining} more[/dim]")
            return

        if row.section_type == "table":
            # Table rendering
            if not isinstance(row.value, list) or not row.value:
                return

            table = Table(box=box.ROUNDED, show_header=True, header_style="bold")

            # Add columns from first row
            first_row = row.value[0]
            if isinstance(first_row, dict):
                for key in first_row.keys():
                    table.add_column(str(key).replace("_", " ").title())

                # Add data rows
                for data_row in row.value:
                    table.add_row(*[str(v) for v in data_row.values()])

                self.console.print(table)
            return

        if row.section_type == "key_value":
            # Key-value pair rendering
            if not row.show_if_empty and not row.value:
                return

            # Format value
            formatted_value = self._format_value(row)

            # Apply semantic style
            style = self.STYLE_MAP.get(row.style_class, "")
            if style:
                formatted_value = f"[{style}]{formatted_value}[/{style}]"

            # Apply icon
            icon = self.ICON_MAP.get(row.icon, "")
            icon_str = f"{icon} " if icon else ""

            # Render
            if row.label:
                self.console.print(f"{indent}{row.label}: {icon_str}{formatted_value}")
            else:
                self.console.print(f"{indent}{icon_str}{formatted_value}")

    def _format_value(self, row: OutputRow) -> str:
        """
        Format row value for display.

        Args:
            row: OutputRow

        Returns:
            Formatted string
        """
        if row.value is None:
            return "[dim]none[/dim]"

        if isinstance(row.value, bool):
            return "Yes" if row.value else "No"

        if isinstance(row.value, (list, tuple)):
            if row.collapse_list and len(row.value) > 3:
                visible = row.value[:3]
                return f"{', '.join(str(v) for v in visible)} ... (+{len(row.value) - 3})"
            return ", ".join(str(v) for v in row.value)

        if isinstance(row.value, dict) and row.format_as == "json":
            return json_module.dumps(row.value, indent=2)

        return str(row.value)

    def render_summary(self) -> None:
        """Render summary of all analyses."""
        if self.verbosity == VerbosityLevel.QUIET:
            return

        self.console.print()
        self.console.print("[bold blue]═══ Summary ═══[/bold blue]")
        self.console.print()

        total_errors = len(self.all_errors)
        total_warnings = len(self.all_warnings)

        if total_errors == 0 and total_warnings == 0:
            self.console.print("[green]✓ No issues found![/green]")
        else:
            if total_errors > 0:
                self.console.print(f"[red]✗ {total_errors} error(s) found:[/red]")
                for category, error in self.all_errors:
                    self.console.print(f"  [red]• [{category}] {error}[/red]")
                self.console.print()

            if total_warnings > 0:
                self.console.print(f"[yellow]⚠ {total_warnings} warning(s) found:[/yellow]")
                for category, warning in self.all_warnings:
                    self.console.print(f"  [yellow]• [{category}] {warning}[/yellow]")

        self.console.print()
