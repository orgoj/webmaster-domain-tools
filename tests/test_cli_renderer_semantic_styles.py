"""Test CLIRenderer's semantic style mapping.

This module tests the v1.0.0 semantic styling system:
- Semantic style class mapping to colors
- Icon mapping
- Verbosity filtering
- Error/warning collection
"""

from io import StringIO

from rich.console import Console

from webmaster_domain_tool.analyzers.protocol import OutputDescriptor, OutputRow, VerbosityLevel
from webmaster_domain_tool.renderers.cli_renderer import CLIRenderer

# ============================================================================
# Test Cases
# ============================================================================


class TestCLIRendererSemanticStyles:
    """Test CLIRenderer maps semantic styles to theme colors correctly."""

    def test_semantic_style_mapping(self):
        """Test that semantic style classes map to correct Rich colors."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL)

        # Check style map exists and has expected mappings
        assert renderer.STYLE_MAP["success"] == "green"
        assert renderer.STYLE_MAP["error"] == "red"
        assert renderer.STYLE_MAP["warning"] == "yellow"
        assert renderer.STYLE_MAP["info"] == "blue"
        assert renderer.STYLE_MAP["highlight"] == "bold"
        assert renderer.STYLE_MAP["muted"] == "dim"
        assert renderer.STYLE_MAP["neutral"] == ""

    def test_icon_mapping(self):
        """Test that semantic icon names map to Unicode characters."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL)

        # Check icon map
        assert renderer.ICON_MAP["check"] == "✓"
        assert renderer.ICON_MAP["cross"] == "✗"
        assert renderer.ICON_MAP["warning"] == "⚠"
        assert renderer.ICON_MAP["info"] == "ℹ"
        assert renderer.ICON_MAP["arrow"] == "→"
        assert renderer.ICON_MAP["globe"] == "🌐"
        assert renderer.ICON_MAP["lock"] == "🔒"
        assert renderer.ICON_MAP["shield"] == "🛡"

    def test_verbosity_filtering(self):
        """Test that rows are filtered by verbosity level."""
        # Create descriptor with rows at different verbosity levels
        descriptor = OutputDescriptor(title="Test", category="test")

        descriptor.add_row(
            label="Normal",
            value="Shown at normal",
            verbosity=VerbosityLevel.NORMAL,
        )

        descriptor.add_row(
            label="Verbose",
            value="Only shown at verbose",
            verbosity=VerbosityLevel.VERBOSE,
        )

        descriptor.add_row(
            label="Debug",
            value="Only shown at debug",
            verbosity=VerbosityLevel.DEBUG,
        )

        # Test filtering at NORMAL verbosity
        filtered = descriptor.filter_by_verbosity(VerbosityLevel.NORMAL)
        assert len(filtered) == 1
        assert filtered[0].label == "Normal"

        # Test filtering at VERBOSE verbosity
        filtered = descriptor.filter_by_verbosity(VerbosityLevel.VERBOSE)
        assert len(filtered) == 2
        labels = [row.label for row in filtered]
        assert "Normal" in labels
        assert "Verbose" in labels

        # Test filtering at DEBUG verbosity
        filtered = descriptor.filter_by_verbosity(VerbosityLevel.DEBUG)
        assert len(filtered) == 3

    def test_error_warning_collection(self):
        """Test that errors and warnings are collected from rows."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL)

        # Create descriptor with errors and warnings
        descriptor = OutputDescriptor(title="Test Category", category="test")

        descriptor.add_row(
            value="This is an error",
            section_type="text",
            severity="error",
            style_class="error",
        )

        descriptor.add_row(
            value="This is a warning",
            section_type="text",
            severity="warning",
            style_class="warning",
        )

        descriptor.add_row(
            value="This is normal info",
            section_type="text",
            severity="info",
            style_class="info",
        )

        # Collect errors/warnings
        renderer.collect_errors_warnings(descriptor, "Test Category")

        # Verify collection
        assert len(renderer.all_errors) == 1
        assert len(renderer.all_warnings) == 1

        # Check content
        error_category, error_msg = renderer.all_errors[0]
        assert error_category == "Test Category"
        assert "error" in error_msg.lower()

        warning_category, warning_msg = renderer.all_warnings[0]
        assert warning_category == "Test Category"
        assert "warning" in warning_msg.lower()


class TestCLIRendererOutput:
    """Test CLIRenderer's output rendering."""

    def test_render_key_value_with_semantic_style(self):
        """Test rendering key-value pair with semantic styling."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL, color=True)

        # Create mock result
        result = {"status": "success"}

        # Create descriptor with semantic styling
        descriptor = OutputDescriptor(title="Test Output", category="test")
        descriptor.add_row(
            label="Status",
            value="Success",
            style_class="success",
            icon="check",
            severity="info",
        )

        # Render to string buffer
        old_console = renderer.console
        string_io = StringIO()
        renderer.console = Console(file=string_io, force_terminal=True, width=120)

        renderer.render(descriptor, result, "test")

        output = string_io.getvalue()
        renderer.console = old_console

        # Verify output contains expected elements
        assert "Test Output" in output
        assert "Status" in output
        assert "Success" in output

    def test_render_list_section(self):
        """Test rendering list section."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL, color=True)

        result = {"items": ["item1", "item2", "item3"]}

        descriptor = OutputDescriptor(title="List Test", category="test")
        descriptor.add_row(
            label="Items",
            value=["item1", "item2", "item3"],
            section_type="list",
        )

        # Render
        string_io = StringIO()
        old_console = renderer.console
        renderer.console = Console(file=string_io, force_terminal=True, width=120)

        renderer.render(descriptor, result, "test")

        output = string_io.getvalue()
        renderer.console = old_console

        # Verify list items are present
        assert "item1" in output
        assert "item2" in output
        assert "item3" in output

    def test_render_text_with_icon(self):
        """Test rendering text section with icon."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL, color=True)

        result = {}

        descriptor = OutputDescriptor(title="Icon Test", category="test")
        descriptor.add_row(
            value="Success message",
            section_type="text",
            style_class="success",
            icon="check",
            severity="info",
        )

        # Render
        string_io = StringIO()
        old_console = renderer.console
        renderer.console = Console(file=string_io, force_terminal=True, width=120)

        renderer.render(descriptor, result, "test")

        output = string_io.getvalue()
        renderer.console = old_console

        # Verify message is present
        assert "Success message" in output

    def test_quiet_mode_uses_summary(self):
        """Test that quiet mode uses custom summary function."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.QUIET, color=True)

        result = {"status": "ok"}

        descriptor = OutputDescriptor(title="Quiet Test", category="test")
        descriptor.quiet_summary = lambda r: f"Summary: {r['status']}"
        descriptor.add_row(
            label="Verbose Detail",
            value="This should not appear in quiet mode",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Render
        string_io = StringIO()
        old_console = renderer.console
        renderer.console = Console(file=string_io, force_terminal=True, width=120)

        renderer.render(descriptor, result, "test")

        output = string_io.getvalue()
        renderer.console = old_console

        # Verify only summary appears
        assert "Summary: ok" in output
        assert "Verbose Detail" not in output


class TestCLIRendererSummary:
    """Test CLIRenderer's summary rendering."""

    def test_render_summary_no_issues(self):
        """Test summary when there are no errors or warnings."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL, color=True)

        # No errors or warnings added
        string_io = StringIO()
        old_console = renderer.console
        renderer.console = Console(file=string_io, force_terminal=True, width=120)

        renderer.render_summary()

        output = string_io.getvalue()
        renderer.console = old_console

        # Should show success message
        assert "No issues found" in output or "✓" in output

    def test_render_summary_with_errors(self):
        """Test summary when there are errors."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL, color=True)

        # Add error
        renderer.all_errors.append(("Test", "Test error message"))

        string_io = StringIO()
        old_console = renderer.console
        renderer.console = Console(file=string_io, force_terminal=True, width=120)

        renderer.render_summary()

        output = string_io.getvalue()
        renderer.console = old_console

        # Should show error count and message
        assert "error" in output.lower()
        assert "Test error message" in output

    def test_render_summary_with_warnings(self):
        """Test summary when there are warnings."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL, color=True)

        # Add warning
        renderer.all_warnings.append(("Test", "Test warning message"))

        string_io = StringIO()
        old_console = renderer.console
        renderer.console = Console(file=string_io, force_terminal=True, width=120)

        renderer.render_summary()

        output = string_io.getvalue()
        renderer.console = old_console

        # Should show warning count and message
        assert "warning" in output.lower()
        assert "Test warning message" in output


class TestCLIRendererValueFormatting:
    """Test CLIRenderer's value formatting."""

    def test_format_boolean_values(self):
        """Test that boolean values are formatted as Yes/No."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL)

        # Create row with boolean
        row = OutputRow(label="Enabled", value=True, section_type="key_value")
        formatted = renderer._format_value(row)
        assert formatted == "Yes"

        row = OutputRow(label="Disabled", value=False, section_type="key_value")
        formatted = renderer._format_value(row)
        assert formatted == "No"

    def test_format_list_values(self):
        """Test that list values are formatted as comma-separated."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL)

        row = OutputRow(
            label="Items",
            value=["item1", "item2", "item3"],
            section_type="key_value",
        )
        formatted = renderer._format_value(row)
        assert "item1" in formatted
        assert "item2" in formatted
        assert "," in formatted

    def test_format_none_value(self):
        """Test that None values are formatted as 'none'."""
        renderer = CLIRenderer(verbosity=VerbosityLevel.NORMAL)

        row = OutputRow(label="Empty", value=None, section_type="key_value")
        formatted = renderer._format_value(row)
        assert "none" in formatted.lower()
