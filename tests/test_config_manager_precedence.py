"""Test ConfigManager's multi-layer configuration merging.

This module tests the v1.0.0 configuration system:
- Multi-layer config file precedence
- Per-analyzer config isolation
- Default config loading
- Config validation and error handling
"""

import tempfile
from pathlib import Path

import pytest
from pydantic import Field

from webmaster_domain_tool.analyzers.protocol import AnalyzerConfig
from webmaster_domain_tool.core.config_manager import ConfigManager

# ============================================================================
# Mock Analyzer and Config for Testing
# ============================================================================


class TestAnalyzerConfig(AnalyzerConfig):
    """Test analyzer configuration."""

    test_value: str = Field(default="default", description="Test value")
    test_number: int = Field(default=42, description="Test number")
    test_list: list[str] = Field(default_factory=list, description="Test list")


class TestAnalyzer:
    """Test analyzer."""

    analyzer_id = "test-analyzer"
    name = "Test Analyzer"
    description = "Test analyzer for config testing"
    category = "test"
    icon = "test"
    config_class = TestAnalyzerConfig
    depends_on = []

    def analyze(self, domain: str, config: TestAnalyzerConfig):
        return {"value": config.test_value, "number": config.test_number}

    def describe_output(self, result):
        from webmaster_domain_tool.analyzers.protocol import OutputDescriptor

        return OutputDescriptor(title="Test")

    def to_dict(self, result):
        return result


class AnotherAnalyzerConfig(AnalyzerConfig):
    """Another test analyzer configuration."""

    another_value: str = Field(default="another", description="Another value")


class AnotherAnalyzer:
    """Another test analyzer for isolation testing."""

    analyzer_id = "another-analyzer"
    name = "Another Analyzer"
    description = "Another test analyzer"
    category = "test"
    icon = "test"
    config_class = AnotherAnalyzerConfig
    depends_on = []

    def analyze(self, domain: str, config: AnotherAnalyzerConfig):
        return {"value": config.another_value}

    def describe_output(self, result):
        from webmaster_domain_tool.analyzers.protocol import OutputDescriptor

        return OutputDescriptor(title="Another")

    def to_dict(self, result):
        return result


# ============================================================================
# Test Cases
# ============================================================================


class TestConfigManagerPrecedence:
    """Test ConfigManager's multi-layer configuration merging."""

    def setup_method(self):
        """Set up test environment before each test."""
        # Register test analyzers with global registry
        from webmaster_domain_tool.core.registry import registry

        registry.register(TestAnalyzer)
        registry.register(AnotherAnalyzer)

    def test_default_config_loads(self):
        """Test that default config loads when no files exist."""
        # ConfigManager without any config files
        config_mgr = ConfigManager()
        config_mgr.load_from_files(extra_paths=[])

        # Should get default config for test analyzer
        config = config_mgr.get_analyzer_config("test-analyzer")
        assert config.test_value == "default"
        assert config.test_number == 42
        assert config.test_list == []

    def test_user_config_overrides_default(self):
        """Test that user config file overrides defaults."""
        # Create temp config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(
                """
[test-analyzer]
test_value = "user_override"
test_number = 100
test_list = ["user1", "user2"]
"""
            )
            config_file = Path(f.name)

        try:
            config_mgr = ConfigManager()
            config_mgr.load_from_files(extra_paths=[config_file])

            config = config_mgr.get_analyzer_config("test-analyzer")
            assert config.test_value == "user_override"
            assert config.test_number == 100
            assert config.test_list == ["user1", "user2"]
        finally:
            config_file.unlink()

    def test_local_config_highest_priority(self):
        """Test that local config has highest priority (overrides user config)."""
        # Create user config
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(
                """
[test-analyzer]
test_value = "user"
test_number = 100
"""
            )
            user_config = Path(f.name)

        # Create local config (higher priority)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(
                """
[test-analyzer]
test_value = "local"
"""
            )
            local_config = Path(f.name)

        try:
            config_mgr = ConfigManager()
            # Load in order: user first, then local (simulates precedence)
            config_mgr.load_from_files(extra_paths=[user_config, local_config])

            config = config_mgr.get_analyzer_config("test-analyzer")
            # Local should override user
            assert config.test_value == "local"
            # Number from user config should still be there
            assert config.test_number == 100
        finally:
            user_config.unlink()
            local_config.unlink()

    def test_per_analyzer_config_isolation(self):
        """Test that analyzer configs don't affect each other."""
        # Create config with both analyzers
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(
                """
[test-analyzer]
test_value = "test_config"

[another-analyzer]
another_value = "another_config"
"""
            )
            config_file = Path(f.name)

        try:
            config_mgr = ConfigManager()
            config_mgr.load_from_files(extra_paths=[config_file])

            # Test analyzer config
            test_config = config_mgr.get_analyzer_config("test-analyzer")
            assert test_config.test_value == "test_config"
            assert not hasattr(test_config, "another_value")

            # Another analyzer config
            another_config = config_mgr.get_analyzer_config("another-analyzer")
            assert another_config.another_value == "another_config"
            assert not hasattr(another_config, "test_value")
        finally:
            config_file.unlink()

    def test_invalid_config_section_ignored(self):
        """Test that invalid config sections are ignored gracefully."""
        # Create config with invalid section
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(
                """
[test-analyzer]
test_value = "valid"
invalid_field = "should be ignored"

[nonexistent-analyzer]
some_value = "ignored"
"""
            )
            config_file = Path(f.name)

        try:
            config_mgr = ConfigManager()
            config_mgr.load_from_files(extra_paths=[config_file])

            # Should load valid fields
            config = config_mgr.get_analyzer_config("test-analyzer")
            assert config.test_value == "valid"

            # Pydantic extra='allow' means invalid_field is ignored
            # but doesn't raise error

            # Nonexistent analyzer section should be ignored
            # No exception should be raised
        finally:
            config_file.unlink()


class TestConfigManagerCLIOverrides:
    """Test ConfigManager's CLI override functionality."""

    def setup_method(self):
        """Set up test environment before each test."""
        # Register test analyzer with global registry
        from webmaster_domain_tool.core.registry import registry

        registry.register(TestAnalyzer)

    def test_cli_overrides_config_file(self):
        """Test that CLI overrides take precedence over config files."""
        # Create config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(
                """
[test-analyzer]
test_value = "file"
test_number = 100
"""
            )
            config_file = Path(f.name)

        try:
            config_mgr = ConfigManager()
            config_mgr.load_from_files(extra_paths=[config_file])

            # Apply CLI overrides
            config_mgr.merge_cli_overrides("test-analyzer", {"test_value": "cli"})

            config = config_mgr.get_analyzer_config("test-analyzer")
            assert config.test_value == "cli"  # CLI override
            assert config.test_number == 100  # From file
        finally:
            config_file.unlink()

    def test_invalid_cli_override_handled(self):
        """Test that invalid CLI overrides are handled gracefully."""
        config_mgr = ConfigManager()
        config_mgr.load_from_files(extra_paths=[])

        # Try to override with invalid type
        # Pydantic should handle validation
        # This should not crash, but validation may fail silently or log error
        config_mgr.merge_cli_overrides("test-analyzer", {"test_number": "not_a_number"})

        # Config should still be accessible (may have default or error)
        config = config_mgr.get_analyzer_config("test-analyzer")
        assert config is not None


class TestConfigManagerGlobal:
    """Test ConfigManager's global configuration."""

    def test_global_config_loads(self):
        """Test that global config section loads correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(
                """
[global]
verbosity = "verbose"
color = false
parallel = true
"""
            )
            config_file = Path(f.name)

        try:
            config_mgr = ConfigManager()
            config_mgr.load_from_files(extra_paths=[config_file])

            assert config_mgr.global_config.verbosity == "verbose"
            assert config_mgr.global_config.color is False
            assert config_mgr.global_config.parallel is True
        finally:
            config_file.unlink()

    def test_global_config_defaults(self):
        """Test that global config has sensible defaults."""
        config_mgr = ConfigManager()
        config_mgr.load_from_files(extra_paths=[])

        assert config_mgr.global_config.verbosity == "normal"
        assert config_mgr.global_config.color is True
        assert config_mgr.global_config.parallel is False


class TestConfigManagerExport:
    """Test ConfigManager's export functionality."""

    def test_export_to_toml(self):
        """Test exporting config to TOML file."""
        pytest.importorskip("tomli_w", reason="tomli_w required for export")

        from webmaster_domain_tool.core.registry import registry

        registry.register(TestAnalyzer)

        config_mgr = ConfigManager()
        config_mgr.load_from_files(extra_paths=[])

        # Export to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            export_path = Path(f.name)

        try:
            config_mgr.export_to_toml(export_path)

            # Verify file was created and is valid TOML
            assert export_path.exists()
            content = export_path.read_text()
            assert "[global]" in content or "[test-analyzer]" in content
        finally:
            if export_path.exists():
                export_path.unlink()
