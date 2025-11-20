"""Configuration management for modular analyzers.

This module handles loading and merging configuration from multiple TOML files
with proper precedence. Each analyzer gets its own isolated config section.
"""

import logging
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .registry import registry

logger = logging.getLogger(__name__)


class GlobalConfig(BaseModel):
    """Global configuration (not analyzer-specific)."""

    model_config = ConfigDict(extra="ignore")

    verbosity: str = Field(
        default="normal",
        description="Output verbosity: quiet, normal, verbose, debug",
    )
    color: bool = Field(default=True, description="Enable colored output")
    parallel: bool = Field(default=False, description="Run independent analyzers in parallel")


class ConfigManager:
    """
    Manages configuration loading for all analyzers.

    Loads from multiple sources with precedence (highest to lowest):
    1. CLI overrides (passed programmatically)
    2. Local config (./.webmaster-domain-tool.toml)
    3. Home config (~/.webmaster-domain-tool.toml)
    4. User config (~/.config/webmaster-domain-tool/config.toml)
    5. System config (/etc/webmaster-domain-tool/config.toml)
    6. Package defaults

    Example TOML structure:
        [global]
        verbosity = "normal"
        color = true

        [dns]
        timeout = 5.0
        check_dnssec = true
        nameservers = ["8.8.8.8", "1.1.1.1"]

        [ssl]
        min_tls_version = "1.2"
        check_certificate_transparency = true
    """

    def __init__(self, strict: bool = False):
        """
        Initialize ConfigManager.

        Args:
            strict: If True, raise exceptions on config validation errors.
                   If False (default), log warnings and use defaults.
        """
        self.strict = strict
        self.global_config = GlobalConfig()
        self.analyzer_configs: dict[str, Any] = {}

    def load_from_files(self, extra_paths: list[Path] | None = None) -> None:
        """
        Load configuration from TOML files.

        Args:
            extra_paths: Additional config file paths to load
        """
        paths = self._get_config_paths()
        if extra_paths:
            paths.extend(extra_paths)

        # Merged data from all files
        merged_data: dict[str, Any] = {}

        for path in paths:
            if not path.exists():
                logger.debug(f"Config file not found: {path}")
                continue

            try:
                with open(path, "rb") as f:
                    file_data = tomllib.load(f)
                    merged_data = self._merge_dicts(merged_data, file_data)
                    logger.info(f"Loaded config from {path}")
            except Exception as e:
                if self.strict:
                    raise RuntimeError(f"Failed to load config from {path}: {e}") from e
                logger.warning(f"Failed to load config from {path}: {e}")

        # Parse global config
        if "global" in merged_data:
            try:
                self.global_config = GlobalConfig(**merged_data["global"])
            except ValidationError as e:
                if self.strict:
                    raise
                logger.error(f"Invalid global config: {e}")

        # Parse analyzer configs
        for analyzer_id, metadata in registry.get_all().items():
            if analyzer_id in merged_data:
                try:
                    config = metadata.config_class(**merged_data[analyzer_id])
                    self.analyzer_configs[analyzer_id] = config
                    logger.debug(f"Loaded config for {analyzer_id}")
                except ValidationError as e:
                    if self.strict:
                        raise ValidationError(
                            f"Invalid config for analyzer '{analyzer_id}': {e}"
                        ) from e
                    logger.warning(f"Invalid config for {analyzer_id}: {e}")
                    # Use default config
                    self.analyzer_configs[analyzer_id] = metadata.config_class()
            else:
                # Use default config
                self.analyzer_configs[analyzer_id] = metadata.config_class()
                logger.debug(f"Using default config for {analyzer_id}")

    def get_analyzer_config(self, analyzer_id: str) -> Any:
        """
        Get configuration for a specific analyzer.

        Args:
            analyzer_id: Analyzer ID

        Returns:
            Analyzer configuration (Pydantic model instance)
        """
        if analyzer_id not in self.analyzer_configs:
            metadata = registry.get(analyzer_id)
            if metadata:
                self.analyzer_configs[analyzer_id] = metadata.config_class()
            else:
                raise ValueError(f"Unknown analyzer: {analyzer_id}")

        return self.analyzer_configs.get(analyzer_id)

    def merge_cli_overrides(self, analyzer_id: str, overrides: dict[str, Any]) -> None:
        """
        Merge CLI overrides into analyzer config.

        Args:
            analyzer_id: Analyzer ID
            overrides: Dictionary of config field overrides
        """
        if analyzer_id not in self.analyzer_configs:
            self.get_analyzer_config(analyzer_id)

        current = self.analyzer_configs[analyzer_id]

        # Create new instance with overrides
        current_dict = current.model_dump()
        current_dict.update(overrides)

        metadata = registry.get(analyzer_id)
        if metadata:
            try:
                self.analyzer_configs[analyzer_id] = metadata.config_class(**current_dict)
            except ValidationError as e:
                logger.error(f"Invalid CLI overrides for {analyzer_id}: {e}")

    def export_to_toml(self, path: Path) -> None:
        """
        Export current config to TOML file.

        Args:
            path: Output file path
        """
        data = {"global": self.global_config.model_dump(exclude_none=True)}

        for analyzer_id, config in self.analyzer_configs.items():
            data[analyzer_id] = config.model_dump(exclude_none=True)

        # Convert to TOML (requires tomli_w)
        try:
            import tomli_w

            with open(path, "wb") as f:
                tomli_w.dump(data, f)
            logger.info(f"Exported config to {path}")
        except ImportError:
            logger.error("tomli_w not installed, cannot export TOML")
            raise

    @staticmethod
    def _get_config_paths() -> list[Path]:
        """
        Get configuration file paths in precedence order (lowest to highest).

        Returns:
            List of config file paths
        """
        paths = []

        # 1. Package default (if exists)
        package_dir = Path(__file__).parent.parent
        default_config = package_dir / "default_config.toml"
        if default_config.exists():
            paths.append(default_config)

        # 2. System-wide
        system_config = Path("/etc/webmaster-domain-tool/config.toml")
        paths.append(system_config)

        # 3. User config
        user_config = Path.home() / ".config" / "webmaster-domain-tool" / "config.toml"
        paths.append(user_config)

        # 4. Home config (legacy)
        home_config = Path.home() / ".webmaster-domain-tool.toml"
        paths.append(home_config)

        # 5. Local config (highest precedence)
        local_config = Path.cwd() / ".webmaster-domain-tool.toml"
        paths.append(local_config)

        return paths

    @staticmethod
    def _merge_dicts(base: dict, override: dict) -> dict:
        """
        Recursively merge dictionaries.

        Args:
            base: Base dictionary
            override: Dictionary to merge in (takes precedence)

        Returns:
            Merged dictionary
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigManager._merge_dicts(result[key], value)
            else:
                result[key] = value
        return result

    def create_default_config_file(self, path: Path) -> None:
        """
        Create a default config file with all analyzers.

        Args:
            path: Output file path
        """
        # Use defaults for all analyzers
        for analyzer_id, metadata in registry.get_all().items():
            if analyzer_id not in self.analyzer_configs:
                self.analyzer_configs[analyzer_id] = metadata.config_class()

        self.export_to_toml(path)
        logger.info(f"Created default config file: {path}")
