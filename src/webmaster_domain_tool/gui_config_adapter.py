"""GUI configuration adapter for working with ConfigManager.

This module provides a bridge between the GUI's profile-based configuration
system and the new modular ConfigManager architecture.
"""

import logging
from typing import Any

from .core.config_manager import ConfigManager, GlobalConfig
from .core.registry import registry

logger = logging.getLogger(__name__)


class GUIConfigAdapter:
    """
    Adapter for GUI to work with ConfigManager.

    Provides a unified dict-based interface for GUI profile storage
    while internally using the modular ConfigManager system.

    Example:
        # Create from defaults
        adapter = GUIConfigAdapter()

        # Export to dict for profile storage
        profile_data = adapter.to_dict()

        # Load from dict (profile loading)
        adapter.from_dict(profile_data)

        # Get ConfigManager for analysis
        config_manager = adapter.config_manager
    """

    def __init__(self):
        """Initialize adapter with default configuration."""
        self.config_manager = ConfigManager()
        # Initialize all analyzer configs with defaults
        for analyzer_id, metadata in registry.get_all().items():
            if analyzer_id not in self.config_manager.analyzer_configs:
                self.config_manager.analyzer_configs[analyzer_id] = metadata.config_class()

    def to_dict(self) -> dict[str, Any]:
        """
        Export all configs to a single dict for GUI editing/storage.

        Returns:
            Dictionary with global config and all analyzer configs
        """
        result = {"global": self.config_manager.global_config.model_dump()}

        for analyzer_id, config in self.config_manager.analyzer_configs.items():
            result[analyzer_id] = config.model_dump()

        return result

    def from_dict(self, data: dict[str, Any]):
        """
        Load configs from dict (for profile loading).

        Args:
            data: Dictionary with global config and analyzer configs
        """
        # Load global config
        if "global" in data:
            try:
                self.config_manager.global_config = GlobalConfig(**data["global"])
            except Exception as e:
                logger.warning(f"Failed to load global config: {e}")
                self.config_manager.global_config = GlobalConfig()

        # Load analyzer configs
        for analyzer_id, metadata in registry.get_all().items():
            if analyzer_id in data:
                try:
                    config = metadata.config_class(**data[analyzer_id])
                    self.config_manager.analyzer_configs[analyzer_id] = config
                except Exception as e:
                    logger.warning(f"Failed to load config for {analyzer_id}: {e}")
                    # Use default
                    self.config_manager.analyzer_configs[analyzer_id] = metadata.config_class()
            else:
                # Use default if not in data
                self.config_manager.analyzer_configs[analyzer_id] = metadata.config_class()

    def get_analyzer_config(self, analyzer_id: str) -> Any:
        """
        Get configuration for a specific analyzer.

        Args:
            analyzer_id: Analyzer ID

        Returns:
            Analyzer configuration
        """
        return self.config_manager.get_analyzer_config(analyzer_id)

    def set_analyzer_config(self, analyzer_id: str, config: Any):
        """
        Set configuration for a specific analyzer.

        Args:
            analyzer_id: Analyzer ID
            config: Analyzer configuration
        """
        self.config_manager.analyzer_configs[analyzer_id] = config

    @classmethod
    def from_config_manager(cls, config_manager: ConfigManager) -> "GUIConfigAdapter":
        """
        Create adapter from existing ConfigManager.

        Args:
            config_manager: ConfigManager instance

        Returns:
            GUIConfigAdapter wrapping the ConfigManager
        """
        adapter = cls()
        adapter.config_manager = config_manager
        return adapter
