"""Core components of the webmaster-domain-tool.

This package contains the core infrastructure for the modular analyzer system.
"""

from .config_manager import ConfigManager, GlobalConfig
from .registry import AnalyzerMetadata, AnalyzerRegistry, registry

__all__ = [
    "ConfigManager",
    "GlobalConfig",
    "registry",
    "AnalyzerMetadata",
    "AnalyzerRegistry",
]
