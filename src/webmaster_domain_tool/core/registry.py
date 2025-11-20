"""Analyzer registry with auto-discovery and dependency resolution.

This module provides the central registry for all analyzer plugins.
Analyzers register themselves using the @registry.register decorator.
"""

import logging
from dataclasses import dataclass

from ..analyzers.protocol import AnalyzerConfig, AnalyzerPlugin

logger = logging.getLogger(__name__)


@dataclass
class AnalyzerMetadata:
    """Metadata about a registered analyzer."""

    analyzer_id: str
    name: str
    description: str
    category: str
    icon: str
    config_class: type[AnalyzerConfig]
    plugin_class: type[AnalyzerPlugin]
    depends_on: list[str]


class AnalyzerRegistry:
    """
    Central registry for all analyzer plugins.

    Provides:
    - Auto-discovery via @registry.register decorator
    - Dependency resolution (topological sort)
    - Plugin metadata storage

    Example:
        @registry.register
        class DNSAnalyzer:
            analyzer_id = "dns"
            name = "DNS Analysis"
            ...

        # Later:
        metadata = registry.get("dns")
        instance = metadata.plugin_class()
    """

    def __init__(self):
        self._plugins: dict[str, AnalyzerMetadata] = {}

    def register(self, plugin_class: type[AnalyzerPlugin]) -> type[AnalyzerPlugin]:
        """
        Register an analyzer plugin.

        Can be used as decorator or called directly.

        Args:
            plugin_class: Analyzer class to register

        Returns:
            Plugin class (for decorator usage)

        Raises:
            ValueError: If plugin is missing required attributes
            TypeError: If plugin doesn't implement AnalyzerPlugin protocol

        Example:
            @registry.register
            class DNSAnalyzer:
                analyzer_id = "dns"
                name = "DNS Analysis"
                ...
        """
        # Validate required attributes
        required_attrs = [
            "analyzer_id",
            "name",
            "description",
            "category",
            "icon",
            "config_class",
        ]
        for attr in required_attrs:
            if not hasattr(plugin_class, attr):
                raise ValueError(
                    f"Analyzer {plugin_class.__name__} missing required attribute: {attr}"
                )

        analyzer_id = plugin_class.analyzer_id

        # Check for duplicates
        if analyzer_id in self._plugins:
            logger.warning(f"Analyzer '{analyzer_id}' already registered, overwriting")

        # Create metadata
        metadata = AnalyzerMetadata(
            analyzer_id=analyzer_id,
            name=plugin_class.name,
            description=plugin_class.description,
            category=plugin_class.category,
            icon=plugin_class.icon,
            config_class=plugin_class.config_class,
            plugin_class=plugin_class,
            depends_on=getattr(plugin_class, "depends_on", []),
        )

        self._plugins[analyzer_id] = metadata
        logger.debug(f"Registered analyzer: {analyzer_id}")

        return plugin_class

    def get(self, analyzer_id: str) -> AnalyzerMetadata | None:
        """
        Get analyzer metadata by ID.

        Args:
            analyzer_id: Analyzer ID

        Returns:
            Metadata if found, None otherwise
        """
        return self._plugins.get(analyzer_id)

    def get_all(self) -> dict[str, AnalyzerMetadata]:
        """
        Get all registered analyzers.

        Returns:
            Dictionary of analyzer_id -> metadata
        """
        return self._plugins.copy()

    def get_all_ids(self) -> list[str]:
        """
        Get all registered analyzer IDs.

        Returns:
            List of analyzer IDs
        """
        return list(self._plugins.keys())

    def resolve_dependencies(self, requested: list[str], skip: set[str] | None = None) -> list[str]:
        """
        Resolve analyzer dependencies and return execution order.

        Uses topological sort to ensure dependencies run before dependents.

        Args:
            requested: List of requested analyzer IDs
            skip: Set of analyzer IDs to skip

        Returns:
            Ordered list of analyzer IDs (dependencies first)

        Raises:
            ValueError: If unknown analyzer or circular dependency detected

        Example:
            # SSL depends on HTTP, HTTP depends on DNS
            registry.resolve_dependencies(["ssl"])
            # Returns: ["dns", "http", "ssl"]
        """
        skip = skip or set()
        resolved: list[str] = []
        visited: set[str] = set()
        visiting: set[str] = set()  # For cycle detection

        def visit(analyzer_id: str):
            """Visit node in dependency graph."""
            if analyzer_id in skip:
                return

            if analyzer_id in visiting:
                raise ValueError(f"Circular dependency detected: {analyzer_id} is part of a cycle")

            if analyzer_id in visited:
                return

            metadata = self._plugins.get(analyzer_id)
            if not metadata:
                raise ValueError(f"Unknown analyzer: {analyzer_id}")

            visiting.add(analyzer_id)

            # Visit dependencies first
            for dep in metadata.depends_on:
                visit(dep)

            visiting.remove(analyzer_id)
            visited.add(analyzer_id)
            resolved.append(analyzer_id)

        # Visit all requested analyzers
        for analyzer_id in requested:
            visit(analyzer_id)

        return resolved

    def validate_skip_list(self, skip_list: list[str]) -> tuple[bool, list[str]]:
        """
        Validate that all skip entries are known analyzers.

        Args:
            skip_list: List of analyzer IDs to validate

        Returns:
            Tuple of (all_valid, unknown_analyzers)
        """
        unknown = [aid for aid in skip_list if aid not in self._plugins]
        return len(unknown) == 0, unknown


# Global registry instance
registry = AnalyzerRegistry()
