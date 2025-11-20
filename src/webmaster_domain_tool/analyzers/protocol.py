"""Protocol definitions for modular analyzers.

This module defines the core protocols and data structures for the
analyzer plugin system. All analyzers must implement AnalyzerPlugin protocol.
"""

from abc import abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel


class VerbosityLevel(Enum):
    """Output verbosity levels."""

    QUIET = "quiet"
    NORMAL = "normal"
    VERBOSE = "verbose"
    DEBUG = "debug"

    def __ge__(self, other):
        """Allow >= comparison for verbosity filtering."""
        if not isinstance(other, VerbosityLevel):
            return NotImplemented
        levels = [
            VerbosityLevel.QUIET,
            VerbosityLevel.NORMAL,
            VerbosityLevel.VERBOSE,
            VerbosityLevel.DEBUG,
        ]
        return levels.index(self) >= levels.index(other)

    def __gt__(self, other):
        """Allow > comparison for verbosity filtering."""
        if not isinstance(other, VerbosityLevel):
            return NotImplemented
        levels = [
            VerbosityLevel.QUIET,
            VerbosityLevel.NORMAL,
            VerbosityLevel.VERBOSE,
            VerbosityLevel.DEBUG,
        ]
        return levels.index(self) > levels.index(other)


@dataclass
class OutputRow:
    """
    Renderer-agnostic output row.

    Describes WHAT to display, not HOW. Uses semantic styling that
    renderers interpret based on their theme.

    Example:
        OutputRow(
            label="SSL Certificate",
            value="Valid",
            style_class="success",  # Renderer decides: green, checkmark, etc.
            severity="info",
            icon="check"  # Semantic icon name
        )
    """

    # Content
    label: str | None = None
    value: Any = None

    # Semantic presentation hints (NOT specific colors/styles)
    style_class: str = "neutral"  # success, error, warning, info, highlight, muted, neutral
    severity: str = "info"  # critical, error, warning, info, debug

    # Structure
    section_type: str = "key_value"  # key_value, list, table, heading, text, badge, link
    section_name: str | None = None  # Group rows into sections
    subsection: str | None = None  # Nested grouping

    # Verbosity control
    verbosity: VerbosityLevel = VerbosityLevel.NORMAL

    # Behavior
    show_if_empty: bool = True
    collapse_list: bool = False  # For lists: show first N items
    max_items: int | None = None  # For lists: max items to show

    # Icons (semantic names, renderer maps to actual icons)
    icon: str | None = None  # check, cross, warning, info, arrow, globe, lock, etc.

    # Links (renderer decides if clickable)
    link_url: str | None = None
    link_text: str | None = None

    # Badges (semantic)
    badge_label: str | None = None
    badge_value: str | None = None
    badge_style: str = "neutral"  # success, error, warning, info

    # Special formatting
    format_as: str | None = None  # json, code, table, badge


@dataclass
class OutputDescriptor:
    """
    Describes how to render analyzer results at different verbosity levels.

    This is the core abstraction that decouples analyzers from renderers.
    Analyzers describe their output structure, renderers interpret it.
    """

    rows: list[OutputRow] = field(default_factory=list)

    # Section metadata
    title: str = ""
    category: str = "general"  # general, security, seo, advanced

    # Summary for quiet mode
    quiet_summary: Callable[[Any], str] | None = None

    def add_row(self, label: str | None = None, value: Any = None, **kwargs) -> "OutputDescriptor":
        """
        Builder pattern for adding rows.

        Args:
            label: Row label
            value: Row value
            **kwargs: Additional OutputRow parameters

        Returns:
            Self for chaining
        """
        self.rows.append(OutputRow(label=label, value=value, **kwargs))
        return self

    def filter_by_verbosity(self, verbosity: VerbosityLevel) -> list[OutputRow]:
        """
        Return only rows that should be shown at this verbosity level.

        Args:
            verbosity: Current verbosity level

        Returns:
            Filtered list of rows
        """
        return [row for row in self.rows if verbosity >= row.verbosity]


class AnalyzerConfig(BaseModel):
    """
    Base configuration for all analyzers.

    Each analyzer extends this with its own fields using Pydantic.

    Example:
        class DNSConfig(AnalyzerConfig):
            nameservers: list[str] = Field(default=["8.8.8.8"])
            check_dnssec: bool = Field(default=True)
    """

    enabled: bool = True
    timeout: float = 10.0

    class Config:
        extra = "allow"  # Allow analyzer-specific fields


TConfig = TypeVar("TConfig", bound=AnalyzerConfig)
TResult = TypeVar("TResult")


@runtime_checkable
class AnalyzerPlugin(Protocol[TConfig, TResult]):
    """
    Protocol that all analyzer plugins must implement.

    This protocol is checked at registration time to ensure analyzers
    follow the contract.

    Example:
        @registry.register
        class DNSAnalyzer:
            analyzer_id = "dns"
            name = "DNS Analysis"
            config_class = DNSConfig
            depends_on = []

            def analyze(self, domain: str, config: DNSConfig) -> DNSResult:
                ...

            def describe_output(self, result: DNSResult) -> OutputDescriptor:
                ...

            def to_dict(self, result: DNSResult) -> dict:
                ...
    """

    # Required class attributes (metadata)
    analyzer_id: str  # Unique ID: "dns", "whois", "ssl"
    name: str  # Display name: "DNS Analysis"
    description: str  # Short description
    category: str  # "general", "security", "seo", "advanced"
    icon: str  # Semantic icon name: "globe", "lock", "search"
    config_class: type[TConfig]  # Pydantic model
    depends_on: list[str]  # Dependencies: ["dns", "http"]

    @abstractmethod
    def analyze(self, domain: str, config: TConfig) -> TResult:
        """
        Perform analysis.

        Args:
            domain: Domain to analyze
            config: This analyzer's configuration

        Returns:
            Result object (must have errors/warnings lists)
        """
        ...

    @abstractmethod
    def describe_output(self, result: TResult) -> OutputDescriptor:
        """
        Describe how to render results (semantic, theme-agnostic).

        Args:
            result: Analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        ...

    @abstractmethod
    def to_dict(self, result: TResult) -> dict[str, Any]:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Analysis result

        Returns:
            JSON-serializable dict
        """
        ...
