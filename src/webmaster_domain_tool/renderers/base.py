"""Base renderer protocol.

All renderers must implement this protocol. Renderers are completely decoupled
from analyzers - they only know about OutputDescriptor protocol.
"""

from abc import ABC, abstractmethod
from typing import Any

from ..analyzers.protocol import OutputDescriptor, VerbosityLevel


class BaseRenderer(ABC):
    """
    Base class for all output renderers.

    Renderers interpret OutputDescriptor semantic styles and render them
    according to their output format (CLI, GUI, JSON, HTML, etc.).
    """

    def __init__(self, verbosity: VerbosityLevel = VerbosityLevel.NORMAL):
        """
        Initialize renderer.

        Args:
            verbosity: Output verbosity level
        """
        self.verbosity = verbosity
        self.all_errors: list[tuple[str, str]] = []  # (category, message)
        self.all_warnings: list[tuple[str, str]] = []  # (category, message)

    @abstractmethod
    def render(self, descriptor: OutputDescriptor, result: Any, analyzer_id: str) -> None:
        """
        Render analyzer output.

        Args:
            descriptor: Output structure description
            result: Analyzer result (for accessing raw data if needed)
            analyzer_id: Analyzer ID (for categorizing errors/warnings)
        """
        ...

    @abstractmethod
    def render_summary(self) -> None:
        """Render summary of all analyses (errors, warnings, totals)."""
        ...

    def collect_errors_warnings(self, descriptor: OutputDescriptor, category: str) -> None:
        """
        Collect errors and warnings from descriptor for summary.

        Args:
            descriptor: Output descriptor
            category: Category name for grouping
        """
        for row in descriptor.rows:
            # Primary check: severity (canonical source of truth)
            if row.severity == "error":
                msg = str(row.value) if row.value else str(row.label)
                self.all_errors.append((category, msg))
            elif row.severity == "warning":
                msg = str(row.value) if row.value else str(row.label)
                self.all_warnings.append((category, msg))
