"""Base classes for all analyzers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Generic, TypeVar


@dataclass
class BaseAnalysisResult:
    """
    Base class for all analysis results.

    All analyzer results must inherit from this class to ensure
    consistent error and warning tracking.
    """

    domain: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# Type variable for generic analyzer result types
TResult = TypeVar("TResult", bound=BaseAnalysisResult)


class BaseAnalyzer(ABC, Generic[TResult]):
    """
    Abstract base class for all domain analyzers.

    This class defines the interface that all analyzers must implement.
    It ensures consistency across all analyzer implementations and provides
    a foundation for future extensions.

    Type Parameters:
        TResult: The specific result type this analyzer returns,
                 must be a subclass of BaseAnalysisResult
    """

    @abstractmethod
    def analyze(self, domain: str) -> TResult:
        """
        Analyze the given domain.

        This is the main entry point for all analyzers. Implementations
        should perform their specific analysis and return a result object
        with errors and warnings populated as appropriate.

        Args:
            domain: Domain name to analyze (e.g., 'example.com')

        Returns:
            Analysis result with errors and warnings populated.
            The specific type depends on the analyzer implementation.

        Raises:
            Implementation-specific exceptions may be raised, but
            analyzers should generally catch exceptions and add them
            to the result's errors list instead.
        """
        pass
