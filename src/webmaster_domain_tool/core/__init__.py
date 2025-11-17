"""Core analysis functionality shared between CLI and GUI."""

from .analyzer import (
    ANALYZER_REGISTRY,
    AnalyzerMetadata,
    DomainAnalysisResults,
    run_domain_analysis,
)

__all__ = [
    "ANALYZER_REGISTRY",
    "AnalyzerMetadata",
    "DomainAnalysisResults",
    "run_domain_analysis",
]
