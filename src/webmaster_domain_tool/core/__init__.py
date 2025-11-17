"""Core analysis functionality shared between CLI and GUI."""

from .analyzer import DomainAnalysisResults, run_domain_analysis

__all__ = ["DomainAnalysisResults", "run_domain_analysis"]
