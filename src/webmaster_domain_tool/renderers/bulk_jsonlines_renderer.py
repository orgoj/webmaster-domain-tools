"""JSON Lines renderer for bulk domain analysis.

This renderer outputs one JSON object per domain (JSON Lines format),
suitable for streaming bulk analysis results.
"""

import json
import sys
from typing import Any

from ..analyzers.protocol import OutputDescriptor
from .base import BaseRenderer


class BulkJSONLinesRenderer(BaseRenderer):
    """
    Renders bulk domain analysis to JSON Lines format.

    Each domain is output as a single JSON line, allowing for
    streaming processing of large domain lists.

    JSON Lines format: http://jsonlines.org/
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.current_domain: str | None = None
        self.domain_results: dict[str, dict[str, Any]] = {}

    def set_current_domain(self, domain: str) -> None:
        """
        Set current domain being analyzed.

        Args:
            domain: Domain name
        """
        self.current_domain = domain
        self.domain_results = {}
        # Reset error/warning tracking for new domain
        self.all_errors = []
        self.all_warnings = []

    def render(self, descriptor: OutputDescriptor, result: Any, analyzer_id: str) -> None:
        """
        Collect results for current domain.

        Args:
            descriptor: Output descriptor
            result: Analyzer result
            analyzer_id: Analyzer ID
        """
        # Collect errors/warnings for summary
        self.collect_errors_warnings(descriptor, descriptor.title)

        # Build JSON structure (same as JSONRenderer)
        data = {
            "title": descriptor.title,
            "category": descriptor.category,
            "rows": [],
        }

        # Add all rows (preserve semantic styling)
        for row in descriptor.rows:
            row_data = {
                "label": row.label,
                "value": self._serialize_value(row.value),
                "style_class": row.style_class,
                "severity": row.severity,
                "section_type": row.section_type,
                "section_name": row.section_name,
                "verbosity": row.verbosity.value,
                "icon": row.icon,
            }

            # Add optional fields
            if row.link_url:
                row_data["link_url"] = row.link_url
            if row.link_text:
                row_data["link_text"] = row.link_text
            if row.badge_value:
                row_data["badge_value"] = row.badge_value

            data["rows"].append(row_data)

        # Add raw result data if available
        if hasattr(result, "__dict__"):
            data["raw"] = {k: self._serialize_value(v) for k, v in result.__dict__.items()}
        elif hasattr(result, "model_dump"):
            # Pydantic model
            data["raw"] = result.model_dump()

        self.domain_results[analyzer_id] = data

    def render_summary(self) -> None:
        """Output single JSON line for current domain."""
        total_errors = len(self.all_errors)
        total_warnings = len(self.all_warnings)

        output = {
            "domain": self.current_domain,
            "analyzers": self.domain_results,
            "summary": {
                "total_errors": total_errors,
                "total_warnings": total_warnings,
                "errors": [{"category": cat, "message": msg} for cat, msg in self.all_errors],
                "warnings": [{"category": cat, "message": msg} for cat, msg in self.all_warnings],
            },
        }

        # Single line JSON (no indentation for JSON Lines format)
        json.dump(output, sys.stdout, default=str)
        print()  # Newline to separate records

    @staticmethod
    def _serialize_value(value: Any) -> Any:
        """
        Serialize value to JSON-compatible format.

        Args:
            value: Value to serialize

        Returns:
            JSON-serializable value
        """
        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, (list, tuple)):
            return [BulkJSONLinesRenderer._serialize_value(v) for v in value]

        if isinstance(value, dict):
            return {k: BulkJSONLinesRenderer._serialize_value(v) for k, v in value.items()}

        if hasattr(value, "__dict__"):
            return {k: BulkJSONLinesRenderer._serialize_value(v) for k, v in value.__dict__.items()}

        if hasattr(value, "model_dump"):
            # Pydantic model
            return value.model_dump()

        # Fallback: convert to string
        return str(value)
