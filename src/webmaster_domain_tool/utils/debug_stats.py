"""Debug statistics tracking for DNS and HTTP requests.

This module provides a global statistics tracker that can be used across
all analyzers to track DNS queries and HTTP requests when debug mode is enabled.
"""

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import ClassVar

logger = logging.getLogger(__name__)


@dataclass
class DNSQueryStats:
    """Statistics for DNS queries."""

    # Count by record type (A, AAAA, MX, TXT, NS, SOA, CAA, CNAME, DNSKEY, DS, PTR)
    by_type: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Total DNS queries
    total: int = 0

    # Failed queries (timeouts, errors)
    failed: int = 0

    # Successful queries
    successful: int = 0


@dataclass
class HTTPRequestStats:
    """Statistics for HTTP requests."""

    # Total HTTP requests
    total: int = 0

    # By status code (200, 301, 302, 404, etc.)
    by_status_code: dict[int, int] = field(default_factory=lambda: defaultdict(int))

    # By protocol (http, https)
    by_protocol: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Failed requests (connection errors, timeouts)
    failed: int = 0

    # Successful requests (any response received)
    successful: int = 0


class DebugStatsTracker:
    """
    Global statistics tracker for debug mode.

    This is a thread-safe singleton that tracks DNS and HTTP request statistics
    across all analyzers during domain analysis.
    """

    _instance: ClassVar["DebugStatsTracker | None"] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self) -> None:
        """Initialize statistics."""
        self.dns = DNSQueryStats()
        self.http = HTTPRequestStats()
        self._enabled = False
        self._data_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "DebugStatsTracker":
        """Get singleton instance (thread-safe)."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def enable(self) -> None:
        """Enable statistics tracking."""
        self._enabled = True
        logger.debug("Debug statistics tracking enabled")

    def disable(self) -> None:
        """Disable statistics tracking."""
        self._enabled = False

    def is_enabled(self) -> bool:
        """Check if statistics tracking is enabled."""
        return self._enabled

    def reset(self) -> None:
        """Reset all statistics."""
        with self._data_lock:
            self.dns = DNSQueryStats()
            self.http = HTTPRequestStats()
        logger.debug("Debug statistics reset")

    # ========================================================================
    # DNS Statistics
    # ========================================================================

    def record_dns_query(
        self,
        domain: str,
        record_type: str,
        success: bool = True,
        error: str | None = None,
    ) -> None:
        """
        Record a DNS query.

        Args:
            domain: Domain queried
            record_type: Type of DNS record (A, AAAA, MX, TXT, etc.)
            success: Whether query succeeded
            error: Error message if failed
        """
        if not self._enabled:
            return

        with self._data_lock:
            self.dns.total += 1
            self.dns.by_type[record_type] += 1

            if success:
                self.dns.successful += 1
                logger.debug(f"→ DNS {record_type}: {domain}")
            else:
                self.dns.failed += 1
                error_msg = f" ({error})" if error else ""
                logger.debug(f"✗ DNS {record_type}: {domain}{error_msg}")

    # ========================================================================
    # HTTP Statistics
    # ========================================================================

    def record_http_request(
        self,
        url: str,
        status_code: int | None = None,
        success: bool = True,
        error: str | None = None,
        response_time: float | None = None,
    ) -> None:
        """
        Record an HTTP request.

        Args:
            url: URL requested
            status_code: HTTP status code (None if request failed)
            success: Whether request succeeded
            error: Error message if failed
            response_time: Response time in seconds
        """
        if not self._enabled:
            return

        with self._data_lock:
            self.http.total += 1

            # Track protocol (http vs https)
            protocol = "https" if url.startswith("https://") else "http"
            self.http.by_protocol[protocol] += 1

            if success and status_code:
                self.http.successful += 1
                self.http.by_status_code[status_code] += 1

                time_str = f" ({response_time:.2f}s)" if response_time is not None else ""
                logger.debug(f"→ HTTP {status_code}: {url}{time_str}")
            else:
                self.http.failed += 1
                error_msg = f" ({error})" if error else ""
                logger.debug(f"✗ HTTP request failed: {url}{error_msg}")

    # ========================================================================
    # Statistics Retrieval
    # ========================================================================

    def get_summary(self) -> str:
        """
        Get formatted summary of statistics.

        Returns:
            Formatted string with statistics
        """
        if not self._enabled:
            return "Debug statistics tracking disabled"

        with self._data_lock:
            lines = []
            lines.append("\n" + "=" * 70)
            lines.append("DEBUG STATISTICS SUMMARY")
            lines.append("=" * 70)

            # DNS Statistics
            if self.dns.total > 0:
                lines.append("\nDNS Queries:")
                lines.append(f"  Total:      {self.dns.total}")
                lines.append(f"  Successful: {self.dns.successful}")
                lines.append(f"  Failed:     {self.dns.failed}")

                if self.dns.by_type:
                    lines.append("\n  By record type:")
                    for record_type in sorted(self.dns.by_type.keys()):
                        count = self.dns.by_type[record_type]
                        lines.append(f"    {record_type:8s}: {count:3d}")
            else:
                lines.append("\nDNS Queries: None")

            # HTTP Statistics
            if self.http.total > 0:
                lines.append("\nHTTP Requests:")
                lines.append(f"  Total:      {self.http.total}")
                lines.append(f"  Successful: {self.http.successful}")
                lines.append(f"  Failed:     {self.http.failed}")

                if self.http.by_protocol:
                    lines.append("\n  By protocol:")
                    for protocol in sorted(self.http.by_protocol.keys()):
                        count = self.http.by_protocol[protocol]
                        lines.append(f"    {protocol:5s}: {count:3d}")

                if self.http.by_status_code:
                    lines.append("\n  By status code:")
                    for status_code in sorted(self.http.by_status_code.keys()):
                        count = self.http.by_status_code[status_code]
                        lines.append(f"    {status_code}: {count:3d}")
            else:
                lines.append("\nHTTP Requests: None")

            lines.append("=" * 70)
            return "\n".join(lines)


# Global instance accessor
def get_stats_tracker() -> DebugStatsTracker:
    """Get the global statistics tracker instance."""
    return DebugStatsTracker.get_instance()
