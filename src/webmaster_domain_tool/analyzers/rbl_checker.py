"""RBL (Realtime Blacklist) checker - identify blacklisted IPs.

This analyzer checks IP addresses against multiple RBL servers to detect
if they are listed on any spam/malware blacklists. Completely self-contained
with config, logic, and output formatting.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import dns.exception
import dns.resolver
from pydantic import Field

from ..constants import DEFAULT_RBL_SERVERS, DEFAULT_RBL_TIMEOUT
from ..core.registry import registry
from .dns_utils import create_resolver
from .protocol import (
    AnalyzerConfig,
    OutputDescriptor,
    VerbosityLevel,
)

if TYPE_CHECKING:
    from .dns_analyzer import DNSAnalysisResult

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class RBLConfig(AnalyzerConfig):
    """RBL checker configuration."""

    rbl_servers: list[str] = Field(
        default_factory=lambda: DEFAULT_RBL_SERVERS.copy(),
        description="List of RBL servers to check against",
    )
    timeout: float = Field(
        default=DEFAULT_RBL_TIMEOUT,
        description="DNS query timeout in seconds",
    )


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class RBLCheckResult:
    """Result of RBL check for an IP address."""

    ip: str
    listed: bool = False
    blacklists: list[str] = field(default_factory=list)
    not_listed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class RBLAnalysisResult:
    """Results from RBL analysis."""

    domain: str
    checks: list[RBLCheckResult] = field(default_factory=list)
    total_listed: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class RBLChecker:
    """
    Checks IP addresses against realtime blacklists.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (RBLConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "rbl"
    name = "RBL Blacklist Check"
    description = "Check IP addresses against spam/malware blacklists"
    category = "security"
    icon = "shield"
    config_class = RBLConfig
    depends_on = ["dns"]  # Needs DNS lookups and IP addresses from DNS

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: RBLConfig) -> RBLAnalysisResult:
        """
        Perform RBL analysis.

        Note: This method receives IP addresses from DNS analyzer via
        the execution context. For now, it returns placeholder data.
        Full integration happens in CLI orchestration.

        Args:
            domain: Domain to analyze
            config: RBL checker configuration

        Returns:
            RBLAnalysisResult with blacklist check results
        """
        result = RBLAnalysisResult(domain=domain)

        # TODO: Get IP addresses from DNS analysis context
        # For now, return placeholder
        result.warnings.append("RBL checking requires DNS analysis first")

        return result

    def check_ips(self, domain: str, ips: list[str], config: RBLConfig) -> RBLAnalysisResult:
        """
        Check multiple IP addresses against RBL servers.

        This is the main entry point used by the orchestrator after
        DNS analysis provides IP addresses.

        Args:
            domain: Domain name (for result tracking)
            ips: List of IP addresses to check
            config: RBL checker configuration

        Returns:
            RBLAnalysisResult with all check results
        """
        result = RBLAnalysisResult(domain=domain)

        # Create resolver with configured timeout
        resolver = create_resolver(timeout=config.timeout)

        for ip in ips:
            check_result = self._check_ip(ip, config.rbl_servers, resolver)
            result.checks.append(check_result)

            if check_result.listed:
                result.total_listed += 1
                result.warnings.append(
                    f"IP {ip} is listed on {len(check_result.blacklists)} blacklist(s): "
                    f"{', '.join(check_result.blacklists)}"
                )

            result.errors.extend(check_result.errors)

        return result

    def describe_output(self, result: RBLAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: RBL analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        descriptor.quiet_summary = lambda r: (
            f"RBL: {r.total_listed} blacklisted" if r.total_listed > 0 else "RBL: Clean"
        )

        # Overall status
        if result.total_listed > 0:
            descriptor.add_row(
                label="Blacklist Status",
                value=f"{result.total_listed} IP(s) blacklisted",
                style_class="error",
                severity="error",
                icon="cross",
                verbosity=VerbosityLevel.NORMAL,
            )
        else:
            descriptor.add_row(
                label="Blacklist Status",
                value="Clean (not blacklisted)",
                style_class="success",
                severity="info",
                icon="check",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Show each IP check result (verbose mode)
        for check in result.checks:
            if check.listed:
                # Listed IPs - show in normal mode
                descriptor.add_row(
                    label=f"IP {check.ip}",
                    value=f"Listed on {len(check.blacklists)} RBL(s)",
                    style_class="error",
                    severity="error",
                    icon="warning",
                    verbosity=VerbosityLevel.NORMAL,
                )

                # Show which blacklists (verbose)
                descriptor.add_row(
                    label="  Blacklists",
                    value=check.blacklists,
                    section_type="list",
                    style_class="error",
                    verbosity=VerbosityLevel.VERBOSE,
                )
            else:
                # Clean IPs - only show in verbose mode
                descriptor.add_row(
                    label=f"IP {check.ip}",
                    value="Clean (not listed)",
                    style_class="success",
                    severity="info",
                    icon="check",
                    verbosity=VerbosityLevel.VERBOSE,
                )

            # Show RBL query errors (verbose)
            for error in check.errors:
                descriptor.add_row(
                    label=f"  {check.ip}",
                    value=error,
                    section_type="text",
                    style_class="warning",
                    severity="warning",
                    verbosity=VerbosityLevel.VERBOSE,
                )

        # Errors
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Warnings
        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                severity="warning",
                icon="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        return descriptor

    def to_dict(self, result: RBLAnalysisResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: RBL analysis result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "total_listed": result.total_listed,
            "checks": [
                {
                    "ip": check.ip,
                    "listed": check.listed,
                    "blacklists": check.blacklists,
                    "not_listed": check.not_listed,
                    "errors": check.errors,
                }
                for check in result.checks
            ],
            "errors": result.errors,
            "warnings": result.warnings,
        }

    # ========================================================================
    # RBL Checking Logic
    # ========================================================================

    def _check_ip(
        self, ip: str, rbl_servers: list[str], resolver: dns.resolver.Resolver
    ) -> RBLCheckResult:
        """
        Check a single IP address against all RBL servers.

        Args:
            ip: IP address to check
            rbl_servers: List of RBL servers
            resolver: DNS resolver to use

        Returns:
            RBLCheckResult with blacklist status
        """
        result = RBLCheckResult(ip=ip)

        # Reverse IP for RBL lookup
        reversed_ip = self._reverse_ip(ip)
        if not reversed_ip:
            result.errors.append(f"Invalid IP address: {ip}")
            return result

        # Check against each RBL server
        for rbl_server in rbl_servers:
            rbl_query = f"{reversed_ip}.{rbl_server}"

            try:
                # If query succeeds, IP is listed
                answers = resolver.resolve(rbl_query, "A")
                if answers:
                    result.listed = True
                    result.blacklists.append(rbl_server)
                    logger.debug(f"IP {ip} is listed on {rbl_server}")
            except dns.resolver.NXDOMAIN:
                # Not listed (expected for clean IPs)
                result.not_listed.append(rbl_server)
                logger.debug(f"IP {ip} is not listed on {rbl_server}")
            except dns.resolver.NoAnswer:
                # Not listed
                result.not_listed.append(rbl_server)
                logger.debug(f"IP {ip} is not listed on {rbl_server}")
            except dns.exception.Timeout:
                logger.debug(f"Timeout checking {ip} on {rbl_server}")
                result.errors.append(f"Timeout checking {rbl_server}")
            except Exception as e:
                logger.debug(f"Error checking {ip} on {rbl_server}: {e}")
                result.errors.append(f"Error checking {rbl_server}: {str(e)}")

        return result

    def _reverse_ip(self, ip: str) -> str | None:
        """
        Reverse IP address for RBL lookup.

        Args:
            ip: IP address (e.g., "1.2.3.4")

        Returns:
            Reversed IP (e.g., "4.3.2.1") or None if invalid
        """
        try:
            # Handle IPv4
            parts = ip.split(".")
            if len(parts) == 4:
                # Validate each part is a number 0-255
                for part in parts:
                    num = int(part)
                    if num < 0 or num > 255:
                        return None
                return ".".join(reversed(parts))

            # TODO: Handle IPv6 if needed
            return None
        except (ValueError, AttributeError):
            return None


# ============================================================================
# Helper Functions
# ============================================================================


def extract_ips_from_dns_result(dns_result: "DNSAnalysisResult") -> list[str]:
    """
    Extract IP addresses from DNS analysis result.

    This helper function is used by the orchestrator to get IPs
    from DNS results to pass to RBL checker.

    Args:
        dns_result: DNS analysis result

    Returns:
        List of unique IP addresses
    """
    ips = set()

    # Get A records
    for key, records in dns_result.records.items():
        if key.endswith(":A"):
            for record in records:
                ips.add(record.value)

    # Get IPs from MX records
    # First get MX hostnames, then resolve them
    mx_hosts = set()
    for key, records in dns_result.records.items():
        if key.endswith(":MX"):
            for record in records:
                parts = record.value.split()
                if len(parts) >= 2:
                    mx_host = parts[1].rstrip(".")
                    mx_hosts.add(mx_host)

    # Resolve MX hosts to IPs
    for mx_host in mx_hosts:
        for key, records in dns_result.records.items():
            if key.startswith(f"{mx_host}:A"):
                for record in records:
                    ips.add(record.value)

    return list(ips)
