"""RBL (Realtime Blacklist) checker for IP addresses."""

import logging
from dataclasses import dataclass, field

import dns.resolver
import dns.exception

from ..constants import DEFAULT_DNS_PUBLIC_SERVERS, DEFAULT_RBL_SERVERS, DEFAULT_RBL_TIMEOUT

logger = logging.getLogger(__name__)


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

    checks: list[RBLCheckResult] = field(default_factory=list)
    total_listed: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class RBLChecker:
    """Checks IP addresses against realtime blacklists."""

    def __init__(
        self,
        rbl_servers: list[str] | None = None,
        timeout: float = DEFAULT_RBL_TIMEOUT,
    ):
        """
        Initialize RBL checker.

        Args:
            rbl_servers: List of RBL servers to check
            timeout: DNS query timeout in seconds
        """
        self.rbl_servers = rbl_servers or DEFAULT_RBL_SERVERS

        # Create resolver
        try:
            self.resolver = dns.resolver.Resolver()
            if not self.resolver.nameservers:
                raise dns.resolver.NoResolverConfiguration("no nameservers")
        except (dns.resolver.NoResolverConfiguration, OSError):
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.nameservers = DEFAULT_DNS_PUBLIC_SERVERS

        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def check_ip(self, ip: str) -> RBLCheckResult:
        """
        Check a single IP address against all RBL servers.

        Args:
            ip: IP address to check

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
        for rbl_server in self.rbl_servers:
            rbl_query = f"{reversed_ip}.{rbl_server}"

            try:
                # If query succeeds, IP is listed
                answers = self.resolver.resolve(rbl_query, "A")
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
                logger.warning(f"Timeout checking {ip} on {rbl_server}")
                result.errors.append(f"Timeout checking {rbl_server}")
            except Exception as e:
                logger.warning(f"Error checking {ip} on {rbl_server}: {e}")
                result.errors.append(f"Error checking {rbl_server}: {str(e)}")

        return result

    def check_ips(self, ips: list[str]) -> RBLAnalysisResult:
        """
        Check multiple IP addresses against RBL servers.

        Args:
            ips: List of IP addresses to check

        Returns:
            RBLAnalysisResult with all check results
        """
        result = RBLAnalysisResult()

        for ip in ips:
            check_result = self.check_ip(ip)
            result.checks.append(check_result)

            if check_result.listed:
                result.total_listed += 1
                result.warnings.append(
                    f"IP {ip} is listed on {len(check_result.blacklists)} blacklist(s): "
                    f"{', '.join(check_result.blacklists)}"
                )

            result.errors.extend(check_result.errors)

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


def extract_ips_from_dns_result(dns_result: "DNSAnalysisResult") -> list[str]:
    """
    Extract IP addresses from DNS analysis result.

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
