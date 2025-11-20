"""DNS analysis module for checking domain DNS records.

This analyzer performs comprehensive DNS analysis including record lookups,
DNSSEC validation, PTR checks, and MX validation. Follows the modular
analyzer protocol for self-contained configuration and output.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

import dns.dnssec
import dns.exception
import dns.name
import dns.resolver
import dns.reversename
from pydantic import Field

from ..constants import DEFAULT_DNS_TIMEOUT
from ..core.registry import registry
from .dns_utils import create_resolver
from .protocol import (
    AnalyzerConfig,
    OutputDescriptor,
    VerbosityLevel,
)

logger = logging.getLogger(__name__)


def _format_seconds_human(seconds: int) -> str:
    """Convert seconds to human-readable format (e.g., '1d 2h' or '30m')."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:  # Less than 1 hour
        minutes = seconds // 60
        return f"{minutes}m"
    elif seconds < 86400:  # Less than 1 day
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        if minutes > 0:
            return f"{hours}h {minutes}m"
        return f"{hours}h"
    else:  # Days
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        if hours > 0:
            return f"{days}d {hours}h"
        return f"{days}d"


# ============================================================================
# Configuration
# ============================================================================


class DNSConfig(AnalyzerConfig):
    """DNS analyzer configuration."""

    nameservers: list[str] | None = Field(
        default=None,
        description="Custom nameservers to use for queries (uses system default if not specified)",
    )
    check_dnssec: bool = Field(default=True, description="Check DNSSEC validation status")
    warn_www_not_cname: bool = Field(
        default=False,
        description="Warn if www subdomain uses A/AAAA instead of CNAME",
    )
    skip_www: bool = Field(
        default=False,
        description="Skip checking www subdomain (useful for subdomains)",
    )
    timeout: float = Field(default=DEFAULT_DNS_TIMEOUT, description="DNS query timeout in seconds")


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class DNSRecord:
    """Represents a DNS record."""

    record_type: str
    name: str
    value: str
    ttl: int | None = None


@dataclass
class DNSSECInfo:
    """DNSSEC validation information."""

    enabled: bool = False
    valid: bool = False
    has_dnskey: bool = False
    has_ds: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class DNSAnalysisResult:
    """Results from DNS analysis."""

    domain: str
    records: dict[str, list[DNSRecord]] = field(default_factory=dict)
    ptr_records: dict[str, str] = field(default_factory=dict)  # IP -> PTR mapping
    dnssec: DNSSECInfo | None = None
    info_messages: list[str] = field(default_factory=list)  # Informational messages (not warnings)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class DNSAnalyzer:
    """
    Analyzes DNS records for a domain.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (DNSConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Performs comprehensive DNS analysis including:
    - A, AAAA, MX, TXT, NS, SOA, CAA, CNAME records
    - DNSSEC validation (DNSKEY, DS records)
    - PTR (reverse DNS) lookups
    - MX record validation
    - www subdomain checks with best practice warnings
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "dns"
    name = "DNS Analysis"
    description = "Comprehensive DNS record analysis and DNSSEC validation"
    category = "general"
    icon = "globe"
    config_class = DNSConfig
    depends_on = []  # DNS has no dependencies

    # ========================================================================
    # DNS Record Types
    # ========================================================================

    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME"]

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: DNSConfig) -> DNSAnalysisResult:
        """
        Perform comprehensive DNS analysis of a domain.

        Args:
            domain: The domain to analyze
            config: DNS analyzer configuration

        Returns:
            DNSAnalysisResult with all DNS information
        """
        logger.info(f"Starting DNS analysis for {domain}")

        # Normalize domain (remove trailing dot if present)
        domain = domain.rstrip(".")

        result = DNSAnalysisResult(domain=domain)

        # Create DNS resolver using centralized utility
        resolver = create_resolver(nameservers=config.nameservers, timeout=config.timeout)

        # Check main domain
        self._check_domain_records(domain, result, resolver)

        # Check www subdomain if not already a subdomain and not skipping www
        if not config.skip_www and not domain.startswith("www."):
            www_domain = f"www.{domain}"
            self._check_domain_records(www_domain, result, resolver)

            # Check if www subdomain should be CNAME
            if config.warn_www_not_cname:
                self._check_www_cname(www_domain, result)

        # Validate MX records
        self._validate_mx_records(result, resolver)

        # Check PTR records for A records
        self._check_ptr_records(result, resolver)

        # Check DNSSEC
        if config.check_dnssec:
            result.dnssec = self._check_dnssec(domain, resolver)
            if result.dnssec:
                result.errors.extend(result.dnssec.errors)
                result.warnings.extend(result.dnssec.warnings)

        return result

    def describe_output(self, result: DNSAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render DNS analysis results.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: DNS analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        descriptor.quiet_summary = lambda r: (
            f"DNS: {len([k for k in r.records.keys() if not k.endswith(':CNAME_A')])} record types"
        )

        # Display DNS records grouped by domain and type
        domains_seen = set()
        for key in sorted(result.records.keys()):
            if key.endswith(":CNAME_A"):
                continue  # Skip CNAME_A records (shown with CNAME)

            domain_name, record_type = key.rsplit(":", 1)
            records_list = result.records[key]

            if not records_list:
                continue

            # Add domain heading if new domain
            if domain_name not in domains_seen:
                domains_seen.add(domain_name)
                descriptor.add_row(
                    value=f"DNS Records for {domain_name}",
                    section_type="heading",
                    style_class="info",
                    verbosity=VerbosityLevel.NORMAL,
                )

            # Format records for display
            if record_type == "CNAME":
                # Show CNAME and its resolved A records
                for record in records_list:
                    descriptor.add_row(
                        label=f"{record_type} ({_format_ttl(record.ttl)})",
                        value=record.value,
                        style_class="success",
                        icon="arrow",
                        verbosity=VerbosityLevel.NORMAL,
                    )

                    # Show resolved A records if available
                    cname_a_key = f"{domain_name}:CNAME_A"
                    if cname_a_key in result.records:
                        a_records = result.records[cname_a_key]
                        for a_rec in a_records:
                            descriptor.add_row(
                                label="  → A",
                                value=a_rec.value,
                                style_class="info",
                                verbosity=VerbosityLevel.NORMAL,
                            )
            else:
                # Standard record display
                for record in records_list:
                    descriptor.add_row(
                        label=f"{record_type} ({_format_ttl(record.ttl)})",
                        value=record.value,
                        style_class="success",
                        icon="check",
                        verbosity=VerbosityLevel.NORMAL,
                    )

        # DNSSEC Information
        if result.dnssec:
            descriptor.add_row(
                value="DNSSEC Status",
                section_type="heading",
                style_class="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            if result.dnssec.enabled:
                status = "Valid" if result.dnssec.valid else "Enabled (validation incomplete)"
                style = "success" if result.dnssec.valid else "warning"
                icon = "check" if result.dnssec.valid else "warning"

                descriptor.add_row(
                    label="DNSSEC",
                    value=status,
                    style_class=style,
                    icon=icon,
                    verbosity=VerbosityLevel.NORMAL,
                )

                # Show details in verbose mode
                descriptor.add_row(
                    label="DNSKEY",
                    value="Present" if result.dnssec.has_dnskey else "Missing",
                    style_class="success" if result.dnssec.has_dnskey else "muted",
                    verbosity=VerbosityLevel.VERBOSE,
                )

                descriptor.add_row(
                    label="DS Record",
                    value="Present" if result.dnssec.has_ds else "Missing",
                    style_class="success" if result.dnssec.has_ds else "muted",
                    verbosity=VerbosityLevel.VERBOSE,
                )
            else:
                descriptor.add_row(
                    label="DNSSEC",
                    value="Not enabled",
                    style_class="muted",
                    verbosity=VerbosityLevel.NORMAL,
                )

        # PTR Records (Reverse DNS)
        if result.ptr_records:
            descriptor.add_row(
                value="Reverse DNS (PTR Records)",
                section_type="heading",
                style_class="info",
                verbosity=VerbosityLevel.VERBOSE,
            )

            for ip, ptr in result.ptr_records.items():
                descriptor.add_row(
                    label=ip,
                    value=ptr,
                    style_class="success",
                    icon="check",
                    verbosity=VerbosityLevel.VERBOSE,
                )

        # Info Messages
        for info_msg in result.info_messages:
            descriptor.add_row(
                value=info_msg,
                section_type="text",
                style_class="info",
                severity="info",
                icon="info",
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

    def to_dict(self, result: DNSAnalysisResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: DNS analysis result

        Returns:
            JSON-serializable dict
        """
        # Convert DNSRecord objects to dicts
        records_dict = {}
        for key, records_list in result.records.items():
            records_dict[key] = [
                {
                    "type": rec.record_type,
                    "name": rec.name,
                    "value": rec.value,
                    "ttl": rec.ttl,
                }
                for rec in records_list
            ]

        # Convert DNSSEC info
        dnssec_dict = None
        if result.dnssec:
            dnssec_dict = {
                "enabled": result.dnssec.enabled,
                "valid": result.dnssec.valid,
                "has_dnskey": result.dnssec.has_dnskey,
                "has_ds": result.dnssec.has_ds,
                "errors": result.dnssec.errors,
                "warnings": result.dnssec.warnings,
            }

        return {
            "domain": result.domain,
            "records": records_dict,
            "ptr_records": result.ptr_records,
            "dnssec": dnssec_dict,
            "info_messages": result.info_messages,
            "errors": result.errors,
            "warnings": result.warnings,
        }

    # ========================================================================
    # Helper Methods (Internal DNS Logic)
    # ========================================================================

    def _check_domain_records(
        self, domain: str, result: DNSAnalysisResult, resolver: dns.resolver.Resolver
    ) -> None:
        """Check all DNS records for a domain."""
        for record_type in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, record_type)

                # Track seen values to avoid duplicates
                key = f"{domain}:{record_type}"
                if key not in result.records:
                    result.records[key] = []

                seen_values = {rec.value for rec in result.records[key]}

                for rdata in answers:
                    record = self._create_dns_record(
                        record_type=record_type,
                        name=domain,
                        rdata=rdata,
                        ttl=answers.ttl,
                    )
                    if record and record.value not in seen_values:
                        result.records[key].append(record)
                        seen_values.add(record.value)

                        # If CNAME, resolve the target A record
                        if record_type == "CNAME":
                            cname_target = str(rdata).rstrip(".")
                            try:
                                a_answers = resolver.resolve(cname_target, "A")
                                a_key = f"{domain}:CNAME_A"
                                if a_key not in result.records:
                                    result.records[a_key] = []

                                for a_rdata in a_answers:
                                    a_record = DNSRecord(
                                        record_type="A",
                                        name=cname_target,
                                        value=str(a_rdata),
                                        ttl=a_answers.ttl,
                                    )
                                    # Check for duplicates in CNAME_A records
                                    if not any(
                                        r.value == a_record.value for r in result.records[a_key]
                                    ):
                                        result.records[a_key].append(a_record)
                                logger.debug(f"Resolved CNAME {cname_target} to A records")
                            except Exception as e:
                                logger.debug(f"Could not resolve CNAME target {cname_target}: {e}")

                logger.debug(
                    f"Found {len(result.records[key])} unique {record_type} records for {domain}"
                )

            except dns.resolver.NXDOMAIN:
                logger.debug(f"Domain {domain} does not exist")
                result.errors.append(f"Domain {domain} does not exist (NXDOMAIN)")
                break  # No point checking other records
            except dns.resolver.NoAnswer:
                logger.debug(f"No {record_type} records found for {domain}")
            except dns.resolver.NoNameservers:
                logger.debug(f"No nameservers available for {domain}")
                result.errors.append(f"No nameservers available for {domain}")
                break
            except dns.exception.Timeout:
                logger.debug(f"DNS query timeout for {domain} {record_type}")
                result.warnings.append(f"DNS query timeout for {domain} {record_type}")
            except Exception as e:
                logger.debug(f"Error querying {record_type} for {domain}: {e}")
                result.errors.append(f"Error querying {record_type} for {domain}: {str(e)}")

        # DNS rule: if domain has CNAME, it cannot have A/AAAA records
        # Remove A/AAAA if CNAME exists (they might be returned by resolver following CNAME)
        cname_key = f"{domain}:CNAME"
        if cname_key in result.records and result.records[cname_key]:
            a_key = f"{domain}:A"
            aaaa_key = f"{domain}:AAAA"
            if a_key in result.records:
                logger.debug(f"Removing A records for {domain} (has CNAME)")
                del result.records[a_key]
            if aaaa_key in result.records:
                logger.debug(f"Removing AAAA records for {domain} (has CNAME)")
                del result.records[aaaa_key]

    def _check_www_cname(self, www_domain: str, result: DNSAnalysisResult) -> None:
        """
        Check if www subdomain is a CNAME record (best practice).

        Args:
            www_domain: The www subdomain to check (e.g., "www.example.com")
            result: DNS analysis result to update
        """
        cname_key = f"{www_domain}:CNAME"
        a_key = f"{www_domain}:A"
        aaaa_key = f"{www_domain}:AAAA"

        # Check if www has CNAME
        has_cname = cname_key in result.records and result.records[cname_key]
        has_a_or_aaaa = (a_key in result.records and result.records[a_key]) or (
            aaaa_key in result.records and result.records[aaaa_key]
        )

        # If www has A/AAAA but not CNAME, add warning
        if has_a_or_aaaa and not has_cname:
            warning = f"{www_domain} uses direct A/AAAA records instead of CNAME (consider using CNAME for easier management)"
            result.warnings.append(warning)
            logger.debug(f"www subdomain not using CNAME: {www_domain}")

    def _create_dns_record(
        self, record_type: str, name: str, rdata: Any, ttl: int | None
    ) -> DNSRecord | None:
        """Create a DNSRecord from DNS response data."""
        try:
            if record_type == "MX":
                value = f"{rdata.preference} {rdata.exchange}"
            elif record_type == "SOA":
                # Format: mname rname serial refresh retry expire minimum
                value = (
                    f"{rdata.mname} {rdata.rname} "
                    f"(serial: {rdata.serial}, "
                    f"refresh: {_format_seconds_human(rdata.refresh)}, "
                    f"retry: {_format_seconds_human(rdata.retry)}, "
                    f"expire: {_format_seconds_human(rdata.expire)}, "
                    f"minimum: {_format_seconds_human(rdata.minimum)})"
                )
            elif record_type == "CAA":
                value = f'{rdata.flags} {rdata.tag} "{rdata.value}"'
            else:
                value = str(rdata)

            return DNSRecord(record_type=record_type, name=name, value=value, ttl=ttl)
        except Exception as e:
            logger.debug(f"Error creating DNS record: {e}")
            return None

    def _validate_mx_records(
        self, result: DNSAnalysisResult, resolver: dns.resolver.Resolver
    ) -> None:
        """Validate MX records and check for common issues."""
        mx_keys = [k for k in result.records.keys() if k.endswith(":MX")]

        if not mx_keys:
            result.warnings.append(f"No MX records found for {result.domain}")
            return

        # Check if MX records point to valid hosts
        for mx_key in mx_keys:
            for mx_record in result.records[mx_key]:
                # Extract hostname from MX record (format: "priority hostname")
                parts = mx_record.value.split()
                if len(parts) >= 2:
                    mx_host = parts[1].rstrip(".")

                    # Check if MX host resolves
                    try:
                        resolver.resolve(mx_host, "A")
                        logger.debug(f"MX host {mx_host} resolves correctly")
                    except Exception as e:
                        result.warnings.append(f"MX host {mx_host} does not resolve: {str(e)}")

    def _check_ptr_records(
        self, result: DNSAnalysisResult, resolver: dns.resolver.Resolver
    ) -> None:
        """Check PTR (reverse DNS) records for all A records."""
        # Collect all A records (IPv4)
        a_record_keys = [k for k in result.records.keys() if k.endswith(":A")]

        for a_key in a_record_keys:
            for a_record in result.records[a_key]:
                ip_address = a_record.value

                try:
                    # Perform reverse DNS lookup
                    rev_name = dns.reversename.from_address(ip_address)
                    answers = resolver.resolve(rev_name, "PTR")

                    if answers:
                        # Get first PTR record
                        ptr_value = str(answers[0]).rstrip(".")
                        result.ptr_records[ip_address] = ptr_value
                        logger.debug(f"PTR record for {ip_address}: {ptr_value}")

                        # Validate PTR record points back to original domain
                        # Forward lookup PTR value to verify it resolves to the same IP
                        try:
                            forward_answers = resolver.resolve(ptr_value, "A")
                            forward_ips = [str(rdata) for rdata in forward_answers]

                            if ip_address not in forward_ips:
                                result.warnings.append(
                                    f"PTR record {ptr_value} for {ip_address} resolves to {', '.join(forward_ips)} (mismatch)"
                                )
                        except Exception:
                            result.info_messages.append(
                                f"PTR record {ptr_value} for {ip_address} does not resolve in forward lookup"
                            )
                except dns.resolver.NXDOMAIN:
                    logger.debug(f"No PTR record for {ip_address}")
                    result.info_messages.append(f"No PTR record found for {ip_address}")
                except dns.resolver.NoAnswer:
                    logger.debug(f"No PTR record for {ip_address}")
                except Exception as e:
                    logger.debug(f"Error checking PTR for {ip_address}: {e}")

    def _check_dnssec(self, domain: str, resolver: dns.resolver.Resolver) -> DNSSECInfo:
        """
        Check DNSSEC status for a domain.

        Args:
            domain: The domain to check
            resolver: DNS resolver to use

        Returns:
            DNSSECInfo with validation status
        """
        dnssec_info = DNSSECInfo()

        try:
            domain_name = dns.name.from_text(domain)

            # Check for DNSKEY records
            try:
                dnskey_answers = resolver.resolve(domain, "DNSKEY")
                if dnskey_answers:
                    dnssec_info.has_dnskey = True
                    dnssec_info.enabled = True
                    logger.debug(f"DNSKEY records found for {domain}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No DNSKEY records for {domain}")
            except Exception as e:
                logger.debug(f"Error checking DNSKEY for {domain}: {e}")

            # Check for DS records (in parent zone)
            # We need to query parent zone for DS records
            if len(domain_name.labels) > 2:  # Has parent zone
                try:
                    ds_answers = resolver.resolve(domain, "DS")
                    if ds_answers:
                        dnssec_info.has_ds = True
                        logger.debug(f"DS records found for {domain}")
                except dns.resolver.NoAnswer:
                    logger.debug(f"No DS records for {domain}")
                except Exception as e:
                    logger.debug(f"Error checking DS for {domain}: {e}")

            # If DNSSEC is enabled, try to validate
            if dnssec_info.enabled:
                # Note: Full DNSSEC validation requires recursive resolution
                # with signature validation, which is complex
                # We'll just check presence of records here
                if dnssec_info.has_dnskey and dnssec_info.has_ds:
                    dnssec_info.valid = True
                    logger.debug(f"DNSSEC appears to be properly configured for {domain}")
                elif dnssec_info.has_dnskey and not dnssec_info.has_ds:
                    dnssec_info.warnings.append(
                        "DNSKEY present but no DS record in parent zone "
                        "(DNSSEC chain of trust incomplete)"
                    )
                else:
                    dnssec_info.warnings.append("DNSSEC configuration may be incomplete")
            else:
                dnssec_info.warnings.append(
                    "DNSSEC not enabled for this domain (consider enabling for better security)"
                )

        except Exception as e:
            logger.debug(f"Error checking DNSSEC for {domain}: {e}")
            dnssec_info.errors.append(f"Error checking DNSSEC: {str(e)}")

        return dnssec_info


# ============================================================================
# Helper Functions
# ============================================================================


def _format_ttl(ttl: int | None) -> str:
    """Format TTL for display."""
    if ttl is None:
        return "TTL: N/A"
    return f"TTL: {_format_seconds_human(ttl)}"
