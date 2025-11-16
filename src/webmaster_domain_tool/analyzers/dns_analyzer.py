"""DNS analysis module for checking domain DNS records."""

import logging
from dataclasses import dataclass, field
from typing import Any

import dns.dnssec
import dns.exception
import dns.name
import dns.resolver
import dns.reversename

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
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class DNSAnalyzer:
    """Analyzes DNS records for a domain."""

    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME"]

    def __init__(
        self,
        nameservers: list[str] | None = None,
        check_dnssec: bool = True,
        warn_www_not_cname: bool = False,
    ):
        """
        Initialize DNS analyzer.

        Args:
            nameservers: Optional list of nameservers to use for queries
            check_dnssec: Whether to check DNSSEC validation
            warn_www_not_cname: Warn if www subdomain is not a CNAME record
        """
        self.check_dnssec = check_dnssec
        self.warn_www_not_cname = warn_www_not_cname

        # Try to create resolver with system config, fallback to manual config
        try:
            self.resolver = dns.resolver.Resolver()
            # Check if we have nameservers
            if not self.resolver.nameservers:
                raise dns.resolver.NoResolverConfiguration("no nameservers")
        except (dns.resolver.NoResolverConfiguration, OSError):
            # System DNS not available, create unconfigured resolver
            self.resolver = dns.resolver.Resolver(configure=False)
            logger.debug("System DNS not available, using public DNS servers")

        # Override with provided nameservers or use public DNS
        if nameservers:
            self.resolver.nameservers = nameservers
        elif not self.resolver.nameservers:
            # Use public DNS servers as fallback
            self.resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
            logger.debug("Using fallback public DNS servers: 8.8.8.8, 8.8.4.4, 1.1.1.1")

    def analyze(self, domain: str) -> DNSAnalysisResult:
        """
        Perform comprehensive DNS analysis of a domain.

        Args:
            domain: The domain to analyze

        Returns:
            DNSAnalysisResult with all DNS information
        """
        logger.info(f"Starting DNS analysis for {domain}")

        # Normalize domain (remove trailing dot if present)
        domain = domain.rstrip(".")

        result = DNSAnalysisResult(domain=domain)

        # Check main domain
        self._check_domain_records(domain, result)

        # Check www subdomain if not already a subdomain
        if not domain.startswith("www."):
            www_domain = f"www.{domain}"
            self._check_domain_records(www_domain, result)

            # Check if www subdomain should be CNAME
            if self.warn_www_not_cname:
                self._check_www_cname(www_domain, result)

        # Validate MX records
        self._validate_mx_records(result)

        # Check PTR records for A records
        self._check_ptr_records(result)

        # Check DNSSEC
        if self.check_dnssec:
            result.dnssec = self._check_dnssec(domain)
            if result.dnssec:
                result.errors.extend(result.dnssec.errors)
                result.warnings.extend(result.dnssec.warnings)

        return result

    def _check_domain_records(self, domain: str, result: DNSAnalysisResult) -> None:
        """Check all DNS records for a domain."""
        for record_type in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(domain, record_type)

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
                                a_answers = self.resolver.resolve(cname_target, "A")
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
                logger.warning(f"No nameservers available for {domain}")
                result.errors.append(f"No nameservers available for {domain}")
                break
            except dns.exception.Timeout:
                logger.warning(f"DNS query timeout for {domain} {record_type}")
                result.warnings.append(f"DNS query timeout for {domain} {record_type}")
            except Exception as e:
                logger.error(f"Error querying {record_type} for {domain}: {e}")
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
            logger.error(f"Error creating DNS record: {e}")
            return None

    def _validate_mx_records(self, result: DNSAnalysisResult) -> None:
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
                        self.resolver.resolve(mx_host, "A")
                        logger.debug(f"MX host {mx_host} resolves correctly")
                    except Exception as e:
                        result.warnings.append(f"MX host {mx_host} does not resolve: {str(e)}")

    def _check_ptr_records(self, result: DNSAnalysisResult) -> None:
        """Check PTR (reverse DNS) records for all A records."""
        # Collect all A records (IPv4)
        a_record_keys = [k for k in result.records.keys() if k.endswith(":A")]

        for a_key in a_record_keys:
            for a_record in result.records[a_key]:
                ip_address = a_record.value

                try:
                    # Perform reverse DNS lookup
                    rev_name = dns.reversename.from_address(ip_address)
                    answers = self.resolver.resolve(rev_name, "PTR")

                    if answers:
                        # Get first PTR record
                        ptr_value = str(answers[0]).rstrip(".")
                        result.ptr_records[ip_address] = ptr_value
                        logger.debug(f"PTR record for {ip_address}: {ptr_value}")

                        # Validate PTR record points back to original domain
                        # Forward lookup PTR value to verify it resolves to the same IP
                        try:
                            forward_answers = self.resolver.resolve(ptr_value, "A")
                            forward_ips = [str(rdata) for rdata in forward_answers]

                            if ip_address not in forward_ips:
                                result.warnings.append(
                                    f"PTR record {ptr_value} for {ip_address} does not resolve back to {ip_address}"
                                )
                        except Exception:
                            result.warnings.append(
                                f"PTR record {ptr_value} for {ip_address} does not resolve in forward lookup"
                            )
                except dns.resolver.NXDOMAIN:
                    logger.debug(f"No PTR record for {ip_address}")
                    result.warnings.append(f"No PTR record found for {ip_address}")
                except dns.resolver.NoAnswer:
                    logger.debug(f"No PTR record for {ip_address}")
                except Exception as e:
                    logger.debug(f"Error checking PTR for {ip_address}: {e}")

    def _check_dnssec(self, domain: str) -> DNSSECInfo:
        """
        Check DNSSEC status for a domain.

        Args:
            domain: The domain to check

        Returns:
            DNSSECInfo with validation status
        """
        dnssec_info = DNSSECInfo()

        try:
            domain_name = dns.name.from_text(domain)

            # Check for DNSKEY records
            try:
                dnskey_answers = self.resolver.resolve(domain, "DNSKEY")
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
                    ds_answers = self.resolver.resolve(domain, "DS")
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
            logger.error(f"Error checking DNSSEC for {domain}: {e}")
            dnssec_info.errors.append(f"Error checking DNSSEC: {str(e)}")

        return dnssec_info
