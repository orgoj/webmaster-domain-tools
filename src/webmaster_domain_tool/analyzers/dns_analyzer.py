"""DNS analysis module for checking domain DNS records."""

import logging
from dataclasses import dataclass, field
from typing import Any

import dns.resolver
import dns.exception
import dns.dnssec
import dns.name

logger = logging.getLogger(__name__)


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
    dnssec: DNSSECInfo | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class DNSAnalyzer:
    """Analyzes DNS records for a domain."""

    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME"]

    def __init__(self, nameservers: list[str] | None = None, check_dnssec: bool = True):
        """
        Initialize DNS analyzer.

        Args:
            nameservers: Optional list of nameservers to use for queries
            check_dnssec: Whether to check DNSSEC validation
        """
        self.check_dnssec = check_dnssec

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
        result = DNSAnalysisResult(domain=domain)

        # Normalize domain (remove trailing dot if present)
        domain = domain.rstrip(".")

        # Check main domain
        self._check_domain_records(domain, result)

        # Check www subdomain if not already a subdomain
        if not domain.startswith("www."):
            www_domain = f"www.{domain}"
            self._check_domain_records(www_domain, result)

        # Validate MX records
        self._validate_mx_records(result)

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

                for rdata in answers:
                    record = self._create_dns_record(
                        record_type=record_type,
                        name=domain,
                        rdata=rdata,
                        ttl=answers.ttl,
                    )
                    if record:
                        key = f"{domain}:{record_type}"
                        if key not in result.records:
                            result.records[key] = []
                        result.records[key].append(record)

                logger.debug(f"Found {len(answers)} {record_type} records for {domain}")

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

    def _create_dns_record(
        self, record_type: str, name: str, rdata: Any, ttl: int | None
    ) -> DNSRecord | None:
        """Create a DNSRecord from DNS response data."""
        try:
            if record_type == "MX":
                value = f"{rdata.preference} {rdata.exchange}"
            elif record_type == "SOA":
                value = f"{rdata.mname} {rdata.rname}"
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
                        result.warnings.append(
                            f"MX host {mx_host} does not resolve: {str(e)}"
                        )

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
                    parent_domain = ".".join(domain.split(".")[1:])
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
