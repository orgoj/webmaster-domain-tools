"""Email security analysis module for SPF, DKIM, and DMARC."""

import logging
from dataclasses import dataclass, field

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


@dataclass
class SPFRecord:
    """Represents an SPF record."""

    record: str
    mechanisms: list[str] = field(default_factory=list)
    qualifier: str = "~all"  # Default soft fail
    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class DKIMRecord:
    """Represents a DKIM record."""

    selector: str
    record: str
    version: str = ""
    key_type: str = ""
    public_key: str = ""
    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class DMARCRecord:
    """Represents a DMARC record."""

    record: str
    policy: str = ""
    subdomain_policy: str = ""
    percentage: int = 100
    rua: list[str] = field(default_factory=list)  # Aggregate reports
    ruf: list[str] = field(default_factory=list)  # Forensic reports
    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class EmailSecurityResult:
    """Results from email security analysis."""

    domain: str
    spf: SPFRecord | None = None
    dkim: dict[str, DKIMRecord] = field(default_factory=dict)
    dmarc: DMARCRecord | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class EmailSecurityAnalyzer:
    """Analyzes email security records (SPF, DKIM, DMARC)."""

    # Common DKIM selectors to try if not specified
    DEFAULT_DKIM_SELECTORS = [
        "default",
        "google",
        "k1",
        "k2",
        "selector1",
        "selector2",
        "dkim",
        "mail",
        "s1",
        "s2",
    ]

    def __init__(self, dkim_selectors: list[str] | None = None):
        """
        Initialize email security analyzer.

        Args:
            dkim_selectors: List of DKIM selectors to check
        """
        self.dkim_selectors = dkim_selectors or self.DEFAULT_DKIM_SELECTORS
        self.resolver = dns.resolver.Resolver()

    def analyze(self, domain: str) -> EmailSecurityResult:
        """
        Perform comprehensive email security analysis.

        Args:
            domain: The domain to analyze

        Returns:
            EmailSecurityResult with SPF, DKIM, and DMARC information
        """
        logger.info(f"Starting email security analysis for {domain}")
        result = EmailSecurityResult(domain=domain)

        # Normalize domain
        domain = domain.rstrip(".")

        # Check SPF
        result.spf = self._check_spf(domain)
        if result.spf:
            result.errors.extend(result.spf.errors)
            result.warnings.extend(result.spf.warnings)

        # Check DKIM
        for selector in self.dkim_selectors:
            dkim_record = self._check_dkim(domain, selector)
            if dkim_record:
                result.dkim[selector] = dkim_record
                result.errors.extend(dkim_record.errors)
                result.warnings.extend(dkim_record.warnings)

        if not result.dkim:
            result.warnings.append(
                f"No DKIM records found for selectors: {', '.join(self.dkim_selectors)}"
            )

        # Check DMARC
        result.dmarc = self._check_dmarc(domain)
        if result.dmarc:
            result.errors.extend(result.dmarc.errors)
            result.warnings.extend(result.dmarc.warnings)

        return result

    def _check_spf(self, domain: str) -> SPFRecord | None:
        """
        Check SPF record for a domain.

        Args:
            domain: The domain to check

        Returns:
            SPFRecord or None if not found
        """
        try:
            answers = self.resolver.resolve(domain, "TXT")

            # Find SPF record (starts with "v=spf1")
            spf_record = None
            for rdata in answers:
                txt_string = rdata.to_text().strip('"')
                if txt_string.startswith("v=spf1"):
                    spf_record = txt_string
                    break

            if not spf_record:
                logger.debug(f"No SPF record found for {domain}")
                return None

            # Parse SPF record
            spf = SPFRecord(record=spf_record)
            parts = spf_record.split()

            for part in parts[1:]:  # Skip "v=spf1"
                if part.startswith(("ip4:", "ip6:", "a:", "mx:", "include:", "exists:")):
                    spf.mechanisms.append(part)
                elif part in ("~all", "-all", "+all", "?all"):
                    spf.qualifier = part

            # Validate SPF
            self._validate_spf(spf)

            logger.debug(f"Found SPF record for {domain}: {spf_record}")
            return spf

        except dns.resolver.NoAnswer:
            logger.debug(f"No TXT records found for {domain}")
            return None
        except Exception as e:
            logger.error(f"Error checking SPF for {domain}: {e}")
            spf = SPFRecord(record="", is_valid=False)
            spf.errors.append(f"Error checking SPF: {str(e)}")
            return spf

    def _validate_spf(self, spf: SPFRecord) -> None:
        """Validate SPF record and add warnings/errors."""
        # Check qualifier
        if spf.qualifier == "+all":
            spf.warnings.append("SPF uses '+all' (allows all senders, insecure)")
        elif spf.qualifier == "?all":
            spf.warnings.append("SPF uses '?all' (neutral, not recommended)")
        elif spf.qualifier == "~all":
            # This is OK (soft fail)
            pass
        elif spf.qualifier == "-all":
            # This is strict (hard fail)
            pass

        # Check for too many DNS lookups (SPF limit is 10)
        include_count = sum(1 for m in spf.mechanisms if m.startswith("include:"))
        if include_count > 8:
            spf.warnings.append(
                f"SPF has {include_count} includes (limit is 10, may cause issues)"
            )

        # Check for common issues
        if not spf.mechanisms:
            spf.warnings.append("SPF has no mechanisms defined")

    def _check_dkim(self, domain: str, selector: str) -> DKIMRecord | None:
        """
        Check DKIM record for a domain and selector.

        Args:
            domain: The domain to check
            selector: The DKIM selector

        Returns:
            DKIMRecord or None if not found
        """
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = self.resolver.resolve(dkim_domain, "TXT")

            # Combine TXT record parts (DKIM records can be split)
            dkim_record = ""
            for rdata in answers:
                dkim_record += rdata.to_text().strip('"')

            if not dkim_record:
                logger.debug(f"No DKIM record found for {dkim_domain}")
                return None

            # Parse DKIM record
            dkim = DKIMRecord(selector=selector, record=dkim_record)

            # Parse DKIM tags
            tags = {}
            for part in dkim_record.split(";"):
                part = part.strip()
                if "=" in part:
                    key, value = part.split("=", 1)
                    tags[key.strip()] = value.strip()

            dkim.version = tags.get("v", "")
            dkim.key_type = tags.get("k", "rsa")
            dkim.public_key = tags.get("p", "")

            # Validate DKIM
            self._validate_dkim(dkim)

            logger.debug(f"Found DKIM record for {selector}.{domain}")
            return dkim

        except dns.resolver.NXDOMAIN:
            logger.debug(f"DKIM selector {selector} does not exist for {domain}")
            return None
        except dns.resolver.NoAnswer:
            logger.debug(f"No DKIM record found for {selector}.{domain}")
            return None
        except Exception as e:
            logger.debug(f"Error checking DKIM for {selector}.{domain}: {e}")
            return None

    def _validate_dkim(self, dkim: DKIMRecord) -> None:
        """Validate DKIM record and add warnings/errors."""
        # Check version
        if dkim.version and dkim.version != "DKIM1":
            dkim.warnings.append(f"Unknown DKIM version: {dkim.version}")

        # Check if public key exists
        if not dkim.public_key:
            dkim.is_valid = False
            dkim.errors.append("DKIM record has no public key (p= tag)")

        # Check key type
        if dkim.key_type not in ("rsa", "ed25519"):
            dkim.warnings.append(f"Unknown key type: {dkim.key_type}")

    def _check_dmarc(self, domain: str) -> DMARCRecord | None:
        """
        Check DMARC record for a domain.

        Args:
            domain: The domain to check

        Returns:
            DMARCRecord or None if not found
        """
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, "TXT")

            # Find DMARC record (starts with "v=DMARC1")
            dmarc_record = None
            for rdata in answers:
                txt_string = rdata.to_text().strip('"')
                if txt_string.startswith("v=DMARC1"):
                    dmarc_record = txt_string
                    break

            if not dmarc_record:
                logger.debug(f"No DMARC record found for {domain}")
                return None

            # Parse DMARC record
            dmarc = DMARCRecord(record=dmarc_record)

            # Parse DMARC tags
            tags = {}
            for part in dmarc_record.split(";"):
                part = part.strip()
                if "=" in part:
                    key, value = part.split("=", 1)
                    tags[key.strip()] = value.strip()

            dmarc.policy = tags.get("p", "")
            dmarc.subdomain_policy = tags.get("sp", dmarc.policy)

            # Parse percentage
            try:
                dmarc.percentage = int(tags.get("pct", "100"))
            except ValueError:
                dmarc.percentage = 100

            # Parse report addresses
            if "rua" in tags:
                dmarc.rua = [addr.strip() for addr in tags["rua"].split(",")]
            if "ruf" in tags:
                dmarc.ruf = [addr.strip() for addr in tags["ruf"].split(",")]

            # Validate DMARC
            self._validate_dmarc(dmarc)

            logger.debug(f"Found DMARC record for {domain}: {dmarc_record}")
            return dmarc

        except dns.resolver.NXDOMAIN:
            logger.debug(f"DMARC record does not exist for {domain}")
            return None
        except dns.resolver.NoAnswer:
            logger.debug(f"No DMARC record found for {domain}")
            return None
        except Exception as e:
            logger.error(f"Error checking DMARC for {domain}: {e}")
            dmarc = DMARCRecord(record="", is_valid=False)
            dmarc.errors.append(f"Error checking DMARC: {str(e)}")
            return dmarc

    def _validate_dmarc(self, dmarc: DMARCRecord) -> None:
        """Validate DMARC record and add warnings/errors."""
        # Check policy
        if not dmarc.policy:
            dmarc.is_valid = False
            dmarc.errors.append("DMARC has no policy defined (p= tag)")
        elif dmarc.policy not in ("none", "quarantine", "reject"):
            dmarc.warnings.append(f"Unknown DMARC policy: {dmarc.policy}")
        elif dmarc.policy == "none":
            dmarc.warnings.append(
                "DMARC policy is 'none' (monitoring only, consider 'quarantine' or 'reject')"
            )

        # Check percentage
        if dmarc.percentage < 100:
            dmarc.warnings.append(
                f"DMARC policy applies to only {dmarc.percentage}% of messages"
            )

        # Check report addresses
        if not dmarc.rua:
            dmarc.warnings.append("No aggregate report address (rua) configured")
