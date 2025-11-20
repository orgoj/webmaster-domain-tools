"""Email security analysis module for SPF, DKIM, DMARC, BIMI, MTA-STS, and TLS-RPT.

This analyzer detects and validates email authentication and security records.
Completely self-contained with config, logic, and output formatting.
"""

import logging
from dataclasses import dataclass, field

import dns.exception
import dns.resolver
import httpx
from pydantic import Field

from ..constants import DEFAULT_DKIM_SELECTORS, SPF_MAX_INCLUDES_LIMIT, SPF_MAX_INCLUDES_WARNING
from ..core.registry import registry
from .dns_utils import create_resolver
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class EmailConfig(AnalyzerConfig):
    """Email security analyzer configuration."""

    dkim_selectors: list[str] = Field(
        default_factory=lambda: DEFAULT_DKIM_SELECTORS.copy(),
        description="List of DKIM selectors to check",
    )
    check_bimi: bool = Field(default=True, description="Check BIMI records")
    check_mta_sts: bool = Field(default=True, description="Check MTA-STS")
    check_tls_rpt: bool = Field(default=True, description="Check TLS-RPT")
    nameservers: list[str] | None = Field(
        default=None, description="Optional list of nameservers to use"
    )


# ============================================================================
# Result Models
# ============================================================================


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
class BIMIRecord:
    """BIMI record information."""

    domain: str
    record_found: bool = False
    record_value: str | None = None
    logo_url: str | None = None
    vmc_url: str | None = None  # Verified Mark Certificate
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class MTASTSRecord:
    """MTA-STS record and policy information."""

    domain: str
    record_found: bool = False
    record_value: str | None = None
    policy_found: bool = False
    policy_content: str | None = None
    policy_mode: str | None = None  # testing, enforce, none
    policy_max_age: int | None = None
    mx_patterns: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class TLSRPTRecord:
    """TLS-RPT record information."""

    domain: str
    record_found: bool = False
    record_value: str | None = None
    reporting_addresses: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class EmailSecurityResult:
    """Results from email security analysis."""

    domain: str
    spf: SPFRecord | None = None
    dkim: dict[str, DKIMRecord] = field(default_factory=dict)
    dmarc: DMARCRecord | None = None
    dkim_selectors_searched: list[str] = field(default_factory=list)
    bimi: BIMIRecord | None = None
    mta_sts: MTASTSRecord | None = None
    tls_rpt: TLSRPTRecord | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class EmailSecurityAnalyzer:
    """
    Analyzes email security records (SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT).

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (EmailConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "email"
    name = "Email Security"
    description = "Analyze email authentication and security records"
    category = "security"
    icon = "envelope"
    config_class = EmailConfig
    depends_on = ["dns"]  # Email needs DNS TXT records

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: EmailConfig) -> EmailSecurityResult:
        """
        Perform comprehensive email security analysis.

        Args:
            domain: The domain to analyze
            config: Email security analyzer configuration

        Returns:
            EmailSecurityResult with SPF, DKIM, DMARC, BIMI, MTA-STS, and TLS-RPT information
        """
        logger.info(f"Starting email security analysis for {domain}")
        result = EmailSecurityResult(domain=domain, dkim_selectors_searched=config.dkim_selectors)

        # Normalize domain
        domain = domain.rstrip(".")

        # Create DNS resolver
        resolver = create_resolver(nameservers=config.nameservers, timeout=config.timeout)

        # Check SPF
        result.spf = self._check_spf(domain, resolver)
        if result.spf:
            result.errors.extend(result.spf.errors)
            result.warnings.extend(result.spf.warnings)

        # Check DKIM
        for selector in config.dkim_selectors:
            dkim_record = self._check_dkim(domain, selector, resolver)
            if dkim_record:
                result.dkim[selector] = dkim_record
                result.errors.extend(dkim_record.errors)
                result.warnings.extend(dkim_record.warnings)

        # Check DMARC
        result.dmarc = self._check_dmarc(domain, resolver)
        if result.dmarc:
            result.errors.extend(result.dmarc.errors)
            result.warnings.extend(result.dmarc.warnings)

        # Check BIMI
        if config.check_bimi:
            result.bimi = self._check_bimi(domain, resolver)
            result.errors.extend(result.bimi.errors)
            result.warnings.extend(result.bimi.warnings)

        # Check MTA-STS
        if config.check_mta_sts:
            result.mta_sts = self._check_mta_sts(domain, resolver, config.timeout)
            result.errors.extend(result.mta_sts.errors)
            result.warnings.extend(result.mta_sts.warnings)

        # Check TLS-RPT
        if config.check_tls_rpt:
            result.tls_rpt = self._check_tls_rpt(domain, resolver)
            result.errors.extend(result.tls_rpt.errors)
            result.warnings.extend(result.tls_rpt.warnings)

        return result

    def describe_output(self, result: EmailSecurityResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: Email security analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        descriptor.quiet_summary = lambda r: self._get_quiet_summary(r)

        # SPF Section
        if result.spf:
            descriptor.add_row(
                label="SPF Record",
                value="Found",
                style_class="success" if result.spf.is_valid else "error",
                icon="check" if result.spf.is_valid else "cross",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            # Show SPF record in verbose mode
            descriptor.add_row(
                label="SPF Value",
                value=result.spf.record,
                style_class="info",
                format_as="code",
                verbosity=VerbosityLevel.VERBOSE,
            )

            # Show qualifier
            descriptor.add_row(
                label="SPF Qualifier",
                value=result.spf.qualifier,
                style_class="info",
                verbosity=VerbosityLevel.VERBOSE,
            )

            # Show mechanisms in verbose
            if result.spf.mechanisms:
                descriptor.add_row(
                    label="SPF Mechanisms",
                    value=result.spf.mechanisms,
                    section_type="list",
                    style_class="info",
                    verbosity=VerbosityLevel.VERBOSE,
                )
        else:
            descriptor.add_row(
                label="SPF Record",
                value="Not found",
                style_class="warning",
                icon="warning",
                severity="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        # DKIM Section
        if result.dkim:
            descriptor.add_row(
                label="DKIM Records",
                value=f"Found {len(result.dkim)} selector(s)",
                style_class="success",
                icon="check",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            # Show each DKIM record in verbose
            for selector, dkim in result.dkim.items():
                descriptor.add_row(
                    label=f"DKIM ({selector})",
                    value=dkim.record if len(dkim.record) < 100 else dkim.record[:100] + "...",
                    style_class="info",
                    format_as="code",
                    verbosity=VerbosityLevel.VERBOSE,
                )
        else:
            descriptor.add_row(
                label="DKIM Records",
                value=f"Not found (checked: {', '.join(result.dkim_selectors_searched)})",
                style_class="muted",
                icon="info",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        # DMARC Section
        if result.dmarc:
            # Style based on policy strength
            policy_style = {
                "reject": "success",
                "quarantine": "warning",
                "none": "muted",
            }.get(result.dmarc.policy, "neutral")

            descriptor.add_row(
                label="DMARC Policy",
                value=result.dmarc.policy.upper() if result.dmarc.policy else "Not set",
                style_class=policy_style,
                icon="check" if result.dmarc.is_valid else "cross",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            # Show DMARC record in verbose
            descriptor.add_row(
                label="DMARC Record",
                value=result.dmarc.record,
                style_class="info",
                format_as="code",
                verbosity=VerbosityLevel.VERBOSE,
            )

            # Show report addresses
            if result.dmarc.rua:
                descriptor.add_row(
                    label="Aggregate Reports (rua)",
                    value=result.dmarc.rua,
                    section_type="list",
                    style_class="info",
                    verbosity=VerbosityLevel.VERBOSE,
                )
        else:
            descriptor.add_row(
                label="DMARC Policy",
                value="Not configured",
                style_class="warning",
                icon="warning",
                severity="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        # BIMI Section
        if result.bimi and result.bimi.record_found:
            descriptor.add_row(
                label="BIMI",
                value="Configured",
                style_class="success",
                icon="check",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            if result.bimi.logo_url:
                descriptor.add_row(
                    label="BIMI Logo",
                    value=result.bimi.logo_url,
                    link_url=result.bimi.logo_url,
                    style_class="info",
                    verbosity=VerbosityLevel.VERBOSE,
                )

        # MTA-STS Section
        if result.mta_sts and result.mta_sts.record_found:
            mode_style = {
                "enforce": "success",
                "testing": "warning",
                "none": "muted",
            }.get(result.mta_sts.policy_mode, "neutral")

            descriptor.add_row(
                label="MTA-STS",
                value=(
                    f"Enabled ({result.mta_sts.policy_mode})"
                    if result.mta_sts.policy_mode
                    else "DNS record found"
                ),
                style_class=mode_style,
                icon="check",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            if result.mta_sts.mx_patterns:
                descriptor.add_row(
                    label="MTA-STS MX Patterns",
                    value=result.mta_sts.mx_patterns,
                    section_type="list",
                    style_class="info",
                    verbosity=VerbosityLevel.VERBOSE,
                )

        # TLS-RPT Section
        if result.tls_rpt and result.tls_rpt.record_found:
            descriptor.add_row(
                label="TLS-RPT",
                value="Configured",
                style_class="success",
                icon="check",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

            if result.tls_rpt.reporting_addresses:
                descriptor.add_row(
                    label="TLS-RPT Addresses",
                    value=result.tls_rpt.reporting_addresses,
                    section_type="list",
                    style_class="info",
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

    def to_dict(self, result: EmailSecurityResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Email security analysis result

        Returns:
            JSON-serializable dict
        """
        output = {
            "domain": result.domain,
            "errors": result.errors,
            "warnings": result.warnings,
        }

        # SPF
        if result.spf:
            output["spf"] = {
                "record": result.spf.record,
                "mechanisms": result.spf.mechanisms,
                "qualifier": result.spf.qualifier,
                "is_valid": result.spf.is_valid,
                "errors": result.spf.errors,
                "warnings": result.spf.warnings,
            }
        else:
            output["spf"] = None

        # DKIM
        output["dkim"] = {}
        for selector, dkim in result.dkim.items():
            output["dkim"][selector] = {
                "record": dkim.record,
                "version": dkim.version,
                "key_type": dkim.key_type,
                "public_key": dkim.public_key,
                "is_valid": dkim.is_valid,
                "errors": dkim.errors,
                "warnings": dkim.warnings,
            }
        output["dkim_selectors_searched"] = result.dkim_selectors_searched

        # DMARC
        if result.dmarc:
            output["dmarc"] = {
                "record": result.dmarc.record,
                "policy": result.dmarc.policy,
                "subdomain_policy": result.dmarc.subdomain_policy,
                "percentage": result.dmarc.percentage,
                "rua": result.dmarc.rua,
                "ruf": result.dmarc.ruf,
                "is_valid": result.dmarc.is_valid,
                "errors": result.dmarc.errors,
                "warnings": result.dmarc.warnings,
            }
        else:
            output["dmarc"] = None

        # BIMI
        if result.bimi:
            output["bimi"] = {
                "record_found": result.bimi.record_found,
                "record_value": result.bimi.record_value,
                "logo_url": result.bimi.logo_url,
                "vmc_url": result.bimi.vmc_url,
                "errors": result.bimi.errors,
                "warnings": result.bimi.warnings,
            }
        else:
            output["bimi"] = None

        # MTA-STS
        if result.mta_sts:
            output["mta_sts"] = {
                "record_found": result.mta_sts.record_found,
                "record_value": result.mta_sts.record_value,
                "policy_found": result.mta_sts.policy_found,
                "policy_mode": result.mta_sts.policy_mode,
                "policy_max_age": result.mta_sts.policy_max_age,
                "mx_patterns": result.mta_sts.mx_patterns,
                "errors": result.mta_sts.errors,
                "warnings": result.mta_sts.warnings,
            }
        else:
            output["mta_sts"] = None

        # TLS-RPT
        if result.tls_rpt:
            output["tls_rpt"] = {
                "record_found": result.tls_rpt.record_found,
                "record_value": result.tls_rpt.record_value,
                "reporting_addresses": result.tls_rpt.reporting_addresses,
                "errors": result.tls_rpt.errors,
                "warnings": result.tls_rpt.warnings,
            }
        else:
            output["tls_rpt"] = None

        return output

    # ========================================================================
    # Helper Methods (kept intact from original implementation)
    # ========================================================================

    def _get_quiet_summary(self, result: EmailSecurityResult) -> str:
        """Generate quiet mode summary."""
        parts = []

        if result.spf:
            parts.append(f"SPF: {result.spf.qualifier}")
        else:
            parts.append("SPF: None")

        if result.dkim:
            parts.append(f"DKIM: {len(result.dkim)}")
        else:
            parts.append("DKIM: None")

        if result.dmarc:
            parts.append(f"DMARC: {result.dmarc.policy}")
        else:
            parts.append("DMARC: None")

        return " | ".join(parts)

    def _check_spf(self, domain: str, resolver: dns.resolver.Resolver) -> SPFRecord | None:
        """
        Check SPF record for a domain.

        Args:
            domain: The domain to check
            resolver: DNS resolver to use

        Returns:
            SPFRecord or None if not found
        """
        try:
            answers = resolver.resolve(domain, "TXT")

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
            logger.debug(f"Error checking SPF for {domain}: {e}")
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
        if include_count > SPF_MAX_INCLUDES_WARNING:
            spf.warnings.append(
                f"SPF has {include_count} includes (limit is {SPF_MAX_INCLUDES_LIMIT}, may cause issues)"
            )

        # Check for common issues
        if not spf.mechanisms:
            spf.warnings.append("SPF has no mechanisms defined")

    def _check_dkim(
        self, domain: str, selector: str, resolver: dns.resolver.Resolver
    ) -> DKIMRecord | None:
        """
        Check DKIM record for a domain and selector.

        Args:
            domain: The domain to check
            selector: The DKIM selector
            resolver: DNS resolver to use

        Returns:
            DKIMRecord or None if not found
        """
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = resolver.resolve(dkim_domain, "TXT")

            # Combine TXT record parts (DKIM records can be split)
            dkim_record = ""
            for rdata in answers:
                dkim_record += rdata.to_text().strip('"')

            if not dkim_record:
                logger.debug(f"No DKIM record found for {dkim_domain}")
                return None

            # Parse DKIM tags first to validate it's actually a DKIM record
            tags = {}
            for part in dkim_record.split(";"):
                part = part.strip()
                if "=" in part:
                    key, value = part.split("=", 1)
                    tags[key.strip()] = value.strip()

            # Check if this is actually a DKIM record
            # DKIM records should have a p= tag (public key) or at minimum not be SPF
            version = tags.get("v", "")
            if version.startswith("spf"):
                logger.debug(f"TXT record at {dkim_domain} is SPF, not DKIM")
                return None

            # DKIM records must have a public key tag (p=)
            # Empty p= is valid (revoked key), but tag must exist
            if "p" not in tags:
                logger.debug(f"TXT record at {dkim_domain} has no p= tag, not a valid DKIM record")
                return None

            # Parse DKIM record
            dkim = DKIMRecord(selector=selector, record=dkim_record)
            dkim.version = version
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

    def _check_dmarc(self, domain: str, resolver: dns.resolver.Resolver) -> DMARCRecord | None:
        """
        Check DMARC record for a domain.

        Args:
            domain: The domain to check
            resolver: DNS resolver to use

        Returns:
            DMARCRecord or None if not found
        """
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, "TXT")

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
            logger.debug(f"Error checking DMARC for {domain}: {e}")
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
            dmarc.warnings.append(f"DMARC policy applies to only {dmarc.percentage}% of messages")

        # Check report addresses
        if not dmarc.rua:
            dmarc.warnings.append("No aggregate report address (rua) configured")

    def _check_bimi(self, domain: str, resolver: dns.resolver.Resolver) -> BIMIRecord:
        """Check BIMI (Brand Indicators for Message Identification) record."""
        # BIMI record is at default._bimi.domain.com
        bimi_domain = f"default._bimi.{domain}"
        result = BIMIRecord(domain=domain)

        try:
            answers = resolver.resolve(bimi_domain, "TXT")

            for rdata in answers:
                txt_string = rdata.to_text().strip('"')

                # Check if this is a BIMI record (starts with v=BIMI1)
                if txt_string.startswith("v=BIMI1"):
                    result.record_found = True
                    result.record_value = txt_string

                    # Parse BIMI record
                    parts = txt_string.split(";")
                    for part in parts:
                        part = part.strip()
                        if part.startswith("l="):
                            result.logo_url = part[2:].strip()
                        elif part.startswith("a="):
                            result.vmc_url = part[2:].strip()

                    logger.info(f"BIMI record found for {domain}")
                    break

            if not result.record_found:
                # Record exists but is not valid BIMI
                result.warnings.append("DNS record found but not a valid BIMI record")

        except dns.resolver.NXDOMAIN:
            logger.debug(f"No BIMI record for {domain}")
        except dns.resolver.NoAnswer:
            logger.debug(f"No BIMI TXT record for {domain}")
        except dns.resolver.Timeout:
            result.warnings.append(f"DNS timeout checking BIMI for {domain}")
        except Exception as e:
            result.warnings.append(f"Error checking BIMI: {str(e)}")
            logger.debug(f"Error checking BIMI for {domain}: {e}")

        return result

    def _check_mta_sts(
        self, domain: str, resolver: dns.resolver.Resolver, timeout: float
    ) -> MTASTSRecord:
        """Check MTA-STS (Mail Transfer Agent Strict Transport Security)."""
        # MTA-STS DNS record is at _mta-sts.domain.com
        mta_sts_domain = f"_mta-sts.{domain}"
        result = MTASTSRecord(domain=domain)

        # Check DNS record
        try:
            answers = resolver.resolve(mta_sts_domain, "TXT")

            for rdata in answers:
                txt_string = rdata.to_text().strip('"')

                # Check if this is an MTA-STS record (starts with v=STSv1)
                if txt_string.startswith("v=STSv1"):
                    result.record_found = True
                    result.record_value = txt_string
                    logger.info(f"MTA-STS DNS record found for {domain}")
                    break

        except dns.resolver.NXDOMAIN:
            logger.debug(f"No MTA-STS DNS record for {domain}")
        except dns.resolver.NoAnswer:
            logger.debug(f"No MTA-STS TXT record for {domain}")
        except dns.resolver.Timeout:
            result.warnings.append(f"DNS timeout checking MTA-STS for {domain}")
        except Exception as e:
            result.warnings.append(f"Error checking MTA-STS DNS: {str(e)}")
            logger.debug(f"Error checking MTA-STS DNS for {domain}: {e}")

        # If DNS record found, check policy file
        if result.record_found:
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

            try:
                with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                    response = client.get(policy_url)

                if response.status_code == 200:
                    result.policy_found = True
                    result.policy_content = response.text

                    # Parse policy
                    for line in response.text.split("\n"):
                        line = line.strip()
                        if line.startswith("mode:"):
                            result.policy_mode = line.split(":", 1)[1].strip()
                        elif line.startswith("max_age:"):
                            try:
                                result.policy_max_age = int(line.split(":", 1)[1].strip())
                            except ValueError:
                                pass
                        elif line.startswith("mx:"):
                            mx_pattern = line.split(":", 1)[1].strip()
                            result.mx_patterns.append(mx_pattern)

                    logger.info(f"MTA-STS policy found for {domain} (mode: {result.policy_mode})")
                else:
                    result.errors.append(
                        f"MTA-STS policy file returned HTTP {response.status_code}"
                    )

            except httpx.TimeoutException:
                result.errors.append("Timeout fetching MTA-STS policy")
            except Exception as e:
                result.errors.append(f"Error fetching MTA-STS policy: {str(e)}")
                logger.debug(f"Error fetching MTA-STS policy for {domain}: {e}")

        return result

    def _check_tls_rpt(self, domain: str, resolver: dns.resolver.Resolver) -> TLSRPTRecord:
        """Check TLS-RPT (TLS Reporting) record."""
        # TLS-RPT record is at _smtp._tls.domain.com
        tls_rpt_domain = f"_smtp._tls.{domain}"
        result = TLSRPTRecord(domain=domain)

        try:
            answers = resolver.resolve(tls_rpt_domain, "TXT")

            for rdata in answers:
                txt_string = rdata.to_text().strip('"')

                # Check if this is a TLS-RPT record (starts with v=TLSRPTv1)
                if txt_string.startswith("v=TLSRPTv1"):
                    result.record_found = True
                    result.record_value = txt_string

                    # Parse reporting addresses (rua=)
                    parts = txt_string.split(";")
                    for part in parts:
                        part = part.strip()
                        if part.startswith("rua="):
                            # Multiple addresses can be comma-separated
                            addresses = part[4:].split(",")
                            result.reporting_addresses.extend([a.strip() for a in addresses])

                    logger.info(f"TLS-RPT record found for {domain}")
                    break

        except dns.resolver.NXDOMAIN:
            logger.debug(f"No TLS-RPT record for {domain}")
        except dns.resolver.NoAnswer:
            logger.debug(f"No TLS-RPT TXT record for {domain}")
        except dns.resolver.Timeout:
            result.warnings.append(f"DNS timeout checking TLS-RPT for {domain}")
        except Exception as e:
            result.warnings.append(f"Error checking TLS-RPT: {str(e)}")
            logger.debug(f"Error checking TLS-RPT for {domain}: {e}")

        return result
