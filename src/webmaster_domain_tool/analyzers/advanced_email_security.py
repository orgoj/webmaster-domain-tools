"""Advanced email security analyzer - BIMI, MTA-STS, TLS-RPT."""

import logging
from dataclasses import dataclass, field

import dns.resolver
import httpx

from .base import BaseAnalysisResult, BaseAnalyzer
from .dns_utils import create_resolver

logger = logging.getLogger(__name__)


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
class AdvancedEmailSecurityResult(BaseAnalysisResult):
    """Results from advanced email security analysis."""

    bimi: BIMIRecord | None = None
    mta_sts: MTASTSRecord | None = None
    tls_rpt: TLSRPTRecord | None = None


class AdvancedEmailSecurityAnalyzer(BaseAnalyzer[AdvancedEmailSecurityResult]):
    """Analyzes advanced email security features (BIMI, MTA-STS, TLS-RPT)."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        check_bimi: bool = True,
        check_mta_sts: bool = True,
        check_tls_rpt: bool = True,
        timeout: float = 5.0,
    ):
        """
        Initialize advanced email security analyzer.

        Args:
            nameservers: Optional list of nameservers to use
            check_bimi: Check BIMI records
            check_mta_sts: Check MTA-STS
            check_tls_rpt: Check TLS-RPT
            timeout: DNS and HTTP timeout
        """
        self.check_bimi = check_bimi
        self.check_mta_sts = check_mta_sts
        self.check_tls_rpt = check_tls_rpt
        self.timeout = timeout

        # Create DNS resolver using centralized utility
        self.resolver = create_resolver(nameservers=nameservers, timeout=timeout)

    def analyze(self, domain: str) -> AdvancedEmailSecurityResult:
        """
        Analyze advanced email security for a domain.

        Args:
            domain: Domain to analyze

        Returns:
            AdvancedEmailSecurityResult with all findings
        """
        result = AdvancedEmailSecurityResult(domain=domain)

        # Check BIMI
        if self.check_bimi:
            result.bimi = self._check_bimi(domain)
            result.errors.extend(result.bimi.errors)
            result.warnings.extend(result.bimi.warnings)

        # Check MTA-STS
        if self.check_mta_sts:
            result.mta_sts = self._check_mta_sts(domain)
            result.errors.extend(result.mta_sts.errors)
            result.warnings.extend(result.mta_sts.warnings)

        # Check TLS-RPT
        if self.check_tls_rpt:
            result.tls_rpt = self._check_tls_rpt(domain)
            result.errors.extend(result.tls_rpt.errors)
            result.warnings.extend(result.tls_rpt.warnings)

        return result

    def _check_bimi(self, domain: str) -> BIMIRecord:
        """Check BIMI (Brand Indicators for Message Identification) record."""
        # BIMI record is at default._bimi.domain.com
        bimi_domain = f"default._bimi.{domain}"
        result = BIMIRecord(domain=domain)

        try:
            answers = self.resolver.resolve(bimi_domain, "TXT")

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
            logger.error(f"Error checking BIMI for {domain}: {e}")

        return result

    def _check_mta_sts(self, domain: str) -> MTASTSRecord:
        """Check MTA-STS (Mail Transfer Agent Strict Transport Security)."""
        # MTA-STS DNS record is at _mta-sts.domain.com
        mta_sts_domain = f"_mta-sts.{domain}"
        result = MTASTSRecord(domain=domain)

        # Check DNS record
        try:
            answers = self.resolver.resolve(mta_sts_domain, "TXT")

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
            logger.error(f"Error checking MTA-STS DNS for {domain}: {e}")

        # If DNS record found, check policy file
        if result.record_found:
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
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
                logger.error(f"Error fetching MTA-STS policy for {domain}: {e}")

        return result

    def _check_tls_rpt(self, domain: str) -> TLSRPTRecord:
        """Check TLS-RPT (TLS Reporting) record."""
        # TLS-RPT record is at _smtp._tls.domain.com
        tls_rpt_domain = f"_smtp._tls.{domain}"
        result = TLSRPTRecord(domain=domain)

        try:
            answers = self.resolver.resolve(tls_rpt_domain, "TXT")

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
            logger.error(f"Error checking TLS-RPT for {domain}: {e}")

        return result
