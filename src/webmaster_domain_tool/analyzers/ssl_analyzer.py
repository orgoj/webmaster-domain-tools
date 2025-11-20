"""SSL/TLS certificate analysis module.

This analyzer examines SSL/TLS certificates and configurations.
Completely self-contained with config, logic, and output formatting.
"""

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import Field

from ..constants import (
    DEFAULT_SSL_EXPIRY_CRITICAL_DAYS,
    DEFAULT_SSL_EXPIRY_WARNING_DAYS,
    DEFAULT_SSL_PORT,
)
from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class SSLConfig(AnalyzerConfig):
    """SSL/TLS analyzer configuration."""

    port: int = Field(default=DEFAULT_SSL_PORT, description="SSL/TLS port to check")
    cert_expiry_warning_days: int = Field(
        default=DEFAULT_SSL_EXPIRY_WARNING_DAYS, description="Days before expiry to show warning"
    )
    cert_expiry_critical_days: int = Field(
        default=DEFAULT_SSL_EXPIRY_CRITICAL_DAYS,
        description="Days before expiry to show critical error",
    )
    check_www: bool = Field(default=True, description="Also check www subdomain")


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class CertificateInfo:
    """Represents SSL/TLS certificate information."""

    subject: dict[str, str]
    issuer: dict[str, str]
    version: int
    serial_number: str
    not_before: datetime
    not_after: datetime
    san: list[str] = field(default_factory=list)  # Subject Alternative Names
    is_valid: bool = True
    days_until_expiry: int = 0
    status: str = "ok"  # "ok", "mismatch", "none"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SSLAnalysisResult:
    """Results from SSL/TLS analysis."""

    domain: str
    port: int = DEFAULT_SSL_PORT
    certificates: dict[str, CertificateInfo] = field(default_factory=dict)
    protocols: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class SSLAnalyzer:
    """
    Analyzes SSL/TLS certificates and configurations.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (SSLConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "ssl"
    name = "SSL/TLS Analysis"
    description = "Analyze SSL/TLS certificates and configurations"
    category = "security"
    icon = "lock"
    config_class = SSLConfig
    depends_on = ["http"]  # SSL needs HTTP connection info

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: SSLConfig) -> SSLAnalysisResult:
        """
        Perform comprehensive SSL/TLS analysis of a domain.

        Args:
            domain: The domain to analyze
            config: SSL analyzer configuration

        Returns:
            SSLAnalysisResult with certificate and SSL information
        """
        logger.info(f"Starting SSL analysis for {domain}:{config.port}")
        result = SSLAnalysisResult(domain=domain, port=config.port)

        # Normalize domain
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

        # Check domain and www.domain
        domains_to_check = [domain]
        if config.check_www and not domain.startswith("www."):
            domains_to_check.append(f"www.{domain}")

        for check_domain in domains_to_check:
            cert_info = self._get_certificate_info(
                check_domain,
                config.port,
                config.timeout,
                config.cert_expiry_warning_days,
                config.cert_expiry_critical_days,
            )
            if cert_info:
                result.certificates[check_domain] = cert_info

                # Add certificate warnings/errors to result
                result.errors.extend(cert_info.errors)
                result.warnings.extend(cert_info.warnings)

        # Check supported protocols and ciphers
        self._check_ssl_config(domain, config.port, config.timeout, result)

        return result

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _get_certificate_info(
        self,
        domain: str,
        port: int,
        timeout: float,
        cert_expiry_warning_days: int,
        cert_expiry_critical_days: int,
    ) -> CertificateInfo | None:
        """
        Get SSL certificate information for a domain.

        Args:
            domain: The domain to check
            port: The port to check
            timeout: Connection timeout in seconds
            cert_expiry_warning_days: Days before expiry to show warning
            cert_expiry_critical_days: Days before expiry to show critical error

        Returns:
            CertificateInfo object or None if failed
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()

            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Extract certificate information
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))

                    # Parse dates
                    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

                    # Calculate days until expiry
                    days_until_expiry = (not_after - datetime.now()).days

                    # Extract Subject Alternative Names (SAN)
                    san = []
                    for key, value in cert.get("subjectAltName", []):
                        if key == "DNS":
                            san.append(value)

                    # Create certificate info
                    cert_info = CertificateInfo(
                        subject=subject,
                        issuer=issuer,
                        version=cert.get("version", 0),
                        serial_number=cert.get("serialNumber", ""),
                        not_before=not_before,
                        not_after=not_after,
                        san=san,
                        days_until_expiry=days_until_expiry,
                    )

                    # Validate certificate
                    self._validate_certificate(
                        cert_info,
                        domain,
                        cert_expiry_warning_days,
                        cert_expiry_critical_days,
                    )

                    logger.debug(f"Retrieved certificate for {domain}")
                    return cert_info

        except ssl.SSLError as e:
            logger.debug(f"SSL error for {domain}:{port}: {e}")

            # Determine status based on error message
            error_str = str(e).lower()
            if "hostname mismatch" in error_str or "not valid for" in error_str:
                status = "mismatch"
            else:
                status = "none"

            cert_info = CertificateInfo(
                subject={},
                issuer={},
                version=0,
                serial_number="",
                not_before=datetime.now(),
                not_after=datetime.now(),
                is_valid=False,
                status=status,
            )
            cert_info.errors.append(f"SSL error: {str(e)}")
            return cert_info

        except TimeoutError:
            logger.debug(f"Connection timeout for {domain}:{port}")
            return None

        except socket.gaierror as e:
            logger.debug(f"DNS resolution failed for {domain}: {e}")
            return None

        except Exception as e:
            logger.debug(f"Unexpected error getting certificate for {domain}:{port}: {e}")
            cert_info = CertificateInfo(
                subject={},
                issuer={},
                version=0,
                serial_number="",
                not_before=datetime.now(),
                not_after=datetime.now(),
                is_valid=False,
            )
            cert_info.errors.append(f"Error: {str(e)}")
            return cert_info

    def _validate_certificate(
        self,
        cert_info: CertificateInfo,
        domain: str,
        cert_expiry_warning_days: int,
        cert_expiry_critical_days: int,
    ) -> None:
        """
        Validate certificate and add warnings/errors.

        Args:
            cert_info: Certificate information to validate
            domain: The domain being checked
            cert_expiry_warning_days: Days before expiry to show warning
            cert_expiry_critical_days: Days before expiry to show critical error
        """
        # Check expiry
        if cert_info.days_until_expiry < 0:
            cert_info.is_valid = False
            cert_info.errors.append(
                f"Certificate expired {abs(cert_info.days_until_expiry)} days ago"
            )
        elif cert_info.days_until_expiry < cert_expiry_critical_days:
            cert_info.warnings.append(f"Certificate expires in {cert_info.days_until_expiry} days")
        elif cert_info.days_until_expiry < cert_expiry_warning_days:
            cert_info.warnings.append(
                f"Certificate expires in {cert_info.days_until_expiry} days (consider renewal)"
            )

        # Check if certificate is not yet valid
        if cert_info.not_before > datetime.now():
            cert_info.is_valid = False
            cert_info.errors.append("Certificate not yet valid")

        # Check if domain matches certificate
        domain_matched = False
        if cert_info.subject.get("commonName") == domain:
            domain_matched = True
        elif domain in cert_info.san:
            domain_matched = True
        else:
            # Check for wildcard matches
            for san_entry in cert_info.san:
                if san_entry.startswith("*."):
                    wildcard_domain = san_entry[2:]
                    if domain.endswith(wildcard_domain):
                        domain_matched = True
                        break

        if not domain_matched and cert_info.san:
            cert_info.warnings.append(
                f"Domain {domain} not found in certificate SAN: {', '.join(cert_info.san)}"
            )

    def _check_ssl_config(
        self,
        domain: str,
        port: int,
        timeout: float,
        result: SSLAnalysisResult,
    ) -> None:
        """
        Check SSL/TLS configuration (protocols, ciphers).

        Args:
            domain: The domain to check
            port: The port to check
            timeout: Connection timeout in seconds
            result: Result object to update
        """
        try:
            # Check TLS versions
            protocols_to_check = [
                ("TLSv1.0", ssl.TLSVersion.TLSv1),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
                ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
            ]

            for protocol_name, protocol_version in protocols_to_check:
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.minimum_version = protocol_version
                    context.maximum_version = protocol_version
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((domain, port), timeout=timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=domain):
                            result.protocols.append(protocol_name)
                            logger.debug(f"{domain} supports {protocol_name}")
                except Exception:
                    logger.debug(f"{domain} does not support {protocol_name}")

            # Warn about old protocols
            if "TLSv1.0" in result.protocols:
                result.warnings.append("TLSv1.0 is supported (deprecated, should be disabled)")
            if "TLSv1.1" in result.protocols:
                result.warnings.append("TLSv1.1 is supported (deprecated, should be disabled)")

            # Check if TLSv1.3 is supported
            if "TLSv1.3" not in result.protocols:
                result.warnings.append("TLSv1.3 is not supported (recommended)")

        except Exception as e:
            logger.debug(f"Error checking SSL configuration for {domain}:{port}: {e}")
            result.errors.append(f"Error checking SSL configuration: {str(e)}")

    def describe_output(self, result: SSLAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: SSL analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        descriptor.quiet_summary = lambda r: (
            f"SSL: {len(r.certificates)} cert(s), {len(r.protocols)} protocol(s)"
        )

        # Certificate information
        for domain, cert_info in result.certificates.items():
            section_name = f"Certificate: {domain}"

            # Certificate status with semantic styling
            if cert_info.status == "ok" and cert_info.is_valid:
                descriptor.add_row(
                    label="Status",
                    value="Valid",
                    style_class="success",
                    icon="check",
                    severity="info",
                    section_name=section_name,
                    verbosity=VerbosityLevel.NORMAL,
                )
            elif cert_info.status == "mismatch":
                descriptor.add_row(
                    label="Status",
                    value="Hostname Mismatch",
                    style_class="error",
                    icon="cross",
                    severity="error",
                    section_name=section_name,
                    verbosity=VerbosityLevel.NORMAL,
                )
            elif cert_info.status == "none":
                descriptor.add_row(
                    label="Status",
                    value="No Certificate",
                    style_class="error",
                    icon="cross",
                    severity="error",
                    section_name=section_name,
                    verbosity=VerbosityLevel.NORMAL,
                )
            else:
                descriptor.add_row(
                    label="Status",
                    value="Invalid",
                    style_class="error",
                    icon="cross",
                    severity="error",
                    section_name=section_name,
                    verbosity=VerbosityLevel.NORMAL,
                )

            # Expiry information with semantic styling
            if cert_info.days_until_expiry >= 0:
                # Determine style based on days until expiry
                if cert_info.days_until_expiry < 7:
                    expiry_style = "error"
                    expiry_severity = "critical"
                elif cert_info.days_until_expiry < 30:
                    expiry_style = "warning"
                    expiry_severity = "warning"
                else:
                    expiry_style = "success"
                    expiry_severity = "info"

                descriptor.add_row(
                    label="Expires In",
                    value=f"{cert_info.days_until_expiry} days",
                    style_class=expiry_style,
                    severity=expiry_severity,
                    section_name=section_name,
                    verbosity=VerbosityLevel.NORMAL,
                )

            # Subject (verbose)
            if cert_info.subject:
                subject_str = ", ".join(f"{k}={v}" for k, v in cert_info.subject.items())
                descriptor.add_row(
                    label="Subject",
                    value=subject_str,
                    style_class="info",
                    section_name=section_name,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            # Issuer (verbose)
            if cert_info.issuer:
                issuer_str = ", ".join(f"{k}={v}" for k, v in cert_info.issuer.items())
                descriptor.add_row(
                    label="Issuer",
                    value=issuer_str,
                    style_class="info",
                    section_name=section_name,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            # SAN - Subject Alternative Names (verbose)
            if cert_info.san:
                descriptor.add_row(
                    label="Subject Alt Names",
                    value=cert_info.san,
                    section_type="list",
                    style_class="info",
                    section_name=section_name,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            # Serial number (verbose)
            if cert_info.serial_number:
                descriptor.add_row(
                    label="Serial Number",
                    value=cert_info.serial_number,
                    style_class="muted",
                    section_name=section_name,
                    verbosity=VerbosityLevel.VERBOSE,
                )

            # Validity dates (verbose)
            descriptor.add_row(
                label="Valid From",
                value=cert_info.not_before.strftime("%Y-%m-%d %H:%M:%S"),
                style_class="info",
                section_name=section_name,
                verbosity=VerbosityLevel.VERBOSE,
            )

            descriptor.add_row(
                label="Valid Until",
                value=cert_info.not_after.strftime("%Y-%m-%d %H:%M:%S"),
                style_class="info",
                section_name=section_name,
                verbosity=VerbosityLevel.VERBOSE,
            )

        # TLS Protocols
        if result.protocols:
            # Determine protocol status with semantic styling
            has_tls13 = "TLSv1.3" in result.protocols
            has_old_tls = "TLSv1.0" in result.protocols or "TLSv1.1" in result.protocols

            protocol_style = (
                "success"
                if has_tls13 and not has_old_tls
                else ("warning" if has_old_tls else "info")
            )

            descriptor.add_row(
                label="TLS Protocols",
                value=", ".join(result.protocols),
                style_class=protocol_style,
                section_name="TLS Configuration",
                verbosity=VerbosityLevel.NORMAL,
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

    def to_dict(self, result: SSLAnalysisResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: SSL analysis result

        Returns:
            JSON-serializable dict
        """
        # Convert certificate info to dict
        certificates_dict = {}
        for domain, cert_info in result.certificates.items():
            certificates_dict[domain] = {
                "subject": cert_info.subject,
                "issuer": cert_info.issuer,
                "version": cert_info.version,
                "serial_number": cert_info.serial_number,
                "not_before": cert_info.not_before.isoformat(),
                "not_after": cert_info.not_after.isoformat(),
                "san": cert_info.san,
                "is_valid": cert_info.is_valid,
                "days_until_expiry": cert_info.days_until_expiry,
                "status": cert_info.status,
                "errors": cert_info.errors,
                "warnings": cert_info.warnings,
            }

        return {
            "domain": result.domain,
            "port": result.port,
            "certificates": certificates_dict,
            "protocols": result.protocols,
            "ciphers": result.ciphers,
            "errors": result.errors,
            "warnings": result.warnings,
        }
