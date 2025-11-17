"""SSL/TLS certificate analysis module."""

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime

from ..constants import (
    DEFAULT_SSL_EXPIRY_CRITICAL_DAYS,
    DEFAULT_SSL_EXPIRY_WARNING_DAYS,
    DEFAULT_SSL_PORT,
    DEFAULT_SSL_TIMEOUT,
)
from .base import BaseAnalysisResult, BaseAnalyzer

logger = logging.getLogger(__name__)


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
class SSLAnalysisResult(BaseAnalysisResult):
    """Results from SSL/TLS analysis."""

    port: int = DEFAULT_SSL_PORT
    certificates: dict[str, CertificateInfo] = field(default_factory=dict)
    protocols: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)


class SSLAnalyzer(BaseAnalyzer[SSLAnalysisResult]):
    """Analyzes SSL/TLS certificates and configurations."""

    def __init__(
        self,
        timeout: float = DEFAULT_SSL_TIMEOUT,
        cert_expiry_warning_days: int = DEFAULT_SSL_EXPIRY_WARNING_DAYS,
        cert_expiry_critical_days: int = DEFAULT_SSL_EXPIRY_CRITICAL_DAYS,
    ):
        """
        Initialize SSL analyzer.

        Args:
            timeout: Connection timeout in seconds
            cert_expiry_warning_days: Days before expiry to show warning
            cert_expiry_critical_days: Days before expiry to show critical error
        """
        self.timeout = timeout
        self.cert_expiry_warning_days = cert_expiry_warning_days
        self.cert_expiry_critical_days = cert_expiry_critical_days

    def analyze(self, domain: str, port: int = DEFAULT_SSL_PORT) -> SSLAnalysisResult:
        """
        Perform comprehensive SSL/TLS analysis of a domain.

        Args:
            domain: The domain to analyze
            port: The port to check (default: 443)

        Returns:
            SSLAnalysisResult with certificate and SSL information
        """
        logger.info(f"Starting SSL analysis for {domain}:{port}")
        result = SSLAnalysisResult(domain=domain, port=port)

        # Normalize domain
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

        # Check domain and www.domain
        domains_to_check = [domain]
        if not domain.startswith("www."):
            domains_to_check.append(f"www.{domain}")

        for check_domain in domains_to_check:
            cert_info = self._get_certificate_info(check_domain, port)
            if cert_info:
                result.certificates[check_domain] = cert_info

                # Add certificate warnings/errors to result
                result.errors.extend(cert_info.errors)
                result.warnings.extend(cert_info.warnings)

        # Check supported protocols and ciphers
        self._check_ssl_config(domain, port, result)

        return result

    def _get_certificate_info(self, domain: str, port: int) -> CertificateInfo | None:
        """
        Get SSL certificate information for a domain.

        Args:
            domain: The domain to check
            port: The port to check

        Returns:
            CertificateInfo object or None if failed
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()

            # Connect and get certificate
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
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
                    self._validate_certificate(cert_info, domain)

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
            logger.error(f"Connection timeout for {domain}:{port}")
            return None

        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {domain}: {e}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error getting certificate for {domain}:{port}: {e}")
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

    def _validate_certificate(self, cert_info: CertificateInfo, domain: str) -> None:
        """
        Validate certificate and add warnings/errors.

        Args:
            cert_info: Certificate information to validate
            domain: The domain being checked
        """
        # Check expiry
        if cert_info.days_until_expiry < 0:
            cert_info.is_valid = False
            cert_info.errors.append(
                f"Certificate expired {abs(cert_info.days_until_expiry)} days ago"
            )
        elif cert_info.days_until_expiry < self.cert_expiry_critical_days:
            cert_info.warnings.append(f"Certificate expires in {cert_info.days_until_expiry} days")
        elif cert_info.days_until_expiry < self.cert_expiry_warning_days:
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

    def _check_ssl_config(self, domain: str, port: int, result: SSLAnalysisResult) -> None:
        """
        Check SSL/TLS configuration (protocols, ciphers).

        Args:
            domain: The domain to check
            port: The port to check
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

                    with socket.create_connection((domain, port), timeout=self.timeout) as sock:
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
            logger.error(f"Error checking SSL configuration for {domain}:{port}: {e}")
            result.errors.append(f"Error checking SSL configuration: {str(e)}")
