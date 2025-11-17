"""WHOIS analysis module for checking domain registration information."""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import whois

from .base import BaseAnalysisResult, BaseAnalyzer

logger = logging.getLogger(__name__)

# Default expiry warning threshold (in days)
DEFAULT_WHOIS_EXPIRY_WARNING_DAYS = 30
DEFAULT_WHOIS_EXPIRY_CRITICAL_DAYS = 7


@dataclass
class WhoisAnalysisResult(BaseAnalysisResult):
    """Results from WHOIS analysis."""

    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    registrant_name: str | None = None
    registrant_organization: str | None = None
    admin_name: str | None = None
    admin_email: str | None = None
    nameservers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    days_until_expiry: int | None = None


class WhoisAnalyzer(BaseAnalyzer[WhoisAnalysisResult]):
    """Analyzes WHOIS registration information for a domain."""

    def __init__(
        self,
        expiry_warning_days: int = DEFAULT_WHOIS_EXPIRY_WARNING_DAYS,
        expiry_critical_days: int = DEFAULT_WHOIS_EXPIRY_CRITICAL_DAYS,
    ):
        """
        Initialize WHOIS analyzer.

        Args:
            expiry_warning_days: Days before expiry to show warning
            expiry_critical_days: Days before expiry to show critical error
        """
        self.expiry_warning_days = expiry_warning_days
        self.expiry_critical_days = expiry_critical_days

    def analyze(self, domain: str) -> WhoisAnalysisResult:
        """
        Perform WHOIS analysis of a domain.

        Args:
            domain: The domain to analyze

        Returns:
            WhoisAnalysisResult with registration information
        """
        logger.info(f"Starting WHOIS analysis for {domain}")
        result = WhoisAnalysisResult(domain=domain)

        # Normalize domain - remove protocol and www prefix
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")
        if domain.startswith("www."):
            domain = domain[4:]

        try:
            # Query WHOIS
            whois_data = whois.whois(domain)

            if not whois_data:
                result.errors.append("WHOIS query returned no data")
                return result

            # Extract registrar
            result.registrar = self._extract_string_field(whois_data, "registrar")

            # Extract dates
            result.creation_date = self._extract_date_field(whois_data, "creation_date")
            result.expiration_date = self._extract_date_field(whois_data, "expiration_date")
            result.updated_date = self._extract_date_field(whois_data, "updated_date")

            # Calculate days until expiry and check thresholds
            if result.expiration_date:
                now = datetime.now()
                # Handle timezone-aware datetimes
                if result.expiration_date.tzinfo is not None:
                    from datetime import timezone

                    now = datetime.now(timezone.utc)

                days_until_expiry = (result.expiration_date - now).days
                result.days_until_expiry = days_until_expiry

                if days_until_expiry < 0:
                    result.errors.append(f"Domain has expired {abs(days_until_expiry)} days ago")
                elif days_until_expiry <= self.expiry_critical_days:
                    result.errors.append(f"Domain expires in {days_until_expiry} days (critical)")
                elif days_until_expiry <= self.expiry_warning_days:
                    result.warnings.append(f"Domain expires in {days_until_expiry} days")
            else:
                result.warnings.append("Expiration date not available in WHOIS data")

            # Extract registrant information
            # Try multiple possible field names (different TLDs use different keys)
            result.registrant_name = (
                self._extract_string_field(whois_data, "name")
                or self._extract_string_field(whois_data, "registrant_name")
                or self._extract_string_field(whois_data, "registrant")
            )
            result.registrant_organization = (
                self._extract_string_field(whois_data, "org")
                or self._extract_string_field(whois_data, "registrant_organization")
                or self._extract_string_field(whois_data, "registrant_org")
            )

            # Extract admin contact (may not be available due to GDPR)
            result.admin_name = self._extract_string_field(
                whois_data, "admin_name"
            ) or self._extract_string_field(whois_data, "admin")
            result.admin_email = self._extract_string_field(
                whois_data, "admin_email"
            ) or self._extract_string_field(whois_data, "admin_mail")

            # Extract nameservers
            nameservers = whois_data.get("name_servers")
            if nameservers:
                if isinstance(nameservers, list):
                    result.nameservers = [
                        ns.lower() if isinstance(ns, str) else str(ns) for ns in nameservers
                    ]
                elif isinstance(nameservers, str):
                    result.nameservers = [nameservers.lower()]

            # Extract status
            status = whois_data.get("status")
            if status:
                if isinstance(status, list):
                    result.status = [s if isinstance(s, str) else str(s) for s in status]
                elif isinstance(status, str):
                    result.status = [status]

            # Validate required fields
            if not result.registrar:
                result.warnings.append("Registrar information not available")

            logger.debug(f"WHOIS analysis completed for {domain}")

        except Exception as e:
            error_msg = str(e).lower()
            # Check if it's a WHOIS-specific error (domain not found)
            if (
                "no match" in error_msg
                or "not found" in error_msg
                or "no entries found" in error_msg
            ):
                result.errors.append("Domain not found in WHOIS database")
                logger.error(f"WHOIS domain not found: {domain}")
            # Check if it's a connection/timeout error
            elif "timed out" in error_msg or "connection" in error_msg:
                result.warnings.append("WHOIS query timed out or connection failed")
                logger.warning(f"WHOIS connection error for {domain}: {e}")
            # Other errors
            else:
                result.errors.append(f"WHOIS analysis failed: {e}")
                logger.error(f"Unexpected error in WHOIS analysis for {domain}: {e}")

        return result

    def _extract_string_field(self, whois_data: Any, field: str) -> str | None:
        """
        Extract a string field from WHOIS data.

        Args:
            whois_data: WHOIS data object
            field: Field name to extract

        Returns:
            String value or None if not available
        """
        value = whois_data.get(field)
        if value is None:
            return None

        # Handle lists (take first element)
        if isinstance(value, list):
            if len(value) > 0:
                value = value[0]
            else:
                return None

        # Convert to string and clean
        if isinstance(value, str):
            value = value.strip()
            return value if value else None

        return str(value) if value else None

    def _extract_date_field(self, whois_data: Any, field: str) -> datetime | None:
        """
        Extract a date field from WHOIS data.

        Args:
            whois_data: WHOIS data object
            field: Field name to extract

        Returns:
            datetime object or None if not available
        """
        value = whois_data.get(field)
        if value is None:
            return None

        # Handle lists (take first element)
        if isinstance(value, list):
            if len(value) > 0:
                value = value[0]
            else:
                return None

        # Convert to datetime if it's not already
        if isinstance(value, datetime):
            return value
        elif isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                logger.warning(f"Could not parse date string: {value}")
                return None

        return None
