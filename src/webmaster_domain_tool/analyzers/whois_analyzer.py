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
    registrant_email: str | None = None
    admin_name: str | None = None
    admin_email: str | None = None
    admin_contact: str | None = None  # For .cz admin-c handle
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

            # Extract registrant email
            result.registrant_email = (
                self._extract_string_field(whois_data, "registrant_email")
                or self._extract_string_field(whois_data, "email")
                or self._extract_string_field(whois_data, "emails")
            )

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

            # Special handling for .cz domains
            # .cz WHOIS has specific format that needs custom parsing
            if domain.endswith(".cz"):
                logger.debug("Applying .cz specific WHOIS parsing")
                self._parse_cz_whois(whois_data, result)

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

    def _parse_cz_whois(self, whois_data: Any, result: WhoisAnalysisResult) -> None:
        """
        Parse .cz specific WHOIS data from raw text.

        .cz domains have a specific format where the registrar in the domain section
        is different from registrars in contact sections. We need to parse the raw
        text to extract the correct values.

        Args:
            whois_data: WHOIS data object (may contain 'text' attribute)
            result: Result object to populate
        """
        # Try to get raw WHOIS text
        raw_text = None
        if hasattr(whois_data, "text"):
            raw_text = whois_data.text
        elif isinstance(whois_data, dict) and "text" in whois_data:
            raw_text = whois_data["text"]

        if not raw_text:
            logger.debug("No raw WHOIS text available for .cz parsing")
            return

        # Clear fields that may contain handles instead of actual names
        # These will be re-populated from contact sections with proper values
        result.registrant_name = None
        result.registrant_organization = None
        result.admin_name = None

        lines = raw_text.split("\n")
        in_domain_section = False  # Not in domain section yet
        in_contact_section = False
        in_nsset_section = False
        in_keyset_section = False
        current_contact = None
        registrant_handle = None

        for line in lines:
            line = line.strip()

            # Skip comments (but don't change section state)
            if line.startswith("%"):
                continue

            # Empty line ends current section
            if not line:
                in_domain_section = False
                in_contact_section = False
                in_nsset_section = False
                in_keyset_section = False
                continue

            # Detect start of domain section
            if line.startswith("domain:"):
                in_domain_section = True
                in_contact_section = False
                in_nsset_section = False
                in_keyset_section = False
                continue

            # Detect section boundaries - contact: always starts a new section
            if line.startswith("contact:"):
                in_domain_section = False
                in_contact_section = True
                in_nsset_section = False
                in_keyset_section = False
                # Extract contact handle
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current_contact = parts[1].strip()
                continue

            # nsset: and keyset: start new sections (after domain section ends with blank line)
            if line.startswith("nsset:"):
                in_domain_section = False
                in_contact_section = False
                in_nsset_section = True
                in_keyset_section = False
                continue

            if line.startswith("keyset:"):
                in_domain_section = False
                in_contact_section = False
                in_nsset_section = False
                in_keyset_section = True
                continue

            # Parse domain section fields
            if in_domain_section and ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                if key == "registrar":
                    # This is the domain's registrar, not a contact's registrar
                    result.registrar = value
                    logger.debug(f"Extracted .cz domain registrar: {value}")
                elif key == "registrant":
                    registrant_handle = value
                elif key == "admin-c":
                    result.admin_contact = value
                    logger.debug(f"Extracted .cz admin-c: {value}")

            # Parse contact section fields
            if in_contact_section and current_contact and ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                # Only extract contact details for the registrant
                if current_contact == registrant_handle:
                    if key == "e-mail":
                        result.registrant_email = value
                        logger.debug(f"Extracted .cz registrant email: {value}")
                    elif key == "name":
                        result.registrant_name = value
                        logger.debug(f"Extracted .cz registrant name: {value}")
                    elif key == "org":
                        result.registrant_organization = value
                        logger.debug(f"Extracted .cz registrant org: {value}")

                # Extract admin contact details if it matches admin-c
                if result.admin_contact and current_contact == result.admin_contact:
                    if key == "e-mail":
                        result.admin_email = value
                        logger.debug(f"Extracted .cz admin email: {value}")
                    elif key == "name":
                        result.admin_name = value
                        logger.debug(f"Extracted .cz admin name: {value}")
