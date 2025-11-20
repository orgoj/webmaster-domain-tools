"""Universal site verification analyzer - supports Google, Facebook, Pinterest, etc.

This analyzer detects site verification codes from meta tags, DNS TXT records,
and HTML files. It supports multiple verification services (Google, Bing, Facebook, etc.)
and can auto-detect verification IDs. Also includes legacy Google tracking code detection.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.resolver
import httpx
from pydantic import Field

from ..constants import (
    DEFAULT_USER_AGENT,
    TRACKING_PATTERNS,
)
from ..core.registry import registry
from .base import BaseAnalysisResult, BaseAnalyzer
from .dns_utils import create_resolver
from .protocol import (
    AnalyzerConfig,
    OutputDescriptor,
    VerbosityLevel,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class VerificationConfig(AnalyzerConfig):
    """Site verification analyzer configuration."""

    services: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of verification service configurations (ServiceConfig as dicts)",
    )
    user_agent: str = Field(
        default=DEFAULT_USER_AGENT, description="User agent string for HTTP requests"
    )
    nameservers: list[str] | None = Field(
        default=None, description="DNS nameservers to use for verification checks"
    )


# ============================================================================
# Service Configuration & Result Models
# ============================================================================


@dataclass
class ServiceConfig:
    """Configuration for a single verification service."""

    name: str
    ids: list[str]
    dns_pattern: str | None = None
    file_pattern: str | None = None
    meta_name: str | None = None
    auto_detect: bool = True


@dataclass
class VerificationResult:
    """Result for a single verification ID."""

    service: str  # Service name (Google, Facebook, etc.)
    verification_id: str
    found: bool = False
    methods: list[str] = field(default_factory=list)  # DNS, file, meta tag
    errors: list[str] = field(default_factory=list)


@dataclass
class TrackingCode:
    """Detected tracking code (legacy - Google specific)."""

    name: str  # GTM, GA4, GAds, etc.
    code: str  # The actual code (e.g., GTM-XXXXXX)
    location: str  # Where it was found (e.g., "HTML head", "HTML body")


@dataclass
class ServiceResult:
    """Results for a single service."""

    service: str
    verification_results: list[VerificationResult] = field(default_factory=list)
    detected_verification_ids: list[VerificationResult] = field(default_factory=list)


@dataclass
class SiteVerificationAnalysisResult(BaseAnalysisResult):
    """Results from site verification analysis."""

    html_content: str | None = None  # Cached HTML content
    html_fetch_error: str | None = None

    # Results per service
    service_results: list[ServiceResult] = field(default_factory=list)

    # Tracking codes (legacy - Google specific)
    tracking_codes: list[TrackingCode] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class SiteVerificationAnalyzer(BaseAnalyzer[SiteVerificationAnalysisResult]):
    """
    Universal site verification analyzer supporting multiple services.

    Detects verification codes from Google, Bing, Facebook, Pinterest, and other
    services via meta tags, DNS TXT records, and HTML files. Also detects Google
    tracking codes (GTM, GA4, etc.).

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (VerificationConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "verification"
    name = "Site Verification"
    description = "Detect site verification codes and tracking codes"
    category = "seo"
    icon = "check"
    config_class = VerificationConfig
    depends_on = ["http"]  # Needs HTTP result for final URL

    def __init__(self):
        """
        Initialize site verification analyzer.

        Configuration is passed to analyze() method per new protocol.
        Internal state is initialized on each analyze() call.
        """
        pass

    def analyze(self, domain: str, config: VerificationConfig) -> SiteVerificationAnalysisResult:
        """
        Perform comprehensive site verification analysis for all configured services.

        Args:
            domain: The domain to analyze
            config: Verification analyzer configuration

        Returns:
            SiteVerificationAnalysisResult with verification and tracking information
        """
        logger.info(f"Starting site verification analysis for {domain}")
        result = SiteVerificationAnalysisResult(domain=domain)

        # Initialize instance variables from config
        self.timeout = config.timeout
        self.user_agent = config.user_agent

        # Precompile regex patterns for tracking codes (Google specific - legacy)
        self.compiled_tracking_patterns = {
            name: (re.compile(pattern), description)
            for name, (pattern, description) in TRACKING_PATTERNS.items()
        }

        # Create DNS resolver using centralized utility
        self.resolver = create_resolver(nameservers=config.nameservers, timeout=config.timeout)

        # Convert service dicts to ServiceConfig objects
        services = []
        for service_dict in config.services:
            services.append(ServiceConfig(**service_dict))

        # Normalize domain
        domain = domain.rstrip(".")

        # Fetch HTML content once (will be used for multiple checks)
        # TODO: Get final URL from HTTP analyzer via context
        self._fetch_html_content(domain, result, preferred_url=None)

        # Process each service
        for service_config in services:
            service_result = self._analyze_service(domain, service_config, result)
            result.service_results.append(service_result)

        # Detect tracking codes in HTML (Google specific - legacy)
        if result.html_content:
            self._detect_tracking_codes(result)

        return result

    def _analyze_service(
        self,
        domain: str,
        service_config: ServiceConfig,
        main_result: SiteVerificationAnalysisResult,
    ) -> ServiceResult:
        """
        Analyze verification for a single service.

        Args:
            domain: Domain to check
            service_config: Service configuration
            main_result: Main result object (for accessing HTML content)

        Returns:
            ServiceResult with verification results
        """
        logger.debug(f"Analyzing {service_config.name} verification")
        service_result = ServiceResult(service=service_config.name)

        # Check each configured ID
        for verification_id in service_config.ids:
            verification = self._check_verification(
                domain, service_config, verification_id, main_result
            )
            service_result.verification_results.append(verification)

        # Auto-detect verification IDs if enabled
        if service_config.auto_detect:
            detected = self._detect_verification_ids(domain, service_config, main_result)
            service_result.detected_verification_ids = detected

        return service_result

    def _check_verification(
        self,
        domain: str,
        service_config: ServiceConfig,
        verification_id: str,
        main_result: SiteVerificationAnalysisResult,
    ) -> VerificationResult:
        """
        Check all verification methods for a given verification ID.

        Args:
            domain: Domain to check
            service_config: Service configuration
            verification_id: Verification ID to check
            main_result: Main result object (for accessing HTML content)

        Returns:
            VerificationResult with found methods
        """
        verification = VerificationResult(
            service=service_config.name, verification_id=verification_id
        )

        # Check DNS TXT record if pattern provided
        if service_config.dns_pattern:
            if self._check_verification_dns(domain, service_config.dns_pattern, verification_id):
                verification.found = True
                verification.methods.append("DNS TXT record")
                logger.debug(f"{service_config.name} verification {verification_id} found via DNS")

        # Check HTML file if pattern provided
        if service_config.file_pattern:
            if self._check_verification_file(domain, service_config.file_pattern, verification_id):
                verification.found = True
                verification.methods.append("HTML file")
                logger.debug(
                    f"{service_config.name} verification {verification_id} found via HTML file"
                )

        # Check meta tag in HTML if meta_name provided
        if service_config.meta_name and main_result.html_content:
            if self._check_verification_meta(
                main_result.html_content, service_config.meta_name, verification_id
            ):
                verification.found = True
                verification.methods.append("Meta tag")
                logger.debug(
                    f"{service_config.name} verification {verification_id} found via meta tag"
                )

        if not verification.found:
            verification.errors.append(
                f"Verification ID {verification_id} not found via any method"
            )

        return verification

    def _check_verification_dns(self, domain: str, dns_pattern: str, verification_id: str) -> bool:
        """
        Check for verification via DNS TXT record.

        Args:
            domain: Domain to check
            dns_pattern: DNS TXT pattern with {id} placeholder
            verification_id: Verification ID to look for

        Returns:
            True if verification ID found in DNS TXT records
        """
        expected_value = dns_pattern.replace("{id}", verification_id)

        try:
            answers = self.resolver.resolve(domain, "TXT")

            for rdata in answers:
                txt_value = str(rdata).strip('"')
                # Must match exactly (not substring)
                if txt_value == expected_value:
                    return True

        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logger.debug(f"No TXT records found for {domain}")
        except Exception as e:
            logger.debug(f"Error checking DNS TXT for {domain}: {e}")

        return False

    def _check_verification_file(
        self, domain: str, file_pattern: str, verification_id: str
    ) -> bool:
        """
        Check for verification via HTML file.

        Args:
            domain: Domain to check
            file_pattern: File path pattern with {id} placeholder
            verification_id: Verification ID (used in filename)

        Returns:
            True if verification file exists and is accessible
        """
        # Build file URL from pattern
        file_path = file_pattern.replace("{id}", verification_id)
        url = f"https://{domain}/{file_path}"

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                verify=True,
            ) as client:
                response = client.get(
                    url,
                    headers={"User-Agent": self.user_agent},
                )

                # File should exist and return 200
                if response.status_code == 200:
                    return True

        except Exception as e:
            logger.debug(f"Error checking verification file {url}: {e}")

        return False

    def _check_verification_meta(
        self, html_content: str, meta_name: str, verification_id: str
    ) -> bool:
        """
        Check for verification via meta tag in HTML.

        Args:
            html_content: HTML content to search
            meta_name: Meta tag name attribute value
            verification_id: Verification ID to look for

        Returns:
            True if verification meta tag found
        """
        # Look for: <meta name="xxx" content="verification_id">
        pattern = re.compile(
            r'<meta\s+name=["\']'
            + re.escape(meta_name)
            + r'["\']\s+content=["\']'
            + re.escape(verification_id)
            + r'["\']',
            re.IGNORECASE,
        )

        # Also check reversed attribute order
        pattern_reversed = re.compile(
            r'<meta\s+content=["\']'
            + re.escape(verification_id)
            + r'["\']\s+name=["\']'
            + re.escape(meta_name)
            + r'["\']',
            re.IGNORECASE,
        )

        return bool(pattern.search(html_content) or pattern_reversed.search(html_content))

    def _detect_verification_ids(
        self,
        domain: str,
        service_config: ServiceConfig,
        main_result: SiteVerificationAnalysisResult,
    ) -> list[VerificationResult]:
        """
        Auto-detect verification IDs from DNS and HTML for a service.
        Only detects IDs that aren't already in configured IDs.

        Args:
            domain: Domain to check
            service_config: Service configuration
            main_result: Main result object (for accessing HTML content)

        Returns:
            List of detected VerificationResult
        """
        detected_ids: set[str] = set()

        # Extract IDs from DNS TXT records if pattern provided
        if service_config.dns_pattern:
            # Build regex pattern from dns_pattern
            # e.g., "google-site-verification={id}" -> "google-site-verification=([a-zA-Z0-9_-]+)"
            pattern_parts = service_config.dns_pattern.split("{id}")
            if len(pattern_parts) == 2:
                prefix = re.escape(pattern_parts[0])
                suffix = re.escape(pattern_parts[1])
                dns_regex = f"{prefix}([a-zA-Z0-9_-]+){suffix}"

                try:
                    answers = self.resolver.resolve(domain, "TXT")
                    for rdata in answers:
                        txt_value = str(rdata).strip('"')
                        match = re.match(dns_regex, txt_value)
                        if match:
                            verification_id = match.group(1)
                            # Only add if not in configured IDs
                            if verification_id not in service_config.ids:
                                detected_ids.add(verification_id)
                                logger.debug(
                                    f"Auto-detected {service_config.name} verification ID in DNS: {verification_id}"
                                )
                except dns.resolver.NXDOMAIN:
                    logger.debug(f"Domain {domain} does not exist")
                except dns.resolver.NoAnswer:
                    logger.debug(f"No TXT records found for {domain}")
                except Exception as e:
                    logger.debug(f"Error checking DNS TXT for verification IDs: {e}")

        # Extract IDs from HTML meta tags if meta_name provided
        if service_config.meta_name and main_result.html_content:
            # Look for: <meta name="xxx" content="XXXXX">
            pattern = re.compile(
                r'<meta\s+name=["\']'
                + re.escape(service_config.meta_name)
                + r'["\']\s+content=["\']([a-zA-Z0-9_-]+)["\']',
                re.IGNORECASE,
            )
            # Also check reversed attribute order
            pattern_reversed = re.compile(
                r'<meta\s+content=["\']([a-zA-Z0-9_-]+)["\']\s+name=["\']'
                + re.escape(service_config.meta_name)
                + r'["\']',
                re.IGNORECASE,
            )

            for match in pattern.finditer(main_result.html_content):
                verification_id = match.group(1)
                if verification_id not in service_config.ids:
                    detected_ids.add(verification_id)
                    logger.debug(
                        f"Auto-detected {service_config.name} verification ID in HTML meta: {verification_id}"
                    )

            for match in pattern_reversed.finditer(main_result.html_content):
                verification_id = match.group(1)
                if verification_id not in service_config.ids:
                    detected_ids.add(verification_id)
                    logger.debug(
                        f"Auto-detected {service_config.name} verification ID in HTML meta: {verification_id}"
                    )

        # Create verification results for detected IDs
        detected_results = []
        for verification_id in sorted(detected_ids):
            verification = self._check_verification(
                domain, service_config, verification_id, main_result
            )
            detected_results.append(verification)

        return detected_results

    def _fetch_html_content(
        self,
        domain: str,
        result: SiteVerificationAnalysisResult,
        preferred_url: str | None = None,
    ) -> None:
        """
        Fetch HTML content from the domain or specific URL.

        Args:
            domain: Domain to fetch
            result: Result object to store HTML content
            preferred_url: Optional specific URL to fetch (e.g., from redirect analysis).
                          If provided, only this URL will be tried.
        """
        # If preferred URL is provided, use it directly
        if preferred_url:
            try:
                with httpx.Client(
                    timeout=self.timeout,
                    follow_redirects=False,  # URL is already final
                    verify=True,
                ) as client:
                    response = client.get(
                        preferred_url,
                        headers={"User-Agent": self.user_agent},
                    )

                    if response.status_code == 200:
                        result.html_content = response.text
                        logger.debug(f"Successfully fetched HTML content from {preferred_url}")
                        return
                    else:
                        error_msg = f"HTTP {response.status_code}"
                        result.html_fetch_error = error_msg
                        logger.debug(f"Failed to fetch HTML from {preferred_url}: {error_msg}")
                        return

            except Exception as e:
                error_msg = f"Failed to fetch: {str(e)}"
                result.html_fetch_error = error_msg
                logger.debug(f"Error fetching HTML from {preferred_url}: {e}")
                return

        # No preferred URL - try HTTPS first, then HTTP
        https_url = f"https://{domain}"
        https_error = None

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                verify=True,
            ) as client:
                response = client.get(
                    https_url,
                    headers={"User-Agent": self.user_agent},
                )

                if response.status_code == 200:
                    result.html_content = response.text
                    logger.debug(f"Successfully fetched HTML content from {https_url}")
                    return  # Success, no need to try HTTP
                else:
                    https_error = f"HTTP {response.status_code}"
                    logger.debug(f"HTTPS returned {response.status_code}, will try HTTP")

        except httpx.ConnectError as e:
            # ConnectError includes SSL errors, connection refused, etc.
            https_error = f"Connection error: {str(e)}"
            logger.debug(f"HTTPS connection failed, will try HTTP: {e}")

        except httpx.TimeoutException:
            https_error = "Timeout"
            logger.debug("HTTPS timeout, will try HTTP")

        except Exception as e:
            https_error = f"Error: {str(e)}"
            logger.debug(f"HTTPS failed, will try HTTP: {e}")

        # HTTPS failed, try HTTP
        http_url = f"http://{domain}"
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.get(
                    http_url,
                    headers={"User-Agent": self.user_agent},
                )

                if response.status_code == 200:
                    result.html_content = response.text
                    logger.debug(f"Successfully fetched HTML content from {http_url}")
                    return  # Success
                else:
                    error_msg = f"HTTP {response.status_code} (HTTPS: {https_error})"
                    result.html_fetch_error = error_msg
                    logger.debug(error_msg)

        except httpx.ConnectError as e:
            error_msg = f"Connection error on both HTTPS and HTTP: {str(e)}"
            result.html_fetch_error = error_msg
            logger.debug(error_msg)

        except httpx.TimeoutException:
            error_msg = "Timeout on both HTTPS and HTTP"
            result.html_fetch_error = error_msg
            logger.debug(error_msg)

        except Exception as e:
            error_msg = f"Error fetching HTML (HTTPS: {https_error}, HTTP: {str(e)})"
            result.html_fetch_error = error_msg
            logger.debug(error_msg)

    def _detect_tracking_codes(self, result: SiteVerificationAnalysisResult) -> None:
        """
        Detect tracking codes in HTML content (Google specific - legacy).

        Args:
            result: Result object with HTML content and tracking codes list
        """
        if not result.html_content:
            return

        html = result.html_content

        # Track found codes to avoid duplicates
        found_codes: set[tuple[str, str]] = set()

        for name, (compiled_pattern, description) in self.compiled_tracking_patterns.items():
            matches = compiled_pattern.finditer(html)

            for match in matches:
                code = match.group(0)
                code_key = (name, code)

                if code_key not in found_codes:
                    # Determine location (head vs body)
                    location = self._determine_code_location(html, match.start())

                    tracking_code = TrackingCode(
                        name=description,
                        code=code,
                        location=location,
                    )
                    result.tracking_codes.append(tracking_code)
                    found_codes.add(code_key)
                    logger.debug(f"Found tracking code: {description} ({code}) in {location}")

    def _determine_code_location(self, html: str, position: int) -> str:
        """
        Determine where in HTML the code was found.

        Args:
            html: Full HTML content
            position: Position where code was found

        Returns:
            Location description (e.g., "HTML head", "HTML body")
        """
        # Find <head> and </head> positions
        head_start = html.lower().find("<head")
        head_end = html.lower().find("</head>")

        # Find <body> and </body> positions
        body_start = html.lower().find("<body")
        body_end = html.lower().find("</body>")

        if head_start != -1 and head_end != -1:
            if head_start <= position <= head_end:
                return "HTML head"

        if body_start != -1 and body_end != -1:
            if body_start <= position <= body_end:
                return "HTML body"

        return "HTML"

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def describe_output(self, result: SiteVerificationAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: Site verification analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        def quiet_summary(r: SiteVerificationAnalysisResult) -> str:
            total_verified = sum(
                len([v for v in sr.verification_results if v.found]) for sr in r.service_results
            )
            total_detected = sum(len(sr.detected_verification_ids) for sr in r.service_results)
            if total_verified > 0 or total_detected > 0:
                return f"Verification: {total_verified} verified, {total_detected} detected"
            return "Verification: None"

        descriptor.quiet_summary = quiet_summary

        # HTML fetch error
        if result.html_fetch_error:
            descriptor.add_row(
                label="HTML Fetch",
                value=f"Failed: {result.html_fetch_error}",
                style_class="warning",
                severity="warning",
                icon="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Service results
        for service_result in result.service_results:
            section_name = f"{service_result.service} Verification"

            # Configured verification IDs
            if service_result.verification_results:
                for verification in service_result.verification_results:
                    if verification.found:
                        methods_str = ", ".join(verification.methods)
                        descriptor.add_row(
                            label=verification.verification_id,
                            value=f"Verified via {methods_str}",
                            style_class="success",
                            severity="info",
                            icon="check",
                            section_name=section_name,
                            verbosity=VerbosityLevel.NORMAL,
                        )
                    else:
                        descriptor.add_row(
                            label=verification.verification_id,
                            value="Not found",
                            style_class="error",
                            severity="error",
                            icon="cross",
                            section_name=section_name,
                            verbosity=VerbosityLevel.VERBOSE,
                        )

            # Auto-detected verification IDs
            if service_result.detected_verification_ids:
                for verification in service_result.detected_verification_ids:
                    methods_str = ", ".join(verification.methods)
                    descriptor.add_row(
                        label=f"Detected: {verification.verification_id}",
                        value=f"Found via {methods_str}",
                        style_class="info",
                        severity="info",
                        icon="info",
                        section_name=section_name,
                        subsection="Auto-detected",
                        verbosity=VerbosityLevel.NORMAL,
                    )

        # Tracking codes (legacy Google-specific)
        if result.tracking_codes:
            for tracking_code in result.tracking_codes:
                descriptor.add_row(
                    label=tracking_code.name,
                    value=f"{tracking_code.code} ({tracking_code.location})",
                    style_class="info",
                    severity="info",
                    icon="info",
                    section_name="Tracking Codes",
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

    def to_dict(self, result: SiteVerificationAnalysisResult) -> dict[str, Any]:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Site verification analysis result

        Returns:
            JSON-serializable dict
        """
        # Convert service results
        service_results_dict = []
        for service_result in result.service_results:
            verification_results_dict = []
            for verification in service_result.verification_results:
                verification_results_dict.append(
                    {
                        "service": verification.service,
                        "verification_id": verification.verification_id,
                        "found": verification.found,
                        "methods": verification.methods,
                        "errors": verification.errors,
                    }
                )

            detected_ids_dict = []
            for verification in service_result.detected_verification_ids:
                detected_ids_dict.append(
                    {
                        "service": verification.service,
                        "verification_id": verification.verification_id,
                        "found": verification.found,
                        "methods": verification.methods,
                        "errors": verification.errors,
                    }
                )

            service_results_dict.append(
                {
                    "service": service_result.service,
                    "verification_results": verification_results_dict,
                    "detected_verification_ids": detected_ids_dict,
                }
            )

        # Convert tracking codes
        tracking_codes_dict = []
        for tracking_code in result.tracking_codes:
            tracking_codes_dict.append(
                {
                    "name": tracking_code.name,
                    "code": tracking_code.code,
                    "location": tracking_code.location,
                }
            )

        return {
            "domain": result.domain,
            "html_fetch_error": result.html_fetch_error,
            "service_results": service_results_dict,
            "tracking_codes": tracking_codes_dict,
            "errors": result.errors,
            "warnings": result.warnings,
        }
