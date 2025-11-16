"""Google services analyzer - site verification and tracking codes detection."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx
import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


@dataclass
class GoogleVerificationResult:
    """Result for a single Google Site Verification ID."""

    verification_id: str
    found: bool = False
    methods: list[str] = field(default_factory=list)  # DNS, file, meta tag
    errors: list[str] = field(default_factory=list)


@dataclass
class TrackingCode:
    """Detected tracking code."""

    name: str  # GTM, GA4, GAds, etc.
    code: str  # The actual code (e.g., GTM-XXXXXX)
    location: str  # Where it was found (e.g., "HTML head", "HTML body")


@dataclass
class GoogleAnalysisResult:
    """Results from Google services analysis."""

    domain: str
    html_content: str | None = None  # Cached HTML content
    html_fetch_error: str | None = None

    # Site verification results (configured to check)
    verification_results: list[GoogleVerificationResult] = field(default_factory=list)

    # Auto-detected verification IDs (found but not in config)
    detected_verification_ids: list[GoogleVerificationResult] = field(default_factory=list)

    # Tracking codes
    tracking_codes: list[TrackingCode] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class GoogleAnalyzer:
    """Analyzes Google services: site verification and tracking codes."""

    # Common tracking code patterns
    TRACKING_PATTERNS = {
        "GTM": (r"GTM-[A-Z0-9]+", "Google Tag Manager"),
        "GA4": (r"G-[A-Z0-9]+", "Google Analytics 4"),
        "GAds": (r"AW-[0-9]+", "Google Ads Conversion"),
        "UA": (r"UA-[0-9]+-[0-9]+", "Universal Analytics"),
        "Google Optimize": (r"OPT-[A-Z0-9]+", "Google Optimize"),
        "Google AdSense": (r"ca-pub-[0-9]+", "Google AdSense"),
    }

    def __init__(
        self,
        verification_ids: list[str] | None = None,
        timeout: float = 10.0,
        user_agent: str | None = None,
        nameservers: list[str] | None = None,
    ):
        """
        Initialize Google analyzer.

        Args:
            verification_ids: List of Google Site Verification IDs to check
            timeout: HTTP request timeout in seconds
            user_agent: Custom user agent string
            nameservers: DNS nameservers to use
        """
        self.verification_ids = verification_ids or []
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (compatible; WebmasterDomainTool/0.1; "
            "+https://github.com/orgoj/webmaster-domain-tool)"
        )

        # Setup DNS resolver
        try:
            self.resolver = dns.resolver.Resolver()
            if not self.resolver.nameservers:
                raise dns.resolver.NoResolverConfiguration("no nameservers")
        except (dns.resolver.NoResolverConfiguration, OSError):
            self.resolver = dns.resolver.Resolver(configure=False)
            logger.debug("System DNS not available, using public DNS servers")

        if nameservers:
            self.resolver.nameservers = nameservers
        elif not self.resolver.nameservers:
            self.resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
            logger.debug("Using fallback public DNS servers")

    def analyze(self, domain: str) -> GoogleAnalysisResult:
        """
        Perform comprehensive Google services analysis.

        Args:
            domain: The domain to analyze

        Returns:
            GoogleAnalysisResult with verification and tracking information
        """
        logger.info(f"Starting Google services analysis for {domain}")
        result = GoogleAnalysisResult(domain=domain)

        # Normalize domain
        domain = domain.rstrip(".")

        # Fetch HTML content once (will be used for multiple checks)
        self._fetch_html_content(domain, result)

        # Check Google Site Verification for each configured ID
        for verification_id in self.verification_ids:
            verification_result = self._check_verification(domain, verification_id, result)
            result.verification_results.append(verification_result)

        # Auto-detect verification IDs (that aren't in config)
        self._detect_verification_ids(domain, result)

        # Detect tracking codes in HTML
        if result.html_content:
            self._detect_tracking_codes(result)

        return result

    def _fetch_html_content(self, domain: str, result: GoogleAnalysisResult) -> None:
        """
        Fetch HTML content from the domain (tries HTTPS first, falls back to HTTP).

        Args:
            domain: Domain to fetch
            result: Result object to store HTML content
        """
        # Try HTTPS first
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
            logger.debug(f"HTTPS timeout, will try HTTP")

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
                    logger.warning(error_msg)

        except httpx.ConnectError as e:
            error_msg = f"Connection error on both HTTPS and HTTP: {str(e)}"
            result.html_fetch_error = error_msg
            logger.warning(error_msg)

        except httpx.TimeoutException:
            error_msg = f"Timeout on both HTTPS and HTTP"
            result.html_fetch_error = error_msg
            logger.warning(error_msg)

        except Exception as e:
            error_msg = f"Error fetching HTML (HTTPS: {https_error}, HTTP: {str(e)})"
            result.html_fetch_error = error_msg
            logger.error(error_msg)

    def _check_verification(
        self,
        domain: str,
        verification_id: str,
        result: GoogleAnalysisResult,
    ) -> GoogleVerificationResult:
        """
        Check all verification methods for a given verification ID.

        Args:
            domain: Domain to check
            verification_id: Google Site Verification ID
            result: Main result object (for accessing HTML content)

        Returns:
            GoogleVerificationResult with found methods
        """
        verification_result = GoogleVerificationResult(verification_id=verification_id)

        # Check DNS TXT record
        if self._check_verification_dns(domain, verification_id):
            verification_result.found = True
            verification_result.methods.append("DNS TXT record")
            logger.debug(f"Verification {verification_id} found via DNS")

        # Check HTML file
        if self._check_verification_file(domain, verification_id):
            verification_result.found = True
            verification_result.methods.append("HTML file")
            logger.debug(f"Verification {verification_id} found via HTML file")

        # Check meta tag in HTML
        if result.html_content:
            if self._check_verification_meta(result.html_content, verification_id):
                verification_result.found = True
                verification_result.methods.append("Meta tag")
                logger.debug(f"Verification {verification_id} found via meta tag")

        if not verification_result.found:
            verification_result.errors.append(
                f"Verification ID {verification_id} not found via any method"
            )

        return verification_result

    def _check_verification_dns(self, domain: str, verification_id: str) -> bool:
        """
        Check for Google Site Verification via DNS TXT record.

        Args:
            domain: Domain to check
            verification_id: Verification ID to look for

        Returns:
            True if verification ID found in DNS TXT records
        """
        try:
            answers = self.resolver.resolve(domain, "TXT")

            for rdata in answers:
                txt_value = str(rdata).strip('"')
                # Google verification TXT format: google-site-verification=XXXXX
                if f"google-site-verification={verification_id}" in txt_value:
                    return True

        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logger.debug(f"No TXT records found for {domain}")
        except Exception as e:
            logger.debug(f"Error checking DNS TXT for {domain}: {e}")

        return False

    def _check_verification_file(self, domain: str, verification_id: str) -> bool:
        """
        Check for Google Site Verification via HTML file.

        Args:
            domain: Domain to check
            verification_id: Verification ID (used in filename)

        Returns:
            True if verification file exists and is accessible
        """
        # Google verification file format: google{verification_id}.html
        url = f"https://{domain}/google{verification_id}.html"

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
                    # Optionally verify content contains verification string
                    content = response.text
                    if verification_id in content or "google-site-verification" in content:
                        return True

        except Exception as e:
            logger.debug(f"Error checking verification file {url}: {e}")

        return False

    def _check_verification_meta(self, html_content: str, verification_id: str) -> bool:
        """
        Check for Google Site Verification via meta tag in HTML.

        Args:
            html_content: HTML content to search
            verification_id: Verification ID to look for

        Returns:
            True if verification meta tag found
        """
        # Look for: <meta name="google-site-verification" content="XXXXX">
        pattern = re.compile(
            r'<meta\s+name=["\']google-site-verification["\']\s+content=["\']'
            + re.escape(verification_id)
            + r'["\']',
            re.IGNORECASE
        )

        # Also check reversed attribute order
        pattern_reversed = re.compile(
            r'<meta\s+content=["\']'
            + re.escape(verification_id)
            + r'["\']\s+name=["\']google-site-verification["\']',
            re.IGNORECASE
        )

        return bool(pattern.search(html_content) or pattern_reversed.search(html_content))

    def _detect_verification_ids(self, domain: str, result: GoogleAnalysisResult) -> None:
        """
        Auto-detect Google Site Verification IDs from DNS and HTML.
        Only detects IDs that aren't already in configured verification_ids.

        Args:
            domain: Domain to check
            result: Result object to store detected IDs
        """
        detected_ids: set[str] = set()

        # Extract IDs from DNS TXT records
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                # Look for google-site-verification=XXXXX
                match = re.search(r'google-site-verification=([a-zA-Z0-9_-]+)', txt_value)
                if match:
                    verification_id = match.group(1)
                    # Only add if not in configured IDs
                    if verification_id not in self.verification_ids:
                        detected_ids.add(verification_id)
                        logger.debug(f"Auto-detected verification ID in DNS: {verification_id}")
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logger.debug(f"No TXT records found for {domain}")
        except Exception as e:
            logger.debug(f"Error checking DNS TXT for verification IDs: {e}")

        # Extract IDs from HTML meta tags
        if result.html_content:
            # Look for: <meta name="google-site-verification" content="XXXXX">
            pattern = re.compile(
                r'<meta\s+name=["\']google-site-verification["\']\s+content=["\']([a-zA-Z0-9_-]+)["\']',
                re.IGNORECASE
            )
            # Also check reversed attribute order
            pattern_reversed = re.compile(
                r'<meta\s+content=["\']([a-zA-Z0-9_-]+)["\']\s+name=["\']google-site-verification["\']',
                re.IGNORECASE
            )

            for match in pattern.finditer(result.html_content):
                verification_id = match.group(1)
                if verification_id not in self.verification_ids:
                    detected_ids.add(verification_id)
                    logger.debug(f"Auto-detected verification ID in HTML meta: {verification_id}")

            for match in pattern_reversed.finditer(result.html_content):
                verification_id = match.group(1)
                if verification_id not in self.verification_ids:
                    detected_ids.add(verification_id)
                    logger.debug(f"Auto-detected verification ID in HTML meta: {verification_id}")

        # Create verification results for detected IDs
        for verification_id in sorted(detected_ids):
            verification_result = self._check_verification(domain, verification_id, result)
            result.detected_verification_ids.append(verification_result)

    def _detect_tracking_codes(self, result: GoogleAnalysisResult) -> None:
        """
        Detect tracking codes in HTML content.

        Args:
            result: Result object with HTML content and tracking codes list
        """
        if not result.html_content:
            return

        html = result.html_content

        # Track found codes to avoid duplicates
        found_codes: set[tuple[str, str]] = set()

        for name, (pattern, description) in self.TRACKING_PATTERNS.items():
            matches = re.finditer(pattern, html)

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
