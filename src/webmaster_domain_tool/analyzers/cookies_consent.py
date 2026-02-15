"""Cookies and Consent tracker analyzer for GDPR/ePrivacy compliance.

Analyzes cookie consent mechanisms including:
- Cookie consent banners detection
- Consent Management Platforms (CMP) identification
- Cookie policy pages detection
- GDPR/ePrivacy compliance indicators
- First-party and third-party cookie analysis
"""

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Known Consent Management Platforms (CMP)
# ============================================================================

KNOWN_CMPS = {
    # Major CMP providers
    "onetrust": {
        "name": "OneTrust",
        "patterns": ["onetrust", "ot-sdk", "otBanner", "OptanonWrapper", "otCookiePolicy"],
        "gdpr_compliant": True,
    },
    "cookiebot": {
        "name": "Cookiebot",
        "patterns": ["cookiebot", "CookieConsent", "CookieInformation"],
        "gdpr_compliant": True,
    },
    "quantcast": {
        "name": "Quantcast Choice",
        "patterns": ["quantcast", "qc-cmp2", "quantcastChoice", "__qc"],
        "gdpr_compliant": True,
    },
    "cookieyes": {
        "name": "CookieYes",
        "patterns": ["cookieyes", "cookie-law-info", "ckyBanner", "cky-style"],
        "gdpr_compliant": True,
    },
    "trustarc": {
        "name": "TrustArc",
        "patterns": ["trustarc", "truste", "bb-gdpr-banner", "trustarcmgr"],
        "gdpr_compliant": True,
    },
    "iubenda": {
        "name": "iubenda",
        "patterns": ["iubenda", "_iub", "iub-cmp-banner"],
        "gdpr_compliant": True,
    },
    "didomi": {
        "name": "Didomi",
        "patterns": ["didomi", "Didomi", "didomi-host"],
        "gdpr_compliant": True,
    },
    "usercentrics": {
        "name": "Usercentrics",
        "patterns": ["usercentrics", "uc-ui", "uc-banner"],
        "gdpr_compliant": True,
    },
    "consentmanager": {
        "name": "ConsentManager",
        "patterns": ["consentmanager", "cmptmpl", "cmpbox", "__cmp"],
        "gdpr_compliant": True,
    },
    "sourcepoint": {
        "name": "Sourcepoint",
        "patterns": ["sourcepoint", "sp_message", "_sp_", "spcdp"],
        "gdpr_compliant": True,
    },
    "cookielawinfo": {
        "name": "GDPR Cookie Consent (WordPress)",
        "patterns": ["cookielawinfo", "gdpr-cookie-consent", "moove_gdpr"],
        "gdpr_compliant": True,
    },
    "borlabs": {
        "name": "Borlabs Cookie",
        "patterns": ["borlabs", "borlabsCookie", "BorlabsCookie"],
        "gdpr_compliant": True,
    },
    "cookiefirst": {
        "name": "CookieFirst",
        "patterns": ["cookiefirst", "cf-banner"],
        "gdpr_compliant": True,
    },
    "civic": {
        "name": "Civic Cookie Control",
        "patterns": ["civic", "CookieControl", "ccc-block"],
        "gdpr_compliant": True,
    },
    "osano": {
        "name": "Osano",
        "patterns": ["osano", "Osano", "osano-cm"],
        "gdpr_compliant": True,
    },
    "cookiepro": {
        "name": "CookiePro (OneTrust)",
        "patterns": ["cookiepro", "cookie-pro"],
        "gdpr_compliant": True,
    },
}

# Banner detection patterns
BANNER_PATTERNS = [
    # Common banner class names and IDs
    r'cookie[_-]?consent',
    r'cookie[_-]?banner',
    r'cookie[_-]?notice',
    r'cookie[_-]?popup',
    r'cookie[_-]?bar',
    r'cookie[_-]?modal',
    r'gdpr[_-]?banner',
    r'gdpr[_-]?consent',
    r'gdpr[_-]?notice',
    r'privacy[_-]?banner',
    r'consent[_-]?banner',
    r'consent[_-]?modal',
    r'consent[_-]?popup',
    # TCF (Transparency and Consent Framework)
    r'tcf[_-]',
    r'cmp[_-]?container',
    r'cmp[_-]?banner',
]

# Common accept/reject button patterns
ACCEPT_BUTTON_PATTERNS = [
    r'accept',
    r'agree',
    r'allow',
    r'consent',
    r'ok(?:ay)?',
    r'got\s*it',
    r'i\s*understand',
    r'continue',
    r'proceed',
    r'yes',
    r'sure',
]

REJECT_BUTTON_PATTERNS = [
    r'reject',
    r'decline',
    r'deny',
    r'refuse',
    r'no[^t]',
    r'disagree',
    r'opt[_-]?out',
]

# Cookie policy link patterns
COOKIE_POLICY_PATTERNS = [
    r'cookie[_-]?policy',
    r'cookie[_-]?information',
    r'privacy[_-]?policy',
    r'datenschutz',  # German
    r'privacidade',  # Portuguese
    r'confidentialite',  # French
]


# ============================================================================
# Configuration
# ============================================================================


class CookiesConsentConfig(AnalyzerConfig):
    """Cookies and consent analyzer configuration."""

    timeout: float = Field(default=15.0, description="HTTP request timeout in seconds")
    user_agent: str = Field(
        default="Mozilla/5.0 (compatible; WebmasterDomainTool/1.0; +https://example.com/bot)",
        description="User agent for HTTP requests",
    )
    check_cookie_policy: bool = Field(default=True, description="Check for cookie policy page")
    detect_cmp: bool = Field(default=True, description="Detect known Consent Management Platforms")
    check_banner_presence: bool = Field(default=True, description="Check for consent banner presence")


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class CMPInfo:
    """Information about a detected Consent Management Platform."""

    cmp_id: str
    name: str
    gdpr_compliant: bool
    detection_method: str  # "script", "dom", "cookie"
    confidence: str  # "high", "medium", "low"


@dataclass
class BannerInfo:
    """Information about a detected consent banner."""

    detected: bool = False
    has_accept_button: bool = False
    has_reject_button: bool = False
    has_customize_button: bool = False
    banner_text_preview: str | None = None
    detection_method: str | None = None  # "dom", "script", "inferred"


@dataclass
class CookiePolicyInfo:
    """Information about cookie policy page."""

    found: bool = False
    url: str | None = None
    link_text: str | None = None
    accessible: bool = False


@dataclass
class CookieSummary:
    """Summary of cookies set by the page."""

    first_party_count: int = 0
    third_party_count: int = 0
    known_tracking_cookies: list[str] = field(default_factory=list)
    session_cookies: list[str] = field(default_factory=list)
    persistent_cookies: list[str] = field(default_factory=list)


@dataclass
class ComplianceIndicators:
    """GDPR/ePrivacy compliance indicators."""

    has_consent_mechanism: bool = False
    has_cookie_policy: bool = False
    uses_known_cmp: bool = False
    provides_reject_option: bool = False
    provides_customize_option: bool = False
    respects_dnt: bool = False  # Do Not Track

    # Compliance score (0-100)
    compliance_score: int = 0

    # Issues
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class CookiesConsentResult:
    """Complete cookies and consent analysis result."""

    domain: str
    url: str = ""
    success: bool = False

    # Detection results
    cmp_detected: CMPInfo | None = None
    banner: BannerInfo | None = None
    cookie_policy: CookiePolicyInfo | None = None
    cookie_summary: CookieSummary | None = None
    compliance: ComplianceIndicators | None = None

    # Raw data for debugging
    detected_cmps: list[CMPInfo] = field(default_factory=list)
    banner_indicators: list[str] = field(default_factory=list)
    script_indicators: list[str] = field(default_factory=list)

    # Overall assessment
    has_consent_solution: bool = False
    likely_gdpr_compliant: bool = False

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class CookiesConsentAnalyzer:
    """
    Cookies and Consent Tracker Analyzer.

    Analyzes websites for cookie consent mechanisms and GDPR/ePrivacy compliance:

    Features:
    - Detects 15+ known Consent Management Platforms (CMPs)
    - Identifies consent banners and their features
    - Checks for cookie policy pages
    - Provides compliance scoring and recommendations

    Dependencies:
    - http: Optional, uses HTTP analyzer to determine URL and cookies
    """

    analyzer_id = "cookies_consent"
    name = "Cookies & Consent"
    description = "Detect cookie consent banners, CMPs, and GDPR/ePrivacy compliance"
    category = "compliance"
    icon = "cookie"
    config_class = CookiesConsentConfig
    depends_on = ["http"]

    def analyze(
        self,
        domain: str,
        config: CookiesConsentConfig,
        context: dict[str, object] | None = None,
    ) -> CookiesConsentResult:
        """Perform cookies and consent analysis."""
        url = self._get_url(domain, context)
        result = CookiesConsentResult(domain=domain, url=url)

        try:
            html_content, response_headers = self._fetch_page(url, config)
            if not html_content:
                result.errors.append("Failed to fetch page content")
                return result

            result.success = True
            soup = BeautifulSoup(html_content, "html5lib")

            # Detect CMPs
            if config.detect_cmp:
                self._detect_cmps(html_content, soup, result)

            # Detect consent banner
            if config.check_banner_presence:
                self._detect_banner(soup, result)

            # Check for cookie policy
            if config.check_cookie_policy:
                self._check_cookie_policy(soup, url, config, result)

            # Analyze cookies from context or response
            self._analyze_cookies(response_headers, context, result)

            # Calculate compliance
            self._assess_compliance(result)

        except httpx.HTTPError as e:
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            logger.exception(f"Cookies/consent analysis failed for {domain}")
            result.errors.append(f"Analysis failed: {e}")

        return result

    def _get_url(self, domain: str, context: dict[str, object] | None) -> str:
        """Get URL to analyze from context or fallback."""
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "preferred_final_url") and http_result.preferred_final_url:
                return http_result.preferred_final_url
        return f"https://{domain}"

    def _fetch_page(
        self, url: str, config: CookiesConsentConfig
    ) -> tuple[str | None, dict[str, str]]:
        """Fetch page content with standard headers."""
        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                response = client.get(
                    url,
                    headers={
                        "User-Agent": config.user_agent,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                    },
                )
                response.raise_for_status()
                return response.text, dict(response.headers)
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return None, {}

    def _detect_cmps(
        self, html_content: str, soup: BeautifulSoup, result: CookiesConsentResult
    ) -> None:
        """Detect known Consent Management Platforms."""
        detected = []

        for cmp_id, cmp_info in KNOWN_CMPS.items():
            found = False
            confidence = "low"
            method = None

            # Check script sources
            for script in soup.find_all("script", src=True):
                src = script.get("src", "").lower()
                for pattern in cmp_info["patterns"]:
                    if pattern.lower() in src:
                        found = True
                        confidence = "high"
                        method = "script"
                        result.script_indicators.append(f"Script: {src[:100]}")
                        break
                if found:
                    break

            # Check inline scripts
            if not found:
                for script in soup.find_all("script"):
                    if script.string:
                        script_text = script.string.lower()
                        for pattern in cmp_info["patterns"]:
                            if pattern.lower() in script_text:
                                found = True
                                confidence = "medium"
                                method = "script_inline"
                                break
                    if found:
                        break

            # Check DOM elements (classes, IDs)
            if not found:
                for pattern in cmp_info["patterns"]:
                    # Check by class
                    for element in soup.find_all(class_=re.compile(pattern, re.I)):
                        found = True
                        confidence = "medium"
                        method = "dom"
                        break
                    if found:
                        break

                    # Check by ID
                    for element in soup.find_all(id=re.compile(pattern, re.I)):
                        found = True
                        confidence = "medium"
                        method = "dom"
                        break
                    if found:
                        break

            if found:
                detected.append(CMPInfo(
                    cmp_id=cmp_id,
                    name=cmp_info["name"],
                    gdpr_compliant=cmp_info["gdpr_compliant"],
                    detection_method=method or "unknown",
                    confidence=confidence,
                ))

        result.detected_cmps = detected
        # Use the first (most confident) CMP as primary
        if detected:
            result.cmp_detected = detected[0]

    def _detect_banner(self, soup: BeautifulSoup, result: CookiesConsentResult) -> None:
        """Detect consent banner presence and features."""
        banner = BannerInfo()

        # Common banner detection patterns
        banner_pattern = re.compile("|".join(BANNER_PATTERNS), re.I)

        # Look for banner elements
        for element in soup.find_all(["div", "section", "aside", "footer", "header"]):
            element_id = element.get("id", "")
            element_class = " ".join(element.get("class", []))
            element_attrs = f"{element_id} {element_class}".lower()

            if banner_pattern.search(element_attrs):
                banner.detected = True
                banner.detection_method = "dom"
                result.banner_indicators.append(f"Found banner element: {element_attrs[:50]}")

                # Extract banner text preview
                text = element.get_text(strip=True)
                if text:
                    banner.banner_text_preview = text[:200]

                # Check for buttons
                buttons = element.find_all(["button", "a"])
                for btn in buttons:
                    btn_text = btn.get_text(strip=True).lower()
                    btn_class = " ".join(btn.get("class", [])).lower()

                    # Accept button
                    if not banner.has_accept_button:
                        for pattern in ACCEPT_BUTTON_PATTERNS:
                            if re.search(pattern, btn_text) or re.search(pattern, btn_class):
                                banner.has_accept_button = True
                                break

                    # Reject button
                    if not banner.has_reject_button:
                        for pattern in REJECT_BUTTON_PATTERNS:
                            if re.search(pattern, btn_text) or re.search(pattern, btn_class):
                                banner.has_reject_button = True
                                break

                    # Customize/settings button
                    if not banner.has_customize_button:
                        customize_patterns = ["settings", "customize", "manage", "options", "preferences", "configure"]
                        for pattern in customize_patterns:
                            if pattern in btn_text or pattern in btn_class:
                                banner.has_customize_button = True
                                break

                break  # Found banner, stop searching

        # If no banner found in DOM, check for CMP that likely has banner
        if not banner.detected and result.cmp_detected:
            banner.detected = True
            banner.detection_method = "inferred"
            result.banner_indicators.append(f"Banner inferred from CMP: {result.cmp_detected.name}")

        result.banner = banner

    def _check_cookie_policy(
        self,
        soup: BeautifulSoup,
        base_url: str,
        config: CookiesConsentConfig,
        result: CookiesConsentResult,
    ) -> None:
        """Check for cookie policy page."""
        policy = CookiePolicyInfo()
        policy_pattern = re.compile("|".join(COOKIE_POLICY_PATTERNS), re.I)

        # Look for cookie policy links
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            link_text = link.get_text(strip=True).lower()
            link_href_lower = href.lower()

            # Check link text and href
            if policy_pattern.search(link_text) or policy_pattern.search(link_href_lower):
                policy.found = True
                policy.link_text = link.get_text(strip=True)

                # Resolve relative URLs
                if href.startswith("/"):
                    policy.url = urljoin(base_url, href)
                elif href.startswith("http"):
                    policy.url = href
                else:
                    policy.url = urljoin(base_url, href)

                # Verify policy page is accessible
                try:
                    with httpx.Client(timeout=config.timeout, follow_redirects=True) as client:
                        resp = client.head(policy.url, headers={"User-Agent": config.user_agent})
                        policy.accessible = resp.status_code < 400
                except Exception:
                    policy.accessible = False

                break

        result.cookie_policy = policy

    def _analyze_cookies(
        self,
        response_headers: dict[str, str],
        context: dict[str, object] | None,
        result: CookiesConsentResult,
    ) -> None:
        """Analyze cookies from response and context."""
        summary = CookieSummary()

        # Get cookies from HTTP response
        set_cookie = response_headers.get("set-cookie", "")
        if set_cookie:
            # Parse cookie names (simplified)
            cookies = [c.split("=")[0].strip() for c in set_cookie.split(",") if "=" in c]
            summary.first_party_count = len(cookies)

        # Check context for additional cookie info
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "cookies"):
                # Count cookies from HTTP analyzer if available
                pass

        result.cookie_summary = summary

    def _assess_compliance(self, result: CookiesConsentResult) -> None:
        """Assess GDPR/ePrivacy compliance indicators."""
        compliance = ComplianceIndicators()

        # Check for consent mechanism
        if result.banner and result.banner.detected:
            compliance.has_consent_mechanism = True
            compliance.provides_reject_option = result.banner.has_reject_button
            compliance.provides_customize_option = result.banner.has_customize_button

        # Check for CMP
        if result.cmp_detected:
            compliance.uses_known_cmp = True

        # Check for cookie policy
        if result.cookie_policy and result.cookie_policy.found:
            compliance.has_cookie_policy = True

        # Calculate compliance score
        score = 0

        if compliance.has_consent_mechanism:
            score += 30
        else:
            compliance.issues.append("No consent banner detected - GDPR requires consent for non-essential cookies")

        if compliance.uses_known_cmp:
            score += 25  # Known CMPs are typically GDPR compliant

        if compliance.has_cookie_policy:
            score += 20
        else:
            compliance.issues.append("No cookie policy found - GDPR requires transparent cookie information")
            compliance.recommendations.append("Add a cookie policy page detailing cookie usage")

        if compliance.provides_reject_option:
            score += 15
        else:
            compliance.recommendations.append("Add a 'Reject' option to the consent banner")

        if compliance.provides_customize_option:
            score += 10
        else:
            compliance.recommendations.append("Add cookie preferences/customization option")

        compliance.compliance_score = min(100, score)

        result.compliance = compliance

        # Overall assessment
        result.has_consent_solution = compliance.has_consent_mechanism or compliance.uses_known_cmp
        result.likely_gdpr_compliant = compliance.compliance_score >= 70

        # Add warnings for low scores
        if compliance.compliance_score < 50:
            result.warnings.append(f"Low GDPR compliance score: {compliance.compliance_score}/100")
        elif compliance.compliance_score < 70:
            result.warnings.append(f"Moderate GDPR compliance score: {compliance.compliance_score}/100")

    def describe_output(self, result: CookiesConsentResult) -> OutputDescriptor:
        """Describe how to render cookies/consent results."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        if result.likely_gdpr_compliant:
            descriptor.quiet_summary = lambda r: f"Cookies: ✓ Compliant ({result.compliance.compliance_score if result.compliance else 0}/100)"
        else:
            descriptor.quiet_summary = lambda r: f"Cookies: ✗ Issues ({result.compliance.compliance_score if result.compliance else 0}/100)"

        if not result.success:
            descriptor.add_row(
                value="Failed to analyze cookies/consent",
                style_class="error",
                severity="error",
            )
            return descriptor

        # Compliance Score
        score = result.compliance.compliance_score if result.compliance else 0
        score_style = (
            "success" if score >= 80
            else "warning" if score >= 50
            else "error"
        )
        compliant_text = "Likely Compliant" if result.likely_gdpr_compliant else "May Not Be Compliant"

        descriptor.add_row(
            label="Compliance Score",
            value=f"{score}/100 - {compliant_text}",
            style_class=score_style,
            icon="shield" if score >= 70 else "warning",
        )

        # CMP Detection Section
        descriptor.add_row(
            section_name="Consent Management Platform",
            section_type="heading",
        )

        if result.cmp_detected:
            cmp = result.cmp_detected
            descriptor.add_row(
                label="CMP Detected",
                value=cmp.name,
                style_class="success",
                icon="check",
            )
            descriptor.add_row(
                label="GDPR Compliant",
                value="Yes" if cmp.gdpr_compliant else "Unknown",
                style_class="success" if cmp.gdpr_compliant else "warning",
                verbosity=VerbosityLevel.VERBOSE,
            )
            descriptor.add_row(
                label="Detection Method",
                value=cmp.detection_method,
                verbosity=VerbosityLevel.VERBOSE,
            )
            descriptor.add_row(
                label="Confidence",
                value=cmp.confidence.title(),
                verbosity=VerbosityLevel.VERBOSE,
            )
        elif result.detected_cmps:
            # Multiple CMPs detected
            descriptor.add_row(
                label="CMPs Detected",
                value=", ".join(c.name for c in result.detected_cmps),
                style_class="success",
            )
        else:
            descriptor.add_row(
                label="CMP Detected",
                value="None detected",
                style_class="warning" if not result.banner else "muted",
            )

        # Banner Section
        if result.banner:
            banner = result.banner
            descriptor.add_row(
                section_name="Consent Banner",
                section_type="heading",
            )

            if banner.detected:
                descriptor.add_row(
                    label="Banner Present",
                    value="Yes",
                    style_class="success",
                    icon="check",
                )

                # Banner features
                if banner.has_accept_button:
                    descriptor.add_row(
                        label="Accept Button",
                        value="Yes",
                        style_class="success",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

                if banner.has_reject_button:
                    descriptor.add_row(
                        label="Reject Button",
                        value="Yes",
                        style_class="success",
                        verbosity=VerbosityLevel.VERBOSE,
                    )
                else:
                    descriptor.add_row(
                        label="Reject Button",
                        value="No (recommended)",
                        style_class="warning",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

                if banner.has_customize_button:
                    descriptor.add_row(
                        label="Customize Button",
                        value="Yes",
                        style_class="success",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

                if banner.banner_text_preview:
                    descriptor.add_row(
                        label="Banner Preview",
                        value=banner.banner_text_preview[:100] + "...",
                        verbosity=VerbosityLevel.VERBOSE,
                    )

                descriptor.add_row(
                    label="Detection Method",
                    value=banner.detection_method or "Unknown",
                    verbosity=VerbosityLevel.VERBOSE,
                )
            else:
                descriptor.add_row(
                    label="Banner Present",
                    value="No",
                    style_class="error",
                    icon="cross",
                )

        # Cookie Policy Section
        if result.cookie_policy:
            policy = result.cookie_policy
            descriptor.add_row(
                section_name="Cookie Policy",
                section_type="heading",
            )

            if policy.found:
                descriptor.add_row(
                    label="Policy Found",
                    value="Yes",
                    style_class="success",
                    icon="check",
                )
                if policy.url:
                    descriptor.add_row(
                        label="URL",
                        value=policy.url,
                        link_url=policy.url,
                        verbosity=VerbosityLevel.VERBOSE,
                    )
                if policy.link_text:
                    descriptor.add_row(
                        label="Link Text",
                        value=policy.link_text,
                        verbosity=VerbosityLevel.VERBOSE,
                    )
                descriptor.add_row(
                    label="Accessible",
                    value="Yes" if policy.accessible else "No",
                    style_class="success" if policy.accessible else "warning",
                    verbosity=VerbosityLevel.VERBOSE,
                )
            else:
                descriptor.add_row(
                    label="Policy Found",
                    value="No",
                    style_class="warning",
                    icon="warning",
                )

        # Compliance Indicators Section
        if result.compliance:
            comp = result.compliance
            descriptor.add_row(
                section_name="GDPR Compliance",
                section_type="heading",
            )

            indicators = [
                ("Consent Mechanism", comp.has_consent_mechanism),
                ("Known CMP", comp.uses_known_cmp),
                ("Cookie Policy", comp.has_cookie_policy),
                ("Reject Option", comp.provides_reject_option),
                ("Customize Option", comp.provides_customize_option),
            ]

            for label, has in indicators:
                descriptor.add_row(
                    label=label,
                    value="✓" if has else "✗",
                    style_class="success" if has else "error",
                    verbosity=VerbosityLevel.NORMAL,
                )

            # Issues
            if comp.issues:
                descriptor.add_row(
                    section_name="Issues",
                    section_type="heading",
                )
                for issue in comp.issues:
                    descriptor.add_row(
                        value=f"• {issue}",
                        style_class="warning",
                        icon="warning",
                    )

            # Recommendations
            if comp.recommendations:
                descriptor.add_row(
                    section_name="Recommendations",
                    section_type="heading",
                )
                for rec in comp.recommendations:
                    descriptor.add_row(
                        value=f"→ {rec}",
                        style_class="info",
                    )

        # Cookies Summary (verbose)
        if result.cookie_summary:
            summary = result.cookie_summary
            descriptor.add_row(
                section_name="Cookies Detected",
                section_type="heading",
                verbosity=VerbosityLevel.VERBOSE,
            )
            descriptor.add_row(
                label="First-Party Cookies",
                value=str(summary.first_party_count),
                verbosity=VerbosityLevel.VERBOSE,
            )

        # Errors and warnings
        for error in result.errors:
            descriptor.add_row(
                value=error,
                style_class="error",
                severity="error",
                icon="cross",
            )

        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                style_class="warning",
                severity="warning",
                icon="warning",
            )

        return descriptor

    def to_dict(self, result: CookiesConsentResult) -> dict:
        """Serialize result to JSON-compatible dictionary."""

        def cmp_to_dict(cmp: CMPInfo | None) -> dict | None:
            if cmp is None:
                return None
            return {
                "cmp_id": cmp.cmp_id,
                "name": cmp.name,
                "gdpr_compliant": cmp.gdpr_compliant,
                "detection_method": cmp.detection_method,
                "confidence": cmp.confidence,
            }

        def banner_to_dict(b: BannerInfo | None) -> dict | None:
            if b is None:
                return None
            return {
                "detected": b.detected,
                "has_accept_button": b.has_accept_button,
                "has_reject_button": b.has_reject_button,
                "has_customize_button": b.has_customize_button,
                "banner_text_preview": b.banner_text_preview,
                "detection_method": b.detection_method,
            }

        def policy_to_dict(p: CookiePolicyInfo | None) -> dict | None:
            if p is None:
                return None
            return {
                "found": p.found,
                "url": p.url,
                "link_text": p.link_text,
                "accessible": p.accessible,
            }

        def compliance_to_dict(c: ComplianceIndicators | None) -> dict | None:
            if c is None:
                return None
            return {
                "has_consent_mechanism": c.has_consent_mechanism,
                "has_cookie_policy": c.has_cookie_policy,
                "uses_known_cmp": c.uses_known_cmp,
                "provides_reject_option": c.provides_reject_option,
                "provides_customize_option": c.provides_customize_option,
                "compliance_score": c.compliance_score,
                "issues": c.issues,
                "recommendations": c.recommendations,
            }

        def cookie_summary_to_dict(s: CookieSummary | None) -> dict | None:
            if s is None:
                return None
            return {
                "first_party_count": s.first_party_count,
                "third_party_count": s.third_party_count,
                "known_tracking_cookies": s.known_tracking_cookies,
            }

        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "has_consent_solution": result.has_consent_solution,
            "likely_gdpr_compliant": result.likely_gdpr_compliant,
            "cmp_detected": cmp_to_dict(result.cmp_detected),
            "all_detected_cmps": [cmp_to_dict(c) for c in result.detected_cmps],
            "banner": banner_to_dict(result.banner),
            "cookie_policy": policy_to_dict(result.cookie_policy),
            "cookie_summary": cookie_summary_to_dict(result.cookie_summary),
            "compliance": compliance_to_dict(result.compliance),
            "banner_indicators": result.banner_indicators,
            "script_indicators": result.script_indicators,
            "errors": result.errors,
            "warnings": result.warnings,
        }
