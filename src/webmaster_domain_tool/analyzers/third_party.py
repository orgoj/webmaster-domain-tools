"""Third-party auditor analyzer - detect external scripts, trackers, and services.

This analyzer detects third-party resources loaded on websites including
analytics, advertising, social media widgets, CDN scripts, and tracking services.
Provides privacy impact assessment and categorization of detected services.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from pydantic import Field

from ..constants import DEFAULT_USER_AGENT
from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class ThirdPartyConfig(AnalyzerConfig):
    """Third-party auditor configuration."""

    check_scripts: bool = Field(default=True, description="Check for third-party JavaScript")
    check_iframes: bool = Field(default=True, description="Check for third-party iframes")
    check_images: bool = Field(default=True, description="Check for third-party images")
    check_links: bool = Field(default=True, description="Check for third-party stylesheets and links")
    check_cookies: bool = Field(default=True, description="Check for third-party cookie domains")
    user_agent: str = Field(default=DEFAULT_USER_AGENT, description="User agent for HTTP requests")
    max_resources: int = Field(default=500, description="Maximum resources to analyze")


# ============================================================================
# Third-Party Service Database
# ============================================================================

# Known third-party services categorized by type and privacy impact
# Format: domain_pattern -> (category, privacy_impact, service_name)
# Privacy impact: low, medium, high, critical
THIRD_PARTY_SERVICES: dict[str, tuple[str, str, str]] = {
    # Analytics
    "google-analytics.com": ("analytics", "medium", "Google Analytics"),
    "googletagmanager.com": ("analytics", "medium", "Google Tag Manager"),
    "hotjar.com": ("analytics", "high", "Hotjar"),
    "mixpanel.com": ("analytics", "medium", "Mixpanel"),
    "segment.com": ("analytics", "medium", "Segment"),
    "amplitude.com": ("analytics", "medium", "Amplitude"),
    "heap.io": ("analytics", "medium", "Heap"),
    "matomo.cloud": ("analytics", "low", "Matomo Cloud"),
    "piwik.pro": ("analytics", "low", "Piwik PRO"),
    "plausible.io": ("analytics", "low", "Plausible"),
    "statcounter.com": ("analytics", "medium", "StatCounter"),
    "clicky.com": ("analytics", "medium", "Clicky"),
    "newrelic.com": ("analytics", "medium", "New Relic"),
    "fullstory.com": ("analytics", "high", "FullStory"),
    "mouseflow.com": ("analytics", "high", "Mouseflow"),
    "smartlook.com": ("analytics", "high", "Smartlook"),
    "crazyegg.com": ("analytics", "high", "Crazy Egg"),
    "optimizely.com": ("analytics", "medium", "Optimizely"),
    "abtasty.com": ("analytics", "medium", "AB Tasty"),
    "vwo.com": ("analytics", "medium", "VWO"),
    
    # Advertising
    "doubleclick.net": ("advertising", "critical", "Google DoubleClick"),
    "ads.google.com": ("advertising", "critical", "Google Ads"),
    "adservice.google.com": ("advertising", "critical", "Google Ads Service"),
    "googlesyndication.com": ("advertising", "critical", "Google AdSense"),
    "facebook.net": ("advertising", "critical", "Facebook"),
    "connect.facebook.net": ("advertising", "critical", "Facebook Connect"),
    "facebook.com/tr": ("advertising", "critical", "Facebook Pixel"),
    "ads.twitter.com": ("advertising", "critical", "Twitter Ads"),
    "ads.linkedin.com": ("advertising", "critical", "LinkedIn Ads"),
    "amazon-adsystem.com": ("advertising", "critical", "Amazon Ads"),
    "criteo.com": ("advertising", "critical", "Criteo"),
    "taboola.com": ("advertising", "critical", "Taboola"),
    "outbrain.com": ("advertising", "critical", "Outbrain"),
    "pubmatic.com": ("advertising", "critical", "PubMatic"),
    "openx.net": ("advertising", "critical", "OpenX"),
    "rubiconproject.com": ("advertising", "critical", "Rubicon"),
    "advertising.com": ("advertising", "critical", "AOL Advertising"),
    "adnxs.com": ("advertising", "critical", "AppNexus"),
    "scorecardresearch.com": ("advertising", "critical", "Scorecard Research"),
    "quantserve.com": ("advertising", "critical", "Quantcast"),
    "adsrvr.org": ("advertising", "critical", "The Trade Desk"),
    
    # Social Media
    "platform.twitter.com": ("social", "medium", "Twitter Widgets"),
    "twitter.com/i/widgets": ("social", "medium", "Twitter Widgets"),
    "connect.facebook.net": ("social", "medium", "Facebook SDK"),
    "platform.instagram.com": ("social", "medium", "Instagram Embed"),
    "platform.linkedin.com": ("social", "medium", "LinkedIn Share"),
    "assets.pinterest.com": ("social", "medium", "Pinterest"),
    "widgets.wp.com": ("social", "medium", "WordPress.com"),
    "disqus.com": ("social", "medium", "Disqus"),
    "addthis.com": ("social", "medium", "AddThis"),
    "sharethis.com": ("social", "medium", "ShareThis"),
    
    # CDNs (generally low privacy impact)
    "cdnjs.cloudflare.com": ("cdn", "low", "CDNJS (Cloudflare)"),
    "cdn.jsdelivr.net": ("cdn", "low", "jsDelivr"),
    "unpkg.com": ("cdn", "low", "unpkg"),
    "code.jquery.com": ("cdn", "low", "jQuery CDN"),
    "ajax.googleapis.com": ("cdn", "low", "Google Hosted Libraries"),
    "fonts.googleapis.com": ("cdn", "low", "Google Fonts API"),
    "fonts.gstatic.com": ("cdn", "low", "Google Fonts"),
    "use.fontawesome.com": ("cdn", "low", "Font Awesome"),
    "maxcdn.bootstrapcdn.com": ("cdn", "low", "Bootstrap CDN"),
    "stackpath.bootstrapcdn.com": ("cdn", "low", "Bootstrap CDN"),
    
    # Customer Support / Chat
    "static.zdassets.com": ("support", "medium", "Zendesk"),
    "cdn.livechatinc.com": ("support", "high", "LiveChat"),
    "js.driftt.com": ("support", "high", "Drift"),
    "js.intercomcdn.com": ("support", "high", "Intercom"),
    "assets.tawk.to": ("support", "medium", "Tawk.to"),
    "embed.tawk.to": ("support", "medium", "Tawk.to"),
    "cdn.crisp.chat": ("support", "medium", "Crisp"),
    "client.crisp.chat": ("support", "medium", "Crisp"),
    "static.hellobox.asia": ("support", "medium", "HelloBox"),
    "code.tidio.co": ("support", "medium", "Tidio"),
    
    # Video / Media
    "www.youtube.com/embed": ("media", "medium", "YouTube Embed"),
    "player.vimeo.com": ("media", "medium", "Vimeo"),
    "w.soundcloud.com": ("media", "medium", "SoundCloud"),
    "cdn.jwplayer.com": ("media", "medium", "JW Player"),
    "fast.wistia.com": ("media", "medium", "Wistia"),
    "player.brightcove.com": ("media", "medium", "Brightcove"),
    
    # Payments
    "js.stripe.com": ("payment", "low", "Stripe"),
    "checkout.stripe.com": ("payment", "low", "Stripe Checkout"),
    "paypal.com/sdk": ("payment", "low", "PayPal"),
    "js.braintreegateway.com": ("payment", "low", "Braintree"),
    "cdn.plaid.com": ("payment", "low", "Plaid"),
    
    # Tag Managers
    "googletagmanager.com/gtag": ("tag-manager", "medium", "Google Tag Manager"),
    "tags.tiqcdn.com": ("tag-manager", "medium", "Tealium"),
    "cdn.tagcommander.com": ("tag-manager", "medium", "Commanders Act"),
    "cdn.optimizely.com": ("tag-manager", "medium", "Optimizely"),
    
    # Privacy / Consent
    "cdn.cookielaw.org": ("privacy", "low", "OneTrust"),
    "cdn-ukwest.onetrust.com": ("privacy", "low", "OneTrust"),
    "consent.cookiebot.com": ("privacy", "low", "Cookiebot"),
    "cdn.iubenda.com": ("privacy", "low", "Iubenda"),
    "cmp.quantcast.com": ("privacy", "medium", "Quantcast Choice"),
    
    # Marketing / Email
    "cdn.mxpnl.com": ("marketing", "medium", "Mixpanel"),
    "cdn.hubspot.com": ("marketing", "medium", "HubSpot"),
    "static.mailchimp.com": ("marketing", "medium", "Mailchimp"),
    "button.mailchimp.com": ("marketing", "medium", "Mailchimp"),
    "fast.fonts.com": ("cdn", "low", "Fonts.com"),
    "use.typekit.net": ("cdn", "low", "Adobe Fonts"),
    
    # Hosting Platforms
    "vercel.app": ("hosting", "low", "Vercel"),
    "netlify.app": ("hosting", "low", "Netlify"),
    "github.io": ("hosting", "low", "GitHub Pages"),
    "gitlab.io": ("hosting", "low", "GitLab Pages"),
    "herokuapp.com": ("hosting", "low", "Heroku"),
    "pages.cloudflare.com": ("hosting", "low", "Cloudflare Pages"),
}

# Category descriptions for output
CATEGORY_DESCRIPTIONS = {
    "analytics": "Analytics & tracking",
    "advertising": "Advertising & ad tracking",
    "social": "Social media widgets",
    "cdn": "Content delivery networks",
    "support": "Customer support & chat",
    "media": "Video & media embeds",
    "payment": "Payment processing",
    "tag-manager": "Tag management",
    "privacy": "Privacy & consent management",
    "marketing": "Marketing automation",
    "hosting": "Hosting platforms",
    "unknown": "Uncategorized services",
}

# Privacy impact descriptions
PRIVACY_IMPACT_DESCRIPTIONS = {
    "low": "Minimal privacy impact",
    "medium": "Moderate tracking capability",
    "high": "Significant tracking capability",
    "critical": "Extensive tracking & profiling",
}


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class ThirdPartyResource:
    """A detected third-party resource."""

    url: str
    domain: str
    resource_type: str  # script, iframe, image, link, cookie
    category: str
    service_name: str
    privacy_impact: str  # low, medium, high, critical
    is_known: bool = True  # False if domain not in our database


@dataclass
class ThirdPartyDomain:
    """Summary of a third-party domain."""

    domain: str
    resource_count: int = 0
    categories: set[str] = field(default_factory=set)
    service_name: str | None = None
    privacy_impact: str = "unknown"
    resource_types: set[str] = field(default_factory=set)
    urls: list[str] = field(default_factory=list)


@dataclass
class ThirdPartyAnalysisResult:
    """Results from third-party auditor analysis."""

    domain: str
    html_content: str | None = None
    html_fetch_error: str | None = None
    
    # Detected resources
    resources: list[ThirdPartyResource] = field(default_factory=list)
    
    # Summary by domain
    third_party_domains: list[ThirdPartyDomain] = field(default_factory=list)
    
    # Statistics
    total_resources: int = 0
    total_third_party_domains: int = 0
    privacy_impact_score: int = 0  # 0-100 scale
    
    # Category counts
    category_counts: dict[str, int] = field(default_factory=dict)
    
    # Errors and warnings
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class ThirdPartyAuditor:
    """
    Third-party auditor - detects external scripts, trackers, and services.
    
    This analyzer scans HTML content for:
    - External JavaScript files (<script src>)
    - Third-party iframes (<iframe src>)
    - External images (<img src>)
    - External stylesheets (<link rel="stylesheet">)
    - Third-party domains setting cookies
    
    It categorizes detected services and assesses privacy impact.
    
    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (ThirdPartyConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "third-party"
    name = "Third-Party Auditor"
    description = "Detect third-party scripts, trackers, and services"
    category = "security"
    icon = "shield"
    config_class = ThirdPartyConfig
    depends_on = ["http"]  # Needs HTTP result for final URL

    # ========================================================================
    # Resource Detection Patterns
    # ========================================================================

    # Regex patterns for extracting resource URLs from HTML
    SCRIPT_PATTERN = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    IFRAME_PATTERN = re.compile(
        r'<iframe[^>]+src=["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    IMG_PATTERN = re.compile(
        r'<img[^>]+src=["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    LINK_PATTERN = re.compile(
        r'<link[^>]+(?:href|src)=["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    # Embedded data URIs and inline scripts should be excluded
    DATA_URI_PATTERN = re.compile(r'^data:', re.IGNORECASE)
    INLINE_SCRIPT_PATTERN = re.compile(r'^javascript:', re.IGNORECASE)

    def analyze(
        self, 
        domain: str, 
        config: ThirdPartyConfig,
        context: dict[str, Any] | None = None,
    ) -> ThirdPartyAnalysisResult:
        """
        Perform third-party resource analysis.
        
        Args:
            domain: Domain to analyze
            config: Third-party auditor configuration
            context: Optional context with results from dependency analyzers
            
        Returns:
            ThirdPartyAnalysisResult with detected resources and privacy assessment
        """
        logger.info(f"Starting third-party auditor analysis for {domain}")
        result = ThirdPartyAnalysisResult(domain=domain)
        
        # Normalize domain
        domain = domain.rstrip("/").lower()
        base_domain = self._extract_base_domain(domain)
        
        # Get HTML content from context or fetch it
        html_content = None
        if context and "http" in context:
            http_result = context.get("http")
            if hasattr(http_result, "html_content"):
                html_content = http_result.html_content
        
        # If no HTML from context, fetch it ourselves
        if not html_content:
            html_content = self._fetch_html(domain, config, result)
        
        if not html_content:
            result.errors.append("Could not fetch HTML content for analysis")
            return result
        
        result.html_content = html_content
        
        # Extract and analyze resources
        self._analyze_resources(html_content, base_domain, config, result)
        
        # Calculate privacy impact score
        self._calculate_privacy_score(result)
        
        # Generate summary by domain
        self._summarize_by_domain(result)
        
        # Count by category
        self._count_by_category(result)
        
        return result

    def _fetch_html(
        self, 
        domain: str, 
        config: ThirdPartyConfig, 
        result: ThirdPartyAnalysisResult,
    ) -> str | None:
        """
        Fetch HTML content from domain.
        
        Args:
            domain: Domain to fetch
            config: Configuration
            result: Result object to store errors
            
        Returns:
            HTML content or None on failure
        """
        import httpx
        
        # Try HTTPS first
        for protocol in ["https", "http"]:
            url = f"{protocol}://{domain}"
            try:
                with httpx.Client(
                    timeout=config.timeout,
                    follow_redirects=True,
                    verify=True,
                ) as client:
                    response = client.get(
                        url,
                        headers={"User-Agent": config.user_agent},
                    )
                    
                    if response.status_code == 200:
                        return response.text
                        
            except httpx.HTTPError as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Error fetching {url}: {e}")
                continue
        
        result.html_fetch_error = f"Could not fetch HTML from {domain}"
        return None

    def _extract_base_domain(self, domain: str) -> str:
        """
        Extract base domain (without subdomain) for comparison.
        
        Args:
            domain: Full domain
            
        Returns:
            Base domain (e.g., example.com from www.example.com)
        """
        parts = domain.split(".")
        if len(parts) > 2:
            # Handle co.uk, com.au, etc.
            if parts[-2] in ["co", "com", "org", "net", "gov", "edu", "ac"]:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return domain

    def _analyze_resources(
        self,
        html_content: str,
        base_domain: str,
        config: ThirdPartyConfig,
        result: ThirdPartyAnalysisResult,
    ) -> None:
        """
        Analyze HTML content for third-party resources.
        
        Args:
            html_content: HTML to analyze
            base_domain: Base domain of the page
            config: Configuration
            result: Result object to populate
        """
        resource_count = 0
        
        # Extract scripts
        if config.check_scripts:
            for match in self.SCRIPT_PATTERN.finditer(html_content):
                if resource_count >= config.max_resources:
                    result.warnings.append(f"Reached max resource limit ({config.max_resources})")
                    break
                url = match.group(1)
                self._process_resource(url, "script", base_domain, result)
                resource_count += 1
        
        # Extract iframes
        if config.check_iframes:
            for match in self.IFRAME_PATTERN.finditer(html_content):
                if resource_count >= config.max_resources:
                    break
                url = match.group(1)
                self._process_resource(url, "iframe", base_domain, result)
                resource_count += 1
        
        # Extract images
        if config.check_images:
            for match in self.IMG_PATTERN.finditer(html_content):
                if resource_count >= config.max_resources:
                    break
                url = match.group(1)
                self._process_resource(url, "image", base_domain, result)
                resource_count += 1
        
        # Extract stylesheets and other links
        if config.check_links:
            for match in self.LINK_PATTERN.finditer(html_content):
                if resource_count >= config.max_resources:
                    break
                url = match.group(1)
                # Only process stylesheets and preload/prefetch
                if 'rel="stylesheet"' in match.group(0).lower() or \
                   'rel="preload"' in match.group(0).lower() or \
                   'rel="prefetch"' in match.group(0).lower():
                    self._process_resource(url, "link", base_domain, result)
                    resource_count += 1
        
        result.total_resources = len(result.resources)

    def _process_resource(
        self,
        url: str,
        resource_type: str,
        base_domain: str,
        result: ThirdPartyAnalysisResult,
    ) -> None:
        """
        Process a single resource URL.
        
        Args:
            url: Resource URL
            resource_type: Type of resource (script, iframe, etc.)
            base_domain: Base domain of the page
            result: Result object to populate
        """
        # Skip inline scripts and data URIs
        if self.INLINE_SCRIPT_PATTERN.match(url) or self.DATA_URI_PATTERN.match(url):
            return
        
        # Skip relative URLs and same-origin URLs
        if url.startswith("/") or url.startswith("./") or url.startswith("../"):
            return
        
        # Parse URL to get domain
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if not domain:
                return
            
            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]
                
        except Exception:
            return
        
        # Check if it's a third-party domain
        resource_base_domain = self._extract_base_domain(domain)
        if resource_base_domain == base_domain or domain.endswith(f".{base_domain}"):
            return  # Same origin, not third-party
        
        # Identify the service
        category, privacy_impact, service_name = self._identify_service(url, domain)
        
        # Create resource record
        resource = ThirdPartyResource(
            url=url,
            domain=domain,
            resource_type=resource_type,
            category=category,
            service_name=service_name,
            privacy_impact=privacy_impact,
            is_known=(service_name != "Unknown"),
        )
        
        result.resources.append(resource)

    def _identify_service(self, url: str, domain: str) -> tuple[str, str, str]:
        """
        Identify the service from URL and domain.
        
        Args:
            url: Full URL
            domain: Domain name
            
        Returns:
            Tuple of (category, privacy_impact, service_name)
        """
        url_lower = url.lower()
        
        # Check exact domain matches first
        for pattern, (category, privacy_impact, service_name) in THIRD_PARTY_SERVICES.items():
            if domain == pattern or domain.endswith(f".{pattern}"):
                return (category, privacy_impact, service_name)
        
        # Check URL path patterns (for services with specific paths)
        for pattern, (category, privacy_impact, service_name) in THIRD_PARTY_SERVICES.items():
            if "/" in pattern and pattern in url_lower:
                return (category, privacy_impact, service_name)
        
        # Unknown service - try to infer category from domain patterns
        category = "unknown"
        privacy_impact = "medium"  # Default to medium for unknown services
        
        # Infer from domain name patterns
        domain_lower = domain.lower()
        if any(kw in domain_lower for kw in ["ad", "ads", "adv", "tracking", "tracker"]):
            category = "advertising"
            privacy_impact = "high"
        elif any(kw in domain_lower for kw in ["analytic", "stat", "metric", "track"]):
            category = "analytics"
            privacy_impact = "medium"
        elif any(kw in domain_lower for kw in ["cdn", "static", "assets", "cache"]):
            category = "cdn"
            privacy_impact = "low"
        elif any(kw in domain_lower for kw in ["social", "share", "widget"]):
            category = "social"
            privacy_impact = "medium"
        
        return (category, privacy_impact, domain)

    def _calculate_privacy_score(self, result: ThirdPartyAnalysisResult) -> None:
        """
        Calculate overall privacy impact score (0-100).
        
        Higher score = higher privacy risk.
        
        Args:
            result: Result object to update
        """
        if not result.resources:
            result.privacy_impact_score = 0
            return
        
        impact_weights = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
            "unknown": 2,
        }
        
        total_weight = 0
        max_weight = 0
        
        for resource in result.resources:
            weight = impact_weights.get(resource.privacy_impact, 2)
            total_weight += weight
            max_weight += 4  # Maximum possible weight
        
        # Normalize to 0-100 scale
        if max_weight > 0:
            result.privacy_impact_score = int((total_weight / max_weight) * 100)
        else:
            result.privacy_impact_score = 0

    def _summarize_by_domain(self, result: ThirdPartyAnalysisResult) -> None:
        """
        Summarize resources by domain.
        
        Args:
            result: Result object to update
        """
        domain_map: dict[str, ThirdPartyDomain] = {}
        
        for resource in result.resources:
            if resource.domain not in domain_map:
                domain_map[resource.domain] = ThirdPartyDomain(
                    domain=resource.domain,
                    categories=set(),
                    resource_types=set(),
                    urls=[],
                )
            
            domain_entry = domain_map[resource.domain]
            domain_entry.resource_count += 1
            domain_entry.categories.add(resource.category)
            domain_entry.resource_types.add(resource.resource_type)
            domain_entry.urls.append(resource.url)
            
            # Set service name and privacy impact
            if domain_entry.service_name is None or resource.is_known:
                domain_entry.service_name = resource.service_name
            
            # Keep the highest privacy impact
            impact_order = ["low", "medium", "high", "critical"]
            current_idx = impact_order.index(domain_entry.privacy_impact) if domain_entry.privacy_impact in impact_order else -1
            new_idx = impact_order.index(resource.privacy_impact) if resource.privacy_impact in impact_order else 1
            if new_idx > current_idx:
                domain_entry.privacy_impact = resource.privacy_impact
        
        # Convert to sorted list
        result.third_party_domains = sorted(
            domain_map.values(), 
            key=lambda d: (impact_order.index(d.privacy_impact) if d.privacy_impact in impact_order else 0, d.resource_count),
            reverse=True,
        )
        result.total_third_party_domains = len(result.third_party_domains)

    def _count_by_category(self, result: ThirdPartyAnalysisResult) -> None:
        """
        Count resources by category.
        
        Args:
            result: Result object to update
        """
        category_counts: dict[str, int] = {}
        
        for resource in result.resources:
            category_counts[resource.category] = category_counts.get(resource.category, 0) + 1
        
        result.category_counts = category_counts

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def describe_output(self, result: ThirdPartyAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: Third-party analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        def quiet_summary(r: ThirdPartyAnalysisResult) -> str:
            return f"Third-Party: {r.total_third_party_domains} domains, privacy score {r.privacy_impact_score}/100"

        descriptor.quiet_summary = quiet_summary

        # HTML fetch error
        if result.html_fetch_error:
            descriptor.add_row(
                label="HTML Fetch",
                value=f"Failed: {result.html_fetch_error}",
                style_class="error",
                severity="error",
                icon="cross",
                verbosity=VerbosityLevel.NORMAL,
            )
            return descriptor

        # Overall summary
        descriptor.add_row(
            label="Third-Party Domains",
            value=result.total_third_party_domains,
            style_class="info",
            icon="globe",
            severity="info",
            verbosity=VerbosityLevel.NORMAL,
        )

        descriptor.add_row(
            label="Total Resources",
            value=result.total_resources,
            style_class="info",
            icon="file",
            severity="info",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Privacy impact score with color coding
        score = result.privacy_impact_score
        if score >= 75:
            score_style = "error"
            score_icon = "warning"
        elif score >= 50:
            score_style = "warning"
            score_icon = "warning"
        elif score >= 25:
            score_style = "info"
            score_icon = "info"
        else:
            score_style = "success"
            score_icon = "check"

        descriptor.add_row(
            label="Privacy Impact Score",
            value=f"{score}/100",
            style_class=score_style,
            icon=score_icon,
            severity="warning" if score >= 50 else "info",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Category breakdown (verbose)
        if result.category_counts:
            descriptor.add_row(
                label="Categories",
                value=", ".join(f"{CATEGORY_DESCRIPTIONS.get(k, k)}: {v}" for k, v in sorted(result.category_counts.items())),
                section_type="text",
                style_class="info",
                verbosity=VerbosityLevel.VERBOSE,
            )

        # List of third-party domains
        if result.third_party_domains:
            for i, domain_info in enumerate(result.third_party_domains):
                # Determine style based on privacy impact
                impact_style = {
                    "low": "success",
                    "medium": "warning",
                    "high": "error",
                    "critical": "error",
                }.get(domain_info.privacy_impact, "neutral")

                impact_icon = {
                    "low": "check",
                    "medium": "warning",
                    "high": "warning",
                    "critical": "cross",
                }.get(domain_info.privacy_impact, "info")

                # Format domain info
                categories_str = ", ".join(sorted(domain_info.categories))
                service_display = domain_info.service_name or domain_info.domain
                
                descriptor.add_row(
                    label=domain_info.domain,
                    value=f"{service_display} ({domain_info.resource_count} resources, {categories_str})",
                    style_class=impact_style,
                    icon=impact_icon,
                    severity="warning" if domain_info.privacy_impact in ["high", "critical"] else "info",
                    section_name="Third-Party Domains",
                    verbosity=VerbosityLevel.NORMAL if i < 10 else VerbosityLevel.VERBOSE,
                )

        # Privacy recommendations
        if result.privacy_impact_score >= 50:
            descriptor.add_row(
                value="⚠️ High privacy impact detected. Consider reducing third-party tracking services.",
                section_type="text",
                style_class="warning",
                icon="warning",
                severity="warning",
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

    def to_dict(self, result: ThirdPartyAnalysisResult) -> dict[str, Any]:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Third-party analysis result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "total_resources": result.total_resources,
            "total_third_party_domains": result.total_third_party_domains,
            "privacy_impact_score": result.privacy_impact_score,
            "category_counts": result.category_counts,
            "third_party_domains": [
                {
                    "domain": d.domain,
                    "service_name": d.service_name,
                    "resource_count": d.resource_count,
                    "categories": sorted(list(d.categories)),
                    "resource_types": sorted(list(d.resource_types)),
                    "privacy_impact": d.privacy_impact,
                    "urls": d.urls[:10],  # Limit URLs in JSON output
                }
                for d in result.third_party_domains
            ],
            "resources": [
                {
                    "url": r.url,
                    "domain": r.domain,
                    "resource_type": r.resource_type,
                    "category": r.category,
                    "service_name": r.service_name,
                    "privacy_impact": r.privacy_impact,
                    "is_known": r.is_known,
                }
                for r in result.resources[:100]  # Limit resources in JSON output
            ],
            "errors": result.errors,
            "warnings": result.warnings,
        }
