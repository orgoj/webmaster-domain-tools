"""Technology stack analyzer - detect web technologies, frameworks, and platforms.

This analyzer detects various web technologies including CMS, frameworks,
server software, libraries, e-commerce platforms, and other detectable technologies.
Provides comprehensive technology fingerprinting from HTML content and HTTP headers.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import Field

from ..constants import DEFAULT_USER_AGENT
from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class TechnologyConfig(AnalyzerConfig):
    """Technology analyzer configuration."""

    check_html: bool = Field(default=True, description="Check HTML content for technology signatures")
    check_headers: bool = Field(default=True, description="Check HTTP headers for technology signatures")
    check_scripts: bool = Field(default=True, description="Check script sources for technology signatures")
    check_meta: bool = Field(default=True, description="Check meta tags for technology signatures")
    user_agent: str = Field(default=DEFAULT_USER_AGENT, description="User agent for HTTP requests")


# ============================================================================
# Technology Detection Database
# ============================================================================

# Technology categories
TECH_CATEGORIES = {
    "cms": "Content Management System",
    "framework": "JavaScript Framework",
    "server": "Server Software",
    "library": "JavaScript Library",
    "ecommerce": "E-commerce Platform",
    "analytics": "Analytics",
    "advertising": "Advertising",
    "cdn": "Content Delivery Network",
    "font": "Web Font Service",
    "platform": "Platform",
    "builder": "Website Builder",
    "programming": "Programming Language",
    "database": "Database",
    "cache": "Caching",
    "security": "Security",
    "unknown": "Unknown Technology",
}

# HTML detection patterns
# Format: technology_name -> (category, detection_patterns, confidence_level)
HTML_PATTERNS: dict[str, tuple[str, list[str], str]] = {
    # Content Management Systems
    "WordPress": (
        "cms",
        [
            r'<meta\s+name="generator"\s+content="WordPress',
            r'wp-content/',
            r'wp-includes/',
            r'wp-json/',
            r'/xmlrpc\.php',
            r'wp-embed',
            r'wp-block',
            r'class=".*?wp-',
        ],
        "high",
    ),
    "Drupal": (
        "cms",
        [
            r'<meta\s+name="generator"\s+content="Drupal',
            r'Drupal\.settings',
            r'/sites/default/files/',
            r'/misc/drupal\.js',
            r'data-drupal-',
        ],
        "high",
    ),
    "Joomla": (
        "cms",
        [
            r'<meta\s+name="generator"\s+content="Joomla',
            r'/media/jui/',
            r'/components/com_',
            r'/administrator/',
            r'option=com_',
        ],
        "high",
    ),
    "Magento": (
        "ecommerce",
        [
            r'<meta\s+name="generator"\s+content="Magento',
            r'/skin/frontend/',
            r'/js/mage/',
            r'Mage\.Cookies',
            r'magento',
        ],
        "high",
    ),
    "Shopify": (
        "ecommerce",
        [
            r'cdn\.shopify\.com',
            r'Shopify\.theme',
            r'shopify-section',
            r'myshopify\.com',
        ],
        "high",
    ),
    "Wix": (
        "builder",
        [
            r'wix\.com',
            r'wixstatic\.com',
            r'wixcode-',
            r'X-Wix-',
        ],
        "high",
    ),
    "Squarespace": (
        "builder",
        [
            r'squarespace\.com',
            r'static\.squarespace\.com',
            r'Squarespace\.Constants',
        ],
        "high",
    ),
    "Webflow": (
        "builder",
        [
            r'webflow\.com',
            r'webflow\.css',
            r'data-wf-',
        ],
        "high",
    ),
    "Ghost": (
        "cms",
        [
            r'<meta\s+name="generator"\s+content="Ghost',
            r'ghost-url',
            r'/ghost/api/',
        ],
        "high",
    ),
    "HubSpot CMS": (
        "cms",
        [
            r'hs-scripts\.com',
            r'hubspot\.net',
            r'hbspt\.forms',
        ],
        "high",
    ),
    "Craft CMS": (
        "cms",
        [
            r'/craft/app/',
            r'craft\.cms',
        ],
        "medium",
    ),
    "TYPO3": (
        "cms",
        [
            r'<meta\s+name="generator"\s+content="TYPO3',
            r'typo3temp/',
            r'typo3conf/',
        ],
        "high",
    ),
    "Contao": (
        "cms",
        [
            r'<meta\s+name="generator"\s+content="Contao',
            r'contao\.css',
        ],
        "high",
    ),
    "Bitrix": (
        "cms",
        [
            r'bitrix/',
            r'/bitrix/js/',
            r'bx-core',
        ],
        "high",
    ),
    "Adobe Experience Manager": (
        "cms",
        [
            r'/etc/clientlibs/',
            r'/content/dam/',
            r'cq:template',
        ],
        "medium",
    ),

    # E-commerce Platforms
    "WooCommerce": (
        "ecommerce",
        [
            r'woocommerce',
            r'wc-block',
            r'/wc-api/',
            r'wc_add_to_cart',
        ],
        "high",
    ),
    "PrestaShop": (
        "ecommerce",
        [
            r'<meta\s+name="generator"\s+content="PrestaShop',
            r'/modules/',
            r'prestashop',
        ],
        "high",
    ),
    "OpenCart": (
        "ecommerce",
        [
            r'catalog/view/theme/',
            r'opencart',
        ],
        "medium",
    ),
    "BigCommerce": (
        "ecommerce",
        [
            r'bigcommerce\.com',
            r'BCData',
        ],
        "high",
    ),
    "Salesforce Commerce Cloud": (
        "ecommerce",
        [
            r'demandware\.net',
            r'demandware\.store',
        ],
        "high",
    ),

    # JavaScript Frameworks
    "React": (
        "framework",
        [
            r'react\.js',
            r'react\.min\.js',
            r'react-dom',
            r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
            r'data-reactroot',
            r'data-reactid',
        ],
        "high",
    ),
    "Vue.js": (
        "framework",
        [
            r'vue\.js',
            r'vue\.min\.js',
            r'vue@',
            r'data-v-',
            r'__VUE__',
            r'Vue\.',
        ],
        "high",
    ),
    "Angular": (
        "framework",
        [
            r'angular\.js',
            r'angular\.min\.js',
            r'ng-app',
            r'ng-controller',
            r'ng-version',
            r'ng-binding',
            r'_ng[a-z]+_',
        ],
        "high",
    ),
    "Svelte": (
        "framework",
        [
            r'svelte',
            r'svelte-[a-z0-9]+',
        ],
        "medium",
    ),
    "Ember.js": (
        "framework",
        [
            r'ember\.js',
            r'ember\.min\.js',
            r'Ember\.ENV',
        ],
        "high",
    ),
    "Backbone.js": (
        "framework",
        [
            r'backbone\.js',
            r'backbone\.min\.js',
        ],
        "high",
    ),
    "Knockout.js": (
        "framework",
        [
            r'knockout\.js',
            r'ko\.observable',
            r'data-bind=',
        ],
        "high",
    ),
    "Next.js": (
        "framework",
        [
            r'__NEXT_DATA__',
            r'_next/static/',
            r'next/dist/',
        ],
        "high",
    ),
    "Nuxt.js": (
        "framework",
        [
            r'__NUXT__',
            r'_nuxt/',
            r'nuxt-link',
        ],
        "high",
    ),
    "Gatsby": (
        "framework",
        [
            r'gatsby',
            r'gatsby-image',
            r'gatsby-link',
            r'data-gatsby-',
        ],
        "high",
    ),
    "Remix": (
        "framework",
        [
            r'__remixContext',
            r'remix-run',
        ],
        "high",
    ),
    "Astro": (
        "framework",
        [
            r'astro',
            r'astro-[a-z0-9]+',
        ],
        "medium",
    ),
    "SolidJS": (
        "framework",
        [
            r'solid\.js',
            r'solid-js',
        ],
        "high",
    ),
    "Alpine.js": (
        "framework",
        [
            r'alpine\.js',
            r'alpine@',
            r'x-data',
            r'x-bind',
            r'x-show',
        ],
        "high",
    ),
    "HTMX": (
        "framework",
        [
            r'htmx\.js',
            r'htmx\.min\.js',
            r'hx-get',
            r'hx-post',
            r'hx-trigger',
        ],
        "high",
    ),
    "Stimulus": (
        "framework",
        [
            r'stimulus',
            r'data-controller',
            r'data-action',
            r'data-target',
        ],
        "high",
    ),
    "Livewire": (
        "framework",
        [
            r'livewire',
            r'wire:id',
            r'wire:click',
        ],
        "high",
    ),

    # JavaScript Libraries
    "jQuery": (
        "library",
        [
            r'jquery\.js',
            r'jquery\.min\.js',
            r'jquery-[0-9]+\.[0-9]+',
            r'jquery\.css',
        ],
        "high",
    ),
    "jQuery UI": (
        "library",
        [
            r'jquery-ui',
            r'jqueryui',
        ],
        "high",
    ),
    "jQuery Mobile": (
        "library",
        [
            r'jquery-mobile',
            r'jquerymobile',
        ],
        "high",
    ),
    "Bootstrap": (
        "library",
        [
            r'bootstrap\.js',
            r'bootstrap\.min\.js',
            r'bootstrap\.css',
            r'btn-bootstrap',
        ],
        "high",
    ),
    "Tailwind CSS": (
        "library",
        [
            r'tailwindcss',
            r'tailwind\.css',
        ],
        "high",
    ),
    "Foundation": (
        "library",
        [
            r'foundation\.js',
            r'foundation\.min\.js',
            r'foundation\.css',
        ],
        "high",
    ),
    "Bulma": (
        "library",
        [
            r'bulma\.css',
            r'bulma\.min\.css',
        ],
        "high",
    ),
    "Material Design": (
        "library",
        [
            r'material-design',
            r'mdl-',
            r'mdc-',
        ],
        "high",
    ),
    "Chakra UI": (
        "library",
        [
            r'chakra-ui',
            r'chakra',
        ],
        "high",
    ),
    "Material-UI": (
        "library",
        [
            r'mui-',
            r'@mui/',
            r'material-ui',
        ],
        "high",
    ),
    "Ant Design": (
        "library",
        [
            r'antd',
            r'ant-design',
            r'ant-btn',
        ],
        "high",
    ),
    "Element UI": (
        "library",
        [
            r'element-ui',
            r'el-button',
            r'el-input',
        ],
        "high",
    ),
    "Lodash": (
        "library",
        [
            r'lodash\.js',
            r'lodash\.min\.js',
        ],
        "high",
    ),
    "Underscore.js": (
        "library",
        [
            r'underscore\.js',
            r'underscore\.min\.js',
        ],
        "high",
    ),
    "Moment.js": (
        "library",
        [
            r'moment\.js',
            r'moment\.min\.js',
        ],
        "high",
    ),
    "D3.js": (
        "library",
        [
            r'd3\.js',
            r'd3\.min\.js',
            r'd3-selection',
        ],
        "high",
    ),
    "Three.js": (
        "library",
        [
            r'three\.js',
            r'three\.min\.js',
            r'THREE\.',
        ],
        "high",
    ),
    "GSAP": (
        "library",
        [
            r'gsap\.js',
            r'TweenMax',
            r'TimelineMax',
        ],
        "high",
    ),
    "Chart.js": (
        "library",
        [
            r'chart\.js',
            r'Chart\.js',
            r'chartjs',
        ],
        "high",
    ),
    "Axios": (
        "library",
        [
            r'axios\.js',
            r'axios\.min\.js',
        ],
        "high",
    ),
    "Redux": (
        "library",
        [
            r'redux\.js',
            r'redux\.min\.js',
            r'redux-thunk',
            r'__REDUX_DEVTOOLS__',
        ],
        "high",
    ),
    "MobX": (
        "library",
        [
            r'mobx',
        ],
        "high",
    ),

    # Server-side Frameworks
    "Laravel": (
        "framework",
        [
            r'laravel',
            r'Laravel\.framework',
            r'csrf-token.*laravel',
        ],
        "high",
    ),
    "Django": (
        "framework",
        [
            r'csrfmiddlewaretoken',
            r'django',
            r'__admin__',
        ],
        "high",
    ),
    "Ruby on Rails": (
        "framework",
        [
            r'rails',
            r'csrf-token',
            r'data-turbolinks',
            r'turbolinks',
        ],
        "high",
    ),
    "ASP.NET": (
        "framework",
        [
            r'__VIEWSTATE',
            r'__EVENTVALIDATION',
            r'asp\.net',
            r'\.aspx',
        ],
        "high",
    ),

    # Analytics and Tracking
    "Google Analytics": (
        "analytics",
        [
            r'google-analytics\.com',
            r'gtag\(',
            r'ga\.js',
            r'analytics\.js',
            r'UA-\d+',
            r'G-\w+',
        ],
        "high",
    ),
    "Google Tag Manager": (
        "analytics",
        [
            r'googletagmanager\.com',
            r'GTM-',
            r'dataLayer',
        ],
        "high",
    ),
    "Hotjar": (
        "analytics",
        [
            r'hotjar\.com',
            r'hj\(',
        ],
        "high",
    ),
    "Mixpanel": (
        "analytics",
        [
            r'mixpanel\.com',
            r'mixpanel\.track',
        ],
        "high",
    ),
    "Segment": (
        "analytics",
        [
            r'segment\.com',
            r'analytics\.track',
        ],
        "high",
    ),
    "Plausible": (
        "analytics",
        [
            r'plausible\.io',
            r'plausible',
        ],
        "high",
    ),
    "Fathom": (
        "analytics",
        [
            r'fathom',
            r'cdn\.usefathom\.com',
        ],
        "high",
    ),
    "Matomo": (
        "analytics",
        [
            r'matomo',
            r'piwik',
            r'_paq\.push',
        ],
        "high",
    ),

    # Font Services
    "Google Fonts": (
        "font",
        [
            r'fonts\.googleapis\.com',
            r'fonts\.gstatic\.com',
        ],
        "high",
    ),
    "Adobe Fonts": (
        "font",
        [
            r'use\.typekit\.net',
            r'fonts\.adobe\.com',
        ],
        "high",
    ),
    "Font Awesome": (
        "font",
        [
            r'fontawesome',
            r'font-awesome',
            r'fa-',
            r'fab fa-',
            r'fas fa-',
        ],
        "high",
    ),

    # Content Platforms
    "Contentful": (
        "platform",
        [
            r'contentful\.com',
            r'ctfassets\.net',
        ],
        "high",
    ),
    "Prismic": (
        "platform",
        [
            r'prismic\.io',
            r'prismic\.dom',
        ],
        "high",
    ),
    "Sanity": (
        "platform",
        [
            r'sanity\.io',
            r'sanity\.cdn',
        ],
        "high",
    ),

    # Advertising
    "Google AdSense": (
        "advertising",
        [
            r'googlesyndication\.com',
            r'adsense',
            r'google_ad',
        ],
        "high",
    ),
    "Facebook Pixel": (
        "advertising",
        [
            r'connect\.facebook\.net.*fbevents',
            r'fbq\(',
        ],
        "high",
    ),

    # Build Tools
    "Webpack": (
        "library",
        [
            r'webpack',
            r'webpackChunk',
            r'webpackJsonp',
        ],
        "high",
    ),
    "Vite": (
        "library",
        [
            r'vite',
            r'/@vite/',
        ],
        "high",
    ),

    # Miscellaneous
    "PWA": (
        "platform",
        [
            r'manifest\.json',
            r'service-worker\.js',
            r'serviceWorker',
        ],
        "high",
    ),
    "AMP": (
        "platform",
        [
            r'amp-boilerplate',
            r'amp-',
        ],
        "high",
    ),
}

# HTTP Header detection patterns
HEADER_PATTERNS: dict[str, tuple[str, dict[str, list[str]], str]] = {
    "nginx": (
        "server",
        {"server": ["nginx"]},
        "high",
    ),
    "Apache": (
        "server",
        {"server": ["Apache", "apache2"]},
        "high",
    ),
    "Microsoft-IIS": (
        "server",
        {"server": ["Microsoft-IIS", "IIS"]},
        "high",
    ),
    "LiteSpeed": (
        "server",
        {"server": ["LiteSpeed", "litespeed"]},
        "high",
    ),
    "OpenResty": (
        "server",
        {"server": ["openresty"]},
        "high",
    ),
    "Caddy": (
        "server",
        {"server": ["Caddy", "caddy"]},
        "high",
    ),
    "Cloudflare": (
        "server",
        {"server": ["cloudflare"], "cf-ray": []},
        "high",
    ),
    "Varnish": (
        "cache",
        {"via": ["Varnish", "varnish"], "x-varnish": []},
        "high",
    ),
    "Squid": (
        "cache",
        {"server": ["squid"], "via": ["squid"]},
        "high",
    ),
    "PHP": (
        "programming",
        {"x-powered-by": ["PHP", "php"]},
        "high",
    ),
    "Express.js": (
        "framework",
        {"x-powered-by": ["Express", "express"]},
        "high",
    ),
    "ASP.NET": (
        "framework",
        {"x-powered-by": ["ASP.NET", "asp.net"], "x-aspnet-version": []},
        "high",
    ),
    "Next.js": (
        "framework",
        {"x-powered-by": ["Next.js"]},
        "high",
    ),
    "Phusion Passenger": (
        "server",
        {"x-powered-by": ["Phusion Passenger", "Passenger"]},
        "high",
    ),
}


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class DetectedTechnology:
    """A detected web technology."""

    name: str
    category: str
    confidence: str  # high, medium, low
    detection_method: str  # html, header, script, meta
    evidence: list[str] = field(default_factory=list)


@dataclass
class TechnologyCategory:
    """Technologies grouped by category."""

    category_id: str
    category_name: str
    technologies: list[DetectedTechnology] = field(default_factory=list)


@dataclass
class TechnologyAnalysisResult:
    """Results from technology analysis."""

    domain: str
    html_content: str | None = None
    html_fetch_error: str | None = None
    http_headers: dict[str, str] | None = None

    # Detected technologies
    technologies: list[DetectedTechnology] = field(default_factory=list)
    categories: dict[str, TechnologyCategory] = field(default_factory=dict)

    # Summary
    total_technologies: int = 0
    cms: str | None = None
    framework: str | None = None
    server: str | None = None
    ecommerce: str | None = None

    # Errors and warnings
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class TechnologyAnalyzer:
    """
    Technology stack analyzer - detects web technologies, frameworks, and platforms.

    This analyzer scans HTML content and HTTP headers to identify:
    - Content Management Systems (WordPress, Drupal, Joomla, etc.)
    - JavaScript Frameworks (React, Vue, Angular, etc.)
    - Server Software (nginx, Apache, etc.)
    - JavaScript Libraries (jQuery, Bootstrap, etc.)
    - E-commerce Platforms (Shopify, WooCommerce, etc.)
    - Analytics and Tracking services
    - And more...

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (TechnologyConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "technology"
    name = "Technology Stack"
    description = "Detect web technologies, frameworks, and platforms"
    category = "general"
    icon = "code"
    config_class = TechnologyConfig
    depends_on = ["http"]  # Needs HTTP result for headers

    # ========================================================================
    # Analysis Methods
    # ========================================================================

    def analyze(
        self,
        domain: str,
        config: TechnologyConfig,
        context: dict[str, Any] | None = None,
    ) -> TechnologyAnalysisResult:
        """
        Perform technology stack analysis.

        Args:
            domain: Domain to analyze
            config: Technology analyzer configuration
            context: Optional context with results from dependency analyzers

        Returns:
            TechnologyAnalysisResult with detected technologies
        """
        logger.info(f"Starting technology analysis for {domain}")
        result = TechnologyAnalysisResult(domain=domain)

        # Normalize domain
        domain = domain.rstrip("/").lower()

        # Get HTML content and headers from context or fetch them
        html_content = None
        http_headers = None

        if context and "http" in context:
            http_result = context.get("http")
            if hasattr(http_result, "html_content"):
                html_content = http_result.html_content
            if hasattr(http_result, "headers"):
                http_headers = http_result.headers

        # Fetch HTML if not available from context
        if not html_content:
            html_content = self._fetch_html(domain, config, result)

        if html_content:
            result.html_content = html_content

        # Use headers from result (set by _fetch_html) if not from context
        if http_headers is None and result.http_headers:
            http_headers = result.http_headers

        # Detect technologies from different sources
        detected_names: set[str] = set()

        # 1. Detect from HTML content
        if html_content and config.check_html:
            html_technologies = self._detect_from_html(html_content, config)
            for tech in html_technologies:
                if tech.name not in detected_names:
                    detected_names.add(tech.name)
                    result.technologies.append(tech)

        # 2. Detect from HTTP headers
        if http_headers and config.check_headers:
            header_technologies = self._detect_from_headers(http_headers)
            for tech in header_technologies:
                if tech.name not in detected_names:
                    detected_names.add(tech.name)
                    result.technologies.append(tech)

        # Group technologies by category
        self._group_by_category(result)

        # Calculate summary
        self._calculate_summary(result)

        # Log results
        logger.info(f"Detected {result.total_technologies} technologies for {domain}")

        return result

    def _fetch_html(
        self,
        domain: str,
        config: TechnologyConfig,
        result: TechnologyAnalysisResult,
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
                        # Store headers
                        result.http_headers = dict(response.headers)
                        return response.text

            except httpx.HTTPError as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Error fetching {url}: {e}")
                continue

        result.html_fetch_error = f"Could not fetch HTML from {domain}"
        return None

    def _detect_from_html(
        self,
        html_content: str,
        config: TechnologyConfig,
    ) -> list[DetectedTechnology]:
        """
        Detect technologies from HTML content.

        Args:
            html_content: HTML to analyze
            config: Configuration

        Returns:
            List of detected technologies
        """
        technologies: list[DetectedTechnology] = []

        # Check each technology pattern
        for tech_name, (category, patterns, confidence) in HTML_PATTERNS.items():
            evidence: list[str] = []
            detection_method = "html"

            for pattern in patterns:
                try:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    if matches:
                        evidence.extend(matches[:3])  # Limit evidence
                except re.error:
                    continue

            if evidence:
                # Determine detection method
                if config.check_scripts and any(".js" in p for p in patterns):
                    detection_method = "script"
                elif config.check_meta and any("meta" in p.lower() for p in patterns):
                    detection_method = "meta"

                technologies.append(
                    DetectedTechnology(
                        name=tech_name,
                        category=category,
                        confidence=confidence,
                        detection_method=detection_method,
                        evidence=list(set(evidence))[:5],  # Dedupe and limit
                    )
                )

        return technologies

    def _detect_from_headers(
        self,
        headers: dict[str, str],
    ) -> list[DetectedTechnology]:
        """
        Detect technologies from HTTP headers.

        Args:
            headers: HTTP headers dictionary

        Returns:
            List of detected technologies
        """
        technologies: list[DetectedTechnology] = []

        # Normalize headers to lowercase
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check each header pattern
        for tech_name, (category, header_patterns, confidence) in HEADER_PATTERNS.items():
            evidence: list[str] = []

            for header_name, patterns in header_patterns.items():
                header_value = headers_lower.get(header_name.lower(), "")
                if header_value:
                    if not patterns:  # Empty patterns = just check header exists
                        evidence.append(f"{header_name}: {header_value}")
                    else:
                        for pattern in patterns:
                            if pattern.lower() in header_value.lower():
                                evidence.append(f"{header_name}: {header_value}")
                                break

            if evidence:
                technologies.append(
                    DetectedTechnology(
                        name=tech_name,
                        category=category,
                        confidence=confidence,
                        detection_method="header",
                        evidence=evidence[:3],
                    )
                )

        return technologies

    def _group_by_category(self, result: TechnologyAnalysisResult) -> None:
        """
        Group technologies by category.

        Args:
            result: Result object to update
        """
        category_map: dict[str, TechnologyCategory] = {}

        for tech in result.technologies:
            category_id = tech.category
            if category_id not in category_map:
                category_map[category_id] = TechnologyCategory(
                    category_id=category_id,
                    category_name=TECH_CATEGORIES.get(category_id, category_id.capitalize()),
                    technologies=[],
                )
            category_map[category_id].technologies.append(tech)

        # Sort technologies within each category by confidence
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        for category in category_map.values():
            category.technologies.sort(
                key=lambda t: confidence_order.get(t.confidence, 3)
            )

        result.categories = category_map

    def _calculate_summary(self, result: TechnologyAnalysisResult) -> None:
        """
        Calculate summary information.

        Args:
            result: Result object to update
        """
        result.total_technologies = len(result.technologies)

        # Extract key technologies (first high-confidence match per category)
        for tech in result.technologies:
            if tech.category == "cms" and result.cms is None and tech.confidence == "high":
                result.cms = tech.name
            elif tech.category == "framework" and result.framework is None and tech.confidence == "high":
                result.framework = tech.name
            elif tech.category == "server" and result.server is None:
                result.server = tech.name
            elif tech.category == "ecommerce" and result.ecommerce is None and tech.confidence == "high":
                result.ecommerce = tech.name

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def describe_output(self, result: TechnologyAnalysisResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: Technology analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary
        def quiet_summary(r: TechnologyAnalysisResult) -> str:
            parts = []
            if r.cms:
                parts.append(f"CMS: {r.cms}")
            if r.framework:
                parts.append(f"Framework: {r.framework}")
            if r.server:
                parts.append(f"Server: {r.server}")
            if not parts:
                parts.append(f"{r.total_technologies} technologies")
            return f"Tech: {', '.join(parts)}"

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

        # Summary row
        descriptor.add_row(
            label="Technologies Detected",
            value=result.total_technologies,
            style_class="info",
            icon="layers",
            severity="info",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Key technologies (CMS, Framework, Server, E-commerce)
        if result.cms:
            descriptor.add_row(
                label="CMS",
                value=result.cms,
                style_class="highlight",
                icon="content",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        if result.ecommerce:
            descriptor.add_row(
                label="E-commerce",
                value=result.ecommerce,
                style_class="highlight",
                icon="cart",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        if result.framework:
            descriptor.add_row(
                label="Framework",
                value=result.framework,
                style_class="highlight",
                icon="package",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        if result.server:
            descriptor.add_row(
                label="Server",
                value=result.server,
                style_class="info",
                icon="server",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        # Group by category (verbose output)
        if result.categories:
            # Sort categories by priority
            category_priority = ["cms", "ecommerce", "framework", "server", "library", "analytics", "platform", "font", "advertising", "cache"]
            sorted_categories = sorted(
                result.categories.items(),
                key=lambda x: category_priority.index(x[0]) if x[0] in category_priority else 999
            )

            for category_id, category in sorted_categories:
                section_name = category.category_name

                for tech in category.technologies:
                    # Confidence styling
                    confidence_style = {
                        "high": "success",
                        "medium": "warning",
                        "low": "muted",
                    }.get(tech.confidence, "neutral")

                    # Detection method icon
                    method_icon = {
                        "html": "file",
                        "header": "server",
                        "script": "code",
                        "meta": "tag",
                    }.get(tech.detection_method, "info")

                    # Format evidence for verbose display
                    evidence_str = ""
                    if tech.evidence:
                        evidence_str = f" ({tech.evidence[0][:50]}...)" if len(tech.evidence[0]) > 50 else f" ({tech.evidence[0]})"

                    descriptor.add_row(
                        label=tech.name,
                        value=f"{tech.confidence.capitalize()}{evidence_str}",
                        style_class=confidence_style,
                        icon=method_icon,
                        section_name=section_name,
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

    def to_dict(self, result: TechnologyAnalysisResult) -> dict[str, Any]:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Technology analysis result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "total_technologies": result.total_technologies,
            "cms": result.cms,
            "framework": result.framework,
            "server": result.server,
            "ecommerce": result.ecommerce,
            "technologies": [
                {
                    "name": tech.name,
                    "category": tech.category,
                    "category_name": TECH_CATEGORIES.get(tech.category, tech.category),
                    "confidence": tech.confidence,
                    "detection_method": tech.detection_method,
                    "evidence": tech.evidence[:5],
                }
                for tech in result.technologies
            ],
            "categories": {
                cat_id: {
                    "category_id": cat.category_id,
                    "category_name": cat.category_name,
                    "technologies": [tech.name for tech in cat.technologies],
                }
                for cat_id, cat in result.categories.items()
            },
            "errors": result.errors,
            "warnings": result.warnings,
        }
