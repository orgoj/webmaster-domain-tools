"""Core domain analysis functionality shared between CLI and GUI."""

import logging
from dataclasses import dataclass

from ..analyzers.advanced_email_security import (
    AdvancedEmailSecurityAnalyzer,
    AdvancedEmailSecurityResult,
)
from ..analyzers.cdn_detector import CDNDetectionResult, CDNDetector
from ..analyzers.dns_analyzer import DNSAnalysisResult, DNSAnalyzer
from ..analyzers.email_security import EmailSecurityAnalyzer, EmailSecurityResult
from ..analyzers.favicon_analyzer import FaviconAnalysisResult, FaviconAnalyzer
from ..analyzers.http_analyzer import HTTPAnalysisResult, HTTPAnalyzer, HTTPResponse
from ..analyzers.rbl_checker import RBLAnalysisResult, RBLChecker, extract_ips_from_dns_result
from ..analyzers.security_headers import SecurityHeadersAnalyzer, SecurityHeadersResult
from ..analyzers.seo_files_analyzer import SEOFilesAnalysisResult, SEOFilesAnalyzer
from ..analyzers.site_verification_analyzer import (
    ServiceConfig,
    SiteVerificationAnalysisResult,
    SiteVerificationAnalyzer,
)
from ..analyzers.ssl_analyzer import SSLAnalysisResult, SSLAnalyzer
from ..analyzers.whois_analyzer import WhoisAnalysisResult, WhoisAnalyzer
from ..config import Config

logger = logging.getLogger(__name__)


@dataclass
class AnalyzerMetadata:
    """
    Metadata for automatic analyzer registration and display.

    This enables the auto-display system where new analyzers can be added
    with minimal boilerplate. Most analyzers only need to be registered here
    with basic metadata, and both CLI and GUI will automatically display results.
    """

    # Display configuration
    title: str  # "WHOIS Information", "DNS Analysis", etc.
    icon: str  # For GUI: "INFO", "DNS", "HTTP", etc. (from ft.Icons)
    result_field: str  # Field name in DomainAnalysisResults: "whois", "dns", etc.

    # Rendering
    custom_renderer: str | None = None  # None = use auto-display, else specify renderer name

    # Optional metadata
    category: str = "general"  # "general", "security", "seo", "advanced"
    description: str = ""  # Optional description for documentation


# Analyzer Registry - Single source of truth for all analyzers
# To add a new analyzer:
# 1. Create analyzer class in analyzers/
# 2. Add entry here with metadata
# 3. Both CLI and GUI will automatically display it!
ANALYZER_REGISTRY: dict[str, AnalyzerMetadata] = {
    "whois": AnalyzerMetadata(
        title="WHOIS Information",
        icon="INFO",
        result_field="whois",
        custom_renderer="whois",  # Has custom links
        category="general",
        description="Domain registration and ownership information",
    ),
    "dns": AnalyzerMetadata(
        title="DNS Analysis",
        icon="DNS",
        result_field="dns",
        custom_renderer="dns",  # Has clickable IPs
        category="general",
        description="DNS records and DNSSEC validation",
    ),
    "http": AnalyzerMetadata(
        title="HTTP/HTTPS Analysis",
        icon="HTTP",
        result_field="http",
        custom_renderer="http",  # Special chain format
        category="general",
        description="HTTP/HTTPS redirects and response analysis",
    ),
    "ssl": AnalyzerMetadata(
        title="SSL/TLS Analysis",
        icon="SECURITY",
        result_field="ssl",
        custom_renderer="ssl",  # Has SSL Labs link
        category="security",
        description="SSL/TLS certificates and security",
    ),
    "email": AnalyzerMetadata(
        title="Email Security",
        icon="EMAIL",
        result_field="email",
        custom_renderer="email",  # Combined with advanced_email
        category="security",
        description="SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT",
    ),
    "headers": AnalyzerMetadata(
        title="Security Headers",
        icon="SHIELD",
        result_field="headers",
        custom_renderer="headers",  # List format
        category="security",
        description="HTTP security headers validation",
    ),
    "rbl": AnalyzerMetadata(
        title="RBL Blacklist Check",
        icon="BLOCK",
        result_field="rbl",
        custom_renderer="rbl",  # Has clickable IPs
        category="security",
        description="IP blacklist reputation check",
    ),
    "seo": AnalyzerMetadata(
        title="SEO Files",
        icon="SEARCH",
        result_field="seo",
        custom_renderer="seo",  # Has clickable file URLs
        category="seo",
        description="robots.txt, sitemap.xml, llms.txt detection",
    ),
    "favicon": AnalyzerMetadata(
        title="Favicon Detection",
        icon="IMAGE",
        result_field="favicon",
        custom_renderer="favicon",  # Has clickable favicon URLs
        category="seo",
        description="Favicon file detection and sizes",
    ),
    "site_verification": AnalyzerMetadata(
        title="Site Verification",
        icon="VERIFIED",
        result_field="site_verification",
        custom_renderer=None,  # Can use auto-display
        category="seo",
        description="Google, Facebook, Pinterest verification codes",
    ),
    "cdn": AnalyzerMetadata(
        title="CDN Detection",
        icon="CLOUD",
        result_field="cdn",
        custom_renderer=None,  # Can use auto-display
        category="advanced",
        description="Content Delivery Network detection",
    ),
}


@dataclass
class DomainAnalysisResults:
    """Container for all domain analysis results."""

    domain: str
    whois: WhoisAnalysisResult | None = None
    dns: DNSAnalysisResult | None = None
    http: HTTPAnalysisResult | None = None
    ssl: SSLAnalysisResult | None = None
    email: EmailSecurityResult | None = None
    advanced_email: AdvancedEmailSecurityResult | None = None
    headers: list[SecurityHeadersResult] | None = None
    rbl: RBLAnalysisResult | None = None
    seo: SEOFilesAnalysisResult | None = None
    favicon: FaviconAnalysisResult | None = None
    site_verification: SiteVerificationAnalysisResult | None = None
    cdn: CDNDetectionResult | None = None


def get_preferred_final_url(
    http_result: HTTPAnalysisResult,
) -> tuple[str | None, HTTPResponse | None, list[str], list[str]]:
    """
    Analyze redirect chains and return the preferred final URL.

    This function checks all redirect chains and determines the single
    canonical final URL to use for content analysis (security headers,
    tracking codes, etc.).

    Args:
        http_result: HTTP analysis result with redirect chains

    Returns:
        Tuple of (preferred_url, preferred_response, warnings, errors):
        - preferred_url: The selected final URL (or None if no successful chains)
        - preferred_response: The HTTP response for that URL (or None)
        - warnings: List of warning messages
        - errors: List of error messages (e.g., inconsistent redirect chains)
    """
    warnings = []
    errors = []

    # Collect unique final URLs from all successful redirect chains
    final_urls = {}  # normalized_url -> (original_url, response)

    for chain in http_result.chains:
        if chain.responses:
            last_response = chain.responses[-1]
            if last_response.status_code == 200:
                # Normalize URL for comparison (remove trailing slash, lowercase)
                normalized_url = last_response.url.rstrip("/").lower()

                if normalized_url not in final_urls:
                    final_urls[normalized_url] = (last_response.url, last_response)

    # No successful final URLs found
    if not final_urls:
        return None, None, warnings, errors

    # All chains lead to the same final URL - perfect!
    if len(final_urls) == 1:
        normalized_url = list(final_urls.keys())[0]
        final_url, final_response = final_urls[normalized_url]
        logger.debug(f"All redirect chains lead to the same final URL: {final_url}")
        return final_url, final_response, warnings, errors

    # Multiple different final URLs - this is a CONFIGURATION ERROR
    urls_list = [url for url, _ in final_urls.values()]
    error_msg = f"Redirect chains lead to different final URLs: {', '.join(urls_list)}"
    errors.append(error_msg)
    logger.debug(f"Configuration error detected: {error_msg}")

    # Choose preferred URL (priority: https with www > https without www > http)
    def url_priority(url: str) -> tuple[int, int, str]:
        """Return priority tuple (https=0/http=1, has_www=0/no_www=1, url)."""
        is_https = 0 if url.startswith("https://") else 1
        has_www = 0 if "://www." in url else 1
        return (is_https, has_www, url)

    # Sort by priority and take the best one
    preferred_normalized = min(final_urls.keys(), key=lambda k: url_priority(final_urls[k][0]))
    preferred_url, preferred_response = final_urls[preferred_normalized]

    logger.info(f"Using preferred final URL for analysis: {preferred_url}")
    return preferred_url, preferred_response, warnings, errors


def run_domain_analysis(
    domain: str,
    config: Config,
    # Optional parameters for CLI overrides
    nameservers: str | None = None,
    timeout: float | None = None,
    max_redirects: int | None = None,
    warn_www_not_cname: bool | None = None,
    skip_www: bool | None = None,
    dkim_selectors: str | None = None,
    check_path: str | None = None,
    verify: list[str] | None = None,
    # Skip flags
    skip_whois: bool = False,
    skip_dns: bool = False,
    skip_http: bool = False,
    skip_ssl: bool = False,
    skip_email: bool = False,
    skip_headers: bool = False,
    skip_site_verification: bool = False,
    do_rbl_check: bool = False,
    # Progress callback for GUI
    progress_callback: callable | None = None,
) -> DomainAnalysisResults:
    """
    Run complete domain analysis based on configuration.

    This is the SINGLE SOURCE OF TRUTH for running domain analysis.
    Both CLI and GUI should call this function.

    Args:
        domain: Domain name to analyze
        config: Configuration object
        nameservers: Optional comma-separated nameserver IPs (overrides config)
        timeout: Optional timeout in seconds (overrides config)
        max_redirects: Optional max redirects (overrides config)
        warn_www_not_cname: Optional www CNAME warning flag (overrides config)
        skip_www: Optional flag to skip www subdomain checks (overrides config)
        dkim_selectors: Optional comma-separated DKIM selectors (overrides config)
        check_path: Optional path to check on final URL
        verify: Optional list of verification IDs in "Service:ID" format
        skip_whois: Skip WHOIS analysis
        skip_dns: Skip DNS analysis
        skip_http: Skip HTTP analysis
        skip_ssl: Skip SSL analysis
        skip_email: Skip email security analysis
        skip_headers: Skip security headers analysis
        skip_site_verification: Skip site verification analysis
        do_rbl_check: Enable RBL blacklist checking

    Returns:
        DomainAnalysisResults containing all analysis results
    """
    results = DomainAnalysisResults(domain=domain)

    # WHOIS Analysis
    if not skip_whois:
        if progress_callback:
            progress_callback("Running WHOIS analysis...")
        logger.info("Running WHOIS analysis...")
        whois_analyzer = WhoisAnalyzer(
            expiry_warning_days=config.whois.expiry_warning_days,
            expiry_critical_days=config.whois.expiry_critical_days,
        )
        results.whois = whois_analyzer.analyze(domain)

    # DNS Analysis
    if not skip_dns:
        if progress_callback:
            progress_callback("Running DNS analysis...")
        logger.info("Running DNS analysis...")
        dns_analyzer = DNSAnalyzer(
            nameservers=nameservers.split(",") if nameservers else config.dns.nameservers,
            check_dnssec=config.dns.check_dnssec,
            warn_www_not_cname=(
                warn_www_not_cname
                if warn_www_not_cname is not None
                else config.dns.warn_www_not_cname
            ),
            skip_www=skip_www if skip_www else config.analysis.skip_www,
        )
        results.dns = dns_analyzer.analyze(domain)

    # HTTP/HTTPS Analysis
    if not skip_http:
        if progress_callback:
            progress_callback("Running HTTP/HTTPS analysis...")
        logger.info("Running HTTP/HTTPS analysis...")
        http_analyzer = HTTPAnalyzer(
            timeout=timeout if timeout else config.http.timeout,
            max_redirects=max_redirects if max_redirects else config.http.max_redirects,
            skip_www=skip_www if skip_www else config.analysis.skip_www,
        )
        results.http = http_analyzer.analyze(domain)

        # Analyze redirect chains and add any errors/warnings BEFORE returning
        preferred_url, _, url_warnings, url_errors = get_preferred_final_url(results.http)
        results.http.errors.extend(url_errors)
        results.http.warnings.extend(url_warnings)
        results.http.preferred_final_url = preferred_url

        # Check specific path if requested
        if check_path and preferred_url:
            logger.info(f"Checking path: {check_path}")
            path_result = http_analyzer.check_path(preferred_url, check_path)
            results.http.path_check_result = path_result

    # CDN Detection (uses DNS CNAME + HTTP headers)
    if not config.analysis.skip_cdn_detection and results.http:
        if progress_callback:
            progress_callback("Detecting CDN...")
        logger.info("Detecting CDN...")
        cdn_detector = CDNDetector()

        # Detect from HTTP headers
        if results.http.preferred_final_url and results.http.chains:
            # Get headers from preferred final response
            final_response = None
            for chain in results.http.chains:
                if chain.responses and chain.final_url == results.http.preferred_final_url:
                    final_response = chain.responses[-1]
                    break

            if final_response and final_response.headers:
                header_result = cdn_detector.detect_from_headers(final_response.headers)
                header_result.domain = domain

                # Detect from DNS CNAME if available
                cname_result = cdn_detector.detect_from_cname([])
                if results.dns:
                    cname_key = f"{domain}:CNAME"
                    if cname_key in results.dns.records:
                        cname_values = [r.value for r in results.dns.records[cname_key]]
                        cname_result = cdn_detector.detect_from_cname(cname_values)

                # Combine results
                results.cdn = cdn_detector.combine_results(domain, header_result, cname_result)

    # SSL/TLS Analysis
    if not skip_ssl:
        if progress_callback:
            progress_callback("Running SSL/TLS analysis...")
        logger.info("Running SSL/TLS analysis...")
        ssl_analyzer = SSLAnalyzer(
            timeout=timeout if timeout else config.http.timeout,
            cert_expiry_warning_days=config.ssl.cert_expiry_warning_days,
            cert_expiry_critical_days=config.ssl.cert_expiry_critical_days,
        )
        results.ssl = ssl_analyzer.analyze(domain)

    # Email Security Analysis (SPF, DKIM, DMARC + BIMI, MTA-STS, TLS-RPT)
    if not skip_email:
        if progress_callback:
            progress_callback("Running email security analysis...")
        logger.info("Running email security analysis...")
        selectors = dkim_selectors.split(",") if dkim_selectors else config.email.dkim_selectors
        email_analyzer = EmailSecurityAnalyzer(dkim_selectors=selectors)
        results.email = email_analyzer.analyze(domain)

        # Advanced Email Security (BIMI, MTA-STS, TLS-RPT)
        if not config.analysis.skip_advanced_email:
            if progress_callback:
                progress_callback("Running advanced email security analysis...")
            logger.info("Running advanced email security analysis...")
            advanced_email_analyzer = AdvancedEmailSecurityAnalyzer(
                nameservers=nameservers.split(",") if nameservers else config.dns.nameservers,
                check_bimi=config.advanced_email.check_bimi,
                check_mta_sts=config.advanced_email.check_mta_sts,
                check_tls_rpt=config.advanced_email.check_tls_rpt,
                timeout=timeout if timeout else config.http.timeout,
            )
            results.advanced_email = advanced_email_analyzer.analyze(domain)

    # Security Headers Analysis
    if not skip_headers and results.http:
        if progress_callback:
            progress_callback("Running security headers analysis...")
        logger.info("Running security headers analysis...")

        # Get the preferred final URL from all redirect chains
        # (errors/warnings already added to http_result in HTTP analysis section)
        final_url, final_response, _, _ = get_preferred_final_url(results.http)

        # Only analyze if we have a successful final URL
        if final_url and final_response:
            # Prepare enabled checks from config
            enabled_checks = {
                "check_strict_transport_security": config.security_headers.check_strict_transport_security,
                "check_content_security_policy": config.security_headers.check_content_security_policy,
                "check_x_frame_options": config.security_headers.check_x_frame_options,
                "check_x_content_type_options": config.security_headers.check_x_content_type_options,
                "check_referrer_policy": config.security_headers.check_referrer_policy,
                "check_permissions_policy": config.security_headers.check_permissions_policy,
                "check_x_xss_protection": config.security_headers.check_x_xss_protection,
                "check_content_type": config.security_headers.check_content_type,
            }

            # Analyze the preferred final URL
            headers_analyzer = SecurityHeadersAnalyzer(enabled_checks=enabled_checks)
            headers_result = headers_analyzer.analyze(
                final_response.url,
                final_response.headers,
            )
            results.headers = [headers_result]

    # Site Verification Analysis (Google, Facebook, Pinterest, etc.)
    if not skip_site_verification:
        # Build list of service configurations from config
        services = []
        for service_cfg in config.site_verification.services:
            services.append(
                ServiceConfig(
                    name=service_cfg.name,
                    ids=list(service_cfg.ids),  # Copy to avoid modifying config
                    dns_pattern=service_cfg.dns_pattern,
                    file_pattern=service_cfg.file_pattern,
                    meta_name=service_cfg.meta_name,
                    auto_detect=service_cfg.auto_detect,
                )
            )

        # Parse and add CLI-provided verification IDs
        if verify:
            for verify_arg in verify:
                # Support comma-separated values in single --verify
                # e.g., --verify "Google:ABC,Facebook:XYZ"
                verify_items = [item.strip() for item in verify_arg.split(",")]

                for verify_item in verify_items:
                    # Parse format: Service:ID
                    if ":" not in verify_item:
                        logger.error(
                            f"Invalid --verify format: '{verify_item}'. "
                            f"Expected format: 'Service:ID' (e.g., 'Google:ABC123')"
                        )
                        continue

                    service_name, verification_id = verify_item.split(":", 1)
                    service_name = service_name.strip()
                    verification_id = verification_id.strip()

                    if not service_name or not verification_id:
                        logger.error(
                            f"Invalid --verify format: '{verify_item}'. "
                            f"Both service name and ID are required."
                        )
                        continue

                    # Find service in list
                    service = next((s for s in services if s.name == service_name), None)
                    if service:
                        # Add CLI ID to existing service (if not already there)
                        if verification_id not in service.ids:
                            service.ids.append(verification_id)
                            logger.debug(
                                f"Added verification ID for {service_name}: {verification_id}"
                            )
                    else:
                        # Service not in config, log warning
                        logger.warning(
                            f"Service '{service_name}' not found in predefined services. "
                            f"Available services: {', '.join(s.name for s in services)}. "
                            f"Add custom service to config.site_verification.services if needed."
                        )

        # Only run if there are services configured
        if services:
            if progress_callback:
                progress_callback("Running site verification analysis...")
            logger.info("Running site verification analysis...")
            site_verification_analyzer = SiteVerificationAnalyzer(
                services=services,
                timeout=timeout if timeout else config.http.timeout,
                nameservers=nameservers.split(",") if nameservers else config.dns.nameservers,
            )

            # Use preferred final URL from HTTP analysis if available
            verification_url = None
            if results.http:
                final_url, final_response, _, _ = get_preferred_final_url(results.http)
                verification_url = final_url

            results.site_verification = site_verification_analyzer.analyze(
                domain, url=verification_url
            )

    # RBL (Blacklist) Check
    if do_rbl_check and results.dns:
        if progress_callback:
            progress_callback("Running RBL blacklist check...")
        logger.info("Running RBL blacklist check...")
        ips = extract_ips_from_dns_result(results.dns)
        if ips:
            rbl_checker = RBLChecker(
                rbl_servers=config.email.rbl_servers,
                timeout=config.dns.timeout,
            )
            results.rbl = rbl_checker.check_ips(domain, ips)
        else:
            logger.debug("No IP addresses found for RBL check")

    # SEO Files Analysis (robots.txt, sitemap.xml, llms.txt)
    if not config.analysis.skip_seo and results.http and results.http.preferred_final_url:
        if progress_callback:
            progress_callback("Running SEO files analysis...")
        logger.info("Running SEO files analysis...")
        seo_analyzer = SEOFilesAnalyzer(
            timeout=timeout if timeout else config.http.timeout,
            check_robots=config.seo.check_robots,
            check_llms_txt=config.seo.check_llms_txt,
            check_sitemap=config.seo.check_sitemap,
        )
        results.seo = seo_analyzer.analyze(results.http.preferred_final_url)

    # Favicon Detection
    if not config.analysis.skip_favicon and results.http and results.http.preferred_final_url:
        if progress_callback:
            progress_callback("Running favicon detection...")
        logger.info("Running favicon detection...")
        favicon_analyzer = FaviconAnalyzer(
            timeout=timeout if timeout else config.http.timeout,
            check_html=config.favicon.check_html,
            check_defaults=config.favicon.check_defaults,
        )
        results.favicon = favicon_analyzer.analyze(results.http.preferred_final_url)

    logger.info("Analysis complete")
    return results
