"""Command-line interface for webmaster-domain-tool."""

import logging
import re
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich import box
import rich.panel

logger = logging.getLogger(__name__)

# Remove borders from CLI help output by monkey-patching Panel
_original_panel_init = rich.panel.Panel.__init__


def _no_border_panel_init(self, *args, **kwargs):
    # Remove borders from panels - use HORIZONTALS for minimal formatting
    kwargs['box'] = box.HORIZONTALS
    return _original_panel_init(self, *args, **kwargs)


rich.panel.Panel.__init__ = _no_border_panel_init

from .analyzers.dns_analyzer import DNSAnalyzer
from .analyzers.http_analyzer import HTTPAnalyzer, HTTPAnalysisResult, HTTPResponse
from .analyzers.ssl_analyzer import SSLAnalyzer
from .analyzers.email_security import EmailSecurityAnalyzer
from .analyzers.security_headers import SecurityHeadersAnalyzer
from .analyzers.rbl_checker import RBLChecker, extract_ips_from_dns_result
from .analyzers.site_verification_analyzer import (
    SiteVerificationAnalyzer,
    ServiceConfig,
)
from .analyzers.whois_analyzer import WhoisAnalyzer
from .config import load_config, create_default_user_config, Config
from .utils.logger import setup_logger, VerbosityLevel
from .utils.output import OutputFormatter

app = typer.Typer(
    name="webmaster-domain-tool",
    help="Comprehensive domain analysis tool for webmasters",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


# Validation functions
def validate_domain(domain: str) -> str:
    """Validate domain name format."""
    # Remove protocol and trailing slash if present
    domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

    # Basic domain validation regex
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )

    if not domain_pattern.match(domain):
        raise typer.BadParameter(
            f"Invalid domain format: {domain}. Expected format: example.com"
        )

    return domain


def validate_timeout(value: float) -> float:
    """Validate timeout value."""
    if value <= 0 or value > 300:
        raise typer.BadParameter("Timeout must be between 0 and 300 seconds")
    return value


def validate_max_redirects(value: int) -> int:
    """Validate max redirects value."""
    if value < 0 or value > 50:
        raise typer.BadParameter("Max redirects must be between 0 and 50")
    return value


def validate_nameservers(value: Optional[str]) -> Optional[str]:
    """Validate nameserver IP addresses."""
    if value is None:
        return None

    import ipaddress

    nameservers = value.split(",")
    for ns in nameservers:
        ns = ns.strip()
        try:
            ipaddress.ip_address(ns)
        except ValueError:
            raise typer.BadParameter(f"Invalid nameserver IP address: {ns}")

    return value


def validate_config_file(value: Optional[str]) -> Optional[str]:
    """Validate config file exists."""
    if value is None:
        return None

    config_path = Path(value)
    if not config_path.exists():
        raise typer.BadParameter(f"Config file does not exist: {value}")

    if not config_path.is_file():
        raise typer.BadParameter(f"Config path is not a file: {value}")

    return value


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
                normalized_url = last_response.url.rstrip('/').lower()

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
    logger.error(error_msg)

    # Also add as warning for backward compatibility
    warnings.append(error_msg)

    # Choose preferred URL (priority: https with www > https without www > http)
    def url_priority(url: str) -> tuple[int, int, str]:
        """Return priority tuple (https=0/http=1, has_www=0/no_www=1, url)."""
        is_https = 0 if url.startswith('https://') else 1
        has_www = 0 if '://www.' in url else 1
        return (is_https, has_www, url)

    # Sort by priority and take the best one
    preferred_normalized = min(final_urls.keys(),
                              key=lambda k: url_priority(final_urls[k][0]))
    preferred_url, preferred_response = final_urls[preferred_normalized]

    logger.info(f"Using preferred final URL for analysis: {preferred_url}")
    return preferred_url, preferred_response, warnings, errors


@app.command()
def analyze(
    domain: str = typer.Argument(
        ...,
        help="Domain to analyze (e.g., example.com)",
        callback=validate_domain,
    ),
    # Verbosity options
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Quiet mode (only errors)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Verbose output",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        "-d",
        help="Debug output (very detailed)",
    ),
    # Analysis options
    skip_dns: bool = typer.Option(
        False,
        "--skip-dns",
        help="Skip DNS analysis",
    ),
    skip_http: bool = typer.Option(
        False,
        "--skip-http",
        help="Skip HTTP/HTTPS analysis",
    ),
    skip_ssl: bool = typer.Option(
        False,
        "--skip-ssl",
        help="Skip SSL/TLS analysis",
    ),
    skip_email: bool = typer.Option(
        False,
        "--skip-email",
        help="Skip email security analysis (SPF, DKIM, DMARC)",
    ),
    skip_headers: bool = typer.Option(
        False,
        "--skip-headers",
        help="Skip security headers analysis",
    ),
    skip_site_verification: bool = typer.Option(
        False,
        "--skip-site-verification",
        help="Skip site verification analysis (Google, Facebook, Pinterest, etc.)",
    ),
    skip_whois: bool = typer.Option(
        False,
        "--skip-whois",
        help="Skip WHOIS registration analysis",
    ),
    # Email security options
    dkim_selectors: Optional[str] = typer.Option(
        None,
        "--dkim-selectors",
        help="Comma-separated list of DKIM selectors to check (e.g., 'default,google,k1')",
    ),
    # Site verification options
    verify: Optional[list[str]] = typer.Option(
        None,
        "--verify",
        help="Add verification IDs (format: 'Service:ID' or 'Service1:ID1,Service2:ID2'). Can be used multiple times.",
    ),
    # HTTP options
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        "-t",
        help="HTTP request timeout in seconds (0-300)",
        callback=validate_timeout,
    ),
    max_redirects: int = typer.Option(
        10,
        "--max-redirects",
        help="Maximum number of redirects to follow (0-50)",
        callback=validate_max_redirects,
    ),
    # DNS options
    nameservers: Optional[str] = typer.Option(
        None,
        "--nameservers",
        help="Comma-separated list of nameservers to use (e.g., '8.8.8.8,1.1.1.1')",
        callback=validate_nameservers,
    ),
    warn_www_not_cname: Optional[bool] = typer.Option(
        None,
        "--warn-www-not-cname/--no-warn-www-not-cname",
        help="Warn if www subdomain is not a CNAME record (best practice)",
    ),
    # Output options
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output",
    ),
    # Config options
    config_file: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file (overrides default config locations)",
        callback=validate_config_file,
    ),
    # RBL options
    check_rbl: Optional[bool] = typer.Option(
        None,
        "--check-rbl/--no-check-rbl",
        help="Check IP addresses against blacklists (RBL)",
    ),
) -> None:
    """
    Analyze a domain and display comprehensive information for webmasters.

    This tool checks DNS records, HTTP/HTTPS redirects, SSL certificates,
    email security (SPF, DKIM, DMARC), and security headers.
    """
    # Load configuration
    config = load_config()

    # Merge CLI arguments with config (CLI takes precedence)
    # Determine verbosity level
    if debug:
        verbosity: VerbosityLevel = "debug"
    elif verbose:
        verbosity = "verbose"
    elif quiet:
        verbosity = "quiet"
    else:
        verbosity = config.output.verbosity  # type: ignore

    # Setup logger
    logger = setup_logger(level=verbosity)

    # Create console with color preference
    use_color = config.output.color if no_color is False else not no_color
    output_console = Console(force_terminal=use_color, no_color=not use_color)
    formatter = OutputFormatter(console=output_console, verbosity=verbosity)

    # Domain is already normalized by validate_domain callback
    logger.info(f"Starting analysis for {domain}")

    # Print header
    formatter.print_header(domain)

    # Merge skip options with config
    skip_dns = skip_dns or config.analysis.skip_dns
    skip_http = skip_http or config.analysis.skip_http
    skip_ssl = skip_ssl or config.analysis.skip_ssl
    skip_email = skip_email or config.analysis.skip_email
    skip_headers = skip_headers or config.analysis.skip_headers
    skip_site_verification = skip_site_verification or config.analysis.skip_site_verification
    skip_whois = skip_whois or config.analysis.skip_whois

    # Determine RBL check
    do_rbl_check = check_rbl if check_rbl is not None else config.email.check_rbl

    try:
        # WHOIS Analysis
        whois_result = None
        if not skip_whois:
            logger.info("Running WHOIS analysis...")
            whois_analyzer = WhoisAnalyzer(
                expiry_warning_days=config.whois.expiry_warning_days,
                expiry_critical_days=config.whois.expiry_critical_days,
            )
            whois_result = whois_analyzer.analyze(domain)
            formatter.print_whois_results(whois_result)

        # DNS Analysis
        dns_result = None
        if not skip_dns:
            logger.info("Running DNS analysis...")
            dns_analyzer = DNSAnalyzer(
                nameservers=nameservers.split(",") if nameservers else config.dns.nameservers,
                check_dnssec=config.dns.check_dnssec,
                warn_www_not_cname=warn_www_not_cname if warn_www_not_cname is not None else config.dns.warn_www_not_cname,
            )
            dns_result = dns_analyzer.analyze(domain)
            formatter.print_dns_results(dns_result)
        else:
            dns_result = None

        # HTTP/HTTPS Analysis
        http_result = None
        if not skip_http:
            logger.info("Running HTTP/HTTPS analysis...")
            http_analyzer = HTTPAnalyzer(
                timeout=timeout if timeout else config.http.timeout,
                max_redirects=max_redirects if max_redirects else config.http.max_redirects,
            )
            http_result = http_analyzer.analyze(domain)
            formatter.print_http_results(http_result)

        # SSL/TLS Analysis
        ssl_result = None
        if not skip_ssl:
            logger.info("Running SSL/TLS analysis...")
            ssl_analyzer = SSLAnalyzer(
                timeout=timeout if timeout else config.http.timeout,
                cert_expiry_warning_days=config.ssl.cert_expiry_warning_days,
                cert_expiry_critical_days=config.ssl.cert_expiry_critical_days,
            )
            ssl_result = ssl_analyzer.analyze(domain)
            formatter.print_ssl_results(ssl_result)

        # Email Security Analysis
        email_result = None
        if not skip_email:
            logger.info("Running email security analysis...")
            selectors = (
                dkim_selectors.split(",") if dkim_selectors else config.email.dkim_selectors
            )
            email_analyzer = EmailSecurityAnalyzer(dkim_selectors=selectors)
            email_result = email_analyzer.analyze(domain)
            formatter.print_email_security_results(email_result)

        # Security Headers Analysis
        security_headers_results = []
        if not skip_headers and http_result:
            logger.info("Running security headers analysis...")

            # Get the preferred final URL from all redirect chains
            final_url, final_response, url_warnings, url_errors = get_preferred_final_url(http_result)

            # Add any errors/warnings about inconsistent redirect chains
            http_result.errors.extend(url_errors)
            http_result.warnings.extend(url_warnings)

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
                security_headers_results.append(headers_result)
                formatter.print_security_headers_results(headers_result)

        # Site Verification Analysis (Google, Facebook, Pinterest, etc.)
        site_verification_result = None
        if not skip_site_verification:
            # Build list of service configurations from config
            services = []
            for service_cfg in config.site_verification.services:
                services.append(ServiceConfig(
                    name=service_cfg.name,
                    ids=list(service_cfg.ids),  # Copy to avoid modifying config
                    dns_pattern=service_cfg.dns_pattern,
                    file_pattern=service_cfg.file_pattern,
                    meta_name=service_cfg.meta_name,
                    auto_detect=service_cfg.auto_detect,
                ))

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
                                logger.debug(f"Added verification ID for {service_name}: {verification_id}")
                        else:
                            # Service not in config, log warning
                            logger.warning(
                                f"Service '{service_name}' not found in predefined services. "
                                f"Available services: {', '.join(s.name for s in services)}. "
                                f"Add custom service to config.site_verification.services if needed."
                            )

            # Only run if there are services configured
            if services:
                logger.info("Running site verification analysis...")
                site_verification_analyzer = SiteVerificationAnalyzer(
                    services=services,
                    timeout=timeout if timeout else config.http.timeout,
                    nameservers=nameservers.split(",") if nameservers else config.dns.nameservers,
                )

                # Use preferred final URL from HTTP analysis if available
                verification_url = None
                if http_result:
                    final_url, final_response, _, _ = get_preferred_final_url(http_result)
                    verification_url = final_url

                site_verification_result = site_verification_analyzer.analyze(
                    domain, url=verification_url
                )
                formatter.print_site_verification_results(site_verification_result)

        # RBL (Blacklist) Check
        rbl_result = None
        if do_rbl_check and dns_result:
            logger.info("Running RBL blacklist check...")
            ips = extract_ips_from_dns_result(dns_result)
            if ips:
                rbl_checker = RBLChecker(
                    rbl_servers=config.email.rbl_servers,
                    timeout=config.dns.timeout,
                )
                rbl_result = rbl_checker.check_ips(ips)
                formatter.print_rbl_results(rbl_result)
            else:
                logger.debug("No IP addresses found for RBL check")

        # Print summary
        formatter.print_summary(
            whois_result=whois_result,
            dns_result=dns_result,
            http_result=http_result,
            ssl_result=ssl_result,
            email_result=email_result,
            security_headers=security_headers_results,
            rbl_result=rbl_result,
            site_verification_result=site_verification_result,
        )

        logger.info("Analysis complete")

    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during analysis: {e}", exc_info=debug)
        console.print(f"\n[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def create_config() -> None:
    """Create default user configuration file."""
    try:
        config_path = create_default_user_config()
        console.print(f"[green]✓[/green] Created config file: [cyan]{config_path}[/cyan]")
        console.print(
            f"\nEdit this file to customize default settings.\n"
            f"You can also create a local config: [dim].webmaster-domain-tool.toml[/dim]"
        )
    except Exception as e:
        console.print(f"[red]Error creating config: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    from . import __version__

    console.print(f"webmaster-domain-tool version {__version__}")


def main() -> None:
    """Main entry point with automatic 'analyze' command insertion."""
    import sys

    # If first argument doesn't look like a known command or option,
    # assume it's a domain and insert 'analyze' command
    if len(sys.argv) > 1:
        first_arg = sys.argv[1]
        known_commands = ["analyze", "create-config", "version"]

        # If it's not a known command and not an option (doesn't start with -)
        # then it's probably a domain, so insert 'analyze' before it
        if first_arg not in known_commands and not first_arg.startswith("-"):
            sys.argv.insert(1, "analyze")

    app()


if __name__ == "__main__":
    main()
