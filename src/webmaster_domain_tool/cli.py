"""Command-line interface for webmaster-domain-tool."""

import logging
import re
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .analyzers.dns_analyzer import DNSAnalyzer
from .analyzers.http_analyzer import HTTPAnalyzer
from .analyzers.ssl_analyzer import SSLAnalyzer
from .analyzers.email_security import EmailSecurityAnalyzer
from .analyzers.security_headers import SecurityHeadersAnalyzer
from .analyzers.rbl_checker import RBLChecker, extract_ips_from_dns_result
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
    # Email security options
    dkim_selectors: Optional[str] = typer.Option(
        None,
        "--dkim-selectors",
        help="Comma-separated list of DKIM selectors to check (e.g., 'default,google,k1')",
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

    # Determine RBL check
    do_rbl_check = check_rbl if check_rbl is not None else config.email.check_rbl

    try:
        # DNS Analysis
        dns_result = None
        if not skip_dns:
            logger.info("Running DNS analysis...")
            dns_analyzer = DNSAnalyzer(
                nameservers=nameservers.split(",") if nameservers else config.dns.nameservers,
                check_dnssec=config.dns.check_dnssec,
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
                timeout=timeout if timeout else config.http.timeout
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

            # Analyze headers from final URLs in redirect chains
            for chain in http_result.chains:
                if chain.responses:
                    last_response = chain.responses[-1]
                    if last_response.status_code == 200:
                        headers_analyzer = SecurityHeadersAnalyzer()
                        headers_result = headers_analyzer.analyze(
                            last_response.url,
                            last_response.headers,
                        )
                        security_headers_results.append(headers_result)

            # Print only unique final URLs (avoid duplicates)
            seen_urls = set()
            for headers_result in security_headers_results:
                if headers_result.url not in seen_urls:
                    formatter.print_security_headers_results(headers_result)
                    seen_urls.add(headers_result.url)

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
            dns_result=dns_result,
            http_result=http_result,
            ssl_result=ssl_result,
            email_result=email_result,
            security_headers=security_headers_results,
            rbl_result=rbl_result,
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


if __name__ == "__main__":
    app()
