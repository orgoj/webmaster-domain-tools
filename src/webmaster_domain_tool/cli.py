"""Command-line interface for webmaster-domain-tool."""

import logging
import re
from pathlib import Path

import rich.panel
import typer
from rich import box
from rich.console import Console

logger = logging.getLogger(__name__)

# Remove borders from CLI help output by monkey-patching Panel
_original_panel_init = rich.panel.Panel.__init__


def _no_border_panel_init(self, *args, **kwargs):
    # Remove borders from panels - use HORIZONTALS for minimal formatting
    kwargs["box"] = box.HORIZONTALS
    return _original_panel_init(self, *args, **kwargs)


rich.panel.Panel.__init__ = _no_border_panel_init

# flake8: noqa: E402
# ruff: noqa: E402
from .config import create_default_user_config, load_config
from .core import ANALYZER_REGISTRY, run_domain_analysis
from .utils.logger import VerbosityLevel, setup_logger
from .utils.output import OutputFormatter

app = typer.Typer(
    name="webmaster-domain-tool",
    help="Comprehensive domain analysis tool for webmasters",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def build_skip_params_from_cli_args(**cli_args):
    """
    Build skip parameters dict from CLI arguments using ANALYZER_REGISTRY.

    This maps CLI argument names to their values based on registry metadata,
    handling both normal skip_* params and inverted do_* params.

    Args:
        **cli_args: CLI arguments (skip_dns=True, do_rbl_check=False, etc.)

    Returns:
        dict of skip parameter names to values for passing to run_domain_analysis()
    """
    skip_params = {}

    for analyzer_key, metadata in ANALYZER_REGISTRY.items():
        if not metadata.skip_param_name:
            continue

        param_name = metadata.skip_param_name

        # Get value from CLI args if present
        if param_name in cli_args:
            skip_params[param_name] = cli_args[param_name]

    return skip_params


# Validation functions
def validate_domain(domain: str) -> str:
    """Validate domain name format."""
    # Remove protocol and trailing slash if present
    domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

    # Basic domain validation regex
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    if not domain_pattern.match(domain):
        raise typer.BadParameter(f"Invalid domain format: {domain}. Expected format: example.com")

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


def validate_nameservers(value: str | None) -> str | None:
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


def validate_config_file(value: str | None) -> str | None:
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
    # Analysis options - synchronized with ANALYZER_REGISTRY
    # NOTE: These parameters must match skip_param_name in ANALYZER_REGISTRY metadata
    # Processing is registry-driven via build_skip_params_from_cli_args()
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
    skip_www: bool = typer.Option(
        False,
        "--skip-www",
        help="Skip testing www subdomain (useful for subdomains or domains without www)",
    ),
    # Email security options
    dkim_selectors: str | None = typer.Option(
        None,
        "--dkim-selectors",
        help="Comma-separated list of DKIM selectors to check (e.g., 'default,google,k1')",
    ),
    # Site verification options
    verify: list[str] | None = typer.Option(
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
    check_path: str | None = typer.Option(
        None,
        "--check-path",
        help="Check if specific path exists on final URL (e.g., '/.wdt.hosting.info.txt')",
    ),
    # DNS options
    nameservers: str | None = typer.Option(
        None,
        "--nameservers",
        help="Comma-separated list of nameservers to use (e.g., '8.8.8.8,1.1.1.1')",
        callback=validate_nameservers,
    ),
    warn_www_not_cname: bool | None = typer.Option(
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
    config_file: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file (overrides default config locations)",
        callback=validate_config_file,
    ),
    # RBL options
    check_rbl: bool | None = typer.Option(
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

    # Build skip parameters from CLI args using registry (DRY!)
    # No more hardcoded merge - uses ANALYZER_REGISTRY as single source of truth
    cli_skip_args = {
        "skip_dns": skip_dns,
        "skip_http": skip_http,
        "skip_ssl": skip_ssl,
        "skip_email": skip_email,
        "skip_headers": skip_headers,
        "skip_site_verification": skip_site_verification,
        "skip_whois": skip_whois,
        "do_rbl_check": check_rbl if check_rbl is not None else config.email.check_rbl,
    }

    skip_params = build_skip_params_from_cli_args(**cli_skip_args)

    try:
        # Run all analysis using core module with dynamic skip params
        results = run_domain_analysis(
            domain=domain,
            config=config,
            nameservers=nameservers,
            timeout=timeout,
            max_redirects=max_redirects,
            warn_www_not_cname=warn_www_not_cname,
            skip_www=skip_www,
            dkim_selectors=dkim_selectors,
            check_path=check_path,
            verify=verify,
            **skip_params,  # Dynamic parameters from registry!
        )

        # Print results using formatter
        if results.whois:
            formatter.print_whois_results(results.whois)

        if results.dns:
            formatter.print_dns_results(results.dns)

        if results.http:
            formatter.print_http_results(results.http)

        if results.cdn:
            formatter.print_cdn_results(results.cdn)

        if results.ssl:
            formatter.print_ssl_results(results.ssl)

        if results.email:
            formatter.print_email_security_results(results.email)

        if results.headers:
            for headers_result in results.headers:
                formatter.print_security_headers_results(headers_result)

        if results.site_verification:
            formatter.print_site_verification_results(results.site_verification)

        if results.rbl:
            formatter.print_rbl_results(results.rbl)

        if results.seo:
            formatter.print_seo_results(results.seo)

        if results.favicon:
            formatter.print_favicon_results(results.favicon)

        # Print summary
        formatter.print_summary(
            whois_result=results.whois,
            dns_result=results.dns,
            http_result=results.http,
            ssl_result=results.ssl,
            email_result=results.email,
            security_headers=results.headers if results.headers else [],
            rbl_result=results.rbl,
            site_verification_result=results.site_verification,
            seo_result=results.seo,
            favicon_result=results.favicon,
            cdn_result=results.cdn,
        )

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
            "\nEdit this file to customize default settings.\n"
            "You can also create a local config: [dim].webmaster-domain-tool.toml[/dim]"
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
