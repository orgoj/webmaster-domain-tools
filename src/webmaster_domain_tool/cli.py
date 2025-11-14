"""Command-line interface for webmaster-domain-tool."""

import logging
from typing import Optional

import typer
from rich.console import Console

from .analyzers.dns_analyzer import DNSAnalyzer
from .analyzers.http_analyzer import HTTPAnalyzer
from .analyzers.ssl_analyzer import SSLAnalyzer
from .analyzers.email_security import EmailSecurityAnalyzer
from .analyzers.security_headers import SecurityHeadersAnalyzer
from .utils.logger import setup_logger, VerbosityLevel
from .utils.output import OutputFormatter

app = typer.Typer(
    name="webmaster-domain-tool",
    help="Comprehensive domain analysis tool for webmasters",
    add_completion=False,
)

console = Console()


@app.command()
def analyze(
    domain: str = typer.Argument(
        ...,
        help="Domain to analyze (e.g., example.com)",
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
        help="HTTP request timeout in seconds",
    ),
    max_redirects: int = typer.Option(
        10,
        "--max-redirects",
        help="Maximum number of redirects to follow",
    ),
    # DNS options
    nameservers: Optional[str] = typer.Option(
        None,
        "--nameservers",
        help="Comma-separated list of nameservers to use (e.g., '8.8.8.8,1.1.1.1')",
    ),
    # Output options
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output",
    ),
) -> None:
    """
    Analyze a domain and display comprehensive information for webmasters.

    This tool checks DNS records, HTTP/HTTPS redirects, SSL certificates,
    email security (SPF, DKIM, DMARC), and security headers.
    """
    # Determine verbosity level
    if debug:
        verbosity: VerbosityLevel = "debug"
    elif verbose:
        verbosity = "verbose"
    elif quiet:
        verbosity = "quiet"
    else:
        verbosity = "normal"

    # Setup logger
    logger = setup_logger(level=verbosity)

    # Create console with color preference
    output_console = Console(force_terminal=not no_color, no_color=no_color)
    formatter = OutputFormatter(console=output_console)

    # Normalize domain
    domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

    logger.info(f"Starting analysis for {domain}")

    # Print header
    formatter.print_header(domain)

    try:
        # DNS Analysis
        if not skip_dns:
            logger.info("Running DNS analysis...")
            dns_analyzer = DNSAnalyzer(
                nameservers=nameservers.split(",") if nameservers else None
            )
            dns_result = dns_analyzer.analyze(domain)
            formatter.print_dns_results(dns_result)
        else:
            dns_result = None

        # HTTP/HTTPS Analysis
        if not skip_http:
            logger.info("Running HTTP/HTTPS analysis...")
            http_analyzer = HTTPAnalyzer(
                timeout=timeout,
                max_redirects=max_redirects,
            )
            http_result = http_analyzer.analyze(domain)
            formatter.print_http_results(http_result)
        else:
            http_result = None

        # SSL/TLS Analysis
        if not skip_ssl:
            logger.info("Running SSL/TLS analysis...")
            ssl_analyzer = SSLAnalyzer(timeout=timeout)
            ssl_result = ssl_analyzer.analyze(domain)
            formatter.print_ssl_results(ssl_result)
        else:
            ssl_result = None

        # Email Security Analysis
        if not skip_email:
            logger.info("Running email security analysis...")
            selectors = dkim_selectors.split(",") if dkim_selectors else None
            email_analyzer = EmailSecurityAnalyzer(dkim_selectors=selectors)
            email_result = email_analyzer.analyze(domain)
            formatter.print_email_security_results(email_result)
        else:
            email_result = None

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

        # Print summary
        formatter.print_summary(
            dns_result=dns_result,
            http_result=http_result,
            ssl_result=ssl_result,
            email_result=email_result,
            security_headers=security_headers_results,
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
def version() -> None:
    """Show version information."""
    from . import __version__

    console.print(f"webmaster-domain-tool version {__version__}")


if __name__ == "__main__":
    app()
