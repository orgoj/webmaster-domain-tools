"""Output formatting using rich library."""

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

from ..analyzers.dns_analyzer import DNSAnalysisResult
from ..analyzers.http_analyzer import HTTPAnalysisResult, HTTPResponse
from ..analyzers.ssl_analyzer import (
    SSLAnalysisResult,
    CertificateInfo,
    DEFAULT_SSL_EXPIRY_CRITICAL_DAYS,
    DEFAULT_SSL_EXPIRY_WARNING_DAYS,
)
from ..analyzers.email_security import EmailSecurityResult
from ..analyzers.security_headers import SecurityHeadersResult
from ..analyzers.rbl_checker import RBLAnalysisResult
from ..analyzers.site_verification_analyzer import SiteVerificationAnalysisResult
from ..analyzers.whois_analyzer import WhoisAnalysisResult
from ..analyzers.seo_files_analyzer import SEOFilesAnalysisResult
from ..analyzers.favicon_analyzer import FaviconAnalysisResult
from ..analyzers.advanced_email_security import AdvancedEmailSecurityResult
from ..analyzers.cdn_detector import CDNDetectionResult

# Output formatting constants
MAX_SAN_DISPLAY = 5
SECURITY_SCORE_GOOD = 75
SECURITY_SCORE_WARNING = 50


class OutputFormatter:
    """Formats analysis results for console output."""

    def __init__(self, console: Console | None = None, verbosity: str = "normal"):
        """
        Initialize output formatter.

        Args:
            console: Rich console instance (creates new one if not provided)
            verbosity: Output verbosity level (quiet, normal, verbose, debug)
        """
        self.console = console or Console()
        self.verbosity = verbosity
        # Central error/warning collection
        self.all_errors: list[tuple[str, str]] = []  # (category, message)
        self.all_warnings: list[tuple[str, str]] = []  # (category, message)

    @staticmethod
    def _get_issuer_name(cert: CertificateInfo) -> str:
        """
        Extract a human-readable issuer name from certificate.

        Args:
            cert: Certificate information

        Returns:
            Issuer name (organization or common name)
        """
        if not cert.issuer:
            return "Unknown"

        # Try organization first (most common for CAs)
        if "O" in cert.issuer:
            return cert.issuer["O"]

        # Fallback to common name
        if "CN" in cert.issuer:
            return cert.issuer["CN"]

        # Last resort: concatenate all available fields
        return ", ".join(f"{k}={v}" for k, v in cert.issuer.items())

    def print_header(self, domain: str) -> None:
        """Print analysis header."""
        # Reset error/warning collections for new analysis
        self.all_errors = []
        self.all_warnings = []

        if self.verbosity == "quiet":
            self.console.print(f"[bold]{domain}[/bold]")
        else:
            self.console.print()
            self.console.print(f"[bold cyan]Webmaster Domain Analysis[/bold cyan]")
            self.console.print(f"Domain: [yellow]{domain}[/yellow]")
            self.console.print()

    def print_whois_results(self, result: WhoisAnalysisResult) -> None:
        """Print WHOIS analysis results."""
        if self.verbosity == "quiet":
            self._print_whois_quiet(result)
            return
        elif self.verbosity == "normal":
            self._print_whois_compact(result)
            return
        else:  # verbose or debug
            self._print_whois_verbose(result)

    def _print_whois_quiet(self, result: WhoisAnalysisResult) -> None:
        """Print WHOIS results in quiet mode."""
        if result.errors:
            status = f"[red]✗ WHOIS: {len(result.errors)} errors[/red]"
        elif result.warnings:
            status = f"[yellow]⚠ WHOIS: {len(result.warnings)} warnings[/yellow]"
        elif result.registrar and result.expiration_date:
            status = f"[green]✓ WHOIS: {result.registrar}[/green]"
        else:
            status = "[dim]WHOIS: Limited data[/dim]"
        self.console.print(status)

    def _print_whois_compact(self, result: WhoisAnalysisResult) -> None:
        """Print WHOIS results in compact mode."""
        self.console.print("[bold blue]WHOIS[/bold blue]")

        # Handle errors
        if result.errors:
            for error in result.errors:
                self.all_errors.append(("WHOIS", error))
                self.console.print(f"  [red]✗ {error}[/red]")
            return

        # Registrar
        if result.registrar:
            self.console.print(f"  Registrar: {result.registrar}")
        else:
            warning_msg = "Registrar information not available"
            self.all_warnings.append(("WHOIS", warning_msg))
            self.console.print(f"  [yellow]⚠ {warning_msg}[/yellow]")

        # Expiration date with color coding
        if result.expiration_date:
            exp_str = result.expiration_date.strftime("%Y-%m-%d")
            if result.days_until_expiry is not None:
                if result.days_until_expiry < 0:
                    # Expired - shown as error
                    self.console.print(f"  [red]Expires: {exp_str} (EXPIRED)[/red]")
                elif result.days_until_expiry <= 7:
                    # Critical - shown as error
                    self.console.print(
                        f"  [red]Expires: {exp_str} ({result.days_until_expiry} days)[/red]"
                    )
                elif result.days_until_expiry <= 30:
                    # Warning
                    self.console.print(
                        f"  [yellow]Expires: {exp_str} ({result.days_until_expiry} days)[/yellow]"
                    )
                else:
                    # OK
                    self.console.print(
                        f"  [green]Expires: {exp_str} ({result.days_until_expiry} days)[/green]"
                    )
            else:
                self.console.print(f"  Expires: {exp_str}")
        else:
            warning_msg = "Expiration date not available"
            self.all_warnings.append(("WHOIS", warning_msg))
            self.console.print(f"  [yellow]⚠ {warning_msg}[/yellow]")

        # Owner/Registrant (if available)
        if result.registrant_name or result.registrant_organization:
            owner_parts = []
            if result.registrant_organization:
                owner_parts.append(result.registrant_organization)
            if result.registrant_name:
                owner_parts.append(result.registrant_name)
            self.console.print(f"  Owner: {' / '.join(owner_parts)}")

        # Admin contact (if available)
        if result.admin_name or result.admin_email:
            admin_parts = []
            if result.admin_name:
                admin_parts.append(result.admin_name)
            if result.admin_email:
                admin_parts.append(result.admin_email)
            self.console.print(f"  Admin: {' / '.join(admin_parts)}")

        # Warnings
        for warning in result.warnings:
            self.all_warnings.append(("WHOIS", warning))
            self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

    def _print_whois_verbose(self, result: WhoisAnalysisResult) -> None:
        """Print WHOIS results in verbose mode."""
        self.console.print("[bold blue]WHOIS Registration Information[/bold blue]")

        # Handle errors
        if result.errors:
            for error in result.errors:
                self.all_errors.append(("WHOIS", error))
                self.console.print(f"  [red]✗ {error}[/red]")
            return

        # Create table for WHOIS info
        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value")

        # Domain
        table.add_row("Domain", result.domain)

        # Registrar
        if result.registrar:
            table.add_row("Registrar", result.registrar)
        else:
            table.add_row("Registrar", "[yellow]Not available[/yellow]")

        # Dates
        if result.creation_date:
            table.add_row("Created", result.creation_date.strftime("%Y-%m-%d %H:%M:%S"))

        if result.updated_date:
            table.add_row("Updated", result.updated_date.strftime("%Y-%m-%d %H:%M:%S"))

        if result.expiration_date:
            exp_str = result.expiration_date.strftime("%Y-%m-%d %H:%M:%S")
            if result.days_until_expiry is not None:
                if result.days_until_expiry < 0:
                    exp_display = f"[red]{exp_str} (EXPIRED {abs(result.days_until_expiry)} days ago)[/red]"
                elif result.days_until_expiry <= 7:
                    exp_display = f"[red]{exp_str} ({result.days_until_expiry} days)[/red]"
                elif result.days_until_expiry <= 30:
                    exp_display = f"[yellow]{exp_str} ({result.days_until_expiry} days)[/yellow]"
                else:
                    exp_display = f"[green]{exp_str} ({result.days_until_expiry} days)[/green]"
            else:
                exp_display = exp_str
            table.add_row("Expires", exp_display)

        # Registrant
        if result.registrant_organization:
            table.add_row("Organization", result.registrant_organization)

        if result.registrant_name:
            table.add_row("Registrant", result.registrant_name)

        # Admin contact
        if result.admin_name:
            table.add_row("Admin Name", result.admin_name)

        if result.admin_email:
            table.add_row("Admin Email", result.admin_email)

        # Nameservers
        if result.nameservers:
            ns_list = "\n".join(result.nameservers[:5])  # Show first 5
            if len(result.nameservers) > 5:
                ns_list += f"\n... and {len(result.nameservers) - 5} more"
            table.add_row("Nameservers", ns_list)

        # Status
        if result.status:
            status_list = "\n".join(result.status[:3])  # Show first 3
            if len(result.status) > 3:
                status_list += f"\n... and {len(result.status) - 3} more"
            table.add_row("Status", status_list)

        self.console.print(table)

        # Warnings
        if result.warnings:
            self.console.print()
            for warning in result.warnings:
                self.all_warnings.append(("WHOIS", warning))
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

    def print_dns_results(self, result: DNSAnalysisResult) -> None:
        """Print DNS analysis results."""
        if self.verbosity == "quiet":
            self._print_dns_quiet(result)
            return
        elif self.verbosity == "normal":
            self._print_dns_compact(result)
            return
        else:  # verbose or debug
            self._print_dns_verbose(result)

    def _print_dns_quiet(self, result: DNSAnalysisResult) -> None:
        """Print DNS results in quiet mode (single line)."""
        if result.errors:
            status = f"[red]✗ DNS: {len(result.errors)} errors[/red]"
        elif result.warnings:
            status = f"[yellow]⚠ DNS: OK, {len(result.warnings)} warnings[/yellow]"
        else:
            record_types = set(k.split(":")[1] for k in result.records.keys())
            status = f"[green]✓ DNS: {', '.join(sorted(record_types))}[/green]"
        self.console.print(status)

    def _print_dns_compact(self, result: DNSAnalysisResult) -> None:
        """Print DNS results in compact mode."""
        self.console.print("[bold blue]DNS[/bold blue]")

        if result.errors:
            for error in result.errors:
                self.all_errors.append(("DNS", error))
                self.console.print(f"  [red]✗ {error}[/red]")
            return

        # Group records by domain, then by type
        records_by_domain = {}
        for key, records in result.records.items():
            domain, record_type = key.rsplit(":", 1)
            if domain not in records_by_domain:
                records_by_domain[domain] = {}
            if record_type not in records_by_domain[domain]:
                records_by_domain[domain][record_type] = []
            for record in records:
                records_by_domain[domain][record_type].append(record.value)

        # Important record types to always show
        # NS and SOA are domain-wide, so only show for main domain
        important_types = ["A", "AAAA", "MX", "TXT", "CNAME"]
        domain_wide_types = ["NS", "SOA", "CAA"]

        # Sort domains: main domain first (without www), then www subdomain, then others
        sorted_domains = sorted(
            records_by_domain.keys(),
            key=lambda d: (
                0 if d == result.domain else (1 if d == f"www.{result.domain}" else 2),
                d
            )
        )

        # Print records for each domain
        for domain_idx, domain in enumerate(sorted_domains):
            records_by_type = records_by_domain[domain]

            # Print domain header only if it's different from main domain
            # or if there are multiple domains
            if len(sorted_domains) > 1:
                if domain == result.domain:
                    self.console.print(f"  [dim]{domain}:[/dim]")
                elif domain == f"www.{result.domain}":
                    self.console.print(f"  [dim]www.{result.domain}:[/dim]")
                else:
                    self.console.print(f"  [dim]{domain}:[/dim]")
                indent = "    "
            else:
                indent = "  "

            # Print records (show important types first, then others)
            shown_types = set()
            for record_type in important_types:
                if record_type in records_by_type:
                    values = records_by_type[record_type]
                    if len(values) == 1:
                        self.console.print(f"{indent}{record_type}: {values[0]}")
                    elif record_type in ("A", "AAAA"):
                        # A, AAAA records on single line, space-separated
                        self.console.print(f"{indent}{record_type}: {' '.join(values)}")
                    else:
                        self.console.print(f"{indent}{record_type}:")
                        for value in values:
                            self.console.print(f"{indent}  - {value}")
                    shown_types.add(record_type)

                    # If CNAME, also show resolved A records
                    if record_type == "CNAME" and "CNAME_A" in records_by_type:
                        cname_a_values = records_by_type["CNAME_A"]
                        self.console.print(f"{indent}└─> A (resolved): {' '.join(cname_a_values)}")
                        shown_types.add("CNAME_A")
                elif len(sorted_domains) == 1 or domain == result.domain:
                    # Only show missing important records for main domain
                    self.console.print(f"{indent}{record_type}: [dim]none[/dim]")

            # Show domain-wide types only for main domain
            if domain == result.domain:
                for record_type in domain_wide_types:
                    if record_type in records_by_type:
                        values = records_by_type[record_type]
                        shown_types.add(record_type)
                        if len(values) == 1:
                            self.console.print(f"{indent}{record_type}: {values[0]}")
                        elif record_type == "NS":
                            # NS records on single line, space-separated
                            self.console.print(f"{indent}{record_type}: {' '.join(values)}")
                        else:
                            self.console.print(f"{indent}{record_type}:")
                            for value in values:
                                self.console.print(f"{indent}  - {value}")

            # Show any other record types (excluding domain-wide types for non-main domains)
            for record_type in sorted(records_by_type.keys()):
                if record_type not in shown_types and record_type not in domain_wide_types:
                    values = records_by_type[record_type]
                    if len(values) == 1:
                        self.console.print(f"{indent}{record_type}: {values[0]}")
                    else:
                        self.console.print(f"{indent}{record_type}:")
                        for value in values:
                            self.console.print(f"{indent}  - {value}")

        # Show PTR records
        if result.ptr_records:
            # Single line: IP → hostname
            ptr_list = [f"{ip} → {ptr}" for ip, ptr in result.ptr_records.items()]
            self.console.print(f"  PTR: {', '.join(ptr_list)}")

        # Show DNSSEC status
        if result.dnssec and result.dnssec.enabled:
            status = "✓" if result.dnssec.valid else "⚠"
            self.console.print(f"  DNSSEC: [{('green' if result.dnssec.valid else 'yellow')}]{status}[/]")

        # Show info messages (not counted as warnings)
        for info in result.info_messages:
            self.console.print(f"  [dim]ℹ {info}[/dim]")

        # Show actual warnings
        for warning in result.warnings:
            self.all_warnings.append(("DNS", warning))
            self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

    def _print_dns_verbose(self, result: DNSAnalysisResult) -> None:
        """Print DNS results in verbose mode (full detail)."""
        self.console.print("[bold blue]═══ DNS Records ═══[/bold blue]")
        self.console.print()

        if result.errors:
            for error in result.errors:
                self.all_errors.append(("DNS", error))
                self.console.print(f"[red]✗ {error}[/red]")
            self.console.print()
            return

        # Group records by domain
        domains = {}
        for key, records in result.records.items():
            domain, record_type = key.rsplit(":", 1)
            if domain not in domains:
                domains[domain] = {}
            domains[domain][record_type] = records

        # Create table for each domain
        for domain, record_types in domains.items():
            table = Table(title=f"[cyan]{domain}[/cyan]", box=box.ROUNDED)
            table.add_column("Type", style="cyan", width=10)
            table.add_column("Value", style="white")
            table.add_column("TTL", style="dim", width=8)

            for record_type, records in sorted(record_types.items()):
                for i, record in enumerate(records):
                    table.add_row(
                        record_type if i == 0 else "",
                        record.value,
                        str(record.ttl) if record.ttl else "-",
                    )

            self.console.print(table)
            self.console.print()

        # Print PTR (reverse DNS) records
        if result.ptr_records:
            self.console.print("[cyan]PTR Records (Reverse DNS):[/cyan]")
            for ip, ptr in result.ptr_records.items():
                self.console.print(f"  {ip} → {ptr}")
            self.console.print()

        # Print DNSSEC info
        if result.dnssec:
            dnssec = result.dnssec
            if dnssec.enabled:
                if dnssec.valid:
                    status = "[green]✓ DNSSEC Enabled and Valid[/green]"
                else:
                    status = "[yellow]⚠ DNSSEC Enabled but Invalid[/yellow]"
            else:
                status = "[dim]DNSSEC Not Enabled[/dim]"

            self.console.print(status)
            if dnssec.has_dnskey:
                self.console.print("  [dim]DNSKEY: ✓[/dim]")
            if dnssec.has_ds:
                self.console.print("  [dim]DS: ✓[/dim]")

            for error in dnssec.errors:
                self.all_errors.append(("DNS/DNSSEC", error))
                self.console.print(f"  [red]✗ {error}[/red]")
            for warning in dnssec.warnings:
                self.all_warnings.append(("DNS/DNSSEC", warning))
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

            self.console.print()

        # Print info messages (not counted as warnings)
        if result.info_messages:
            for info in result.info_messages:
                self.console.print(f"[dim]ℹ {info}[/dim]")
            self.console.print()

        # Print warnings
        if result.warnings:
            for warning in result.warnings:
                self.all_warnings.append(("DNS", warning))
                self.console.print(f"[yellow]⚠ {warning}[/yellow]")
            self.console.print()

    def print_http_results(self, result: HTTPAnalysisResult) -> None:
        """Print HTTP/HTTPS analysis results."""
        if self.verbosity == "quiet":
            self._print_http_quiet(result)
            return
        elif self.verbosity == "normal":
            self._print_http_compact(result)
            return
        else:
            self._print_http_verbose(result)

    def _print_http_quiet(self, result: HTTPAnalysisResult) -> None:
        """Print HTTP results in quiet mode."""
        if result.errors:
            status = f"[red]✗ HTTP: {len(result.errors)} errors[/red]"
        elif result.warnings:
            status = f"[yellow]⚠ HTTP: OK, {len(result.warnings)} warnings[/yellow]"
        else:
            ok_chains = sum(1 for c in result.chains if c.responses and c.responses[-1].status_code == 200)
            status = f"[green]✓ HTTP: {ok_chains}/{len(result.chains)} OK[/green]"
        self.console.print(status)

    def _print_http_compact(self, result: HTTPAnalysisResult) -> None:
        """Print HTTP results in compact mode."""
        self.console.print("[bold blue]HTTP/HTTPS[/bold blue]")

        for chain in result.chains:
            if chain.responses:
                last_response = chain.responses[-1]

                # Check if final URL is HTTP (insecure) - use warning color
                if last_response.status_code == 200 and chain.final_url.startswith("http://"):
                    status_color = "yellow"
                    status_symbol = "⚠"
                elif last_response.status_code == 200:
                    status_color = "green"
                    status_symbol = "✓"
                elif last_response.error:
                    status_color = "red"
                    status_symbol = "✗"
                else:
                    status_color = "yellow"
                    status_symbol = "⚠"

                # Build redirect chain string: url (code) → url (code)
                if len(chain.responses) > 1:
                    parts = []
                    for i, resp in enumerate(chain.responses):
                        if resp.error:
                            parts.append(f"{resp.url} (ERROR)")
                        else:
                            parts.append(f"{resp.url} ({resp.status_code})")
                    redirect_info = " → ".join(parts)
                    # Remove the start_url from redirect_info since we show it separately
                    redirect_info = redirect_info.replace(f"{chain.start_url} ({chain.responses[0].status_code}) → ", "")
                    self.console.print(f"  [{status_color}]{status_symbol}[/] {chain.start_url} ({chain.responses[0].status_code}) → {redirect_info}")
                else:
                    # No redirect, just show URL with status
                    self.console.print(f"  [{status_color}]{status_symbol}[/] {chain.start_url} ({last_response.status_code})")

        # Show errors
        for error in result.errors:
            self.all_errors.append(("HTTP", error))
            self.console.print(f"  [red]✗ {error}[/red]")

        # Show warnings
        for warning in result.warnings:
            self.all_warnings.append(("HTTP", warning))
            self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

        # Show which URL is used for further analysis
        if result.preferred_final_url:
            self.console.print(f"  [dim]→ Using {result.preferred_final_url} for security headers and site verification analysis[/dim]")

        # Show path check result if available
        if result.path_check_result:
            path_check = result.path_check_result
            if path_check.success:
                self.console.print(f"  [green]✓ Path check: {path_check.path} exists ({path_check.content_length} bytes, {path_check.response_time:.2f}s)[/green]")
            else:
                error_msg = f"Path check failed: {path_check.path} - {path_check.error}"
                self.all_errors.append(("HTTP", error_msg))
                self.console.print(f"  [red]✗ {error_msg}[/red]")

    def _print_http_verbose(self, result: HTTPAnalysisResult) -> None:
        """Print HTTP results in verbose mode."""
        self.console.print("[bold blue]═══ HTTP/HTTPS Analysis ═══[/bold blue]")
        self.console.print()

        for chain in result.chains:
            # Create tree for redirect chain
            tree = Tree(f"[cyan]{chain.start_url}[/cyan]")

            for i, response in enumerate(chain.responses):
                # Format status code with color
                if response.error:
                    status_str = f"[red]ERROR[/red]"
                    node_label = f"{status_str} - {response.error}"
                elif response.status_code >= 400:
                    status_str = f"[red]{response.status_code}[/red]"
                    node_label = f"{status_str}"
                elif response.status_code >= 300:
                    status_str = f"[yellow]{response.status_code}[/yellow]"
                    redirect_to = response.redirect_to or "?"
                    node_label = f"{status_str} → [cyan]{redirect_to}[/cyan]"
                else:
                    status_str = f"[green]{response.status_code}[/green]"
                    node_label = f"{status_str} [dim]({response.response_time:.2f}s)[/dim]"

                tree.add(node_label)

            self.console.print(tree)
            self.console.print()

        # Print errors and warnings
        if result.errors:
            for error in result.errors:
                self.all_errors.append(("HTTP", error))
                self.console.print(f"[red]✗ {error}[/red]")
        if result.warnings:
            for warning in result.warnings:
                self.all_warnings.append(("HTTP", warning))
                self.console.print(f"[yellow]⚠ {warning}[/yellow]")

        if result.errors or result.warnings:
            self.console.print()

        # Show which URL is used for further analysis
        if result.preferred_final_url:
            self.console.print(f"[dim]→ Using {result.preferred_final_url} for security headers and site verification analysis[/dim]")
            self.console.print()

        # Show path check result if available
        if result.path_check_result:
            path_check = result.path_check_result
            if path_check.success:
                self.console.print(f"[green]✓ Path check: {path_check.path} exists ({path_check.content_length} bytes, {path_check.response_time:.2f}s)[/green]")
            else:
                error_msg = f"Path check failed: {path_check.path} - {path_check.error}"
                self.all_errors.append(("HTTP", error_msg))
                self.console.print(f"[red]✗ {error_msg}[/red]")
            self.console.print()

    def print_ssl_results(self, result: SSLAnalysisResult) -> None:
        """Print SSL/TLS analysis results."""
        if self.verbosity == "quiet":
            self._print_ssl_quiet(result)
            return
        elif self.verbosity == "normal":
            self._print_ssl_compact(result)
            return
        else:
            self._print_ssl_verbose(result)

    def _print_ssl_quiet(self, result: SSLAnalysisResult) -> None:
        """Print SSL results in quiet mode."""
        if not result.certificates:
            status = "[red]✗ SSL: No certificates[/red]"
        elif result.errors:
            status = f"[red]✗ SSL: {len(result.errors)} errors[/red]"
        elif result.warnings:
            min_days = min((c.days_until_expiry for c in result.certificates.values() if not c.errors), default=999)
            status = f"[yellow]⚠ SSL: Valid ({min_days}d), {len(result.warnings)} warnings[/yellow]"
        else:
            min_days = min((c.days_until_expiry for c in result.certificates.values()), default=999)
            status = f"[green]✓ SSL: Valid ({min_days} days)[/green]"
        self.console.print(status)

    def _print_ssl_compact(self, result: SSLAnalysisResult) -> None:
        """Print SSL results in compact mode."""
        self.console.print("[bold blue]SSL/TLS[/bold blue]")

        if not result.certificates:
            self.console.print("  [red]✗ No certificates found[/red]")
            return

        for domain, cert in result.certificates.items():
            # Determine status and color
            if cert.status == "none":
                color = "yellow"
                symbol = "⚠"
                status_text = "none"
                days_text = ""  # No days for none status
            elif cert.status == "mismatch":
                color = "yellow"
                symbol = "⚠"
                status_text = "mismatch"
                days_text = f" ({cert.days_until_expiry}d)" if cert.days_until_expiry > 0 else ""
            else:  # ok
                # Check expiry for ok certificates
                if cert.days_until_expiry < DEFAULT_SSL_EXPIRY_CRITICAL_DAYS:
                    color = "red"
                    symbol = "✗"
                elif cert.days_until_expiry < DEFAULT_SSL_EXPIRY_WARNING_DAYS:
                    color = "yellow"
                    symbol = "⚠"
                else:
                    color = "green"
                    symbol = "✓"
                status_text = "ok"
                days_text = f" ({cert.days_until_expiry}d)"

            # Get issuer name (show if certificate has issuer info)
            issuer_text = ""
            if cert.issuer:
                issuer_name = self._get_issuer_name(cert)
                issuer_text = f" [{issuer_name}]"

            self.console.print(
                f"  [{color}]{symbol}[/] {domain}: {status_text}{days_text}{issuer_text}"
            )

        if result.protocols:
            self.console.print(f"  TLS: {', '.join(result.protocols)}")

        # Show TLSv1.3 warning if applicable
        if result.protocols and "TLSv1.3" not in result.protocols:
            self.all_warnings.append(("SSL", "TLSv1.3 is not supported (recommended)"))
            self.console.print(f"  [yellow]⚠ TLSv1.3 is not supported (recommended)[/yellow]")

    def _print_ssl_verbose(self, result: SSLAnalysisResult) -> None:
        """Print SSL results in verbose mode."""
        self.console.print("[bold blue]═══ SSL/TLS Certificates ═══[/bold blue]")
        self.console.print()

        if not result.certificates:
            self.all_errors.append(("SSL", "No SSL certificates found"))
            self.console.print("[red]✗ No SSL certificates found[/red]")
            self.console.print()
            return

        for domain, cert in result.certificates.items():
            if cert.errors:
                # Certificate has errors
                self.console.print(f"[red]✗ {domain}[/red]")
                for error in cert.errors:
                    self.all_errors.append(("SSL", error))
                    self.console.print(f"  [red]{error}[/red]")
                self.console.print()
                continue

            # Create certificate info table
            table = Table(title=f"[cyan]{domain}[/cyan]", box=box.ROUNDED, show_header=False)
            table.add_column("Property", style="cyan", width=20)
            table.add_column("Value", style="white")

            # Subject
            subject_cn = cert.subject.get("commonName", "N/A")
            table.add_row("Subject (CN)", subject_cn)

            # Issuer
            issuer_cn = cert.issuer.get("commonName", "N/A")
            issuer_org = cert.issuer.get("organizationName", "")
            issuer_str = f"{issuer_cn}"
            if issuer_org:
                issuer_str += f" ({issuer_org})"
            table.add_row("Issuer", issuer_str)

            # Validity
            table.add_row(
                "Valid From",
                cert.not_before.strftime("%Y-%m-%d %H:%M:%S"),
            )

            # Expiry with color based on days left
            if cert.days_until_expiry < 0:
                expiry_str = f"[red]{cert.not_after.strftime('%Y-%m-%d %H:%M:%S')} (EXPIRED)[/red]"
            elif cert.days_until_expiry < DEFAULT_SSL_EXPIRY_CRITICAL_DAYS:
                expiry_str = f"[red]{cert.not_after.strftime('%Y-%m-%d %H:%M:%S')} ({cert.days_until_expiry} days)[/red]"
            elif cert.days_until_expiry < DEFAULT_SSL_EXPIRY_WARNING_DAYS:
                expiry_str = f"[yellow]{cert.not_after.strftime('%Y-%m-%d %H:%M:%S')} ({cert.days_until_expiry} days)[/yellow]"
            else:
                expiry_str = f"[green]{cert.not_after.strftime('%Y-%m-%d %H:%M:%S')} ({cert.days_until_expiry} days)[/green]"

            table.add_row("Valid Until", expiry_str)

            # SAN
            if cert.san:
                san_str = ", ".join(cert.san[:MAX_SAN_DISPLAY])
                if len(cert.san) > MAX_SAN_DISPLAY:
                    san_str += f" ... (+{len(cert.san) - MAX_SAN_DISPLAY} more)"
                table.add_row("SAN", san_str)

            self.console.print(table)

            # Print warnings
            if cert.warnings:
                for warning in cert.warnings:
                    self.all_warnings.append(("SSL", warning))
                    self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

            self.console.print()

        # Print protocol support
        if result.protocols:
            protocol_table = Table(title="Supported Protocols", box=box.ROUNDED, show_header=False)
            protocol_table.add_column("Protocol", style="cyan")
            protocol_table.add_column("Status", style="white")

            for protocol in result.protocols:
                if protocol in ("TLSv1.0", "TLSv1.1"):
                    status = "[yellow]Supported (deprecated)[/yellow]"
                elif protocol == "TLSv1.3":
                    status = "[green]Supported[/green]"
                else:
                    status = "Supported"
                protocol_table.add_row(protocol, status)

            self.console.print(protocol_table)
            self.console.print()

        # Print warnings and errors
        if result.errors:
            for error in result.errors:
                self.all_errors.append(("SSL", error))
                self.console.print(f"[red]✗ {error}[/red]")
        if result.warnings:
            for warning in result.warnings:
                self.all_warnings.append(("SSL", warning))
                self.console.print(f"[yellow]⚠ {warning}[/yellow]")

        if result.errors or result.warnings:
            self.console.print()

    def print_email_security_results(
        self,
        result: EmailSecurityResult,
        advanced_result: "AdvancedEmailSecurityResult | None" = None
    ) -> None:
        """Print email security analysis results (SPF/DKIM/DMARC + advanced)."""
        if self.verbosity == "quiet":
            self._print_email_quiet(result, advanced_result)
            return
        elif self.verbosity == "normal":
            self._print_email_compact(result, advanced_result)
            return
        else:
            self._print_email_verbose(result, advanced_result)

    def _print_email_quiet(
        self,
        result: EmailSecurityResult,
        advanced_result: "AdvancedEmailSecurityResult | None" = None
    ) -> None:
        """Print email security results in quiet mode."""
        spf_ok = result.spf and result.spf.is_valid
        dmarc_ok = result.dmarc and result.dmarc.is_valid
        dkim_count = len(result.dkim)

        # Check advanced features
        advanced_count = 0
        if advanced_result:
            if advanced_result.bimi and advanced_result.bimi.record_found:
                advanced_count += 1
            if advanced_result.mta_sts and advanced_result.mta_sts.policy_found:
                advanced_count += 1
            if advanced_result.tls_rpt and advanced_result.tls_rpt.record_found:
                advanced_count += 1

        if spf_ok and dmarc_ok and dkim_count > 0:
            status = f"[green]✓ Email: SPF, DKIM({dkim_count}), DMARC"
            if advanced_count > 0:
                status += f" +{advanced_count} advanced"
            status += "[/green]"
        elif result.errors:
            status = f"[red]✗ Email: {len(result.errors)} errors[/red]"
        else:
            missing = []
            if not spf_ok:
                missing.append("SPF")
            if not dmarc_ok:
                missing.append("DMARC")
            if dkim_count == 0:
                missing.append("DKIM")
            status = f"[yellow]⚠ Email: Missing {', '.join(missing)}[/yellow]"
        self.console.print(status)

    def _print_email_compact(
        self,
        result: EmailSecurityResult,
        advanced_result: "AdvancedEmailSecurityResult | None" = None
    ) -> None:
        """Print email security results in compact mode."""
        self.console.print("[bold blue]Email Security[/bold blue]")

        # SPF
        if result.spf:
            symbol = "✓" if result.spf.is_valid else "⚠"
            color = "green" if result.spf.is_valid else "yellow"
            # Show full SPF record
            self.console.print(f"  [{color}]{symbol}[/] SPF: {result.spf.record}")
        else:
            self.all_errors.append(("Email/SPF", "SPF: Not configured"))
            self.console.print("  [red]✗ SPF: Not configured[/red]")

        # DKIM
        if result.dkim:
            selectors = ", ".join(result.dkim.keys())
            self.console.print(f"  [green]✓[/] DKIM: {selectors}")
        else:
            # Show which selectors were searched
            searched = ", ".join(result.dkim_selectors_searched)
            warning_msg = f"DKIM: Not found (searched: {searched})"
            self.all_warnings.append(("Email/DKIM", warning_msg))
            self.console.print(f"  [yellow]⚠ {warning_msg}[/yellow]")

        # DMARC
        if result.dmarc:
            symbol = "✓" if result.dmarc.is_valid else "⚠"
            color = "green" if result.dmarc.is_valid and result.dmarc.policy in ("quarantine", "reject") else "yellow"
            # Show full DMARC record
            self.console.print(f"  [{color}]{symbol}[/] DMARC: {result.dmarc.record}")
        else:
            self.all_errors.append(("Email/DMARC", "DMARC: Not configured"))
            self.console.print("  [red]✗ DMARC: Not configured[/red]")

        # Advanced Email Security (BIMI, MTA-STS, TLS-RPT)
        if advanced_result:
            # BIMI
            if advanced_result.bimi:
                if advanced_result.bimi.record_found:
                    self.console.print(f"  [green]✓[/] BIMI configured")
                    if advanced_result.bimi.logo_url and self.verbosity in ["verbose", "debug"]:
                        self.console.print(f"    [dim]Logo: {advanced_result.bimi.logo_url}[/dim]")
                else:
                    self.console.print(f"  [dim]BIMI not configured[/dim]")

            # MTA-STS
            if advanced_result.mta_sts:
                if advanced_result.mta_sts.policy_found:
                    mode_color = "green" if advanced_result.mta_sts.policy_mode == "enforce" else "yellow"
                    self.console.print(f"  [{mode_color}]✓[/] MTA-STS (mode: {advanced_result.mta_sts.policy_mode})")
                elif advanced_result.mta_sts.record_found:
                    for error in advanced_result.mta_sts.errors:
                        self.all_errors.append(("Email/MTA-STS", error))
                        self.console.print(f"  [red]✗ MTA-STS: {error}[/red]")
                else:
                    self.console.print(f"  [dim]MTA-STS not configured[/dim]")

            # TLS-RPT
            if advanced_result.tls_rpt:
                if advanced_result.tls_rpt.record_found:
                    self.console.print(f"  [green]✓[/] TLS-RPT configured")
                    if advanced_result.tls_rpt.reporting_addresses and self.verbosity in ["verbose", "debug"]:
                        for addr in advanced_result.tls_rpt.reporting_addresses:
                            self.console.print(f"    [dim]Reporting: {addr}[/dim]")
                else:
                    self.console.print(f"  [dim]TLS-RPT not configured[/dim]")

        # Show actual warnings (deduplicated)
        seen_warnings = set()
        for warning in result.warnings:
            # Skip "No DKIM records found for selectors" if we already showed "DKIM: Not found"
            if "No DKIM records found for selectors" in warning and not result.dkim:
                continue
            if warning not in seen_warnings:
                self.all_warnings.append(("Email", warning))
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")
                seen_warnings.add(warning)

    def _print_email_verbose(
        self,
        result: EmailSecurityResult,
        advanced_result: "AdvancedEmailSecurityResult | None" = None
    ) -> None:
        """Print email security results in verbose mode."""
        self.console.print("[bold blue]═══ Email Security ═══[/bold blue]")
        self.console.print()

        # SPF
        if result.spf:
            spf_status = "[green]✓[/green]" if result.spf.is_valid else "[red]✗[/red]"
            self.console.print(f"{spf_status} [cyan]SPF Record[/cyan]")
            self.console.print(f"  {result.spf.record}")

            if result.spf.mechanisms:
                self.console.print(f"  [dim]Mechanisms: {', '.join(result.spf.mechanisms)}[/dim]")
                self.console.print(f"  [dim]Policy: {result.spf.qualifier}[/dim]")

            for warning in result.spf.warnings:
                self.all_warnings.append(("Email/SPF", warning))
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")
            for error in result.spf.errors:
                self.all_errors.append(("Email/SPF", error))
                self.console.print(f"  [red]✗ {error}[/red]")
        else:
            self.all_errors.append(("Email/SPF", "No SPF record found"))
            self.console.print("[red]✗ No SPF record found[/red]")

        self.console.print()

        # DKIM
        if result.dkim:
            self.console.print(f"[green]✓[/green] [cyan]DKIM Records ({len(result.dkim)} found)[/cyan]")
            for selector, dkim in result.dkim.items():
                dkim_status = "[green]✓[/green]" if dkim.is_valid else "[red]✗[/red]"
                self.console.print(f"  {dkim_status} Selector: [yellow]{selector}[/yellow]")
                self.console.print(f"     [dim]Key Type: {dkim.key_type}[/dim]")

                for warning in dkim.warnings:
                    self.all_warnings.append(("Email/DKIM", warning))
                    self.console.print(f"     [yellow]⚠ {warning}[/yellow]")
                for error in dkim.errors:
                    self.all_errors.append(("Email/DKIM", error))
                    self.console.print(f"     [red]✗ {error}[/red]")
        else:
            self.all_warnings.append(("Email/DKIM", "No DKIM records found"))
            self.console.print("[yellow]⚠ No DKIM records found[/yellow]")

        self.console.print()

        # DMARC
        if result.dmarc:
            dmarc_status = "[green]✓[/green]" if result.dmarc.is_valid else "[red]✗[/red]"
            self.console.print(f"{dmarc_status} [cyan]DMARC Record[/cyan]")
            self.console.print(f"  {result.dmarc.record}")

            if result.dmarc.policy:
                # Color policy based on strictness
                if result.dmarc.policy == "reject":
                    policy_str = "[green]reject[/green]"
                elif result.dmarc.policy == "quarantine":
                    policy_str = "[yellow]quarantine[/yellow]"
                else:
                    policy_str = f"[dim]{result.dmarc.policy}[/dim]"

                self.console.print(f"  [dim]Policy: {policy_str}[/dim]")
                self.console.print(f"  [dim]Percentage: {result.dmarc.percentage}%[/dim]")

            if result.dmarc.rua:
                self.console.print(f"  [dim]Aggregate Reports: {', '.join(result.dmarc.rua)}[/dim]")

            for warning in result.dmarc.warnings:
                self.all_warnings.append(("Email/DMARC", warning))
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")
            for error in result.dmarc.errors:
                self.all_errors.append(("Email/DMARC", error))
                self.console.print(f"  [red]✗ {error}[/red]")
        else:
            self.all_errors.append(("Email/DMARC", "No DMARC record found"))
            self.console.print("[red]✗ No DMARC record found[/red]")

        # Advanced Email Security
        if advanced_result:
            self.console.print()
            self.console.print("[cyan]Advanced Features[/cyan]")
            self.console.print()

            # BIMI
            if advanced_result.bimi:
                if advanced_result.bimi.record_found:
                    self.console.print(f"[green]✓[/green] [cyan]BIMI configured[/cyan]")
                    if advanced_result.bimi.logo_url:
                        self.console.print(f"  Logo URL: {advanced_result.bimi.logo_url}")
                    if advanced_result.bimi.vmc_url:
                        self.console.print(f"  VMC URL: {advanced_result.bimi.vmc_url}")
                else:
                    self.console.print("[dim]BIMI not configured[/dim]")

            # MTA-STS
            if advanced_result.mta_sts:
                if advanced_result.mta_sts.policy_found:
                    mode_color = "green" if advanced_result.mta_sts.policy_mode == "enforce" else "yellow"
                    self.console.print(f"[{mode_color}]✓[/{mode_color}] [cyan]MTA-STS[/cyan]")
                    self.console.print(f"  Mode: {advanced_result.mta_sts.policy_mode}")
                    if advanced_result.mta_sts.max_age:
                        self.console.print(f"  Max Age: {advanced_result.mta_sts.max_age} seconds")
                    if advanced_result.mta_sts.mx_patterns:
                        self.console.print(f"  MX patterns: {', '.join(advanced_result.mta_sts.mx_patterns)}")
                elif advanced_result.mta_sts.record_found:
                    for error in advanced_result.mta_sts.errors:
                        self.all_errors.append(("Email/MTA-STS", error))
                        self.console.print(f"[red]✗ MTA-STS: {error}[/red]")
                else:
                    self.console.print("[dim]MTA-STS not configured[/dim]")

            # TLS-RPT
            if advanced_result.tls_rpt:
                if advanced_result.tls_rpt.record_found:
                    self.console.print(f"[green]✓[/green] [cyan]TLS-RPT configured[/cyan]")
                    for addr in advanced_result.tls_rpt.reporting_addresses:
                        self.console.print(f"  Reporting: {addr}")
                else:
                    self.console.print("[dim]TLS-RPT not configured[/dim]")

        self.console.print()

    def print_security_headers_results(self, result: SecurityHeadersResult) -> None:
        """Print security headers analysis results."""
        if self.verbosity == "quiet":
            self._print_security_headers_quiet(result)
            return
        elif self.verbosity == "normal":
            self._print_security_headers_compact(result)
            return
        else:
            self._print_security_headers_verbose(result)

    def _print_security_headers_quiet(self, result: SecurityHeadersResult) -> None:
        """Print security headers results in quiet mode."""
        if result.score >= SECURITY_SCORE_GOOD:
            status = f"[green]✓ Headers: {result.score}/100[/green]"
        elif result.score >= SECURITY_SCORE_WARNING:
            status = f"[yellow]⚠ Headers: {result.score}/100[/yellow]"
        else:
            status = f"[red]✗ Headers: {result.score}/100[/red]"
        self.console.print(status)

    def _print_security_headers_compact(self, result: SecurityHeadersResult) -> None:
        """Print security headers results in compact mode."""
        score_color = (
            "green"
            if result.score >= SECURITY_SCORE_GOOD
            else "yellow"
            if result.score >= SECURITY_SCORE_WARNING
            else "red"
        )
        self.console.print(f"[bold blue]Security Headers[/bold blue] [{score_color}]({result.score}/100)[/]")

        present_count = sum(1 for h in result.headers.values() if h.present)
        total_count = len(result.headers)
        self.console.print(f"  {present_count}/{total_count} headers present")

        # Show missing critical headers
        missing_headers = [name for name, check in result.headers.items() if not check.present]
        if missing_headers:
            self.console.print(f"  [yellow]Missing: {', '.join(missing_headers)}[/yellow]")

        # Show actual warnings
        for warning in result.warnings:
            self.all_warnings.append(("Security Headers", warning))
            self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

    def _print_security_headers_verbose(self, result: SecurityHeadersResult) -> None:
        """Print security headers results in verbose mode."""
        self.console.print("[bold blue]═══ Security Headers ═══[/bold blue]")
        self.console.print()

        # Print score
        score_color = (
            "green"
            if result.score >= SECURITY_SCORE_GOOD
            else "yellow"
            if result.score >= SECURITY_SCORE_WARNING
            else "red"
        )
        self.console.print(
            f"[{score_color}]Security Score: {result.score}/100[/{score_color}]"
        )
        self.console.print()

        # Create headers table
        table = Table(box=box.ROUNDED)
        table.add_column("Header", style="cyan", width=30)
        table.add_column("Status", style="white", width=10)
        table.add_column("Value / Recommendation", style="dim")

        for header_name, check in result.headers.items():
            if check.present:
                status = "[green]✓[/green]"
                value = check.value or ""
                if len(value) > 60:
                    value = value[:57] + "..."
            else:
                status = "[red]✗[/red]"
                value = f"[dim]Recommended: {check.recommendation}[/dim]"

            table.add_row(header_name, status, value)

        self.console.print(table)
        self.console.print()

        # Print warnings grouped by header
        if result.warnings:
            for header_name, check in result.headers.items():
                if check.warnings:
                    self.console.print(f"[yellow]{header_name}:[/yellow]")
                    for warning in check.warnings:
                        self.all_warnings.append(("Security Headers", warning))
                        self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

            self.console.print()

    def print_rbl_results(self, result: RBLAnalysisResult) -> None:
        """Print RBL (blacklist) check results."""
        if self.verbosity == "quiet":
            self._print_rbl_quiet(result)
            return
        elif self.verbosity == "normal":
            self._print_rbl_compact(result)
            return
        else:
            self._print_rbl_verbose(result)

    def _print_rbl_quiet(self, result: RBLAnalysisResult) -> None:
        """Print RBL results in quiet mode."""
        if not result.checks:
            return  # Skip if no checks
        if result.total_listed > 0:
            status = f"[red]✗ RBL: {result.total_listed} IP(s) blacklisted[/red]"
        else:
            status = f"[green]✓ RBL: All clean ({len(result.checks)} checked)[/green]"
        self.console.print(status)

    def _print_rbl_compact(self, result: RBLAnalysisResult) -> None:
        """Print RBL results in compact mode."""
        if not result.checks:
            return

        self.console.print("[bold blue]RBL Check[/bold blue]")

        listed_count = sum(1 for c in result.checks if c.listed)
        if listed_count > 0:
            self.console.print(f"  [red]✗ {listed_count}/{len(result.checks)} IP(s) blacklisted[/red]")
            for check in result.checks:
                if check.listed:
                    self.console.print(f"    {check.ip}: {', '.join(check.blacklists)}")
        else:
            # Show which IPs were checked
            ips_checked = ", ".join(c.ip for c in result.checks)
            self.console.print(f"  [green]✓ All clean: {ips_checked}[/green]")

    def _print_rbl_verbose(self, result: RBLAnalysisResult) -> None:
        """Print RBL results in verbose mode."""
        self.console.print("[bold blue]═══ RBL (Blacklist) Check ═══[/bold blue]")
        self.console.print()

        if not result.checks:
            self.console.print("[dim]No IP addresses to check[/dim]")
            self.console.print()
            return

        # Create table
        table = Table(box=box.ROUNDED)
        table.add_column("IP Address", style="cyan", width=15)
        table.add_column("Status", style="white", width=12)
        table.add_column("Blacklists", style="dim")

        for check in result.checks:
            if check.listed:
                status = f"[red]LISTED ({len(check.blacklists)})[/red]"
                blacklists = ", ".join(check.blacklists)
            else:
                status = "[green]CLEAN[/green]"
                blacklists = f"[dim]Checked {len(check.not_listed)} RBL(s)[/dim]"

            table.add_row(check.ip, status, blacklists)

        self.console.print(table)
        self.console.print()

        # Print warnings
        if result.warnings:
            for warning in result.warnings:
                self.all_warnings.append(("RBL", warning))
                self.console.print(f"[yellow]⚠ {warning}[/yellow]")
            self.console.print()

        # Print summary
        if result.total_listed > 0:
            self.console.print(
                f"[red]⚠ {result.total_listed} IP address(es) found on blacklists![/red]"
            )
        else:
            self.console.print("[green]✓ No IP addresses found on blacklists[/green]")
        self.console.print()

    def print_site_verification_results(self, result: SiteVerificationAnalysisResult) -> None:
        """Print site verification analysis results (Google, Facebook, Pinterest, etc.)."""
        if self.verbosity == "quiet":
            self._print_site_verification_quiet(result)
            return
        elif self.verbosity == "normal":
            self._print_site_verification_compact(result)
            return
        else:  # verbose or debug
            self._print_site_verification_verbose(result)

    def _print_site_verification_quiet(self, result: SiteVerificationAnalysisResult) -> None:
        """Print site verification results in quiet mode."""
        if not result.service_results and not result.tracking_codes:
            return  # Nothing to print

        # Print status for each service
        for service_result in result.service_results:
            # Skip services with no results
            if not service_result.verification_results and not service_result.detected_verification_ids:
                continue

            # Count verification results
            verified_count = sum(1 for v in service_result.verification_results if v.found)
            total_verification = len(service_result.verification_results)

            # Count auto-detected verification IDs
            detected_count = len(service_result.detected_verification_ids)

            parts = []
            if total_verification > 0:
                if verified_count == total_verification:
                    parts.append(f"verified {verified_count}/{total_verification}")
                else:
                    parts.append(f"[yellow]verified {verified_count}/{total_verification}[/yellow]")
            if detected_count > 0:
                parts.append(f"{detected_count} auto-detected")

            if parts:
                status = f"[green]✓ {service_result.service}: {', '.join(parts)}[/green]"
                self.console.print(status)

        # Print tracking codes count if any (Google-specific legacy)
        if result.tracking_codes:
            tracking_count = len(result.tracking_codes)
            self.console.print(f"[green]✓ Tracking Codes: {tracking_count} detected[/green]")

        if result.errors:
            self.console.print(f"[red]✗ Site Verification: {len(result.errors)} errors[/red]")

    def _print_site_verification_compact(self, result: SiteVerificationAnalysisResult) -> None:
        """Print site verification results in compact mode."""
        self.console.print("[bold blue]Site Verification[/bold blue]")

        # Print HTML fetch error if any
        if result.html_fetch_error:
            self.all_warnings.append(("Site Verification", f"Could not fetch HTML: {result.html_fetch_error}"))
            self.console.print(f"  [yellow]⚠ Could not fetch HTML: {result.html_fetch_error}[/yellow]")

        # Print results for each service
        for service_result in result.service_results:
            # Skip services with no results
            if not service_result.verification_results and not service_result.detected_verification_ids:
                continue

            self.console.print(f"  [bold cyan]{service_result.service}[/bold cyan]")

            # Print Site Verification results (configured)
            if service_result.verification_results:
                self.console.print("    [dim]Configured IDs:[/dim]")
                for verification in service_result.verification_results:
                    if verification.found:
                        methods_str = ", ".join(verification.methods)
                        self.console.print(
                            f"      [green]✓ {verification.verification_id}[/green] "
                            f"[dim]({methods_str})[/dim]"
                        )
                    else:
                        self.all_errors.append(
                            (f"{service_result.service}/Verification", f"ID {verification.verification_id} not found")
                        )
                        self.console.print(
                            f"      [red]✗ {verification.verification_id}[/red] "
                            f"[dim](not found)[/dim]"
                        )

            # Print auto-detected verification IDs
            if service_result.detected_verification_ids:
                self.console.print("    [dim]Auto-detected:[/dim]")
                for verification in service_result.detected_verification_ids:
                    methods_str = ", ".join(verification.methods)
                    self.console.print(
                        f"      [cyan]• {verification.verification_id}[/cyan] "
                        f"[dim]({methods_str})[/dim]"
                    )

        # Print tracking codes (Google-specific legacy)
        if result.tracking_codes:
            self.console.print("  [dim]Tracking Codes:[/dim]")
            for code in result.tracking_codes:
                self.console.print(
                    f"    [cyan]• {code.name}:[/cyan] {code.code} "
                    f"[dim]({code.location})[/dim]"
                )
        elif not result.html_fetch_error and result.service_results:
            # Only show "no tracking codes" if we successfully fetched HTML
            self.console.print("  [dim]Tracking Codes: None detected[/dim]")

        # Print errors
        if result.errors:
            for error in result.errors:
                self.all_errors.append(("Site Verification", error))
                self.console.print(f"  [red]✗ {error}[/red]")

        # Print warnings
        if result.warnings:
            for warning in result.warnings:
                self.all_warnings.append(("Site Verification", warning))
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

        self.console.print()

    def _print_site_verification_verbose(self, result: SiteVerificationAnalysisResult) -> None:
        """Print site verification results in verbose mode with detailed tables."""
        self.console.print("[bold blue]═══ Site Verification ═══[/bold blue]")
        self.console.print()

        # Print HTML fetch status
        if result.html_fetch_error:
            self.all_warnings.append(("Site Verification", f"Could not fetch HTML: {result.html_fetch_error}"))
            self.console.print(f"[yellow]⚠ HTML Fetch Error: {result.html_fetch_error}[/yellow]")
            self.console.print()
        else:
            self.console.print("[green]✓ HTML content fetched successfully[/green]")
            self.console.print()

        # Print verification tables for each service
        for service_result in result.service_results:
            # Skip services with no results
            if not service_result.verification_results and not service_result.detected_verification_ids:
                continue

            self.console.print(f"[bold cyan]═══ {service_result.service} ═══[/bold cyan]")
            self.console.print()

            # Site Verification Table (configured)
            if service_result.verification_results:
                self.console.print(f"[bold]{service_result.service} Verification (Configured)[/bold]")
                table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
                table.add_column("Verification ID")
                table.add_column("Status")
                table.add_column("Methods Found")

                for verification in service_result.verification_results:
                    if verification.found:
                        status = "[green]✓ VERIFIED[/green]"
                        methods = ", ".join(verification.methods)
                    else:
                        status = "[red]✗ NOT FOUND[/red]"
                        methods = "[dim]—[/dim]"
                        self.all_errors.append(
                            (f"{service_result.service}/Verification", f"ID {verification.verification_id} not found")
                        )

                    table.add_row(verification.verification_id, status, methods)

                self.console.print(table)
                self.console.print()

            # Auto-detected Verification IDs Table
            if service_result.detected_verification_ids:
                self.console.print(f"[bold]{service_result.service} Verification (Auto-detected)[/bold]")
                table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
                table.add_column("Verification ID")
                table.add_column("Methods Found")

                for verification in service_result.detected_verification_ids:
                    methods = ", ".join(verification.methods)
                    table.add_row(
                        f"[cyan]{verification.verification_id}[/cyan]",
                        methods
                    )

                self.console.print(table)
                self.console.print()

        # Tracking Codes Table (Google-specific legacy)
        if result.tracking_codes:
            self.console.print("[bold]Tracking Codes Detected[/bold]")
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            table.add_column("Type")
            table.add_column("Code")
            table.add_column("Location")

            for code in result.tracking_codes:
                table.add_row(
                    code.name,
                    f"[cyan]{code.code}[/cyan]",
                    f"[dim]{code.location}[/dim]"
                )

            self.console.print(table)
            self.console.print()
        elif not result.html_fetch_error and result.service_results:
            self.console.print("[dim]No tracking codes detected[/dim]")
            self.console.print()

        # Print errors
        if result.errors:
            for error in result.errors:
                self.all_errors.append(("Site Verification", error))
                self.console.print(f"[red]✗ {error}[/red]")
            self.console.print()

        # Print warnings
        if result.warnings:
            for warning in result.warnings:
                self.all_warnings.append(("Site Verification", warning))
                self.console.print(f"[yellow]⚠ {warning}[/yellow]")
            self.console.print()

    def print_summary(
        self,
        whois_result: WhoisAnalysisResult | None = None,
        dns_result: DNSAnalysisResult | None = None,
        http_result: HTTPAnalysisResult | None = None,
        ssl_result: SSLAnalysisResult | None = None,
        email_result: EmailSecurityResult | None = None,
        security_headers: list[SecurityHeadersResult] | None = None,
        rbl_result: RBLAnalysisResult | None = None,
        site_verification_result: SiteVerificationAnalysisResult | None = None,
        seo_result: SEOFilesAnalysisResult | None = None,
        favicon_result: FaviconAnalysisResult | None = None,
        advanced_email_result: AdvancedEmailSecurityResult | None = None,
        cdn_result: CDNDetectionResult | None = None,
    ) -> None:
        """Print summary of all results."""
        if self.verbosity == "quiet":
            return  # No summary in quiet mode

        if self.verbosity == "normal":
            # Compact summary
            self.console.print()
        else:
            # Verbose summary
            self.console.print("[bold blue]═══ Summary ═══[/bold blue]")
            self.console.print()

        # Count issues from central arrays
        total_errors = len(self.all_errors)
        total_warnings = len(self.all_warnings)

        # Print summary with individual errors/warnings
        if total_errors == 0 and total_warnings == 0:
            self.console.print("[green]✓ No issues found![/green]")
        else:
            # Display individual errors
            if total_errors > 0:
                self.console.print(f"[red]✗ {total_errors} error(s) found:[/red]")
                for category, error in self.all_errors:
                    self.console.print(f"  [red]• [{category}] {error}[/red]")
                self.console.print()

            # Display individual warnings
            if total_warnings > 0:
                self.console.print(f"[yellow]⚠ {total_warnings} warning(s) found:[/yellow]")
                for category, warning in self.all_warnings:
                    self.console.print(f"  [yellow]• [{category}] {warning}[/yellow]")

        self.console.print()

    def print_seo_results(self, result: SEOFilesAnalysisResult) -> None:
        """Print SEO files analysis results."""
        if self.verbosity == "quiet":
            return

        self.console.print("[bold blue]SEO Files[/bold blue]")

        # robots.txt
        if result.robots:
            if result.robots.exists:
                size_info = f" ({result.robots.size} bytes)" if result.robots.size else ""
                self.console.print(f"  [green]✓ robots.txt[/green]{size_info}")
                # Show sitemap count in robots.txt
                if result.robots.sitemaps:
                    sitemap_count = len(result.robots.sitemaps)
                    self.console.print(f"    [dim]{sitemap_count} sitemap(s) referenced[/dim]")
            else:
                for error in result.robots.errors:
                    self.all_errors.append(("SEO", error))
                    self.console.print(f"  [red]✗ robots.txt: {error}[/red]")
                for warning in result.robots.warnings:
                    self.all_warnings.append(("SEO", warning))
                    self.console.print(f"  [yellow]⚠ robots.txt: {warning}[/yellow]")

        # llms.txt
        if result.llms_txt:
            if result.llms_txt.exists:
                size_info = f" ({result.llms_txt.size} bytes)" if result.llms_txt.size else ""
                self.console.print(f"  [green]✓ llms.txt[/green]{size_info}")

        # sitemaps - show URL + count/error on same line
        for sitemap in result.sitemaps:
            if sitemap.exists:
                if sitemap.is_index:
                    self.console.print(f"  [green]✓ Sitemap[/green]: {sitemap.url} - {sitemap.sitemap_count} sitemap(s)")
                else:
                    self.console.print(f"  [green]✓ Sitemap[/green]: {sitemap.url} - {sitemap.url_count} URL(s)")
            elif sitemap.errors:
                # Sitemap referenced but has errors
                error_msg = sitemap.errors[0] if sitemap.errors else "Unknown error"
                self.all_errors.append(("SEO/Sitemap", f"{sitemap.url}: {error_msg}"))
                self.console.print(f"  [red]✗ Sitemap[/red]: {sitemap.url} - {error_msg}")
                # Log remaining errors
                for error in sitemap.errors[1:]:
                    self.all_errors.append(("SEO/Sitemap", f"{sitemap.url}: {error}"))

            # Warnings for this sitemap
            for warning in sitemap.warnings:
                self.all_warnings.append(("SEO/Sitemap", f"{sitemap.url}: {warning}"))
                self.console.print(f"  [yellow]⚠ Sitemap[/yellow]: {sitemap.url} - {warning}")

    def print_favicon_results(self, result: FaviconAnalysisResult) -> None:
        """Print favicon detection results."""
        if self.verbosity == "quiet":
            return

        self.console.print("[bold blue]Favicons[/bold blue]")

        found_favicons = [f for f in result.favicons if f.exists]

        if found_favicons:
            for favicon in found_favicons:
                # Source indicator
                source_labels = {
                    "html": "Found in HTML",
                    "default": "Default path",
                    "manifest": "Web App Manifest",
                    "meta": "Meta tag"
                }
                source_label = source_labels.get(favicon.source, favicon.source)

                # Dimensions info (actual from image data)
                dims_info = ""
                if favicon.all_dimensions:
                    # Multi-layer ICO - show all dimensions
                    dims_info = f" {', '.join(favicon.all_dimensions)}"
                elif favicon.actual_width and favicon.actual_height:
                    dims_info = f" {favicon.actual_width}×{favicon.actual_height}"
                elif favicon.sizes:
                    # Fallback to HTML sizes attribute if no actual dimensions
                    dims_info = f" {favicon.sizes}"
                    if favicon.source == "html":
                        dims_info += " (from HTML)"

                # File size
                size_info = f" ({favicon.size_bytes} bytes)" if favicon.size_bytes else ""

                # Extra attributes (color for mask-icon, purpose for manifest)
                extra_info = []
                if favicon.color:
                    extra_info.append(f"color={favicon.color}")
                if favicon.purpose:
                    extra_info.append(f"purpose={favicon.purpose}")
                if favicon.rel and favicon.rel not in ["icon", "shortcut icon"]:
                    extra_info.append(f"rel={favicon.rel}")

                extra_str = f" [{', '.join(extra_info)}]" if extra_info else ""

                # Full output
                self.console.print(f"  [green]✓[/green] {favicon.url}")
                self.console.print(f"    [dim]{source_label}{dims_info}{size_info}{extra_str}[/dim]")

        # Display warnings
        for warning in result.warnings:
            self.all_warnings.append(("Favicon", warning))
            self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

        if not found_favicons and not result.warnings:
            self.console.print(f"  [dim]No favicons found[/dim]")

    def print_cdn_results(self, result: CDNDetectionResult) -> None:
        """Print CDN detection results."""
        if self.verbosity == "quiet":
            return

        self.console.print("[bold blue]CDN Detection[/bold blue]")

        if result.cdn_detected:
            confidence_color = {"high": "green", "medium": "yellow", "low": "dim"}.get(result.confidence, "dim")
            self.console.print(f"  [{confidence_color}]✓ CDN detected: {result.cdn_provider}[/{confidence_color}]")
            self.console.print(f"    Method: {result.detection_method}, Confidence: {result.confidence}")
            if self.verbosity in ["verbose", "debug"]:
                for evidence in result.evidence:
                    self.console.print(f"    [dim]• {evidence}[/dim]")
        else:
            self.console.print(f"  [dim]No CDN detected[/dim]")

        for warning in result.warnings:
            self.all_warnings.append(("CDN", warning))
            self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

