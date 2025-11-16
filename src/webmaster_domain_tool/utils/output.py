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

    def print_header(self, domain: str) -> None:
        """Print analysis header."""
        if self.verbosity == "quiet":
            self.console.print(f"[bold]{domain}[/bold]")
        else:
            self.console.print()
            self.console.print(f"[bold cyan]Webmaster Domain Analysis[/bold cyan]")
            self.console.print(f"Domain: [yellow]{domain}[/yellow]")
            self.console.print()

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
                self.console.print(f"  [red]✗ {error}[/red]")
            return

        # Group records by type and show values
        records_by_type = {}
        for key, records in result.records.items():
            domain, record_type = key.rsplit(":", 1)
            if record_type not in records_by_type:
                records_by_type[record_type] = []
            for record in records:
                records_by_type[record_type].append(record.value)

        # Important record types to always show
        important_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

        # Print records (show important types first, then others)
        shown_types = set()
        for record_type in important_types:
            if record_type in records_by_type:
                values = records_by_type[record_type]
                if len(values) == 1:
                    self.console.print(f"  {record_type}: {values[0]}")
                elif record_type in ("NS", "A", "AAAA"):
                    # NS, A, AAAA records on single line, space-separated
                    self.console.print(f"  {record_type}: {' '.join(values)}")
                else:
                    self.console.print(f"  {record_type}:")
                    for value in values:
                        self.console.print(f"    - {value}")
                shown_types.add(record_type)

                # If CNAME, also show resolved A records
                if record_type == "CNAME" and "CNAME_A" in records_by_type:
                    cname_a_values = records_by_type["CNAME_A"]
                    self.console.print(f"  └─> A (resolved): {' '.join(cname_a_values)}")
                    shown_types.add("CNAME_A")
            else:
                # Show missing important records
                self.console.print(f"  {record_type}: [dim]none[/dim]")

        # Show any other record types
        for record_type in sorted(records_by_type.keys()):
            if record_type not in shown_types:
                values = records_by_type[record_type]
                if len(values) == 1:
                    self.console.print(f"  {record_type}: {values[0]}")
                else:
                    self.console.print(f"  {record_type}:")
                    for value in values:
                        self.console.print(f"    - {value}")

        # Show PTR records
        if result.ptr_records:
            # Single line: IP → hostname
            ptr_list = [f"{ip} → {ptr}" for ip, ptr in result.ptr_records.items()]
            self.console.print(f"  PTR: {', '.join(ptr_list)}")

        # Show DNSSEC status
        if result.dnssec and result.dnssec.enabled:
            status = "✓" if result.dnssec.valid else "⚠"
            self.console.print(f"  DNSSEC: [{('green' if result.dnssec.valid else 'yellow')}]{status}[/]")

        # Show actual warnings
        for warning in result.warnings:
            self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

    def _print_dns_verbose(self, result: DNSAnalysisResult) -> None:
        """Print DNS results in verbose mode (full detail)."""
        self.console.print("[bold blue]═══ DNS Records ═══[/bold blue]")
        self.console.print()

        if result.errors:
            for error in result.errors:
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
                self.console.print(f"  [red]✗ {error}[/red]")
            for warning in dnssec.warnings:
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

            self.console.print()

        # Print warnings
        if result.warnings:
            for warning in result.warnings:
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

        # Show actual warnings (deduplicated)
        seen_warnings = set()
        for warning in result.warnings:
            # Skip duplicate warnings about HTTP ending
            if "ends on HTTP" in warning and "does not redirect to HTTPS" in result.warnings:
                if "ends on HTTP" in warning:
                    continue
            if warning not in seen_warnings:
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")
                seen_warnings.add(warning)

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
                self.console.print(f"[red]✗ {error}[/red]")
        if result.warnings:
            for warning in result.warnings:
                self.console.print(f"[yellow]⚠ {warning}[/yellow]")

        if result.errors or result.warnings:
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
            if cert.errors:
                self.console.print(f"  [red]✗ {domain}: {cert.errors[0]}[/red]")
            else:
                if cert.days_until_expiry < DEFAULT_SSL_EXPIRY_CRITICAL_DAYS:
                    color = "red"
                    symbol = "✗"
                elif cert.days_until_expiry < DEFAULT_SSL_EXPIRY_WARNING_DAYS:
                    color = "yellow"
                    symbol = "⚠"
                else:
                    color = "green"
                    symbol = "✓"

                issuer = cert.issuer.get("organizationName", cert.issuer.get("commonName", "Unknown"))
                self.console.print(
                    f"  [{color}]{symbol}[/] {domain}: {issuer} ({cert.days_until_expiry}d)"
                )

        if result.protocols:
            self.console.print(f"  TLS: {', '.join(result.protocols)}")

        # Show actual warnings
        for warning in result.warnings:
            self.console.print(f"  [yellow]⚠ {warning}[/yellow]")

    def _print_ssl_verbose(self, result: SSLAnalysisResult) -> None:
        """Print SSL results in verbose mode."""
        self.console.print("[bold blue]═══ SSL/TLS Certificates ═══[/bold blue]")
        self.console.print()

        if not result.certificates:
            self.console.print("[red]✗ No SSL certificates found[/red]")
            self.console.print()
            return

        for domain, cert in result.certificates.items():
            if cert.errors:
                # Certificate has errors
                self.console.print(f"[red]✗ {domain}[/red]")
                for error in cert.errors:
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
                self.console.print(f"[red]✗ {error}[/red]")
        if result.warnings:
            for warning in result.warnings:
                self.console.print(f"[yellow]⚠ {warning}[/yellow]")

        if result.errors or result.warnings:
            self.console.print()

    def print_email_security_results(self, result: EmailSecurityResult) -> None:
        """Print email security analysis results."""
        if self.verbosity == "quiet":
            self._print_email_quiet(result)
            return
        elif self.verbosity == "normal":
            self._print_email_compact(result)
            return
        else:
            self._print_email_verbose(result)

    def _print_email_quiet(self, result: EmailSecurityResult) -> None:
        """Print email security results in quiet mode."""
        spf_ok = result.spf and result.spf.is_valid
        dmarc_ok = result.dmarc and result.dmarc.is_valid
        dkim_count = len(result.dkim)

        if spf_ok and dmarc_ok and dkim_count > 0:
            status = f"[green]✓ Email: SPF, DKIM({dkim_count}), DMARC[/green]"
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

    def _print_email_compact(self, result: EmailSecurityResult) -> None:
        """Print email security results in compact mode."""
        self.console.print("[bold blue]Email Security[/bold blue]")

        # SPF
        if result.spf:
            symbol = "✓" if result.spf.is_valid else "⚠"
            color = "green" if result.spf.is_valid else "yellow"
            self.console.print(f"  [{color}]{symbol}[/] SPF: {result.spf.qualifier}")
        else:
            self.console.print("  [red]✗ SPF: Not configured[/red]")

        # DKIM
        if result.dkim:
            selectors = ", ".join(result.dkim.keys())
            self.console.print(f"  [green]✓[/] DKIM: {selectors}")
        else:
            self.console.print("  [yellow]⚠ DKIM: Not found[/yellow]")

        # DMARC
        if result.dmarc:
            symbol = "✓" if result.dmarc.is_valid else "⚠"
            color = "green" if result.dmarc.is_valid and result.dmarc.policy in ("quarantine", "reject") else "yellow"
            # Show full DMARC record
            self.console.print(f"  [{color}]{symbol}[/] DMARC: {result.dmarc.record}")
        else:
            self.console.print("  [red]✗ DMARC: Not configured[/red]")

        # Show actual warnings (deduplicated)
        seen_warnings = set()
        for warning in result.warnings:
            # Skip "No DKIM records found for selectors" if we already showed "DKIM: Not found"
            if "No DKIM records found for selectors" in warning and not result.dkim:
                continue
            if warning not in seen_warnings:
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")
                seen_warnings.add(warning)

    def _print_email_verbose(self, result: EmailSecurityResult) -> None:
        """Print email security results in verbose mode."""
        self.console.print("[bold blue]═══ Email Security (SPF, DKIM, DMARC) ═══[/bold blue]")
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
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")
            for error in result.spf.errors:
                self.console.print(f"  [red]✗ {error}[/red]")
        else:
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
                    self.console.print(f"     [yellow]⚠ {warning}[/yellow]")
                for error in dkim.errors:
                    self.console.print(f"     [red]✗ {error}[/red]")
        else:
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
                self.console.print(f"  [yellow]⚠ {warning}[/yellow]")
            for error in result.dmarc.errors:
                self.console.print(f"  [red]✗ {error}[/red]")
        else:
            self.console.print("[red]✗ No DMARC record found[/red]")

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

    def print_summary(
        self,
        dns_result: DNSAnalysisResult | None = None,
        http_result: HTTPAnalysisResult | None = None,
        ssl_result: SSLAnalysisResult | None = None,
        email_result: EmailSecurityResult | None = None,
        security_headers: list[SecurityHeadersResult] | None = None,
        rbl_result: RBLAnalysisResult | None = None,
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

        # Count issues
        total_errors = 0
        total_warnings = 0

        if dns_result:
            total_errors += len(dns_result.errors)
            total_warnings += len(dns_result.warnings)

        if http_result:
            total_errors += len(http_result.errors)
            total_warnings += len(http_result.warnings)

        if ssl_result:
            total_errors += len(ssl_result.errors)
            total_warnings += len(ssl_result.warnings)

        if email_result:
            total_errors += len(email_result.errors)
            total_warnings += len(email_result.warnings)

        if security_headers:
            for sh_result in security_headers:
                total_errors += len(sh_result.errors)
                total_warnings += len(sh_result.warnings)

        if rbl_result:
            total_errors += len(rbl_result.errors)
            total_warnings += len(rbl_result.warnings)

        # Print summary
        if total_errors == 0 and total_warnings == 0:
            self.console.print("[green]✓ No issues found![/green]")
        else:
            if total_errors > 0:
                self.console.print(f"[red]✗ {total_errors} error(s) found[/red]")
            if total_warnings > 0:
                self.console.print(f"[yellow]⚠ {total_warnings} warning(s) found[/yellow]")

        self.console.print()
