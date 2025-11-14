"""Output formatting using rich library."""

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

from ..analyzers.dns_analyzer import DNSAnalysisResult
from ..analyzers.http_analyzer import HTTPAnalysisResult, HTTPResponse
from ..analyzers.ssl_analyzer import SSLAnalysisResult, CertificateInfo
from ..analyzers.email_security import EmailSecurityResult
from ..analyzers.security_headers import SecurityHeadersResult
from ..analyzers.rbl_checker import RBLAnalysisResult


class OutputFormatter:
    """Formats analysis results for console output."""

    def __init__(self, console: Console | None = None):
        """
        Initialize output formatter.

        Args:
            console: Rich console instance (creates new one if not provided)
        """
        self.console = console or Console()

    def print_header(self, domain: str) -> None:
        """Print analysis header."""
        self.console.print()
        self.console.print(
            Panel(
                f"[bold cyan]Webmaster Domain Analysis[/bold cyan]\n"
                f"[white]Domain:[/white] [yellow]{domain}[/yellow]",
                box=box.DOUBLE,
                expand=False,
            )
        )
        self.console.print()

    def print_dns_results(self, result: DNSAnalysisResult) -> None:
        """Print DNS analysis results."""
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
            elif cert.days_until_expiry < 30:
                expiry_str = f"[red]{cert.not_after.strftime('%Y-%m-%d %H:%M:%S')} ({cert.days_until_expiry} days)[/red]"
            elif cert.days_until_expiry < 60:
                expiry_str = f"[yellow]{cert.not_after.strftime('%Y-%m-%d %H:%M:%S')} ({cert.days_until_expiry} days)[/yellow]"
            else:
                expiry_str = f"[green]{cert.not_after.strftime('%Y-%m-%d %H:%M:%S')} ({cert.days_until_expiry} days)[/green]"

            table.add_row("Valid Until", expiry_str)

            # SAN
            if cert.san:
                san_str = ", ".join(cert.san[:5])
                if len(cert.san) > 5:
                    san_str += f" ... (+{len(cert.san) - 5} more)"
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
        self.console.print("[bold blue]═══ Security Headers ═══[/bold blue]")
        self.console.print()

        # Print score
        score_color = "green" if result.score >= 75 else "yellow" if result.score >= 50 else "red"
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
