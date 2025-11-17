"""Flet multiplatform GUI application for webmaster-domain-tool."""

import logging
import re
import threading
from dataclasses import dataclass
from typing import Any

import flet as ft

from .analyzers.advanced_email_security import AdvancedEmailSecurityAnalyzer
from .analyzers.cdn_detector import CDNDetector
from .analyzers.dns_analyzer import DNSAnalyzer
from .analyzers.email_security import EmailSecurityAnalyzer
from .analyzers.favicon_analyzer import FaviconAnalyzer
from .analyzers.http_analyzer import HTTPAnalyzer
from .analyzers.rbl_checker import RBLChecker, extract_ips_from_dns_result
from .analyzers.security_headers import SecurityHeadersAnalyzer
from .analyzers.seo_files_analyzer import SEOFilesAnalyzer
from .analyzers.site_verification_analyzer import ServiceConfig, SiteVerificationAnalyzer
from .analyzers.ssl_analyzer import SSLAnalyzer
from .analyzers.whois_analyzer import WhoisAnalyzer
from .config import load_config

logger = logging.getLogger(__name__)


@dataclass
class UITheme:
    """Centralized UI theme configuration for consistent styling."""

    # Primary colors
    primary_color: str = ft.Colors.BLUE_700
    primary_bg: str = ft.Colors.WHITE

    # Text colors
    text_primary: str = ft.Colors.BLUE_700
    text_secondary: str = ft.Colors.GREY_700

    # Status colors
    success_color: str = ft.Colors.GREEN
    success_bg: str = ft.Colors.GREEN_50
    error_color: str = ft.Colors.RED
    error_bg: str = ft.Colors.RED_50
    warning_color: str = ft.Colors.ORANGE
    warning_bg: str = ft.Colors.ORANGE_50

    # Icon sizes
    icon_large: int = 40
    icon_medium: int = 30
    icon_small: int = 20

    # Text sizes
    text_title: int = 28
    text_heading: int = 18
    text_subheading: int = 16
    text_label: int = 14
    text_body: int = 12
    text_small: int = 11

    # Spacing
    spacing_large: int = 20
    spacing_medium: int = 15
    spacing_small: int = 10
    spacing_tiny: int = 5

    # Padding
    padding_large: int = 20
    padding_medium: int = 15
    padding_small: int = 10

    # Border radius
    border_radius_large: int = 10
    border_radius_small: int = 5


class DomainAnalyzerApp:
    """Main Flet application for domain analysis."""

    def __init__(self, page: ft.Page) -> None:
        """Initialize the application."""
        self.page = page
        self.page.title = "Webmaster Domain Tool"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.scroll = ft.ScrollMode.AUTO

        # Initialize theme
        self.theme = UITheme()
        self.page.padding = self.theme.padding_large

        # Load config
        self.config = load_config()

        # UI Components
        self.domain_input = ft.TextField(
            label="Domain name",
            hint_text="example.com",
            prefix_icon=ft.Icons.LANGUAGE,
            expand=True,
            autofocus=True,
            on_submit=lambda _: self.run_analysis(),
        )

        self.analyze_button = ft.ElevatedButton(
            "Analyze Domain",
            icon=ft.Icons.SEARCH,
            on_click=lambda _: self.run_analysis(),
            style=ft.ButtonStyle(
                color=self.theme.primary_bg,
                bgcolor=self.theme.primary_color,
            ),
        )

        self.progress_bar = ft.ProgressBar(visible=False)
        self.status_text = ft.Text("", size=self.theme.text_label, color=self.theme.text_secondary)

        # Analysis options checkboxes
        self.check_dns = ft.Checkbox(label="DNS Analysis", value=True)
        self.check_http = ft.Checkbox(label="HTTP/HTTPS Analysis", value=True)
        self.check_ssl = ft.Checkbox(label="SSL/TLS Analysis", value=True)
        self.check_email = ft.Checkbox(label="Email Security (SPF/DKIM/DMARC)", value=True)
        self.check_headers = ft.Checkbox(label="Security Headers", value=True)
        self.check_whois = ft.Checkbox(label="WHOIS Info", value=True)
        self.check_rbl = ft.Checkbox(label="RBL Blacklist Check", value=False)
        self.check_seo = ft.Checkbox(label="SEO Files", value=True)
        self.check_favicon = ft.Checkbox(label="Favicon Detection", value=True)
        self.check_site_verification = ft.Checkbox(label="Site Verification", value=True)

        # Results container
        self.results_column = ft.Column(spacing=self.theme.spacing_small, expand=True)

        # Build UI
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the user interface."""
        # Header
        header = ft.Container(
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Icon(
                                ft.Icons.DOMAIN,
                                size=self.theme.icon_large,
                                color=self.theme.primary_color,
                            ),
                            ft.Text(
                                "Webmaster Domain Tool",
                                size=self.theme.text_title,
                                weight=ft.FontWeight.BOLD,
                                color=self.theme.primary_color,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    ft.Text(
                        "Comprehensive domain analysis for webmasters",
                        size=self.theme.text_label,
                        color=self.theme.text_secondary,
                        text_align=ft.TextAlign.CENTER,
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=ft.padding.only(bottom=self.theme.padding_large),
        )

        # Input section
        input_section = ft.Card(
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.Text(
                            "Enter Domain", size=self.theme.text_heading, weight=ft.FontWeight.BOLD
                        ),
                        ft.Row(
                            [
                                self.domain_input,
                                self.analyze_button,
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        self.progress_bar,
                        self.status_text,
                    ],
                    spacing=self.theme.spacing_small,
                ),
                padding=self.theme.padding_large,
            ),
            elevation=2,
        )

        # Options section
        options_section = ft.Card(
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.Text(
                            "Analysis Options",
                            size=self.theme.text_heading,
                            weight=ft.FontWeight.BOLD,
                        ),
                        ft.ResponsiveRow(
                            [
                                ft.Container(self.check_dns, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(self.check_http, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(self.check_ssl, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(self.check_email, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(self.check_headers, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(self.check_whois, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(self.check_rbl, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(self.check_seo, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(self.check_favicon, col={"sm": 6, "md": 4, "xl": 3}),
                                ft.Container(
                                    self.check_site_verification, col={"sm": 6, "md": 4, "xl": 3}
                                ),
                            ],
                        ),
                    ],
                    spacing=self.theme.spacing_medium,
                ),
                padding=self.theme.padding_large,
            ),
            elevation=2,
        )

        # Results section
        results_section = ft.Card(
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Results", size=self.theme.text_heading, weight=ft.FontWeight.BOLD),
                        self.results_column,
                    ],
                    spacing=self.theme.spacing_small,
                ),
                padding=self.theme.padding_large,
            ),
            elevation=2,
            visible=False,
        )

        self.results_card = results_section

        # Main layout
        main_column = ft.Column(
            [
                header,
                input_section,
                options_section,
                results_section,
            ],
            spacing=self.theme.spacing_large,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )

        self.page.add(main_column)

    def validate_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        domain = domain.strip()
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )

        return bool(domain_pattern.match(domain))

    def normalize_domain(self, domain: str) -> str:
        """Normalize domain name."""
        domain = domain.strip()
        domain = domain.replace("http://", "").replace("https://", "").rstrip("/")
        return domain

    def run_analysis(self) -> None:
        """Run domain analysis."""
        domain = self.domain_input.value

        if not domain:
            self.show_error("Please enter a domain name")
            return

        if not self.validate_domain(domain):
            self.show_error("Invalid domain format. Expected format: example.com")
            return

        domain = self.normalize_domain(domain)

        # Show progress
        self.progress_bar.visible = True
        self.analyze_button.disabled = True
        self.status_text.value = f"Analyzing {domain}..."
        self.results_column.controls.clear()
        self.results_card.visible = False
        self.page.update()

        # Run analysis in background thread
        thread = threading.Thread(target=self._run_analysis_sync, args=(domain,), daemon=True)
        thread.start()

    def _run_analysis_sync(self, domain: str) -> None:
        """Run analysis synchronously in background thread."""
        try:
            results: dict[str, Any] = {}

            # WHOIS Analysis
            if self.check_whois.value:
                self.update_status("Checking WHOIS information...")
                whois_analyzer = WhoisAnalyzer(
                    expiry_warning_days=self.config.whois.expiry_warning_days,
                    expiry_critical_days=self.config.whois.expiry_critical_days,
                )
                results["whois"] = whois_analyzer.analyze(domain)

            # DNS Analysis
            if self.check_dns.value:
                self.update_status("Analyzing DNS records...")
                dns_analyzer = DNSAnalyzer(
                    nameservers=self.config.dns.nameservers,
                    check_dnssec=self.config.dns.check_dnssec,
                    warn_www_not_cname=self.config.dns.warn_www_not_cname,
                )
                results["dns"] = dns_analyzer.analyze(domain)

            # HTTP/HTTPS Analysis
            if self.check_http.value:
                self.update_status("Analyzing HTTP/HTTPS...")
                http_analyzer = HTTPAnalyzer(
                    timeout=self.config.http.timeout,
                    max_redirects=self.config.http.max_redirects,
                )
                results["http"] = http_analyzer.analyze(domain)

            # SSL/TLS Analysis
            if self.check_ssl.value:
                self.update_status("Analyzing SSL/TLS certificates...")
                ssl_analyzer = SSLAnalyzer(
                    timeout=self.config.http.timeout,
                    cert_expiry_warning_days=self.config.ssl.cert_expiry_warning_days,
                    cert_expiry_critical_days=self.config.ssl.cert_expiry_critical_days,
                )
                results["ssl"] = ssl_analyzer.analyze(domain)

            # Email Security
            if self.check_email.value:
                self.update_status("Checking email security (SPF/DKIM/DMARC)...")
                email_analyzer = EmailSecurityAnalyzer(
                    dkim_selectors=self.config.email.dkim_selectors
                )
                results["email"] = email_analyzer.analyze(domain)

                # Advanced Email Security
                if not self.config.analysis.skip_advanced_email:
                    advanced_email_analyzer = AdvancedEmailSecurityAnalyzer(
                        nameservers=self.config.dns.nameservers,
                        check_bimi=self.config.advanced_email.check_bimi,
                        check_mta_sts=self.config.advanced_email.check_mta_sts,
                        check_tls_rpt=self.config.advanced_email.check_tls_rpt,
                        timeout=self.config.http.timeout,
                    )
                    results["advanced_email"] = advanced_email_analyzer.analyze(domain)

            # Security Headers
            if self.check_headers.value and results.get("http"):
                self.update_status("Checking security headers...")
                http_result = results["http"]
                if http_result.chains and http_result.chains[0].responses:
                    final_response = http_result.chains[0].responses[-1]
                    if final_response.status_code == 200:
                        enabled_checks = {
                            "check_strict_transport_security": self.config.security_headers.check_strict_transport_security,
                            "check_content_security_policy": self.config.security_headers.check_content_security_policy,
                            "check_x_frame_options": self.config.security_headers.check_x_frame_options,
                            "check_x_content_type_options": self.config.security_headers.check_x_content_type_options,
                            "check_referrer_policy": self.config.security_headers.check_referrer_policy,
                            "check_permissions_policy": self.config.security_headers.check_permissions_policy,
                            "check_x_xss_protection": self.config.security_headers.check_x_xss_protection,
                            "check_content_type": self.config.security_headers.check_content_type,
                        }
                        headers_analyzer = SecurityHeadersAnalyzer(enabled_checks=enabled_checks)
                        results["headers"] = headers_analyzer.analyze(
                            final_response.url, final_response.headers
                        )

            # RBL Check
            if self.check_rbl.value and results.get("dns"):
                self.update_status("Checking RBL blacklists...")
                dns_result = results["dns"]
                ips = extract_ips_from_dns_result(dns_result)
                if ips:
                    rbl_checker = RBLChecker(
                        rbl_servers=self.config.email.rbl_servers,
                        timeout=self.config.dns.timeout,
                    )
                    results["rbl"] = rbl_checker.check_ips(domain, ips)

            # SEO Files
            if self.check_seo.value and results.get("http"):
                self.update_status("Checking SEO files...")
                http_result = results["http"]
                if http_result.chains and http_result.chains[0].responses:
                    final_response = http_result.chains[0].responses[-1]
                    if final_response.status_code == 200:
                        seo_analyzer = SEOFilesAnalyzer(
                            timeout=self.config.http.timeout,
                            check_robots=self.config.seo.check_robots,
                            check_llms_txt=self.config.seo.check_llms_txt,
                            check_sitemap=self.config.seo.check_sitemap,
                        )
                        results["seo"] = seo_analyzer.analyze(final_response.url)

            # Favicon Detection
            if self.check_favicon.value and results.get("http"):
                self.update_status("Detecting favicon...")
                http_result = results["http"]
                if http_result.chains and http_result.chains[0].responses:
                    final_response = http_result.chains[0].responses[-1]
                    if final_response.status_code == 200:
                        favicon_analyzer = FaviconAnalyzer(
                            timeout=self.config.http.timeout,
                            check_html=self.config.favicon.check_html,
                            check_defaults=self.config.favicon.check_defaults,
                        )
                        results["favicon"] = favicon_analyzer.analyze(final_response.url)

            # Site Verification
            if self.check_site_verification.value:
                self.update_status("Checking site verification...")
                services = []
                for service_cfg in self.config.site_verification.services:
                    services.append(
                        ServiceConfig(
                            name=service_cfg.name,
                            ids=list(service_cfg.ids),
                            dns_pattern=service_cfg.dns_pattern,
                            file_pattern=service_cfg.file_pattern,
                            meta_name=service_cfg.meta_name,
                            auto_detect=service_cfg.auto_detect,
                        )
                    )

                if services:
                    site_verification_analyzer = SiteVerificationAnalyzer(
                        services=services,
                        timeout=self.config.http.timeout,
                        nameservers=self.config.dns.nameservers,
                    )

                    verification_url = None
                    if results.get("http"):
                        http_result = results["http"]
                        if http_result.chains and http_result.chains[0].responses:
                            final_response = http_result.chains[0].responses[-1]
                            if final_response.status_code == 200:
                                verification_url = final_response.url

                    results["site_verification"] = site_verification_analyzer.analyze(
                        domain, verification_url
                    )

            # CDN Detection
            if results.get("http") and results.get("dns"):
                self.update_status("Detecting CDN...")
                cdn_detector = CDNDetector()
                http_result = results["http"]
                dns_result = results["dns"]

                if http_result.chains and http_result.chains[0].responses:
                    final_response = http_result.chains[0].responses[-1]
                    if final_response.status_code == 200 and final_response.headers:
                        header_result = cdn_detector.detect_from_headers(final_response.headers)
                        header_result.domain = domain

                        cname_result = cdn_detector.detect_from_cname([])
                        cname_key = f"{domain}:CNAME"
                        if cname_key in dns_result.records:
                            cname_values = [r.value for r in dns_result.records[cname_key]]
                            cname_result = cdn_detector.detect_from_cname(cname_values)

                        results["cdn"] = cdn_detector.combine_results(
                            domain, header_result, cname_result
                        )

            # Display results
            self.display_results(domain, results)

        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)
            self.show_error(f"Analysis failed: {str(e)}")
        finally:
            self.progress_bar.visible = False
            self.analyze_button.disabled = False
            self.status_text.value = ""
            self.page.update()

    def update_status(self, message: str) -> None:
        """Update status message."""
        self.status_text.value = message
        self.page.update()

    def display_results(self, domain: str, results: dict[str, Any]) -> None:
        """Display analysis results."""
        self.results_column.controls.clear()

        # Summary
        total_errors = 0
        total_warnings = 0

        for result in results.values():
            if hasattr(result, "errors"):
                total_errors += len(result.errors)
            if hasattr(result, "warnings"):
                total_warnings += len(result.warnings)

        summary_card = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(
                        ft.Icons.CHECK_CIRCLE,
                        color=self.theme.success_color,
                        size=self.theme.icon_medium,
                    ),
                    ft.Column(
                        [
                            ft.Text(
                                f"Analysis completed for: {domain}",
                                size=self.theme.text_subheading,
                                weight="bold",
                            ),
                            ft.Text(
                                f"Errors: {total_errors} | Warnings: {total_warnings}",
                                size=self.theme.text_body,
                                color=self.theme.text_secondary,
                            ),
                        ],
                        spacing=self.theme.spacing_tiny,
                    ),
                ],
                alignment=ft.MainAxisAlignment.START,
            ),
            bgcolor=self.theme.success_bg,
            border_radius=self.theme.border_radius_large,
            padding=self.theme.padding_medium,
        )
        self.results_column.controls.append(summary_card)

        # Individual results
        if "whois" in results:
            self.results_column.controls.append(self._create_whois_panel(results["whois"]))

        if "dns" in results:
            self.results_column.controls.append(self._create_dns_panel(results["dns"]))

        if "http" in results:
            self.results_column.controls.append(self._create_http_panel(results["http"]))

        if "ssl" in results:
            self.results_column.controls.append(self._create_ssl_panel(results["ssl"]))

        if "email" in results:
            self.results_column.controls.append(
                self._create_email_panel(results["email"], results.get("advanced_email"))
            )

        if "headers" in results:
            self.results_column.controls.append(self._create_headers_panel(results["headers"]))

        if "rbl" in results:
            self.results_column.controls.append(self._create_rbl_panel(results["rbl"]))

        if "seo" in results:
            self.results_column.controls.append(self._create_seo_panel(results["seo"]))

        if "favicon" in results:
            self.results_column.controls.append(self._create_favicon_panel(results["favicon"]))

        if "site_verification" in results:
            self.results_column.controls.append(
                self._create_site_verification_panel(results["site_verification"])
            )

        if "cdn" in results:
            self.results_column.controls.append(self._create_cdn_panel(results["cdn"]))

        self.results_card.visible = True
        self.page.update()

    def _create_error_container(self, message: str) -> ft.Container:
        """Create a standardized error display container.

        Args:
            message: Error message to display

        Returns:
            Formatted Container widget with error styling
        """
        return ft.Container(
            content=ft.Row(
                [
                    ft.Icon(
                        ft.Icons.ERROR, color=self.theme.error_color, size=self.theme.icon_small
                    ),
                    ft.Text(message, color=self.theme.error_color),
                ]
            ),
            bgcolor=self.theme.error_bg,
            border_radius=self.theme.border_radius_small,
            padding=self.theme.padding_small,
        )

    def _create_warning_container(self, message: str) -> ft.Container:
        """Create a standardized warning display container.

        Args:
            message: Warning message to display

        Returns:
            Formatted Container widget with warning styling
        """
        return ft.Container(
            content=ft.Row(
                [
                    ft.Icon(
                        ft.Icons.WARNING, color=self.theme.warning_color, size=self.theme.icon_small
                    ),
                    ft.Text(message, color=self.theme.warning_color),
                ]
            ),
            bgcolor=self.theme.warning_bg,
            border_radius=self.theme.border_radius_small,
            padding=self.theme.padding_small,
        )

    def _add_errors_and_warnings(self, content: list[ft.Control], result: Any) -> None:
        """Add error and warning displays to content list.

        Args:
            content: List of controls to append to
            result: Analysis result object with errors and warnings attributes
        """
        if hasattr(result, "errors") and result.errors:
            for error in result.errors:
                content.append(self._create_error_container(error))

        if hasattr(result, "warnings") and result.warnings:
            for warning in result.warnings:
                content.append(self._create_warning_container(warning))

    def _create_expandable_panel(
        self, title: str, icon: str, content: list[ft.Control], error_count: int = 0
    ) -> ft.ExpansionTile:
        """Create an expandable panel for results."""
        title_color = self.theme.error_color if error_count > 0 else self.theme.text_primary

        return ft.ExpansionTile(
            title=ft.Text(title, size=self.theme.text_subheading, weight="bold", color=title_color),
            leading=ft.Icon(icon, color=title_color),
            controls=content,
            initially_expanded=error_count > 0,
        )

    def _create_whois_panel(self, result: Any) -> ft.ExpansionTile:
        """Create WHOIS results panel."""
        content: list[ft.Control] = []
        self._add_errors_and_warnings(content, result)

        if result.registrar:
            content.append(ft.Text(f"Registrar: {result.registrar}"))
        if result.creation_date:
            content.append(ft.Text(f"Created: {result.creation_date}"))
        if result.expiration_date:
            content.append(ft.Text(f"Expires: {result.expiration_date}"))
        if result.updated_date:
            content.append(ft.Text(f"Updated: {result.updated_date}"))

        # Owner/Registrant information
        if result.registrant_name or result.registrant_organization or result.registrant_email:
            owner_parts = []
            if result.registrant_organization:
                owner_parts.append(result.registrant_organization)
            if result.registrant_name:
                owner_parts.append(result.registrant_name)
            if result.registrant_email:
                owner_parts.append(result.registrant_email)
            content.append(ft.Text(f"Owner: {' / '.join(owner_parts)}"))

        # Admin contact information
        if result.admin_name or result.admin_email or result.admin_contact:
            admin_parts = []
            if result.admin_contact:
                admin_parts.append(f"[{result.admin_contact}]")
            if result.admin_name:
                admin_parts.append(result.admin_name)
            if result.admin_email:
                admin_parts.append(result.admin_email)
            content.append(ft.Text(f"Admin: {' / '.join(admin_parts)}"))

        return self._create_expandable_panel(
            "WHOIS Information", ft.Icons.INFO, content, len(result.errors)
        )

    def _create_dns_panel(self, result: Any) -> ft.ExpansionTile:
        """Create DNS results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # DNS records
        for record_key, records in result.records.items():
            if records:
                record_type = record_key.split(":")[-1]
                content.append(
                    ft.Text(
                        f"{record_type} Records:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                for record in records:
                    content.append(ft.Text(f"  • {record.value}", size=self.theme.text_body))

        return self._create_expandable_panel(
            "DNS Analysis", ft.Icons.DNS, content, len(result.errors)
        )

    def _create_http_panel(self, result: Any) -> ft.ExpansionTile:
        """Create HTTP results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Redirect chains
        for i, chain in enumerate(result.chains, 1):
            content.append(
                ft.Text(
                    f"Chain {i}: {chain.start_url}",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            for response in chain.responses:
                status_color = (
                    self.theme.success_color
                    if response.status_code == 200
                    else self.theme.warning_color
                )
                content.append(
                    ft.Text(
                        f"  → {response.status_code} {response.url}",
                        size=self.theme.text_body,
                        color=status_color,
                    )
                )

        return self._create_expandable_panel(
            "HTTP/HTTPS Analysis", ft.Icons.HTTP, content, len(result.errors)
        )

    def _create_ssl_panel(self, result: Any) -> ft.ExpansionTile:
        """Create SSL results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        if result.certificates:
            for hostname, cert in result.certificates.items():
                content.append(
                    ft.Text(
                        f"Certificate for {hostname}:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(ft.Text(f"  Issuer: {cert.issuer}", size=self.theme.text_body))
                content.append(ft.Text(f"  Subject: {cert.subject}", size=self.theme.text_body))
                content.append(
                    ft.Text(f"  Valid from: {cert.not_valid_before}", size=self.theme.text_body)
                )
                content.append(
                    ft.Text(f"  Valid until: {cert.not_valid_after}", size=self.theme.text_body)
                )

        return self._create_expandable_panel(
            "SSL/TLS Analysis", ft.Icons.SECURITY, content, len(result.errors)
        )

    def _create_email_panel(self, result: Any, advanced_result: Any = None) -> ft.ExpansionTile:
        """Create email security results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # SPF
        if result.spf_record:
            content.append(
                ft.Text(
                    "SPF Record:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            content.append(ft.Text(f"  {result.spf_record}", size=self.theme.text_body))

        # DMARC
        if result.dmarc_record:
            content.append(
                ft.Text(
                    "DMARC Record:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            content.append(ft.Text(f"  {result.dmarc_record}", size=self.theme.text_body))

        # Advanced email (BIMI, MTA-STS, TLS-RPT)
        if advanced_result:
            if advanced_result.bimi_record:
                content.append(
                    ft.Text(
                        "BIMI Record:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(
                    ft.Text(f"  {advanced_result.bimi_record}", size=self.theme.text_body)
                )

            if advanced_result.mta_sts_policy:
                content.append(
                    ft.Text(
                        "MTA-STS:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(
                    ft.Text(f"  Mode: {advanced_result.mta_sts_policy}", size=self.theme.text_body)
                )

        return self._create_expandable_panel(
            "Email Security", ft.Icons.EMAIL, content, len(result.errors)
        )

    def _create_headers_panel(self, result: Any) -> ft.ExpansionTile:
        """Create security headers results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Present headers
        for header_name, header_value in result.present_headers.items():
            content.append(ft.Text(f"{header_name}:", size=self.theme.text_label, weight="bold"))
            content.append(ft.Text(f"  {header_value}", size=self.theme.text_body))

        return self._create_expandable_panel(
            "Security Headers", ft.Icons.SHIELD, content, len(result.errors)
        )

    def _create_rbl_panel(self, result: Any) -> ft.ExpansionTile:
        """Create RBL results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Blacklist status
        for ip, listings in result.blacklisted_ips.items():
            content.append(
                ft.Text(
                    f"IP: {ip}",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.error_color,
                )
            )
            for listing in listings:
                content.append(ft.Text(f"  • Listed on: {listing}", size=self.theme.text_body))

        if not result.blacklisted_ips:
            content.append(
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            ft.Text("No blacklist listings found", color=self.theme.success_color),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        return self._create_expandable_panel(
            "RBL Check", ft.Icons.BLOCK, content, len(result.errors)
        )

    def _create_seo_panel(self, result: Any) -> ft.ExpansionTile:
        """Create SEO files results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # SEO files status
        if result.robots_txt:
            content.append(
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            ft.Text("robots.txt found", color=self.theme.success_color),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        if result.sitemap_xml:
            content.append(
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            ft.Text("sitemap.xml found", color=self.theme.success_color),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        if result.llms_txt:
            content.append(
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            ft.Text("llms.txt found", color=self.theme.success_color),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        return self._create_expandable_panel(
            "SEO Files", ft.Icons.SEARCH, content, len(result.errors)
        )

    def _create_favicon_panel(self, result: Any) -> ft.ExpansionTile:
        """Create favicon detection results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Favicon findings
        if result.favicons:
            content.append(
                ft.Text(
                    "Found favicons:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            for favicon in result.favicons:
                content.append(ft.Text(f"  • {favicon.url}", size=self.theme.text_body))
                if favicon.sizes:
                    content.append(
                        ft.Text(
                            f"    Sizes: {favicon.sizes}",
                            size=self.theme.text_small,
                            color=self.theme.text_secondary,
                        )
                    )

        return self._create_expandable_panel(
            "Favicon Detection", ft.Icons.IMAGE, content, len(result.errors)
        )

    def _create_site_verification_panel(self, result: Any) -> ft.ExpansionTile:
        """Create site verification results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Verification findings
        for service_name, verifications in result.verifications.items():
            if verifications:
                content.append(
                    ft.Text(
                        f"{service_name}:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                for verification in verifications:
                    content.append(
                        ft.Text(
                            f"  • {verification.verification_id} ({verification.method})",
                            size=self.theme.text_body,
                        )
                    )

        return self._create_expandable_panel(
            "Site Verification", ft.Icons.VERIFIED, content, len(result.errors)
        )

    def _create_cdn_panel(self, result: Any) -> ft.ExpansionTile:
        """Create CDN detection results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # CDN detection
        if result.detected_cdns:
            content.append(
                ft.Text(
                    "Detected CDNs:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            for cdn in result.detected_cdns:
                content.append(ft.Text(f"  • {cdn}", size=self.theme.text_body))
        else:
            content.append(
                ft.Text(
                    "No CDN detected", size=self.theme.text_body, color=self.theme.text_secondary
                )
            )

        return self._create_expandable_panel(
            "CDN Detection", ft.Icons.CLOUD, content, len(result.errors)
        )

    def show_error(self, message: str) -> None:
        """Show error message."""
        error_banner = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.ERROR, color=self.theme.error_color),
                    ft.Text(message, color=self.theme.error_color),
                ],
            ),
            bgcolor=self.theme.error_bg,
            border=ft.border.all(1, self.theme.error_color),
            border_radius=self.theme.border_radius_large,
            padding=self.theme.padding_medium,
        )

        self.results_column.controls.clear()
        self.results_column.controls.append(error_banner)
        self.results_card.visible = True
        self.page.update()


def main() -> None:
    """Main entry point for Flet app."""

    def create_app(page: ft.Page) -> None:
        """Create and initialize the app."""
        DomainAnalyzerApp(page)

    ft.app(target=create_app)


if __name__ == "__main__":
    main()
