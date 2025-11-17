"""Flet multiplatform GUI application for webmaster-domain-tool."""

import logging
import re
import threading
from dataclasses import dataclass
from typing import Any

import flet as ft

from .config import load_config
from .core.analyzer import (
    run_domain_analysis,
)

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

        # Results container (aligned left, not centered)
        self.results_column = ft.Column(
            spacing=self.theme.spacing_small,
            expand=True,
            horizontal_alignment=ft.CrossAxisAlignment.START,
        )

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
            # Update status for user
            self.update_status(f"Analyzing {domain}...")

            # Copy config to avoid side effects when modifying for checkbox overrides
            config = self.config.model_copy(deep=True)

            # Apply GUI checkbox overrides to config for features without skip parameters
            if not self.check_seo.value:
                config.analysis.skip_seo = True
            if not self.check_favicon.value:
                config.analysis.skip_favicon = True
            # CDN detection doesn't have a checkbox, uses config default

            # Call CORE analysis (same as CLI!)
            results = run_domain_analysis(
                domain,
                config,
                skip_whois=not self.check_whois.value,
                skip_dns=not self.check_dns.value,
                skip_http=not self.check_http.value,
                skip_ssl=not self.check_ssl.value,
                skip_email=not self.check_email.value,
                skip_headers=not self.check_headers.value,
                skip_site_verification=not self.check_site_verification.value,
                do_rbl_check=self.check_rbl.value,
            )

            # Convert to dict for display_results
            results_dict = {
                "whois": results.whois,
                "dns": results.dns,
                "http": results.http,
                "ssl": results.ssl,
                "email": results.email,
                "advanced_email": results.advanced_email,
                "headers": results.headers,
                "rbl": results.rbl,
                "seo": results.seo,
                "favicon": results.favicon,
                "site_verification": results.site_verification,
                "cdn": results.cdn,
            }

            # Display results (existing method handles this)
            self.display_results(domain, results_dict)

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

        # Determine status icon and color based on errors/warnings
        if total_errors > 0:
            status_icon = ft.Icons.ERROR
            status_color = self.theme.error_color
            status_bg = self.theme.error_bg
            status_text = "Analysis completed with errors"
        elif total_warnings > 0:
            status_icon = ft.Icons.WARNING
            status_color = "#FFA500"  # Orange
            status_bg = "#FFF3CD"  # Light orange/yellow background
            status_text = "Analysis completed with warnings"
        else:
            status_icon = ft.Icons.CHECK_CIRCLE
            status_color = self.theme.success_color
            status_bg = self.theme.success_bg
            status_text = "Analysis completed successfully"

        summary_card = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(
                        status_icon,
                        color=status_color,
                        size=self.theme.icon_medium,
                    ),
                    ft.Column(
                        [
                            ft.Text(
                                f"{status_text}: {domain}",
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
                        alignment=ft.MainAxisAlignment.START,
                    ),
                ],
                alignment=ft.MainAxisAlignment.START,
            ),
            bgcolor=status_bg,
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
            content=self._row(
                [
                    ft.Icon(
                        ft.Icons.ERROR, color=self.theme.error_color, size=self.theme.icon_small
                    ),
                    self._text(message, color=self.theme.error_color),
                ],
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
            content=self._row(
                [
                    ft.Icon(
                        ft.Icons.WARNING, color=self.theme.warning_color, size=self.theme.icon_small
                    ),
                    self._text(message, color=self.theme.warning_color),
                ],
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

    def _text(self, text: str, **kwargs) -> ft.Text:
        """Create a left-aligned text widget with defaults.

        Args:
            text: Text content
            **kwargs: Additional Text properties

        Returns:
            Text widget with left alignment
        """
        if "text_align" not in kwargs:
            kwargs["text_align"] = ft.TextAlign.LEFT
        return ft.Text(text, **kwargs)

    def _row(self, controls: list[ft.Control], **kwargs) -> ft.Row:
        """Create a left-aligned row widget with defaults.

        Args:
            controls: List of controls
            **kwargs: Additional Row properties

        Returns:
            Row widget with left alignment
        """
        if "alignment" not in kwargs:
            kwargs["alignment"] = ft.MainAxisAlignment.START
        return ft.Row(controls, **kwargs)

    def _create_clickable_url(self, url: str, display_text: str | None = None) -> ft.TextButton:
        """Create a clickable URL link.

        Args:
            url: URL to open
            display_text: Optional display text (defaults to url)

        Returns:
            Clickable TextButton
        """
        return ft.TextButton(
            text=display_text or url,
            url=url,
            style=ft.ButtonStyle(
                color=ft.Colors.BLUE,
                padding=0,
            ),
        )

    def _create_clickable_ip(self, ip: str) -> ft.TextButton:
        """Create a clickable IP address link to IP info service.

        Args:
            ip: IP address

        Returns:
            Clickable TextButton linking to IP lookup service
        """
        return ft.TextButton(
            text=ip,
            url=f"https://ipinfo.io/{ip}",
            style=ft.ButtonStyle(
                color=ft.Colors.BLUE,
                padding=0,
            ),
            tooltip=f"Lookup {ip} on ipinfo.io",
        )

    def _create_clickable_whois(self, domain: str) -> ft.TextButton:
        """Create a clickable WHOIS lookup link.

        Args:
            domain: Domain name

        Returns:
            Clickable TextButton linking to WHOIS service
        """
        return ft.TextButton(
            text="View full WHOIS",
            url=f"https://www.whois.com/whois/{domain}",
            icon=ft.Icons.OPEN_IN_NEW,
            style=ft.ButtonStyle(
                color=ft.Colors.BLUE,
                padding=0,
            ),
            tooltip=f"Open WHOIS lookup for {domain}",
        )

    def _create_ssl_labs_link(self, domain: str) -> ft.TextButton:
        """Create a clickable SSL Labs link.

        Args:
            domain: Domain name

        Returns:
            Clickable TextButton linking to SSL Labs
        """
        return ft.TextButton(
            text="Check on SSL Labs",
            url=f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}",
            icon=ft.Icons.OPEN_IN_NEW,
            style=ft.ButtonStyle(
                color=ft.Colors.BLUE,
                padding=0,
            ),
            tooltip=f"Analyze {domain} on SSL Labs",
        )

    def _is_ip_address(self, value: str) -> bool:
        """Check if a string is an IP address (IPv4 or IPv6).

        Args:
            value: String to check

        Returns:
            True if value is an IP address
        """
        import ipaddress

        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _create_expandable_panel(
        self,
        title: str,
        icon: str,
        content: list[ft.Control],
        error_count: int = 0,
        warning_count: int = 0,
    ) -> ft.ExpansionTile:
        """Create an expandable panel for results."""
        # Build title with error/warning counts
        title_parts = [title]
        if error_count > 0:
            title_parts.append(f"({error_count} error{'s' if error_count > 1 else ''})")
        if warning_count > 0:
            title_parts.append(f"({warning_count} warning{'s' if warning_count > 1 else ''})")

        full_title = " ".join(title_parts)

        # Color based on severity: errors > warnings > normal
        if error_count > 0:
            title_color = self.theme.error_color
        elif warning_count > 0:
            title_color = "#FFA500"  # Orange for warnings
        else:
            title_color = self.theme.text_primary

        return ft.ExpansionTile(
            title=ft.Text(
                full_title, size=self.theme.text_subheading, weight="bold", color=title_color
            ),
            leading=ft.Icon(icon, color=title_color),
            controls=content,
            initially_expanded=error_count > 0,  # Auto-expand if errors
        )

    def _create_whois_panel(self, result: Any) -> ft.ExpansionTile:
        """Create WHOIS results panel."""
        content: list[ft.Control] = []
        self._add_errors_and_warnings(content, result)

        if result.registrar:
            content.append(self._text(f"Registrar: {result.registrar}"))
        if result.creation_date:
            content.append(self._text(f"Created: {result.creation_date}"))
        if result.expiration_date:
            content.append(self._text(f"Expires: {result.expiration_date}"))
        if result.updated_date:
            content.append(self._text(f"Updated: {result.updated_date}"))

        # Owner/Registrant information
        if result.registrant_name or result.registrant_organization or result.registrant_email:
            owner_parts = []
            if result.registrant_organization:
                owner_parts.append(result.registrant_organization)
            if result.registrant_name:
                owner_parts.append(result.registrant_name)
            if result.registrant_email:
                owner_parts.append(result.registrant_email)
            content.append(self._text(f"Owner: {' / '.join(owner_parts)}"))

        # Admin contact information
        if result.admin_name or result.admin_email or result.admin_contact:
            admin_parts = []
            if result.admin_contact:
                admin_parts.append(f"[{result.admin_contact}]")
            if result.admin_name:
                admin_parts.append(result.admin_name)
            if result.admin_email:
                admin_parts.append(result.admin_email)
            content.append(self._text(f"Admin: {' / '.join(admin_parts)}"))

        # Add clickable WHOIS lookup link
        content.append(ft.Divider())
        content.append(self._create_clickable_whois(result.domain))

        return self._create_expandable_panel(
            "WHOIS Information", ft.Icons.INFO, content, len(result.errors), len(result.warnings)
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
                    self._text(
                        f"{record_type} Records:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                for record in records:
                    # Make IPs clickable
                    if self._is_ip_address(record.value):
                        content.append(
                            self._row(
                                [
                                    self._text("  • ", size=self.theme.text_body),
                                    self._create_clickable_ip(record.value),
                                ],
                                spacing=0,
                            )
                        )
                    else:
                        content.append(
                            self._text(
                                f"  • {record.value}",
                                size=self.theme.text_body,
                            )
                        )

        return self._create_expandable_panel(
            "DNS Analysis", ft.Icons.DNS, content, len(result.errors), len(result.warnings)
        )

    def _create_http_panel(self, result: Any) -> ft.ExpansionTile:
        """Create HTTP results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Redirect chains - format: URL (CODE) → URL (CODE) → URL (CODE)
        for chain in result.chains:
            if not chain.responses:
                continue

            # Build chain components
            chain_parts = []
            last_response = chain.responses[-1]

            # Determine overall status color
            if last_response.status_code == 200:
                status_color = self.theme.success_color
            else:
                status_color = self.theme.warning_color

            # Build each part: URL (CODE)
            for resp in chain.responses:
                url_button = self._create_clickable_url(resp.url)
                code_text = self._text(
                    f" ({resp.status_code})",
                    size=self.theme.text_body,
                    color=status_color,
                )
                chain_parts.append(url_button)
                chain_parts.append(code_text)

                # Add arrow between responses (but not after last one)
                if resp != chain.responses[-1]:
                    arrow = self._text(" → ", size=self.theme.text_body)
                    chain_parts.append(arrow)

            # Create single row with all parts
            content.append(self._row(chain_parts, spacing=0))

        return self._create_expandable_panel(
            "HTTP/HTTPS Analysis", ft.Icons.HTTP, content, len(result.errors), len(result.warnings)
        )

    def _create_ssl_panel(self, result: Any) -> ft.ExpansionTile:
        """Create SSL results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        if result.certificates:
            for hostname, cert in result.certificates.items():
                content.append(
                    self._text(
                        f"Certificate for {hostname}:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(
                    self._text(
                        f"  Issuer: {cert.issuer}",
                        size=self.theme.text_body,
                    )
                )
                content.append(
                    self._text(
                        f"  Subject: {cert.subject}",
                        size=self.theme.text_body,
                    )
                )
                content.append(
                    self._text(
                        f"  Valid from: {cert.not_before}",
                        size=self.theme.text_body,
                    )
                )
                content.append(
                    self._text(
                        f"  Valid until: {cert.not_after}",
                        size=self.theme.text_body,
                    )
                )

            # Add SSL Labs check link
            content.append(ft.Divider())
            content.append(self._create_ssl_labs_link(result.domain))

        return self._create_expandable_panel(
            "SSL/TLS Analysis", ft.Icons.SECURITY, content, len(result.errors), len(result.warnings)
        )

    def _create_email_panel(self, result: Any, advanced_result: Any = None) -> ft.ExpansionTile:
        """Create email security results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # SPF
        if result.spf:
            content.append(
                self._text(
                    "SPF Record:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            content.append(
                self._text(
                    f"  {result.spf.record}",
                    size=self.theme.text_body,
                )
            )

        # DMARC
        if result.dmarc:
            content.append(
                self._text(
                    "DMARC Record:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            content.append(
                self._text(
                    f"  {result.dmarc.record}",
                    size=self.theme.text_body,
                )
            )

        # Advanced email (BIMI, MTA-STS, TLS-RPT)
        if advanced_result:
            if advanced_result.bimi:
                content.append(
                    self._text(
                        "BIMI Record:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(
                    self._text(
                        f"  {advanced_result.bimi.record_value}",
                        size=self.theme.text_body,
                    )
                )

            if advanced_result.mta_sts:
                content.append(
                    self._text(
                        "MTA-STS:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                content.append(
                    self._text(
                        f"  Mode: {advanced_result.mta_sts.policy_mode}",
                        size=self.theme.text_body,
                    )
                )

        # Count warnings from both basic and advanced email results
        warning_count = len(result.warnings)
        if advanced_result and hasattr(advanced_result, "warnings"):
            warning_count += len(advanced_result.warnings)

        return self._create_expandable_panel(
            "Email Security",
            ft.Icons.EMAIL,
            content,
            len(result.errors),
            warning_count,
        )

    def _create_headers_panel(self, result: Any) -> ft.ExpansionTile:
        """Create security headers results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Headers (dict of SecurityHeaderCheck objects)
        for header_name, header_check in result.headers.items():
            content.append(
                self._text(
                    f"{header_name}:",
                    size=self.theme.text_label,
                    weight="bold",
                )
            )
            if header_check.present:
                content.append(
                    self._text(
                        "  ✓ Present",
                        size=self.theme.text_body,
                        color="green",
                    )
                )
            else:
                content.append(
                    self._text(
                        "  ✗ Missing",
                        size=self.theme.text_body,
                        color="red",
                    )
                )

        return self._create_expandable_panel(
            "Security Headers", ft.Icons.SHIELD, content, len(result.errors), len(result.warnings)
        )

    def _create_rbl_panel(self, result: Any) -> ft.ExpansionTile:
        """Create RBL results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Blacklist status
        for check in result.checks:
            if check.listed:
                content.append(
                    self._row(
                        [
                            self._text(
                                "IP: ",
                                size=self.theme.text_label,
                                weight="bold",
                                color=self.theme.error_color,
                            ),
                            self._create_clickable_ip(check.ip),
                        ],
                        spacing=0,
                    )
                )
                for blacklist in check.blacklists:
                    content.append(
                        self._text(
                            f"  • Listed on: {blacklist}",
                            size=self.theme.text_body,
                        )
                    )

        if result.total_listed == 0:
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
            "RBL Check", ft.Icons.BLOCK, content, len(result.errors), len(result.warnings)
        )

    def _create_seo_panel(self, result: Any) -> ft.ExpansionTile:
        """Create SEO files results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # SEO files status
        if result.robots:
            content.append(
                ft.Container(
                    content=self._row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            self._text("robots.txt found: ", color=self.theme.success_color),
                            self._create_clickable_url(result.robots.url, "View"),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        if result.sitemaps:
            content.append(
                ft.Container(
                    content=ft.Column(
                        [
                            self._row(
                                [
                                    ft.Icon(
                                        ft.Icons.CHECK_CIRCLE,
                                        color=self.theme.success_color,
                                        size=self.theme.icon_small,
                                    ),
                                    self._text(
                                        f"{len(result.sitemaps)} sitemap(s) found:",
                                        color=self.theme.success_color,
                                    ),
                                ],
                            ),
                            *[
                                self._row(
                                    [
                                        self._text("  • "),
                                        self._create_clickable_url(sitemap.url),
                                    ],
                                    spacing=0,
                                )
                                for sitemap in result.sitemaps
                            ],
                        ],
                        spacing=5,
                        horizontal_alignment=ft.CrossAxisAlignment.START,
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        if result.llms_txt:
            content.append(
                ft.Container(
                    content=self._row(
                        [
                            ft.Icon(
                                ft.Icons.CHECK_CIRCLE,
                                color=self.theme.success_color,
                                size=self.theme.icon_small,
                            ),
                            self._text("llms.txt found: ", color=self.theme.success_color),
                            self._create_clickable_url(result.llms_txt.url, "View"),
                        ]
                    ),
                    bgcolor=self.theme.success_bg,
                    border_radius=self.theme.border_radius_small,
                    padding=self.theme.padding_small,
                )
            )

        return self._create_expandable_panel(
            "SEO Files", ft.Icons.SEARCH, content, len(result.errors), len(result.warnings)
        )

    def _create_favicon_panel(self, result: Any) -> ft.ExpansionTile:
        """Create favicon detection results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Favicon findings
        if result.favicons:
            content.append(
                self._text(
                    "Found favicons:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            for favicon in result.favicons:
                content.append(
                    self._row(
                        [
                            self._text("  • ", size=self.theme.text_body),
                            self._create_clickable_url(favicon.url),
                        ],
                        spacing=0,
                    )
                )
                if favicon.sizes:
                    content.append(
                        self._text(
                            f"    Sizes: {favicon.sizes}",
                            size=self.theme.text_small,
                            color=self.theme.text_secondary,
                        )
                    )

        return self._create_expandable_panel(
            "Favicon Detection", ft.Icons.IMAGE, content, len(result.errors), len(result.warnings)
        )

    def _create_site_verification_panel(self, result: Any) -> ft.ExpansionTile:
        """Create site verification results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # Verification findings
        for service_result in result.service_results:
            if service_result.detected_verification_ids:
                content.append(
                    self._text(
                        f"{service_result.service}:",
                        size=self.theme.text_label,
                        weight="bold",
                        color=self.theme.text_primary,
                    )
                )
                for verification in service_result.detected_verification_ids:
                    methods_str = (
                        ", ".join(verification.methods) if verification.methods else "unknown"
                    )
                    content.append(
                        self._text(
                            f"  • {verification.verification_id} ({methods_str})",
                            size=self.theme.text_body,
                        )
                    )

        return self._create_expandable_panel(
            "Site Verification",
            ft.Icons.VERIFIED,
            content,
            len(result.errors),
            len(result.warnings),
        )

    def _create_cdn_panel(self, result: Any) -> ft.ExpansionTile:
        """Create CDN detection results panel."""
        content: list[ft.Control] = []

        self._add_errors_and_warnings(content, result)

        # CDN detection
        if result.cdn_detected and result.cdn_provider:
            content.append(
                self._text(
                    "CDN Detected:",
                    size=self.theme.text_label,
                    weight="bold",
                    color=self.theme.text_primary,
                )
            )
            content.append(
                self._text(
                    f"  Provider: {result.cdn_provider}",
                    size=self.theme.text_body,
                )
            )
            if result.detection_method:
                content.append(
                    self._text(
                        f"  Detection method: {result.detection_method}",
                        size=self.theme.text_body,
                    )
                )
            if result.confidence:
                content.append(
                    self._text(
                        f"  Confidence: {result.confidence}",
                        size=self.theme.text_body,
                    )
                )
            if result.evidence:
                content.append(
                    self._text(
                        "  Evidence:",
                        size=self.theme.text_body,
                    )
                )
                for evidence in result.evidence:
                    content.append(
                        self._text(
                            f"    • {evidence}",
                            size=self.theme.text_body,
                        )
                    )
        else:
            content.append(
                self._text(
                    "No CDN detected",
                    size=self.theme.text_body,
                    color=self.theme.text_secondary,
                )
            )

        return self._create_expandable_panel(
            "CDN Detection", ft.Icons.CLOUD, content, len(result.errors), len(result.warnings)
        )

    def _create_default_auto_display_panel(self, metadata: Any, result: Any) -> ft.ExpansionTile:
        """
        Default auto-display panel for any analyzer result.

        This is called when an analyzer doesn't have a custom renderer.
        It automatically displays all fields from the result object
        using reflection.

        Args:
            metadata: AnalyzerMetadata with display configuration
            result: Any analyzer result object (with errors/warnings)

        Returns:
            Expansion panel with auto-generated content
        """
        content: list[ft.Control] = []

        # Add errors and warnings
        self._add_errors_and_warnings(content, result)

        # Auto-display all other fields (skip domain, errors, warnings)
        skip_fields = {"domain", "errors", "warnings"}

        if hasattr(result, "__dict__"):
            displayed_any = False
            for field_name, value in result.__dict__.items():
                if field_name in skip_fields or value is None:
                    continue

                # Format field name nicely
                field_label = field_name.replace("_", " ").title()

                # Display based on type
                if isinstance(value, bool):
                    # Boolean: show as ✓/✗ with color
                    icon = ft.Icons.CHECK_CIRCLE if value else ft.Icons.CANCEL
                    color = self.theme.success_color if value else self.theme.error_color
                    content.append(
                        self._row(
                            [
                                ft.Icon(icon, color=color, size=self.theme.icon_small),
                                self._text(field_label, color=color),
                            ]
                        )
                    )
                    displayed_any = True
                elif isinstance(value, (str, int, float)):
                    # Simple types: just display
                    content.append(self._text(f"{field_label}: {value}"))
                    displayed_any = True
                elif isinstance(value, list):
                    # Lists: show count and items
                    if value:
                        content.append(
                            self._text(
                                f"{field_label}: ({len(value)} items)",
                                weight="bold",
                                size=self.theme.text_label,
                            )
                        )
                        for item in value[:5]:  # Show first 5
                            content.append(self._text(f"  • {item}", size=self.theme.text_body))
                        if len(value) > 5:
                            content.append(
                                self._text(
                                    f"  ... and {len(value) - 5} more",
                                    size=self.theme.text_small,
                                    color=self.theme.text_secondary,
                                )
                            )
                        displayed_any = True
                elif isinstance(value, dict):
                    # Dicts: show count and keys
                    if value:
                        content.append(
                            self._text(
                                f"{field_label}: ({len(value)} items)",
                                weight="bold",
                                size=self.theme.text_label,
                            )
                        )
                        for key, val in list(value.items())[:5]:
                            content.append(self._text(f"  {key}: {val}", size=self.theme.text_body))
                        if len(value) > 5:
                            content.append(
                                self._text(
                                    f"  ... and {len(value) - 5} more",
                                    size=self.theme.text_small,
                                    color=self.theme.text_secondary,
                                )
                            )
                        displayed_any = True
                else:
                    # Complex objects: try str()
                    content.append(
                        self._text(f"{field_label}: {str(value)}", size=self.theme.text_small)
                    )
                    displayed_any = True

            if not displayed_any and not result.errors and not result.warnings:
                content.append(
                    self._text(
                        "No data available",
                        color=self.theme.text_secondary,
                        size=self.theme.text_small,
                    )
                )

        # Get icon from metadata
        icon = getattr(ft.Icons, metadata.icon, ft.Icons.INFO)

        # Count errors and warnings
        error_count = len(result.errors) if hasattr(result, "errors") else 0
        warning_count = len(result.warnings) if hasattr(result, "warnings") else 0

        return self._create_expandable_panel(
            metadata.title, icon, content, error_count, warning_count
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
