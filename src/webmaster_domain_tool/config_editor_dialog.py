"""Configuration editor dialog for Flet GUI."""

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import flet as ft

from .config import Config

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ConfigEditorDialog:
    """Comprehensive configuration editor dialog with tabbed interface."""

    def __init__(self, page: ft.Page, config: Config, on_save: Callable[[Config], None]) -> None:
        """
        Initialize config editor dialog.

        Args:
            page: Flet page
            config: Current configuration to edit
            on_save: Callback when config is saved (receives Config object)
        """
        self.page = page
        self.config = config.model_copy(deep=True)  # Work on a copy
        self.on_save = on_save

        # UI field references (grouped by section)
        self.dns_fields: dict[str, ft.Control] = {}
        self.http_fields: dict[str, ft.Control] = {}
        self.ssl_fields: dict[str, ft.Control] = {}
        self.security_headers_fields: dict[str, ft.Control] = {}
        self.email_fields: dict[str, ft.Control] = {}
        self.whois_fields: dict[str, ft.Control] = {}
        self.seo_fields: dict[str, ft.Control] = {}
        self.favicon_fields: dict[str, ft.Control] = {}
        self.site_verification_fields: dict[str, ft.Control] = {}
        self.output_fields: dict[str, ft.Control] = {}

        # Build dialog
        self.dialog = self._build_dialog()

    def _build_dialog(self) -> ft.AlertDialog:
        """Build the main dialog with tabs."""
        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                self._create_dns_tab(),
                self._create_http_tab(),
                self._create_ssl_tab(),
                self._create_email_tab(),
                self._create_security_headers_tab(),
                self._create_seo_tab(),
                self._create_favicon_tab(),
                self._create_whois_tab(),
                self._create_site_verification_tab(),
                self._create_output_tab(),
            ],
            expand=1,
        )

        return ft.AlertDialog(
            modal=True,
            title=ft.Text("Configuration Editor", size=20, weight="bold"),
            content=ft.Container(
                content=tabs,
                width=700,
                height=500,
            ),
            actions=[
                ft.TextButton("Import TOML", on_click=lambda _: self._import_toml()),
                ft.TextButton("Export TOML", on_click=lambda _: self._export_toml()),
                ft.TextButton("Cancel", on_click=lambda _: self._close_dialog()),
                ft.ElevatedButton("Save", on_click=lambda _: self._save_and_close()),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

    # ========== TAB CREATORS ==========

    def _create_dns_tab(self) -> ft.Tab:
        """Create DNS configuration tab."""
        self.dns_fields["skip"] = ft.Checkbox(
            label="Skip DNS analysis",
            value=self.config.dns.skip,
        )
        self.dns_fields["nameservers"] = ft.TextField(
            label="DNS Nameservers (comma-separated)",
            value=", ".join(self.config.dns.nameservers),
            hint_text="8.8.8.8, 8.8.4.4, 1.1.1.1",
            multiline=False,
        )
        self.dns_fields["timeout"] = ft.TextField(
            label="DNS Timeout (seconds)",
            value=str(self.config.dns.timeout),
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        self.dns_fields["check_dnssec"] = ft.Checkbox(
            label="Check DNSSEC validation",
            value=self.config.dns.check_dnssec,
        )
        self.dns_fields["warn_www_not_cname"] = ft.Checkbox(
            label="Warn if www is not CNAME (best practice)",
            value=self.config.dns.warn_www_not_cname,
        )
        self.dns_fields["skip_www"] = ft.Checkbox(
            label="Skip testing www subdomain",
            value=self.config.dns.skip_www,
        )

        return ft.Tab(
            text="DNS",
            icon=ft.Icons.DNS,
            content=ft.Container(
                content=ft.Column(
                    [
                        self.dns_fields["skip"],
                        ft.Divider(),
                        self.dns_fields["nameservers"],
                        self.dns_fields["timeout"],
                        self.dns_fields["check_dnssec"],
                        self.dns_fields["warn_www_not_cname"],
                        self.dns_fields["skip_www"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_http_tab(self) -> ft.Tab:
        """Create HTTP configuration tab."""
        self.http_fields["skip"] = ft.Checkbox(
            label="Skip HTTP/HTTPS analysis",
            value=self.config.http.skip,
        )
        self.http_fields["timeout"] = ft.TextField(
            label="HTTP Timeout (seconds)",
            value=str(self.config.http.timeout),
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        self.http_fields["max_redirects"] = ft.TextField(
            label="Maximum Redirects",
            value=str(self.config.http.max_redirects),
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        self.http_fields["user_agent"] = ft.TextField(
            label="Custom User Agent (optional)",
            value=self.config.http.user_agent or "",
            hint_text="Leave empty for default",
        )
        self.http_fields["skip_cdn_detection"] = ft.Checkbox(
            label="Skip CDN detection",
            value=self.config.http.skip_cdn_detection,
        )

        return ft.Tab(
            text="HTTP",
            icon=ft.Icons.HTTP,
            content=ft.Container(
                content=ft.Column(
                    [
                        self.http_fields["skip"],
                        ft.Divider(),
                        self.http_fields["timeout"],
                        self.http_fields["max_redirects"],
                        self.http_fields["user_agent"],
                        self.http_fields["skip_cdn_detection"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_ssl_tab(self) -> ft.Tab:
        """Create SSL configuration tab."""
        self.ssl_fields["skip"] = ft.Checkbox(
            label="Skip SSL/TLS analysis",
            value=self.config.ssl.skip,
        )
        self.ssl_fields["cert_expiry_warning_days"] = ft.TextField(
            label="Certificate Expiry Warning (days)",
            value=str(self.config.ssl.cert_expiry_warning_days),
            keyboard_type=ft.KeyboardType.NUMBER,
            hint_text="Default: 14 (Let's Encrypt auto-renewal)",
        )
        self.ssl_fields["cert_expiry_critical_days"] = ft.TextField(
            label="Certificate Expiry Critical (days)",
            value=str(self.config.ssl.cert_expiry_critical_days),
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        return ft.Tab(
            text="SSL/TLS",
            icon=ft.Icons.LOCK,
            content=ft.Container(
                content=ft.Column(
                    [
                        self.ssl_fields["skip"],
                        ft.Divider(),
                        self.ssl_fields["cert_expiry_warning_days"],
                        self.ssl_fields["cert_expiry_critical_days"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_email_tab(self) -> ft.Tab:
        """Create email security configuration tab."""
        self.email_fields["skip"] = ft.Checkbox(
            label="Skip email security analysis",
            value=self.config.email.skip,
        )
        self.email_fields["dkim_selectors"] = ft.TextField(
            label="DKIM Selectors (comma-separated)",
            value=", ".join(self.config.email.dkim_selectors),
            hint_text="default, google, k1, k2, selector1, selector2",
            multiline=True,
            min_lines=2,
            max_lines=3,
        )
        self.email_fields["check_rbl"] = ft.Checkbox(
            label="Check RBL (Realtime Blacklists)",
            value=self.config.email.check_rbl,
        )
        self.email_fields["rbl_servers"] = ft.TextField(
            label="RBL Servers (comma-separated)",
            value=", ".join(self.config.email.rbl_servers),
            hint_text="zen.spamhaus.org, bl.spamcop.net",
            multiline=True,
            min_lines=2,
            max_lines=3,
        )
        self.email_fields["check_bimi"] = ft.Checkbox(
            label="Check BIMI records",
            value=self.config.email.check_bimi,
        )
        self.email_fields["check_mta_sts"] = ft.Checkbox(
            label="Check MTA-STS",
            value=self.config.email.check_mta_sts,
        )
        self.email_fields["check_tls_rpt"] = ft.Checkbox(
            label="Check TLS-RPT",
            value=self.config.email.check_tls_rpt,
        )

        return ft.Tab(
            text="Email",
            icon=ft.Icons.EMAIL,
            content=ft.Container(
                content=ft.Column(
                    [
                        self.email_fields["skip"],
                        ft.Divider(),
                        self.email_fields["dkim_selectors"],
                        self.email_fields["check_rbl"],
                        self.email_fields["rbl_servers"],
                        ft.Divider(),
                        ft.Text("Advanced Email Security", weight=ft.FontWeight.BOLD),
                        self.email_fields["check_bimi"],
                        self.email_fields["check_mta_sts"],
                        self.email_fields["check_tls_rpt"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_security_headers_tab(self) -> ft.Tab:
        """Create security headers configuration tab."""
        self.security_headers_fields["skip"] = ft.Checkbox(
            label="Skip security headers analysis",
            value=self.config.security_headers.skip,
        )

        headers = [
            ("check_strict_transport_security", "Strict-Transport-Security (HSTS)"),
            ("check_content_security_policy", "Content-Security-Policy (CSP)"),
            ("check_x_frame_options", "X-Frame-Options"),
            ("check_x_content_type_options", "X-Content-Type-Options"),
            ("check_referrer_policy", "Referrer-Policy"),
            ("check_permissions_policy", "Permissions-Policy"),
            ("check_x_xss_protection", "X-XSS-Protection"),
            ("check_content_type", "Content-Type"),
            ("check_cors", "CORS (Access-Control-Allow-Origin)"),
        ]

        controls = [self.security_headers_fields["skip"], ft.Divider()]
        for field_name, label in headers:
            current_value = getattr(self.config.security_headers, field_name)
            checkbox = ft.Checkbox(label=f"Check {label}", value=current_value)
            self.security_headers_fields[field_name] = checkbox
            controls.append(checkbox)

        return ft.Tab(
            text="Security Headers",
            icon=ft.Icons.SHIELD,
            content=ft.Container(
                content=ft.Column(
                    controls,
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_seo_tab(self) -> ft.Tab:
        """Create SEO configuration tab."""
        self.seo_fields["skip"] = ft.Checkbox(
            label="Skip SEO files analysis",
            value=self.config.seo.skip,
        )
        self.seo_fields["check_robots"] = ft.Checkbox(
            label="Check robots.txt",
            value=self.config.seo.check_robots,
        )
        self.seo_fields["check_llms_txt"] = ft.Checkbox(
            label="Check llms.txt (AI crawlers)",
            value=self.config.seo.check_llms_txt,
        )
        self.seo_fields["check_sitemap"] = ft.Checkbox(
            label="Check sitemap.xml",
            value=self.config.seo.check_sitemap,
        )

        return ft.Tab(
            text="SEO",
            icon=ft.Icons.SEARCH,
            content=ft.Container(
                content=ft.Column(
                    [
                        self.seo_fields["skip"],
                        ft.Divider(),
                        self.seo_fields["check_robots"],
                        self.seo_fields["check_llms_txt"],
                        self.seo_fields["check_sitemap"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_favicon_tab(self) -> ft.Tab:
        """Create favicon configuration tab."""
        self.favicon_fields["skip"] = ft.Checkbox(
            label="Skip favicon detection",
            value=self.config.favicon.skip,
        )
        self.favicon_fields["check_html"] = ft.Checkbox(
            label="Parse HTML for favicon links",
            value=self.config.favicon.check_html,
        )
        self.favicon_fields["check_defaults"] = ft.Checkbox(
            label="Check default favicon paths",
            value=self.config.favicon.check_defaults,
        )

        return ft.Tab(
            text="Favicon",
            icon=ft.Icons.IMAGE,
            content=ft.Container(
                content=ft.Column(
                    [
                        self.favicon_fields["skip"],
                        ft.Divider(),
                        self.favicon_fields["check_html"],
                        self.favicon_fields["check_defaults"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_whois_tab(self) -> ft.Tab:
        """Create WHOIS configuration tab."""
        self.whois_fields["skip"] = ft.Checkbox(
            label="Skip WHOIS analysis",
            value=self.config.whois.skip,
        )
        self.whois_fields["expiry_warning_days"] = ft.TextField(
            label="Domain Expiry Warning (days)",
            value=str(self.config.whois.expiry_warning_days),
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        self.whois_fields["expiry_critical_days"] = ft.TextField(
            label="Domain Expiry Critical (days)",
            value=str(self.config.whois.expiry_critical_days),
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        return ft.Tab(
            text="WHOIS",
            icon=ft.Icons.INFO,
            content=ft.Container(
                content=ft.Column(
                    [
                        self.whois_fields["skip"],
                        ft.Divider(),
                        self.whois_fields["expiry_warning_days"],
                        self.whois_fields["expiry_critical_days"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_site_verification_tab(self) -> ft.Tab:
        """Create site verification configuration tab with TOML editor."""
        self.site_verification_fields["skip"] = ft.Checkbox(
            label="Skip site verification analysis",
            value=self.config.site_verification.skip,
        )

        # Generate TOML for site_verification.services
        try:
            import tomli_w

            services_dict = {
                "services": [
                    s.model_dump(mode="json") for s in self.config.site_verification.services
                ]
            }
            toml_content = tomli_w.dumps(services_dict)
        except ImportError:
            toml_content = (
                "# tomli_w not installed - cannot display TOML\n# Install with: pip install tomli-w"
            )
        except Exception as e:
            toml_content = f"# Error generating TOML: {e}"

        self.site_verification_fields["toml_editor"] = ft.TextField(
            label="Site Verification Services (TOML format)",
            value=toml_content,
            multiline=True,
            min_lines=15,
            max_lines=20,
            text_style=ft.TextStyle(font_family="monospace"),
        )

        return ft.Tab(
            text="Site Verification",
            icon=ft.Icons.VERIFIED,
            content=ft.Container(
                content=ft.Column(
                    [
                        self.site_verification_fields["skip"],
                        ft.Divider(),
                        ft.Text(
                            "Edit services configuration in TOML format:",
                            weight=ft.FontWeight.BOLD,
                        ),
                        self.site_verification_fields["toml_editor"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    def _create_output_tab(self) -> ft.Tab:
        """Create output configuration tab."""
        self.output_fields["color"] = ft.Checkbox(
            label="Enable colored output (CLI only)",
            value=self.config.output.color,
        )
        self.output_fields["verbosity"] = ft.Dropdown(
            label="Verbosity Level (CLI only)",
            value=self.config.output.verbosity,
            options=[
                ft.dropdown.Option("quiet"),
                ft.dropdown.Option("normal"),
                ft.dropdown.Option("verbose"),
                ft.dropdown.Option("debug"),
            ],
        )

        return ft.Tab(
            text="Output",
            icon=ft.Icons.OUTPUT,
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.Text("Note: These settings affect CLI output only", italic=True),
                        self.output_fields["color"],
                        self.output_fields["verbosity"],
                    ],
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                ),
                padding=20,
            ),
        )

    # ========== TOML IMPORT/EXPORT ==========

    def _import_toml(self) -> None:
        """Import configuration from TOML file."""

        def on_file_picked(e: ft.FilePickerResultEvent):
            if e.files and len(e.files) > 0:
                file_path = e.files[0].path
                try:
                    imported_config = Config.from_toml_file(Path(file_path))
                    # Update our working config
                    self.config = imported_config
                    # Refresh dialog fields with imported values
                    self._refresh_all_fields()
                    self._show_success(f"Imported config from: {file_path}")
                except Exception as ex:
                    logger.error(f"Failed to import config: {ex}")
                    self._show_error(f"Failed to import config: {ex}")

        file_picker = ft.FilePicker(on_result=on_file_picked)
        self.page.overlay.append(file_picker)
        self.page.update()
        file_picker.pick_files(
            dialog_title="Import TOML Configuration",
            allowed_extensions=["toml"],
            allow_multiple=False,
        )

    def _export_toml(self) -> None:
        """Export configuration to TOML file."""

        def on_file_picked(e: ft.FilePickerResultEvent):
            if e.path:
                try:
                    # Build config from current UI state
                    config = self._validate_and_build_config()
                    if config:
                        config.to_toml_file(Path(e.path))
                        self._show_success(f"Exported config to: {e.path}")
                except Exception as ex:
                    logger.error(f"Failed to export config: {ex}")
                    self._show_error(f"Failed to export config: {ex}")

        file_picker = ft.FilePicker(on_result=on_file_picked)
        self.page.overlay.append(file_picker)
        self.page.update()
        file_picker.save_file(
            dialog_title="Export TOML Configuration",
            file_name="wdt-config.toml",
            allowed_extensions=["toml"],
        )

    def _refresh_all_fields(self) -> None:
        """Refresh all UI fields with current config values."""
        # DNS
        self.dns_fields["skip"].value = self.config.dns.skip
        self.dns_fields["nameservers"].value = ", ".join(self.config.dns.nameservers)
        self.dns_fields["timeout"].value = str(self.config.dns.timeout)
        self.dns_fields["check_dnssec"].value = self.config.dns.check_dnssec
        self.dns_fields["warn_www_not_cname"].value = self.config.dns.warn_www_not_cname
        self.dns_fields["skip_www"].value = self.config.dns.skip_www

        # HTTP
        self.http_fields["skip"].value = self.config.http.skip
        self.http_fields["timeout"].value = str(self.config.http.timeout)
        self.http_fields["max_redirects"].value = str(self.config.http.max_redirects)
        self.http_fields["user_agent"].value = self.config.http.user_agent or ""
        self.http_fields["skip_cdn_detection"].value = self.config.http.skip_cdn_detection

        # SSL
        self.ssl_fields["skip"].value = self.config.ssl.skip
        self.ssl_fields["cert_expiry_warning_days"].value = str(
            self.config.ssl.cert_expiry_warning_days
        )
        self.ssl_fields["cert_expiry_critical_days"].value = str(
            self.config.ssl.cert_expiry_critical_days
        )

        # Email
        self.email_fields["skip"].value = self.config.email.skip
        self.email_fields["dkim_selectors"].value = ", ".join(self.config.email.dkim_selectors)
        self.email_fields["check_rbl"].value = self.config.email.check_rbl
        self.email_fields["rbl_servers"].value = ", ".join(self.config.email.rbl_servers)
        self.email_fields["check_bimi"].value = self.config.email.check_bimi
        self.email_fields["check_mta_sts"].value = self.config.email.check_mta_sts
        self.email_fields["check_tls_rpt"].value = self.config.email.check_tls_rpt

        # Security Headers
        self.security_headers_fields["skip"].value = self.config.security_headers.skip
        for field_name in self.security_headers_fields:
            if field_name != "skip" and hasattr(self.config.security_headers, field_name):
                self.security_headers_fields[field_name].value = getattr(
                    self.config.security_headers, field_name
                )

        # SEO
        self.seo_fields["skip"].value = self.config.seo.skip
        self.seo_fields["check_robots"].value = self.config.seo.check_robots
        self.seo_fields["check_llms_txt"].value = self.config.seo.check_llms_txt
        self.seo_fields["check_sitemap"].value = self.config.seo.check_sitemap

        # Favicon
        self.favicon_fields["skip"].value = self.config.favicon.skip
        self.favicon_fields["check_html"].value = self.config.favicon.check_html
        self.favicon_fields["check_defaults"].value = self.config.favicon.check_defaults

        # WHOIS
        self.whois_fields["skip"].value = self.config.whois.skip
        self.whois_fields["expiry_warning_days"].value = str(self.config.whois.expiry_warning_days)
        self.whois_fields["expiry_critical_days"].value = str(
            self.config.whois.expiry_critical_days
        )

        # Site Verification
        self.site_verification_fields["skip"].value = self.config.site_verification.skip
        try:
            import tomli_w

            services_dict = {
                "services": [
                    s.model_dump(mode="json") for s in self.config.site_verification.services
                ]
            }
            self.site_verification_fields["toml_editor"].value = tomli_w.dumps(services_dict)
        except Exception:
            pass

        # Output
        self.output_fields["color"].value = self.config.output.color
        self.output_fields["verbosity"].value = self.config.output.verbosity

        self.page.update()

    # ========== VALIDATION & SAVE ==========

    def _validate_and_build_config(self) -> Config | None:
        """
        Validate all fields and build Config object.

        Returns:
            Config object if validation passes, None otherwise
        """
        try:
            # Build config dict from UI fields
            config_dict: dict[str, Any] = {}

            # DNS
            nameservers_str = self.dns_fields["nameservers"].value
            nameservers = [ns.strip() for ns in nameservers_str.split(",") if ns.strip()]
            config_dict["dns"] = {
                "skip": self.dns_fields["skip"].value,
                "nameservers": nameservers,
                "timeout": float(self.dns_fields["timeout"].value),
                "check_dnssec": self.dns_fields["check_dnssec"].value,
                "warn_www_not_cname": self.dns_fields["warn_www_not_cname"].value,
                "skip_www": self.dns_fields["skip_www"].value,
            }

            # HTTP
            user_agent = self.http_fields["user_agent"].value.strip()
            config_dict["http"] = {
                "skip": self.http_fields["skip"].value,
                "timeout": float(self.http_fields["timeout"].value),
                "max_redirects": int(self.http_fields["max_redirects"].value),
                "user_agent": user_agent if user_agent else None,
                "skip_cdn_detection": self.http_fields["skip_cdn_detection"].value,
            }

            # SSL
            config_dict["ssl"] = {
                "skip": self.ssl_fields["skip"].value,
                "cert_expiry_warning_days": int(self.ssl_fields["cert_expiry_warning_days"].value),
                "cert_expiry_critical_days": int(
                    self.ssl_fields["cert_expiry_critical_days"].value
                ),
            }

            # Email
            dkim_selectors_str = self.email_fields["dkim_selectors"].value
            dkim_selectors = [s.strip() for s in dkim_selectors_str.split(",") if s.strip()]
            rbl_servers_str = self.email_fields["rbl_servers"].value
            rbl_servers = [s.strip() for s in rbl_servers_str.split(",") if s.strip()]
            config_dict["email"] = {
                "skip": self.email_fields["skip"].value,
                "dkim_selectors": dkim_selectors,
                "check_rbl": self.email_fields["check_rbl"].value,
                "rbl_servers": rbl_servers,
                "check_bimi": self.email_fields["check_bimi"].value,
                "check_mta_sts": self.email_fields["check_mta_sts"].value,
                "check_tls_rpt": self.email_fields["check_tls_rpt"].value,
            }

            # Security Headers
            security_headers_dict = {"skip": self.security_headers_fields["skip"].value}
            for field_name, checkbox in self.security_headers_fields.items():
                if field_name != "skip":
                    security_headers_dict[field_name] = checkbox.value
            config_dict["security_headers"] = security_headers_dict

            # SEO
            config_dict["seo"] = {
                "skip": self.seo_fields["skip"].value,
                "check_robots": self.seo_fields["check_robots"].value,
                "check_llms_txt": self.seo_fields["check_llms_txt"].value,
                "check_sitemap": self.seo_fields["check_sitemap"].value,
            }

            # Favicon
            config_dict["favicon"] = {
                "skip": self.favicon_fields["skip"].value,
                "check_html": self.favicon_fields["check_html"].value,
                "check_defaults": self.favicon_fields["check_defaults"].value,
            }

            # WHOIS
            config_dict["whois"] = {
                "skip": self.whois_fields["skip"].value,
                "expiry_warning_days": int(self.whois_fields["expiry_warning_days"].value),
                "expiry_critical_days": int(self.whois_fields["expiry_critical_days"].value),
            }

            # Site Verification - parse TOML from editor
            site_verification_dict = {"skip": self.site_verification_fields["skip"].value}
            try:
                import tomllib

                toml_content = self.site_verification_fields["toml_editor"].value
                parsed = tomllib.loads(toml_content)
                if "services" in parsed:
                    site_verification_dict["services"] = parsed["services"]
                else:
                    # Keep existing services if TOML doesn't have services key
                    site_verification_dict["services"] = [
                        s.model_dump(mode="json") for s in self.config.site_verification.services
                    ]
            except Exception as e:
                logger.warning(f"Failed to parse site verification TOML: {e}")
                # Keep existing services
                site_verification_dict["services"] = [
                    s.model_dump(mode="json") for s in self.config.site_verification.services
                ]
            config_dict["site_verification"] = site_verification_dict

            # Output
            config_dict["output"] = {
                "color": self.output_fields["color"].value,
                "verbosity": self.output_fields["verbosity"].value,
            }

            # Create and validate Config
            return Config(**config_dict)

        except (ValueError, KeyError) as e:
            logger.error(f"Config validation failed: {e}")
            self._show_error(f"Invalid configuration: {e}")
            return None

    def _show_error(self, message: str) -> None:
        """Show error snackbar."""
        snackbar = ft.SnackBar(
            content=ft.Text(message, color="white"),
            bgcolor="red",
        )
        self.page.overlay.append(snackbar)
        snackbar.open = True
        self.page.update()

    def _show_success(self, message: str) -> None:
        """Show success snackbar."""
        snackbar = ft.SnackBar(
            content=ft.Text(message, color="white"),
            bgcolor="green",
        )
        self.page.overlay.append(snackbar)
        snackbar.open = True
        self.page.update()

    def _save_and_close(self) -> None:
        """Validate, save, and close dialog."""
        config = self._validate_and_build_config()
        if config:
            self.on_save(config)
            self._close_dialog()

    def _close_dialog(self) -> None:
        """Close the dialog."""
        self.dialog.open = False
        self.page.update()

    def show(self) -> None:
        """Show the config editor dialog."""
        self.page.overlay.append(self.dialog)
        self.dialog.open = True
        self.page.update()
