"""Configuration management for webmaster-domain-tool."""

import logging
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class DNSConfig(BaseModel):
    """DNS analysis configuration."""

    skip: bool = Field(default=False, description="Skip DNS analysis")
    nameservers: list[str] = Field(
        default_factory=lambda: ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
        description="DNS nameservers to use",
    )
    timeout: float = Field(default=5.0, description="DNS query timeout in seconds")
    check_dnssec: bool = Field(default=True, description="Check DNSSEC validation")
    warn_www_not_cname: bool = Field(
        default=False,
        description="Warn if www subdomain is not a CNAME record",
    )
    skip_www: bool = Field(
        default=False,
        description="Skip testing www subdomain (useful for subdomains or domains without www)",
    )


class HTTPConfig(BaseModel):
    """HTTP/HTTPS analysis configuration."""

    skip: bool = Field(default=False, description="Skip HTTP/HTTPS analysis")
    timeout: float = Field(default=10.0, description="HTTP request timeout in seconds")
    max_redirects: int = Field(default=10, description="Maximum number of redirects to follow")
    user_agent: str | None = Field(
        default=None,
        description="Custom user agent string",
    )
    skip_cdn_detection: bool = Field(default=False, description="Skip CDN detection")


class SSLConfig(BaseModel):
    """SSL/TLS analysis configuration."""

    skip: bool = Field(default=False, description="Skip SSL/TLS analysis")
    cert_expiry_warning_days: int = Field(
        default=14,
        description="Number of days before certificate expiry to show warning (default: 14 for Let's Encrypt auto-renewal)",
    )
    cert_expiry_critical_days: int = Field(
        default=7,
        description="Number of days before certificate expiry to show critical error",
    )


class SecurityHeadersConfig(BaseModel):
    """Security headers check configuration."""

    skip: bool = Field(default=False, description="Skip security headers analysis")
    check_strict_transport_security: bool = Field(
        default=True,
        description="Check Strict-Transport-Security (HSTS) header",
    )
    check_content_security_policy: bool = Field(
        default=True,
        description="Check Content-Security-Policy (CSP) header",
    )
    check_x_frame_options: bool = Field(
        default=True,
        description="Check X-Frame-Options header",
    )
    check_x_content_type_options: bool = Field(
        default=True,
        description="Check X-Content-Type-Options header",
    )
    check_referrer_policy: bool = Field(
        default=True,
        description="Check Referrer-Policy header",
    )
    check_permissions_policy: bool = Field(
        default=True,
        description="Check Permissions-Policy header",
    )
    check_x_xss_protection: bool = Field(
        default=True,
        description="Check X-XSS-Protection header",
    )
    check_content_type: bool = Field(
        default=True,
        description="Check Content-Type header",
    )
    check_cors: bool = Field(
        default=True,
        description="Check CORS headers (Access-Control-Allow-Origin)",
    )


class SEOConfig(BaseModel):
    """SEO files configuration."""

    skip: bool = Field(default=False, description="Skip SEO files analysis")
    check_robots: bool = Field(default=True, description="Check robots.txt")
    check_llms_txt: bool = Field(default=True, description="Check /llms.txt for AI crawlers")
    check_sitemap: bool = Field(default=True, description="Check sitemap.xml")


class FaviconConfig(BaseModel):
    """Favicon detection configuration."""

    skip: bool = Field(default=False, description="Skip favicon detection")
    check_html: bool = Field(default=True, description="Parse HTML for favicon links")
    check_defaults: bool = Field(default=True, description="Check default favicon paths")


class EmailConfig(BaseModel):
    """Email security configuration."""

    skip: bool = Field(default=False, description="Skip email security analysis")
    dkim_selectors: list[str] = Field(
        default_factory=lambda: [
            "default",
            "google",
            "k1",
            "k2",
            "selector1",
            "selector2",
            "dkim",
            "mail",
            "s1",
            "s2",
        ],
        description="DKIM selectors to check",
    )
    check_rbl: bool = Field(
        default=False,
        description="Check realtime blacklists (RBL) for mail servers",
    )
    rbl_servers: list[str] = Field(
        default_factory=lambda: [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "b.barracudacentral.org",
            "dnsbl.sorbs.net",
        ],
        description="RBL servers to check",
    )
    check_bimi: bool = Field(default=True, description="Check BIMI records")
    check_mta_sts: bool = Field(default=True, description="Check MTA-STS")
    check_tls_rpt: bool = Field(default=True, description="Check TLS-RPT")


class WhoisConfig(BaseModel):
    """WHOIS registration information configuration."""

    skip: bool = Field(default=False, description="Skip WHOIS analysis")
    expiry_warning_days: int = Field(
        default=30,
        description="Number of days before domain expiry to show warning",
    )
    expiry_critical_days: int = Field(
        default=7,
        description="Number of days before domain expiry to show critical error",
    )


class OutputConfig(BaseModel):
    """Output configuration."""

    color: bool = Field(default=True, description="Enable colored output")
    verbosity: str = Field(
        default="normal",
        description="Verbosity level: quiet, normal, verbose, debug",
    )


class ServiceVerificationConfig(BaseModel):
    """Configuration for a single service verification (Google, Facebook, Pinterest, etc)."""

    name: str = Field(description="Service name (e.g., 'Google', 'Facebook', 'Pinterest')")
    ids: list[str] = Field(
        default_factory=list,
        description="Verification IDs to check for this service",
    )
    dns_pattern: str | None = Field(
        default=None,
        description="DNS TXT record pattern with {id} placeholder (e.g., 'google-site-verification={id}')",
    )
    file_pattern: str | None = Field(
        default=None,
        description="File URL path pattern with {id} placeholder (e.g., 'google{id}.html')",
    )
    meta_name: str | None = Field(
        default=None,
        description="Meta tag name attribute value (e.g., 'google-site-verification')",
    )
    auto_detect: bool = Field(
        default=True,
        description="Auto-detect verification IDs from DNS and HTML even if not in ids list",
    )


def _get_default_verification_services() -> list[ServiceVerificationConfig]:
    """Get default list of predefined verification services."""
    return [
        ServiceVerificationConfig(
            name="Google",
            ids=[],
            dns_pattern="google-site-verification={id}",
            file_pattern="google{id}.html",
            meta_name="google-site-verification",
            auto_detect=True,
        ),
        ServiceVerificationConfig(
            name="Facebook",
            ids=[],
            dns_pattern="facebook-domain-verification={id}",
            meta_name="facebook-domain-verification",
            auto_detect=True,
        ),
        ServiceVerificationConfig(
            name="Pinterest",
            ids=[],
            meta_name="p:domain_verify",
            auto_detect=True,
        ),
        ServiceVerificationConfig(
            name="Bing",
            ids=[],
            file_pattern="BingSiteAuth.xml",
            meta_name="msvalidate.01",
            auto_detect=True,
        ),
        ServiceVerificationConfig(
            name="Yandex",
            ids=[],
            file_pattern="yandex_{id}.html",
            meta_name="yandex-verification",
            auto_detect=True,
        ),
    ]


class SiteVerificationConfig(BaseModel):
    """Site verification configuration for multiple services."""

    skip: bool = Field(default=False, description="Skip site verification analysis")
    services: list[ServiceVerificationConfig] = Field(
        default_factory=_get_default_verification_services,
        description="List of verification services to check",
    )


class Config(BaseSettings):
    """Main configuration for webmaster-domain-tool."""

    model_config = SettingsConfigDict(
        extra="ignore",
    )

    dns: DNSConfig = Field(default_factory=DNSConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    ssl: SSLConfig = Field(default_factory=SSLConfig)
    security_headers: SecurityHeadersConfig = Field(default_factory=SecurityHeadersConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    whois: WhoisConfig = Field(default_factory=WhoisConfig)
    site_verification: SiteVerificationConfig = Field(default_factory=SiteVerificationConfig)
    seo: SEOConfig = Field(default_factory=SEOConfig)
    favicon: FaviconConfig = Field(default_factory=FaviconConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    def to_toml(self) -> str:
        """
        Export configuration to TOML string.

        Returns:
            TOML formatted configuration string
        """
        try:
            import tomli_w
        except ImportError:
            raise ImportError(
                "tomli_w is required for TOML export. Install with: pip install tomli-w"
            )

        config_dict = self.model_dump(mode="json")
        return tomli_w.dumps(config_dict)

    def to_toml_file(self, path: Path) -> None:
        """
        Export configuration to TOML file.

        Args:
            path: Path to save the TOML file
        """
        try:
            import tomli_w
        except ImportError:
            raise ImportError(
                "tomli_w is required for TOML export. Install with: pip install tomli-w"
            )

        config_dict = self.model_dump(mode="json")
        with open(path, "wb") as f:
            tomli_w.dump(config_dict, f)
        logger.info(f"Exported config to: {path}")

    @classmethod
    def from_toml_string(cls, toml_string: str) -> "Config":
        """
        Import configuration from TOML string.

        Args:
            toml_string: TOML formatted configuration string

        Returns:
            Config object
        """
        config_data = tomllib.loads(toml_string)
        return cls(**config_data)

    @classmethod
    def from_toml_file(cls, path: Path) -> "Config":
        """
        Import configuration from TOML file.

        Args:
            path: Path to the TOML file

        Returns:
            Config object
        """
        with open(path, "rb") as f:
            config_data = tomllib.load(f)
        logger.info(f"Imported config from: {path}")
        return cls(**config_data)


def get_config_paths() -> list[Path]:
    """
    Get configuration file paths in order of precedence (lowest to highest).

    Returns:
        List of config file paths
    """
    paths = []

    # 1. Package default config
    package_dir = Path(__file__).parent
    default_config = package_dir / "default_config.toml"
    if default_config.exists():
        paths.append(default_config)

    # 2. System-wide config
    system_config = Path("/etc/webmaster-domain-tool/config.toml")
    if system_config.exists():
        paths.append(system_config)

    # 3. User config in XDG_CONFIG_HOME or ~/.config
    xdg_config_home = Path.home() / ".config"
    user_config = xdg_config_home / "webmaster-domain-tool" / "config.toml"
    if user_config.exists():
        paths.append(user_config)

    # 4. User config in home directory (legacy)
    home_config = Path.home() / ".webmaster-domain-tool.toml"
    if home_config.exists():
        paths.append(home_config)

    # 5. Current directory config
    current_config = Path.cwd() / ".webmaster-domain-tool.toml"
    if current_config.exists():
        paths.append(current_config)

    return paths


def load_config() -> Config:
    """
    Load configuration from files.

    Configuration is loaded in this order (later files override earlier):
    1. Package default config
    2. System-wide config (/etc/webmaster-domain-tool/config.toml)
    3. User config (~/.config/webmaster-domain-tool/config.toml)
    4. User home config (~/.webmaster-domain-tool.toml)
    5. Current directory config (.webmaster-domain-tool.toml)

    Returns:
        Merged configuration
    """
    config_paths = get_config_paths()

    # Start with default config
    config_data: dict[str, Any] = {}

    # Merge all config files
    for config_path in config_paths:
        try:
            with open(config_path, "rb") as f:
                file_data = tomllib.load(f)
                config_data = _merge_configs(config_data, file_data)
                logger.debug(f"Loaded config from {config_path}")
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")

    # Create Config object
    return Config(**config_data)


def _merge_configs(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively merge two configuration dictionaries.

    Args:
        base: Base configuration
        override: Configuration to override base with

    Returns:
        Merged configuration
    """
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_configs(result[key], value)
        else:
            result[key] = value

    return result


def create_default_user_config() -> Path:
    """
    Create default user configuration file.

    Returns:
        Path to created config file
    """
    config_dir = Path.home() / ".config" / "webmaster-domain-tool"
    config_dir.mkdir(parents=True, exist_ok=True)

    config_path = config_dir / "config.toml"

    if config_path.exists():
        logger.info(f"Config file already exists: {config_path}")
        return config_path

    # Get default config content
    package_dir = Path(__file__).parent
    default_config_path = package_dir / "default_config.toml"

    if default_config_path.exists():
        import shutil

        shutil.copy(default_config_path, config_path)
        logger.info(f"Created config file: {config_path}")
    else:
        # Fallback: create from Config defaults
        default_config = Config()
        default_config.to_toml_file(config_path)
        logger.info(f"Created default config file: {config_path}")

    return config_path
