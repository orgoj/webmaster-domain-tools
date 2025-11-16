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


class HTTPConfig(BaseModel):
    """HTTP/HTTPS analysis configuration."""

    timeout: float = Field(default=10.0, description="HTTP request timeout in seconds")
    max_redirects: int = Field(default=10, description="Maximum number of redirects to follow")
    user_agent: str | None = Field(
        default=None,
        description="Custom user agent string",
    )


class SSLConfig(BaseModel):
    """SSL/TLS analysis configuration."""

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


class EmailConfig(BaseModel):
    """Email security configuration."""

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


class OutputConfig(BaseModel):
    """Output configuration."""

    color: bool = Field(default=True, description="Enable colored output")
    verbosity: str = Field(
        default="normal",
        description="Verbosity level: quiet, normal, verbose, debug",
    )


class ServiceVerificationConfig(BaseModel):
    """Configuration for a single service verification (Google, Facebook, Pinterest, etc)."""

    name: str = Field(
        description="Service name (e.g., 'Google', 'Facebook', 'Pinterest')"
    )
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


class SiteVerificationConfig(BaseModel):
    """Site verification configuration for multiple services."""

    services: list[ServiceVerificationConfig] = Field(
        default_factory=list,
        description="List of verification services to check",
    )


class AnalysisConfig(BaseModel):
    """Analysis options configuration."""

    skip_dns: bool = Field(default=False, description="Skip DNS analysis")
    skip_http: bool = Field(default=False, description="Skip HTTP/HTTPS analysis")
    skip_ssl: bool = Field(default=False, description="Skip SSL/TLS analysis")
    skip_email: bool = Field(default=False, description="Skip email security analysis")
    skip_headers: bool = Field(default=False, description="Skip security headers analysis")
    skip_site_verification: bool = Field(
        default=False, description="Skip site verification analysis"
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
    site_verification: SiteVerificationConfig = Field(default_factory=SiteVerificationConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)


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
        # Create minimal config
        config_path.write_text(
            """# Webmaster Domain Tool Configuration

[dns]
# DNS nameservers to use (default: Google DNS, Cloudflare DNS)
nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
timeout = 5.0
check_dnssec = true
# Warn if www subdomain is not a CNAME record (best practice)
warn_www_not_cname = false

[http]
timeout = 10.0
max_redirects = 10
# user_agent = "Custom User Agent"

[ssl]
# Certificate expiry warning threshold (days before expiry)
cert_expiry_warning_days = 14
cert_expiry_critical_days = 7

[security_headers]
# Enable or disable individual security header checks
check_strict_transport_security = true
check_content_security_policy = true
check_x_frame_options = true
check_x_content_type_options = true
check_referrer_policy = true
check_permissions_policy = true
check_x_xss_protection = true
check_content_type = true

[email]
dkim_selectors = ["default", "google", "k1", "k2", "selector1", "selector2"]
check_rbl = false
rbl_servers = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net"]

[google]
# Google Site Verification IDs to check (empty by default)
# Example: verification_ids = ["abcd1234efgh5678", "ijkl9012mnop3456"]
verification_ids = []

[output]
color = true
verbosity = "normal"  # quiet, normal, verbose, debug

[analysis]
skip_dns = false
skip_http = false
skip_ssl = false
skip_email = false
skip_headers = false
skip_google = false
"""
        )
        logger.info(f"Created default config file: {config_path}")

    return config_path
