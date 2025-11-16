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


class HTTPConfig(BaseModel):
    """HTTP/HTTPS analysis configuration."""

    timeout: float = Field(default=10.0, description="HTTP request timeout in seconds")
    max_redirects: int = Field(default=10, description="Maximum number of redirects to follow")
    user_agent: str | None = Field(
        default=None,
        description="Custom user agent string",
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
        default=True,
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


class AnalysisConfig(BaseModel):
    """Analysis options configuration."""

    skip_dns: bool = Field(default=False, description="Skip DNS analysis")
    skip_http: bool = Field(default=False, description="Skip HTTP/HTTPS analysis")
    skip_ssl: bool = Field(default=False, description="Skip SSL/TLS analysis")
    skip_email: bool = Field(default=False, description="Skip email security analysis")
    skip_headers: bool = Field(default=False, description="Skip security headers analysis")


class Config(BaseSettings):
    """Main configuration for webmaster-domain-tool."""

    model_config = SettingsConfigDict(
        extra="ignore",
    )

    dns: DNSConfig = Field(default_factory=DNSConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
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

[http]
timeout = 10.0
max_redirects = 10
# user_agent = "Custom User Agent"

[email]
dkim_selectors = ["default", "google", "k1", "k2", "selector1", "selector2"]
check_rbl = true
rbl_servers = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net"]

[output]
color = true
verbosity = "normal"  # quiet, normal, verbose, debug

[analysis]
skip_dns = false
skip_http = false
skip_ssl = false
skip_email = false
skip_headers = false
"""
        )
        logger.info(f"Created default config file: {config_path}")

    return config_path
