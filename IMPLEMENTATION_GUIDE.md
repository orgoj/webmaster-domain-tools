# Multi-Profile Configuration Implementation Guide

## Architecture Diagram: Current vs Proposed

### Current Architecture
```
TOML Files (5 layers)
        ↓
ConfigManager._merge_dicts()
        ↓
Merged Dict: {
  "global": {...},
  "dns": {...},
  "email": {...}
}
        ↓
Pydantic Validation
        ↓
AnalyzerConfig instances
        ↓
Analyzer.analyze(config)
```

### Proposed Architecture with Profiles
```
TOML Files (5 layers, now with nested profiles)
        ↓
ConfigManager._merge_dicts() [NO CHANGES NEEDED]
        ↓
Merged Dict: {
  "dns": {
    "enabled": true,
    "active_profile": "default",
    "profiles": {
      "default": {"nameservers": [...]},
      "aggressive": {"nameservers": [...]}
    }
  }
}
        ↓
Pydantic Validation [DNS uses nested BaseModel]
        ↓
DNSConfig with get_active_profile()
        ↓
Analyzer.analyze(config)
        └─→ config.get_active_profile() for actual values
```

---

## Complete Working Example: DNS Analyzer with Profiles

### 1. TOML Configuration

```toml
# default_config.toml

[dns]
enabled = true
timeout = 5.0
active_profile = "default"

# Profile definitions (nested structure)
[dns.profiles.default]
nameservers = ["8.8.8.8", "8.8.4.4"]
check_dnssec = true
warn_www_not_cname = false
skip_www = false

[dns.profiles.aggressive]
nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.123"]
check_dnssec = true
warn_www_not_cname = false
skip_www = false
timeout = 10.0

[dns.profiles.minimal]
nameservers = ["8.8.8.8"]
check_dnssec = false
warn_www_not_cname = false
skip_www = false
timeout = 3.0
```

### 2. Updated Pydantic Model

```python
# dns_analyzer.py

from dataclasses import dataclass, field
from pydantic import BaseModel, Field, ConfigDict
from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor

# ============================================================================
# Profile Data Model (Nested Pydantic)
# ============================================================================

class DNSProfileData(BaseModel):
    """DNS-specific settings within a profile."""

    model_config = ConfigDict(extra="ignore")

    nameservers: list[str] | None = Field(
        default=None,
        description="Custom nameservers to use for queries"
    )
    check_dnssec: bool = Field(
        default=True,
        description="Check DNSSEC validation status"
    )
    warn_www_not_cname: bool = Field(
        default=False,
        description="Warn if www subdomain uses A/AAAA instead of CNAME"
    )
    skip_www: bool = Field(
        default=False,
        description="Skip checking www subdomain"
    )

# ============================================================================
# Main Config with Profile Support
# ============================================================================

class DNSConfig(AnalyzerConfig):
    """DNS analyzer configuration with profile support."""

    active_profile: str = Field(
        default="default",
        description="Currently active profile name"
    )

    profiles: dict[str, DNSProfileData] = Field(
        default_factory=lambda: {
            "default": DNSProfileData(
                nameservers=["8.8.8.8", "8.8.4.4"],
                check_dnssec=True
            )
        },
        description="Named DNS profiles"
    )

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def get_active_profile(self) -> DNSProfileData:
        """
        Get the currently active profile data.

        Returns:
            DNSProfileData for active profile, or default if not found
        """
        if self.active_profile not in self.profiles:
            logger.warning(
                f"Active profile '{self.active_profile}' not found, "
                f"using 'default'"
            )
            return self.profiles.get("default", DNSProfileData())

        return self.profiles[self.active_profile]

    def set_active_profile(self, profile_name: str) -> None:
        """
        Set the active profile.

        Raises:
            ValueError: If profile doesn't exist
        """
        if profile_name not in self.profiles:
            raise ValueError(
                f"Profile '{profile_name}' not found. "
                f"Available: {list(self.profiles.keys())}"
            )
        self.active_profile = profile_name

    def get_profile_names(self) -> list[str]:
        """Get list of available profile names."""
        return list(self.profiles.keys())

# ============================================================================
# Analyzer Implementation
# ============================================================================

@registry.register
class DNSAnalyzer:
    """DNS analyzer with profile support."""

    analyzer_id = "dns"
    name = "DNS Analysis"
    description = "Comprehensive DNS record analysis with profile support"
    category = "general"
    icon = "globe"
    config_class = DNSConfig
    depends_on = []

    def analyze(self, domain: str, config: DNSConfig) -> DNSAnalysisResult:
        """
        Perform DNS analysis using active profile.

        Args:
            domain: Domain to analyze
            config: DNS configuration with profiles

        Returns:
            Analysis result
        """
        logger.info(f"DNS analysis for {domain} using profile '{config.active_profile}'")

        # Get active profile data
        profile = config.get_active_profile()

        # Use profile values with fallback to config defaults
        nameservers = profile.nameservers or ["8.8.8.8"]
        check_dnssec = profile.check_dnssec
        timeout = config.timeout  # Global timeout

        result = DNSAnalysisResult(domain=domain)

        try:
            # Create resolver with profile's nameservers
            resolver = create_resolver(nameservers, timeout)

            # ... rest of DNS analysis logic using profile values

        except Exception as e:
            result.errors.append(f"DNS analysis failed: {e}")

        return result
```

---

## Example: Email Security with Multiple Profiles

```toml
# For email security analysis with different focuses

[email]
enabled = true
timeout = 5.0
active_profile = "default"

[email.profiles.default]
dkim_selectors = ["default", "google", "k1", "selector1", "selector2"]
check_bimi = true
check_mta_sts = true
check_tls_rpt = true

[email.profiles.spf-focused]
# Minimal DKIM checking for quick SPF validation
dkim_selectors = ["default"]
check_bimi = false
check_mta_sts = false
check_tls_rpt = false

[email.profiles.complete]
# Maximum validation - more DKIM selectors
dkim_selectors = [
    "default", "google", "k1", "k2", "k3",
    "selector1", "selector2", "selector3",
    "dkim", "mail", "s1", "s2",
    "brevo", "sendgrid", "mailgun",
    "amazonses", "postmark"
]
check_bimi = true
check_mta_sts = true
check_tls_rpt = true

[email.profiles.enterprise]
# Enterprise focus - DMARC and authentication only
dkim_selectors = ["default", "google", "selector1"]
check_bimi = true
check_mta_sts = true
check_tls_rpt = true
# Future: additional validation fields
```

**Pydantic model:**

```python
class EmailProfileData(BaseModel):
    """Email security profile settings."""

    model_config = ConfigDict(extra="ignore")

    dkim_selectors: list[str] = Field(
        default_factory=list,
        description="DKIM selectors to check"
    )
    check_bimi: bool = Field(default=True)
    check_mta_sts: bool = Field(default=True)
    check_tls_rpt: bool = Field(default=True)

    @field_validator('dkim_selectors')
    @classmethod
    def validate_selectors(cls, v: list[str]) -> list[str]:
        """Ensure selectors are non-empty strings."""
        if not v:
            return ["default"]
        return [s.strip() for s in v if s.strip()]

class EmailConfig(AnalyzerConfig):
    """Email security analyzer with profiles."""

    active_profile: str = Field(default="default")

    profiles: dict[str, EmailProfileData] = Field(
        default_factory=lambda: {
            "default": EmailProfileData(
                dkim_selectors=DEFAULT_DKIM_SELECTORS.copy()
            )
        }
    )

    def get_active_profile(self) -> EmailProfileData:
        """Get active profile, fallback to default."""
        return self.profiles.get(
            self.active_profile,
            self.profiles.get("default", EmailProfileData())
        )
```

---

## CLI Integration Example

### Option 1: Global Profile Selection

```bash
# Use DNS aggressive profile
wdt analyze --profile aggressive example.com

# Use email spf-focused profile
wdt analyze --profile spf-focused example.com

# Show available profiles
wdt list-analyzers --show-profiles
```

**Implementation in cli.py:**

```python
@app.command()
def analyze(
    domain: str,
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help="Configuration profile (default, aggressive, etc.)"
        )
    ] = None,
    skip: Annotated[list[str] | None, typer.Option()] = None,
    **kwargs
) -> None:
    """Analyze domain using specified profile."""

    config_manager = ConfigManager()
    config_manager.load_from_files()

    # Set profile globally if specified
    if profile:
        for analyzer_id, config in config_manager.analyzer_configs.items():
            if hasattr(config, 'set_active_profile'):
                try:
                    config.set_active_profile(profile)
                except ValueError as e:
                    console.print(f"[red]Error:[/red] {e}")
                    raise typer.Exit(1)

    # ... rest of analyze implementation
```

### Option 2: Per-Analyzer Profile Selection

```bash
# Different profiles for different analyzers
wdt analyze \
    --profile-dns aggressive \
    --profile-email complete \
    example.com

# Still use default for unlisted analyzers
wdt analyze --profile-email spf-focused example.com
```

---

## Profile Management Command (Future)

```bash
# List available profiles for an analyzer
wdt profile list dns
# Output:
#   default     (Active)
#   aggressive
#   minimal

# Show profile details
wdt profile describe dns aggressive
# Output:
#   [dns-aggressive]
#   Nameservers: 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9, 208.67.222.123
#   Check DNSSEC: yes
#   Timeout: 10.0s

# Create custom profile
wdt profile create dns custom --from aggressive
# Edits ~/.config/webmaster-domain-tool/config.toml

# Switch active profile
wdt profile set dns aggressive
```

**Implementation outline:**

```python
@app.command()
def profile(
    action: Annotated[
        str,
        typer.Argument(help="list, describe, create, set, delete")
    ],
    analyzer: Annotated[
        str | None,
        typer.Argument(help="Analyzer ID (dns, email, etc.)")
    ] = None,
    profile_name: Annotated[
        str | None,
        typer.Argument(help="Profile name")
    ] = None,
    **kwargs
) -> None:
    """Manage configuration profiles."""

    if action == "list":
        config = config_manager.get_analyzer_config(analyzer)
        for name in config.get_profile_names():
            is_active = " (Active)" if name == config.active_profile else ""
            console.print(f"  {name}{is_active}")

    elif action == "describe":
        config = config_manager.get_analyzer_config(analyzer)
        profile = config.profiles[profile_name]
        # Pretty-print profile settings
        console.print(profile.model_dump())

    # ... etc
```

---

## Configuration Validation Example

```python
# email_security.py with profile validation

from pydantic import field_validator

class EmailProfileData(BaseModel):
    """Email security profile with validation."""

    dkim_selectors: list[str] = Field(default_factory=list)
    check_bimi: bool = True
    check_mta_sts: bool = True
    check_tls_rpt: bool = True

    # Add validation logic
    @field_validator('dkim_selectors')
    @classmethod
    def validate_selectors(cls, v: list[str]) -> list[str]:
        """
        Validate DKIM selectors.

        Rules:
        - Non-empty list
        - Each selector must be DNS-safe
        - Max 20 selectors (performance)
        """
        if not v:
            logger.warning("Empty DKIM selectors list, using default")
            return ["default"]

        if len(v) > 20:
            raise ValueError(f"Too many selectors: {len(v)} (max 20)")

        valid = []
        for selector in v:
            selector = selector.strip()
            if not selector:
                continue

            # Validate DNS selector format (alphanumeric + hyphen)
            if not re.match(r'^[a-z0-9_-]+$', selector, re.IGNORECASE):
                raise ValueError(f"Invalid selector format: '{selector}'")

            valid.append(selector)

        return valid if valid else ["default"]
```

---

## Backward Compatibility & Migration

```python
# dns_analyzer.py with backward compatibility

class DNSConfig(AnalyzerConfig):
    """DNS config with migration support."""

    # Old flat fields (deprecated)
    nameservers: list[str] | None = Field(default=None, deprecated=True)
    check_dnssec: bool = Field(default=True, deprecated=True)

    # New profile system
    active_profile: str = "default"
    profiles: dict[str, DNSProfileData] = Field(default_factory=dict)

    @model_validator(mode='after')
    def migrate_old_to_new(self):
        """Auto-migrate old flat config to profile structure."""

        # If user has old-style flat config, migrate to default profile
        if not self.profiles and (
            self.nameservers is not None or not self.check_dnssec
        ):
            logger.warning(
                "Old flat DNS config detected. "
                "Please update to profile format in your TOML file. "
                "Auto-migrating to 'default' profile for now."
            )

            self.profiles["default"] = DNSProfileData(
                nameservers=self.nameservers,
                check_dnssec=self.check_dnssec
            )

        # Ensure at least default profile exists
        if "default" not in self.profiles:
            self.profiles["default"] = DNSProfileData()

        return self
```

---

## Testing Multi-Profile Configuration

```python
# tests/test_dns_profiles.py

def test_dns_default_profile():
    """Test default DNS profile."""
    config_data = {
        "enabled": True,
        "active_profile": "default",
        "profiles": {
            "default": {
                "nameservers": ["8.8.8.8"],
                "check_dnssec": True
            }
        }
    }
    config = DNSConfig(**config_data)
    profile = config.get_active_profile()

    assert profile.nameservers == ["8.8.8.8"]
    assert profile.check_dnssec is True


def test_dns_aggressive_profile():
    """Test aggressive DNS profile."""
    config_data = {
        "active_profile": "aggressive",
        "profiles": {
            "aggressive": {
                "nameservers": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
                "check_dnssec": True
            }
        }
    }
    config = DNSConfig(**config_data)
    config.set_active_profile("aggressive")
    profile = config.get_active_profile()

    assert len(profile.nameservers) == 3


def test_missing_profile_falls_back_to_default():
    """Test fallback when profile doesn't exist."""
    config_data = {
        "active_profile": "nonexistent",
        "profiles": {
            "default": {"nameservers": ["8.8.8.8"]}
        }
    }
    config = DNSConfig(**config_data)
    profile = config.get_active_profile()

    assert profile.nameservers == ["8.8.8.8"]


def test_profile_switching():
    """Test switching between profiles at runtime."""
    config = DNSConfig(
        active_profile="default",
        profiles={
            "default": DNSProfileData(nameservers=["8.8.8.8"]),
            "aggressive": DNSProfileData(nameservers=["1.1.1.1"])
        }
    )

    profile1 = config.get_active_profile()
    assert profile1.nameservers == ["8.8.8.8"]

    config.set_active_profile("aggressive")
    profile2 = config.get_active_profile()
    assert profile2.nameservers == ["1.1.1.1"]
```

---

## Rollout Plan

### Phase 1: Foundation (v1.5.0)
- Add profile support to 2-3 analyzers (DNS, Email)
- Support old flat format with migration
- Document in README
- No CLI changes yet

### Phase 2: Expansion (v1.6.0)
- Add profiles to remaining analyzers
- Add CLI `--profile` parameter
- Add `profile list` command
- Update default_config.toml with example profiles

### Phase 3: Maturity (v2.0.0)
- Drop deprecated flat format
- Add `profile manage` commands (create, edit, delete)
- Profile inheritance/composition
- Web UI profile selector

### Phase 4: Advanced Features (v2.1.0+)
- Profile templates for common use cases
- Profile composition/inheritance
- Constraint expressions
- Dynamic profile generation
