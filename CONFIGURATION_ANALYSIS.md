# Configuration System Analysis & Multi-Profile Design

## Current Configuration System Architecture

### 1. Multi-Layer Configuration Merging

**ConfigManager** (`core/config_manager.py`) implements 5-layer configuration with recursive dict merging:

```
Layer 1 (Highest): ./.webmaster-domain-tool.toml (local)
Layer 2:           ~/.webmaster-domain-tool.toml (home)
Layer 3:           ~/.config/webmaster-domain-tool/config.toml (user)
Layer 4:           /etc/webmaster-domain-tool/config.toml (system)
Layer 5 (Lowest):  src/webmaster_domain_tool/default_config.toml (package default)
```

**Key Method: `_merge_dicts()`** (recursive):
- Recursively merges dictionaries from lower to higher precedence
- Lists are REPLACED, not merged
- Dictionaries are MERGED deeply
- Later values override earlier ones

```python
@staticmethod
def _merge_dicts(base: dict, override: dict) -> dict:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = ConfigManager._merge_dicts(result[key], value)
        else:
            result[key] = value  # Lists are replaced, not merged
    return result
```

**Current Structure (TOML)**:
```toml
[global]
verbosity = "normal"
color = true

[dns]
enabled = true
timeout = 5.0
nameservers = ["8.8.8.8"]
check_dnssec = true

[email]
dkim_selectors = ["default", "google", "k1"]
check_bimi = true
```

### 2. Per-Analyzer Configuration Pattern

Each analyzer has its own **Pydantic config class** extending `AnalyzerConfig`:

```python
# AnalyzerConfig base (protocol.py)
class AnalyzerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    timeout: float = 10.0

# Example: DNSConfig (dns_analyzer.py)
class DNSConfig(AnalyzerConfig):
    nameservers: list[str] | None = None
    check_dnssec: bool = Field(default=True)
    warn_www_not_cname: bool = Field(default=False)
    skip_www: bool = Field(default=False)

# Example: EmailConfig (email_security.py)
class EmailConfig(AnalyzerConfig):
    dkim_selectors: list[str] = Field(
        default_factory=lambda: DEFAULT_DKIM_SELECTORS.copy(),
        description="List of DKIM selectors to check"
    )
    check_bimi: bool = Field(default=True)
```

### 3. Configuration Loading Flow

1. **ConfigManager loads from TOML files** (in precedence order)
2. **Merges all files** into single dict using `_merge_dicts()`
3. **For each registered analyzer:**
   - Extract section: `merged_data[analyzer_id]`
   - Instantiate config: `config_class(**merged_data[analyzer_id])`
   - Pydantic validates against schema
   - Store in `analyzer_configs[analyzer_id]`
4. **CLI gets analyzer config:**
   ```python
   config = config_manager.get_analyzer_config(analyzer_id)
   result = analyzer.analyze(domain, config)
   ```

### 4. Pydantic Model Capabilities

**Current usage:**
- Field validation and type hints
- Default values
- Field descriptions
- ConfigDict for global settings (e.g., `extra="ignore"`)

**Key Feature: Field with defaults**
```python
dkim_selectors: list[str] = Field(
    default_factory=lambda: DEFAULT_DKIM_SELECTORS.copy(),
    description="List of DKIM selectors to check",
)
```

---

## Best Approaches for Multi-Profile Configuration

### Approach 1: Nested TOML Structure (RECOMMENDED)

**Pros:**
- Natural TOML nesting
- Pydantic has native support via nested BaseModel
- Clean, hierarchical structure
- Easy to understand and edit

**Cons:**
- Requires restructuring config classes
- Migration path needed for existing configs

**Implementation:**

```toml
# New structure with profiles
[dns.profiles.default]
nameservers = ["8.8.8.8"]
check_dnssec = true

[dns.profiles.aggressive]
nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
check_dnssec = true
timeout = 10.0

[email.profiles.default]
dkim_selectors = ["default", "google", "k1", "selector1"]
check_bimi = true

[email.profiles.spf-focused]
dkim_selectors = ["default"]
check_bimi = false
check_mta_sts = false
check_tls_rpt = false
```

**Pydantic Model Design:**

```python
# Generic profile structure
from pydantic import BaseModel, Field

class ProfileConfig(BaseModel):
    """Base for all profile-enabled configs."""
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    timeout: float = 10.0
    active_profile: str = Field(
        default="default",
        description="Currently active profile name"
    )
    profiles: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Named configuration profiles"
    )

# DNS example
class DNSProfileData(BaseModel):
    """DNS-specific profile settings."""
    nameservers: list[str] | None = None
    check_dnssec: bool = True
    warn_www_not_cname: bool = False
    skip_www: bool = False

class DNSConfig(AnalyzerConfig):
    """DNS analyzer with profile support."""
    active_profile: str = Field(
        default="default",
        description="Currently active profile"
    )
    profiles: dict[str, DNSProfileData] = Field(
        default_factory=lambda: {
            "default": DNSProfileData()
        },
        description="Named DNS profiles"
    )

    def get_active_profile(self) -> DNSProfileData:
        """Get currently active profile data."""
        if self.active_profile not in self.profiles:
            return self.profiles.get("default", DNSProfileData())
        return self.profiles[self.active_profile]
```

---

### Approach 2: Flat TOML with Suffix Convention

**Pros:**
- No structural changes to config classes
- Backward compatible
- Can coexist with existing flat structure

**Cons:**
- Less elegant
- More verbose
- Custom merging logic needed

**Implementation:**

```toml
# Flat structure with profile suffixes
[email]
enabled = true
timeout = 5.0

[email.profile-default]
dkim_selectors = ["default", "google", "k1"]
check_bimi = true

[email.profile-spf-focused]
dkim_selectors = ["default"]
check_bimi = false

# Then in code:
class EmailConfig(AnalyzerConfig):
    active_profile: str = Field(default="default")
    dkim_selectors: list[str] = Field(
        default_factory=lambda: DEFAULT_DKIM_SELECTORS.copy()
    )
    # ... other fields
```

---

### Approach 3: Separate Config Files Per Profile

**Pros:**
- Minimal code changes
- Leverages existing merging system
- Clear file organization

**Cons:**
- Many config files
- No single source of truth
- Complex precedence rules

**Implementation:**

```
~/.config/webmaster-domain-tool/
├── config.toml                    # Base/default
├── config.profile-validation.toml # Validation profile
├── config.profile-seo.toml        # SEO profile
└── config.profile-security.toml   # Security profile
```

---

## Recommended Implementation: Hybrid Approach

**Use Approach 1 (Nested TOML) with:**

1. **Backward Compatibility Layer**
   - Support old flat structure during transition
   - Flat values become "default" profile
   - Warn users about deprecation

2. **Profile Activation**
   - Global setting: `[global] active_profile = "default"`
   - Or CLI override: `--profile validation`
   - Cascade to all analyzers with profiles

3. **Profile Inheritance**
   - Base "default" profile always present
   - Other profiles inherit from default
   - Only override changed values

---

## Example Use Cases

### Web Validator Profiles

```toml
[email.profiles.default]
dkim_selectors = ["default", "google", "k1", "selector1"]
check_bimi = true
check_mta_sts = true

[email.profiles.spf-include-check]
dkim_selectors = ["default"]
check_bimi = false
check_mta_sts = false
# Custom field (future): verify_spf_includes = ["include:mail.example.com"]

[dns.profiles.default]
nameservers = ["8.8.8.8"]

[dns.profiles.authoritative]
nameservers = ["8.8.8.8"]
# Custom field (future): check_zone_transfers = true
```

### CDN/Server Detection Profiles

```toml
[http.profiles.default]
timeout = 5.0
max_redirects = 10

[http.profiles.aggressive]
timeout = 2.0
max_redirects = 5
# Custom field (future): follow_redirects = false

[cdn.profiles.default]
check_headers = true
check_cname = true

[cdn.profiles.ip-lookup]
check_headers = true
check_cname = true
# Custom field (future): check_ip_geolocation = true
```

---

## Technical Implementation Checklist

### Step 1: Extend Pydantic Models
```python
# In each analyzer's config class
class XyzConfig(AnalyzerConfig):
    active_profile: str = Field(default="default")
    profiles: dict[str, dict[str, Any]] = Field(
        default_factory=dict
    )

    def get_active_profile_data(self) -> dict[str, Any]:
        """Get active profile settings."""
        return self.profiles.get(
            self.active_profile,
            self.profiles.get("default", {})
        )
```

### Step 2: Update ConfigManager
- No changes needed to merging logic
- Just properly handle nested dicts
- Pydantic will validate nested structures automatically

### Step 3: Update TOML Default Config
```toml
[dns.profiles.default]
nameservers = ["8.8.8.8"]
check_dnssec = true
```

### Step 4: CLI Integration
```bash
wdt analyze --profile validation example.com
wdt analyze --profile spf-check example.com
wdt list-analyzers --show-profiles
```

### Step 5: Analyzer Usage
```python
# In analyze() method
config = DNSConfig(**loaded_config)
active_data = config.get_active_profile_data()
nameservers = active_data.get("nameservers", config.nameservers)
```

---

## Constraint Handling with Profiles

### SPF Include Verification (Future Example)

```toml
[email.profiles.spf-validation]
dkim_selectors = ["default"]
check_spf_includes = true
spf_includes_to_verify = [
    "include:mail.google.com",
    "include:sendgrid.net"
]

[email.profiles.dmarc-only]
dkim_selectors = []
check_bimi = false
check_mta_sts = false
check_tls_rpt = false
```

**Pydantic model:**
```python
class EmailProfileData(BaseModel):
    dkim_selectors: list[str] = []
    check_spf_includes: bool = False
    spf_includes_to_verify: list[str] = Field(
        default_factory=list
    )
    check_bimi: bool = True

    @field_validator('spf_includes_to_verify')
    def validate_spf_includes(cls, v):
        """Validate SPF include format."""
        for include in v:
            if not include.startswith("include:"):
                raise ValueError(f"Invalid include: {include}")
        return v
```

---

## Migration Strategy

### Phase 1: Support Both Formats (v1.x)
```python
class DNSConfig(AnalyzerConfig):
    # Old flat fields (for backward compatibility)
    nameservers: list[str] | None = None
    check_dnssec: bool = True

    # New profile system
    active_profile: str = "default"
    profiles: dict[str, dict] = {}

    @model_validator(mode='after')
    def migrate_flat_to_profiles(self):
        """Convert old flat config to profile structure."""
        if not self.profiles and self.nameservers is not None:
            # User has old-style config, migrate to default profile
            self.profiles["default"] = {
                "nameservers": self.nameservers,
                "check_dnssec": self.check_dnssec
            }
        return self
```

### Phase 2: Deprecation Warning (v2.0)
- Warn users when flat config detected
- Suggest migration path

### Phase 3: Drop Flat Support (v3.0)
- Only support profiles
- Clean up model

---

## Key Takeaways

1. **Nested TOML (Approach 1) is best** because:
   - Pydantic native support
   - Clean hierarchical structure
   - Aligns with TOML philosophy
   - Easy to understand

2. **ConfigManager needs NO changes** - dict merging already handles nesting

3. **Pydantic validation is powerful** for:
   - Nested structures
   - Custom validation logic
   - Type safety

4. **Profile activation** can be:
   - Global setting: `[global] active_profile = ""`
   - Per-analyzer: `[dns] active_profile = ""`
   - CLI override: `--profile name`

5. **Migration path** should support both formats during transition
