# Multi-Profile Configuration System: Executive Summary

## Quick Answer

**To implement multi-profile configuration, use Nested TOML (Approach 1):**

```toml
[dns]
enabled = true
active_profile = "default"

[dns.profiles.default]
nameservers = ["8.8.8.8"]

[dns.profiles.aggressive]
nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
```

**Why:**
- ConfigManager needs ZERO changes (recursive dict merging already handles it)
- Pydantic native support via nested BaseModel
- Type-safe validation
- User-intuitive TOML structure
- ~2-3 hours per analyzer to implement

---

## Current Configuration System

### Architecture (5-Layer Merge)
```
Package Default < System < User < Home < Local
                (all merged recursively by ConfigManager)
```

### Key Components
1. **ConfigManager** (`core/config_manager.py`)
   - Loads TOML files in precedence order
   - Recursive dict merging via `_merge_dicts()`
   - Pydantic validation per analyzer

2. **Per-Analyzer Configs**
   - Each analyzer: `XyzConfig(AnalyzerConfig)` Pydantic model
   - Example: `DNSConfig`, `EmailConfig`
   - Current: flat structure (no profiles)

3. **Pydantic Benefits**
   - Type hints and validation
   - Default values via Field()
   - Complex nested structures support
   - ConfigDict for global settings

### Example: Current DNSConfig
```python
class DNSConfig(AnalyzerConfig):
    nameservers: list[str] | None = None
    check_dnssec: bool = True
    warn_www_not_cname: bool = False
    timeout: float = 5.0
```

---

## Proposed Multi-Profile System

### Structure: Nested BaseModel

```python
# Profile data (new nested class)
class DNSProfileData(BaseModel):
    nameservers: list[str] | None = None
    check_dnssec: bool = True

# Main config (with profiles)
class DNSConfig(AnalyzerConfig):
    active_profile: str = "default"
    profiles: dict[str, DNSProfileData] = {}

    def get_active_profile(self) -> DNSProfileData:
        return self.profiles.get(
            self.active_profile,
            self.profiles.get("default", DNSProfileData())
        )
```

### TOML Structure

```toml
[dns]
enabled = true
timeout = 5.0
active_profile = "default"

[dns.profiles.default]
nameservers = ["8.8.8.8", "8.8.4.4"]
check_dnssec = true

[dns.profiles.aggressive]
nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.123"]
check_dnssec = true

[dns.profiles.minimal]
nameservers = ["8.8.8.8"]
check_dnssec = false
```

---

## Why This Works

### 1. ConfigManager: Zero Changes Required
```python
# Current recursive merging ALREADY handles nested dicts perfectly
@staticmethod
def _merge_dicts(base: dict, override: dict) -> dict:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = ConfigManager._merge_dicts(result[key], value)  # Recursive!
        else:
            result[key] = value
    return result

# With nested profiles:
# merged_data["dns"]["profiles"]["default"]["nameservers"] automatically works
```

### 2. Pydantic: Native Nested Support
```python
# Pydantic ALREADY validates nested structures
class DNSConfig(AnalyzerConfig):
    profiles: dict[str, DNSProfileData] = Field(default_factory=dict)
    # ↑ This works automatically - no custom validation needed
```

### 3. Analyzer Usage: Simple get_active_profile()
```python
def analyze(self, domain: str, config: DNSConfig) -> DNSAnalysisResult:
    profile = config.get_active_profile()
    nameservers = profile.nameservers or ["8.8.8.8"]
    # Use nameservers for DNS queries...
```

---

## Three Approaches Compared

| Feature | Approach 1: Nested TOML | Approach 2: Flat+Suffix | Approach 3: Multiple Files |
|---------|------------------------|-------------------------|---------------------------|
| **Recommended** | **YES** | No | No |
| **ConfigManager Changes** | **0** | Custom logic | 0 |
| **Type Safety** | **100%** | ~70% | 100% |
| **User Confusion** | Low | High | Very High |
| **Effort/Analyzer** | 2-3 hrs | 4-5 hrs | 3-4 hrs |
| **File Count** | 1 | 1 | 15+ |
| **TOML Naturalness** | Excellent | Poor | N/A |

**Approach 1 Winner:** Best code, best UX, least effort, zero ConfigManager changes

---

## Implementation Overview

### For Each Analyzer (2-3 hours)

1. **Create ProfileData class** (10 min)
   ```python
   class DNSProfileData(BaseModel):
       nameservers: list[str] | None = None
       check_dnssec: bool = True
   ```

2. **Update Config class** (15 min)
   ```python
   class DNSConfig(AnalyzerConfig):
       active_profile: str = "default"
       profiles: dict[str, DNSProfileData] = {}

       def get_active_profile(self) -> DNSProfileData:
           return self.profiles.get(
               self.active_profile,
               self.profiles.get("default", DNSProfileData())
           )
   ```

3. **Update analyze() method** (20 min)
   ```python
   profile = config.get_active_profile()
   # Use profile.* instead of config.*
   ```

4. **Update TOML config** (20 min)
   ```toml
   [dns]
   active_profile = "default"
   [dns.profiles.default]
   nameservers = ["8.8.8.8"]
   ```

5. **Add tests** (40 min)
   - Test profile switching
   - Test missing profile fallback
   - Test old format migration

6. **Documentation** (30 min)
   - README examples
   - Migration guide
   - Custom profile creation

### Total Per Analyzer: 2-3 hours
### All 8 Analyzers: 20-25 hours

---

## Real-World Examples

### Example 1: DNS Validation Profiles

```toml
[dns.profiles.default]
nameservers = ["8.8.8.8"]
check_dnssec = true

[dns.profiles.authoritative]
nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]  # Multiple nameservers
check_dnssec = true
timeout = 10.0

[dns.profiles.minimal]
nameservers = ["8.8.8.8"]
check_dnssec = false  # Skip slow DNSSEC validation
timeout = 3.0
```

**Use Cases:**
- Default: General-purpose DNS checking
- Authoritative: Full validation against multiple resolvers
- Minimal: Quick DNS check for CI/CD pipelines

### Example 2: Email Security Profiles

```toml
[email.profiles.default]
dkim_selectors = ["default", "google", "k1", "selector1"]
check_bimi = true
check_mta_sts = true

[email.profiles.spf-focused]
dkim_selectors = ["default"]  # Minimal DKIM
check_bimi = false  # Skip BIMI
check_mta_sts = false

[email.profiles.complete]
dkim_selectors = ["default", "google", "k1", "k2", "selector1", "selector2", ...]
check_bimi = true
check_mta_sts = true
```

**Use Cases:**
- Default: Standard email validation
- SPF-focused: Quick SPF/DMARC check
- Complete: Enterprise full validation

---

## Backward Compatibility Strategy

### Phase 1 (v1.5): Dual Support
- Old format still works (auto-migrates to default profile)
- No user action required
- Log deprecation warnings

### Phase 2 (v2.0): Deprecated
- Old format still supported
- Strong migration warnings
- Provide migration tool

### Phase 3 (v3.0): Removed
- Only profile-based config
- Clean codebase

**User Impact:** Transparent migration over 3 releases

---

## How It Handles Use Cases

### Use Case 1: Multiple Server IPs

**Old (flat):** Can't express variants
```toml
[dns]
nameservers = ["8.8.8.8"]  # Only one!
```

**New (profiles):** Clean separation
```toml
[dns.profiles.default]
nameservers = ["8.8.8.8"]

[dns.profiles.authoritative]
nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# Use: wdt analyze --profile authoritative example.com
```

### Use Case 2: CDN Provider Detection

**Current Issue:** Can't configure different providers per profile
```toml
[cdn]
enabled = true  # Either enabled or not
```

**With Profiles:** Can create profiles per detection strategy
```toml
[cdn.profiles.default]
check_headers = true
check_cname = true

[cdn.profiles.headers-only]
check_headers = true
check_cname = false

[cdn.profiles.deep]
check_headers = true
check_cname = true
# Future: check_ip_geolocation = true
```

### Use Case 3: SPF Include Verification

**Future Enhancement:** Verify specific SPF includes
```toml
[email.profiles.spf-strict]
check_spf = true
verify_spf_includes = [
    "include:mail.google.com",
    "include:sendgrid.net"
]

[email.profiles.dmarc-only]
check_spf = false
check_dkim = false
check_bimi = false
```

---

## CLI Integration (Phase 2)

### Basic Usage
```bash
# Use a profile
wdt analyze --profile aggressive example.com

# List available profiles
wdt list-analyzers --show-profiles dns

# Set profile
wdt profile set dns aggressive
```

### Advanced (Future)
```bash
# Manage profiles
wdt profile create dns custom --from aggressive
wdt profile list dns
wdt profile describe dns aggressive
wdt profile delete dns custom
```

---

## Validation Examples

### Type Safety with Pydantic

```python
class DNSProfileData(BaseModel):
    nameservers: list[str] = Field(
        default_factory=list,
        description="Valid DNS servers"
    )

    @field_validator('nameservers')
    @classmethod
    def validate_ips(cls, v: list[str]) -> list[str]:
        """Ensure valid IP addresses."""
        import ipaddress
        for ip in v:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"Invalid IP: {ip}")
        return v
```

**Result:** Invalid config is caught during loading, not at runtime.

---

## Key Advantages

1. **Zero ConfigManager Changes**
   - Existing recursive merging works perfectly
   - No custom logic needed
   - Proven, tested code path

2. **Type-Safe Validation**
   - Pydantic enforces types
   - Invalid configs rejected early
   - Clear error messages

3. **User-Intuitive**
   - TOML nesting matches mental model
   - Clear hierarchy: analyzer → profiles → settings
   - Easy to understand for non-developers

4. **Extensible**
   - Easy to add more profiles
   - Future: inheritance, composition
   - Scalable to complex scenarios

5. **Minimal Code Changes**
   - ~50-75 lines per analyzer
   - No changes to registry or CLI (initially)
   - Backward compatible via migration

---

## Testing Strategy

### Unit Tests (Per Analyzer)
```python
def test_dns_default_profile():
    config = DNSConfig(
        active_profile="default",
        profiles={"default": DNSProfileData(nameservers=["8.8.8.8"])}
    )
    profile = config.get_active_profile()
    assert profile.nameservers == ["8.8.8.8"]

def test_missing_profile_fallback():
    config = DNSConfig(
        active_profile="nonexistent",
        profiles={"default": DNSProfileData()}
    )
    profile = config.get_active_profile()
    assert profile == config.profiles["default"]
```

### Integration Tests
```python
def test_config_loading_with_profiles():
    config_manager = ConfigManager()
    config_manager.load_from_files()

    dns_config = config_manager.get_analyzer_config("dns")
    profile = dns_config.get_active_profile()
    assert profile is not None
```

### Migration Tests
```python
def test_old_format_auto_migrates():
    old_data = {"nameservers": ["8.8.8.8"]}
    config = DNSConfig(**old_data)

    assert config.profiles["default"].nameservers == ["8.8.8.8"]
```

---

## Summary Table

| Question | Answer |
|----------|--------|
| **What's the best approach?** | Nested TOML (Approach 1) |
| **Do we need ConfigManager changes?** | **No** - existing code works perfectly |
| **How much code per analyzer?** | ~50-75 lines |
| **Effort per analyzer?** | 2-3 hours |
| **Total effort all analyzers?** | 20-25 hours |
| **Type safety?** | 100% via Pydantic |
| **User experience?** | Excellent - intuitive TOML structure |
| **Backward compatibility?** | Yes - auto-migrate old configs |
| **Can extend with profiles?** | Yes - no ConfigManager changes |
| **When to start?** | After architecture approval (v1.5.0) |

---

## Next Steps

1. **Approval** - Confirm nested TOML approach is acceptable
2. **Design** - Finalize ProfileData structures per analyzer
3. **Pilot** - Implement DNS and Email analyzers first
4. **Test** - Comprehensive test suite
5. **Document** - README, migration guide, examples
6. **Expand** - Roll out to remaining analyzers
7. **Release** - v1.5.0 with profile support
