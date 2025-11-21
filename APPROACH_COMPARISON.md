# Multi-Profile Configuration: Approach Comparison

## Quick Reference Table

| Aspect | Approach 1: Nested TOML | Approach 2: Flat + Suffix | Approach 3: Separate Files |
|--------|------------------------|--------------------------|-----------------------------|
| **TOML Naturalness** | Excellent - native nesting | Poor - verbose suffixes | N/A - multiple files |
| **Pydantic Support** | Native via nested BaseModel | Manual dict handling | Native (simple) |
| **ConfigManager Changes** | NONE | Minor merging tweaks | NONE |
| **Backward Compat** | Medium - needs migration | High - coexists easily | High - file-based |
| **File Organization** | Single file per analyzer | Single file per analyzer | Multiple files per profile |
| **User Experience** | Intuitive structure | Confusing suffix naming | File explosion |
| **Merging Complexity** | Zero additional work | Custom list merging logic | Complex precedence rules |
| **Validation** | Type-safe nested models | Strings & manual parsing | Type-safe (simple) |
| **Recommended?** | **YES** | No | No |

---

## Detailed Comparison

### Approach 1: Nested TOML (WINNER)

#### How It Works
```toml
[dns]
enabled = true
active_profile = "default"

[dns.profiles.default]
nameservers = ["8.8.8.8"]

[dns.profiles.aggressive]
nameservers = ["1.1.1.1", "8.8.8.8"]
```

#### Pydantic Models
```python
class DNSProfileData(BaseModel):
    nameservers: list[str] = ["8.8.8.8"]

class DNSConfig(AnalyzerConfig):
    active_profile: str = "default"
    profiles: dict[str, DNSProfileData] = {}
```

#### Pros
- Follows TOML philosophy (nested structure matches hierarchy)
- Pydantic handles everything natively
- **ConfigManager: NO changes required**
- Type-safe validation
- Clean syntax in TOML files
- Easy to understand for users

#### Cons
- Requires Pydantic model restructuring
- Migration path needed from flat format
- Slightly more verbose than current flat structure

#### Implementation Complexity
- **Low** - just add nested BaseModel class
- **Estimated effort:** 2-3 hours per analyzer
- **ConfigManager:** 0 changes

#### When to Use
- **NEW CODE** - start with profiles
- **EXISTING ANALYZERS** - gradually migrate
- **Long-term maintenance** - cleanest approach

---

### Approach 2: Flat TOML with Suffix Convention

#### How It Works
```toml
[email]
enabled = true
timeout = 5.0
active_profile = "default"

[email.profile-default]
dkim_selectors = ["default"]

[email.profile-spf]
dkim_selectors = ["default"]
check_bimi = false
```

#### Issues
1. **Suffix confusion**: Is `[email.profile-default]` or `[email-profile-default]` correct?
2. **Custom parsing needed**: Must manually extract `profile-*` keys
3. **List replacement**: When merging configs, which list wins?
4. **Ambiguous hierarchy**: Unclear what's a profile vs analyzer setting

#### Pros
- No Pydantic model changes
- Can coexist with flat config
- File merging still works

#### Cons
- **Confusing TOML syntax** - users may misunderstand structure
- **Custom ConfigManager logic** - breaks clean design
- **Manual dict handling** - lose type safety
- **Hard to document** - explain suffix convention clearly
- **Validation nightmares** - strings not structured types

#### Implementation Complexity
- **Medium** - needs custom merging logic
- **Estimated effort:** 4-5 hours per analyzer
- **ConfigManager:** Custom prefix extraction code needed
- **Testing:** Complex edge cases with merging

#### Example Problem: List Merging
```toml
# System config
[email.profile-default]
dkim_selectors = ["selector1"]

# User config - what happens?
[email.profile-default]
dkim_selectors = ["selector2"]

# Result: selector2 REPLACES selector1
# But user might expect both!
# This is confusing.
```

#### When NOT to Use
- Users will be confused by `profile-*` naming
- Configuration merging becomes unpredictable
- Type safety is lost

---

### Approach 3: Separate Config Files Per Profile

#### How It Works
```
~/.config/webmaster-domain-tool/
├── config.toml                    # default profile
├── config.profile-aggressive.toml
└── config.profile-spf.toml
```

#### Pros
- Minimal code changes
- Existing merging system handles it
- Clear file separation

#### Cons
- **File explosion** - 5 analyzers × 3 profiles = 15 files
- **No single source of truth** - settings scattered
- **Complex precedence rules** - which file wins?
- **User experience nightmare** - where to find what?
- **Maintenance burden** - duplicated settings
- **Defaults missing** - hard to track base values

#### Example Problem: Precedence Conflicts
```
File precedence (lowest to highest):
1. config.toml (default)
2. config.profile-aggressive.toml
3. .webmaster-domain-tool.toml (local)

If config.profile-aggressive.toml sets DNS timeout=2.0
And .webmaster-domain-tool.toml sets DNS timeout=5.0
Which wins? Confusing!
```

#### When NOT to Use
- Users will lose track of settings
- Maintenance becomes nightmare
- No clear default baseline

---

## Decision Matrix

### Choose Nested TOML (Approach 1) if:
- Targeting v1.5+ (profile support is new feature)
- Want long-term clean architecture
- Can dedicate time to Pydantic model updates
- User base willing to migrate configs
- Want type safety and validation

### Choose Flat + Suffix (Approach 2) if:
- ONLY short-term solution needed
- ConfigManager customization acceptable
- Users understand suffix convention
- No CLI changes desired

### Choose Separate Files (Approach 3) if:
- Profiles are global system admin only
- Few profiles total
- Users manage separate deployments

---

## Migration Path for Approach 1

### Phase 1: Dual Support (v1.5)
```python
class DNSConfig(AnalyzerConfig):
    # OLD FLAT (deprecated, marked in Field)
    nameservers: list[str] | None = Field(default=None)

    # NEW PROFILES
    active_profile: str = "default"
    profiles: dict[str, DNSProfileData] = {}

    @model_validator(mode='after')
    def migrate_old_to_new(self):
        """Auto-migrate old format."""
        if self.nameservers and not self.profiles:
            self.profiles["default"] = DNSProfileData(
                nameservers=self.nameservers
            )
        return self
```

Result: Old `[dns]` with `nameservers` auto-migrates to `[dns.profiles.default]`

### Phase 2: Deprecation (v2.0)
- Warn when flat format detected
- Log migration suggestion
- Still support old format

### Phase 3: Cleanup (v3.0)
- Remove flat fields
- Only profiles support
- Clean, simple code

**Migration Time for Users:**
- Auto-migration: Transparent (v1.5)
- Manual migration: ~5 minutes for 5 analyzers
- CLI tool to auto-generate new format

---

## Implementation Checklist

### For Nested TOML Approach

**Step 1: Create Profile Data Classes**
- [ ] Define `XyzProfileData(BaseModel)` for each analyzer
- [ ] Include all configurable fields
- [ ] Add field validators for complex logic
- [ ] Document field defaults

**Step 2: Update Analyzer Config**
- [ ] Add `active_profile: str` field
- [ ] Add `profiles: dict[str, XyzProfileData]` field
- [ ] Implement `get_active_profile()` method
- [ ] Implement `set_active_profile()` method
- [ ] Add backward compatibility validator

**Step 3: Update Analyzer Logic**
- [ ] Call `config.get_active_profile()` in `analyze()`
- [ ] Use profile values instead of direct config
- [ ] Handle missing profile gracefully
- [ ] Log which profile is active

**Step 4: Update TOML Files**
- [ ] Restructure `default_config.toml` with profiles
- [ ] Create example profiles for each analyzer
- [ ] Include comments explaining profiles
- [ ] Document migration path

**Step 5: CLI Integration**
- [ ] Add `--profile` parameter to `analyze` command
- [ ] Add `profile list <analyzer>` command
- [ ] Add validation for profile names
- [ ] Update help text

**Step 6: Testing**
- [ ] Test default profile loading
- [ ] Test profile switching
- [ ] Test missing profile fallback
- [ ] Test old format migration
- [ ] Test TOML merging with profiles

**Step 7: Documentation**
- [ ] Update README with profile examples
- [ ] Document how to create custom profiles
- [ ] Explain migration from old format
- [ ] Add troubleshooting guide

---

## Code Quality Impact

### Nested TOML Approach
```
Code Metrics:
- Lines added per analyzer: ~50-75
- Complexity increase: Minimal (1-2 nested classes)
- Type coverage: 100% (Pydantic enforced)
- Test coverage needed: 5-7 tests per analyzer
- ConfigManager changes: 0 lines
- Performance impact: None
```

### Flat + Suffix Approach
```
Code Metrics:
- Lines added per analyzer: ~30-40
- Complexity increase: Medium (custom dict parsing)
- Type coverage: ~70% (strings, manual validation)
- Test coverage needed: 10-15 tests per analyzer
- ConfigManager changes: 20-30 lines
- Performance impact: Negligible
```

---

## User Experience Comparison

### Nested TOML User View (Recommended)
```toml
# Intuitive structure
[dns]
active_profile = "aggressive"

[dns.profiles.default]
nameservers = ["8.8.8.8"]

[dns.profiles.aggressive]
nameservers = ["8.8.8.8", "1.1.1.1"]

# Clear hierarchy: analyzer → profiles → settings
# Users think: "DNS analyzer has multiple profiles"
```

### Flat + Suffix User View (Not Recommended)
```toml
# Confusing structure
[dns]
active_profile = "aggressive"
nameservers = ["8.8.8.8"]  # Is this used?

[dns.profile-default]
nameservers = ["8.8.8.8"]

[dns.profile-aggressive]
nameservers = ["8.8.8.8", "1.1.1.1"]

# Users think: "Why multiple 'nameservers' fields?"
# Which one is active?
```

---

## Final Recommendation

**Use Approach 1: Nested TOML Structure**

### Why?
1. **Pydantic native support** - no custom logic needed
2. **ConfigManager: Zero changes** - existing merging works perfectly
3. **Type safety** - validators catch mistakes
4. **User intuitive** - TOML nesting makes sense
5. **Long-term maintainability** - clean architecture
6. **Zero performance impact** - no runtime overhead

### Rollout Strategy
1. **v1.5.0**: Add to DNS and Email analyzers (pilot)
2. **v1.6.0**: Add to all analyzers
3. **v2.0.0**: Drop old flat format
4. **v2.1+**: Add advanced features (inheritance, composition)

### Estimated Timeline
- DNS analyzer: 2-3 hours
- Email analyzer: 2-3 hours
- Other 6 analyzers: 1-1.5 hours each
- Testing: 2-3 hours
- Documentation: 1-2 hours
- **Total: ~20-25 hours for complete implementation**

### Success Metrics
- Config loading tests pass 100%
- Profile switching works seamlessly
- Old format migration transparent
- Users can create custom profiles easily
- No performance regression
