# TODO: GUI Config Profiles - Remaining Tasks

## Summary
Config profiles backend is **DONE** (ConfigProfileManager + tests).
GUI integration and config editor dialog still **TODO**.

---

## ✅ Completed (Session 2025-11-17)

### Backend Implementation
- [x] `ConfigProfileManager` class - save/load/delete/list profiles
- [x] JSON storage in `~/.config/webmaster-domain-tool/profiles/`
- [x] Profile validation with Pydantic
- [x] 12 unit tests with 93% coverage
- [x] Lint & format (black, ruff, isort)

### GUI Fixes
- [x] Fixed async event loop error (threading instead of asyncio)
- [x] Fixed AttributeError: `chain.starting_url` → `chain.start_url`
- [x] GUI analysis now works correctly

### Infrastructure
- [x] All dependencies updated to latest stable versions
- [x] Pre-commit hooks configured and working
- [x] SessionStart hook for auto pre-commit install

---

## 🔨 TODO: GUI Config Profiles Integration

### 1. Profile Selector UI (High Priority)
**File**: `src/webmaster_domain_tool/flet_app.py`

**Add to header section:**
```python
# Profile dropdown
self.profile_dropdown = ft.Dropdown(
    label="Config Profile",
    options=[],  # Populated in _load_profiles()
    on_change=lambda e: self._on_profile_changed(e.data),
    width=200,
)

# Profile buttons
self.save_profile_btn = ft.IconButton(
    icon=ft.Icons.SAVE,
    tooltip="Save current config as profile",
    on_click=lambda _: self._show_save_profile_dialog(),
)

self.delete_profile_btn = ft.IconButton(
    icon=ft.Icons.DELETE,
    tooltip="Delete selected profile",
    on_click=lambda _: self._delete_profile(),
)
```

**Methods to add:**
- `_load_profiles()` - populate dropdown from ConfigProfileManager
- `_on_profile_changed(profile_name)` - switch to selected profile, reload config
- `_show_save_profile_dialog()` - dialog to save current config with name
- `_delete_profile()` - delete selected profile with confirmation

**Location**: Add dropdown to header row (line ~155), before title

---

### 2. Config Editor Dialog (Large Task - 300-500 lines)
**File**: `src/webmaster_domain_tool/flet_app.py`

**Requirements:**
- Tabbed interface with sections:
  - **DNS** tab: nameservers (list), timeout, check_dnssec, warn_www_not_cname
  - **HTTP** tab: timeout, max_redirects
  - **SSL** tab: cert_expiry_warning_days, cert_expiry_critical_days
  - **Email** tab: dkim_selectors (list), rbl_servers (list)
  - **Security Headers** tab: checkboxes for each header check
  - **SEO** tab: check_robots, check_llms_txt, check_sitemap
  - **Favicon** tab: check_html, check_defaults
  - **Advanced Email** tab: check_bimi, check_mta_sts, check_tls_rpt
  - **WHOIS** tab: expiry_warning_days, expiry_critical_days
  - **Site Verification** tab: services configuration
  - **Analysis** tab: skip_advanced_email, other analysis options

**Methods to implement:**
```python
def _show_config_editor(self) -> None:
    """Show config editor dialog with all settings."""

def _create_dns_tab(self) -> ft.Tab:
    """Create DNS configuration tab."""

def _create_http_tab(self) -> ft.Tab:
    """Create HTTP configuration tab."""

# ... one method for each tab

def _save_config_from_dialog(self) -> None:
    """Save config from dialog fields back to self.config."""

def _validate_config_fields(self) -> bool:
    """Validate all config fields before saving."""
```

**Add button to header:**
```python
self.config_btn = ft.IconButton(
    icon=ft.Icons.SETTINGS,
    tooltip="Edit configuration",
    on_click=lambda _: self._show_config_editor(),
)
```

---

### 3. Profile Integration
**File**: `src/webmaster_domain_tool/flet_app.py`

**In `__init__`:**
```python
from .config_profiles import ConfigProfileManager

self.profile_manager = ConfigProfileManager()
self.current_profile = "default"

# Load default or create
self.config = self.profile_manager.get_or_create_default()
```

**Update analysis to use current profile:**
- Analysis already uses `self.config` ✓
- Just need to reload config when profile changes

---

### 4. Tests
**File**: `tests/test_flet_app.py` (new file)

**Test cases:**
- Profile dropdown population
- Profile switching (mock ConfigProfileManager)
- Config editor dialog open/close
- Config validation in editor
- Save profile dialog
- Delete profile with confirmation

**Estimated**: 10-15 test functions

---

### 5. Documentation

#### README.md
**Section to add** (after "GUI Application" section):

```markdown
### Configuration Profiles

The GUI supports named configuration profiles for different use cases:

**Managing Profiles:**
1. Select profile from dropdown in header
2. Edit settings via ⚙️ Settings button
3. Save current config as new profile via 💾 Save button
4. Delete profiles via 🗑️ Delete button

**Profile Storage:**
- Profiles saved in `~/.config/webmaster-domain-tool/profiles/`
- JSON format, one file per profile
- `default.json` auto-created on first run

**Example Use Cases:**
- `fast` - minimal checks for quick scans
- `full` - all checks enabled
- `security` - focus on security headers and SSL
- `email` - detailed email configuration checks
```

#### CHANGELOG.md
**Add to `## [Unreleased]` under `### Added`:**

```markdown
- **GUI Configuration Profiles**
  - Named configuration profiles for different analysis scenarios
  - Profile dropdown in GUI header for quick switching
  - Save/load/delete profiles via GUI buttons
  - Config editor dialog with tabbed interface for all settings
  - Profiles stored in `~/.config/webmaster-domain-tool/profiles/`
  - JSON format with Pydantic validation
  - Comprehensive test coverage for profile management
```

---

## 📊 Estimated Work

| Task | Lines of Code | Time Estimate |
|------|---------------|---------------|
| Profile Selector UI | 50-100 | 30 min |
| Config Editor Dialog | 300-500 | 2-3 hours |
| Profile Integration | 50-100 | 30 min |
| Tests | 200-300 | 1 hour |
| Documentation | - | 30 min |
| **Total** | **600-1000** | **4-5 hours** |

---

## 🎯 Implementation Order

1. **Profile Selector UI** - Get basic switching working
2. **Profile Integration** - Wire up profile loading
3. **Simple Config Editor** - Start with 2-3 tabs, expand later
4. **Tests** - Test as you build
5. **Full Config Editor** - Complete all tabs
6. **Documentation** - Final step

---

## 🔥 Quick Start (Next Session)

```python
# 1. Add to __init__ (line ~90)
from .config_profiles import ConfigProfileManager
self.profile_manager = ConfigProfileManager()

# 2. Add dropdown to header (line ~155)
# See "Profile Selector UI" section above

# 3. Test basic profile switching
uv run wdt-app
```

---

## 📝 Notes

- **Config editor is the big task** - consider doing it in phases (essential tabs first)
- All config fields are in `src/webmaster_domain_tool/config.py` - use as reference
- Flet Tabs: https://flet.dev/docs/controls/tabs/
- Flet Form controls: https://flet.dev/docs/controls/textfield/, dropdown, checkbox
- Profile manager already handles all backend logic ✓

---

## ✨ Current Status

**Backend**: 100% complete ✅
**GUI Integration**: 0% complete 🔨
**Tests**: Backend 93%, GUI 0%
**Docs**: Backend done, GUI TODO

**Files Modified This Session:**
- `src/webmaster_domain_tool/config_profiles.py` (new)
- `tests/test_config_profiles.py` (new)
- `src/webmaster_domain_tool/flet_app.py` (async fix)
- `CHANGELOG.md` (updated)

**Commits:**
- `76c1619` - Add config profiles management and fix GUI display error
- `01c7af5` - Fix GUI async event loop error - use threading instead of asyncio
