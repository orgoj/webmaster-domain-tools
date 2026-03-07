# Configuration System Analysis

## Overview

The Webmaster Domain Tools uses a multi-layer configuration system that merges settings from multiple sources and validates them using Pydantic.

## Configuration Layers

The system loads configuration in this precedence order (highest to lowest):

```
Package Default (lowest)
        ↓
System Config (/etc/webmaster-domain-tool/config.toml)
        ↓
User Config (~/.config/webmaster-domain-tool/config.toml)
        ↓
Home Config (~/webmaster-domain-tool.toml)
        ↓
Local Config (./.webmaster-domain-tool.toml) (highest)
```

## ConfigManager Implementation

### Location

`src/webmaster_domain_tool/core/config_manager.py`

### Key Methods

- `load_from_files(paths: list[Path])` - Load and merge config files
- `get_analyzer_config(analyzer_id: str)` - Get config for specific analyzer
- `export_to_toml(path: Path)` - Export current config to file
- `_merge_dicts(base: dict, override: dict) -> dict` - Recursive dict merging

### Merging Behavior

The `_merge_dicts()` method merges dictionaries recursively:

```python
@staticmethod
def _merge_dicts(base: dict, override: dict) -> dict:
    """Merge two dicts recursively."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = ConfigManager._merge_dicts(result[key], value)
        else:
            result[key] = value
    return result
```

**Important notes:**
- Lists are REPLACED, not merged
- Nested dicts are merged recursively
- Override values take precedence

## Per-Analyzer Configuration

Each analyzer has its own config section in TOML:

```toml
# Example: DNS analyzer config
[dns]
enabled = true
timeout = 5.0
check_dnssec = true
nameservers = ["8.8.8.8", "8.8.4.4"]
```

### Config Schema

All analyzer configs extend `AnalyzerConfig`:

```python
from pydantic import BaseModel, Field

class AnalyzerConfig(BaseModel):
    """Base config for all analyzers."""
    enabled: bool = Field(default=True, description="Enable/disable analyzer")
    timeout: float = Field(default=10.0, description="Analysis timeout")
```

## Default Configuration

### Location

`default_config.toml` (package root)

### Example

```toml
# Global settings
[global]
verbosity = "normal"
color_output = true

# DNS analyzer
[dns]
enabled = true
timeout = 5.0
check_dnssec = true

# Email security
[email]
enabled = true
dkim_selectors = ["default", "google", "k1", "k2"]
check_bimi = true
```

## Configuration Best Practices

### For Users

1. **Use Local Config for Project-Specific Settings**
   ```bash
   # Create local config
   cat > .webmaster-domain-tool.toml << EOF
   [dns]
   nameservers = ["8.8.8.8", "8.8.4.4"]
   EOF
   ```

2. **Use Home Config for User-Wide Defaults**
   ```bash
   # Create user config
   cat > ~/.webmaster-domain-tool.toml << EOF
   [global]
   verbosity = "verbose"
   EOF
   ```

3. **Export Current Config**
   ```bash
   # Export to file
   wdt create-config -o my-config.toml
   ```

### For Developers

1. **Follow Pydantic Best Practices**
   - Use `Field()` for all config options
   - Add `description` for documentation
   - Use proper type hints

2. **Validate in Config Classes**
   ```python
   class DNSConfig(AnalyzerConfig):
       @field_validator('timeout')
       @classmethod
       def validate_timeout(cls, v):
           if v <= 0:
               raise ValueError("Timeout must be positive")
           return v
   ```

3. **Document All Options**
   - Help text in `Field()`
   - Examples in README
   - Default values in default_config.toml

## Configuration Profiles (Future)

See `IMPLEMENTATION_GUIDE.md` for proposed multi-profile configuration system.

## Troubleshooting

### Config Not Loading

Check config file locations:
```bash
# Check all possible locations
cat ~/.config/webmaster-domain-tool/config.toml
cat ~/webmaster-domain-tool.toml
cat ./.webmaster-domain-tool.toml
```

### Validation Errors

If Pydantic validation fails:
```bash
# Run with verbose output
wdt analyze example.com --verbosity debug
```

### TOML Syntax Errors

Check TOML syntax:
```bash
# Use toml-check or similar
uv run tomli --help
```
