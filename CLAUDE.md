# Webmaster Domain Tool - AI Assistant Guide

This document provides comprehensive information about the project for AI assistants working on this codebase.

## Project Overview

**Webmaster Domain Tool** is a comprehensive CLI tool for analyzing domains. It performs DNS, HTTP/HTTPS, SSL/TLS, email security (SPF/DKIM/DMARC), security headers, and RBL blacklist checks.

**Tech Stack:**
- Python 3.10+ with type hints
- `typer` for CLI
- `rich` for terminal output
- `dnspython` for DNS queries
- `httpx` for HTTP requests
- `cryptography` for SSL analysis
- `pydantic` for configuration and data validation

## ⚠️ CRITICAL: Test-Driven Development Workflow

**ALWAYS follow this workflow when making ANY code changes:**

### The Rule

**NEVER commit code without testing it first!**

### Required Workflow

1. **Write a test FIRST**
   - Create a test that demonstrates the issue or feature
   - The test should FAIL initially (proving the bug exists or feature is missing)
   - Example: `tests/test_progress_callback.py`

2. **Make the code change**
   - Fix the bug or implement the feature
   - DO NOT run the application manually - rely on tests

3. **Run the test**
   - Test MUST pass after your changes
   - If test fails, fix until it passes
   - Example: `uv run pytest tests/test_progress_callback.py -v`

4. **Verify no regressions**
   - Run full test suite: `uv run pytest`
   - All existing tests must still pass

5. **Only then commit**
   - Commit test AND fix together
   - Include both in the same commit

### Example: Type Hint Error

**BAD (what NOT to do):**
```python
# Just wrote code with type hint error
progress_callback: callable | None = None  # ❌ WRONG - `callable` is builtin, not a type
# Committed without testing
# Application crashes on import
```

**GOOD (correct workflow):**
```python
# Step 1: Write test first
# tests/test_progress_callback.py
def test_import_analyzer_module():
    from webmaster_domain_tool.core import analyzer
    assert analyzer is not None

# Step 2: Run test - FAILS with TypeError
$ uv run pytest tests/test_progress_callback.py::test_import_analyzer_module
# ERROR: TypeError: unsupported operand type(s) for |: 'builtin_function_or_method' and 'NoneType'

# Step 3: Fix the code
from collections.abc import Callable
progress_callback: Callable[[str], None] | None = None  # ✅ CORRECT

# Step 4: Run test again - PASSES
$ uv run pytest tests/test_progress_callback.py -v
# test_import_analyzer_module PASSED

# Step 5: Run full test suite
$ uv run pytest

# Step 6: Commit test + fix together
$ git add tests/test_progress_callback.py src/webmaster_domain_tool/core/analyzer.py
$ git commit -m "Fix type hint error in progress_callback"
```

### Common Type Hint Mistakes

**Wrong:**
```python
def foo(callback: callable) -> None:  # ❌ `callable` is a builtin function
```

**Correct:**
```python
from collections.abc import Callable  # ✅ Import Callable type

def foo(callback: Callable[[str], None]) -> None:  # ✅ Proper type hint
    # Callable[[arg_types], return_type]
    pass
```

### Why This Matters

- **Runtime errors**: Type hint errors cause import failures (app won't even start)
- **User trust**: Every untested commit breaks user's confidence
- **Debugging cost**: Finding bugs without tests is 10x harder
- **No excuses**: "I forgot to test" is not acceptable

### Testing Levels

1. **Unit tests**: Test individual functions/classes (`tests/test_*.py`)
2. **Integration tests**: Test analyzer interactions (`tests/test_cli.py`)
3. **Import tests**: Verify modules can be imported (catches type hint errors)
4. **Manual testing**: Only AFTER all automated tests pass

**Remember: If there's no test, the feature doesn't exist.**

## ⚠️ CRITICAL: Always Delete Dead Code During Redesign

**NEVER leave old unused code around "just in case" - that's what Git history is for!**

### The Rule

**When redesigning or refactoring, IMMEDIATELY delete all old code that's no longer used.**

### Why This Matters

- **Confusion**: Other developers (or AI assistants) waste time editing the wrong file
- **Debugging hell**: Bugs appear to be fixed in dead code, but still occur in production
- **Technical debt**: Unused code accumulates and makes codebase hard to navigate
- **False security**: "Keeping it as backup" is pointless - Git has the history

### Example: Config Editor Redesign

**BAD (what happened):**
```python
# Created new file: config_editor_view.py (full-page view)
# Left old file: config_editor_dialog.py (popup dialog) ❌ NOT DELETED!
# Result: Half day wasted editing wrong file during debugging
```

**GOOD (correct approach):**
```python
# 1. Create new file: config_editor_view.py
# 2. Update imports: flet_app.py uses new view
# 3. IMMEDIATELY delete: config_editor_dialog.py
# 4. IMMEDIATELY update: tests, scripts, any references
# 5. Commit together: new code + deleted old code + updated references
```

### Checklist When Replacing Code

When you replace/redesign a module:

1. ✅ **Delete the old file** - `git rm old_file.py`
2. ✅ **Find all references** - `grep -r "old_module" .`
3. ✅ **Update imports** - everywhere that imported old code
4. ✅ **Update tests** - test files that imported old code
5. ✅ **Update scripts** - CI scripts, pre-commit hooks, etc.
6. ✅ **Commit everything together** - deletion + updates in one commit

### Commands to Find References

```bash
# Find all Python imports of a module
grep -r "from.*old_module import\|import.*old_module" --include="*.py"

# Find all mentions in any file
grep -r "old_module" .

# Check git for who's using it
git grep "old_module"
```

### If You Need to Reference Old Code

If you really need to see old implementation:
- Use `git log` and `git show` to view history
- Create a `docs/archive/` folder with markdown notes (NOT CODE!)
- Link to specific Git commits in comments

**Never keep executable dead code "for reference".**

## Architecture

**The project uses a modular plugin-based architecture with complete decoupling between analyzers, configuration, and output rendering.**

### Core Components

```
src/webmaster_domain_tool/
├── cli.py                      # CLI entry point (Typer app)
├── core/
│   ├── registry.py             # Analyzer auto-discovery and dependency resolution
│   └── config_manager.py       # Multi-layer configuration management
├── analyzers/
│   ├── protocol.py             # Protocol definitions (AnalyzerPlugin, OutputDescriptor)
│   ├── dns_analyzer.py         # DNS + DNSSEC validation
│   ├── whois_analyzer.py       # WHOIS information
│   ├── http_analyzer.py        # HTTP/HTTPS redirect analysis
│   ├── ssl_analyzer.py         # SSL/TLS certificate analysis
│   ├── email_security.py       # SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT
│   ├── security_headers.py     # Security headers checking
│   ├── site_verification_analyzer.py  # Site verification + tracking codes
│   ├── rbl_checker.py          # RBL blacklist checking
│   ├── cdn_detector.py         # CDN provider detection
│   ├── seo_files_analyzer.py   # robots.txt, sitemap.xml, llms.txt
│   └── favicon_analyzer.py     # Favicon detection and analysis
├── renderers/
│   ├── base.py                 # Base renderer protocol
│   ├── cli_renderer.py         # CLI output with Rich
│   └── json_renderer.py        # JSON export renderer
└── utils/
    └── logger.py               # Logging configuration
```

### Data Flow

1. **CLI** (`cli.py`) - Entry point that:
   - Loads configuration via `ConfigManager`
   - Gets enabled analyzers from `registry`
   - Resolves analyzer dependencies automatically
   - Executes analyzers in dependency order
   - Delegates rendering to `Renderer` (CLI or JSON)

2. **Registry** (`core/registry.py`) - Central coordination:
   - Auto-discovers analyzers via `@registry.register` decorator
   - Validates analyzer protocol compliance
   - Resolves execution order via topological sort
   - Detects circular dependencies

3. **Analyzers** (`analyzers/*.py`) - Self-contained modules that:
   - Implement `AnalyzerPlugin` protocol
   - Define their own configuration schema (Pydantic)
   - Declare dependencies on other analyzers
   - Return structured results (dataclasses)
   - Provide semantic output description via `describe_output()`
   - **Zero coupling** - never import CLI, config, or renderers

4. **Renderers** (`renderers/*.py`) - Output adapters:
   - Interpret semantic `OutputDescriptor` from analyzers
   - Map semantic styles to theme-specific colors/formatting
   - Support multiple output formats (CLI, JSON, future: HTML)
   - **Zero coupling** - never import specific analyzer code

## Key Design Decisions

### 1. Protocol-Based Plugin System

**Design Philosophy:** Analyzers use Python's `@runtime_checkable Protocol` instead of class inheritance.

Benefits:
- **No inheritance coupling**: Analyzers don't subclass anything
- **Protocol validation**: Registry validates all required methods/attributes exist
- **Duck typing**: Any class that looks like AnalyzerPlugin *is* one
- **Adding analyzers**: Just create a class, add `@registry.register`, done

```python
from .core.registry import registry
from .analyzers.protocol import AnalyzerPlugin

@registry.register  # That's it - analyzer is now available!
class MyNewAnalyzer:
    # Required metadata
    analyzer_id = "my-analyzer"
    name = "My Analyzer"
    description = "What it does"
    category = "general"  # general, security, seo, advanced
    icon = "globe"
    config_class = MyConfig  # Pydantic model
    depends_on = []  # Or ["dns", "http"] for dependencies

    def analyze(self, domain: str, config: MyConfig) -> MyResult:
        ...

    def describe_output(self, result: MyResult) -> OutputDescriptor:
        ...

    def to_dict(self, result: MyResult) -> dict:
        ...
```

### 2. Semantic Output Styling (Theme-Agnostic)

**Critical Concept:** Analyzers define WHAT to show, not HOW to show it.

Analyzers use semantic style classes like `success`, `error`, `warning`, `info`, `highlight`, `muted`:

```python
# CORRECT - semantic styling (renderer decides color)
descriptor.add_row(
    label="SSL Certificate",
    value="Valid",
    style_class="success",  # NOT color="green"
    icon="check",  # NOT icon="✓"
    severity="info",
)

# WRONG - hardcoded colors/icons
descriptor.add_row(
    label="SSL Certificate",
    value="Valid",
    color="green",  # ❌ Couples to specific theme
    icon="✓",  # ❌ Renderer should choose icon
)
```

The renderer (`CLIRenderer`, `JSONRenderer`) interprets semantic styles:
- CLI: Maps `success` → green, `check` → ✓
- JSON: Preserves semantic styles as-is
- Future HTML: Maps to CSS classes
- Future GUI: Can switch themes without code changes

### 3. Error/Warning Tracking in Renderers

Renderers track errors/warnings from `OutputDescriptor` rows:

```python
# In BaseRenderer
def collect_errors_warnings(self, descriptor: OutputDescriptor, category: str):
    """Collect errors and warnings from output rows."""
    for row in descriptor.rows:
        if row.severity == "error":
            self.all_errors.append((category, str(row.value)))
        elif row.severity == "warning":
            self.all_warnings.append((category, str(row.value)))
```

This ensures 100% accurate counting - the summary count always matches displayed messages.

### 2. DNS CNAME/A Record Rule

**DNS Fundamental Rule:** A domain with a CNAME record CANNOT have A/AAAA records at the same level.

Implementation in `dns_analyzer.py`:
- After collecting all DNS records, check if CNAME exists
- If CNAME found, delete any A/AAAA records for that domain
- This prevents showing both CNAME and A records (resolver might return both)

```python
# After DNS queries complete
cname_key = f"{domain}:CNAME"
if cname_key in result.records and result.records[cname_key]:
    # Remove A/AAAA as they shouldn't coexist with CNAME
    if f"{domain}:A" in result.records:
        del result.records[f"{domain}:A"]
```

### 3. WWW CNAME Best Practice Warning

Optional feature (`warn_www_not_cname`) that warns when www subdomain uses direct A/AAAA records instead of CNAME.

**Why it matters:**
- CNAME makes DNS management easier
- Changing hosting only requires updating one record
- Clients with cached A records won't experience downtime
- Industry best practice for subdomains

Implementation:
- Config: `dns.warn_www_not_cname = true/false`
- CLI: `--warn-www-not-cname` / `--no-warn-www-not-cname`
- Check in `DNSAnalyzer._check_www_cname()`

### 4. Per-Analyzer Configuration (Isolated)

**Each analyzer has its own configuration section** in TOML:

```toml
[dns]
enabled = true
timeout = 5.0
nameservers = ["1.1.1.1", "8.8.8.8"]
check_dnssec = true

[ssl]
enabled = true
timeout = 10.0
check_tls_versions = true
expiry_warning_days = 30
```

Implemented in `core/config_manager.py` with multi-layer merging:

1. Package default config (lowest)
2. System-wide: `/etc/webmaster-domain-tool/config.toml`
3. User config: `~/.config/webmaster-domain-tool/config.toml`
4. Home config: `~/.webmaster-domain-tool.toml`
5. Local config: `./.webmaster-domain-tool.toml`
6. CLI parameters (highest - always override)

Each analyzer defines its config schema via Pydantic:

```python
class DNSConfig(AnalyzerConfig):
    """DNS analyzer configuration."""
    nameservers: list[str] = Field(default=["8.8.8.8"])
    timeout: float = Field(default=5.0)
    check_dnssec: bool = Field(default=True)
```

### 5. Dependency Resolution

The registry automatically resolves analyzer execution order:

```python
# CDN analyzer declares dependencies
class CDNDetector:
    depends_on = ["http", "dns"]  # Needs HTTP headers and DNS CNAME
```

The CLI uses topological sort to ensure correct order:
1. DNS runs first (no dependencies)
2. HTTP runs (depends on DNS)
3. CDN runs (depends on HTTP and DNS)

Circular dependencies are detected and reported as errors.

### 6. Output Verbosity Levels

Controlled via `VerbosityLevel` enum:
- **QUIET**: Minimal output (custom summary functions)
- **NORMAL**: Standard output with summaries
- **VERBOSE**: Detailed tables and full information
- **DEBUG**: Maximum detail including debug logs

Rows in `OutputDescriptor` specify minimum verbosity:

```python
descriptor.add_row(
    label="DNSSEC",
    value="Enabled",
    verbosity=VerbosityLevel.VERBOSE,  # Only shown in verbose mode
)
```

## Analyzer Implementation Patterns

### Complete Analyzer Template

Each analyzer is a **self-contained module** with config, logic, and output formatting:

```python
"""My analyzer - does something useful."""

import logging
from dataclasses import dataclass, field

from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

class MyConfig(AnalyzerConfig):
    """My analyzer configuration."""

    some_option: bool = Field(default=True, description="Enable some feature")
    timeout: float = Field(default=10.0, description="Operation timeout")


# ============================================================================
# Result Model
# ============================================================================

@dataclass
class MyResult:
    """Results from my analyzer."""

    domain: str
    success: bool = False
    data: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================

@registry.register
class MyAnalyzer:
    """
    My analyzer does X, Y, and Z.

    This analyzer is completely self-contained - it declares its own:
    - Configuration schema (MyConfig)
    - Output formatting (via describe_output)
    - JSON serialization (via to_dict)
    - Metadata

    Adding it to the registry makes it automatically available in
    CLI, GUI, and any other frontend.
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "my-analyzer"
    name = "My Analyzer"
    description = "Does something useful"
    category = "general"  # general, security, seo, advanced
    icon = "globe"  # Semantic icon name
    config_class = MyConfig
    depends_on = []  # Or ["dns", "http"] if you need their results

    # ========================================================================
    # Required Protocol Methods
    # ========================================================================

    def analyze(self, domain: str, config: MyConfig) -> MyResult:
        """
        Perform analysis.

        Args:
            domain: Domain to analyze
            config: This analyzer's configuration

        Returns:
            MyResult with analysis data
        """
        result = MyResult(domain=domain)

        try:
            # Perform your analysis here
            result.success = True
            result.data["example"] = "value"

        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            result.errors.append(f"Analysis failed: {e}")

        return result

    def describe_output(self, result: MyResult) -> OutputDescriptor:
        """
        Describe how to render this analyzer's output.

        Uses semantic styling (theme-agnostic) - no hardcoded colors.

        Args:
            result: Analysis result

        Returns:
            OutputDescriptor with semantic styling
        """
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet mode summary (optional)
        descriptor.quiet_summary = lambda r: (
            f"My Analyzer: {'Success' if r.success else 'Failed'}"
        )

        # Normal verbosity
        descriptor.add_row(
            label="Status",
            value="Success" if result.success else "Failed",
            style_class="success" if result.success else "error",
            icon="check" if result.success else "cross",
            severity="info",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Verbose data
        descriptor.add_row(
            label="Details",
            value=result.data,
            section_type="key_value",
            verbosity=VerbosityLevel.VERBOSE,
        )

        # Errors and warnings
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
                verbosity=VerbosityLevel.NORMAL,
            )

        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                severity="warning",
                icon="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        return descriptor

    def to_dict(self, result: MyResult) -> dict:
        """
        Serialize result to JSON-compatible dictionary.

        Args:
            result: Analysis result

        Returns:
            JSON-serializable dict
        """
        return {
            "domain": result.domain,
            "success": result.success,
            "data": result.data,
            "errors": result.errors,
            "warnings": result.warnings,
        }
```

### Error vs Warning Guidelines

**Errors** - Critical issues that prevent functionality:
- Domain doesn't exist (NXDOMAIN)
- No SSL certificates found
- SPF/DMARC not configured
- No nameservers available

**Warnings** - Issues that should be addressed but not critical:
- Weak DMARC policy
- Deprecated TLS protocols
- Missing security headers
- DNS query timeouts
- www not using CNAME (when enabled)

## Common Tasks

### Adding a New Analyzer

**CRITICAL: Adding an analyzer now requires editing only ONE file!**

1. **Create new file** in `src/webmaster_domain_tool/analyzers/my_analyzer.py`
2. **Copy the complete analyzer template** from "Analyzer Implementation Patterns" section above
3. **Implement the three methods**: `analyze()`, `describe_output()`, `to_dict()`
4. **Add `@registry.register`** decorator to your class
5. **Done!** The analyzer is now:
   - Available in CLI via `wdt analyze` (auto-discovered)
   - Skippable via `wdt analyze --skip my-analyzer`
   - Listed in `wdt list-analyzers`
   - Available in GUI automatically
   - Config section `[my-analyzer]` in TOML works automatically

**Example - adding a WHOIS analyzer:**

```python
# Create: src/webmaster_domain_tool/analyzers/whois_analyzer.py

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor

class WhoisConfig(AnalyzerConfig):
    """WHOIS configuration."""
    timeout: float = 10.0
    expiry_warning_days: int = 30

@registry.register  # ← That's it!
class WhoisAnalyzer:
    analyzer_id = "whois"
    name = "WHOIS Information"
    description = "Domain registration details"
    category = "general"
    icon = "search"
    config_class = WhoisConfig
    depends_on = []

    def analyze(self, domain: str, config: WhoisConfig) -> WhoisResult:
        # Your implementation
        ...

    def describe_output(self, result: WhoisResult) -> OutputDescriptor:
        # Your output description
        ...

    def to_dict(self, result: WhoisResult) -> dict:
        # JSON serialization
        ...
```

**No other file changes needed!** The CLI, config system, and registry automatically discover it.

### Adding Configuration Options to Existing Analyzer

1. **Update the analyzer's config class** (in the analyzer file itself):

```python
class DNSConfig(AnalyzerConfig):
    """DNS analyzer configuration."""
    nameservers: list[str] = Field(default=["8.8.8.8"])
    timeout: float = Field(default=5.0)

    # Add new option
    new_feature: bool = Field(
        default=False,
        description="Enable new feature"
    )
```

2. **Update `default_config.toml`** with the new option:

```toml
[dns]
enabled = true
nameservers = ["8.8.8.8", "1.1.1.1"]
timeout = 5.0
new_feature = false
```

3. **Done!** The option is now:
   - Available in config files
   - Loaded via ConfigManager
   - Passed to analyzer's `analyze()` method

**No CLI changes needed** - config options are file-based only. CLI only has `--skip` parameter.

### Modifying Output Display

**Analyzers control output** via `describe_output()` method.

To add/modify output rows, edit the analyzer's `describe_output()`:

```python
def describe_output(self, result: MyResult) -> OutputDescriptor:
    descriptor = OutputDescriptor(title=self.name, category=self.category)

    # Add new row with semantic styling
    descriptor.add_row(
        label="New Field",
        value=result.new_field,
        style_class="success",  # semantic style
        icon="check",  # semantic icon
        severity="info",  # for error/warning tracking
        verbosity=VerbosityLevel.NORMAL,  # when to show
    )

    return descriptor
```

**Renderers automatically handle** error/warning collection from rows with `severity="error"` or `severity="warning"`.

## Testing

Run tests with:
```bash
uv run pytest
```

Test coverage focuses on:
- Analyzer logic correctness
- Configuration loading and merging
- Output formatting accuracy
- Error/warning counting accuracy

## Code Style

- **Type hints**: All functions must have type hints
- **Docstrings**: Use Google-style docstrings
- **Formatting**: Black with default settings
- **Linting**: Ruff with project configuration
- **Line length**: 100 characters (configured in `pyproject.toml`)

Example function signature:
```python
def analyze_domain(
    domain: str,
    check_dnssec: bool = True,
    timeout: float = 5.0,
) -> DNSAnalysisResult:
    """
    Analyze DNS records for a domain.

    Args:
        domain: Domain name to analyze
        check_dnssec: Whether to validate DNSSEC
        timeout: Query timeout in seconds

    Returns:
        Analysis result with DNS records and validation status

    Raises:
        ValueError: If domain format is invalid
    """
    pass
```

## Documentation and Version Management

**CRITICAL: These rules MUST be followed for every feature addition or significant change.**

### When Adding/Modifying Features

1. **ALWAYS Update README.md**
   - Add new features to the Features section
   - Update usage examples if needed
   - Add configuration options to the Configuration section
   - Update command-line options if CLI changed

2. **ALWAYS Update CHANGELOG.md**
   - Add entry under `## [Unreleased]` section
   - Use categories: `Added`, `Changed`, `Fixed`, `Removed`
   - Be specific about what changed and why
   - Include references to issues/PRs if applicable

3. **Bump Version in pyproject.toml**
   - Follow Semantic Versioning (MAJOR.MINOR.PATCH)
   - MAJOR: Breaking changes (incompatible API changes)
   - MINOR: New features (backward-compatible)
   - PATCH: Bug fixes (backward-compatible)
   - Update version in `pyproject.toml` `[project]` section

### Documentation Workflow

After implementing a feature:
1. Update CHANGELOG.md with specific changes
2. Update README.md with new functionality
3. Bump version appropriately
4. Commit all changes together

Example commit message:
```
Add multi-layer ICO favicon detection

- Implement _get_ico_all_dimensions() for parsing ICO headers
- Display all embedded dimensions in output
- Update README.md with new capability
- Update CHANGELOG.md
- Bump version to 0.2.0
```

### Never Skip Documentation

If you find yourself committing code changes without updating:
- README.md
- CHANGELOG.md
- Version number

**STOP and update these files first!** The user depends on accurate documentation.

## Important Files

**Core Architecture:**
- `analyzers/protocol.py` - Protocol definitions, OutputDescriptor, VerbosityLevel
- `core/registry.py` - Analyzer auto-discovery and dependency resolution
- `core/config_manager.py` - Multi-layer configuration management
- `cli.py` - CLI entry point with unified `--skip` parameter
- `renderers/cli_renderer.py` - CLI output with semantic style mapping
- `renderers/json_renderer.py` - JSON export renderer

**Analyzers (self-contained):**
- `analyzers/dns_analyzer.py` - DNS queries and DNSSEC validation
- `analyzers/whois_analyzer.py` - WHOIS information
- `analyzers/ssl_analyzer.py` - SSL/TLS certificate analysis
- `analyzers/email_security.py` - Email security (SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT)
- `analyzers/*` - 11 total analyzers, all following same pattern

**Documentation:**
- `README.md` - User-facing documentation (ALWAYS keep updated)
- `CHANGELOG.md` - Version history (ALWAYS keep updated)
- `CLAUDE.md` - This file, AI assistant guide
- `pyproject.toml` - Project metadata and dependencies

## Common Pitfalls

1. **Hardcoding colors/icons instead of semantic styles** → Use `style_class="success"` not `color="green"`
2. **Forgetting to import analyzer in `analyzers/__init__.py`** → Registry can't discover it
3. **Violating DNS CNAME rule** → Showing both CNAME and A records
4. **Not handling DNS timeouts gracefully** → Should be warnings, not errors
5. **Not setting verbosity levels on OutputRows** → Data shows at wrong verbosity
6. **Editing CLI/config/renderers when adding analyzer** → Only edit analyzer file!
7. **Using `Any` type hints** → Be specific with types for better validation
8. **Not updating dependent UI state after changes (GUI)** → When state changes (e.g., profile name), ALL dependent UI elements must be updated immediately
   - Example: After saving new profile, button states must be updated via `_update_profile_buttons()`
   - Example: After changing profile, dropdown value AND button states must sync
   - Rule: **Think thoroughly about what else depends on the state you're changing**
   - Always ask: "What UI elements read this state? Do they need to be updated?"

## Recent Major Changes

### Version 1.0.0 - Modular Architecture Refactoring (Latest)

**Breaking changes - complete rewrite:**

1. **Protocol-Based Plugin System**
   - Analyzers use `@runtime_checkable Protocol` instead of inheritance
   - Auto-discovery via `@registry.register` decorator
   - Dependency resolution with topological sort
   - Adding analyzer = create one file, done

2. **Semantic Output Styling**
   - `OutputDescriptor` with semantic style classes (success, error, warning, info)
   - Renderers map to theme-specific colors/formatting
   - Theme switching without code changes
   - Future: HTML, GUI renderers without analyzer modifications

3. **Per-Analyzer Configuration**
   - Isolated TOML sections: `[dns]`, `[ssl]`, `[email]`
   - Pydantic config classes in analyzer files
   - Multi-layer merging with `ConfigManager`
   - No config cross-contamination

4. **Unified CLI**
   - `--skip dns --skip whois` instead of `--skip-dns --skip-whois`
   - `--verbosity quiet|normal|verbose|debug` instead of `-q/-v/-d`
   - `--format cli|json` for output format
   - `wdt list-analyzers` to see all available analyzers

5. **Zero-Coupling Architecture**
   - Analyzers never import CLI, config, or renderers
   - Renderers never import specific analyzers
   - Registry manages all coordination
   - Complete decoupling for maintainability

**Files deleted:**
- `core/analyzer.py` (25KB) - Old monolithic orchestration
- `utils/output.py` (78KB) - Old coupled OutputFormatter
- `config.py` (16KB) - Old monolithic Config

**Files created:**
- `analyzers/protocol.py` - Protocol definitions
- `core/registry.py` - Auto-discovery system
- `core/config_manager.py` - Per-analyzer config
- `renderers/` - Pluggable renderer system

### Previous Versions

- **0.x.x**: DNSSEC validation, RBL checking, email security, security headers
- **0.x.x**: CNAME/A record coexistence fix, WWW CNAME warning feature
- **0.x.x**: GUI application, CDN detection, SEO files, favicon analysis

## Git Workflow

- Main branch: `main` (to be specified)
- Feature branches: `claude/feature-name-{session-id}`
- Commit messages: Descriptive with bullet points for complex changes
- Always push to feature branches, never directly to main

## Questions to Ask Before Changes

1. **Am I adding a new analyzer?**
   → Create one file in `analyzers/`, add `@registry.register`, done!

2. **Am I modifying output?**
   → Update analyzer's `describe_output()` with semantic styles, NOT colors

3. **Does this introduce new DNS record handling?**
   → Verify DNS rules (CNAME coexistence) are respected

4. **Am I adding configuration?**
   → Add to analyzer's config class, update `default_config.toml`

5. **How does this appear in different verbosity modes?**
   → Set `verbosity` parameter on `OutputRow` objects

6. **Am I editing CLI/config/renderers?**
   → STOP! You probably don't need to. Analyzers are self-contained.

7. **Does README need updating?**
   → New features should be documented with examples

## Useful Commands

```bash
# Development
uv sync --dev                                    # Install dependencies
uv run wdt analyze example.com                   # Test run

# Code quality
uv run black src/                                # Format code
uv run ruff check src/                           # Lint
uv run mypy src/                                 # Type check
uv run pytest                                    # Run tests

# Testing new CLI
wdt list-analyzers                               # List all analyzers
wdt analyze --skip dns --skip whois example.com  # Skip analyzers
wdt analyze --verbosity verbose example.com      # Verbose output
wdt analyze --verbosity debug example.com        # Maximum verbosity
wdt analyze --format json example.com            # JSON output

# Testing specific analyzers
wdt analyze --skip http --skip ssl example.com   # DNS and email only
```

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                          User/Frontend                        │
│                      (CLI, GUI, API, ...)                     │
└────────────┬─────────────────────────────────┬────────────────┘
             │                                 │
             ▼                                 ▼
    ┌─────────────────┐              ┌──────────────────┐
    │   CLI (cli.py)  │              │   GUI (Flet)     │
    │                 │              │                  │
    │  - Arg parsing  │              │  - Web interface │
    │  - Orchestration│              │  - Mobile UI     │
    └────────┬────────┘              └────────┬─────────┘
             │                                │
             └────────────┬───────────────────┘
                          ▼
            ┌──────────────────────────────┐
            │   Registry (core/registry.py) │
            │                               │
            │  - Auto-discovery             │
            │  - Dependency resolution      │
            │  - Topological sort           │
            └──────────┬───────────────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
         ▼             ▼             ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ConfigMgr │  │Analyzers │  │Renderers │
  │          │  │          │  │          │
  │ Multi-   │  │ @register│  │ Semantic │
  │ layer    │  │ Protocol │  │ styles   │
  │ TOML     │  │ based    │  │ →colors  │
  └──────────┘  └─────┬────┘  └──────────┘
                      │
        ┌─────────────┼─────────────┬────────────┬──────────┐
        │             │             │            │          │
        ▼             ▼             ▼            ▼          ▼
    ┌──────┐    ┌──────┐    ┌──────┐    ┌──────────┐ ┌─────────┐
    │ DNS  │    │WHOIS │    │ HTTP │    │   SSL    │ │  Email  │  ...
    │      │    │      │    │      │    │          │ │         │
    │  │   │    │  │   │    │  │   │    │    │     │ │    │    │
    │  ↓   │    │  ↓   │    │  ↓   │    │    ↓     │ │    ↓    │
    │Config│    │Config│    │Config│    │  Config  │ │  Config │
    │Output│    │Output│    │Output│    │  Output  │ │  Output │
    │ JSON │    │ JSON │    │ JSON │    │   JSON   │ │   JSON  │
    └──────┘    └──────┘    └──────┘    └──────────┘ └─────────┘

Key Principles:
1. Zero coupling - analyzers never import CLI/config/renderers
2. Protocol-based - no inheritance, duck typing via @runtime_checkable
3. Auto-discovery - just add @registry.register
4. Semantic output - analyzers say WHAT, renderers decide HOW
5. Dependency resolution - automatic execution order
```

## Support

For questions about this codebase, refer to:
- This document (CLAUDE.md)
- README.md for user-facing documentation
- Code comments and docstrings
- Git commit history for change rationale
