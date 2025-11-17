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

## Architecture

### Core Components

```
src/webmaster_domain_tool/
├── cli.py                    # CLI entry point (Typer app)
├── config.py                 # Configuration management (Pydantic)
├── analyzers/                # Domain analysis modules
│   ├── dns_analyzer.py       # DNS + DNSSEC validation
│   ├── http_analyzer.py      # HTTP/HTTPS redirect analysis
│   ├── ssl_analyzer.py       # SSL/TLS certificate analysis
│   ├── email_security.py     # SPF, DKIM, DMARC validation
│   ├── security_headers.py   # Security headers checking
│   └── rbl_checker.py        # RBL blacklist checking
└── utils/
    ├── logger.py             # Logging configuration
    └── output.py             # Rich terminal output formatting
```

### Data Flow

1. **CLI** (`cli.py`) - Entry point that:
   - Loads configuration from files and merges with CLI args
   - Creates analyzer instances
   - Coordinates analysis execution
   - Formats and displays output

2. **Analyzers** - Independent modules that:
   - Each analyzer has a single `analyze()` method
   - Return dataclass results with `errors` and `warnings` lists
   - No inter-dependencies between analyzers

3. **Output Formatter** (`output.py`) - Centralized output that:
   - Collects all errors/warnings in central arrays
   - Displays results with Rich formatting
   - Ensures accurate error/warning counting
   - Supports multiple verbosity levels (quiet, normal, verbose, debug)

## Key Design Decisions

### 1. Error/Warning Tracking System

**Critical Implementation Detail:**

All errors and warnings are tracked in **central arrays** in `OutputFormatter`:

```python
class OutputFormatter:
    def __init__(self, ...):
        self.all_errors: list[tuple[str, str]] = []   # (category, message)
        self.all_warnings: list[tuple[str, str]] = []  # (category, message)
```

**When displaying any error/warning, you MUST add it to the central array:**

```python
# CORRECT - adds to both display and central tracking
self.all_warnings.append(("DNS", warning_message))
self.console.print(f"[yellow]⚠ {warning_message}[/yellow]")

# WRONG - displays but doesn't track
self.console.print(f"[yellow]⚠ {warning_message}[/yellow]")
```

This ensures 100% accurate counting in the summary. The count displayed in summary MUST always match exactly what was shown to the user.

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

### 4. Configuration System

Multi-layer configuration with precedence:

1. Package default config (lowest)
2. System-wide: `/etc/webmaster-domain-tool/config.toml`
3. User config: `~/.config/webmaster-domain-tool/config.toml`
4. Home config: `~/.webmaster-domain-tool.toml`
5. Local config: `./.webmaster-domain-tool.toml`
6. CLI parameters (highest - always override)

Implemented in `config.py` using Pydantic Settings with recursive dict merging.

### 5. Output Verbosity Levels

- **quiet**: Only errors, minimal output
- **normal**: Standard output with summaries
- **verbose**: Detailed tables and full information
- **debug**: Maximum detail including debug logs

Each print method in `output.py` has separate implementations for different verbosity levels.

## Analyzer Implementation Patterns

### Standard Analyzer Structure

Each analyzer follows this pattern:

```python
@dataclass
class AnalyzerResult:
    """Result container with errors and warnings lists."""
    domain: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # ... specific fields ...

class Analyzer:
    def __init__(self, config_params):
        """Initialize with config parameters."""
        pass

    def analyze(self, domain: str) -> AnalyzerResult:
        """
        Main entry point.

        Returns:
            Result object with errors and warnings populated
        """
        result = AnalyzerResult(domain=domain)

        try:
            # Perform analysis
            # Add to result.errors or result.warnings as appropriate
        except Exception as e:
            result.errors.append(f"Analysis failed: {e}")

        return result
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

1. Create new file in `analyzers/`
2. Define result dataclass with `errors` and `warnings` lists
3. Implement `analyze(domain: str)` method
4. Add configuration section to `config.py` if needed
5. Integrate in `cli.py` - create instance and call analyze()
6. Add output method in `output.py` for display
7. Update README.md with new feature

### Adding a New Configuration Option

1. Add field to appropriate config class in `config.py`:
   ```python
   class DNSConfig(BaseModel):
       new_option: bool = Field(
           default=False,
           description="Description here"
       )
   ```

2. Update default config template in `create_default_user_config()`

3. Pass to analyzer in `cli.py`:
   ```python
   analyzer = DNSAnalyzer(
       config_param=config.dns.new_option
   )
   ```

4. Add CLI option if needed:
   ```python
   new_option: Optional[bool] = typer.Option(
       None,
       "--new-option/--no-new-option",
       help="Description"
   )
   ```

5. Update README.md with usage examples

### Modifying Output Display

**IMPORTANT:** When displaying errors/warnings, ALWAYS add to central arrays:

```python
def _print_analyzer_results(self, result: AnalyzerResult) -> None:
    # Display errors
    for error in result.errors:
        self.all_errors.append(("Category", error))  # ← CRITICAL
        self.console.print(f"[red]✗ {error}[/red]")

    # Display warnings
    for warning in result.warnings:
        self.all_warnings.append(("Category", warning))  # ← CRITICAL
        self.console.print(f"[yellow]⚠ {warning}[/yellow]")
```

The category should be descriptive: "DNS", "HTTP", "SSL", "Email/SPF", etc.

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

- `cli.py` - Main CLI coordination
- `output.py` - All display logic, central error/warning tracking
- `dns_analyzer.py` - DNS queries and DNSSEC validation
- `config.py` - Configuration schema and loading
- `pyproject.toml` - Project metadata and dependencies
- `README.md` - User-facing documentation (ALWAYS keep updated)
- `CHANGELOG.md` - Version history (ALWAYS keep updated)

## Common Pitfalls

1. **Forgetting to add errors/warnings to central arrays** → Causes count mismatch
2. **Violating DNS CNAME rule** → Showing both CNAME and A records
3. **Not handling DNS timeouts gracefully** → Should be warnings, not errors
4. **Not respecting verbosity levels** → Check `self.verbosity` in output methods
5. **Hardcoding values** → Use configuration system instead

## Recent Major Changes

1. **Error/Warning Counting System** (Latest)
   - Centralized tracking in `OutputFormatter`
   - All display methods updated to track in central arrays
   - Summary now shows detailed list with categories
   - 100% accurate counting guaranteed

2. **CNAME/A Record Coexistence Fix**
   - Implemented DNS rule enforcement
   - Automatic removal of conflicting A/AAAA records
   - Prevents showing invalid DNS configurations

3. **WWW CNAME Warning Feature**
   - New optional configuration `warn_www_not_cname`
   - CLI flag `--warn-www-not-cname`
   - Best practice guidance in README

## Git Workflow

- Main branch: `main` (to be specified)
- Feature branches: `claude/feature-name-{session-id}`
- Commit messages: Descriptive with bullet points for complex changes
- Always push to feature branches, never directly to main

## Questions to Ask Before Changes

1. **Does this change affect error/warning counting?**
   → Ensure central array tracking is updated

2. **Does this introduce new DNS record handling?**
   → Verify DNS rules (CNAME coexistence) are respected

3. **Is this configurable?**
   → Should it be in config file, CLI arg, or both?

4. **How does this appear in different verbosity modes?**
   → Update quiet, normal, and verbose output methods

5. **Does README need updating?**
   → New features should be documented with examples

## Useful Commands

```bash
# Development
uv sync --dev                    # Install dependencies
uv run webmaster-domain-tool analyze example.com  # Test run

# Code quality
uv run black src/                # Format code
uv run ruff check src/           # Lint
uv run mypy src/                 # Type check
uv run pytest                    # Run tests

# Testing features
wdt analyze --warn-www-not-cname example.com     # Test www CNAME warning
wdt analyze -v example.com       # Verbose output
wdt analyze --debug example.com  # Maximum verbosity
```

## Architecture Diagram

```
┌─────────────┐
│   CLI       │  User input, arg parsing, config loading
│  (cli.py)   │
└──────┬──────┘
       │
       ├─────────┬─────────┬─────────┬─────────┬──────────┐
       │         │         │         │         │          │
       ▼         ▼         ▼         ▼         ▼          ▼
    ┌──────┐ ┌──────┐ ┌──────┐ ┌───────┐ ┌────────┐ ┌──────┐
    │ DNS  │ │ HTTP │ │ SSL  │ │ Email │ │Headers │ │ RBL  │  Analyzers
    │      │ │      │ │      │ │       │ │        │ │      │
    └───┬──┘ └───┬──┘ └───┬──┘ └───┬───┘ └───┬────┘ └───┬──┘
        │        │        │        │         │          │
        └────────┴────────┴────────┴─────────┴──────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ OutputFormatter  │  Centralized display
                    │   - Verbosity    │  & error tracking
                    │   - Errors       │
                    │   - Warnings     │
                    └──────────────────┘
```

## Support

For questions about this codebase, refer to:
- This document (CLAUDE.md)
- README.md for user-facing documentation
- Code comments and docstrings
- Git commit history for change rationale
