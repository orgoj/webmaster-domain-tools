# Contributing to Webmaster Domain Tool

Thank you for your interest in contributing to Webmaster Domain Tool! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Adding New Analyzers](#adding-new-analyzers)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow the project's technical standards

## Getting Started

### Prerequisites

- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) package manager

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/webmaster-domain-tools.git
cd webmaster-domain-tools

# Sync dependencies
uv sync --dev

# Install pre-commit hooks
uv run pre-commit install

# Verify setup
uv run pytest
```

## Development Workflow

### ⚠️ CRITICAL: Test-Driven Development

**ALWAYS follow this workflow when making ANY code changes:**

1. **Write a test FIRST**
   - Create a test that demonstrates the issue or feature
   - The test should FAIL initially (proving the bug exists or feature is missing)
   - Example: `tests/test_feature.py`

2. **Make the code change**
   - Fix the bug or implement the feature
   - DO NOT run the application manually - rely on tests

3. **Run the test**
   - Test MUST pass after your changes
   - If test fails, fix until it passes
   - Example: `uv run pytest tests/test_feature.py -v`

4. **Verify no regressions**
   - Run full test suite: `uv run pytest`
   - All existing tests must still pass

5. **Only then commit**
   - Commit test AND fix together
   - Include both in the same commit

### Example TDD Workflow

```python
# Step 1: Write test first (tests/test_feature.py)
def test_import_analyzer_module():
    from webmaster_domain_tool.core import analyzer
    assert analyzer is not None

# Step 2: Run test - FAILS with error
$ uv run pytest tests/test_feature.py
# ERROR: ImportError or assertion failure

# Step 3: Fix the code
# (implement the feature)

# Step 4: Run test again - PASSES
$ uv run pytest tests/test_feature.py -v
# test_import_analyzer_module PASSED

# Step 5: Run full test suite
$ uv run pytest

# Step 6: Commit test + fix together
$ git add tests/test_feature.py src/module.py
$ git commit -m "Add feature X with test coverage"
```

## Code Style Guidelines

### Python Style

- **Python Version**: 3.10+ (use modern features)
- **Line Length**: 100 characters (configured in `pyproject.toml`)
- **Type Hints**: All functions MUST have type hints
- **Docstrings**: Google-style docstrings required

### Type Hints

**Required:**
```python
def analyze_domain(
    domain: str,
    check_dnssec: bool = True,
    timeout: float = 5.0,
) -> DNSAnalysisResult:
    """Analyze DNS records for a domain."""
    pass
```

**Wrong:**
```python
def analyze_domain(domain, check_dnssec=True, timeout=5.0):  # ❌ No type hints
    pass
```

### Docstrings

**Required format:**
```python
def analyze_domain(domain: str, config: DNSConfig) -> DNSAnalysisResult:
    """
    Analyze DNS records for a domain.

    Args:
        domain: Domain name to analyze
        config: DNS analyzer configuration

    Returns:
        Analysis result with DNS records and validation status

    Raises:
        ValueError: If domain format is invalid
    """
    pass
```

### Imports

- Imports organized by `isort`
- Standard library → Third-party → Local imports
- Alphabetically sorted within groups

### Code Formatting

All code is automatically formatted by:
- **Black**: Code formatting
- **isort**: Import ordering
- **Ruff**: Linting and auto-fixes

Run formatters:
```bash
uv run black src/ tests/
uv run isort src/ tests/
uv run ruff check --fix src/ tests/
```

Or use pre-commit (runs automatically on commit):
```bash
uv run pre-commit run --all-files
```

## Testing Requirements

### Coverage Requirements

- **Minimum coverage**: 30% overall (current: 32%)
- **Core modules**: 70%+ (registry, config_manager, renderers)
- **New code**: All new features require tests
- **Bug fixes**: Add regression test before fixing

### Test Structure

```
tests/
├── test_analyzer_instantiation.py  # Analyzer creation tests
├── test_cli_renderer_semantic_styles.py  # Renderer tests
├── test_config_manager_precedence.py  # Config tests
├── test_registry_circular_dependency.py  # Registry tests
└── test_dns_analyzer_output.py  # Analyzer output tests
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_registry_circular_dependency.py

# Run with coverage
uv run pytest --cov=src/webmaster_domain_tool

# Run with verbose output
uv run pytest -v

# Run specific test
uv run pytest tests/test_registry.py::test_circular_dependency -v
```

### Test Naming

- Test files: `test_<module>.py`
- Test classes: `TestClassName`
- Test methods: `test_what_it_tests`

### Common Testing Patterns

**Testing analyzers:**
```python
def test_analyzer_instantiation():
    analyzer = DNSAnalyzer()
    assert analyzer.analyzer_id == "dns"
    assert analyzer.config_class == DNSConfig

def test_analyzer_output_structure():
    analyzer = DNSAnalyzer()
    config = DNSConfig()
    # Use mock data, avoid network calls
    result = create_mock_result()
    descriptor = analyzer.describe_output(result)
    assert isinstance(descriptor, OutputDescriptor)
```

## Pull Request Process

### Before Submitting

1. **Write tests** for all changes
2. **Run full test suite**: `uv run pytest`
3. **Run formatters**: `uv run pre-commit run --all-files`
4. **Update documentation** if needed (README.md, CLAUDE.md)
5. **Update CHANGELOG.md** with your changes

### PR Checklist

- [ ] Tests written and passing
- [ ] Code formatted (black, isort, ruff)
- [ ] Type hints added to all functions
- [ ] Docstrings added/updated
- [ ] Documentation updated (if needed)
- [ ] CHANGELOG.md updated
- [ ] No breaking changes (or documented)
- [ ] All CI checks passing

### PR Title Format

```
<type>: <description>

Types: feat, fix, docs, style, refactor, test, chore
```

**Examples:**
- `feat: Add WHOIS expiry warning feature`
- `fix: Handle DNS timeout errors gracefully`
- `docs: Update README with new CLI options`
- `test: Add integration tests for CLI`

### PR Description Template

```markdown
## Description
Brief description of what this PR does.

## Motivation
Why is this change needed? What problem does it solve?

## Changes
- List of specific changes made
- Each change on a new line

## Testing
How was this tested? Include test commands and results.

## Breaking Changes
List any breaking changes (or "None")

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
```

## Adding New Analyzers

### Complete Analyzer Template

See `CLAUDE.md` for the complete template. Key points:

1. **Create single file**: `src/webmaster_domain_tool/analyzers/my_analyzer.py`
2. **Use `@registry.register` decorator**
3. **Implement three methods**: `analyze()`, `describe_output()`, `to_dict()`
4. **Define config class** with Pydantic
5. **Use semantic styling** in output (not hardcoded colors)

### Analyzer Requirements

**Required metadata:**
```python
analyzer_id = "my-analyzer"  # Unique ID
name = "My Analyzer"  # Display name
description = "What it does"  # Brief description
category = "general"  # general, security, seo, advanced
icon = "globe"  # Semantic icon name
config_class = MyConfig  # Pydantic model
depends_on = []  # Or ["dns", "http"] for dependencies
```

**Required methods:**
```python
def analyze(self, domain: str, config: MyConfig) -> MyResult:
    """Perform analysis."""
    pass

def describe_output(self, result: MyResult) -> OutputDescriptor:
    """Describe how to render output (semantic styling)."""
    pass

def to_dict(self, result: MyResult) -> dict:
    """Serialize result to JSON."""
    pass
```

### Semantic Styling

**Use semantic style classes** (NOT hardcoded colors):

```python
# ✅ CORRECT - semantic styling
descriptor.add_row(
    label="SSL Certificate",
    value="Valid",
    style_class="success",  # NOT color="green"
    icon="check",  # NOT icon="✓"
    severity="info",
)

# ❌ WRONG - hardcoded colors
descriptor.add_row(
    label="SSL Certificate",
    value="Valid",
    color="green",  # ❌ Couples to specific theme
)
```

## Common Mistakes to Avoid

### Type Hints

**Wrong:**
```python
def foo(callback: callable) -> None:  # ❌ `callable` is a builtin function
```

**Correct:**
```python
from collections.abc import Callable

def foo(callback: Callable[[str], None]) -> None:  # ✅ Proper type hint
```

### Testing

**Wrong:**
```python
# No test written, just manual testing
def new_feature():
    return "result"
```

**Correct:**
```python
# Test written first
def test_new_feature():
    result = new_feature()
    assert result == "expected"

def new_feature():
    return "expected"
```

### Configuration

**Wrong:**
```python
# Adding CLI parameter instead of config file option
@app.command()
def analyze(
    domain: str,
    new_option: bool = False,  # ❌ CLI is minimal
):
```

**Correct:**
```python
# Add to analyzer config class
class MyConfig(AnalyzerConfig):
    new_option: bool = Field(default=False, description="...")

# Use in TOML: [my-analyzer] new_option = true
```

## Getting Help

- **Documentation**: See `CLAUDE.md` for comprehensive AI assistant guide
- **Architecture**: See `README.md` Architecture section
- **Issues**: Check existing issues or create new one
- **Discussions**: Use GitHub Discussions for questions

## Resources

- [Project README](README.md)
- [AI Assistant Guide (CLAUDE.md)](CLAUDE.md)
- [Changelog](CHANGELOG.md)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [Google Style Docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

**Thank you for contributing to Webmaster Domain Tool! 🚀**
