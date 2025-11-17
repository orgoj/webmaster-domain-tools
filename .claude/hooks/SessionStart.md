# SessionStart Hook - Webmaster Domain Tool

This hook runs automatically when a new Claude Code session starts in this repository.

## Purpose
Ensures development environment is properly configured for every session, eliminating manual setup steps.

## Actions

### 1. Install Pre-commit Hooks
```bash
uv run pre-commit install
```

Installs git pre-commit hooks that automatically:
- Format code with Black (100 char line length)
- Lint with Ruff and auto-fix issues
- Sort imports with isort (black profile)
- Check YAML/TOML syntax
- Detect trailing whitespace, private keys, merge conflicts

### 2. Verify Installation
```bash
git config --get core.hooksPath || echo "✓ Pre-commit hooks installed in .git/hooks/"
```

## Why This Matters

**Without this hook:**
- Developers must manually run `uv run pre-commit install` every session
- Commits may bypass quality checks
- Inconsistent code formatting across the codebase
- Technical debt accumulates

**With this hook:**
- ✅ Pre-commit auto-installs on every session
- ✅ All commits automatically checked and formatted
- ✅ Consistent code quality guaranteed
- ✅ Zero manual setup required

## Manual Verification

To verify pre-commit is working:
```bash
# Check hook is installed
ls -la .git/hooks/pre-commit

# Test on all files
uv run pre-commit run --all-files
```

## Dependencies

Requires packages in `[dependency-groups] dev`:
- pre-commit>=4.4.0
- isort>=7.0.0
- pytest-cov>=7.0.0

These are automatically installed by `uv sync`.
