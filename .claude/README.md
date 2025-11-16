# Claude Code Configuration

This directory contains Claude Code hooks and configuration files.

## SessionStart Hook

The `SessionStart` hook automatically runs when a Claude Code session starts. It ensures the development environment is properly set up by:

1. **Installing dependencies** - Runs `uv sync --dev` if `.venv` doesn't exist
2. **Installing pre-commit hooks** - Runs `uv run pre-commit install` to set up git hooks

This ensures that every new Claude Code session (including fresh checkouts) has:
- All development dependencies installed
- Pre-commit hooks configured
- Consistent development environment

## Usage

The SessionStart hook runs automatically - no manual intervention needed.

To test it manually:
```bash
./.claude/SessionStart
```

## Files

- `SessionStart` - Session initialization script (automatically executed)
- `README.md` - This file

## More Information

See [Claude Code Hooks Documentation](https://docs.claude.com/claude-code/hooks) for more details.
