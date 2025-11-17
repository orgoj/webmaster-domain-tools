#!/bin/bash
#
# SessionStart hook for webmaster-domain-tools
# This script runs automatically when starting a new Claude Code session on the web
# to ensure the development environment is properly configured.
#

set -euo pipefail

# Only run in remote Claude Code environments (on the web)
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

echo "🔧 Setting up webmaster-domain-tools development environment..."

# Change to project root
cd "$CLAUDE_PROJECT_DIR" || exit 1

# 1. Sync dependencies (including dev dependencies)
echo "📦 Syncing Python dependencies with uv..."
if ! uv sync --dev; then
    echo "❌ Failed to sync dependencies"
    exit 1
fi

# 2. Install pre-commit hooks
echo "🪝 Installing pre-commit hooks..."
if ! uv run pre-commit install 2>&1 | grep -q "pre-commit installed"; then
    echo "⚠️  Warning: Pre-commit hooks may not be installed properly"
else
    echo "✅ Pre-commit hooks installed successfully"
fi

echo "✅ Development environment ready!"
echo ""
echo "💡 Quick commands:"
echo "   uv run wdt analyze example.com  - Run domain analysis"
echo "   uv run pytest                   - Run tests"
echo "   uv run pre-commit run --all-files - Run linters"
echo ""
