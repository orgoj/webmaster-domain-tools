#!/usr/bin/env python3
"""
Import smoke test - checks that all modules can be imported without errors.

This catches AttributeErrors and other import-time issues that static
type checkers might miss (e.g., ft.Colors.SURFACE_VARIANT not existing).
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

MODULES_TO_TEST = [
    "webmaster_domain_tool.cli",
    "webmaster_domain_tool.flet_app",
    "webmaster_domain_tool.config_editor_view",
    "webmaster_domain_tool.gui_config_adapter",
    "webmaster_domain_tool.flet_config_manager",
    "webmaster_domain_tool.config_profiles",
    "webmaster_domain_tool.core.registry",
    "webmaster_domain_tool.core.config_manager",
    "webmaster_domain_tool.analyzers.dns_analyzer",
    "webmaster_domain_tool.analyzers.http_analyzer",
    "webmaster_domain_tool.analyzers.ssl_analyzer",
    "webmaster_domain_tool.analyzers.email_security",
    "webmaster_domain_tool.analyzers.seo_files_analyzer",
    "webmaster_domain_tool.analyzers.html_validator_analyzer",
]


def main():
    """Test importing all modules."""
    failed = []

    for module_name in MODULES_TO_TEST:
        try:
            __import__(module_name)
            print(f"✓ {module_name}")
        except Exception as e:
            print(f"✗ {module_name}: {e}")
            failed.append((module_name, e))

    if failed:
        print(f"\n❌ {len(failed)} module(s) failed to import:")
        for module_name, error in failed:
            print(f"  - {module_name}: {error}")
        sys.exit(1)
    else:
        print(f"\n✅ All {len(MODULES_TO_TEST)} modules imported successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()
