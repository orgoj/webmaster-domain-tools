#!/usr/bin/env python3
"""Environment diagnostic script for debugging ft.Colors.GREEN issue."""

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path


def get_file_hash(filepath: Path) -> str:
    """Get SHA256 hash of a file."""
    if not filepath.exists():
        return "FILE_NOT_FOUND"
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return f"ERROR: {e}"


def main(user="claude"):
    """Collect environment information.

    Args:
        user: Either 'claude' or 'michael' to determine output directory
    """
    env_info = {}

    # Python info
    env_info["python"] = {
        "version": sys.version,
        "version_info": {
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
            "micro": sys.version_info.micro,
            "releaselevel": sys.version_info.releaselevel,
            "serial": sys.version_info.serial,
        },
        "executable": sys.executable,
        "platform": sys.platform,
        "implementation": sys.implementation.name,
    }

    # Platform info
    env_info["platform"] = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }

    # Import flet and check
    try:
        import flet as ft

        flet_module_path = Path(ft.__file__).parent

        # Try to get version
        flet_version = "unknown"
        try:
            flet_version = ft.__version__
        except AttributeError:
            try:
                import importlib.metadata

                flet_version = importlib.metadata.version("flet")
            except Exception:
                pass

        env_info["flet"] = {
            "version": flet_version,
            "module_path": str(flet_module_path),
            "module_file": str(ft.__file__),
        }

        # Check Colors class
        env_info["flet_colors"] = {
            "has_Colors": hasattr(ft, "Colors"),
            "Colors_type": str(type(ft.Colors)) if hasattr(ft, "Colors") else "N/A",
            "has_GREEN": hasattr(ft.Colors, "GREEN") if hasattr(ft, "Colors") else False,
            "has_GREEN_700": hasattr(ft.Colors, "GREEN_700") if hasattr(ft, "Colors") else False,
        }

        # Get all Colors attributes
        if hasattr(ft, "Colors"):
            colors_attrs = [attr for attr in dir(ft.Colors) if not attr.startswith("_")]
            env_info["flet_colors"]["all_colors"] = sorted(colors_attrs)
            env_info["flet_colors"]["total_colors"] = len(colors_attrs)

            # Get GREEN-related colors
            green_colors = [attr for attr in colors_attrs if "GREEN" in attr]
            env_info["flet_colors"]["green_colors"] = green_colors

        # Hash important Flet files
        env_info["flet_file_hashes"] = {}
        colors_file = flet_module_path / "colors.py"
        if colors_file.exists():
            env_info["flet_file_hashes"]["colors.py"] = get_file_hash(colors_file)

        __init_file = flet_module_path / "__init__.py"
        if __init_file.exists():
            env_info["flet_file_hashes"]["__init__.py"] = get_file_hash(__init_file)

    except Exception as e:
        env_info["flet_error"] = str(e)

    # Check installed packages
    try:
        import importlib.metadata

        packages = {}
        for dist in importlib.metadata.distributions():
            packages[dist.name] = dist.version

        # Filter to relevant packages
        relevant = ["flet", "flet-desktop", "flet-core", "flet-runtime"]
        env_info["packages"] = {k: v for k, v in packages.items() if k in relevant}

    except Exception as e:
        env_info["packages_error"] = str(e)

    # Save to file
    output_dir = Path(__file__).parent / user
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "environment.json"
    with open(output_file, "w") as f:
        json.dump(env_info, f, indent=2, default=str)

    print(f"\n{'='*60}")
    print(f"Environment snapshot for: {user.upper()}")
    print(f"Saved to: {output_file}")
    print(f"{'='*60}")
    print("\n=== Key Information ===")
    print(f"Python: {env_info['python']['version']}")
    print(f"Platform: {env_info['platform']['system']} {env_info['platform']['release']}")

    if "flet" in env_info:
        print(f"Flet version: {env_info['flet']['version']}")
        print(f"Flet path: {env_info['flet']['module_path']}")
        print(f"ft.Colors.GREEN exists: {env_info['flet_colors']['has_GREEN']}")
        print(f"ft.Colors.GREEN_700 exists: {env_info['flet_colors']['has_GREEN_700']}")
        print(f"Total Colors attributes: {env_info['flet_colors'].get('total_colors', 'N/A')}")
        print(f"GREEN-related colors: {env_info['flet_colors'].get('green_colors', [])}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate environment snapshot for debugging")
    parser.add_argument(
        "--user",
        choices=["claude", "michael"],
        default="claude",
        help="User name (determines output directory)",
    )
    args = parser.parse_args()
    main(user=args.user)
