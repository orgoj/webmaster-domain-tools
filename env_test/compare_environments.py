#!/usr/bin/env python3
"""Compare Claude and Michael environment snapshots."""

import json
from pathlib import Path


def load_env(user):
    """Load environment JSON for a user."""
    env_file = Path(__file__).parent / user / "environment.json"
    if not env_file.exists():
        return None
    with open(env_file) as f:
        return json.load(f)


def compare_dicts(d1, d2, path=""):
    """Recursively compare two dictionaries and report differences."""
    differences = []

    # Keys only in d1
    only_in_1 = set(d1.keys()) - set(d2.keys())
    for key in only_in_1:
        differences.append(f"{path}.{key}: ONLY IN CLAUDE = {d1[key]}")

    # Keys only in d2
    only_in_2 = set(d2.keys()) - set(d1.keys())
    for key in only_in_2:
        differences.append(f"{path}.{key}: ONLY IN MICHAEL = {d2[key]}")

    # Keys in both - compare values
    common_keys = set(d1.keys()) & set(d2.keys())
    for key in sorted(common_keys):
        v1, v2 = d1[key], d2[key]
        current_path = f"{path}.{key}" if path else key

        if isinstance(v1, dict) and isinstance(v2, dict):
            # Recurse into nested dicts
            differences.extend(compare_dicts(v1, v2, current_path))
        elif isinstance(v1, list) and isinstance(v2, list):
            # Compare lists
            if v1 != v2:
                if len(v1) != len(v2):
                    differences.append(
                        f"{current_path}: LIST LENGTH DIFFERS "
                        f"(Claude: {len(v1)}, Michael: {len(v2)})"
                    )
                # Show different elements
                set1, set2 = set(map(str, v1)), set(map(str, v2))
                only_claude = set1 - set2
                only_michael = set2 - set1
                if only_claude:
                    differences.append(
                        f"{current_path}: ONLY IN CLAUDE: {sorted(only_claude)[:5]}..."
                    )
                if only_michael:
                    differences.append(
                        f"{current_path}: ONLY IN MICHAEL: {sorted(only_michael)[:5]}..."
                    )
        else:
            # Compare scalar values
            if v1 != v2:
                differences.append(f"{current_path}:")
                differences.append(f"  Claude:  {v1}")
                differences.append(f"  Michael: {v2}")

    return differences


def main():
    """Compare environments and report differences."""
    print("=" * 70)
    print("ENVIRONMENT COMPARISON: Claude vs Michael")
    print("=" * 70)

    claude_env = load_env("claude")
    michael_env = load_env("michael")

    if claude_env is None:
        print("❌ ERROR: Claude's environment.json not found!")
        print("   Run: uv run python3 env_test/check_environment.py --user claude")
        return

    if michael_env is None:
        print("❌ ERROR: Michael's environment.json not found!")
        print("   Run: uv run python3 env_test/check_environment.py --user michael")
        return

    print("\n✅ Both environment files loaded")
    print(f"   Claude:  {Path('env_test/claude/environment.json').absolute()}")
    print(f"   Michael: {Path('env_test/michael/environment.json').absolute()}")

    # Compare
    differences = compare_dicts(claude_env, michael_env)

    if not differences:
        print("\n🎉 ENVIRONMENTS ARE IDENTICAL!")
        print("   No differences found.")
    else:
        print(f"\n⚠️  FOUND {len(differences)} DIFFERENCES:\n")
        for diff in differences:
            print(diff)

    print("\n" + "=" * 70)

    # Save diff report
    report_file = Path(__file__).parent / "diff_report.txt"
    with open(report_file, "w") as f:
        f.write("ENVIRONMENT COMPARISON REPORT\n")
        f.write("=" * 70 + "\n\n")
        if differences:
            f.write(f"Found {len(differences)} differences:\n\n")
            for diff in differences:
                f.write(diff + "\n")
        else:
            f.write("No differences found - environments are identical.\n")

    print(f"📄 Full report saved to: {report_file}")


if __name__ == "__main__":
    main()
