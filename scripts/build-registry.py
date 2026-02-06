#!/usr/bin/env python3
"""
Build consolidated registry.yaml from per-tool tool.yaml files.

This script reads all tools/*/tool.yaml files and merges them into
a single registry.yaml with version and timestamp metadata.

Usage:
    python scripts/build-registry.py
    python scripts/build-registry.py --check  # Verify consistency only
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
REGISTRY_PATH = PROJECT_ROOT / "registry.yaml"


def load_tool_yamls() -> dict:
    """Load all tool.yaml files from tools/ directories."""
    tools = {}
    errors = []

    for tool_dir in sorted(TOOLS_DIR.iterdir()):
        if not tool_dir.is_dir():
            continue

        tool_yaml = tool_dir / "tool.yaml"
        if not tool_yaml.exists():
            continue

        try:
            with open(tool_yaml, "r") as f:
                data = yaml.safe_load(f)

            if data is None:
                errors.append(f"{tool_yaml}: empty file")
                continue

            # Use the 'name' field as the registry key if present,
            # otherwise fall back to the directory name.
            # This handles cases like playwright/ dir → playwright-mcp key.
            tool_name = data.get("name", tool_dir.name)
            tools[tool_name] = data

        except yaml.YAMLError as e:
            errors.append(f"{tool_yaml}: YAML parse error: {e}")

    if errors:
        print("Errors loading tool.yaml files:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        sys.exit(1)

    return tools


def validate_tool(tool_name: str, tool: dict) -> list[str]:
    """Validate a single tool entry against required schema."""
    errors = []
    prefix = f"tools/{tool_name}/tool.yaml"

    required_fields = ["name", "description", "image", "capabilities", "phases", "methods"]
    for field in required_fields:
        if field not in tool:
            errors.append(f"{prefix}: missing required field '{field}'")

    # Validate methods have descriptions and params
    for method_name, method in tool.get("methods", {}).items():
        if "description" not in method:
            errors.append(f"{prefix}: methods.{method_name} missing 'description'")
        if "params" not in method:
            errors.append(f"{prefix}: methods.{method_name} missing 'params'")

    return errors


def build_registry(tools: dict) -> dict:
    """Build consolidated registry from tool entries."""
    return {
        "version": "2.0",
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": tools,
    }


def registry_yaml_dump(registry: dict) -> str:
    """Dump registry to YAML with consistent formatting."""
    return yaml.dump(
        registry,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )


def check_consistency(tools: dict) -> bool:
    """Check that per-tool files match existing registry.yaml."""
    if not REGISTRY_PATH.exists():
        print("No existing registry.yaml to compare against")
        return True

    with open(REGISTRY_PATH, "r") as f:
        existing = yaml.safe_load(f)

    existing_tools = existing.get("tools", {})
    ok = True

    # Check for tools in registry but missing tool.yaml
    for name in existing_tools:
        if name not in tools:
            print(f"  MISSING: {name} in registry.yaml but no tool.yaml")
            ok = False

    # Check for tool.yaml files not in registry
    for name in tools:
        if name not in existing_tools:
            print(f"  NEW: {name} has tool.yaml but not in registry.yaml")

    return ok


def main():
    parser = argparse.ArgumentParser(description="Build consolidated registry.yaml")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check consistency without writing",
    )
    args = parser.parse_args()

    # Load all tool.yaml files
    tools = load_tool_yamls()
    print(f"Found {len(tools)} tool.yaml files")

    if not tools:
        print("No tool.yaml files found in tools/*/", file=sys.stderr)
        sys.exit(1)

    # Validate all tools
    all_errors = []
    for name, tool in tools.items():
        all_errors.extend(validate_tool(name, tool))

    if all_errors:
        print("\nValidation errors:", file=sys.stderr)
        for error in all_errors:
            print(f"  - {error}", file=sys.stderr)
        sys.exit(1)

    print("All tools validated successfully")

    if args.check:
        check_consistency(tools)
        return

    # Build and write consolidated registry
    registry = build_registry(tools)
    output = registry_yaml_dump(registry)

    with open(REGISTRY_PATH, "w") as f:
        f.write(output)

    print(f"Wrote {REGISTRY_PATH} ({len(output)} bytes, {len(tools)} tools)")


if __name__ == "__main__":
    main()
