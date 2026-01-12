#!/usr/bin/env python3
"""
Tool Contract Validation Tests

This test suite validates that all methods advertised in the registry.yaml
are actually implemented and registered in the corresponding MCP servers.

The "tool contract" is the agreement that:
1. Every method listed in registry.yaml for a tool EXISTS in the MCP server
2. Every method is CALLABLE (can be invoked without "Unknown method" errors)
3. Every required parameter is documented
4. Error messages are descriptive and helpful

This prevents the "ghost method" problem where the registry advertises
capabilities that don't actually exist in the implementation.
"""

import ast
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
REGISTRY_PATH = PROJECT_ROOT / "registry.yaml"
TOOLS_DIR = PROJECT_ROOT / "tools"


class ContractViolation:
    """Represents a contract violation between registry and implementation."""

    def __init__(
        self,
        tool_name: str,
        violation_type: str,
        message: str,
        severity: str = "error",
    ):
        self.tool_name = tool_name
        self.violation_type = violation_type
        self.message = message
        self.severity = severity

    def __str__(self) -> str:
        icon = "ERROR" if self.severity == "error" else "WARN "
        return f"[{icon}] {self.tool_name}: {self.violation_type} - {self.message}"


class ToolContractValidator:
    """Validates tool contracts between registry and implementation."""

    def __init__(self, registry_path: Path, tools_dir: Path):
        self.registry_path = registry_path
        self.tools_dir = tools_dir
        self.violations: List[ContractViolation] = []

    def load_registry(self) -> Dict:
        """Load and parse the registry.yaml file."""
        with open(self.registry_path, "r") as f:
            return yaml.safe_load(f)

    def extract_registered_methods(self, mcp_server_path: Path) -> Set[str]:
        """
        Extract method names registered via self.register_method() calls.

        Parses the Python AST to find all register_method calls and extracts
        the 'name' parameter value.
        """
        if not mcp_server_path.exists():
            return set()

        with open(mcp_server_path, "r") as f:
            source = f.read()

        registered_methods: Set[str] = set()

        try:
            tree = ast.parse(source)
        except SyntaxError:
            self.violations.append(
                ContractViolation(
                    mcp_server_path.parent.name,
                    "SYNTAX_ERROR",
                    f"Could not parse {mcp_server_path}",
                    "error",
                )
            )
            return set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Look for self.register_method(...) calls
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "register_method"
                ):
                    # Find the 'name' keyword argument
                    for keyword in node.keywords:
                        if keyword.arg == "name":
                            if isinstance(keyword.value, ast.Constant):
                                registered_methods.add(keyword.value.value)
                            elif isinstance(keyword.value, ast.Str):
                                # Python 3.7 compatibility
                                registered_methods.add(keyword.value.s)

        return registered_methods

    def validate_tool(self, tool_name: str, tool_def: Dict) -> List[ContractViolation]:
        """
        Validate a single tool's contract.

        Checks that all methods advertised in the registry are registered
        in the MCP server implementation.
        """
        violations: List[ContractViolation] = []

        # Skip external tools (maintained by third parties)
        if tool_def.get("external", False):
            return violations

        # Get methods from registry
        registry_methods = set(tool_def.get("methods", {}).keys())
        if not registry_methods:
            # No methods defined in registry - might be intentional
            return violations

        # Find the MCP server implementation
        tool_dir = self.tools_dir / tool_name
        mcp_server_path = tool_dir / "mcp-server.py"

        if not tool_dir.exists():
            violations.append(
                ContractViolation(
                    tool_name,
                    "MISSING_IMPLEMENTATION",
                    f"Tool directory not found: {tool_dir}",
                    "error",
                )
            )
            return violations

        if not mcp_server_path.exists():
            violations.append(
                ContractViolation(
                    tool_name,
                    "MISSING_SERVER",
                    f"MCP server not found: {mcp_server_path}",
                    "error",
                )
            )
            return violations

        # Extract registered methods from implementation
        implemented_methods = self.extract_registered_methods(mcp_server_path)

        # Check for ghost methods (in registry but not implemented)
        ghost_methods = registry_methods - implemented_methods
        for method in ghost_methods:
            violations.append(
                ContractViolation(
                    tool_name,
                    "GHOST_METHOD",
                    f"Method '{method}' is advertised in registry but NOT registered in mcp-server.py",
                    "error",
                )
            )

        # Check for undocumented methods (implemented but not in registry)
        undocumented_methods = implemented_methods - registry_methods
        for method in undocumented_methods:
            violations.append(
                ContractViolation(
                    tool_name,
                    "UNDOCUMENTED_METHOD",
                    f"Method '{method}' is registered in mcp-server.py but NOT documented in registry",
                    "warning",
                )
            )

        return violations

    def validate_all(self) -> Tuple[int, int]:
        """
        Validate all tools in the registry.

        Returns:
            Tuple of (error_count, warning_count)
        """
        registry = self.load_registry()
        tools = registry.get("tools", {})

        for tool_name, tool_def in tools.items():
            tool_violations = self.validate_tool(tool_name, tool_def)
            self.violations.extend(tool_violations)

        error_count = sum(1 for v in self.violations if v.severity == "error")
        warning_count = sum(1 for v in self.violations if v.severity == "warning")

        return error_count, warning_count

    def print_report(self) -> None:
        """Print a formatted report of all violations."""
        if not self.violations:
            print("\n" + "=" * 60)
            print("TOOL CONTRACT VALIDATION: ALL PASSED")
            print("=" * 60)
            print("\nNo contract violations found. All registry methods are implemented.")
            return

        print("\n" + "=" * 60)
        print("TOOL CONTRACT VALIDATION REPORT")
        print("=" * 60)

        # Group by tool
        by_tool: Dict[str, List[ContractViolation]] = {}
        for v in self.violations:
            if v.tool_name not in by_tool:
                by_tool[v.tool_name] = []
            by_tool[v.tool_name].append(v)

        for tool_name, violations in sorted(by_tool.items()):
            print(f"\n## {tool_name}")
            print("-" * 40)
            for v in violations:
                print(f"  {v}")

        error_count = sum(1 for v in self.violations if v.severity == "error")
        warning_count = sum(1 for v in self.violations if v.severity == "warning")

        print("\n" + "=" * 60)
        print(f"SUMMARY: {error_count} errors, {warning_count} warnings")
        print("=" * 60)

        if error_count > 0:
            print("\nGHOST METHODS DETECTED!")
            print("These methods are advertised in registry.yaml but not implemented.")
            print("This causes 'Unknown method' errors when agents try to use them.")
            print("\nAction required:")
            print("  1. Implement the missing methods in the MCP server, OR")
            print("  2. Remove the ghost methods from registry.yaml")


def main():
    """Run the tool contract validation."""
    print("Tool Contract Validation")
    print("========================\n")
    print(f"Registry: {REGISTRY_PATH}")
    print(f"Tools Dir: {TOOLS_DIR}")

    if not REGISTRY_PATH.exists():
        print(f"\nERROR: Registry not found at {REGISTRY_PATH}")
        sys.exit(1)

    if not TOOLS_DIR.exists():
        print(f"\nERROR: Tools directory not found at {TOOLS_DIR}")
        sys.exit(1)

    validator = ToolContractValidator(REGISTRY_PATH, TOOLS_DIR)
    error_count, warning_count = validator.validate_all()
    validator.print_report()

    # Exit with error code if there are errors
    if error_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
