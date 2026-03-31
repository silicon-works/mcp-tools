#!/usr/bin/env python3
"""
OpenSploit MCP Server: ilspy

.NET assembly decompilation to readable C# source code via ILSpy CLI (ilspycmd).
"""

import asyncio
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

ILSPYCMD = "ilspycmd"


class IlspyServer(BaseMCPServer):
    """MCP server wrapping ilspycmd for .NET assembly decompilation."""

    def __init__(self):
        super().__init__(
            name="ilspy",
            description=".NET assembly decompilation to C# source code via ILSpy CLI",
            version="9.1.0",
        )

        self.register_method(
            name="decompile",
            description="Decompile an entire .NET assembly to C# source code",
            params={
                "assembly_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the .NET DLL or EXE file to decompile (e.g., '/session/ClientsBackup.dll')",
                },
                "as_project": {
                    "type": "boolean",
                    "default": False,
                    "description": "Decompile as a compilable project (one file per type, with .csproj). Requires more output but easier to navigate.",
                },
            },
            handler=self.decompile,
        )

        self.register_method(
            name="decompile_type",
            description="Decompile a specific type (class/struct/enum) from a .NET assembly",
            params={
                "assembly_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the .NET DLL or EXE file",
                },
                "type_name": {
                    "type": "string",
                    "required": True,
                    "description": "Fully qualified type name (e.g., 'MyNamespace.MyClass', 'BackupService.BackupClients')",
                },
            },
            handler=self.decompile_type,
        )

        self.register_method(
            name="list_types",
            description="List all types (classes, interfaces, structs, delegates, enums) in a .NET assembly",
            params={
                "assembly_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the .NET DLL or EXE file",
                },
                "entity_type": {
                    "type": "string",
                    "enum": ["all", "class", "interface", "struct", "delegate", "enum"],
                    "default": "all",
                    "description": "Type of entities to list. Default: all.",
                },
            },
            handler=self.list_types,
        )

        self.register_method(
            name="list_resources",
            description="List embedded resources in a .NET assembly",
            params={
                "assembly_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the .NET DLL or EXE file",
                },
            },
            handler=self.list_resources,
        )

    async def decompile(
        self,
        assembly_path: str,
        as_project: bool = False,
    ) -> ToolResult:
        """Decompile an entire .NET assembly."""
        self.logger.info(f"Decompiling assembly: {assembly_path}")

        if not os.path.isfile(assembly_path):
            return ToolResult(
                success=False,
                data={},
                error=f"File not found: {assembly_path}",
            )

        if as_project:
            output_dir = f"/session/decompiled-{os.path.basename(assembly_path).replace('.', '_')}"
            os.makedirs(output_dir, exist_ok=True)

            cmd = [ILSPYCMD, "-p", "-o", output_dir, assembly_path]

            try:
                result = await self.run_command(cmd, timeout=120)
                stdout = result.stdout.strip() if result.stdout else ""
                stderr = result.stderr.strip() if result.stderr else ""

                if result.returncode != 0:
                    return ToolResult(
                        success=False,
                        data={},
                        error=f"Decompilation failed: {stderr or stdout}",
                    )

                # List generated files
                files = []
                for root, dirs, filenames in os.walk(output_dir):
                    for f in filenames:
                        rel = os.path.relpath(os.path.join(root, f), output_dir)
                        files.append(rel)

                return ToolResult(
                    success=True,
                    data={
                        "assembly": assembly_path,
                        "output_dir": output_dir,
                        "files": files,
                        "file_count": len(files),
                    },
                    raw_output=f"Decompiled to {output_dir}\nFiles: {len(files)}",
                )

            except Exception as e:
                return ToolResult(success=False, data={}, error=f"Decompilation failed: {e}")
        else:
            # Single-file decompilation to stdout
            cmd = [ILSPYCMD, assembly_path]

            try:
                result = await self.run_command(cmd, timeout=120)
                stdout = result.stdout if result.stdout else ""
                stderr = result.stderr.strip() if result.stderr else ""

                if result.returncode != 0:
                    return ToolResult(
                        success=False,
                        data={},
                        error=f"Decompilation failed: {stderr or stdout}",
                    )

                source = sanitize_output(stdout, max_length=50000)

                # Count classes/methods
                class_count = len(re.findall(r"^\s*(?:public|internal|private|protected)?\s*(?:static\s+)?(?:abstract\s+)?(?:sealed\s+)?class\s+", source, re.MULTILINE))
                method_count = len(re.findall(r"^\s*(?:public|internal|private|protected)\s+.*\(", source, re.MULTILINE))

                return ToolResult(
                    success=True,
                    data={
                        "assembly": assembly_path,
                        "source": source,
                        "source_length": len(source),
                        "class_count": class_count,
                        "method_count": method_count,
                    },
                    raw_output=source,
                )

            except Exception as e:
                return ToolResult(success=False, data={}, error=f"Decompilation failed: {e}")

    async def decompile_type(
        self,
        assembly_path: str,
        type_name: str,
    ) -> ToolResult:
        """Decompile a specific type from a .NET assembly."""
        self.logger.info(f"Decompiling type {type_name} from {assembly_path}")

        if not os.path.isfile(assembly_path):
            return ToolResult(success=False, data={}, error=f"File not found: {assembly_path}")

        cmd = [ILSPYCMD, "-t", type_name, assembly_path]

        try:
            result = await self.run_command(cmd, timeout=60)
            stdout = result.stdout if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if result.returncode != 0 or "Could not find" in stderr:
                return ToolResult(
                    success=False,
                    data={"assembly": assembly_path, "type_name": type_name},
                    error=f"Type '{type_name}' not found. Use list_types to see available types.",
                )

            source = sanitize_output(stdout, max_length=50000)

            return ToolResult(
                success=True,
                data={
                    "assembly": assembly_path,
                    "type_name": type_name,
                    "source": source,
                    "source_length": len(source),
                },
                raw_output=source,
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Decompilation failed: {e}")

    async def list_types(
        self,
        assembly_path: str,
        entity_type: str = "all",
    ) -> ToolResult:
        """List all types in a .NET assembly."""
        self.logger.info(f"Listing types in {assembly_path}")

        if not os.path.isfile(assembly_path):
            return ToolResult(success=False, data={}, error=f"File not found: {assembly_path}")

        # Map entity type to ilspycmd -l format (no commas — ilspycmd expects "cisde" not "c,i,s,d,e")
        type_flags = {
            "all": "cisde",
            "class": "c",
            "interface": "i",
            "struct": "s",
            "delegate": "d",
            "enum": "e",
        }

        cmd = [ILSPYCMD, "-l", type_flags.get(entity_type, "cisde"), assembly_path]

        try:
            result = await self.run_command(cmd, timeout=30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    data={},
                    error=f"Failed to list types: {stderr or stdout}",
                )

            types = []
            for line in stdout.split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Format: "Class Namespace.ClassName" or "Interface Namespace.IName"
                # Keep the full line for context but also extract just the type name
                types.append(line)

            return ToolResult(
                success=True,
                data={
                    "assembly": assembly_path,
                    "entity_type": entity_type,
                    "types": types,
                    "type_count": len(types),
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Failed to list types: {e}")

    async def list_resources(
        self,
        assembly_path: str,
    ) -> ToolResult:
        """List embedded resources in a .NET assembly."""
        self.logger.info(f"Listing resources in {assembly_path}")

        if not os.path.isfile(assembly_path):
            return ToolResult(success=False, data={}, error=f"File not found: {assembly_path}")

        # Decompile and grep for embedded resources
        cmd = [ILSPYCMD, "--il", assembly_path]

        try:
            result = await self.run_command(cmd, timeout=60)
            stdout = result.stdout if result.stdout else ""

            resources = []
            for line in stdout.split("\n"):
                if ".mresource" in line:
                    match = re.search(r"\.mresource\s+(?:public|private)?\s*'?([^']+)'?", line)
                    if match:
                        resources.append(match.group(1).strip())

            return ToolResult(
                success=True,
                data={
                    "assembly": assembly_path,
                    "resources": resources,
                    "resource_count": len(resources),
                },
                raw_output="\n".join(resources) if resources else "No embedded resources found",
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Failed to list resources: {e}")


if __name__ == "__main__":
    IlspyServer.main()
