#!/usr/bin/env python3
"""
OpenSploit MCP Server: ghidra

Binary decompilation and reverse engineering via Ghidra headless mode.

Architecture:
    Agent <-> this script (MCP stdio) <-> Ghidra headless server (HTTP REST on localhost)

Uses bethington/ghidra-mcp's headless server which provides a REST API
without requiring the Ghidra GUI. This script bridges that HTTP API to
the standard MCP stdio protocol via BaseMCPServer.
"""

import asyncio
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from mcp_common import BaseMCPServer, ToolResult, ToolError

GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
GHIDRA_PORT = int(os.environ.get("GHIDRA_HEADLESS_PORT", "8089"))
GHIDRA_PROJECT_DIR = os.environ.get("GHIDRA_PROJECT_DIR", "/projects")
GHIDRA_BASE_URL = f"http://localhost:{GHIDRA_PORT}"

# Track which binaries have been loaded to avoid re-loading
_loaded_binaries: Dict[str, str] = {}  # path -> project name
# Track binaries where analysis may be incomplete
_analysis_incomplete: Dict[str, bool] = {}  # path -> True if timed out


class GhidraServer(BaseMCPServer):
    """MCP server for Ghidra binary analysis."""

    def __init__(self):
        super().__init__(
            name="ghidra",
            description="Binary decompilation and reverse engineering via Ghidra",
            version="1.0.0",
        )

        self._ghidra_process = None
        self._ghidra_ready = False

        # --- Binary loading ---

        self.register_method(
            name="load_binary",
            description="Load a binary into Ghidra and run auto-analysis",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file to load and analyze",
                },
            },
            handler=self.load_binary,
        )

        # --- Analysis methods ---

        self.register_method(
            name="decompile_function",
            description="Decompile a function to C pseudocode by name",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
                "name": {
                    "type": "string",
                    "required": True,
                    "description": "Function name to decompile (e.g., 'main', 'vuln')",
                },
            },
            handler=self.decompile_function,
        )

        self.register_method(
            name="decompile_function_by_address",
            description="Decompile a function at a specific memory address",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
                "address": {
                    "type": "string",
                    "required": True,
                    "description": "Function address in hex (e.g., '0x401234')",
                },
            },
            handler=self.decompile_function_by_address,
        )

        self.register_method(
            name="list_functions",
            description="List all functions in the binary",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
                "offset": {
                    "type": "integer",
                    "default": 0,
                    "description": "Pagination offset",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Max functions to return",
                },
            },
            handler=self.list_functions,
        )

        self.register_method(
            name="search_functions_by_name",
            description="Search for functions by name substring",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
                "query": {
                    "type": "string",
                    "required": True,
                    "description": "Substring to search for in function names",
                },
            },
            handler=self.search_functions_by_name,
        )

        self.register_method(
            name="get_xrefs_to",
            description="Get cross-references TO an address (what calls this)",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
                "address": {
                    "type": "string",
                    "required": True,
                    "description": "Target address in hex or function name",
                },
            },
            handler=self.get_xrefs_to,
        )

        self.register_method(
            name="get_xrefs_from",
            description="Get cross-references FROM an address (what this calls)",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
                "address": {
                    "type": "string",
                    "required": True,
                    "description": "Source address in hex or function name",
                },
            },
            handler=self.get_xrefs_from,
        )

        self.register_method(
            name="list_strings",
            description="Extract strings from the binary",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
                "filter": {
                    "type": "string",
                    "description": "Optional substring filter (e.g., 'password', '/bin')",
                },
                "offset": {
                    "type": "integer",
                    "default": 0,
                    "description": "Pagination offset",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Max strings to return",
                },
            },
            handler=self.list_strings,
        )

        self.register_method(
            name="list_imports",
            description="List imported functions (libc, etc.) with addresses",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
            },
            handler=self.list_imports,
        )

        self.register_method(
            name="list_exports",
            description="List exported symbols",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
            },
            handler=self.list_exports,
        )

        self.register_method(
            name="list_segments",
            description="List memory segments with permissions",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
            },
            handler=self.list_segments,
        )

        self.register_method(
            name="disassemble_function",
            description="Get assembly code for a function",
            params={
                "binary_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the binary file",
                },
                "address": {
                    "type": "string",
                    "required": True,
                    "description": "Function address in hex",
                },
            },
            handler=self.disassemble_function,
        )

    # =========================================================================
    # Ghidra headless server lifecycle
    # =========================================================================

    async def _ensure_ghidra_running(self):
        """Start the Ghidra headless server if not already running."""
        if self._ghidra_ready:
            # Quick health check
            try:
                resp = requests.get(f"{GHIDRA_BASE_URL}/check_connection", timeout=5)
                if resp.status_code == 200:
                    return
            except requests.ConnectionError:
                self._ghidra_ready = False

        if self._ghidra_process is None or self._ghidra_process.poll() is not None:
            self.logger.info("Starting Ghidra headless server...")

            # Ensure project directory exists
            Path(GHIDRA_PROJECT_DIR).mkdir(parents=True, exist_ok=True)

            # Start the headless server
            # bethington's fork uses GhidraMCPHeadlessServer as the main class
            classpath = self._build_classpath()
            cmd = [
                "java",
                "-Xmx4g",
                "-XX:+UseG1GC",
                f"-Dghidra.home={GHIDRA_HOME}",
                "-Dapplication.name=GhidraMCP",
                "-cp", classpath,
                "com.xebyte.headless.GhidraMCPHeadlessServer",
                "--port", str(GHIDRA_PORT),
                "--bind", "127.0.0.1",
            ]

            self._ghidra_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA_HOME},
            )

            # Wait for server to be ready (up to 60s for initial startup)
            for i in range(60):
                await asyncio.sleep(1)
                try:
                    resp = requests.get(f"{GHIDRA_BASE_URL}/check_connection", timeout=2)
                    if resp.status_code == 200:
                        self._ghidra_ready = True
                        self.logger.info(f"Ghidra headless server ready on port {GHIDRA_PORT}")
                        return
                except requests.ConnectionError:
                    pass

                # Check if process died
                if self._ghidra_process.poll() is not None:
                    stderr = self._ghidra_process.stderr.read().decode()
                    raise RuntimeError(f"Ghidra server failed to start: {stderr[:2000]}")

            raise RuntimeError("Ghidra server did not become ready within 60 seconds")

    def _build_classpath(self) -> str:
        """Build Java classpath from Ghidra installation.

        Matches bethington's entrypoint.sh pattern:
        GhidraMCP.jar + Framework/*/lib/*.jar + Features/*/lib/*.jar + Processors/*/lib/*.jar
        """
        jars = ["/app/GhidraMCP.jar"]
        ghidra_path = Path(GHIDRA_HOME) / "Ghidra"

        for category in ("Framework", "Features", "Processors"):
            category_path = ghidra_path / category
            if category_path.exists():
                for jar in category_path.glob("*/lib/*.jar"):
                    jars.append(str(jar))

        return ":".join(jars)

    async def _ensure_binary_loaded(self, binary_path: str):
        """Load a binary into Ghidra if not already loaded."""
        await self._ensure_ghidra_running()

        if binary_path in _loaded_binaries:
            return

        self.logger.info(f"Loading binary: {binary_path}")

        # Use the headless server's load endpoint
        result = self._ghidra_post("/load_program", {"file": binary_path}, timeout=120)
        # Check for error in response body (API may return 200 with error in body)
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(f"Failed to load binary: {result['error']}")

        # Wait for auto-analysis to complete by polling for functions
        self.logger.info("Waiting for Ghidra analysis to complete...")
        analysis_confirmed = False
        for i in range(60):
            await asyncio.sleep(2)
            try:
                resp = requests.get(
                    f"{GHIDRA_BASE_URL}/list_functions",
                    params={"limit": 1},
                    timeout=10,
                )
                if resp.status_code == 200 and resp.text.strip():
                    self.logger.info(f"Analysis complete after {(i + 1) * 2}s")
                    analysis_confirmed = True
                    break
            except Exception:
                pass

        _loaded_binaries[binary_path] = binary_path
        if not analysis_confirmed:
            _analysis_incomplete[binary_path] = True
            self.logger.warning("Analysis may not have completed within 120s — results may be partial")
        else:
            _analysis_incomplete[binary_path] = False
        self.logger.info(f"Binary loaded: {binary_path} (analysis_complete={analysis_confirmed})")

    def _ghidra_get(self, endpoint: str, params: Optional[Dict] = None, timeout: int = 30) -> Any:
        """Make a GET request to the Ghidra headless server."""
        try:
            resp = requests.get(
                f"{GHIDRA_BASE_URL}{endpoint}",
                params=params,
                timeout=timeout,
            )
            if resp.status_code == 200:
                try:
                    return resp.json()
                except json.JSONDecodeError:
                    return resp.text
            else:
                raise RuntimeError(f"Ghidra API error ({resp.status_code}): {resp.text[:500]}")
        except requests.ConnectionError:
            raise RuntimeError("Ghidra server not responding")
        except requests.Timeout:
            raise RuntimeError(f"Ghidra API timeout on {endpoint}")

    def _ghidra_post(self, endpoint: str, data: Optional[Dict] = None, timeout: int = 60) -> Any:
        """Make a POST request to the Ghidra headless server."""
        try:
            resp = requests.post(
                f"{GHIDRA_BASE_URL}{endpoint}",
                json=data or {},
                timeout=timeout,
            )
            if resp.status_code == 200:
                try:
                    return resp.json()
                except json.JSONDecodeError:
                    return resp.text
            else:
                raise RuntimeError(f"Ghidra API error ({resp.status_code}): {resp.text[:500]}")
        except requests.ConnectionError:
            raise RuntimeError("Ghidra server not responding")
        except requests.Timeout:
            raise RuntimeError(f"Ghidra API timeout on {endpoint}")

    # =========================================================================
    # Response parsers — Ghidra API returns plain text, not JSON
    # =========================================================================

    @staticmethod
    def _parse_function_list(text: str) -> List[Dict]:
        """Parse 'name @ address' lines into structured list."""
        functions = []
        for line in text.strip().splitlines():
            line = line.strip()
            if " @ " in line:
                name, address = line.rsplit(" @ ", 1)
                functions.append({"name": name.strip(), "address": address.strip()})
        return functions

    @staticmethod
    def _parse_string_list(text: str) -> List[Dict]:
        """Parse 'address: "string"' lines into structured list."""
        strings = []
        for line in text.strip().splitlines():
            line = line.strip()
            if ": " in line:
                address, value = line.split(": ", 1)
                strings.append({"address": address.strip(), "value": value.strip().strip('"')})
        return strings

    @staticmethod
    def _parse_import_list(text: str) -> List[Dict]:
        """Parse 'name -> source:address' lines into structured list."""
        imports = []
        for line in text.strip().splitlines():
            line = line.strip()
            if " -> " in line:
                name, target = line.split(" -> ", 1)
                imports.append({"name": name.strip(), "target": target.strip()})
        return imports

    @staticmethod
    def _parse_segment_list(text: str) -> List[Dict]:
        """Parse 'name: start - end' lines into structured list."""
        segments = []
        for line in text.strip().splitlines():
            line = line.strip()
            if ": " in line:
                name, rest = line.split(": ", 1)
                parts = rest.split(" - ")
                if len(parts) == 2:
                    segments.append({
                        "name": name.strip(),
                        "start": parts[0].strip(),
                        "end": parts[1].strip(),
                    })
        return segments

    @staticmethod
    def _parse_xref_list(text: str) -> List[Dict]:
        """Parse 'source -> target [type]' lines into structured list."""
        xrefs = []
        for line in text.strip().splitlines():
            line = line.strip()
            if " -> " in line:
                source, rest = line.split(" -> ", 1)
                ref_type = ""
                target = rest
                if "[" in rest and rest.endswith("]"):
                    target, ref_type = rest.rsplit(" [", 1)
                    ref_type = ref_type.rstrip("]")
                xrefs.append({
                    "source": source.strip(),
                    "target": target.strip(),
                    "type": ref_type,
                })
        return xrefs

    def _text_or_json(self, result: Any) -> str:
        """Convert result to string regardless of type."""
        if isinstance(result, str):
            return result
        return json.dumps(result, indent=2)

    @staticmethod
    def _analysis_warning(binary_path: str) -> Optional[str]:
        """Return a warning string if analysis was incomplete for this binary."""
        if _analysis_incomplete.get(binary_path):
            return "WARNING: Ghidra auto-analysis did not complete within 120s. Results may be incomplete — try again or load a smaller binary."
        return None

    # =========================================================================
    # MCP method handlers
    # =========================================================================

    async def load_binary(self, binary_path: str) -> ToolResult:
        """Load a binary into Ghidra and run auto-analysis."""
        try:
            await self._ensure_binary_loaded(binary_path)

            warning = self._analysis_warning(binary_path)
            raw = f"Binary loaded and analyzed: {binary_path}"
            if warning:
                raw = f"{warning}\n{raw}"

            return ToolResult(
                success=True,
                data={
                    "binary_path": binary_path,
                    "analyzed": not _analysis_incomplete.get(binary_path, False),
                    **({"warning": warning} if warning else {}),
                },
                raw_output=raw,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"binary_path": binary_path},
                error=str(e),
            )

    async def decompile_function(self, binary_path: str, name: str) -> ToolResult:
        """Decompile a function by name."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/decompile_function", {"name": name}, timeout=60)
            text = self._text_or_json(result)

            return ToolResult(
                success=True,
                data={"function": name, "decompiled": text},
                raw_output=text,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"function": name},
                error=str(e),
            )

    async def decompile_function_by_address(self, binary_path: str, address: str) -> ToolResult:
        """Decompile a function at a specific address."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/decompile_function", {"address": address}, timeout=60)
            text = self._text_or_json(result)

            return ToolResult(
                success=True,
                data={"address": address, "decompiled": text},
                raw_output=text,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"address": address},
                error=str(e),
            )

    async def list_functions(
        self,
        binary_path: str,
        offset: int = 0,
        limit: int = 100,
    ) -> ToolResult:
        """List all functions in the binary."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/list_functions", {"offset": offset, "limit": limit})
            all_functions = self._parse_function_list(result) if isinstance(result, str) else (result if isinstance(result, list) else [])

            # Apply pagination client-side (Ghidra plain text ignores limit param)
            functions = all_functions[offset:offset + limit]

            warning = self._analysis_warning(binary_path)
            raw = f"Found {len(functions)} functions (total: {len(all_functions)})"
            if warning:
                raw = f"{warning}\n{raw}"

            return ToolResult(
                success=True,
                data={
                    "functions": functions,
                    "count": len(functions),
                    "total": len(all_functions),
                    "offset": offset,
                    **({"warning": warning} if warning else {}),
                },
                raw_output=raw,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def search_functions_by_name(self, binary_path: str, query: str) -> ToolResult:
        """Search for functions by name substring."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/search_functions", {"query": query})
            functions = self._parse_function_list(result) if isinstance(result, str) else (result if isinstance(result, list) else [])

            return ToolResult(
                success=True,
                data={
                    "query": query,
                    "functions": functions,
                    "count": len(functions),
                },
                raw_output=f"Found {len(functions)} functions matching '{query}'",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"query": query},
                error=str(e),
            )

    async def get_xrefs_to(self, binary_path: str, address: str) -> ToolResult:
        """Get cross-references TO an address."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/get_xrefs_to", {"address": address})
            xrefs = self._parse_xref_list(result) if isinstance(result, str) else (result if isinstance(result, list) else [])

            return ToolResult(
                success=True,
                data={
                    "address": address,
                    "xrefs": xrefs,
                    "count": len(xrefs),
                },
                raw_output=f"Found {len(xrefs)} references to {address}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"address": address},
                error=str(e),
            )

    async def get_xrefs_from(self, binary_path: str, address: str) -> ToolResult:
        """Get cross-references FROM an address."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/get_xrefs_from", {"address": address})
            xrefs = self._parse_xref_list(result) if isinstance(result, str) else (result if isinstance(result, list) else [])

            return ToolResult(
                success=True,
                data={
                    "address": address,
                    "xrefs": xrefs,
                    "count": len(xrefs),
                },
                raw_output=f"Found {len(xrefs)} references from {address}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"address": address},
                error=str(e),
            )

    async def list_strings(
        self,
        binary_path: str,
        filter: Optional[str] = None,
        offset: int = 0,
        limit: int = 100,
    ) -> ToolResult:
        """Extract strings from the binary."""
        await self._ensure_binary_loaded(binary_path)

        try:
            params = {"offset": offset, "limit": limit}
            if filter:
                params["filter"] = filter

            result = self._ghidra_get("/list_strings", params)
            all_strings = self._parse_string_list(result) if isinstance(result, str) else (result if isinstance(result, list) else [])

            # Apply pagination client-side (Ghidra plain text may not paginate)
            strings = all_strings[offset:offset + limit]

            return ToolResult(
                success=True,
                data={
                    "strings": strings,
                    "count": len(strings),
                    "total": len(all_strings),
                    "filter": filter,
                },
                raw_output=f"Found {len(strings)} strings" + (f" matching '{filter}'" if filter else ""),
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def list_imports(self, binary_path: str) -> ToolResult:
        """List imported functions."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/list_imports")
            imports = self._parse_import_list(result) if isinstance(result, str) else (result if isinstance(result, list) else [])

            return ToolResult(
                success=True,
                data={
                    "imports": imports,
                    "count": len(imports),
                },
                raw_output=f"Found {len(imports)} imported functions",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def list_exports(self, binary_path: str) -> ToolResult:
        """List exported symbols."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/list_exports")
            exports = self._parse_function_list(result) if isinstance(result, str) else (result if isinstance(result, list) else [])

            return ToolResult(
                success=True,
                data={
                    "exports": exports,
                    "count": len(exports),
                },
                raw_output=f"Found {len(exports)} exported symbols",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def list_segments(self, binary_path: str) -> ToolResult:
        """List memory segments."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/list_segments")
            segments = self._parse_segment_list(result) if isinstance(result, str) else (result if isinstance(result, list) else [])

            return ToolResult(
                success=True,
                data={
                    "segments": segments,
                    "count": len(segments),
                },
                raw_output=f"Found {len(segments)} memory segments",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def disassemble_function(self, binary_path: str, address: str) -> ToolResult:
        """Get assembly code for a function."""
        await self._ensure_binary_loaded(binary_path)

        try:
            result = self._ghidra_get("/disassemble_function", {"address": address}, timeout=60)
            text = self._text_or_json(result)

            if not text.strip():
                return ToolResult(
                    success=False,
                    data={"address": address},
                    error="Disassembly returned empty. The Ghidra headless REST API does not support "
                          "disassemble_function reliably. Use decompile_function or "
                          "decompile_function_by_address instead to get C pseudocode.",
                )

            return ToolResult(
                success=True,
                data={"address": address, "assembly": text},
                raw_output=text,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"address": address},
                error=str(e),
            )


if __name__ == "__main__":
    GhidraServer.main()
