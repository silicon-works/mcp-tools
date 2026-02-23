"""
Base MCP Server implementation for OpenSploit tool servers.

Provides a foundation for building MCP servers that wrap security tools.
"""

import asyncio
import json
import logging
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
    CallToolResult,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


@dataclass
class ToolResult:
    """Result from a tool execution."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None

    def to_content(self) -> List[TextContent]:
        """Convert result to MCP TextContent."""
        if self.success:
            # Include raw_output in successful results when present
            result_data = dict(self.data)
            if self.raw_output:
                result_data["raw_output"] = self.raw_output
            return [TextContent(type="text", text=json.dumps(result_data, indent=2))]
        else:
            return [TextContent(type="text", text=f"Error: {self.error}\n\nRaw output:\n{self.raw_output}")]


@dataclass
class ToolError(Exception):
    """Error during tool execution."""
    message: str
    details: Optional[str] = None

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


@dataclass
class MethodDefinition:
    """Definition of a tool method."""
    name: str
    description: str
    params: Dict[str, Dict[str, Any]]
    handler: Callable


class BaseMCPServer(ABC):
    """
    Base class for MCP tool servers.

    Subclass this to create MCP servers for specific security tools.

    Example:
        class NmapServer(BaseMCPServer):
            def __init__(self):
                super().__init__("nmap", "Network scanner")
                self.register_method(
                    name="port_scan",
                    description="Scan for open ports",
                    params={...},
                    handler=self.port_scan
                )

            async def port_scan(self, target: str, ports: str = "1-1000") -> ToolResult:
                ...
    """

    def __init__(self, name: str, description: str, version: str = "1.0.0"):
        self.name = name
        self.description = description
        self.version = version
        self.methods: Dict[str, MethodDefinition] = {}
        self.logger = logging.getLogger(f"mcp.{name}")
        self._server: Optional[Server] = None

    def register_method(
        self,
        name: str,
        description: str,
        params: Dict[str, Dict[str, Any]],
        handler: Callable,
    ) -> None:
        """
        Register a tool method.

        Args:
            name: Method name (e.g., "port_scan")
            description: Human-readable description
            params: Parameter definitions with types and descriptions
            handler: Async function to handle the method call
        """
        self.methods[name] = MethodDefinition(
            name=name,
            description=description,
            params=params,
            handler=handler,
        )
        self.logger.info(f"Registered method: {name}")

    def _build_input_schema(self, params: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Build JSON schema from parameter definitions."""
        properties = {}
        required = []

        for param_name, param_def in params.items():
            param_type = param_def.get("type", "string")

            # Handle enum type - JSON Schema uses type: "string" with enum array
            if param_type == "enum":
                prop = {
                    "type": "string",
                    "description": param_def.get("description", ""),
                }
                # Support both "values" (our convention) and "enum" keys
                if "values" in param_def:
                    prop["enum"] = param_def["values"]
                elif "enum" in param_def:
                    prop["enum"] = param_def["enum"]
            else:
                prop = {
                    "type": param_type,
                    "description": param_def.get("description", ""),
                }
                if "enum" in param_def:
                    prop["enum"] = param_def["enum"]

            if "default" in param_def:
                prop["default"] = param_def["default"]
            if "items" in param_def:
                prop["items"] = param_def["items"]

            properties[param_name] = prop

            if param_def.get("required", False):
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    async def run_command(
        self,
        cmd: List[str],
        timeout: int = 300,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Run a shell command asynchronously.

        Args:
            cmd: Command and arguments as list
            timeout: Timeout in seconds
            check: Raise exception on non-zero exit

        Returns:
            CompletedProcess with stdout and stderr
        """
        self.logger.info(f"Running command: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            result = subprocess.CompletedProcess(
                args=cmd,
                returncode=proc.returncode or 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
            )

            if check and result.returncode != 0:
                raise ToolError(
                    message=f"Command failed with exit code {result.returncode}",
                    details=result.stderr,
                )

            return result

        except asyncio.TimeoutError:
            raise ToolError(
                message=f"Command timed out after {timeout} seconds",
                details=" ".join(cmd),
            )

    async def _handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle an incoming tool call."""
        if name not in self.methods:
            available_methods = list(self.methods.keys())
            error_msg = f"Unknown method: '{name}'\n\nAvailable methods for {self.name}:\n"
            for method_name in available_methods:
                method = self.methods[method_name]
                error_msg += f"  - {method_name}: {method.description}\n"
            error_msg += f"\nUse tool_registry_search to find the correct method name."
            return CallToolResult(
                content=[TextContent(type="text", text=error_msg)],
                isError=True,
            )

        method = self.methods[name]
        self.logger.info(f"Handling call to {name} with args: {arguments}")

        try:
            result = await method.handler(**arguments)

            if isinstance(result, ToolResult):
                return CallToolResult(
                    content=result.to_content(),
                    isError=not result.success,
                )
            else:
                # Assume raw dict/string response
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(result, indent=2) if isinstance(result, dict) else str(result))],
                    isError=False,
                )

        except ToolError as e:
            self.logger.error(f"Tool error in {name}: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True,
            )
        except Exception as e:
            self.logger.exception(f"Unexpected error in {name}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Internal error: {str(e)}")],
                isError=True,
            )

    def _get_tools(self) -> List[Tool]:
        """Get list of available tools for MCP."""
        tools = []
        for method in self.methods.values():
            tools.append(Tool(
                name=method.name,
                description=method.description,
                inputSchema=self._build_input_schema(method.params),
            ))
        return tools

    async def run(self) -> None:
        """Start the MCP server."""
        self._server = Server(self.name)

        @self._server.list_tools()
        async def list_tools() -> List[Tool]:
            return self._get_tools()

        @self._server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            return await self._handle_tool_call(name, arguments)

        self.logger.info(f"Starting {self.name} MCP server v{self.version}")

        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(
                read_stream,
                write_stream,
                self._server.create_initialization_options(),
            )

    @classmethod
    def main(cls) -> None:
        """Entry point for running the server."""
        server = cls()
        asyncio.run(server.run())
