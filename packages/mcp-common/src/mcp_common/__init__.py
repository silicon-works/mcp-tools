"""
MCP Common - Shared utilities for OpenSploit MCP tool servers.

This package provides base classes and utilities for building MCP servers
that wrap security tools for the OpenSploit platform.
"""

from .base_server import BaseMCPServer, ToolResult, ToolError
from .output_parsers import (
    parse_nmap_xml,
    parse_json_output,
    parse_table_output,
    sanitize_output,
)
from .run_cli_server import RunCliServer

__version__ = "0.4.0"
__all__ = [
    "BaseMCPServer",
    "RunCliServer",
    "ToolResult",
    "ToolError",
    "parse_nmap_xml",
    "parse_json_output",
    "parse_table_output",
    "sanitize_output",
]
