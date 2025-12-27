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

__version__ = "0.2.1"
__all__ = [
    "BaseMCPServer",
    "ToolResult",
    "ToolError",
    "parse_nmap_xml",
    "parse_json_output",
    "parse_table_output",
    "sanitize_output",
]
