"""
RunCliServer — shared MCP server launcher for kind:cli tools.

Most kind:cli tools (curl, sqlmap, nmap, ffuf, …) need no per-tool server code:
the LLM emits a raw argv string, ``cli_in_container`` in the plugin handles
target extraction / scope validation / reject_flags, and the container just
needs to exec the binary and stream the output back. ``BaseMCPServer`` already
auto-registers the ``run_cli`` method that does exactly that.

Before this module each kind:cli tool carried a `mcp-server.py` whose only
purpose was ``class FooServer(BaseMCPServer): super().__init__("foo", ...)``
plus several hundred lines of per-tool method handlers that Feature 35
deprecated. ``RunCliServer`` collapses the still-needed half — the boot
boilerplate — into a single class so every kind:cli tool's server file is
two lines.

Usage in a tool's ``mcp-server.py``::

    from mcp_common import RunCliServer
    RunCliServer.serve("curl", "HTTP client for web requests …")

The full (now legacy) per-tool handler classes remain in git history for any
tool whose structured methods later prove worth resurrecting.
"""

from __future__ import annotations

import asyncio

from .base_server import BaseMCPServer


class RunCliServer(BaseMCPServer):
    """Concrete BaseMCPServer with no methods beyond the auto-registered run_cli.

    BaseMCPServer's ``__init__`` registers ``run_cli`` (and ``verify_clock``
    when ``MCP_TEST_MODE`` is set) for every subclass, so this class adds
    nothing — it exists to give kind:cli tools a non-abstract entry point
    that doesn't require declaring an empty subclass per tool.
    """

    @classmethod
    def serve(cls, name: str, description: str, version: str = "1.0.0") -> None:
        """Construct, run, and block until the server exits.

        This is the entry point for kind:cli tools' ``mcp-server.py`` files.
        Wraps ``asyncio.run()`` so the stub stays a one-liner.

        Args:
            name: Tool name (must match the tool.yaml ``name:`` field).
            description: One-line human description (shown to the LLM in
                tools/list responses; the registry-side description is the
                source of truth for agent-visible metadata).
            version: Semantic version string. Defaults to ``"1.0.0"``.
        """
        asyncio.run(cls(name, description, version=version).run())
