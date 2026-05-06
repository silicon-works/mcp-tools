"""
Smoke test for the metasploit MCP tool — Rapid7's msfmcpd as a kind:mcp.

This is a kind:mcp wrapper, not a kind:cli — there's no Python tool surface
to unit-test. The contract is "container starts, advertises the 8 upstream
tools, no method-name regressions". That's all we own; everything else is
upstream's responsibility.

Skipped automatically if the local image isn't built (CI builds it explicitly
in the metasploit job).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Set

import pytest
import yaml

PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "metasploit"
IMAGE_LOCAL = "mcp-tools-metasploit:msfmcpd-test"
IMAGE_GHCR = "ghcr.io/silicon-works/mcp-tools-metasploit:latest"

# Upstream-canonical tool names (Rapid7 msfmcpd, May 2026).
# This set is the contract. If it ever drifts, that's intentional upstream
# evolution and tool.yaml needs to be updated to match.
EXPECTED_TOOLS: Set[str] = {
    "msf_search_modules",
    "msf_module_info",
    "msf_host_info",
    "msf_service_info",
    "msf_vulnerability_info",
    "msf_note_info",
    "msf_credential_info",
    "msf_loot_info",
}

from conftest import MCPTestClient


def _resolve_image() -> str:
    """Pick whichever image tag exists locally; skip the test if neither does."""
    for tag in (IMAGE_LOCAL, IMAGE_GHCR):
        result = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True,
        )
        if result.returncode == 0:
            return tag
    pytest.skip(
        f"No metasploit image found locally. Build with: "
        f"docker build -f tools/metasploit/Dockerfile -t {IMAGE_LOCAL} ."
    )


@pytest.fixture(scope="module")
def msf_env():
    """Boot the container, complete MCP handshake, expose client + loop."""
    image = _resolve_image()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = MCPTestClient(
        image=image,
        tool_name="metasploit",
        startup_timeout=180.0,  # postgres + msfdb init + msfrpcd auto-spawn
    )
    loop.run_until_complete(client.start())
    try:
        yield client, loop
    finally:
        loop.run_until_complete(client.stop())
        loop.close()


class TestMsfmcpdSurface:
    """The container exposes exactly the upstream-canonical 8 tools."""

    def test_tool_count(self, msf_env):
        client, _ = msf_env
        assert len(client.tools) == len(EXPECTED_TOOLS), (
            f"Expected {len(EXPECTED_TOOLS)} tools (upstream surface), "
            f"got {len(client.tools)}: {[t['name'] for t in client.tools]}"
        )

    def test_tool_names_match_upstream(self, msf_env):
        client, _ = msf_env
        actual = {t["name"] for t in client.tools}
        missing = EXPECTED_TOOLS - actual
        extra = actual - EXPECTED_TOOLS
        assert not missing and not extra, (
            f"Tool name drift from upstream. missing={missing} extra={extra}"
        )

    def test_each_tool_has_input_schema(self, msf_env):
        client, _ = msf_env
        for tool in client.tools:
            assert "inputSchema" in tool, f"{tool['name']}: missing inputSchema"
            schema = tool["inputSchema"]
            assert schema.get("type") == "object", (
                f"{tool['name']}: inputSchema.type should be 'object'"
            )

    def test_search_modules_requires_query(self, msf_env):
        client, _ = msf_env
        spec = next(t for t in client.tools if t["name"] == "msf_search_modules")
        required = spec["inputSchema"].get("required", [])
        assert "query" in required, (
            "msf_search_modules schema must mark 'query' as required"
        )

    def test_module_info_requires_type_and_name(self, msf_env):
        client, _ = msf_env
        spec = next(t for t in client.tools if t["name"] == "msf_module_info")
        required = set(spec["inputSchema"].get("required", []))
        assert {"type", "name"}.issubset(required), (
            f"msf_module_info schema must require 'type' and 'name'; got {required}"
        )


class TestToolYamlContract:
    """tool.yaml advertises the same 8 method names msfmcpd actually exposes.

    Drift here would mean opensploit's tool-registry-search would route to
    method names that don't exist, returning Unknown method at runtime.
    """

    def setup_method(self, _):
        self.tool_yaml = yaml.safe_load((TOOL_DIR / "tool.yaml").read_text())

    def test_method_names_match_upstream(self):
        declared = set((self.tool_yaml.get("methods") or {}).keys())
        missing = EXPECTED_TOOLS - declared
        extra = declared - EXPECTED_TOOLS
        assert not missing and not extra, (
            f"tool.yaml.methods drift from upstream msfmcpd. "
            f"missing={missing} extra={extra}"
        )

    def test_image_tag_matches_ghcr_publish_target(self):
        # Convention across mcp-tools: image: ghcr.io/silicon-works/mcp-tools-<name>:latest
        assert self.tool_yaml.get("image") == IMAGE_GHCR

    def test_service_mode_declared(self):
        # msfmcpd holds a long-running msfrpcd inside; container must run as
        # service (not per-call ephemeral) so DB state persists across tools
        # within an engagement.
        assert self.tool_yaml.get("service") is True
