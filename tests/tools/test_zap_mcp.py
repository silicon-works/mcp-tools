"""
Smoke test for the zap MCP tool — OWASP ZAP MCP Integration add-on as a kind:mcp.

This is a kind:mcp wrapper around upstream's official add-on (zaproxy
zap-extensions, mcp-v0.0.1, alpha April 2026). The container hybrid-installs
the add-on jar into ZAP's plugin dir and runs a stdio↔HTTP bridge so
opensploit's stdio-based ContainerManager talks to ZAP's HTTP-only MCP
endpoint transparently.

The contract this suite validates: container starts, advertises the 14
upstream tools, no method-name regressions, tool.yaml-vs-runtime parity.

Skipped automatically if the local image isn't built (CI builds it
explicitly in the zap job).
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Set

import pytest
import yaml

PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "zap"
IMAGE_LOCAL = "mcp-tools-zap:zap-mcp-test"
IMAGE_GHCR = "ghcr.io/silicon-works/mcp-tools-zap:latest"

# Upstream-canonical tool names (zap-extensions/addOns/mcp/mcp-v0.0.1).
# 14 concrete tools — ZapStartScanTool.java is an abstract base class that
# is NOT registered with the toolRegistry (see ExtensionMcp.hook()), only
# the concrete Start*Tool subclasses are.
EXPECTED_TOOLS: Set[str] = {
    "zap_version",
    "zap_info",
    "zap_create_context",
    "zap_start_spider",
    "zap_stop_spider",
    "zap_get_spider_status",
    "zap_start_ajax_spider",
    "zap_stop_ajax_spider",
    "zap_get_ajax_spider_status",
    "zap_start_active_scan",
    "zap_stop_active_scan",
    "zap_get_active_scan_status",
    "zap_get_passive_scan_status",
    "zap_generate_report",
}

from conftest import MCPTestClient


def _resolve_image() -> str:
    """Pick whichever image tag exists locally; skip if neither does."""
    for tag in (IMAGE_LOCAL, IMAGE_GHCR):
        result = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True,
        )
        if result.returncode == 0:
            return tag
    pytest.skip(
        f"No zap image found locally. Build with: "
        f"docker build -f tools/zap/Dockerfile -t {IMAGE_LOCAL} ."
    )


@pytest.fixture(scope="module")
def zap_env():
    """Boot the container, complete MCP handshake, expose client + loop."""
    image = _resolve_image()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = MCPTestClient(
        image=image,
        tool_name="zap",
        startup_timeout=180.0,  # ZAP cold start ~30s + JVM + add-on load + bridge
    )
    loop.run_until_complete(client.start())
    try:
        yield client, loop
    finally:
        loop.run_until_complete(client.stop())
        loop.close()


class TestZapMcpSurface:
    """The container exposes exactly the upstream-canonical 14 tools."""

    def test_tool_count(self, zap_env):
        client, _ = zap_env
        assert len(client.tools) == len(EXPECTED_TOOLS), (
            f"Expected {len(EXPECTED_TOOLS)} tools (upstream surface), "
            f"got {len(client.tools)}: {sorted(t['name'] for t in client.tools)}"
        )

    def test_tool_names_match_upstream(self, zap_env):
        client, _ = zap_env
        actual = {t["name"] for t in client.tools}
        missing = EXPECTED_TOOLS - actual
        extra = actual - EXPECTED_TOOLS
        assert not missing and not extra, (
            f"Tool name drift from upstream. missing={missing} extra={extra}"
        )

    def test_each_tool_has_input_schema(self, zap_env):
        client, _ = zap_env
        for tool in client.tools:
            assert "inputSchema" in tool, f"{tool['name']}: missing inputSchema"
            schema = tool["inputSchema"]
            assert schema.get("type") == "object", (
                f"{tool['name']}: inputSchema.type should be 'object'"
            )

    def test_create_context_requires_name_and_url(self, zap_env):
        client, _ = zap_env
        spec = next(t for t in client.tools if t["name"] == "zap_create_context")
        required = set(spec["inputSchema"].get("required", []))
        assert {"name", "url"}.issubset(required), (
            f"zap_create_context schema must require 'name' and 'url'; got {required}"
        )

    def test_start_spider_requires_target(self, zap_env):
        client, _ = zap_env
        for tool_name in ("zap_start_spider", "zap_start_ajax_spider", "zap_start_active_scan"):
            spec = next(t for t in client.tools if t["name"] == tool_name)
            required = set(spec["inputSchema"].get("required", []))
            assert "target" in required, (
                f"{tool_name} schema must require 'target'; got {required}"
            )

    def test_status_and_stop_verbs_require_scan_id(self, zap_env):
        client, _ = zap_env
        scan_id_verbs = {
            "zap_get_spider_status",
            "zap_get_ajax_spider_status",
            "zap_get_active_scan_status",
            "zap_stop_spider",
            "zap_stop_ajax_spider",
            "zap_stop_active_scan",
        }
        for tool_name in scan_id_verbs:
            spec = next(t for t in client.tools if t["name"] == tool_name)
            required = set(spec["inputSchema"].get("required", []))
            assert "scan_id" in required, (
                f"{tool_name} schema must require 'scan_id'; got {required}"
            )


class TestToolYamlContract:
    """tool.yaml advertises the same 14 method names ZAP MCP actually exposes.

    Drift would mean opensploit's tool-registry-search would route to method
    names that don't exist, returning 'Unknown method' at runtime.
    """

    def setup_method(self, _):
        self.tool_yaml = yaml.safe_load((TOOL_DIR / "tool.yaml").read_text())

    def test_method_names_match_upstream(self):
        declared = set((self.tool_yaml.get("methods") or {}).keys())
        missing = EXPECTED_TOOLS - declared
        extra = declared - EXPECTED_TOOLS
        assert not missing and not extra, (
            f"tool.yaml.methods drift from upstream zap-mcp. "
            f"missing={missing} extra={extra}"
        )

    def test_image_tag_matches_ghcr_publish_target(self):
        # Convention across mcp-tools: image: ghcr.io/silicon-works/mcp-tools-<name>:latest
        assert self.tool_yaml.get("image") == IMAGE_GHCR

    def test_service_mode_declared(self):
        # ZAP holds long-running scan state (sites tree, alerts, contexts);
        # container must run as service so state persists across MCP calls
        # within an engagement.
        assert self.tool_yaml.get("service") is True

    def test_idle_timeout_long_enough_for_scans(self):
        # Active scans run for minutes to hours; idle_timeout must outlast a
        # typical scan to avoid container eviction mid-scan.
        idle = self.tool_yaml.get("idle_timeout_seconds")
        assert idle is not None and idle >= 600, (
            f"zap idle_timeout_seconds should be ≥600s for scan-friendly lifetime; got {idle}"
        )
