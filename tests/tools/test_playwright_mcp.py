"""
Smoke test for the playwright MCP tool — Microsoft's official @playwright/mcp
npm package as a kind:mcp.

This is a vendor MCP wrapper around upstream's @playwright/mcp v0.0.75. The
container speaks MCP-over-stdio natively; no bridge is needed (unlike ZAP).

The contract this suite validates: container starts, advertises the 44
upstream tools, no method-name regressions, tool.yaml-vs-runtime parity.

Skipped automatically if the local image isn't built (CI builds it
explicitly in the playwright job).
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Set

import pytest
import yaml

PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "playwright"
IMAGE_LOCAL = "mcp-tools-playwright:standardize-test"
IMAGE_GHCR = "ghcr.io/silicon-works/mcp-tools-playwright:latest"

# Upstream-canonical tool names (@playwright/mcp v0.0.75 with
# --caps=vision,pdf,devtools,testing). Validated 2026-05-08.
EXPECTED_TOOLS: Set[str] = {
    # Navigation
    "browser_navigate", "browser_navigate_back", "browser_close",
    # Snapshot + screenshots + PDF
    "browser_snapshot", "browser_take_screenshot", "browser_pdf_save",
    # Console + network
    "browser_console_messages", "browser_network_requests", "browser_network_request",
    # Element interaction
    "browser_click", "browser_type", "browser_fill_form", "browser_press_key",
    "browser_hover", "browser_select_option", "browser_handle_dialog",
    "browser_file_upload", "browser_drag", "browser_drop",
    # Vision-mode mouse (vision cap)
    "browser_mouse_click_xy", "browser_mouse_move_xy", "browser_mouse_drag_xy",
    "browser_mouse_down", "browser_mouse_up", "browser_mouse_wheel",
    # Window / waits
    "browser_resize", "browser_wait_for", "browser_resume",
    # Verify primitives (testing cap)
    "browser_verify_element_visible", "browser_verify_list_visible",
    "browser_verify_text_visible", "browser_verify_value",
    # JS evaluation
    "browser_evaluate", "browser_run_code_unsafe",
    # Multi-tab
    "browser_tabs",
    # Tracing
    "browser_start_tracing", "browser_stop_tracing",
    # Video
    "browser_start_video", "browser_stop_video", "browser_video_chapter",
    # Highlight / locator (testing cap)
    "browser_highlight", "browser_hide_highlight", "browser_annotate",
    "browser_generate_locator",
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
        f"No playwright image found locally. Build with: "
        f"docker build -f tools/playwright/Dockerfile -t {IMAGE_LOCAL} ."
    )


@pytest.fixture(scope="module")
def pw_env():
    """Boot the container, complete MCP handshake, expose client + loop."""
    image = _resolve_image()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = MCPTestClient(
        image=image,
        tool_name="playwright",
        startup_timeout=180.0,  # Node + Chromium spawn ~10-15s + safety margin
    )
    loop.run_until_complete(client.start())
    try:
        yield client, loop
    finally:
        loop.run_until_complete(client.stop())
        loop.close()


class TestPlaywrightSurface:
    """The container exposes exactly the upstream-canonical 44 tools."""

    def test_tool_count(self, pw_env):
        client, _ = pw_env
        assert len(client.tools) == len(EXPECTED_TOOLS), (
            f"Expected {len(EXPECTED_TOOLS)} tools (upstream surface), "
            f"got {len(client.tools)}: {sorted(t['name'] for t in client.tools)}"
        )

    def test_tool_names_match_upstream(self, pw_env):
        client, _ = pw_env
        actual = {t["name"] for t in client.tools}
        missing = EXPECTED_TOOLS - actual
        extra = actual - EXPECTED_TOOLS
        assert not missing and not extra, (
            f"Tool name drift from upstream. missing={missing} extra={extra}"
        )

    def test_each_tool_has_input_schema(self, pw_env):
        client, _ = pw_env
        for tool in client.tools:
            assert "inputSchema" in tool, f"{tool['name']}: missing inputSchema"
            schema = tool["inputSchema"]
            assert schema.get("type") == "object", (
                f"{tool['name']}: inputSchema.type should be 'object'"
            )

    def test_navigate_requires_url(self, pw_env):
        client, _ = pw_env
        spec = next(t for t in client.tools if t["name"] == "browser_navigate")
        required = set(spec["inputSchema"].get("required", []))
        assert "url" in required, (
            f"browser_navigate must require 'url'; got required={required}"
        )

    def test_click_requires_target(self, pw_env):
        client, _ = pw_env
        for tool_name in ("browser_click", "browser_hover", "browser_type",
                           "browser_select_option", "browser_drag"):
            spec = next(t for t in client.tools if t["name"] == tool_name)
            required = set(spec["inputSchema"].get("required", []))
            # browser_drag uses startTarget/endTarget instead of target
            target_keys = {"target", "startTarget"}
            assert target_keys & required, (
                f"{tool_name} must require some target arg; got required={required}"
            )

    def test_vision_xy_tools_require_coords(self, pw_env):
        client, _ = pw_env
        for tool_name in ("browser_mouse_click_xy", "browser_mouse_move_xy"):
            spec = next(t for t in client.tools if t["name"] == tool_name)
            required = set(spec["inputSchema"].get("required", []))
            assert {"x", "y"}.issubset(required), (
                f"{tool_name} must require x and y; got required={required}"
            )

    def test_drag_xy_requires_start_and_end(self, pw_env):
        client, _ = pw_env
        spec = next(t for t in client.tools if t["name"] == "browser_mouse_drag_xy")
        required = set(spec["inputSchema"].get("required", []))
        assert {"startX", "startY", "endX", "endY"}.issubset(required), (
            f"browser_mouse_drag_xy schema drift; got required={required}"
        )


class TestToolYamlContract:
    """tool.yaml advertises the same 44 method names @playwright/mcp actually exposes.

    Drift would mean opensploit's tool-registry-search would route to
    method names that don't exist, returning 'Unknown method' at runtime.
    """

    def setup_method(self, _):
        self.tool_yaml = yaml.safe_load((TOOL_DIR / "tool.yaml").read_text())

    def test_method_names_match_upstream(self):
        declared = set((self.tool_yaml.get("methods") or {}).keys())
        missing = EXPECTED_TOOLS - declared
        extra = declared - EXPECTED_TOOLS
        assert not missing and not extra, (
            f"tool.yaml.methods drift from upstream playwright-mcp. "
            f"missing={missing} extra={extra}"
        )

    def test_image_tag_matches_ghcr_publish_target(self):
        # Convention across mcp-tools: image: ghcr.io/silicon-works/mcp-tools-<name>:latest
        assert self.tool_yaml.get("image") == IMAGE_GHCR

    def test_kind_mcp_declared(self):
        # Standardization: kind: mcp explicit (not relying on default).
        assert self.tool_yaml.get("kind") == "mcp"

    def test_service_mode_declared(self):
        # Browser sessions hold real state (cookies, page DOM, refs); container
        # must run as service so state persists across MCP calls.
        assert self.tool_yaml.get("service") is True

    def test_idle_timeout_long_enough_for_browser_flows(self):
        # Multi-step browser flows (login → navigate → fill → submit → wait)
        # routinely span minutes; idle_timeout must outlast typical interactive
        # session.
        idle = self.tool_yaml.get("idle_timeout_seconds")
        assert idle is not None and idle >= 600, (
            f"playwright idle_timeout_seconds should be ≥600s; got {idle}"
        )
