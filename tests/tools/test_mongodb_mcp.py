"""
Contract suite for mongodb (vendor-MCP swap to mongodb-js/mongodb-mcp-server).

Mirror of test_zap_mcp.py / test_metasploit_msfmcpd.py / test_playwright_mcp.py
patterns: boot the live container; assert tools/list shape matches the
offensive-tuned default surface (13 tools, atlas/create/update/delete deny-
listed); detect upstream-surface drift at version-bump time.

Tests do NOT require a real MongoDB target — they only exercise the MCP server
itself (tools/list, schemas, server self-identification). Live MongoDB
behaviors (connect/find/export end-to-end) are documented in scenarios.md from
manual one-call-per-turn verification.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from typing import Set

import pytest
import yaml

from conftest import MCPTestClient  # type: ignore

PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "mongodb"
IMAGE_LOCAL = "mcp-tools-mongodb:mongodb-mcp-test"
IMAGE_GHCR = "ghcr.io/silicon-works/mcp-tools-mongodb:latest"

# The 13-tool offensive-tuned default surface — verified live 2026-05-08
# pre-connect. Post-connect, `connect` rotates to `switch-connection`
# (dynamic slot toggle); the boot state the smoke test sees has `connect`.
EXPECTED_TOOLS_PRE_CONNECT: Set[str] = {
    "aggregate",
    "collection-indexes",
    "collection-schema",
    "collection-storage-size",
    "connect",
    "count",
    "db-stats",
    "explain",
    "export",
    "find",
    "list-collections",
    "list-databases",
    "mongodb-logs",
}

# Tools that MUST NOT appear in the default surface — destructive verbs
# (atlas/create/update/delete operation types). Each is excluded by the
# entrypoint's MDB_MCP_DISABLED_TOOLS=atlas,create,update,delete. If any
# leaks in, the agent could accidentally destroy target data during recon.
# Security-critical assertion.
MUST_NOT_APPEAR: Set[str] = {
    # Destructive verbs (write/destroy categories)
    "insert-many", "update-many", "delete-many",
    "create-collection", "drop-collection", "rename-collection",
    "drop-database",
    "create-index", "drop-index",
    # Atlas-* tools — silenced by 'atlas' category
    "atlas-list-clusters", "atlas-list-projects", "atlas-list-orgs",
    "atlas-create-cluster", "atlas-create-project", "atlas-create-db-user",
    "atlas-create-access-list", "atlas-connect-cluster",
    "atlas-inspect-cluster", "atlas-inspect-access-list",
    "atlas-get-performance-advisor",
    # switch-connection appears post-connect, NOT pre-connect (dynamic slot)
    "switch-connection",
}


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
        f"No mongodb image found locally. Build with: "
        f"docker build -f tools/mongodb/Dockerfile -t {IMAGE_LOCAL} ."
    )


@pytest.fixture(scope="module")
def mongodb_env():
    """Boot the container, complete MCP handshake, expose client."""
    image = _resolve_image()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = MCPTestClient(
        image=image,
        tool_name="mongodb",
        startup_timeout=30.0,
    )
    loop.run_until_complete(client.start())
    try:
        yield client, loop
    finally:
        loop.run_until_complete(client.stop())
        loop.close()


class TestMongodbSurface:
    """Verify upstream surface matches expectations + drift detection."""

    def test_server_identifies_as_mongodb_mcp_server(self, mongodb_env):
        """Server self-reports as 'MongoDB MCP Server' v0.3.x."""
        client, _ = mongodb_env
        info = client.server_info
        assert info.get("name") == "MongoDB MCP Server", (
            f"Expected 'MongoDB MCP Server', got {info.get('name')!r}. "
            f"Upstream may have renamed — check vendor README."
        )
        ver = info.get("version", "")
        assert ver.startswith("0."), (
            f"Expected v0.x version (npm pin @^0), got {ver!r}. "
            f"Bump Dockerfile to @^1 + rerun suite to absorb drift."
        )

    def test_default_tool_count_is_thirteen_pre_connect(self, mongodb_env):
        """The default offensive-tuned surface is exactly 13 tools."""
        client, _ = mongodb_env
        names = sorted(t["name"] for t in client.tools)
        assert len(names) == 13, (
            f"Expected 13-tool default surface, got {len(names)}. "
            f"Surface drift: {names}. Vendor may have added/removed tools — "
            f"update EXPECTED_TOOLS_PRE_CONNECT to match."
        )

    def test_default_surface_matches_canonical_set(self, mongodb_env):
        """Pre-connect tool set is exactly the expected 13."""
        client, _ = mongodb_env
        names = {t["name"] for t in client.tools}
        missing = EXPECTED_TOOLS_PRE_CONNECT - names
        unexpected = names - EXPECTED_TOOLS_PRE_CONNECT
        assert not missing, f"Missing expected tools: {missing}"
        assert not unexpected, (
            f"Unexpected tools in default surface: {unexpected}. "
            f"Either upstream added new read/connect/metadata tools (update "
            f"EXPECTED_TOOLS_PRE_CONNECT) or the deny-list filter changed."
        )

    def test_destructive_tools_are_not_in_default_surface(self, mongodb_env):
        """Security-critical: no insert/update/delete/atlas in tools/list."""
        client, _ = mongodb_env
        names = {t["name"] for t in client.tools}
        leaked = names & MUST_NOT_APPEAR
        assert not leaked, (
            f"DESTRUCTIVE TOOL LEAKED to default surface: {leaked}. "
            f"The MDB_MCP_DISABLED_TOOLS deny-list in entrypoint.sh is not "
            f"taking effect. Verify entrypoint env exports."
        )

    def test_each_tool_has_input_schema(self, mongodb_env):
        """Every tool advertises an inputSchema with type:object."""
        client, _ = mongodb_env
        for tool in client.tools:
            assert "inputSchema" in tool, f"{tool['name']}: missing inputSchema"
            schema = tool["inputSchema"]
            assert schema.get("type") == "object", (
                f"{tool['name']}: inputSchema.type should be 'object'"
            )

    def test_connect_tool_schema_requires_connection_string(self, mongodb_env):
        """`connect` requires connectionString (offensive flow needs URI per call)."""
        client, _ = mongodb_env
        connect = next(t for t in client.tools if t["name"] == "connect")
        required = set(connect.get("inputSchema", {}).get("required", []))
        assert "connectionString" in required, (
            "connect must require connectionString — agent always passes URI per engagement"
        )

    def test_export_tool_target_is_array_of_objects(self, mongodb_env):
        """`export.exportTarget` is array of cursor-spec objects (not string)."""
        client, _ = mongodb_env
        export = next(t for t in client.tools if t["name"] == "export")
        target = export.get("inputSchema", {}).get("properties", {}).get("exportTarget", {})
        assert target.get("type") == "array", (
            "exportTarget must be array — verified live 2026-05-08 that "
            "string and array-of-strings both fail validation."
        )

    def test_find_tool_has_projection_for_cred_hunt(self, mongodb_env):
        """`find` exposes projection — required for credential-hunt composition."""
        client, _ = mongodb_env
        find = next(t for t in client.tools if t["name"] == "find")
        props = find.get("inputSchema", {}).get("properties", {})
        assert "projection" in props, (
            "find must expose `projection` param — the credential-hunt usage_pattern "
            "depends on it (project to {password:1, hash:1, api_key:1, ...})."
        )


class TestMongodbToolYamlContract:
    """Verify tool.yaml matches the runtime contract."""

    def test_tool_yaml_kind_is_mcp(self):
        """tool.yaml declares kind:mcp explicitly."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("kind") == "mcp", (
            "tool.yaml MUST declare kind:mcp explicitly (mirrors metasploit/zap/playwright pattern)"
        )

    def test_tool_yaml_image_matches_ghcr_path(self):
        """Image tag in tool.yaml matches the container image we publish."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("image") == IMAGE_GHCR, (
            f"tool.yaml image={d.get('image')!r} does not match published "
            f"image {IMAGE_GHCR!r}. CI and tool.yaml drift apart silently."
        )

    def test_tool_yaml_source_url_points_at_vendor(self):
        """source field points at the upstream vendor repo (not a fork)."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        source = d.get("source", "")
        assert source == "https://github.com/mongodb-js/mongodb-mcp-server", (
            f"source URL must point at vendor repo, got {source!r}"
        )

    def test_tool_yaml_idle_timeout_is_set(self):
        """idle_timeout_seconds is documented (mongodb is interactive recon, not one-shot)."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("idle_timeout_seconds", 0) >= 600, (
            "idle_timeout_seconds should be >=600s for interactive recon flows"
        )

    def test_tool_yaml_declares_service_mode(self):
        """mongodb is service:true — connection state held in-process across MCP calls.

        Without service:true ContainerManager spawns a fresh container per
        JSON-RPC call, so the post-connect surface (switch-connection,
        find/aggregate/etc against the active connection) is unreachable.
        Mirrors zap/playwright/metasploit/prowler pattern for stateful kind:mcp tools.
        """
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("service") is True, (
            "tool.yaml MUST declare service:true — mongodb holds connection state "
            "across calls (connect → list-databases → find pattern requires container persistence)."
        )
        assert d.get("service_name") == "mongodb", (
            f"tool.yaml service_name must be 'mongodb', got {d.get('service_name')!r}"
        )

    def test_tool_yaml_methods_match_runtime_surface(self, mongodb_env):
        """Every runtime tool is documented; tool.yaml may also document switch-connection (dynamic slot)."""
        client, _ = mongodb_env
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        documented = set(d.get("methods", {}).keys())
        runtime_pre_connect = {t["name"] for t in client.tools}
        runtime_minus_documented = runtime_pre_connect - documented
        assert runtime_minus_documented == set(), (
            f"Runtime tools NOT in tool.yaml: {runtime_minus_documented}. "
            f"Document them with `description` + `when_to_use` + `params`."
        )
        # tool.yaml may document switch-connection (post-connect slot) even
        # though runtime only shows connect pre-connect — that's expected.
        documented_minus_runtime = documented - runtime_pre_connect
        assert documented_minus_runtime.issubset({"switch-connection"}), (
            f"tool.yaml documents methods that don't exist at runtime: "
            f"{documented_minus_runtime - {'switch-connection'}}. "
            f"Either runtime dropped them or the docs are stale."
        )
