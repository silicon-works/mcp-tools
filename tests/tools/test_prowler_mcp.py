"""
Contract suite for prowler (vendor-MCP swap to prowler-cloud/prowler's mcp_server).

Mirror of mongodb's sync-fixture pattern. Boots the FULL bundled stack
(postgres + redis + dozerdb + django + celery + mcp-server) — cold start
is ~7 min on first boot due to 90+ Django migrations on a fresh DB.

Tests do NOT require connected cloud providers — they only exercise the
MCP server itself (tools/list shape, schemas, server self-identification,
auth-flow plumbing). Live cloud-side behaviors (connect_provider,
trigger_scan, search_security_findings end-to-end) are documented in
scenarios.md from manual one-call-per-turn verification.
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
TOOL_DIR = PROJECT_ROOT / "tools" / "prowler"
IMAGE_LOCAL = "mcp-tools-prowler:dev"
IMAGE_GHCR = "ghcr.io/silicon-works/mcp-tools-prowler:latest"

# 41-tool surface verified live 2026-05-09 against bundled stack.
EXPECTED_TOOLS_BY_NAMESPACE = {
    "prowler_hub_": frozenset({
        "prowler_hub_list_checks",
        "prowler_hub_semantic_search_checks",
        "prowler_hub_get_check_details",
        "prowler_hub_get_check_code",
        "prowler_hub_get_check_fixer",
        "prowler_hub_list_compliances",
        "prowler_hub_semantic_search_compliances",
        "prowler_hub_get_compliance_details",
        "prowler_hub_list_providers",
        "prowler_hub_get_provider_services",
    }),
    "prowler_docs_": frozenset({
        "prowler_docs_search",
        "prowler_docs_get_document",
    }),
    "prowler_app_": frozenset({
        "prowler_app_get_attack_paths_cartography_schema",
        "prowler_app_list_attack_paths_queries",
        "prowler_app_list_attack_paths_scans",
        "prowler_app_run_attack_paths_query",
        "prowler_app_get_compliance_framework_state_details",
        "prowler_app_get_compliance_overview",
        "prowler_app_get_finding_details",
        "prowler_app_get_findings_overview",
        "prowler_app_search_security_findings",
        "prowler_app_create_mute_rule",
        "prowler_app_delete_mute_rule",
        "prowler_app_delete_mutelist",
        "prowler_app_get_mute_rule",
        "prowler_app_get_mutelist",
        "prowler_app_list_mute_rules",
        "prowler_app_set_mutelist",
        "prowler_app_update_mute_rule",
        "prowler_app_connect_provider",
        "prowler_app_delete_provider",
        "prowler_app_search_providers",
        "prowler_app_get_resource",
        "prowler_app_get_resource_events",
        "prowler_app_get_resources_overview",
        "prowler_app_list_resources",
        "prowler_app_get_scan",
        "prowler_app_list_scans",
        "prowler_app_schedule_daily_scan",
        "prowler_app_trigger_scan",
        "prowler_app_update_scan",
    }),
}
EXPECTED_TOOLS_ALL: Set[str] = (
    EXPECTED_TOOLS_BY_NAMESPACE["prowler_hub_"]
    | EXPECTED_TOOLS_BY_NAMESPACE["prowler_docs_"]
    | EXPECTED_TOOLS_BY_NAMESPACE["prowler_app_"]
)


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
        f"No prowler image found locally. Build with: "
        f"docker build -f tools/prowler/Dockerfile -t {IMAGE_LOCAL} ."
    )


@pytest.fixture(scope="module")
def prowler_env():
    """Boot the bundled container, complete MCP handshake, expose client.

    Cold start is ~7 min on first boot (90+ Django migrations). Subsequent
    runs against a warm volume should be ~30-60s. We use 600s startup
    timeout to accommodate the worst case.
    """
    image = _resolve_image()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = MCPTestClient(
        image=image,
        tool_name="prowler",
        # Cold boot via manual FIFO is ~123s, but pytest's MCPTestClient harness
        # adds overhead and observed 485s on first smoke run + timeouts at 300s.
        # 600s gives ~25% headroom over observed worst-case. CI runners may be slower.
        startup_timeout=600.0,
    )
    loop.run_until_complete(client.start())
    try:
        yield client, loop
    finally:
        loop.run_until_complete(client.stop())
        loop.close()


class TestProwlerSurface:
    """Verify upstream surface matches expectations + drift detection."""

    def test_server_identifies_as_prowler_mcp_server(self, prowler_env):
        """Server self-reports as 'prowler-mcp-server' (FastMCP identity)."""
        client, _ = prowler_env
        info = client.server_info
        assert info.get("name") == "prowler-mcp-server", (
            f"Expected 'prowler-mcp-server' (FastMCP server name), "
            f"got {info.get('name')!r}. Vendor may have renamed."
        )
        # version is FastMCP's framework version, not prowler-mcp's package version.
        # 2.x covers the FastMCP versions our local-source pip install lands on.
        ver = info.get("version", "")
        assert ver.startswith("2."), (
            f"Expected FastMCP v2.x framework version, got {ver!r}. "
            f"If FastMCP bumped to 3.x, re-verify schema compat."
        )

    def test_default_tool_count_is_forty_one(self, prowler_env):
        """The default surface is exactly 41 tools (10 hub + 2 docs + 29 app)."""
        client, _ = prowler_env
        names = sorted(t["name"] for t in client.tools)
        assert len(names) == 41, (
            f"Expected 41-tool default surface (10 hub + 2 docs + 29 app), "
            f"got {len(names)}. Surface drift: {names}. Vendor may have "
            f"added/removed tools — update EXPECTED_TOOLS_BY_NAMESPACE."
        )

    def test_default_surface_matches_canonical_set(self, prowler_env):
        """Tool set is exactly the expected 41 tools across 3 namespaces."""
        client, _ = prowler_env
        names = {t["name"] for t in client.tools}
        missing = EXPECTED_TOOLS_ALL - names
        unexpected = names - EXPECTED_TOOLS_ALL
        assert not missing, f"Missing expected tools: {missing}"
        assert not unexpected, (
            f"Unexpected tools in default surface: {unexpected}. "
            f"Either upstream added new tools (update EXPECTED_TOOLS_BY_NAMESPACE) "
            f"or our entrypoint is filtering wrong."
        )

    def test_namespace_counts_match(self, prowler_env):
        """Each namespace has the expected count: 10 hub + 2 docs + 29 app."""
        client, _ = prowler_env
        names = {t["name"] for t in client.tools}
        for prefix, expected_set in EXPECTED_TOOLS_BY_NAMESPACE.items():
            in_namespace = {n for n in names if n.startswith(prefix)}
            assert in_namespace == expected_set, (
                f"Namespace {prefix!r} drift: missing={expected_set - in_namespace} "
                f"unexpected={in_namespace - expected_set}"
            )

    def test_each_tool_has_input_schema(self, prowler_env):
        """Every tool advertises an inputSchema with type:object."""
        client, _ = prowler_env
        for tool in client.tools:
            assert "inputSchema" in tool, f"{tool['name']}: missing inputSchema"
            schema = tool["inputSchema"]
            assert schema.get("type") == "object", (
                f"{tool['name']}: inputSchema.type should be 'object'"
            )

    def test_connect_provider_requires_provider_uid_and_type(self, prowler_env):
        """`prowler_app_connect_provider` requires provider_uid + provider_type."""
        client, _ = prowler_env
        tool = next(t for t in client.tools if t["name"] == "prowler_app_connect_provider")
        required = set(tool.get("inputSchema", {}).get("required", []))
        assert {"provider_uid", "provider_type"}.issubset(required), (
            f"connect_provider must require provider_uid + provider_type; got {required}"
        )

    def test_trigger_scan_requires_provider_id(self, prowler_env):
        """`prowler_app_trigger_scan` requires provider_id (the UUID, not the cloud-native UID)."""
        client, _ = prowler_env
        tool = next(t for t in client.tools if t["name"] == "prowler_app_trigger_scan")
        required = set(tool.get("inputSchema", {}).get("required", []))
        assert "provider_id" in required, (
            f"trigger_scan must require provider_id; got {required}"
        )

    def test_get_check_details_takes_only_check_id(self, prowler_env):
        """`prowler_hub_get_check_details` takes ONLY check_id (NOT provider_id).

        Verified live 2026-05-09: passing provider_id returns
        `Unexpected keyword argument` from Pydantic. Common confusion with
        get_check_code / get_check_fixer which DO take both.
        """
        client, _ = prowler_env
        tool = next(t for t in client.tools if t["name"] == "prowler_hub_get_check_details")
        props = set(tool.get("inputSchema", {}).get("properties", {}).keys())
        assert props == {"check_id"}, (
            f"get_check_details schema MUST be exactly {{check_id}}; got {props}. "
            f"If upstream added provider_id, update tool.yaml gotchas."
        )


class TestProwlerToolYamlContract:
    """Verify tool.yaml matches the runtime contract."""

    def test_tool_yaml_kind_is_mcp(self):
        """tool.yaml declares kind:mcp explicitly (not legacy unmarked-kind:mcp)."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("kind") == "mcp", (
            "tool.yaml MUST declare kind:mcp explicitly (mirrors metasploit/zap/playwright/mongodb pattern)"
        )

    def test_tool_yaml_image_matches_ghcr_path(self):
        """Image tag in tool.yaml matches the published image."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("image") == IMAGE_GHCR, (
            f"tool.yaml image={d.get('image')!r} does not match published "
            f"image {IMAGE_GHCR!r}. CI and tool.yaml drift apart silently."
        )

    def test_tool_yaml_source_url_points_at_vendor(self):
        """source field points at the upstream vendor mcp_server subdir."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        source = d.get("source", "")
        assert source == "https://github.com/prowler-cloud/prowler/tree/master/mcp_server", (
            f"source URL must point at vendor repo's mcp_server, got {source!r}"
        )

    def test_tool_yaml_idle_timeout_is_long_for_service(self):
        """service:true means the stack persists per session; idle timeout should be long."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("idle_timeout_seconds", 0) >= 3600, (
            "idle_timeout_seconds should be >=3600s (1hr) for a service:true stack"
            " to amortize the heavy cold-start cost across the engagement"
        )
        assert d.get("service") is True, "tool.yaml must declare service:true"
        assert d.get("service_name") == "prowler", "tool.yaml service_name must be 'prowler'"

    def test_tool_yaml_resources_reflect_heavy_stack(self):
        """memory_mb must be at least 4 GB given dozerdb heap + django + celery."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        mem = (d.get("resources") or {}).get("memory_mb", 0)
        assert mem >= 4096, (
            f"resources.memory_mb={mem} too low — dozerdb alone needs ~2GB heap"
            f" + page cache, plus django/celery/postgres/redis"
        )

    def test_tool_yaml_methods_match_runtime_surface(self, prowler_env):
        """Every runtime tool is documented in tool.yaml; tool.yaml extras are flagged."""
        client, _ = prowler_env
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        documented = set(d.get("methods", {}).keys())
        runtime = {t["name"] for t in client.tools}
        runtime_minus_documented = runtime - documented
        documented_minus_runtime = documented - runtime
        assert runtime_minus_documented == set(), (
            f"Runtime tools NOT in tool.yaml: {runtime_minus_documented}. "
            f"Document them with `description` + `when_to_use` + `params`."
        )
        assert documented_minus_runtime == set(), (
            f"tool.yaml documents methods that don't exist at runtime: "
            f"{documented_minus_runtime}. Either runtime dropped them or "
            f"the docs are stale."
        )
