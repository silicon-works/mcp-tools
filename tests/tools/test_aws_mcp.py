"""
Contract suite for aws (vendor-MCP standardization wrap of awslabs.aws-api-mcp-server).

Mirror of mongodb/prowler test pattern. Boots the lightweight vendor wrap
container (no DB stack — cold boot is ~5s). Exercises the 2-tool default
surface + tool.yaml↔runtime contract.

NOT a vendor-MCP swap test — `aws` was always a thin wrap. Tests verify
the standardization layer (kind:mcp explicit, service:true, methods doc
parity with vendor) plus surface drift detection.

Tests do NOT require AWS credentials — they only exercise the MCP server
surface itself (tools/list shape, schemas, server self-identification).
Live cloud-side behaviors (call_aws against real AWS) are documented in
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
TOOL_DIR = PROJECT_ROOT / "tools" / "aws"
IMAGE_LOCAL = "mcp-tools-aws:dev"
IMAGE_GHCR = "ghcr.io/silicon-works/mcp-tools-aws:latest"

# 2-tool default surface verified live 2026-05-11 against vendor v1.3.x.
# A 3rd tool `get_execution_plan` registers conditionally on
# EXPERIMENTAL_AGENT_SCRIPTS=true (we don't set this).
EXPECTED_TOOLS_DEFAULT: Set[str] = frozenset({
    "call_aws",
    "suggest_aws_commands",
})

# Tools the conditional EXPERIMENTAL_AGENT_SCRIPTS env adds (NOT in default).
# Tracked for future-proofing in case our env policy changes.
EXPECTED_TOOLS_CONDITIONAL: Set[str] = frozenset({
    "get_execution_plan",
})


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
        f"No aws image found locally. Pull with: "
        f"docker pull {IMAGE_GHCR}"
    )


@pytest.fixture(scope="module")
def aws_env():
    """Boot the aws container, complete MCP handshake, expose client.

    Cold start is ~5s (no DB stack — Python venv + boto3 + FastMCP only).
    Use 60s startup_timeout to cover slower CI runners.
    """
    image = _resolve_image()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = MCPTestClient(
        image=image,
        tool_name="aws",
        startup_timeout=60.0,  # 1 min — actual cold start ~5s, 12x buffer
    )
    loop.run_until_complete(client.start())
    try:
        yield client, loop
    finally:
        loop.run_until_complete(client.stop())
        loop.close()


class TestAwsSurface:
    """Verify upstream surface matches expectations + drift detection."""

    def test_server_identifies_as_aws_api_mcp(self, aws_env):
        """Server self-reports as 'AWS-API-MCP' (FastMCP server name)."""
        client, _ = aws_env
        info = client.server_info
        assert info.get("name") == "AWS-API-MCP", (
            f"Expected 'AWS-API-MCP' (FastMCP server name), "
            f"got {info.get('name')!r}. Vendor may have renamed."
        )
        # version is FastMCP's framework version, not the package version.
        # 3.x covers FastMCP versions our pip install lands on.
        ver = info.get("version", "")
        assert ver.startswith("3."), (
            f"Expected FastMCP v3.x framework version, got {ver!r}. "
            f"If FastMCP bumped to 4.x, re-verify schema compat."
        )

    def test_default_tool_count_is_two(self, aws_env):
        """The default surface is exactly 2 tools (call_aws + suggest_aws_commands)."""
        client, _ = aws_env
        names = sorted(t["name"] for t in client.tools)
        assert len(names) == 2, (
            f"Expected 2-tool default surface (call_aws + suggest_aws_commands), "
            f"got {len(names)}. Surface drift: {names}. Either vendor added "
            f"unconditional tools (update EXPECTED_TOOLS_DEFAULT) OR our "
            f"entrypoint accidentally enabled EXPERIMENTAL_AGENT_SCRIPTS."
        )

    def test_default_surface_matches_canonical_set(self, aws_env):
        """Tool set is exactly the expected 2 tools."""
        client, _ = aws_env
        names = {t["name"] for t in client.tools}
        missing = EXPECTED_TOOLS_DEFAULT - names
        unexpected = names - EXPECTED_TOOLS_DEFAULT
        assert not missing, f"Missing expected default tools: {missing}"
        assert not unexpected, (
            f"Unexpected tools in default surface: {unexpected}. "
            f"If vendor added new always-on tools, update EXPECTED_TOOLS_DEFAULT. "
            f"If get_execution_plan appears, EXPERIMENTAL_AGENT_SCRIPTS leaked into entrypoint."
        )

    def test_conditional_tool_not_in_default(self, aws_env):
        """`get_execution_plan` should NOT appear in the default surface.

        Vendor source registers it conditionally on EXPERIMENTAL_AGENT_SCRIPTS=true.
        Our entrypoint does not set that env. If this assertion fails, our env
        policy regressed.
        """
        client, _ = aws_env
        names = {t["name"] for t in client.tools}
        leaked = EXPECTED_TOOLS_CONDITIONAL & names
        assert not leaked, (
            f"Conditional tool(s) leaked into default surface: {leaked}. "
            f"Check Dockerfile + mcp-server.py for accidental "
            f"EXPERIMENTAL_AGENT_SCRIPTS=true."
        )

    def test_each_tool_has_input_schema(self, aws_env):
        """Every tool advertises an inputSchema with type:object."""
        client, _ = aws_env
        for tool in client.tools:
            assert "inputSchema" in tool, f"{tool['name']}: missing inputSchema"
            schema = tool["inputSchema"]
            assert schema.get("type") == "object", (
                f"{tool['name']}: inputSchema.type should be 'object'"
            )

    def test_call_aws_requires_cli_command(self, aws_env):
        """`call_aws` requires `cli_command` — the only required arg."""
        client, _ = aws_env
        tool = next(t for t in client.tools if t["name"] == "call_aws")
        required = set(tool.get("inputSchema", {}).get("required", []))
        assert required == {"cli_command"}, (
            f"call_aws must require exactly {{cli_command}}; got {required}. "
            f"If vendor added new required args, update tool.yaml + this assertion."
        )

    def test_call_aws_supports_max_results(self, aws_env):
        """`call_aws` advertises optional `max_results` for pagination."""
        client, _ = aws_env
        tool = next(t for t in client.tools if t["name"] == "call_aws")
        props = set(tool.get("inputSchema", {}).get("properties", {}).keys())
        assert "max_results" in props, (
            f"call_aws should expose max_results; got properties {props}"
        )

    def test_suggest_aws_commands_requires_query(self, aws_env):
        """`suggest_aws_commands` requires `query` (NL string)."""
        client, _ = aws_env
        tool = next(t for t in client.tools if t["name"] == "suggest_aws_commands")
        required = set(tool.get("inputSchema", {}).get("required", []))
        assert "query" in required, (
            f"suggest_aws_commands must require query; got {required}"
        )


class TestAwsToolYamlContract:
    """Verify tool.yaml matches the runtime contract."""

    def test_tool_yaml_kind_is_mcp(self):
        """tool.yaml declares kind:mcp explicitly (post-standardization)."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("kind") == "mcp", (
            "tool.yaml MUST declare kind:mcp explicitly (post-standardization round 2026-05-11)"
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
        assert source == "https://github.com/awslabs/mcp/tree/main/src/aws-api-mcp-server", (
            f"source URL must point at vendor repo's aws-api-mcp-server, got {source!r}"
        )

    def test_tool_yaml_declares_service_mode(self):
        """aws is service:true — credentials persist via env across calls.

        Without service:true ContainerManager spawns a fresh container per
        JSON-RPC call, requiring the agent to pass AWS creds in argv (leaks
        via docker inspect / process listings). With service:true, creds set
        once at container start via opensploit's envOverrides persist.
        """
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("service") is True, (
            "tool.yaml MUST declare service:true — AWS creds persist via env"
            " across calls; per-call container spawn would force argv credential leak."
        )
        assert d.get("service_name") == "aws", (
            f"tool.yaml service_name must be 'aws', got {d.get('service_name')!r}"
        )

    def test_tool_yaml_idle_timeout_is_long_for_service(self):
        """service:true means the stack persists per session; idle timeout should be long."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        assert d.get("idle_timeout_seconds", 0) >= 1800, (
            "idle_timeout_seconds should be >=1800s (30min) for a service:true stack"
            " holding AWS credentials across a long engagement"
        )

    def test_tool_yaml_allowed_env_includes_aws_creds(self):
        """allowed_env must include AWS credential env vars for service:true cred passthrough."""
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        allowed = set(d.get("allowed_env", []) or [])
        required_creds = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"}
        missing = required_creds - allowed
        assert not missing, (
            f"allowed_env missing AWS credential env vars: {missing}. "
            f"Without these, opensploit envOverrides cannot pass creds through."
        )

    def test_tool_yaml_methods_match_runtime_surface(self, aws_env):
        """Every runtime tool is documented in tool.yaml; tool.yaml extras are flagged."""
        client, _ = aws_env
        with open(TOOL_DIR / "tool.yaml") as f:
            d = yaml.safe_load(f)
        documented = set(d.get("methods", {}).keys())
        runtime = {t["name"] for t in client.tools}
        runtime_minus_documented = runtime - documented
        documented_minus_runtime = documented - runtime
        # tool.yaml may document conditional tools (get_execution_plan) for
        # the EXPERIMENTAL_AGENT_SCRIPTS unlock path even if runtime doesn't expose them.
        # Currently we don't document those — assert exact match.
        assert runtime_minus_documented == set(), (
            f"Runtime tools NOT in tool.yaml: {runtime_minus_documented}. "
            f"Document them with `description` + `when_to_use` + `params`."
        )
        assert documented_minus_runtime == set(), (
            f"tool.yaml documents methods that don't exist at runtime: "
            f"{documented_minus_runtime}. Either runtime dropped them or "
            f"the docs are stale."
        )
