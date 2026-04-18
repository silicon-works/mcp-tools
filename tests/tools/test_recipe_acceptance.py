"""
Acceptance tests for the impacket recipe system through Docker containers.

These tests start an impacket container in Docker with a mounted /session/ directory
containing recipe files, then exercise the recipe methods through the MCP protocol.

Verifies:
1.  Binary-only recipe appears in list_tools
2.  Binary-only recipe callable (with structured error for unreachable target)
3.  Handler recipe callable (returns known string)
4.  Recipe hot-reload: add recipe after boot, appears in list_tools
5.  Bad recipe doesn't crash server
6.  Recipe with impacket auth params (domain-style auth arg building)
7.  Recipe structuredContent fields present
8.  Multiple recipes all appear
9.  Recipe cannot overwrite built-in method
10. Recipe deletion removes method from list_tools
11. Recipe survives container restart
12. Recipe called multiple times in same engagement

Requires: ``--tool=impacket`` (uses impacket container).
Run with::

    docker build -t mcp-test-impacket -f tools/impacket/Dockerfile .
    pytest tests/tools/test_recipe_acceptance.py --tool=impacket -v --tb=short
"""

import asyncio
import json
import os
import shutil
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from conftest import (
    MCPTestClient,
    assert_tool_error,
    assert_tool_success,
    parse_tool_output,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_recipe(recipe_dir: Path, filename: str, content: str) -> Path:
    """Write a recipe file into the recipe directory."""
    path = recipe_dir / filename
    path.write_text(textwrap.dedent(content))
    return path


def _run(env_tuple, coro):
    """Run an async coroutine on the environment's event loop."""
    _, loop = env_tuple
    return loop.run_until_complete(coro)


# ---------------------------------------------------------------------------
# Module-scoped fixture: temp dir for /session/ + container with volume mount
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def session_dir(tmp_path_factory):
    """Create a temporary /session/ tree with recipes/impacket/ subdir."""
    base = tmp_path_factory.mktemp("session")
    recipe_dir = base / "recipes" / "impacket"
    recipe_dir.mkdir(parents=True)
    return base


@pytest.fixture(scope="module")
def recipe_dir(session_dir):
    """Return the recipe directory inside the session."""
    return session_dir / "recipes" / "impacket"


@pytest.fixture(scope="module")
def recipe_env(request, session_dir):
    """Start an impacket container with /session/ mounted.  Yields (client, loop)."""
    prefix = request.config.getoption("--image-prefix", default="mcp-test-")
    image = f"{prefix}impacket"

    client = MCPTestClient(
        image=image,
        tool_name="impacket",
        volumes={str(session_dir): "/session"},
    )
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(client.start())
    except Exception:
        loop.run_until_complete(client.stop())
        loop.close()
        raise

    yield client, loop

    loop.run_until_complete(client.stop())
    loop.close()


# ===========================================================================
# 1. Binary-only recipe appears in list_tools
# ===========================================================================

class TestBinaryRecipeListTools:
    """A binary-only recipe is discovered and listed after hot-reload."""

    def test_binary_recipe_in_list_tools(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        # Write a binary-only recipe (echo is available in every container)
        _write_recipe(recipe_dir, "recipe_echo.py", '''
            RECIPE = {
                "name": "recipe_echo",
                "description": "Echo test via binary-only recipe",
                "auth": "none",
                "params": {
                    "message": {"type": "string", "required": True, "description": "Message to echo", "flag": ""},
                },
                "binary": "echo",
            }
        ''')

        # Trigger hot-reload by calling list_tools
        tools = loop.run_until_complete(client.list_tools())
        names = {t["name"] for t in tools}
        assert "recipe_echo" in names, f"recipe_echo not in tools: {sorted(names)}"


# ===========================================================================
# 2. Binary-only recipe callable
# ===========================================================================

class TestBinaryRecipeCallable:
    """Binary-only recipe can be called and returns structured output."""

    def test_call_binary_recipe(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        # Ensure recipe exists (may already be there from test 1)
        if not (recipe_dir / "recipe_echo.py").exists():
            _write_recipe(recipe_dir, "recipe_echo.py", '''
                RECIPE = {
                    "name": "recipe_echo",
                    "description": "Echo test via binary-only recipe",
                    "auth": "none",
                    "params": {
                        "message": {"type": "string", "required": True, "description": "Message to echo", "flag": ""},
                    },
                    "binary": "echo",
                }
            ''')

        resp = loop.run_until_complete(
            client.call("recipe_echo", {"message": "hello from recipe"})
        )
        result = assert_tool_success(resp, "recipe_echo should succeed")
        data = parse_tool_output(resp)
        assert "hello from recipe" in data.get("raw_output", ""), (
            f"Expected 'hello from recipe' in output, got: {data}"
        )


# ===========================================================================
# 3. Handler recipe callable
# ===========================================================================

class TestHandlerRecipeCallable:
    """A recipe with a custom async handler is invoked correctly."""

    def test_call_handler_recipe(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        _write_recipe(recipe_dir, "recipe_greeting.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "recipe_greeting",
                "description": "Greeting handler recipe",
                "auth": "none",
                "params": {
                    "name": {"type": "string", "required": True, "description": "Who to greet"},
                },
            }

            async def handler(server, **kwargs):
                who = kwargs.get("name", "world")
                return ToolResult(
                    success=True,
                    data={"greeting": f"Hello, {who}!", "server_tool": server.name},
                )
        ''')

        resp = loop.run_until_complete(
            client.call("recipe_greeting", {"name": "OpenSploit"})
        )
        result = assert_tool_success(resp, "recipe_greeting should succeed")
        data = parse_tool_output(resp)
        assert data["greeting"] == "Hello, OpenSploit!"
        assert data["server_tool"] == "impacket"


# ===========================================================================
# 4. Recipe hot-reload: new recipe appears without restart
# ===========================================================================

class TestRecipeHotReload:
    """A recipe written after container boot is discovered on the next call."""

    def test_hot_reload_new_recipe(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        # Confirm the method does not exist yet
        tools_before = loop.run_until_complete(client.list_tools())
        names_before = {t["name"] for t in tools_before}
        assert "recipe_hotloaded" not in names_before

        # Write the recipe
        _write_recipe(recipe_dir, "recipe_hotloaded.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "recipe_hotloaded",
                "description": "Hot-loaded recipe",
                "auth": "none",
                "params": {},
            }

            async def handler(server, **kwargs):
                return ToolResult(success=True, data={"hot": True})
        ''')

        # list_tools should now include it (hot-reload happens on every call)
        tools_after = loop.run_until_complete(client.list_tools())
        names_after = {t["name"] for t in tools_after}
        assert "recipe_hotloaded" in names_after, (
            f"recipe_hotloaded not discovered after hot-reload: {sorted(names_after)}"
        )

        # Also callable
        resp = loop.run_until_complete(client.call("recipe_hotloaded", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert data["hot"] is True


# ===========================================================================
# 5. Bad recipe doesn't crash server
# ===========================================================================

class TestBadRecipeDoesNotCrash:
    """A recipe with a syntax error does not prevent the server from working."""

    def test_bad_recipe_ignored(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        # Write a broken recipe
        _write_recipe(recipe_dir, "recipe_broken.py", '''
            RECIPE = {
                "name": "recipe_broken"
            # missing closing brace and no description
        ''')

        # Server should still respond to list_tools
        tools = loop.run_until_complete(client.list_tools())
        names = {t["name"] for t in tools}

        # Built-in methods must still be present
        assert "psexec" in names, "Built-in psexec missing after bad recipe"
        assert "secretsdump" in names, "Built-in secretsdump missing after bad recipe"

        # The broken recipe should NOT appear
        assert "recipe_broken" not in names

        # Built-in method should still be callable
        resp = loop.run_until_complete(
            client.call("psexec", {"target": "192.0.2.1", "username": "test", "password": "test"})
        )
        # This will fail (unreachable target) but should NOT be a protocol error
        result = resp.get("result")
        assert result is not None, "Server crashed or did not respond"

        # Clean up so it doesn't interfere with other tests
        (recipe_dir / "recipe_broken.py").unlink(missing_ok=True)


# ===========================================================================
# 6. Recipe with auth params (impacket domain auth)
# ===========================================================================

class TestRecipeWithAuth:
    """A handler recipe using impacket's _build_domain_auth_args works correctly."""

    def test_auth_recipe_builds_args(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        _write_recipe(recipe_dir, "recipe_auth_check.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "recipe_auth_check",
                "description": "Verify impacket auth arg building from a recipe",
                "auth": "none",
                "params": {
                    "target": {"type": "string", "required": True, "description": "DC IP"},
                    "username": {"type": "string", "description": "Username"},
                    "password": {"type": "string", "description": "Password"},
                    "domain": {"type": "string", "description": "Domain"},
                },
            }

            async def handler(server, **kwargs):
                # Use the impacket server's auth building
                identity, auth_args = server._build_domain_auth_args(
                    target=kwargs.get("target", ""),
                    username=kwargs.get("username"),
                    password=kwargs.get("password"),
                    domain=kwargs.get("domain"),
                )
                return ToolResult(
                    success=True,
                    data={
                        "identity_str": identity,
                        "auth_args": auth_args,
                    },
                )
        ''')

        resp = loop.run_until_complete(
            client.call("recipe_auth_check", {
                "target": "10.10.10.1",
                "username": "admin",
                "password": "P@ss123",
                "domain": "CORP.LOCAL",
            })
        )
        result = assert_tool_success(resp, "recipe_auth_check should succeed")
        data = parse_tool_output(resp)

        assert data["identity_str"] == "CORP.LOCAL/admin:P@ss123"
        assert "-dc-ip" in data["auth_args"]
        assert "10.10.10.1" in data["auth_args"]


# ===========================================================================
# 7. Recipe structuredContent
# ===========================================================================

class TestRecipeStructuredContent:
    """Recipe responses include structuredContent with expected fields."""

    def test_structured_content_on_success(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        # Use the handler recipe from test 3 (or recreate)
        if not (recipe_dir / "recipe_greeting.py").exists():
            _write_recipe(recipe_dir, "recipe_greeting.py", '''
                from mcp_common.base_server import ToolResult

                RECIPE = {
                    "name": "recipe_greeting",
                    "description": "Greeting handler recipe",
                    "auth": "none",
                    "params": {
                        "name": {"type": "string", "required": True, "description": "Who to greet"},
                    },
                }

                async def handler(server, **kwargs):
                    who = kwargs.get("name", "world")
                    return ToolResult(
                        success=True,
                        data={"greeting": f"Hello, {who}!"},
                    )
            ''')

        resp = loop.run_until_complete(
            client.call("recipe_greeting", {"name": "test"})
        )
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})

        assert sc.get("success") is True
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc
        assert "data" in sc

    def test_structured_content_on_error(self, recipe_env, recipe_dir):
        """Binary recipe with unreachable target produces error structuredContent."""
        _write_recipe(recipe_dir, "recipe_false.py", '''
            RECIPE = {
                "name": "recipe_false",
                "description": "Always-fail recipe for testing error structuredContent",
                "auth": "none",
                "params": {},
                "binary": "false",
            }
        ''')

        client, loop = recipe_env
        resp = loop.run_until_complete(
            client.call("recipe_false", {})
        )
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})

        assert sc.get("success") is False
        assert "error_class" in sc
        assert "retryable" in sc
        assert isinstance(sc.get("suggestions"), list)


# ===========================================================================
# 8. Multiple recipes all appear
# ===========================================================================

class TestMultipleRecipes:
    """Multiple recipe files are all discovered and listed."""

    def test_three_recipes(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        # Write 3 distinct recipes
        for i in range(1, 4):
            _write_recipe(recipe_dir, f"recipe_multi_{i}.py", f'''
                RECIPE = {{
                    "name": "recipe_multi_{i}",
                    "description": "Multi recipe {i}",
                    "auth": "none",
                    "params": {{}},
                    "binary": "echo",
                }}
            ''')

        tools = loop.run_until_complete(client.list_tools())
        names = {t["name"] for t in tools}

        for i in range(1, 4):
            assert f"recipe_multi_{i}" in names, (
                f"recipe_multi_{i} missing from tools: {sorted(names)}"
            )


# ===========================================================================
# 9. Recipe cannot overwrite built-in method
# ===========================================================================

class TestRecipeCannotOverwriteBuiltin:
    """A recipe named the same as a built-in method is ignored."""

    def test_builtin_psexec_protected(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        # Write a recipe claiming to be "psexec"
        _write_recipe(recipe_dir, "recipe_fake_psexec.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "psexec",
                "description": "Fake psexec from recipe",
                "auth": "none",
                "params": {},
            }

            async def handler(server, **kwargs):
                return ToolResult(success=True, data={"source": "recipe"})
        ''')

        # list_tools to trigger reload
        tools = loop.run_until_complete(client.list_tools())

        # Call psexec -- should get the REAL handler (which requires target), not the recipe
        resp = loop.run_until_complete(
            client.call("psexec", {"target": "192.0.2.1", "username": "x", "password": "x"})
        )
        result = resp.get("result", {})

        # The real psexec will attempt to connect (and fail) -- it won't return {"source": "recipe"}
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]

        # If the recipe overwrote it, we'd get {"source": "recipe"} with success
        assert '"source": "recipe"' not in content_text, (
            "Recipe overwrote the built-in psexec method!"
        )

        # Clean up
        (recipe_dir / "recipe_fake_psexec.py").unlink(missing_ok=True)


# ===========================================================================
# 10. Recipe deletion removes method
# ===========================================================================

class TestRecipeDeletion:
    """Deleting a recipe file causes its method to be unregistered on next call."""

    def test_delete_recipe(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        # Write a recipe
        recipe_path = _write_recipe(recipe_dir, "recipe_ephemeral.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "recipe_ephemeral",
                "description": "Will be deleted",
                "auth": "none",
                "params": {},
            }

            async def handler(server, **kwargs):
                return ToolResult(success=True, data={"alive": True})
        ''')

        # Confirm it appears
        tools = loop.run_until_complete(client.list_tools())
        names = {t["name"] for t in tools}
        assert "recipe_ephemeral" in names

        # Delete the file
        recipe_path.unlink()

        # list_tools should no longer include it
        tools = loop.run_until_complete(client.list_tools())
        names = {t["name"] for t in tools}
        assert "recipe_ephemeral" not in names, (
            f"recipe_ephemeral still listed after deletion: {sorted(names)}"
        )


# ===========================================================================
# 11. Recipe survives container restart
# ===========================================================================

class TestRecipeSurvivesRestart:
    """Recipe persists across container stop/start because it's on mounted /session/."""

    def test_recipe_after_restart(self, request, session_dir, recipe_dir):
        """Write recipe, call it, restart container, call again."""
        prefix = request.config.getoption("--image-prefix", default="mcp-test-")
        image = f"{prefix}impacket"

        # Write recipe before starting container
        _write_recipe(recipe_dir, "recipe_persistent.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "recipe_persistent",
                "description": "Survives restart",
                "auth": "none",
                "params": {},
            }

            async def handler(server, **kwargs):
                return ToolResult(success=True, data={"persistent": True})
        ''')

        loop = asyncio.new_event_loop()
        try:
            # First container
            client1 = MCPTestClient(
                image=image,
                tool_name="impacket",
                volumes={str(session_dir): "/session"},
            )
            loop.run_until_complete(client1.start())

            resp1 = loop.run_until_complete(client1.call("recipe_persistent", {}))
            result1 = assert_tool_success(resp1)
            data1 = parse_tool_output(resp1)
            assert data1["persistent"] is True

            loop.run_until_complete(client1.stop())

            # Second container (restart)
            client2 = MCPTestClient(
                image=image,
                tool_name="impacket",
                volumes={str(session_dir): "/session"},
            )
            loop.run_until_complete(client2.start())

            resp2 = loop.run_until_complete(client2.call("recipe_persistent", {}))
            result2 = assert_tool_success(resp2)
            data2 = parse_tool_output(resp2)
            assert data2["persistent"] is True

            loop.run_until_complete(client2.stop())
        finally:
            loop.close()


# ===========================================================================
# 12. Recipe called multiple times in same engagement
# ===========================================================================

class TestRecipeMultipleCalls:
    """Recipe method can be called multiple times in the same engagement."""

    def test_recipe_idempotent(self, recipe_env, recipe_dir):
        client, loop = recipe_env

        _write_recipe(recipe_dir, "recipe_counter.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "recipe_counter",
                "description": "Counter recipe",
                "auth": "none",
                "params": {
                    "value": {"type": "string", "required": True, "description": "Value to echo"},
                },
            }

            async def handler(server, **kwargs):
                return ToolResult(
                    success=True,
                    data={"value": kwargs.get("value", "")},
                )
        ''')

        for i in range(3):
            resp = loop.run_until_complete(
                client.call("recipe_counter", {"value": f"call_{i}"})
            )
            result = assert_tool_success(resp, f"call {i} should succeed")
            data = parse_tool_output(resp)
            assert data["value"] == f"call_{i}"
