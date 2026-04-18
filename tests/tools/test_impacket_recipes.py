"""
Unit tests for the impacket MCP server recipe system.

Covers:
- Recipe loading from a temp directory
- Recipe with auth="domain" builds correct auth args
- Recipe with auth="target" builds correct auth args
- Recipe with auth="none" passes no auth
- Recipe with script (custom Python) runs correctly
- Recipe hot-reload (new file, modified file, deleted file)
- Bad recipe (syntax error, missing RECIPE, missing name) skipped gracefully
- Recipe can't overwrite built-in psexec
- Recipe params registered correctly
- Kerberos env injected for recipe calls
- Error classification works on recipe method errors
- extra_args on recipe methods
"""

import asyncio
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "impacket"

sys.path.insert(0, str(PROJECT_ROOT / "packages" / "mcp-common" / "src"))
sys.path.insert(0, str(TOOL_DIR))


def _get_server_class():
    """Import and return the ImpacketServer class."""
    spec = importlib.util.spec_from_file_location(
        "impacket_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ImpacketServer


ImpacketServer = _get_server_class()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def recipe_dir(tmp_path):
    """Create and return a temporary recipe directory."""
    d = tmp_path / "recipes" / "impacket"
    d.mkdir(parents=True)
    return d


@pytest.fixture
def server(recipe_dir):
    """Create an ImpacketServer pointed at the temp recipe directory."""
    os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
    try:
        srv = ImpacketServer()
    finally:
        os.environ.pop("MCP_RECIPE_DIR", None)
    return srv


def write_recipe(recipe_dir, filename, content):
    """Write a recipe file to the recipe directory."""
    path = recipe_dir / filename
    path.write_text(textwrap.dedent(content))
    return path


# ===========================================================================
# Test: basic recipe loading
# ===========================================================================

class TestRecipeLoading:
    """Test that recipes are discovered and loaded on server init."""

    def test_no_recipe_dir(self, tmp_path):
        """Server starts fine when recipe directory does not exist."""
        nonexistent = str(tmp_path / "does_not_exist" / "recipes")
        os.environ["MCP_RECIPE_DIR"] = nonexistent
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert len(srv._recipe_methods) == 0

    def test_empty_recipe_dir(self, recipe_dir):
        """Server starts fine with an empty recipe directory."""
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert len(srv._recipe_methods) == 0

    def test_load_binary_recipe(self, recipe_dir):
        """Recipe with binary is loaded and registered."""
        write_recipe(recipe_dir, "certifried.py", '''
            RECIPE = {
                "name": "certifried",
                "description": "CVE-2022-26923 AD CS privilege escalation",
                "auth": "domain",
                "binary": "impacket-certifried",
                "params": {
                    "ca": {"type": "string", "required": True, "description": "CA name"},
                },
            }
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert "certifried" in srv.methods
        assert "certifried" in srv._recipe_methods

    def test_load_script_recipe(self, recipe_dir):
        """Recipe with script path is loaded."""
        write_recipe(recipe_dir, "custom.py", '''
            RECIPE = {
                "name": "custom_exploit",
                "description": "Custom impacket exploit",
                "auth": "target",
                "script": "/session/impacket-scripts/my_exploit.py",
                "params": {},
            }
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert "custom_exploit" in srv.methods
        assert "custom_exploit" in srv._recipe_methods

    def test_multiple_recipes(self, recipe_dir):
        """Multiple recipe files are all loaded."""
        write_recipe(recipe_dir, "tool_a.py", '''
            RECIPE = {"name": "recipe_a", "description": "Tool A", "auth": "none", "binary": "echo"}
        ''')
        write_recipe(recipe_dir, "tool_b.py", '''
            RECIPE = {"name": "recipe_b", "description": "Tool B", "auth": "none", "binary": "echo"}
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert {"recipe_a", "recipe_b"} <= srv._recipe_methods

    def test_non_py_files_ignored(self, recipe_dir):
        """Non-.py files in recipe dir are ignored."""
        (recipe_dir / "README.md").write_text("# notes")
        (recipe_dir / "data.yaml").write_text("key: val")
        write_recipe(recipe_dir, "real.py", '''
            RECIPE = {"name": "real_method", "description": "Real", "auth": "none", "binary": "echo"}
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert srv._recipe_methods == {"real_method"}


# ===========================================================================
# Test: bad recipes
# ===========================================================================

class TestBadRecipes:
    """Test graceful handling of malformed recipe files."""

    def test_syntax_error(self, recipe_dir):
        """Recipe with syntax error is skipped, server still starts."""
        write_recipe(recipe_dir, "bad_syntax.py", '''
            RECIPE = {
                "name": "bad"
            # missing closing brace
        ''')
        write_recipe(recipe_dir, "good.py", '''
            RECIPE = {"name": "good_method", "description": "Works", "auth": "none", "binary": "echo"}
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert "good_method" in srv._recipe_methods
        assert "bad" not in srv.methods

    def test_missing_recipe_dict(self, recipe_dir):
        """Recipe file without RECIPE dict is skipped."""
        write_recipe(recipe_dir, "no_recipe.py", '''
            def handler(server, **kwargs):
                pass
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert len(srv._recipe_methods) == 0

    def test_recipe_dict_not_dict(self, recipe_dir):
        """Recipe where RECIPE is not a dict is skipped."""
        write_recipe(recipe_dir, "wrong_type.py", '''
            RECIPE = "not a dict"
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert len(srv._recipe_methods) == 0

    def test_missing_name(self, recipe_dir):
        """Recipe with RECIPE dict but no name is skipped."""
        write_recipe(recipe_dir, "no_name.py", '''
            RECIPE = {"description": "No name here", "auth": "none", "binary": "echo"}
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert len(srv._recipe_methods) == 0

    def test_no_handler_no_binary_no_script(self, recipe_dir):
        """Recipe with neither handler, binary, nor script is skipped."""
        write_recipe(recipe_dir, "orphan.py", '''
            RECIPE = {
                "name": "orphan_method",
                "description": "Has neither handler nor binary nor script",
                "auth": "none",
                "params": {},
            }
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert "orphan_method" not in srv.methods

    def test_handler_exception_during_load(self, recipe_dir):
        """Recipe that raises during module exec is skipped."""
        write_recipe(recipe_dir, "crash.py", '''
            raise RuntimeError("boom during load")
        ''')
        write_recipe(recipe_dir, "stable.py", '''
            RECIPE = {"name": "stable", "description": "Stable", "auth": "none", "binary": "echo"}
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert "stable" in srv._recipe_methods
        assert len(srv._recipe_methods) == 1


# ===========================================================================
# Test: recipe can't overwrite built-in methods
# ===========================================================================

class TestRecipeConflicts:
    """Test that recipes don't overwrite built-in server methods."""

    def test_builtin_psexec_protected(self, recipe_dir):
        """Recipe with name 'psexec' is skipped — built-in is preserved."""
        write_recipe(recipe_dir, "fake_psexec.py", '''
            RECIPE = {
                "name": "psexec",
                "description": "Fake psexec from recipe",
                "auth": "target",
                "binary": "fake-psexec",
            }
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert "psexec" not in srv._recipe_methods
        # Built-in psexec still registered
        assert "psexec" in srv.methods

    def test_builtin_secretsdump_protected(self, recipe_dir):
        """Recipe with name 'secretsdump' is skipped."""
        write_recipe(recipe_dir, "fake_secretsdump.py", '''
            RECIPE = {
                "name": "secretsdump",
                "description": "Fake secretsdump",
                "auth": "target",
                "binary": "fake-secretsdump",
            }
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert "secretsdump" not in srv._recipe_methods
        assert "secretsdump" in srv.methods

    def test_builtin_dacledit_protected(self, recipe_dir):
        """Recipe with name 'dacledit' (generic method) is skipped."""
        write_recipe(recipe_dir, "fake_dacledit.py", '''
            RECIPE = {
                "name": "dacledit",
                "description": "Fake dacledit",
                "auth": "domain",
                "binary": "fake-dacledit",
            }
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        assert "dacledit" not in srv._recipe_methods
        assert "dacledit" in srv.methods

    def test_recipe_can_replace_itself(self, recipe_dir, server):
        """A recipe file update replaces the previously loaded recipe method."""
        path = write_recipe(recipe_dir, "evolving.py", '''
            RECIPE = {"name": "evolving", "description": "Version 1", "auth": "none", "binary": "echo"}
        ''')
        server._maybe_reload_recipes()
        assert server.methods["evolving"].description == "Version 1"

        time.sleep(0.05)
        path.write_text(textwrap.dedent('''
            RECIPE = {"name": "evolving", "description": "Version 2", "auth": "none", "binary": "echo"}
        '''))
        server._maybe_reload_recipes()
        assert server.methods["evolving"].description == "Version 2"


# ===========================================================================
# Test: recipe params
# ===========================================================================

class TestRecipeParams:
    """Test that recipe parameter definitions are correctly registered."""

    def test_params_schema_with_domain_auth(self, recipe_dir):
        """Recipe with auth=domain gets auth params + custom params + extra_args + timeout."""
        write_recipe(recipe_dir, "paramtest.py", '''
            RECIPE = {
                "name": "param_test",
                "description": "Test params",
                "auth": "domain",
                "binary": "impacket-test",
                "params": {
                    "ca": {"type": "string", "required": True, "description": "CA name"},
                    "template": {"type": "string", "description": "Certificate template"},
                },
            }
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        method = srv.methods["param_test"]

        # Auth params should be present
        assert "target" in method.params
        assert "username" in method.params
        assert "password" in method.params
        assert "domain" in method.params
        assert "hashes" in method.params
        assert "kerberos" in method.params
        assert "dc_ip" in method.params

        # Custom params
        assert method.params["ca"]["required"] is True
        assert method.params["ca"]["type"] == "string"
        assert "template" in method.params

        # Auto-added params
        assert "extra_args" in method.params
        assert "timeout" in method.params

    def test_params_schema_with_no_auth(self, recipe_dir):
        """Recipe with auth=none does NOT get auth params."""
        write_recipe(recipe_dir, "noauth.py", '''
            RECIPE = {
                "name": "no_auth_test",
                "description": "Test no auth",
                "auth": "none",
                "binary": "echo",
                "params": {
                    "ticket": {"type": "string", "required": True, "description": "Ticket file"},
                },
            }
        ''')
        os.environ["MCP_RECIPE_DIR"] = str(recipe_dir)
        try:
            srv = ImpacketServer()
        finally:
            os.environ.pop("MCP_RECIPE_DIR", None)
        method = srv.methods["no_auth_test"]

        # Auth params should NOT be present
        assert "username" not in method.params
        assert "password" not in method.params
        assert "domain" not in method.params
        assert "hashes" not in method.params

        # Custom params
        assert "ticket" in method.params
        # Auto-added
        assert "extra_args" in method.params
        assert "timeout" in method.params


# ===========================================================================
# Test: hot-reload
# ===========================================================================

class TestHotReload:
    """Test the hot-reload mechanism (new/modified/deleted recipes)."""

    def test_new_recipe_discovered(self, recipe_dir, server):
        """A new recipe file added after server start is discovered on reload."""
        assert "late_addition" not in server.methods

        write_recipe(recipe_dir, "late.py", '''
            RECIPE = {"name": "late_addition", "description": "Added later", "auth": "none", "binary": "echo"}
        ''')
        server._maybe_reload_recipes()
        assert "late_addition" in server.methods
        assert "late_addition" in server._recipe_methods

    def test_modified_recipe_reloaded(self, recipe_dir, server):
        """Modified recipe file is reloaded with updated definition."""
        path = write_recipe(recipe_dir, "mutable.py", '''
            RECIPE = {"name": "mutable", "description": "Original", "auth": "none", "binary": "echo"}
        ''')
        server._maybe_reload_recipes()
        assert server.methods["mutable"].description == "Original"

        time.sleep(0.05)
        path.write_text(textwrap.dedent('''
            RECIPE = {"name": "mutable", "description": "Updated", "auth": "none", "binary": "echo"}
        '''))
        server._maybe_reload_recipes()
        assert server.methods["mutable"].description == "Updated"

    def test_deleted_recipe_unregistered(self, recipe_dir, server):
        """Deleted recipe file causes its method to be unregistered."""
        path = write_recipe(recipe_dir, "ephemeral.py", '''
            RECIPE = {"name": "ephemeral", "description": "Temporary", "auth": "none", "binary": "echo"}
        ''')
        server._maybe_reload_recipes()
        assert "ephemeral" in server.methods

        path.unlink()
        server._maybe_reload_recipes()
        assert "ephemeral" not in server.methods
        assert "ephemeral" not in server._recipe_methods

    def test_recipe_dir_removed(self, recipe_dir, server):
        """If recipe directory is removed, all recipe methods are unregistered."""
        write_recipe(recipe_dir, "doomed.py", '''
            RECIPE = {"name": "doomed", "description": "Will be removed", "auth": "none", "binary": "echo"}
        ''')
        server._maybe_reload_recipes()
        assert "doomed" in server.methods

        shutil.rmtree(recipe_dir)
        server._maybe_reload_recipes()
        assert "doomed" not in server.methods
        assert len(server._recipe_methods) == 0

    def test_no_reload_when_unchanged(self, recipe_dir, server):
        """No reload occurs when files haven't changed."""
        write_recipe(recipe_dir, "stable.py", '''
            RECIPE = {"name": "stable", "description": "Stable", "auth": "none", "binary": "echo"}
        ''')
        server._maybe_reload_recipes()

        original_mtimes = dict(server._recipe_mtimes)
        server._maybe_reload_recipes()
        assert server._recipe_mtimes == original_mtimes


# ===========================================================================
# Test: auth building for recipes
# ===========================================================================

class TestRecipeAuthBuilding:
    """Test that recipes use the correct impacket auth builders."""

    @pytest.mark.asyncio
    async def test_domain_auth_recipe(self, recipe_dir, server):
        """Recipe with auth=domain builds domain-style auth args."""
        write_recipe(recipe_dir, "domain_tool.py", '''
            RECIPE = {
                "name": "domain_tool",
                "description": "Domain auth test",
                "auth": "domain",
                "binary": "impacket-test",
                "params": {
                    "action": {"type": "string", "description": "Action to perform"},
                },
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="ok\n", stderr="", returncode=0,
            )
            result = await server.methods["domain_tool"].handler(
                target="10.10.10.1",
                username="admin",
                password="P@ss123",
                domain="CORP.LOCAL",
                action="read",
            )
            cmd = mock_run.call_args[0][0]
            cmd_str = " ".join(cmd)
            # Should have domain/user:pass identity string
            assert "CORP.LOCAL/admin:P@ss123" in cmd_str
            # Should have -dc-ip
            assert "-dc-ip" in cmd
            assert "10.10.10.1" in cmd_str

    @pytest.mark.asyncio
    async def test_target_auth_recipe(self, recipe_dir, server):
        """Recipe with auth=target builds target-style auth args."""
        write_recipe(recipe_dir, "target_tool.py", '''
            RECIPE = {
                "name": "target_tool",
                "description": "Target auth test",
                "auth": "target",
                "binary": "impacket-test",
                "params": {},
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="ok\n", stderr="", returncode=0,
            )
            result = await server.methods["target_tool"].handler(
                target="10.10.10.1",
                username="admin",
                password="P@ss123",
                domain="CORP",
            )
            cmd = mock_run.call_args[0][0]
            cmd_str = " ".join(cmd)
            # Should have domain/user:pass@target identity string
            assert "CORP/admin:P@ss123@10.10.10.1" in cmd_str

    @pytest.mark.asyncio
    async def test_no_auth_recipe(self, recipe_dir, server):
        """Recipe with auth=none builds no auth args."""
        write_recipe(recipe_dir, "noauth_tool.py", '''
            RECIPE = {
                "name": "noauth_tool",
                "description": "No auth test",
                "auth": "none",
                "binary": "echo",
                "params": {
                    "message": {"type": "string", "description": "Message"},
                },
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="hello\n", stderr="", returncode=0,
            )
            result = await server.methods["noauth_tool"].handler(
                message="hello",
            )
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "echo"
            # Should not contain auth-related flags
            cmd_str = " ".join(cmd)
            assert "-dc-ip" not in cmd_str
            assert "-hashes" not in cmd_str
            assert "-k" not in cmd_str

    @pytest.mark.asyncio
    async def test_pass_the_hash_recipe(self, recipe_dir, server):
        """Recipe with hash auth passes -hashes flag."""
        write_recipe(recipe_dir, "pth_tool.py", '''
            RECIPE = {
                "name": "pth_tool",
                "description": "PTH test",
                "auth": "target",
                "binary": "impacket-test",
                "params": {},
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="ok\n", stderr="", returncode=0,
            )
            result = await server.methods["pth_tool"].handler(
                target="10.10.10.1",
                username="admin",
                domain="CORP",
                hashes="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            )
            cmd = mock_run.call_args[0][0]
            assert "-hashes" in cmd
            assert "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" in cmd


# ===========================================================================
# Test: Kerberos env injection
# ===========================================================================

class TestRecipeKerberosEnv:
    """Test that Kerberos environment is injected for recipe calls."""

    @pytest.mark.asyncio
    async def test_kerberos_flag_recipe(self, recipe_dir, server):
        """Recipe with kerberos=True passes -k flag and env."""
        write_recipe(recipe_dir, "kerb_tool.py", '''
            RECIPE = {
                "name": "kerb_tool",
                "description": "Kerberos test",
                "auth": "target",
                "binary": "impacket-test",
                "params": {},
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="ok\n", stderr="", returncode=0,
            )
            # Mock _ensure_krb5_conf to avoid filesystem writes
            with patch.object(server, "_ensure_krb5_conf"):
                result = await server.methods["kerb_tool"].handler(
                    target="10.10.10.1",
                    username="admin",
                    domain="CORP.LOCAL",
                    kerberos=True,
                    dc_ip="10.10.10.1",
                )
            cmd = mock_run.call_args[0][0]
            assert "-k" in cmd
            assert "-no-pass" in cmd  # no password/hash/aes provided


# ===========================================================================
# Test: error classification on recipe methods
# ===========================================================================

class TestRecipeErrorClassification:
    """Test that impacket error classification works on recipe method errors."""

    @pytest.mark.asyncio
    async def test_auth_error_classified(self, recipe_dir, server):
        """Recipe method error with STATUS_LOGON_FAILURE is classified as auth."""
        write_recipe(recipe_dir, "auth_fail.py", '''
            RECIPE = {
                "name": "auth_fail_tool",
                "description": "Auth fail test",
                "auth": "target",
                "binary": "impacket-test",
                "params": {},
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="",
                stderr="SMB SessionError: STATUS_LOGON_FAILURE\n",
                returncode=1,
            )
            result = await server.methods["auth_fail_tool"].handler(
                target="10.10.10.1",
                username="admin",
                password="wrong",
            )
            assert result.success is False
            assert result.error_class == "auth"
            assert result.retryable is False

    @pytest.mark.asyncio
    async def test_network_error_classified(self, recipe_dir, server):
        """Recipe method error with Connection refused is classified as network."""
        write_recipe(recipe_dir, "net_fail.py", '''
            RECIPE = {
                "name": "net_fail_tool",
                "description": "Network fail test",
                "auth": "target",
                "binary": "impacket-test",
                "params": {},
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="",
                stderr="Connection refused\n",
                returncode=1,
            )
            result = await server.methods["net_fail_tool"].handler(
                target="10.10.10.1",
                username="admin",
                password="test",
            )
            assert result.success is False
            assert result.error_class == "network"
            assert result.retryable is True


# ===========================================================================
# Test: extra_args on recipe methods
# ===========================================================================

class TestRecipeExtraArgs:
    """Test that extra_args is forwarded to recipe method calls."""

    @pytest.mark.asyncio
    async def test_extra_args_appended(self, recipe_dir, server):
        """extra_args string is split and appended to the command."""
        write_recipe(recipe_dir, "extra_tool.py", '''
            RECIPE = {
                "name": "extra_tool",
                "description": "Extra args test",
                "auth": "none",
                "binary": "echo",
                "params": {},
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="", stderr="", returncode=0,
            )
            result = await server.methods["extra_tool"].handler(
                extra_args="--deep --threads 8",
            )
            cmd = mock_run.call_args[0][0]
            assert "--deep" in cmd
            assert "--threads" in cmd
            assert "8" in cmd


# ===========================================================================
# Test: script-based recipe
# ===========================================================================

class TestRecipeScript:
    """Test that script-based recipes run correctly."""

    @pytest.mark.asyncio
    async def test_script_recipe_runs_python3(self, recipe_dir, server):
        """Recipe with script field runs python3 <script>."""
        write_recipe(recipe_dir, "script_tool.py", '''
            RECIPE = {
                "name": "script_tool",
                "description": "Script-based recipe",
                "auth": "target",
                "script": "/session/impacket-scripts/exploit.py",
                "params": {
                    "vuln_id": {"type": "string", "description": "CVE ID"},
                },
            }
        ''')
        server._maybe_reload_recipes()

        with patch.object(server, "run_command_with_progress", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                stdout="exploit output\n", stderr="", returncode=0,
            )
            result = await server.methods["script_tool"].handler(
                target="10.10.10.1",
                username="admin",
                password="test",
                vuln_id="CVE-2022-12345",
            )
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "python3"
            assert "/session/impacket-scripts/exploit.py" in cmd[1]


# ===========================================================================
# Test: custom handler recipe
# ===========================================================================

class TestRecipeCustomHandler:
    """Test that recipes with custom async handlers are invoked correctly."""

    def test_handler_receives_kwargs(self, recipe_dir, server):
        """Custom handler receives all method params as kwargs."""
        write_recipe(recipe_dir, "custom_handler.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "custom_handler_test",
                "description": "Custom handler recipe",
                "auth": "none",
                "params": {
                    "msg": {"type": "string", "required": True, "description": "Message"},
                },
            }

            async def handler(server, **kwargs):
                return ToolResult(
                    success=True,
                    data={"received": kwargs, "server_name": server.name},
                )
        ''')
        server._maybe_reload_recipes()
        method = server.methods["custom_handler_test"]

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(method.handler(msg="hello"))
        finally:
            loop.close()

        assert result.success is True
        assert result.data["received"] == {"msg": "hello"}
        assert result.data["server_name"] == "impacket"

    def test_handler_has_server_access(self, recipe_dir, server):
        """Custom handler can access impacket server methods like _build_domain_auth_args."""
        write_recipe(recipe_dir, "server_access.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "server_access_test",
                "description": "Server access test",
                "auth": "none",
                "params": {},
            }

            async def handler(server, **kwargs):
                return ToolResult(
                    success=True,
                    data={
                        "has_build_auth_args": hasattr(server, "_build_auth_args"),
                        "has_build_domain_auth_args": hasattr(server, "_build_domain_auth_args"),
                        "has_classify_error": hasattr(server, "_classify_error"),
                        "server_class": server.__class__.__name__,
                    },
                )
        ''')
        server._maybe_reload_recipes()
        method = server.methods["server_access_test"]

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(method.handler())
        finally:
            loop.close()

        assert result.data["has_build_auth_args"] is True
        assert result.data["has_build_domain_auth_args"] is True
        assert result.data["has_classify_error"] is True
        assert result.data["server_class"] == "ImpacketServer"


# ===========================================================================
# Test: recipe listed in tools via _get_tools
# ===========================================================================

class TestRecipeThroughToolCall:
    """Test recipes invoked through the standard _handle_tool_call path."""

    def test_recipe_listed_in_tools(self, recipe_dir, server):
        """Recipe methods appear in _get_tools()."""
        write_recipe(recipe_dir, "listed.py", '''
            RECIPE = {
                "name": "listed_recipe",
                "description": "Should appear in tools list",
                "auth": "none",
                "binary": "echo",
                "params": {"x": {"type": "string", "required": True, "description": "X"}},
            }
        ''')
        # _get_tools calls _maybe_reload_recipes
        tools = server._get_tools()
        tool_names = {t.name for t in tools}
        assert "listed_recipe" in tool_names

    def test_hot_reload_via_handle_tool_call(self, recipe_dir, server):
        """New recipe is discovered during _handle_tool_call."""
        assert "dynamic_recipe" not in server.methods

        write_recipe(recipe_dir, "dynamic.py", '''
            from mcp_common.base_server import ToolResult

            RECIPE = {
                "name": "dynamic_recipe",
                "description": "Dynamically added",
                "auth": "none",
                "params": {},
            }

            async def handler(server, **kwargs):
                return ToolResult(success=True, data={"dynamic": True})
        ''')

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                server._handle_tool_call("dynamic_recipe", {})
            )
        finally:
            loop.close()

        assert result.isError is False
