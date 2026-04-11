"""
Shared test infrastructure for MCP tool server testing.

Provides:
- MCPTestClient: async client that starts a Docker container and speaks MCP protocol
- Fixtures: mcp_client, tool_yaml, tool_methods_from_yaml, tool_methods_from_server
- CLI args: --tool, --target, --domain, --username, --password, --image-prefix
- Helpers: parse_tool_output, assert_tool_success, assert_tool_error
- Marks: integration, clock
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pytest
import yaml

logger = logging.getLogger(__name__)

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"


# ---------------------------------------------------------------------------
# Pytest configuration
# ---------------------------------------------------------------------------

def pytest_addoption(parser: pytest.Parser) -> None:
    """Register custom CLI options for per-tool and integration testing."""
    parser.addoption(
        "--tool",
        action="store",
        default=None,
        help="Tool name to test (e.g., 'nmap', 'impacket'). Required for per-tool tests.",
    )
    parser.addoption(
        "--target",
        action="store",
        default=None,
        help="Target IP address for integration tests.",
    )
    parser.addoption(
        "--domain",
        action="store",
        default=None,
        help="Domain name for integration tests (Active Directory).",
    )
    parser.addoption(
        "--username",
        action="store",
        default=None,
        help="Username for integration tests.",
    )
    parser.addoption(
        "--password",
        action="store",
        default=None,
        help="Password for integration tests.",
    )
    parser.addoption(
        "--image-prefix",
        action="store",
        default="mcp-test-",
        help="Docker image name prefix (default: 'mcp-test-').",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: tests that require a live target")
    config.addinivalue_line("markers", "clock: tests that verify FAKETIME / clock offset behavior")


# ---------------------------------------------------------------------------
# MCPTestClient
# ---------------------------------------------------------------------------

# Tools that require --privileged for raw socket access, etc.
PRIVILEGED_TOOLS = frozenset({
    "strongswan", "nmap", "ike-scan", "netcat", "metasploit", "responder",
    "scapy",
})


class MCPTestClient:
    """Async MCP client that manages a Docker container for testing.

    Starts a tool's Docker container, performs the MCP initialize handshake,
    and provides ``list_tools()`` and ``call(method, args)`` for tests.

    The container runs with ``--network=host`` and ``MCP_TEST_MODE=1``.
    FAKETIME can be injected via the ``faketime`` constructor parameter.
    """

    def __init__(
        self,
        image: str,
        tool_name: str,
        privileged: bool = False,
        faketime: Optional[str] = None,
        extra_env: Optional[Dict[str, str]] = None,
        startup_timeout: float = 120.0,
        volumes: Optional[Dict[str, str]] = None,
    ):
        self.image = image
        self.tool_name = tool_name
        self.privileged = privileged or (tool_name in PRIVILEGED_TOOLS)
        self.faketime = faketime
        self.extra_env = extra_env or {}
        self.startup_timeout = startup_timeout
        self.volumes = volumes or {}

        self._proc: Optional[asyncio.subprocess.Process] = None
        self._msg_id: int = 0
        self.tools: List[Dict[str, Any]] = []
        self.server_info: Dict[str, Any] = {}

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        """Start the Docker container and perform MCP initialization."""
        docker_args = ["docker", "run", "-i", "--rm", "--network=host"]

        if self.privileged:
            docker_args.append("--privileged")

        # Always inject MCP_TEST_MODE so verify_clock is registered
        docker_args.extend(["-e", "MCP_TEST_MODE=1"])

        # FAKETIME support
        if self.faketime:
            docker_args.extend(["-e", f"FAKETIME={self.faketime}"])

        # Extra env vars
        for key, val in self.extra_env.items():
            docker_args.extend(["-e", f"{key}={val}"])

        # Volume mounts
        for host_path, container_path in self.volumes.items():
            docker_args.extend(["-v", f"{host_path}:{container_path}"])

        docker_args.append(self.image)

        logger.info("Starting container: %s", " ".join(docker_args))

        self._proc = await asyncio.create_subprocess_exec(
            *docker_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=10 * 1024 * 1024,  # 10 MB buffer for large responses
        )

        # MCP initialize handshake
        init_resp = await self._request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-test-client", "version": "1.0"},
        }, timeout=self.startup_timeout)

        self.server_info = init_resp.get("result", {}).get("serverInfo", {})
        logger.info("Connected to %s: %s", self.image, self.server_info)

        # Discover tools via list_tools
        self.tools = await self.list_tools()
        logger.info(
            "Server advertises %d tools: %s",
            len(self.tools),
            [t["name"] for t in self.tools],
        )

    async def stop(self) -> None:
        """Shut down the container gracefully."""
        if self._proc is None:
            return
        try:
            if self._proc.stdin and not self._proc.stdin.is_closing():
                self._proc.stdin.close()
            # Give the process a moment to exit cleanly
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        except ProcessLookupError:
            pass
        finally:
            self._proc = None

    # -- MCP protocol -------------------------------------------------------

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    async def _send(self, msg: Dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        payload = json.dumps(msg) + "\n"
        self._proc.stdin.write(payload.encode())
        await self._proc.stdin.drain()

    async def _recv(self, timeout: float = 600.0) -> Dict[str, Any]:
        """Read the next JSON-RPC response, skipping notifications."""
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            line = await asyncio.wait_for(
                self._proc.stdout.readline(), timeout=timeout,
            )
            if not line:
                raise ConnectionError("MCP server closed stdout unexpectedly")
            msg = json.loads(line.decode())
            # Skip JSON-RPC notifications (no "id" field) — these are progress etc.
            if "id" in msg:
                return msg

    async def _request(
        self,
        method: str,
        params: Dict[str, Any],
        timeout: float = 600.0,
    ) -> Dict[str, Any]:
        """Send a JSON-RPC request and return the response."""
        msg_id = self._next_id()
        await self._send({
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
            "params": params,
        })
        resp = await self._recv(timeout=timeout)
        if resp.get("id") != msg_id:
            raise RuntimeError(
                f"Response id mismatch: expected {msg_id}, got {resp.get('id')}"
            )
        return resp

    # -- public API ---------------------------------------------------------

    async def list_tools(self, timeout: float = 10.0) -> List[Dict[str, Any]]:
        """Call tools/list and return the list of tool definitions."""
        resp = await self._request("tools/list", {}, timeout=timeout)
        tools = resp.get("result", {}).get("tools", [])
        self.tools = tools
        return tools

    async def call(
        self,
        method: str,
        args: Optional[Dict[str, Any]] = None,
        timeout: float = 600.0,
    ) -> Dict[str, Any]:
        """Call a tool method and return the full JSON-RPC result object.

        The return value has the shape::

            {
                "result": {
                    "content": [{"type": "text", "text": "..."}],
                    "isError": false,
                    "structuredContent": {...}
                }
            }

        Use ``parse_tool_output(resp)`` to extract the parsed data,
        or ``assert_tool_success(resp)`` / ``assert_tool_error(resp)``
        for quick assertions.
        """
        return await self._request(
            "tools/call",
            {"name": method, "arguments": args or {}},
            timeout=timeout,
        )

    def tool_names(self) -> Set[str]:
        """Return the set of method names from the last list_tools call."""
        return {t["name"] for t in self.tools}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_tool_output(response: Dict[str, Any]) -> Any:
    """Extract and parse the tool output from an MCP call response.

    For success responses, attempts to JSON-parse the text content.
    For error responses, returns the raw error text.

    Returns the parsed data (dict/list/str) or raises ValueError on
    unexpected response shapes.
    """
    result = response.get("result")
    if result is None:
        # JSON-RPC error (protocol-level, not tool-level)
        error = response.get("error", {})
        raise ValueError(f"JSON-RPC error: {error}")

    content = result.get("content", [])
    if not content:
        return None

    # Concatenate all text content items
    texts = [item["text"] for item in content if item.get("type") == "text"]
    text = "\n".join(texts) if texts else ""

    if not text:
        return None

    # Try JSON parse first (success responses are JSON)
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text


def assert_tool_success(response: Dict[str, Any], msg: str = "") -> Dict[str, Any]:
    """Assert the tool call succeeded (isError is False).

    Returns the result dict for further assertions.
    Raises AssertionError with helpful context on failure.
    """
    result = response.get("result")
    assert result is not None, f"No result in response{': ' + msg if msg else ''}"

    is_error = result.get("isError", False)
    if is_error:
        content = result.get("content", [])
        error_text = ""
        for item in content:
            if item.get("type") == "text":
                error_text += item["text"]
        detail = f"Tool returned error: {error_text[:500]}"
        if msg:
            detail = f"{msg} -- {detail}"
        raise AssertionError(detail)

    return result


def assert_tool_error(
    response: Dict[str, Any],
    substring: Optional[str] = None,
    msg: str = "",
) -> Dict[str, Any]:
    """Assert the tool call failed (isError is True).

    If *substring* is given, also asserts it appears in the error text.
    Returns the result dict for further assertions.
    """
    result = response.get("result")
    assert result is not None, f"No result in response{': ' + msg if msg else ''}"

    is_error = result.get("isError", False)
    if not is_error:
        detail = "Expected tool error but call succeeded"
        if msg:
            detail = f"{msg} -- {detail}"
        raise AssertionError(detail)

    if substring is not None:
        content = result.get("content", [])
        error_text = ""
        for item in content:
            if item.get("type") == "text":
                error_text += item["text"]
        assert substring in error_text, (
            f"Expected '{substring}' in error text, got: {error_text[:500]}"
            + (f" ({msg})" if msg else "")
        )

    return result


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def tool_name(request: pytest.FixtureRequest) -> str:
    """Return the --tool CLI argument, or skip if not provided."""
    name = request.config.getoption("--tool")
    if name is None:
        pytest.skip("--tool not specified")
    return name


@pytest.fixture(scope="module")
def image_name(request: pytest.FixtureRequest, tool_name: str) -> str:
    """Return the Docker image name for the tool under test."""
    prefix = request.config.getoption("--image-prefix")
    return f"{prefix}{tool_name}"


@pytest.fixture(scope="module")
def tool_yaml(tool_name: str) -> Dict[str, Any]:
    """Load and return the tool's tool.yaml as a dict."""
    yaml_path = TOOLS_DIR / tool_name / "tool.yaml"
    if not yaml_path.exists():
        pytest.skip(f"No tool.yaml found at {yaml_path}")
    with open(yaml_path, "r") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def tool_methods_from_yaml(tool_yaml: Dict[str, Any]) -> Set[str]:
    """Return the set of method names defined in tool.yaml."""
    return set(tool_yaml.get("methods", {}).keys())


@pytest.fixture(scope="module")
def mcp_client(
    request: pytest.FixtureRequest,
    image_name: str,
    tool_name: str,
) -> "MCPTestClient":
    """Module-scoped fixture: starts a container, returns MCPTestClient, stops on teardown.

    Each test module gets its own container — not session-scoped (one bad test
    would kill all subsequent tests) and not function-scoped (too slow).
    """
    # Check for FAKETIME marker or parametrize
    faketime = None
    # Allow per-module faketime via a module-level variable
    module = request.module
    if hasattr(module, "FAKETIME"):
        faketime = getattr(module, "FAKETIME")

    client = MCPTestClient(
        image=image_name,
        tool_name=tool_name,
        faketime=faketime,
    )

    # Run the async start in the event loop
    loop = asyncio.get_event_loop_policy().new_event_loop()
    try:
        loop.run_until_complete(client.start())
    except Exception:
        loop.run_until_complete(client.stop())
        loop.close()
        raise

    yield client

    loop.run_until_complete(client.stop())
    loop.close()


@pytest.fixture(scope="module")
def tool_methods_from_server(mcp_client: MCPTestClient) -> Set[str]:
    """Return the set of method names from the server's list_tools response."""
    return mcp_client.tool_names()


# ---------------------------------------------------------------------------
# Integration test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def target(request: pytest.FixtureRequest) -> str:
    """Return --target or skip."""
    val = request.config.getoption("--target")
    if val is None:
        pytest.skip("--target not specified (required for integration tests)")
    return val


@pytest.fixture(scope="session")
def domain(request: pytest.FixtureRequest) -> Optional[str]:
    """Return --domain or None."""
    return request.config.getoption("--domain")


@pytest.fixture(scope="session")
def username(request: pytest.FixtureRequest) -> Optional[str]:
    """Return --username or None."""
    return request.config.getoption("--username")


@pytest.fixture(scope="session")
def password(request: pytest.FixtureRequest) -> Optional[str]:
    """Return --password or None."""
    return request.config.getoption("--password")
