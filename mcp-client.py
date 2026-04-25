#!/usr/bin/env python3
"""MCP client for testing tool servers.

Usage:
  Single command:   python3 mcp-client.py <image> <method> [params-json]
  Interactive mode: python3 mcp-client.py <image> -i

Examples:
  python3 mcp-client.py mcp-zap-test spider '{"target": "http://example.com"}'
  python3 mcp-client.py mcp-zap-test -i

In interactive mode, enter commands as: method_name {"param": "value"}
Type 'quit', 'exit', or Ctrl+C to exit.
"""

import asyncio
import json
import readline  # Enables arrow keys and history in input
import sys


class MCPClient:
    def __init__(self, image):
        self.image = image
        self.proc = None
        self.msg_id = 0
        self.tools = []

    async def start(self):
        """Start the MCP server container."""
        docker_args = ["docker", "run", "-i", "--rm", "--network=host"]
        privileged_tools = ["strongswan", "nmap", "ike-scan", "netcat", "metasploit", "responder"]
        if any(tool in self.image.lower() for tool in privileged_tools):
            docker_args.append("--privileged")
            print(f"[MCP] Running in privileged mode")
        docker_args.append(self.image)

        self.proc = await asyncio.create_subprocess_exec(
            *docker_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=10 * 1024 * 1024,  # 10MB buffer for large base64 image responses
        )

        # Initialize
        await self._send({"jsonrpc": "2.0", "id": self._next_id(), "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "mcp-client", "version": "1.0"}
        }})
        resp = await self._recv(timeout=120)  # ZAP needs ~60s to start
        print(f"[MCP] Connected to {self.image}")
        print(f"[MCP] Server: {resp.get('result', {}).get('serverInfo', {})}")

        # List tools
        await self._send({"jsonrpc": "2.0", "id": self._next_id(), "method": "tools/list", "params": {}})
        resp = await self._recv(timeout=10)
        self.tools = resp.get("result", {}).get("tools", [])
        print(f"\n[MCP] Available tools:")
        for t in self.tools:
            print(f"  - {t['name']}: {t.get('description', '')[:60]}")
        print()

    def _next_id(self):
        self.msg_id += 1
        return self.msg_id

    async def _send(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()

    async def _recv(self, timeout=600):
        while True:
            line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=timeout)
            if not line:
                return None
            msg = json.loads(line.decode())
            # Print notifications (progress heartbeats) instead of silently skipping
            if "id" not in msg:
                params = msg.get("params", {})
                progress_msg = params.get("message", "")
                if progress_msg:
                    print(f"  [PROGRESS] {progress_msg}", flush=True)
                continue
            return msg

    async def call(self, method, params=None, timeout=3600):
        """Call a tool method."""
        msg_id = self._next_id()
        await self._send({
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": "tools/call",
            "params": {
                "name": method,
                "arguments": params or {},
                "_meta": {"progressToken": msg_id},
            }
        })
        return await self._recv(timeout=timeout)

    async def stop(self):
        """Stop the container."""
        if self.proc:
            self.proc.stdin.close()
            await self.proc.wait()


async def single_command(image, method, params):
    """Run a single command and exit."""
    client = MCPClient(image)
    try:
        await client.start()
        print(f"[MCP] Calling {method}...")
        resp = await client.call(method, params)
        print(f"\n[MCP] Result:")
        print(json.dumps(resp.get("result", resp.get("error", {})), indent=2))
    except asyncio.TimeoutError:
        print("[MCP] Timeout waiting for response")
    except Exception as e:
        print(f"[MCP] Error: {e}")
    finally:
        await client.stop()


async def interactive_mode(image):
    """Run interactive REPL mode."""
    client = MCPClient(image)
    try:
        await client.start()
        print("[MCP] Interactive mode. Enter: method_name {\"param\": \"value\"}")
        print("[MCP] Type 'help' for commands, 'quit' to exit.\n")

        while True:
            try:
                line = input("mcp> ").strip()
            except EOFError:
                break

            if not line:
                continue

            if line.lower() in ("quit", "exit", "q"):
                break

            if line.lower() == "help":
                print("\nCommands:")
                print("  <method> [json-params]  - Call a tool method")
                print("  tools                   - List available tools")
                print("  quit / exit             - Exit interactive mode")
                print("\nExamples:")
                print('  spider {"target": "http://example.com", "max_depth": 2}')
                print('  get_urls {"target": "http://example.com"}')
                print("  scan_status")
                print()
                continue

            if line.lower() == "tools":
                for t in client.tools:
                    print(f"  {t['name']}: {t.get('description', '')}")
                print()
                continue

            # Parse command: method [json-params]
            parts = line.split(None, 1)
            method = parts[0]
            params = {}
            if len(parts) > 1:
                try:
                    params = json.loads(parts[1])
                except json.JSONDecodeError as e:
                    print(f"[Error] Invalid JSON: {e}")
                    continue

            # Call the method
            print(f"[MCP] Calling {method}...")
            try:
                resp = await client.call(method, params)
                result = resp.get("result", resp.get("error", {}))

                # Pretty print, handling nested JSON in text content
                if isinstance(result, dict) and "content" in result:
                    for item in result.get("content", []):
                        if item.get("type") == "text":
                            try:
                                parsed = json.loads(item["text"])
                                print(json.dumps(parsed, indent=2))
                            except:
                                print(item["text"])
                        else:
                            print(json.dumps(item, indent=2))
                else:
                    print(json.dumps(result, indent=2))
                print()

            except asyncio.TimeoutError:
                print("[MCP] Timeout waiting for response\n")
            except Exception as e:
                print(f"[MCP] Error: {e}\n")

    except KeyboardInterrupt:
        print("\n[MCP] Interrupted")
    except Exception as e:
        print(f"[MCP] Error: {e}")
    finally:
        print("[MCP] Closing connection...")
        await client.stop()


async def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    image = sys.argv[1]

    # Interactive mode
    if len(sys.argv) == 3 and sys.argv[2] == "-i":
        await interactive_mode(image)
        return

    # Single command mode
    if len(sys.argv) < 3:
        print("Usage: python3 mcp-client.py <image> <method> [params-json]")
        print("       python3 mcp-client.py <image> -i  (interactive mode)")
        sys.exit(1)

    method = sys.argv[2]
    params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    await single_command(image, method, params)


if __name__ == "__main__":
    asyncio.run(main())
