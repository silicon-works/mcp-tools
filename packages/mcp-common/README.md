# mcp-common

Shared utilities for OpenSploit MCP tool servers.

## Features

- `BaseMCPServer` - Base class for building MCP servers
- `ToolResult` - Standard result type for tool executions
- Output parsers for common formats (nmap XML, JSON, tables)

## Usage

```python
from mcp_common import BaseMCPServer, ToolResult

class MyToolServer(BaseMCPServer):
    def __init__(self):
        super().__init__("mytool", "Description")
        self.register_method(
            name="my_method",
            description="What it does",
            params={...},
            handler=self.my_method,
        )

    async def my_method(self, **params) -> ToolResult:
        result = await self.run_command(["mytool", ...])
        return ToolResult(success=True, data={...})

if __name__ == "__main__":
    MyToolServer.main()
```

## License

MIT
