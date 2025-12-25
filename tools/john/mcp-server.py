#!/usr/bin/env python3
"""
OpenSploit MCP Server: john

Password hash cracking tool (John the Ripper).
"""

import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class JohnServer(BaseMCPServer):
    """MCP server wrapping John the Ripper password cracker."""

    WORDLISTS = {
        "rockyou": "/usr/share/wordlists/rockyou.txt",
        "common": "/usr/share/john/password.lst",
    }

    FORMATS = [
        "auto", "md5", "sha1", "sha256", "sha512", "bcrypt", "ntlm", "lm",
        "mysql", "mssql", "oracle", "postgres", "raw-md5", "raw-sha1",
        "raw-sha256", "raw-sha512", "descrypt", "bsdicrypt", "md5crypt",
        "sha256crypt", "sha512crypt", "zip", "rar", "pdf", "ssh", "pkzip",
    ]

    def __init__(self):
        super().__init__(
            name="john",
            description="Password hash cracking tool (John the Ripper)",
            version="1.0.0",
        )

        self.register_method(
            name="crack",
            description="Crack password hashes using wordlist or incremental mode",
            params={
                "hashes": {
                    "type": "string",
                    "required": True,
                    "description": "Hash(es) to crack, one per line, or in user:hash format",
                },
                "format": {
                    "type": "string",
                    "default": "auto",
                    "description": f"Hash format (auto-detect if not specified)",
                },
                "wordlist": {
                    "type": "string",
                    "default": "rockyou",
                    "description": "Wordlist name (rockyou, common) or path",
                },
                "rules": {
                    "type": "boolean",
                    "default": True,
                    "description": "Apply word mangling rules",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Maximum time to spend cracking in seconds",
                },
            },
            handler=self.crack,
        )

        self.register_method(
            name="show",
            description="Show previously cracked passwords from a hash file",
            params={
                "hashes": {
                    "type": "string",
                    "required": True,
                    "description": "Hash(es) to check for cracked passwords",
                },
                "format": {
                    "type": "string",
                    "default": "auto",
                    "description": "Hash format",
                },
            },
            handler=self.show,
        )

        self.register_method(
            name="identify",
            description="Identify the format of a hash",
            params={
                "hash": {
                    "type": "string",
                    "required": True,
                    "description": "Hash to identify",
                },
            },
            handler=self.identify,
        )

    def _resolve_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path."""
        if wordlist in self.WORDLISTS:
            return self.WORDLISTS[wordlist]
        return wordlist

    def _parse_cracked(self, output: str) -> List[Dict[str, str]]:
        """Parse john output for cracked passwords."""
        cracked = []

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("Using ") or line.startswith("Loaded "):
                continue

            # Format: password (username) or just password
            match = re.match(r"^(.+?)\s+\((.+?)\)$", line)
            if match:
                cracked.append({
                    "password": match.group(1),
                    "user": match.group(2),
                })
            elif ":" in line:
                # user:password format
                parts = line.split(":", 1)
                if len(parts) == 2:
                    cracked.append({
                        "user": parts[0],
                        "password": parts[1],
                    })

        return cracked

    async def crack(
        self,
        hashes: str,
        format: str = "auto",
        wordlist: str = "rockyou",
        rules: bool = True,
        timeout: int = 300,
    ) -> ToolResult:
        """Crack password hashes."""
        self.logger.info(f"Starting hash cracking")

        # Write hashes to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hashes)
            hash_file = f.name

        try:
            wordlist_path = self._resolve_wordlist(wordlist)

            args = ["john", f"--wordlist={wordlist_path}"]

            if format != "auto":
                args.append(f"--format={format}")

            if rules:
                args.append("--rules")

            args.append(hash_file)

            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            # Now show cracked passwords
            show_args = ["john", "--show"]
            if format != "auto":
                show_args.append(f"--format={format}")
            show_args.append(hash_file)

            show_result = await self.run_command(show_args, timeout=30)

            cracked = self._parse_cracked(show_result.stdout)

            return ToolResult(
                success=True,
                data={
                    "cracked": cracked,
                    "count": len(cracked),
                    "format": format,
                    "wordlist": wordlist_path,
                },
                raw_output=sanitize_output(result.stdout + result.stderr + "\n" + show_result.stdout),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(hash_file):
                os.unlink(hash_file)

    async def show(
        self,
        hashes: str,
        format: str = "auto",
    ) -> ToolResult:
        """Show previously cracked passwords."""
        self.logger.info("Showing cracked passwords")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hashes)
            hash_file = f.name

        try:
            args = ["john", "--show"]
            if format != "auto":
                args.append(f"--format={format}")
            args.append(hash_file)

            result = await self.run_command(args, timeout=30)
            cracked = self._parse_cracked(result.stdout)

            return ToolResult(
                success=True,
                data={
                    "cracked": cracked,
                    "count": len(cracked),
                },
                raw_output=sanitize_output(result.stdout),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(hash_file):
                os.unlink(hash_file)

    async def identify(
        self,
        hash: str,
    ) -> ToolResult:
        """Identify hash format."""
        self.logger.info(f"Identifying hash format")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hash)
            hash_file = f.name

        try:
            # john --list=format-all-details is too verbose
            # Use john with the hash and capture format detection
            args = ["john", "--show", hash_file]

            result = await self.run_command(args, timeout=10)

            # Try to detect format by loading with different formats
            detected_formats = []
            for fmt in ["md5", "sha1", "sha256", "sha512", "ntlm", "bcrypt", "raw-md5", "raw-sha1"]:
                test_args = ["john", f"--format={fmt}", "--show", hash_file]
                try:
                    test_result = await self.run_command(test_args, timeout=5)
                    if "0 password hashes cracked" in test_result.stdout or "password hash cracked" in test_result.stdout:
                        detected_formats.append(fmt)
                except:
                    pass

            return ToolResult(
                success=True,
                data={
                    "hash": hash[:50] + "..." if len(hash) > 50 else hash,
                    "possible_formats": detected_formats if detected_formats else ["unknown"],
                },
                raw_output=sanitize_output(result.stdout),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(hash_file):
                os.unlink(hash_file)


if __name__ == "__main__":
    JohnServer.main()
