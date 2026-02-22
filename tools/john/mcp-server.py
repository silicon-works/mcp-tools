#!/usr/bin/env python3
"""
OpenSploit MCP Server: john

Password hash cracking tool (John the Ripper).
"""

import os
import re
import tempfile
from typing import Dict, List, Optional

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
                    "description": "Hash format (auto-detect if not specified)",
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
                "mask": {
                    "type": "string",
                    "description": "Mask pattern for targeted cracking (alternative to wordlist). ?l=lowercase, ?u=uppercase, ?d=digit, ?s=special, ?a=all. Examples: '?u?l?l?l?d?d?d?d' (Name1234), 'Company?d?d?d?d' (Company + 4 digits). Overrides wordlist if provided.",
                },
                "incremental": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use incremental (brute-force) mode instead of wordlist. Tries all character combinations. Very slow but guaranteed to find the password eventually. Only practical for short passwords (8 chars or less).",
                },
                "fork": {
                    "type": "integer",
                    "description": "Number of processes to fork for parallel cracking. Set to number of CPU cores for maximum speed. Only useful for slow hash types (bcrypt, scrypt).",
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

        self.register_method(
            name="convert",
            description="Extract crackable hash from an encrypted file using *2john converters",
            params={
                "file_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the encrypted file (e.g., SSH private key, ZIP, RAR, PDF, Office doc)",
                },
                "file_type": {
                    "type": "string",
                    "required": True,
                    "enum": ["ssh", "zip", "rar", "pdf", "office", "7z", "keepass", "gpg",
                             "bitcoin", "ethereum", "truecrypt", "luks", "ansible",
                             "bitwarden", "lastpass", "1password", "keychain", "pfx",
                             "mozilla", "telegram", "signal", "dmg", "bitlocker"],
                    "description": "Type of encrypted file — determines which *2john script to use",
                },
            },
            handler=self.convert,
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
        mask: Optional[str] = None,
        incremental: bool = False,
        fork: Optional[int] = None,
    ) -> ToolResult:
        """Crack password hashes."""
        self.logger.info(f"Starting hash cracking")

        # Write hashes to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hashes)
            hash_file = f.name

        try:
            # Build mode args: incremental > mask > wordlist
            if incremental:
                args = ["john", "--incremental"]
            elif mask:
                args = ["john", f"--mask={mask}"]
            else:
                wordlist_path = self._resolve_wordlist(wordlist)
                args = ["john", f"--wordlist={wordlist_path}"]
                if rules:
                    args.append("--rules")

            if format != "auto":
                args.append(f"--format={format}")

            if fork and fork > 1:
                args.append(f"--fork={fork}")

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

            data = {
                "cracked": cracked,
                "count": len(cracked),
                "format": format,
            }
            if incremental:
                data["mode"] = "incremental"
            elif mask:
                data["mode"] = "mask"
                data["mask"] = mask
            else:
                data["mode"] = "wordlist"
                data["wordlist"] = self._resolve_wordlist(wordlist)

            return ToolResult(
                success=True,
                data=data,
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
        """Identify hash format using pattern matching and john format probing."""
        self.logger.info(f"Identifying hash format")
        hash = hash.strip()
        detected = []

        # Pattern-based detection (fast, reliable)
        patterns = {
            r'^\$1\$': 'md5crypt',
            r'^\$5\$': 'sha256crypt',
            r'^\$6\$': 'sha512crypt',
            r'^\$2[aby]\$': 'bcrypt',
            r'^\$P\$': 'phpass',
            r'^\$H\$': 'phpass',
            r'^\$apr1\$': 'md5apr1',
            r'^\$argon2': 'argon2',
            r'^\{SSHA\}': 'SSHA',
            r'^\{SHA\}': 'Raw-SHA1',
            r'^[0-9a-f]{32}$': 'Raw-MD5 or NTLM (32 hex chars)',
            r'^[0-9a-f]{40}$': 'Raw-SHA1 (40 hex chars)',
            r'^[0-9a-f]{64}$': 'Raw-SHA256 (64 hex chars)',
            r'^[0-9a-f]{128}$': 'Raw-SHA512 (128 hex chars)',
            r'^[0-9a-fA-F]{32}:[0-9a-fA-F]+$': 'NTLM with salt or dynamic format',
            r'^\*[0-9A-F]{40}$': 'mysql-sha1 (MySQL 4.1+)',
        }

        for pattern, fmt in patterns.items():
            if re.match(pattern, hash, re.IGNORECASE):
                detected.append(fmt)

        # If no pattern match, fall back to john format probing
        if not detected:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write(hash)
                hash_file = f.name

            try:
                for fmt in ["md5", "sha1", "sha256", "sha512", "ntlm", "bcrypt", "raw-md5", "raw-sha1"]:
                    test_args = ["john", f"--format={fmt}", "--show", hash_file]
                    try:
                        test_result = await self.run_command(test_args, timeout=5)
                        if "0 password hashes cracked" in test_result.stdout or "password hash cracked" in test_result.stdout:
                            detected.append(fmt)
                    except Exception:
                        pass
            finally:
                if os.path.exists(hash_file):
                    os.unlink(hash_file)

        return ToolResult(
            success=True,
            data={
                "hash": hash[:50] + "..." if len(hash) > 50 else hash,
                "possible_formats": detected if detected else ["unknown"],
            },
            raw_output="",
        )

    async def convert(
        self,
        file_path: str,
        file_type: str,
    ) -> ToolResult:
        """Extract crackable hash from an encrypted file using *2john converters."""
        self.logger.info(f"Converting {file_type} file: {file_path}")

        # Map file types to converter scripts/binaries
        # Python/Perl scripts are in /usr/share/john/
        # Compiled binaries are in /usr/sbin/
        converter_map = {
            "ssh": ("/usr/share/john/ssh2john.py", "python3"),
            "zip": ("/usr/sbin/zip2john", None),
            "rar": ("/usr/sbin/rar2john", None),
            "pdf": ("/usr/share/john/pdf2john.pl", "perl"),
            "office": ("/usr/share/john/office2john.py", "python3"),
            "7z": ("/usr/share/john/7z2john.pl", "perl"),
            "keepass": ("/usr/sbin/keepass2john", None),
            "gpg": ("/usr/sbin/gpg2john", None),
            "bitcoin": ("/usr/share/john/bitcoin2john.py", "python3"),
            "ethereum": ("/usr/share/john/ethereum2john.py", "python3"),
            "truecrypt": ("/usr/share/john/truecrypt2john.py", "python3"),
            "luks": ("/usr/share/john/luks2john.py", "python3"),
            "ansible": ("/usr/share/john/ansible2john.py", "python3"),
            "bitwarden": ("/usr/share/john/bitwarden2john.py", "python3"),
            "lastpass": ("/usr/share/john/lastpass2john.py", "python3"),
            "1password": ("/usr/share/john/1password2john.py", "python3"),
            "keychain": ("/usr/share/john/keychain2john.py", "python3"),
            "pfx": ("/usr/share/john/pfx2john.py", "python3"),
            "mozilla": ("/usr/share/john/mozilla2john.py", "python3"),
            "telegram": ("/usr/share/john/telegram2john.py", "python3"),
            "signal": ("/usr/share/john/signal2john.py", "python3"),
            "dmg": ("/usr/share/john/dmg2john.py", "python3"),
            "bitlocker": ("/usr/sbin/bitlocker2john", None),
        }

        entry = converter_map.get(file_type)
        if not entry:
            return ToolResult(success=False, data={}, error=f"Unknown file type: {file_type}")

        converter_path, interpreter = entry

        if interpreter:
            args = [interpreter, converter_path, file_path]
        else:
            args = [converter_path, file_path]

        try:
            result = await self.run_command(args, timeout=30)
            hash_output = result.stdout.strip()

            return ToolResult(
                success=True,
                data={
                    "hash": hash_output,
                    "file": file_path,
                    "converter": os.path.basename(converter_path),
                    "file_type": file_type,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={}, error=str(e))


if __name__ == "__main__":
    JohnServer.main()
