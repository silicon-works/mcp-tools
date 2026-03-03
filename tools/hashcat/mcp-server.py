#!/usr/bin/env python3
"""
OpenSploit MCP Server: hashcat
Advanced password cracking via hashcat v7.1.2.

Supports dictionary, mask, hybrid, and combinator attacks with
400+ hash modes. CPU-only (no GPU in Docker containers) — uses
-D 1 (CPU device type) and -w 3 (high workload).
"""

import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

HASHCAT_BIN = "/usr/bin/hashcat"
POTFILE = "/tmp/hashcat.potfile"
SESSION_DIR = "/tmp/hashcat_sessions"

WORDLISTS = {
    "rockyou": "/usr/share/wordlists/rockyou.txt",
}

RULES = {
    "best66": "/usr/share/hashcat/rules/best66.rule",
    "rockyou-30000": "/usr/share/hashcat/rules/rockyou-30000.rule",
    "toggles1": "/usr/share/hashcat/rules/toggles1.rule",
    "dive": "/usr/share/hashcat/rules/dive.rule",
    "d3ad0ne": "/usr/share/hashcat/rules/d3ad0ne.rule",
}


class HashcatServer(BaseMCPServer):
    """MCP server wrapping hashcat password cracker."""

    def __init__(self):
        super().__init__(
            name="hashcat",
            description="Advanced password cracking via hashcat",
            version="1.0.0",
        )

        os.makedirs(SESSION_DIR, exist_ok=True)

        self.register_method(
            name="crack_dictionary",
            description="Dictionary attack (-a 0) — wordlist with optional rules",
            params={
                "hashes": {
                    "type": "string",
                    "required": True,
                    "description": "Hash(es) to crack, one per line. Supports user:hash format.",
                },
                "hash_mode": {
                    "type": "integer",
                    "required": True,
                    "description": "Hashcat hash mode number (e.g., 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt). Use 'identify' method if unknown.",
                },
                "wordlist": {
                    "type": "string",
                    "default": "rockyou",
                    "description": "Wordlist name ('rockyou') or absolute path. rockyou: 14M passwords at /usr/share/wordlists/rockyou.txt.",
                },
                "rules": {
                    "type": "string",
                    "description": "Rule file name ('best66', 'rockyou-30000', 'dive', 'toggles1', 'd3ad0ne') or absolute path. best66: 66 effective rules (fast, good coverage), rockyou-30000: aggressive 30K rules, d3ad0ne: community meta-rule. Omit for raw wordlist-only.",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Max cracking time in seconds (default: 300). Hashcat uses --runtime internally.",
                },
                "username": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true if hashes are in user:hash format (enables --username).",
                },
            },
            handler=self.crack_dictionary,
        )

        self.register_method(
            name="crack_mask",
            description="Mask/brute-force attack (-a 3) — pattern-based with optional custom charsets and increment mode",
            params={
                "hashes": {
                    "type": "string",
                    "required": True,
                    "description": "Hash(es) to crack, one per line.",
                },
                "hash_mode": {
                    "type": "integer",
                    "required": True,
                    "description": "Hashcat hash mode number.",
                },
                "mask": {
                    "type": "string",
                    "required": True,
                    "description": "Mask pattern. Built-in charsets: ?l=a-z, ?u=A-Z, ?d=0-9, ?s=special, ?a=all, ?h=hex-lower, ?H=hex-upper. Custom: ?1-?8 (define via custom_charsets). Examples: '?u?l?l?l?d?d?d?d' (Name1234), '?d?d?d?d?d?d' (6-digit PIN), 'Company?d?d?d?d' (literal+mask).",
                },
                "custom_charsets": {
                    "type": "object",
                    "description": "Custom charset definitions. Keys '1'-'8' map to ?1-?8. Values are charset strings. Example: {\"1\": \"?l?d\", \"2\": \"abc123\"} defines ?1=lowercase+digits, ?2=only abc123.",
                },
                "increment": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable mask increment mode — tries lengths from increment_min to mask length. Example: mask '?a?a?a?a' with increment tries 1-char, 2-char, 3-char, 4-char.",
                },
                "increment_min": {
                    "type": "integer",
                    "default": 1,
                    "description": "Start mask incrementing at this length (default: 1).",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Max cracking time in seconds.",
                },
                "username": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true if hashes are in user:hash format.",
                },
            },
            handler=self.crack_mask,
        )

        self.register_method(
            name="crack_hybrid",
            description="Hybrid attack — combine wordlist with mask appending (-a 6) or prepending (-a 7)",
            params={
                "hashes": {
                    "type": "string",
                    "required": True,
                    "description": "Hash(es) to crack, one per line.",
                },
                "hash_mode": {
                    "type": "integer",
                    "required": True,
                    "description": "Hashcat hash mode number.",
                },
                "wordlist": {
                    "type": "string",
                    "required": True,
                    "description": "Wordlist name ('rockyou') or absolute path.",
                },
                "mask": {
                    "type": "string",
                    "required": True,
                    "description": "Mask to append/prepend to each wordlist word. Example: '?d?d?d?d' appends 4 digits to each word (password0000-password9999).",
                },
                "mode": {
                    "type": "string",
                    "default": "wordlist_mask",
                    "description": "'wordlist_mask' (-a 6): word+mask (e.g., password1234). 'mask_wordlist' (-a 7): mask+word (e.g., 1234password).",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Max cracking time in seconds.",
                },
                "username": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true if hashes are in user:hash format.",
                },
            },
            handler=self.crack_hybrid,
        )

        self.register_method(
            name="crack_combinator",
            description="Combinator attack (-a 1) — concatenate words from two wordlists",
            params={
                "hashes": {
                    "type": "string",
                    "required": True,
                    "description": "Hash(es) to crack, one per line.",
                },
                "hash_mode": {
                    "type": "integer",
                    "required": True,
                    "description": "Hashcat hash mode number.",
                },
                "wordlist1": {
                    "type": "string",
                    "required": True,
                    "description": "First wordlist — name ('rockyou') or absolute path.",
                },
                "wordlist2": {
                    "type": "string",
                    "required": True,
                    "description": "Second wordlist — name ('rockyou') or absolute path. Each word from list1 is concatenated with each word from list2.",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Max cracking time in seconds.",
                },
                "username": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true if hashes are in user:hash format.",
                },
            },
            handler=self.crack_combinator,
        )

        self.register_method(
            name="show",
            description="Show previously cracked passwords from hashcat potfile",
            params={
                "hashes": {
                    "type": "string",
                    "required": True,
                    "description": "Hash(es) to check for cracked passwords.",
                },
                "hash_mode": {
                    "type": "integer",
                    "required": True,
                    "description": "Hashcat hash mode number.",
                },
                "username": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true if hashes are in user:hash format.",
                },
            },
            handler=self.show,
        )

        self.register_method(
            name="identify",
            description="Identify hash type — determine possible hashcat mode numbers for a hash",
            params={
                "hash": {
                    "type": "string",
                    "required": True,
                    "description": "Single hash to identify. Provide the raw hash string.",
                },
            },
            handler=self.identify,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _resolve_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path."""
        if wordlist in WORDLISTS:
            return WORDLISTS[wordlist]
        return wordlist

    def _resolve_rules(self, rules: str) -> str:
        """Resolve rule file name to path."""
        if rules in RULES:
            return RULES[rules]
        return rules

    def _base_args(self, hash_mode: int, hash_file: str, timeout: int, username: bool) -> List[str]:
        """Build base hashcat arguments common to all attack modes."""
        args = [
            HASHCAT_BIN,
            "-m", str(hash_mode),
            "--potfile-path", POTFILE,
            "--runtime", str(timeout),
            "-D", "1",          # CPU device type (no GPU in containers)
            "-w", "3",          # High workload profile
            "--force",          # Ignore warnings (no GPU)
            "--quiet",          # Suppress status output (we parse results)
            "-o", "/dev/null",  # Don't write outfile (use potfile)
        ]
        if username:
            args.append("--username")
        args.append(hash_file)
        return args

    def _write_hashes(self, hashes: str) -> str:
        """Write hashes to a temp file, return path."""
        fd, path = tempfile.mkstemp(suffix=".txt", dir=SESSION_DIR)
        with os.fdopen(fd, "w") as f:
            f.write(hashes.strip() + "\n")
        return path

    def _parse_show_output(self, output: str) -> List[Dict[str, str]]:
        """Parse hashcat --show output. Format: hash:plaintext or user:hash:plaintext"""
        cracked = []
        # Lines to skip — hashcat error/info messages that appear in --show output
        skip_patterns = (
            "Hash-type", "Hash.", "Hashfile", "Token length",
            "* Token", "No hashes loaded", "This error happens",
            "malformed", "--username", "--dynamic",
        )
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if any(line.startswith(p) or p in line for p in skip_patterns):
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                # Could be hash:plain or user:hash:plain or hash:salt:plain
                # Simplest: plaintext is always the last field
                cracked.append({
                    "hash": ":".join(parts[:-1]),
                    "plaintext": parts[-1],
                })
        return cracked

    async def _run_and_show(
        self,
        attack_args: List[str],
        hash_file: str,
        hash_mode: int,
        timeout: int,
        username: bool,
        attack_info: Dict[str, Any],
    ) -> ToolResult:
        """Run hashcat attack, then --show to collect results."""
        try:
            # Run the attack
            # Hashcat kernel compilation on CPU can take 30-90s before cracking starts.
            # The 120s margin ensures the outer timeout doesn't fire before --runtime stops hashcat.
            result = await self.run_command(attack_args, timeout=timeout + 120)
            raw = result.stdout + result.stderr

            # Check for hash loading errors (wrong mode, malformed hashes)
            if "No hashes loaded" in raw or "Token length exception" in raw:
                return ToolResult(
                    success=False,
                    error=f"No hashes loaded — hash_mode {hash_mode} may be wrong for this hash format. Use 'identify' to find the correct mode.",
                    raw_output=sanitize_output(raw),
                )

            # Check for invalid hash mode
            if "Invalid -m (hash type) value specified" in raw:
                return ToolResult(
                    success=False,
                    error=f"Invalid hash_mode {hash_mode}. Use 'identify' to find the correct mode number.",
                    raw_output=sanitize_output(raw),
                )

            # Check for unexpected failures — hashcat exit code 255 (-1) means internal error
            # Exit codes 0/1/2/3/4 are normal (cracked/exhausted/aborted/checkpoint/runtime)
            if result.returncode == 255:
                return ToolResult(
                    success=False,
                    error=f"Hashcat internal error (exit {result.returncode}) for hash_mode {hash_mode}. The mode may be invalid. Use 'identify' to find the correct mode.",
                    raw_output=sanitize_output(raw),
                )

            # Run --show to get cracked passwords
            show_args = [
                HASHCAT_BIN,
                "-m", str(hash_mode),
                "--potfile-path", POTFILE,
                "--show",
                "--force",
                "--quiet",
            ]
            if username:
                show_args.append("--username")
            show_args.append(hash_file)

            show_result = await self.run_command(show_args, timeout=30)
            cracked = self._parse_show_output(show_result.stdout)

            data = {
                "cracked": cracked,
                "cracked_count": len(cracked),
                "hash_mode": hash_mode,
            }
            data.update(attack_info)

            # Check if exhausted (all candidates tried)
            exhausted = "Exhausted" in raw or "Status...........: Exhausted" in raw
            if exhausted:
                data["exhausted"] = True

            return ToolResult(
                success=True,
                data=data,
                raw_output=sanitize_output(raw + "\n" + show_result.stdout),
            )

        except Exception as e:
            error_msg = str(e)
            # Check for common hashcat errors
            if "No hashes loaded" in error_msg:
                return ToolResult(
                    success=False,
                    error=f"No hashes loaded — hash_mode {hash_mode} may be wrong for this hash format. Use 'identify' to find the correct mode.",
                    raw_output=sanitize_output(error_msg),
                )
            return ToolResult(
                success=False,
                error=error_msg,
                raw_output=sanitize_output(error_msg),
            )
        finally:
            if os.path.exists(hash_file):
                os.unlink(hash_file)

    # ── Method Handlers ────────────────────────────────────────

    async def crack_dictionary(
        self,
        hashes: str,
        hash_mode: int,
        wordlist: str = "rockyou",
        rules: Optional[str] = None,
        timeout: int = 300,
        username: bool = False,
    ) -> ToolResult:
        """Dictionary attack (-a 0)."""
        if not hashes.strip():
            return ToolResult(success=False, error="No hashes provided.")

        wordlist_path = self._resolve_wordlist(wordlist)
        if not os.path.exists(wordlist_path):
            return ToolResult(success=False, error=f"Wordlist not found: {wordlist_path}")

        hash_file = self._write_hashes(hashes)
        args = self._base_args(hash_mode, hash_file, timeout, username)
        args.extend(["-a", "0", wordlist_path])

        if rules:
            rules_path = self._resolve_rules(rules)
            if os.path.exists(rules_path):
                args.extend(["-r", rules_path])

        attack_info = {
            "attack_mode": "dictionary",
            "wordlist": wordlist_path,
        }
        if rules:
            attack_info["rules"] = self._resolve_rules(rules)

        return await self._run_and_show(args, hash_file, hash_mode, timeout, username, attack_info)

    async def crack_mask(
        self,
        hashes: str,
        hash_mode: int,
        mask: str,
        custom_charsets: Optional[Dict[str, str]] = None,
        increment: bool = False,
        increment_min: int = 1,
        timeout: int = 300,
        username: bool = False,
    ) -> ToolResult:
        """Mask/brute-force attack (-a 3)."""
        if not hashes.strip():
            return ToolResult(success=False, error="No hashes provided.")
        if not mask:
            return ToolResult(success=False, error="Mask pattern is required.")

        hash_file = self._write_hashes(hashes)
        args = self._base_args(hash_mode, hash_file, timeout, username)
        args.extend(["-a", "3"])

        # Custom charsets (?1-?8 supported by hashcat via -1 through -8 flags)
        if custom_charsets:
            for key, value in custom_charsets.items():
                if key in ("1", "2", "3", "4", "5", "6", "7", "8"):
                    args.extend([f"-{key}", value])

        # Increment mode
        if increment:
            args.append("-i")
            args.extend(["--increment-min", str(increment_min)])

        args.append(mask)

        attack_info = {
            "attack_mode": "mask",
            "mask": mask,
        }
        if custom_charsets:
            attack_info["custom_charsets"] = custom_charsets
        if increment:
            attack_info["increment"] = True

        return await self._run_and_show(args, hash_file, hash_mode, timeout, username, attack_info)

    async def crack_hybrid(
        self,
        hashes: str,
        hash_mode: int,
        wordlist: str,
        mask: str,
        mode: str = "wordlist_mask",
        timeout: int = 300,
        username: bool = False,
    ) -> ToolResult:
        """Hybrid attack (-a 6 or -a 7)."""
        if not hashes.strip():
            return ToolResult(success=False, error="No hashes provided.")
        if not mask:
            return ToolResult(success=False, error="Mask pattern is required.")

        wordlist_path = self._resolve_wordlist(wordlist)
        if not os.path.exists(wordlist_path):
            return ToolResult(success=False, error=f"Wordlist not found: {wordlist_path}")

        hash_file = self._write_hashes(hashes)
        args = self._base_args(hash_mode, hash_file, timeout, username)

        if mode == "mask_wordlist":
            # -a 7: mask+wordlist
            args.extend(["-a", "7", mask, wordlist_path])
        else:
            # -a 6: wordlist+mask (default)
            args.extend(["-a", "6", wordlist_path, mask])

        attack_info = {
            "attack_mode": f"hybrid_{mode}",
            "wordlist": wordlist_path,
            "mask": mask,
        }

        return await self._run_and_show(args, hash_file, hash_mode, timeout, username, attack_info)

    async def crack_combinator(
        self,
        hashes: str,
        hash_mode: int,
        wordlist1: str,
        wordlist2: str,
        timeout: int = 300,
        username: bool = False,
    ) -> ToolResult:
        """Combinator attack (-a 1)."""
        if not hashes.strip():
            return ToolResult(success=False, error="No hashes provided.")

        wl1 = self._resolve_wordlist(wordlist1)
        wl2 = self._resolve_wordlist(wordlist2)

        if not os.path.exists(wl1):
            return ToolResult(success=False, error=f"Wordlist1 not found: {wl1}")
        if not os.path.exists(wl2):
            return ToolResult(success=False, error=f"Wordlist2 not found: {wl2}")

        hash_file = self._write_hashes(hashes)
        args = self._base_args(hash_mode, hash_file, timeout, username)
        args.extend(["-a", "1", wl1, wl2])

        attack_info = {
            "attack_mode": "combinator",
            "wordlist1": wl1,
            "wordlist2": wl2,
        }

        return await self._run_and_show(args, hash_file, hash_mode, timeout, username, attack_info)

    async def show(
        self,
        hashes: str,
        hash_mode: int,
        username: bool = False,
    ) -> ToolResult:
        """Show previously cracked passwords from potfile."""
        if not hashes.strip():
            return ToolResult(success=False, error="No hashes provided.")

        hash_file = self._write_hashes(hashes)

        try:
            args = [
                HASHCAT_BIN,
                "-m", str(hash_mode),
                "--potfile-path", POTFILE,
                "--show",
                "--force",
                "--quiet",
            ]
            if username:
                args.append("--username")
            args.append(hash_file)

            result = await self.run_command(args, timeout=30)
            cracked = self._parse_show_output(result.stdout)

            return ToolResult(
                success=True,
                data={
                    "cracked": cracked,
                    "cracked_count": len(cracked),
                    "hash_mode": hash_mode,
                },
                raw_output=sanitize_output(result.stdout),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            if os.path.exists(hash_file):
                os.unlink(hash_file)

    async def identify(
        self,
        hash: str,
    ) -> ToolResult:
        """Identify hash type using hashcat's --identify flag and pattern matching."""
        hash = hash.strip()
        if not hash:
            return ToolResult(success=False, error="No hash provided.")

        possible_modes = []

        # Pattern-based detection (fast, reliable for common types)
        patterns = [
            (r'^\$1\$', [500], "md5crypt"),
            (r'^\$5\$', [7400], "sha256crypt"),
            (r'^\$6\$', [1800], "sha512crypt"),
            (r'^\$2[aby]\$', [3200], "bcrypt"),
            (r'^\$P\$', [400], "phpass"),
            (r'^\$H\$', [400], "phpass"),
            (r'^\$apr1\$', [1600], "Apache $apr1$"),
            (r'^\$argon2id?\$', [1000], "Argon2"),
            (r'^[0-9a-f]{32}$', [0, 1000], "MD5 or NTLM"),
            (r'^[0-9a-f]{40}$', [100], "SHA1"),
            (r'^[0-9a-f]{64}$', [1400], "SHA256"),
            (r'^[0-9a-f]{128}$', [1700], "SHA512"),
            (r'^[0-9a-fA-F]{32}:[0-9a-fA-F]+$', [10, 20], "MD5 with salt"),
            (r'^\*[0-9A-F]{40}$', [300], "MySQL 4.1+"),
            (r'^[0-9a-f]{16}$', [3000], "LM"),
        ]

        for pattern, modes, name in patterns:
            if re.match(pattern, hash, re.IGNORECASE):
                for m in modes:
                    possible_modes.append({"mode": m, "name": name})

        # Also try hashcat --identify
        hash_file = self._write_hashes(hash)
        try:
            args = [
                HASHCAT_BIN,
                "--identify",
                "--force",
                "--quiet",
                hash_file,
            ]
            result = await self.run_command(args, timeout=15)
            output = result.stdout + result.stderr

            # Parse identify output: "The following x hash-modes match..."
            # or individual mode lines
            for line in output.split("\n"):
                line = line.strip()
                # Match lines like "# | Name | Category"
                # or "  100 | SHA1 | Raw Hash"
                match = re.match(r'^\s*(\d+)\s*\|\s*(.+?)\s*\|', line)
                if match:
                    mode_num = int(match.group(1))
                    mode_name = match.group(2).strip()
                    # Avoid duplicates
                    if not any(p["mode"] == mode_num for p in possible_modes):
                        possible_modes.append({"mode": mode_num, "name": mode_name})

        except Exception:
            pass
        finally:
            if os.path.exists(hash_file):
                os.unlink(hash_file)

        return ToolResult(
            success=True,
            data={
                "hash": hash[:80] + "..." if len(hash) > 80 else hash,
                "possible_modes": possible_modes if possible_modes else [{"mode": -1, "name": "unknown"}],
            },
            raw_output="",
        )


if __name__ == "__main__":
    HashcatServer.main()
