#!/usr/bin/env python3
"""
OpenSploit MCP Server: hash-lookup

Online hash lookup tool for querying public hash databases.
Useful for quickly checking if a hash has been cracked before.
"""

import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult


# Hash type detection patterns
HASH_PATTERNS = {
    "md5": r"^[a-fA-F0-9]{32}$",
    "sha1": r"^[a-fA-F0-9]{40}$",
    "sha256": r"^[a-fA-F0-9]{64}$",
    "sha512": r"^[a-fA-F0-9]{128}$",
    "ntlm": r"^[a-fA-F0-9]{32}$",  # Same as MD5, need context
    "mysql": r"^\*[a-fA-F0-9]{40}$",  # MySQL 4.1+
    "bcrypt": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$",
}


class HashLookupServer(BaseMCPServer):
    """MCP server for online hash lookup."""

    def __init__(self):
        super().__init__(
            name="hash-lookup",
            description="Online hash lookup via public databases",
            version="1.0.0",
        )

        self.register_method(
            name="lookup",
            description="Look up a hash in online databases",
            params={
                "hash": {
                    "type": "string",
                    "required": True,
                    "description": "Hash value to look up",
                },
                "hash_type": {
                    "type": "enum",
                    "values": ["auto", "md5", "sha1", "sha256", "ntlm"],
                    "default": "auto",
                    "description": "Hash type (auto-detect if not specified)",
                },
            },
            handler=self.lookup,
        )

        self.register_method(
            name="lookup_batch",
            description="Look up multiple hashes at once",
            params={
                "hashes": {
                    "type": "array",
                    "required": True,
                    "description": "List of hashes to look up",
                },
                "hash_type": {
                    "type": "enum",
                    "values": ["auto", "md5", "sha1", "sha256", "ntlm"],
                    "default": "auto",
                    "description": "Hash type for all hashes",
                },
            },
            handler=self.lookup_batch,
        )

        self.register_method(
            name="identify",
            description="Identify the type of a hash",
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
            name="generate",
            description="Generate hash from plaintext (for testing/comparison)",
            params={
                "plaintext": {
                    "type": "string",
                    "required": True,
                    "description": "Text to hash",
                },
                "hash_type": {
                    "type": "enum",
                    "values": ["md5", "sha1", "sha256", "sha512", "ntlm"],
                    "default": "md5",
                    "description": "Hash algorithm to use",
                },
            },
            handler=self.generate,
        )

    def _detect_hash_type(self, hash_value: str) -> List[str]:
        """Detect possible hash types based on format."""
        possible_types = []
        hash_value = hash_value.strip()

        for hash_type, pattern in HASH_PATTERNS.items():
            if re.match(pattern, hash_value):
                possible_types.append(hash_type)

        # If 32 chars, could be MD5 or NTLM
        if len(hash_value) == 32 and hash_value.isalnum():
            if "md5" not in possible_types:
                possible_types.append("md5")
            if "ntlm" not in possible_types:
                possible_types.append("ntlm")

        return possible_types if possible_types else ["unknown"]

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: int = 10,
    ) -> Optional[str]:
        """Make an HTTP request."""
        if headers is None:
            headers = {}

        headers.setdefault("User-Agent", "OpenSploit-HashLookup/1.0")

        try:
            if data and method == "POST":
                encoded_data = urllib.parse.urlencode(data).encode()
                request = urllib.request.Request(url, data=encoded_data, headers=headers)
            else:
                request = urllib.request.Request(url, headers=headers)

            ctx = ssl.create_default_context()
            response = urllib.request.urlopen(request, timeout=timeout, context=ctx)
            return response.read().decode("utf-8", errors="replace")

        except urllib.error.HTTPError as e:
            self.logger.warning(f"HTTP error {e.code}: {e.reason}")
            return None
        except Exception as e:
            self.logger.warning(f"Request error: {e}")
            return None

    def _lookup_hashes_com(self, hash_value: str) -> Optional[str]:
        """Look up hash on hashes.com (free API)."""
        # hashes.com API endpoint
        url = f"https://hashes.com/en/api/identifier?hash={hash_value}"

        response = self._make_request(url)
        if not response:
            return None

        try:
            data = json.loads(response)
            if data.get("success") and data.get("result"):
                # Check if any result has plaintext
                for result in data["result"]:
                    if result.get("plaintext"):
                        return result["plaintext"]
        except json.JSONDecodeError:
            pass

        return None

    def _lookup_nitrxgen(self, hash_value: str, hash_type: str = "md5") -> Optional[str]:
        """Look up hash on nitrxgen API."""
        # nitrxgen free API
        url = f"https://www.nitrxgen.net/md5db/{hash_value}"

        response = self._make_request(url)
        if response and response.strip():
            # Returns plaintext directly if found
            return response.strip()

        return None

    def _lookup_cmd5(self, hash_value: str) -> Optional[str]:
        """Look up hash on cmd5.org (limited free lookups)."""
        # cmd5 has rate limits, use sparingly
        url = f"https://www.cmd5.org/api.ashx?email=test@test.com&key=test&hash={hash_value}"

        response = self._make_request(url)
        if response and not response.startswith("CMD5"):
            return response.strip()

        return None

    def _lookup_hashtoolkit(self, hash_value: str) -> Optional[str]:
        """Look up hash on hashtoolkit.com."""
        url = f"https://hashtoolkit.com/reverse-hash?hash={hash_value}"

        response = self._make_request(url, timeout=15)
        if not response:
            return None

        # Parse HTML response for result
        # Look for pattern like: <span class="res-text">password</span>
        match = re.search(r'class="res-text"[^>]*>([^<]+)</span>', response)
        if match:
            return match.group(1)

        return None

    async def lookup(
        self,
        hash: str,
        hash_type: str = "auto",
    ) -> ToolResult:
        """Look up a single hash."""
        hash_value = hash.strip().lower()
        self.logger.info(f"Looking up hash: {hash_value[:16]}...")

        # Detect hash type if auto
        if hash_type == "auto":
            detected_types = self._detect_hash_type(hash_value)
            hash_type = detected_types[0] if detected_types else "unknown"

        # Try multiple sources
        sources_tried = []
        plaintext = None

        # 1. Try hashes.com first (best free API)
        sources_tried.append("hashes.com")
        plaintext = self._lookup_hashes_com(hash_value)
        if plaintext:
            return ToolResult(
                success=True,
                data={
                    "hash": hash_value,
                    "hash_type": hash_type,
                    "plaintext": plaintext,
                    "source": "hashes.com",
                    "cracked": True,
                },
                raw_output=f"{hash_value} : {plaintext}",
            )

        # 2. Try nitrxgen (MD5 only, fast)
        if hash_type in ["md5", "auto"]:
            sources_tried.append("nitrxgen")
            plaintext = self._lookup_nitrxgen(hash_value)
            if plaintext:
                return ToolResult(
                    success=True,
                    data={
                        "hash": hash_value,
                        "hash_type": "md5",
                        "plaintext": plaintext,
                        "source": "nitrxgen",
                        "cracked": True,
                    },
                    raw_output=f"{hash_value} : {plaintext}",
                )

        # 3. Try hashtoolkit
        sources_tried.append("hashtoolkit")
        plaintext = self._lookup_hashtoolkit(hash_value)
        if plaintext:
            return ToolResult(
                success=True,
                data={
                    "hash": hash_value,
                    "hash_type": hash_type,
                    "plaintext": plaintext,
                    "source": "hashtoolkit",
                    "cracked": True,
                },
                raw_output=f"{hash_value} : {plaintext}",
            )

        # Not found
        return ToolResult(
            success=True,
            data={
                "hash": hash_value,
                "hash_type": hash_type,
                "plaintext": None,
                "sources_tried": sources_tried,
                "cracked": False,
            },
            raw_output=f"{hash_value} : NOT FOUND (tried: {', '.join(sources_tried)})",
        )

    async def lookup_batch(
        self,
        hashes: List[str],
        hash_type: str = "auto",
    ) -> ToolResult:
        """Look up multiple hashes."""
        self.logger.info(f"Batch lookup of {len(hashes)} hashes")

        results = []
        cracked = []
        not_found = []

        for hash_value in hashes:
            result = await self.lookup(hash_value, hash_type)
            data = result.data

            results.append(data)
            if data.get("cracked"):
                cracked.append(f"{data['hash']}:{data['plaintext']}")
            else:
                not_found.append(data["hash"])

        output_lines = []
        if cracked:
            output_lines.append("=== CRACKED ===")
            output_lines.extend(cracked)
        if not_found:
            output_lines.append(f"\n=== NOT FOUND ({len(not_found)}) ===")
            output_lines.extend(not_found[:10])  # Limit output
            if len(not_found) > 10:
                output_lines.append(f"... and {len(not_found) - 10} more")

        return ToolResult(
            success=True,
            data={
                "results": results,
                "total": len(hashes),
                "cracked_count": len(cracked),
                "not_found_count": len(not_found),
            },
            raw_output="\n".join(output_lines),
        )

    async def identify(self, hash: str) -> ToolResult:
        """Identify hash type."""
        hash_value = hash.strip()
        self.logger.info(f"Identifying hash: {hash_value[:16]}...")

        possible_types = self._detect_hash_type(hash_value)

        # Provide more context
        type_info = {
            "md5": "MD5 - 128-bit hash, commonly used for passwords",
            "sha1": "SHA-1 - 160-bit hash, legacy password storage",
            "sha256": "SHA-256 - 256-bit hash, modern password storage",
            "sha512": "SHA-512 - 512-bit hash, high security",
            "ntlm": "NTLM - Windows password hash",
            "mysql": "MySQL 4.1+ password hash",
            "bcrypt": "bcrypt - Adaptive password hashing (slow to crack)",
            "unknown": "Unknown hash type",
        }

        descriptions = [type_info.get(t, t) for t in possible_types]

        return ToolResult(
            success=True,
            data={
                "hash": hash_value,
                "length": len(hash_value),
                "possible_types": possible_types,
                "descriptions": descriptions,
            },
            raw_output=f"Hash: {hash_value}\nPossible types: {', '.join(possible_types)}",
        )

    async def generate(
        self,
        plaintext: str,
        hash_type: str = "md5",
    ) -> ToolResult:
        """Generate hash from plaintext."""
        self.logger.info(f"Generating {hash_type} hash")

        try:
            if hash_type == "md5":
                hash_value = hashlib.md5(plaintext.encode()).hexdigest()
            elif hash_type == "sha1":
                hash_value = hashlib.sha1(plaintext.encode()).hexdigest()
            elif hash_type == "sha256":
                hash_value = hashlib.sha256(plaintext.encode()).hexdigest()
            elif hash_type == "sha512":
                hash_value = hashlib.sha512(plaintext.encode()).hexdigest()
            elif hash_type == "ntlm":
                # NTLM is MD4 of UTF-16LE encoded password
                import binascii
                hash_value = hashlib.new(
                    "md4", plaintext.encode("utf-16le")
                ).hexdigest()
            else:
                return ToolResult(
                    success=False,
                    data={},
                    error=f"Unsupported hash type: {hash_type}",
                )

            return ToolResult(
                success=True,
                data={
                    "plaintext": plaintext,
                    "hash_type": hash_type,
                    "hash": hash_value,
                },
                raw_output=f"{plaintext}:{hash_value}",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    HashLookupServer.main()
