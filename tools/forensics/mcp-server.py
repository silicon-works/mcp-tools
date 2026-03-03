#!/usr/bin/env python3
"""
OpenSploit MCP Server: forensics
File analysis bundle — binwalk v2.4.3, foremost v1.5.7, steghide v0.5.1,
exiftool v13.50. Six methods: extract (binwalk recursive extraction),
analyze (binwalk signature scan), carve (foremost file carving),
stego_extract (steghide data extraction), stego_info (steghide file info),
metadata (exiftool JSON output).
"""

import glob
import json
import os
import re
import shutil
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

SESSION_DIR = "/session"


class ForensicsServer(BaseMCPServer):
    """MCP server wrapping binwalk, foremost, steghide, and exiftool."""

    def __init__(self):
        super().__init__(
            name="forensics",
            description="File analysis bundle — binwalk, foremost, steghide, exiftool",
            version="1.0.0",
        )

        self.register_method(
            name="extract",
            description="Extract embedded files using binwalk — recursive signature-based extraction (-e -M)",
            params={
                "file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to file to analyze (must be under /session/).",
                },
                "depth": {
                    "type": "integer",
                    "default": 8,
                    "description": "Max recursion depth for matryoshka extraction (-d). Default 8. Reduce for large files to prevent long runtimes.",
                },
            },
            handler=self.extract,
        )

        self.register_method(
            name="analyze",
            description="Scan file for embedded signatures without extracting (binwalk -B)",
            params={
                "file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to file to scan (must be under /session/).",
                },
            },
            handler=self.analyze,
        )

        self.register_method(
            name="carve",
            description="Carve files from disk image or binary using foremost — recovers files by header/footer signatures",
            params={
                "file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to file/image to carve from (must be under /session/).",
                },
                "types": {
                    "type": "string",
                    "description": "Comma-separated file types to carve: jpg, gif, png, bmp, avi, exe, mpg, wav, riff, wmv, mov, pdf, ole, doc, zip, rar, htm, cpp, all. Default: all types.",
                },
            },
            handler=self.carve,
        )

        self.register_method(
            name="stego_extract",
            description="Extract hidden data from steganographic file using steghide — supports JPEG, BMP, WAV, AU formats",
            params={
                "file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to stego file (JPEG/BMP/WAV/AU) containing hidden data.",
                },
                "passphrase": {
                    "type": "string",
                    "default": "",
                    "description": "Passphrase for extraction. Use empty string for no passphrase (steghide embed without -p).",
                },
            },
            handler=self.stego_extract,
        )

        self.register_method(
            name="stego_info",
            description="Display info about a potential steganographic file — shows format, capacity, and whether data is embedded (steghide info)",
            params={
                "file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to file to inspect.",
                },
            },
            handler=self.stego_info,
        )

        self.register_method(
            name="metadata",
            description="Extract file metadata using exiftool — EXIF, XMP, IPTC, GPS, timestamps, camera info, PDF properties, and more",
            params={
                "file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to file to extract metadata from.",
                },
            },
            handler=self.metadata,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _validate_file(self, file_path: str) -> Optional[ToolResult]:
        """Validate file exists. Returns ToolResult error or None if OK."""
        if not file_path:
            return ToolResult(success=False, error="No file path provided.")
        if not os.path.exists(file_path):
            return ToolResult(success=False, error=f"File not found: {file_path}")
        if os.path.isdir(file_path):
            return ToolResult(success=False, error=f"Path is a directory, not a file: {file_path}")
        return None

    def _list_files_recursive(self, directory: str) -> List[str]:
        """List all files under a directory recursively."""
        files = []
        if not os.path.isdir(directory):
            return files
        for root, dirs, filenames in os.walk(directory):
            for fname in filenames:
                files.append(os.path.join(root, fname))
        return sorted(files)

    def _parse_binwalk_output(self, output: str) -> List[Dict[str, str]]:
        """Parse binwalk signature scan output into structured data."""
        signatures = []
        for line in output.strip().split("\n"):
            line = line.strip()
            # Skip header lines and separators
            if not line or line.startswith("DECIMAL") or line.startswith("---") or line.startswith("Scan"):
                continue
            # Format: DECIMAL       HEXADECIMAL     DESCRIPTION
            match = re.match(r'^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$', line)
            if match:
                signatures.append({
                    "offset_decimal": int(match.group(1)),
                    "offset_hex": match.group(2),
                    "description": match.group(3).strip(),
                })
        return signatures

    # ── Method Handlers ────────────────────────────────────────

    async def extract(
        self,
        file: str,
        depth: int = 8,
    ) -> ToolResult:
        """Extract embedded files using binwalk -e -M."""
        err = self._validate_file(file)
        if err:
            return err

        # Create unique extraction directory
        basename = os.path.basename(file).replace(".", "_")
        extract_dir = os.path.join(SESSION_DIR, f"extracted_{basename}")

        # Clean previous extraction
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir, exist_ok=True)

        cmd = [
            "binwalk",
            "-e",               # extract
            "-M",               # matryoshka (recursive)
            "-d", str(depth),   # max recursion depth
            "-C", extract_dir,  # output directory
            "--run-as=root",    # allow extraction utils as root (container)
            file,
        ]

        try:
            result = await self.run_command(cmd, timeout=300)
            raw = result.stdout + result.stderr

            # Parse signatures found
            signatures = self._parse_binwalk_output(result.stdout)

            # List extracted files
            extracted = self._list_files_recursive(extract_dir)

            return ToolResult(
                success=True,
                data={
                    "signatures_found": signatures,
                    "signature_count": len(signatures),
                    "extracted_files": extracted,
                    "extracted_count": len(extracted),
                    "extract_directory": extract_dir,
                },
                raw_output=sanitize_output(raw),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    async def analyze(
        self,
        file: str,
    ) -> ToolResult:
        """Scan file for signatures without extracting (binwalk -B)."""
        err = self._validate_file(file)
        if err:
            return err

        cmd = ["binwalk", "-B", file]

        try:
            result = await self.run_command(cmd, timeout=120)
            raw = result.stdout + result.stderr

            signatures = self._parse_binwalk_output(result.stdout)

            return ToolResult(
                success=True,
                data={
                    "signatures": signatures,
                    "signature_count": len(signatures),
                    "file": file,
                },
                raw_output=sanitize_output(raw),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    async def carve(
        self,
        file: str,
        types: Optional[str] = None,
    ) -> ToolResult:
        """Carve files from binary/image using foremost."""
        err = self._validate_file(file)
        if err:
            return err

        # Create unique output directory
        basename = os.path.basename(file).replace(".", "_")
        carve_dir = os.path.join(SESSION_DIR, f"carved_{basename}")

        # Clean previous carving
        if os.path.exists(carve_dir):
            shutil.rmtree(carve_dir)

        cmd = [
            "foremost",
            "-o", carve_dir,    # output directory
            "-i", file,         # input file
        ]

        if types:
            cmd.extend(["-t", types])

        try:
            result = await self.run_command(cmd, timeout=300)
            raw = result.stdout + result.stderr

            # List carved files (foremost creates subdirs by type)
            carved = self._list_files_recursive(carve_dir)
            # Filter out audit.txt (foremost's log)
            carved_files = [f for f in carved if not f.endswith("audit.txt")]

            # Parse audit.txt for summary
            audit_path = os.path.join(carve_dir, "audit.txt")
            audit_summary = ""
            if os.path.exists(audit_path):
                with open(audit_path, "r") as f:
                    audit_summary = f.read()

            return ToolResult(
                success=True,
                data={
                    "carved_files": carved_files,
                    "carved_count": len(carved_files),
                    "carve_directory": carve_dir,
                    "audit_summary": audit_summary[:2000],
                },
                raw_output=sanitize_output(raw + "\n" + audit_summary[:2000]),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    async def stego_extract(
        self,
        file: str,
        passphrase: str = "",
    ) -> ToolResult:
        """Extract hidden data from steganographic file using steghide."""
        err = self._validate_file(file)
        if err:
            return err

        basename = os.path.basename(file).replace(".", "_")
        output_path = os.path.join(SESSION_DIR, f"stego_out_{basename}")

        # Remove old output file to avoid false positives
        if os.path.exists(output_path):
            os.unlink(output_path)

        cmd = [
            "steghide", "extract",
            "-sf", file,        # stego file
            "-xf", output_path, # extract to
            "-p", passphrase,   # passphrase (empty = no passphrase)
            "-f",               # force overwrite
        ]

        try:
            result = await self.run_command(cmd, timeout=60)
            raw = result.stdout + result.stderr

            # Check for extraction errors in stderr
            if "could not extract" in raw.lower() or "passphrase" in result.stderr.lower():
                return ToolResult(
                    success=False,
                    error="Extraction failed — wrong passphrase or no hidden data embedded.",
                    raw_output=sanitize_output(raw),
                )

            if os.path.exists(output_path):
                size = os.path.getsize(output_path)
                # Try to read content if small enough
                content = ""
                if size < 4096:
                    try:
                        with open(output_path, "r", errors="replace") as f:
                            content = f.read()
                    except Exception:
                        content = "(binary data)"

                return ToolResult(
                    success=True,
                    data={
                        "output_path": output_path,
                        "size_bytes": size,
                        "content": content if content else "(binary data)",
                    },
                    raw_output=sanitize_output(raw),
                )
            else:
                # steghide didn't produce output — check for errors
                error_msg = raw.strip() if raw.strip() else "No data extracted. Wrong passphrase or no hidden data."
                return ToolResult(success=False, error=error_msg, raw_output=sanitize_output(raw))

        except Exception as e:
            error_str = str(e)
            if "could not extract" in error_str.lower() or "passphrase" in error_str.lower():
                return ToolResult(
                    success=False,
                    error="Extraction failed — wrong passphrase or no hidden data embedded.",
                    raw_output=sanitize_output(error_str),
                )
            return ToolResult(success=False, error=error_str, raw_output=sanitize_output(error_str))

    async def stego_info(
        self,
        file: str,
    ) -> ToolResult:
        """Display info about a potential steganographic file using steghide info."""
        err = self._validate_file(file)
        if err:
            return err

        # Pass empty passphrase to avoid interactive prompt in non-TTY mode.
        # With -p "", steghide will attempt to reveal embedded file info:
        #   - If data is embedded: prints "embedded file ..." line
        #   - If no data: prints "could not extract any data with that passphrase!"
        cmd = ["steghide", "info", "-p", "", file]

        try:
            result = await self.run_command(cmd, timeout=30)
            raw = result.stdout + result.stderr

            # Check for format errors
            if "not supported" in raw.lower():
                return ToolResult(
                    success=False,
                    error="Unsupported file format. Steghide supports JPEG, BMP, WAV, AU only.",
                    raw_output=sanitize_output(raw),
                )

            # Parse steghide info output
            info = {
                "file": file,
                "format": "",
                "capacity": "",
                "embedded": False,
            }

            for line in raw.split("\n"):
                line = line.strip()
                if line.startswith("format:"):
                    info["format"] = line.split(":", 1)[1].strip()
                elif line.startswith("capacity:"):
                    info["capacity"] = line.split(":", 1)[1].strip()
                elif line.startswith("embedded file"):
                    info["embedded"] = True

            return ToolResult(
                success=True,
                data=info,
                raw_output=sanitize_output(raw),
            )
        except Exception as e:
            error_str = str(e)
            if "unsupported" in error_str.lower():
                return ToolResult(
                    success=False,
                    error="Unsupported file format. Steghide supports JPEG, BMP, WAV, AU only.",
                    raw_output=sanitize_output(error_str),
                )
            return ToolResult(success=False, error=error_str, raw_output=sanitize_output(error_str))

    async def metadata(
        self,
        file: str,
    ) -> ToolResult:
        """Extract metadata using exiftool -j (JSON output)."""
        err = self._validate_file(file)
        if err:
            return err

        cmd = ["exiftool", "-j", file]

        try:
            result = await self.run_command(cmd, timeout=30)
            raw = result.stdout

            # exiftool -j outputs a JSON array
            try:
                metadata_list = json.loads(raw)
                metadata = metadata_list[0] if metadata_list else {}
            except (json.JSONDecodeError, IndexError):
                metadata = {"raw": raw[:2000]}

            return ToolResult(
                success=True,
                data={
                    "metadata": metadata,
                    "field_count": len(metadata),
                    "file": file,
                },
                raw_output=sanitize_output(raw),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))


if __name__ == "__main__":
    ForensicsServer.main()
