#!/usr/bin/env python3
"""
OpenSploit MCP Server: target-tracker

Tracks target state throughout a penetration test engagement.
Provides structured memory of discovered hosts, ports, credentials,
vulnerabilities, and attack history.

This enables the agent to maintain context across operations and
make informed decisions about next steps.
"""

import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime

from mcp_common import BaseMCPServer, ToolResult


class CredentialStatus(str, Enum):
    DISCOVERED = "discovered"  # Found but not tested
    TESTING = "testing"        # Currently being tested
    VALID = "valid"            # Confirmed working
    INVALID = "invalid"        # Tested and failed
    EXPIRED = "expired"        # Was valid, now expired


class VulnerabilityStatus(str, Enum):
    POTENTIAL = "potential"    # Suspected but not confirmed
    CONFIRMED = "confirmed"    # Confirmed exploitable
    EXPLOITED = "exploited"    # Successfully exploited
    PATCHED = "patched"        # Was vulnerable, now patched


@dataclass
class Port:
    """Discovered port information."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    discovered_at: float = field(default_factory=time.time)


@dataclass
class Credential:
    """Discovered credential."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    username: str = ""
    password: Optional[str] = None
    hash: Optional[str] = None
    private_key: Optional[str] = None
    service: Optional[str] = None  # ssh, smb, web, etc.
    source: Optional[str] = None   # Where found (file, bruteforce, etc.)
    status: CredentialStatus = CredentialStatus.DISCOVERED
    tested_at: Optional[float] = None
    valid_for: List[str] = field(default_factory=list)  # List of host:port
    notes: Optional[str] = None


@dataclass
class Vulnerability:
    """Discovered vulnerability."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    cve: Optional[str] = None
    name: str = ""
    description: Optional[str] = None
    severity: Optional[str] = None  # critical, high, medium, low
    affected_component: Optional[str] = None  # service/port/app
    status: VulnerabilityStatus = VulnerabilityStatus.POTENTIAL
    exploit_available: bool = False
    exploit_used: Optional[str] = None
    discovered_at: float = field(default_factory=time.time)
    exploited_at: Optional[float] = None
    notes: Optional[str] = None


@dataclass
class Session:
    """Active session on target."""
    id: str
    session_type: str  # ssh, reverse_shell, web_shell
    user: Optional[str] = None
    privilege_level: Optional[str] = None  # user, root, system
    established_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    shell_session_id: Optional[str] = None  # Reference to shell-session


@dataclass
class Loot:
    """Retrieved file or data."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    loot_type: str = "file"  # file, hash, key, config, database
    path: Optional[str] = None
    content_preview: Optional[str] = None
    size_bytes: Optional[int] = None
    retrieved_at: float = field(default_factory=time.time)
    notes: Optional[str] = None


@dataclass
class AttackAttempt:
    """Record of an attack attempt."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    attack_type: str = ""  # exploit, bruteforce, injection, etc.
    target_service: Optional[str] = None
    tool_used: Optional[str] = None
    payload: Optional[str] = None
    success: bool = False
    result: Optional[str] = None
    attempted_at: float = field(default_factory=time.time)
    notes: Optional[str] = None


@dataclass
class Target:
    """Complete target state."""
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None

    # Discovered information
    ports: Dict[int, Port] = field(default_factory=dict)
    credentials: Dict[str, Credential] = field(default_factory=dict)
    vulnerabilities: Dict[str, Vulnerability] = field(default_factory=dict)
    sessions: Dict[str, Session] = field(default_factory=dict)
    loot: Dict[str, Loot] = field(default_factory=dict)
    attack_history: List[AttackAttempt] = field(default_factory=list)

    # Metadata
    discovered_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Flags
    user_owned: bool = False
    root_owned: bool = False


class TargetTrackerServer(BaseMCPServer):
    """
    MCP server for tracking target state during penetration tests.

    Maintains structured memory of discovered hosts, services, credentials,
    vulnerabilities, and attack history. This enables the agent to maintain
    context and make informed decisions.
    """

    def __init__(self):
        super().__init__(
            name="target-tracker",
            description="Track target state, credentials, vulnerabilities, and attack history",
            version="1.0.0",
        )

        # In-memory target storage
        self.targets: Dict[str, Target] = {}

        # Persistence file (optional)
        self.data_file = os.environ.get("TARGET_DATA_FILE", "/tmp/targets.json")
        self._load_data()

        # Register target methods
        self.register_method(
            name="add_target",
            description="Add or update a target host",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP address"},
                "hostname": {"type": "string", "description": "Target hostname"},
                "os": {"type": "string", "description": "Operating system"},
                "os_version": {"type": "string", "description": "OS version"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for categorization"},
            },
            handler=self.add_target,
        )

        self.register_method(
            name="get_target",
            description="Get complete state for a target",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP address"},
            },
            handler=self.get_target,
        )

        self.register_method(
            name="list_targets",
            description="List all tracked targets",
            params={
                "filter_owned": {"type": "boolean", "description": "Only show owned targets"},
                "filter_tag": {"type": "string", "description": "Filter by tag"},
            },
            handler=self.list_targets,
        )

        # Port methods
        self.register_method(
            name="add_port",
            description="Add discovered port/service to target",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "port": {"type": "integer", "required": True, "description": "Port number"},
                "protocol": {"type": "string", "default": "tcp", "description": "Protocol (tcp/udp)"},
                "service": {"type": "string", "description": "Service name"},
                "version": {"type": "string", "description": "Service version"},
                "banner": {"type": "string", "description": "Service banner"},
            },
            handler=self.add_port,
        )

        # Credential methods
        self.register_method(
            name="add_credential",
            description="Add discovered credential",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "username": {"type": "string", "required": True, "description": "Username"},
                "password": {"type": "string", "description": "Password"},
                "hash": {"type": "string", "description": "Password hash"},
                "private_key": {"type": "string", "description": "SSH private key"},
                "service": {"type": "string", "description": "Service (ssh, smb, web)"},
                "source": {"type": "string", "description": "Where credential was found"},
                "status": {"type": "string", "enum": ["discovered", "testing", "valid", "invalid"], "default": "discovered"},
            },
            handler=self.add_credential,
        )

        self.register_method(
            name="update_credential",
            description="Update credential status after testing",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "credential_id": {"type": "string", "required": True, "description": "Credential ID"},
                "status": {"type": "string", "required": True, "enum": ["discovered", "testing", "valid", "invalid", "expired"]},
                "notes": {"type": "string", "description": "Additional notes"},
            },
            handler=self.update_credential,
        )

        self.register_method(
            name="get_credentials",
            description="Get credentials for a target, optionally filtered",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "status": {"type": "string", "enum": ["discovered", "testing", "valid", "invalid", "expired"], "description": "Filter by status"},
                "service": {"type": "string", "description": "Filter by service"},
            },
            handler=self.get_credentials,
        )

        # Vulnerability methods
        self.register_method(
            name="add_vulnerability",
            description="Add discovered vulnerability",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "name": {"type": "string", "required": True, "description": "Vulnerability name"},
                "cve": {"type": "string", "description": "CVE identifier"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Severity level"},
                "affected_component": {"type": "string", "description": "Affected service/component"},
                "description": {"type": "string", "description": "Vulnerability description"},
                "exploit_available": {"type": "boolean", "default": False, "description": "Is exploit available"},
            },
            handler=self.add_vulnerability,
        )

        self.register_method(
            name="update_vulnerability",
            description="Update vulnerability status",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "vuln_id": {"type": "string", "required": True, "description": "Vulnerability ID"},
                "status": {"type": "string", "required": True, "enum": ["potential", "confirmed", "exploited", "patched"]},
                "exploit_used": {"type": "string", "description": "Exploit that was used"},
                "notes": {"type": "string", "description": "Additional notes"},
            },
            handler=self.update_vulnerability,
        )

        # Session methods
        self.register_method(
            name="add_session",
            description="Register an active session on target",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "session_id": {"type": "string", "required": True, "description": "Session ID (from shell-session)"},
                "session_type": {"type": "string", "required": True, "enum": ["ssh", "reverse_shell", "web_shell"]},
                "user": {"type": "string", "description": "User context"},
                "privilege_level": {"type": "string", "enum": ["user", "root", "system"], "description": "Privilege level"},
            },
            handler=self.add_session,
        )

        self.register_method(
            name="remove_session",
            description="Remove closed session",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "session_id": {"type": "string", "required": True, "description": "Session ID"},
            },
            handler=self.remove_session,
        )

        # Loot methods
        self.register_method(
            name="add_loot",
            description="Record retrieved file or data",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "name": {"type": "string", "required": True, "description": "Loot name/filename"},
                "loot_type": {"type": "string", "default": "file", "enum": ["file", "hash", "key", "config", "database", "flag"]},
                "path": {"type": "string", "description": "Original path on target"},
                "content_preview": {"type": "string", "description": "Preview of content"},
                "notes": {"type": "string", "description": "Additional notes"},
            },
            handler=self.add_loot,
        )

        # Attack history methods
        self.register_method(
            name="record_attack",
            description="Record an attack attempt",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "attack_type": {"type": "string", "required": True, "description": "Type of attack"},
                "target_service": {"type": "string", "description": "Target service/port"},
                "tool_used": {"type": "string", "description": "Tool used"},
                "payload": {"type": "string", "description": "Payload used"},
                "success": {"type": "boolean", "required": True, "description": "Was attack successful"},
                "result": {"type": "string", "description": "Result description"},
            },
            handler=self.record_attack,
        )

        self.register_method(
            name="get_attack_history",
            description="Get attack history for target",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "attack_type": {"type": "string", "description": "Filter by attack type"},
                "success_only": {"type": "boolean", "description": "Only show successful attacks"},
            },
            handler=self.get_attack_history,
        )

        # Ownership flags
        self.register_method(
            name="mark_owned",
            description="Mark target as owned (user or root)",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "level": {"type": "string", "required": True, "enum": ["user", "root"], "description": "Ownership level"},
            },
            handler=self.mark_owned,
        )

        # Notes
        self.register_method(
            name="add_note",
            description="Add a note to target",
            params={
                "ip": {"type": "string", "required": True, "description": "Target IP"},
                "note": {"type": "string", "required": True, "description": "Note content"},
            },
            handler=self.add_note,
        )

        # Summary methods
        self.register_method(
            name="get_summary",
            description="Get engagement summary",
            params={},
            handler=self.get_summary,
        )

        self.register_method(
            name="suggest_next_steps",
            description="Get suggested next steps based on current state",
            params={
                "ip": {"type": "string", "description": "Target IP (optional, for specific target)"},
            },
            handler=self.suggest_next_steps,
        )

    def _load_data(self):
        """Load persisted data if available."""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r") as f:
                    data = json.load(f)
                    # Reconstruct Target objects
                    for ip, target_data in data.items():
                        self.targets[ip] = self._dict_to_target(target_data)
                self.logger.info(f"Loaded {len(self.targets)} targets from {self.data_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load data: {e}")

    def _save_data(self):
        """Persist current data."""
        try:
            data = {ip: self._target_to_dict(t) for ip, t in self.targets.items()}
            with open(self.data_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to save data: {e}")

    def _target_to_dict(self, target: Target) -> dict:
        """Convert Target to dictionary for JSON serialization."""
        d = asdict(target)
        # Convert enums to strings
        for cred in d.get("credentials", {}).values():
            if isinstance(cred.get("status"), CredentialStatus):
                cred["status"] = cred["status"].value
        for vuln in d.get("vulnerabilities", {}).values():
            if isinstance(vuln.get("status"), VulnerabilityStatus):
                vuln["status"] = vuln["status"].value
        return d

    def _dict_to_target(self, d: dict) -> Target:
        """Convert dictionary to Target object."""
        target = Target(ip=d["ip"])
        target.hostname = d.get("hostname")
        target.os = d.get("os")
        target.os_version = d.get("os_version")
        target.discovered_at = d.get("discovered_at", time.time())
        target.last_updated = d.get("last_updated", time.time())
        target.notes = d.get("notes", [])
        target.tags = d.get("tags", [])
        target.user_owned = d.get("user_owned", False)
        target.root_owned = d.get("root_owned", False)

        # Reconstruct nested objects
        for port_num, port_data in d.get("ports", {}).items():
            target.ports[int(port_num)] = Port(**port_data)

        for cred_id, cred_data in d.get("credentials", {}).items():
            if isinstance(cred_data.get("status"), str):
                cred_data["status"] = CredentialStatus(cred_data["status"])
            target.credentials[cred_id] = Credential(**cred_data)

        for vuln_id, vuln_data in d.get("vulnerabilities", {}).items():
            if isinstance(vuln_data.get("status"), str):
                vuln_data["status"] = VulnerabilityStatus(vuln_data["status"])
            target.vulnerabilities[vuln_id] = Vulnerability(**vuln_data)

        for sess_id, sess_data in d.get("sessions", {}).items():
            target.sessions[sess_id] = Session(**sess_data)

        for loot_id, loot_data in d.get("loot", {}).items():
            target.loot[loot_id] = Loot(**loot_data)

        for attack_data in d.get("attack_history", []):
            target.attack_history.append(AttackAttempt(**attack_data))

        return target

    def _ensure_target(self, ip: str) -> Target:
        """Ensure target exists, create if not."""
        if ip not in self.targets:
            self.targets[ip] = Target(ip=ip)
        return self.targets[ip]

    async def add_target(
        self,
        ip: str,
        hostname: Optional[str] = None,
        os: Optional[str] = None,
        os_version: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> ToolResult:
        """Add or update a target."""
        target = self._ensure_target(ip)

        if hostname:
            target.hostname = hostname
        if os:
            target.os = os
        if os_version:
            target.os_version = os_version
        if tags:
            target.tags = list(set(target.tags + tags))

        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "hostname": target.hostname, "tags": target.tags},
            raw_output=f"Target {ip} added/updated",
        )

    async def get_target(self, ip: str) -> ToolResult:
        """Get complete target state."""
        if ip not in self.targets:
            return ToolResult(
                success=False,
                data={"ip": ip},
                error=f"Target not found: {ip}",
            )

        target = self.targets[ip]
        return ToolResult(
            success=True,
            data=self._target_to_dict(target),
            raw_output=json.dumps(self._target_to_dict(target), indent=2),
        )

    async def list_targets(
        self,
        filter_owned: Optional[bool] = None,
        filter_tag: Optional[str] = None,
    ) -> ToolResult:
        """List all targets."""
        targets = []

        for ip, target in self.targets.items():
            if filter_owned and not (target.user_owned or target.root_owned):
                continue
            if filter_tag and filter_tag not in target.tags:
                continue

            targets.append({
                "ip": ip,
                "hostname": target.hostname,
                "os": target.os,
                "ports_count": len(target.ports),
                "credentials_count": len(target.credentials),
                "user_owned": target.user_owned,
                "root_owned": target.root_owned,
                "tags": target.tags,
            })

        return ToolResult(
            success=True,
            data={"targets": targets, "total": len(targets)},
            raw_output=f"Found {len(targets)} targets",
        )

    async def add_port(
        self,
        ip: str,
        port: int,
        protocol: str = "tcp",
        service: Optional[str] = None,
        version: Optional[str] = None,
        banner: Optional[str] = None,
    ) -> ToolResult:
        """Add discovered port."""
        target = self._ensure_target(ip)

        port_obj = Port(
            port=port,
            protocol=protocol,
            service=service,
            version=version,
            banner=banner,
        )
        target.ports[port] = port_obj
        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "port": port, "service": service},
            raw_output=f"Added port {port}/{protocol} ({service or 'unknown'}) to {ip}",
        )

    async def add_credential(
        self,
        ip: str,
        username: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        private_key: Optional[str] = None,
        service: Optional[str] = None,
        source: Optional[str] = None,
        status: str = "discovered",
    ) -> ToolResult:
        """Add discovered credential."""
        target = self._ensure_target(ip)

        cred = Credential(
            username=username,
            password=password,
            hash=hash,
            private_key=private_key,
            service=service,
            source=source,
            status=CredentialStatus(status),
        )
        target.credentials[cred.id] = cred
        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "credential_id": cred.id, "username": username},
            raw_output=f"Added credential {username} (id: {cred.id}) for {ip}",
        )

    async def update_credential(
        self,
        ip: str,
        credential_id: str,
        status: str,
        notes: Optional[str] = None,
    ) -> ToolResult:
        """Update credential status."""
        if ip not in self.targets:
            return ToolResult(
                success=False,
                data={"ip": ip},
                error=f"Target not found: {ip}",
            )

        target = self.targets[ip]
        if credential_id not in target.credentials:
            return ToolResult(
                success=False,
                data={"ip": ip, "credential_id": credential_id},
                error=f"Credential not found: {credential_id}",
            )

        cred = target.credentials[credential_id]
        cred.status = CredentialStatus(status)
        cred.tested_at = time.time()
        if notes:
            cred.notes = notes

        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "credential_id": credential_id, "status": status},
            raw_output=f"Updated credential {credential_id} to status: {status}",
        )

    async def get_credentials(
        self,
        ip: str,
        status: Optional[str] = None,
        service: Optional[str] = None,
    ) -> ToolResult:
        """Get credentials for target."""
        if ip not in self.targets:
            return ToolResult(
                success=False,
                data={"ip": ip},
                error=f"Target not found: {ip}",
            )

        target = self.targets[ip]
        creds = []

        for cred in target.credentials.values():
            if status and cred.status.value != status:
                continue
            if service and cred.service != service:
                continue
            creds.append({
                "id": cred.id,
                "username": cred.username,
                "password": "***" if cred.password else None,
                "hash": cred.hash[:20] + "..." if cred.hash else None,
                "service": cred.service,
                "status": cred.status.value,
                "source": cred.source,
            })

        return ToolResult(
            success=True,
            data={"ip": ip, "credentials": creds, "total": len(creds)},
            raw_output=json.dumps(creds, indent=2),
        )

    async def add_vulnerability(
        self,
        ip: str,
        name: str,
        cve: Optional[str] = None,
        severity: Optional[str] = None,
        affected_component: Optional[str] = None,
        description: Optional[str] = None,
        exploit_available: bool = False,
    ) -> ToolResult:
        """Add discovered vulnerability."""
        target = self._ensure_target(ip)

        vuln = Vulnerability(
            name=name,
            cve=cve,
            severity=severity,
            affected_component=affected_component,
            description=description,
            exploit_available=exploit_available,
        )
        target.vulnerabilities[vuln.id] = vuln
        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "vuln_id": vuln.id, "name": name, "cve": cve},
            raw_output=f"Added vulnerability {name} ({cve or 'no CVE'}) to {ip}",
        )

    async def update_vulnerability(
        self,
        ip: str,
        vuln_id: str,
        status: str,
        exploit_used: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ToolResult:
        """Update vulnerability status."""
        if ip not in self.targets:
            return ToolResult(
                success=False,
                data={"ip": ip},
                error=f"Target not found: {ip}",
            )

        target = self.targets[ip]
        if vuln_id not in target.vulnerabilities:
            return ToolResult(
                success=False,
                data={"ip": ip, "vuln_id": vuln_id},
                error=f"Vulnerability not found: {vuln_id}",
            )

        vuln = target.vulnerabilities[vuln_id]
        vuln.status = VulnerabilityStatus(status)
        if status == "exploited":
            vuln.exploited_at = time.time()
        if exploit_used:
            vuln.exploit_used = exploit_used
        if notes:
            vuln.notes = notes

        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "vuln_id": vuln_id, "status": status},
            raw_output=f"Updated vulnerability {vuln_id} to status: {status}",
        )

    async def add_session(
        self,
        ip: str,
        session_id: str,
        session_type: str,
        user: Optional[str] = None,
        privilege_level: Optional[str] = None,
    ) -> ToolResult:
        """Register active session."""
        target = self._ensure_target(ip)

        session = Session(
            id=session_id,
            session_type=session_type,
            user=user,
            privilege_level=privilege_level,
            shell_session_id=session_id,
        )
        target.sessions[session_id] = session
        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "session_id": session_id, "type": session_type},
            raw_output=f"Registered {session_type} session on {ip}",
        )

    async def remove_session(
        self,
        ip: str,
        session_id: str,
    ) -> ToolResult:
        """Remove closed session."""
        if ip not in self.targets:
            return ToolResult(
                success=False,
                data={"ip": ip},
                error=f"Target not found: {ip}",
            )

        target = self.targets[ip]
        if session_id in target.sessions:
            del target.sessions[session_id]
            target.last_updated = time.time()
            self._save_data()
            return ToolResult(
                success=True,
                data={"ip": ip, "session_id": session_id},
                raw_output=f"Removed session {session_id} from {ip}",
            )

        return ToolResult(
            success=False,
            data={"ip": ip, "session_id": session_id},
            error=f"Session not found: {session_id}",
        )

    async def add_loot(
        self,
        ip: str,
        name: str,
        loot_type: str = "file",
        path: Optional[str] = None,
        content_preview: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ToolResult:
        """Record retrieved loot."""
        target = self._ensure_target(ip)

        loot = Loot(
            name=name,
            loot_type=loot_type,
            path=path,
            content_preview=content_preview[:500] if content_preview else None,
            notes=notes,
        )
        target.loot[loot.id] = loot
        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "loot_id": loot.id, "name": name, "type": loot_type},
            raw_output=f"Added loot: {name} ({loot_type}) from {ip}",
        )

    async def record_attack(
        self,
        ip: str,
        attack_type: str,
        success: bool,
        target_service: Optional[str] = None,
        tool_used: Optional[str] = None,
        payload: Optional[str] = None,
        result: Optional[str] = None,
    ) -> ToolResult:
        """Record attack attempt."""
        target = self._ensure_target(ip)

        attack = AttackAttempt(
            attack_type=attack_type,
            target_service=target_service,
            tool_used=tool_used,
            payload=payload,
            success=success,
            result=result,
        )
        target.attack_history.append(attack)
        target.last_updated = time.time()
        self._save_data()

        status = "SUCCESS" if success else "FAILED"
        return ToolResult(
            success=True,
            data={"ip": ip, "attack_id": attack.id, "type": attack_type, "success": success},
            raw_output=f"[{status}] {attack_type} on {ip}:{target_service or 'unknown'}",
        )

    async def get_attack_history(
        self,
        ip: str,
        attack_type: Optional[str] = None,
        success_only: Optional[bool] = None,
    ) -> ToolResult:
        """Get attack history."""
        if ip not in self.targets:
            return ToolResult(
                success=False,
                data={"ip": ip},
                error=f"Target not found: {ip}",
            )

        target = self.targets[ip]
        attacks = []

        for attack in target.attack_history:
            if attack_type and attack.attack_type != attack_type:
                continue
            if success_only and not attack.success:
                continue
            attacks.append(asdict(attack))

        return ToolResult(
            success=True,
            data={"ip": ip, "attacks": attacks, "total": len(attacks)},
            raw_output=f"Found {len(attacks)} attack records for {ip}",
        )

    async def mark_owned(
        self,
        ip: str,
        level: str,
    ) -> ToolResult:
        """Mark target as owned."""
        target = self._ensure_target(ip)

        if level == "user":
            target.user_owned = True
        elif level == "root":
            target.root_owned = True
            target.user_owned = True  # Root implies user

        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "level": level, "user_owned": target.user_owned, "root_owned": target.root_owned},
            raw_output=f"Target {ip} marked as {level} owned!",
        )

    async def add_note(
        self,
        ip: str,
        note: str,
    ) -> ToolResult:
        """Add note to target."""
        target = self._ensure_target(ip)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        target.notes.append(f"[{timestamp}] {note}")
        target.last_updated = time.time()
        self._save_data()

        return ToolResult(
            success=True,
            data={"ip": ip, "notes_count": len(target.notes)},
            raw_output=f"Note added to {ip}",
        )

    async def get_summary(self) -> ToolResult:
        """Get engagement summary."""
        total_targets = len(self.targets)
        user_owned = sum(1 for t in self.targets.values() if t.user_owned)
        root_owned = sum(1 for t in self.targets.values() if t.root_owned)
        total_ports = sum(len(t.ports) for t in self.targets.values())
        total_creds = sum(len(t.credentials) for t in self.targets.values())
        valid_creds = sum(
            1 for t in self.targets.values()
            for c in t.credentials.values()
            if c.status == CredentialStatus.VALID
        )
        total_vulns = sum(len(t.vulnerabilities) for t in self.targets.values())
        exploited_vulns = sum(
            1 for t in self.targets.values()
            for v in t.vulnerabilities.values()
            if v.status == VulnerabilityStatus.EXPLOITED
        )
        total_attacks = sum(len(t.attack_history) for t in self.targets.values())
        successful_attacks = sum(
            1 for t in self.targets.values()
            for a in t.attack_history
            if a.success
        )
        total_loot = sum(len(t.loot) for t in self.targets.values())

        summary = {
            "targets": {"total": total_targets, "user_owned": user_owned, "root_owned": root_owned},
            "ports": total_ports,
            "credentials": {"total": total_creds, "valid": valid_creds},
            "vulnerabilities": {"total": total_vulns, "exploited": exploited_vulns},
            "attacks": {"total": total_attacks, "successful": successful_attacks},
            "loot": total_loot,
        }

        report = f"""
Engagement Summary
==================
Targets: {total_targets} ({user_owned} user, {root_owned} root owned)
Ports discovered: {total_ports}
Credentials: {total_creds} ({valid_creds} valid)
Vulnerabilities: {total_vulns} ({exploited_vulns} exploited)
Attacks: {total_attacks} ({successful_attacks} successful)
Loot items: {total_loot}
"""

        return ToolResult(
            success=True,
            data=summary,
            raw_output=report.strip(),
        )

    async def suggest_next_steps(
        self,
        ip: Optional[str] = None,
    ) -> ToolResult:
        """Suggest next steps based on current state."""
        suggestions = []

        targets_to_check = [self.targets[ip]] if ip and ip in self.targets else self.targets.values()

        for target in targets_to_check:
            target_ip = target.ip

            # Check for untested credentials
            untested_creds = [c for c in target.credentials.values() if c.status == CredentialStatus.DISCOVERED]
            if untested_creds:
                suggestions.append({
                    "target": target_ip,
                    "priority": "high",
                    "action": "test_credentials",
                    "detail": f"Test {len(untested_creds)} discovered credentials",
                })

            # Check for unexploited vulnerabilities
            unexploited = [v for v in target.vulnerabilities.values()
                          if v.status == VulnerabilityStatus.CONFIRMED and v.exploit_available]
            if unexploited:
                suggestions.append({
                    "target": target_ip,
                    "priority": "high",
                    "action": "exploit_vulnerability",
                    "detail": f"Exploit {len(unexploited)} confirmed vulnerabilities with available exploits",
                    "vulns": [v.name for v in unexploited],
                })

            # Check for active sessions without escalation
            user_sessions = [s for s in target.sessions.values() if s.privilege_level == "user"]
            if user_sessions and not target.root_owned:
                suggestions.append({
                    "target": target_ip,
                    "priority": "medium",
                    "action": "privilege_escalation",
                    "detail": "Attempt privilege escalation on existing user sessions",
                })

            # If not owned at all, suggest initial access
            if not target.user_owned and target.ports:
                valid_creds = [c for c in target.credentials.values() if c.status == CredentialStatus.VALID]
                if valid_creds:
                    suggestions.append({
                        "target": target_ip,
                        "priority": "high",
                        "action": "initial_access",
                        "detail": f"Use {len(valid_creds)} valid credentials for initial access",
                    })
                else:
                    suggestions.append({
                        "target": target_ip,
                        "priority": "medium",
                        "action": "enumerate",
                        "detail": f"Enumerate {len(target.ports)} open ports for vulnerabilities",
                    })

        if not suggestions:
            suggestions.append({
                "priority": "low",
                "action": "complete",
                "detail": "No immediate actions identified. Consider deeper enumeration or new targets.",
            })

        # Sort by priority
        priority_order = {"high": 0, "medium": 1, "low": 2}
        suggestions.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 2))

        return ToolResult(
            success=True,
            data={"suggestions": suggestions, "total": len(suggestions)},
            raw_output=json.dumps(suggestions, indent=2),
        )


if __name__ == "__main__":
    TargetTrackerServer.main()
