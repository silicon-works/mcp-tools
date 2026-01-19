#!/usr/bin/env python3
"""
OpenSploit MCP Server: strongswan

IPsec VPN client for establishing VPN connections using strongSwan.
Supports IKEv1/IKEv2 with PSK, EAP, or certificate authentication.
"""

import asyncio
import os
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class StrongSwanServer(BaseMCPServer):
    """MCP server wrapping strongSwan for IPsec VPN connections."""

    def __init__(self):
        super().__init__(
            name="strongswan",
            description="IPsec VPN client for establishing VPN connections with PSK, EAP, or certificates",
            version="1.0.0",
        )

        # Track active connections
        self.connections: Dict[str, Dict[str, Any]] = {}

        # Register methods
        self.register_method(
            name="connect",
            description="Establish an IPsec VPN connection",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "VPN gateway IP address or hostname",
                },
                "psk": {
                    "type": "string",
                    "description": "Pre-shared key for authentication",
                },
                "group_name": {
                    "type": "string",
                    "description": "IKE ID / group name (used with PSK)",
                },
                "username": {
                    "type": "string",
                    "description": "Username for EAP authentication",
                },
                "password": {
                    "type": "string",
                    "description": "Password for EAP authentication",
                },
                "cert": {
                    "type": "string",
                    "description": "Path to certificate file (e.g., /session/certs/client.crt)",
                },
                "key": {
                    "type": "string",
                    "description": "Path to private key file (e.g., /session/certs/client.key)",
                },
                "ike_version": {
                    "type": "integer",
                    "default": 1,
                    "description": "IKE version (1 or 2)",
                },
                "mode": {
                    "type": "string",
                    "default": "aggressive",
                    "description": "IKEv1 mode: 'aggressive' or 'main'",
                },
                "transforms": {
                    "type": "string",
                    "description": "Custom IKE/ESP transforms (e.g., 'aes256-sha1-modp1024')",
                },
                "connection_name": {
                    "type": "string",
                    "description": "Custom connection name (auto-generated if not provided)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Connection timeout in seconds (default: 120)",
                },
            },
            handler=self.connect,
        )

        self.register_method(
            name="disconnect",
            description="Disconnect a VPN connection",
            params={
                "connection": {
                    "type": "string",
                    "default": "all",
                    "description": "Connection name to disconnect, or 'all' for all connections",
                },
            },
            handler=self.disconnect,
        )

        self.register_method(
            name="status",
            description="Get status of active VPN connections",
            params={},
            handler=self.status,
        )

    def _generate_connection_name(self, target: str) -> str:
        """Generate a unique connection name."""
        import hashlib
        import time
        hash_input = f"{target}-{time.time()}"
        short_hash = hashlib.md5(hash_input.encode()).hexdigest()[:8]
        return f"vpn-{short_hash}"

    def _detect_auth_method(
        self,
        psk: Optional[str],
        username: Optional[str],
        password: Optional[str],
        cert: Optional[str],
        key: Optional[str],
    ) -> str:
        """Detect authentication method based on provided parameters."""
        if cert and key:
            return "cert"
        elif username and password:
            return "eap"
        elif psk:
            return "psk"
        else:
            raise ToolError("No authentication credentials provided. Need psk, username/password, or cert/key.")

    def _generate_ipsec_conf(
        self,
        connection_name: str,
        target: str,
        auth_method: str,
        ike_version: int,
        mode: str,
        group_name: Optional[str],
        username: Optional[str],
        transforms: Optional[str],
        cert: Optional[str],
        key: Optional[str],
    ) -> str:
        """Generate ipsec.conf content."""

        # Determine IKE and ESP proposals
        # NOTE: ESP proposals use '!' suffix to disable PFS - many legacy VPNs don't support PFS
        # IMPORTANT: strongSwan 6.x has issues parsing comma-separated ESP proposals,
        # so we use a single ESP proposal matching the IKE transform
        if transforms:
            ike_proposal = transforms
            # Extract encryption and hash algorithms from transform (e.g., "3des-sha1-modp1024")
            parts = transforms.split('-')
            enc_alg = parts[0]
            hash_alg = parts[1] if len(parts) > 1 else "sha1"
            # Single ESP proposal matching IKE, with ! to disable PFS
            esp_proposal = f"{enc_alg}-{hash_alg}!"
        else:
            # Default proposals that work with most VPNs
            if ike_version == 1:
                ike_proposal = "3des-sha1-modp1024"
                # Single ESP proposal with ! to disable PFS for legacy IKEv1
                esp_proposal = "3des-sha1!"
            else:
                ike_proposal = "aes256-sha256-modp2048"
                esp_proposal = "aes256-sha256"

        # Build left (local) identity
        if group_name:
            leftid = f'leftid="{group_name}"'
        elif username:
            leftid = f'leftid="{username}"'
        else:
            leftid = "leftid=%any"

        # Build authentication settings
        if auth_method == "psk":
            leftauth = "leftauth=psk"
            rightauth = "rightauth=psk"
            eap_identity = ""
        elif auth_method == "eap":
            leftauth = "leftauth=eap-mschapv2"
            rightauth = "rightauth=pubkey"
            eap_identity = f'eap_identity="{username}"' if username else ""
        else:  # cert
            leftauth = "leftauth=pubkey"
            rightauth = "rightauth=pubkey"
            eap_identity = ""

        # IKEv1 aggressive mode settings
        aggressive = ""
        if ike_version == 1 and mode == "aggressive":
            aggressive = "aggressive=yes"

        # For IKEv1 aggressive mode, accept any server ID
        rightid = "rightid=%any" if (ike_version == 1 and mode == "aggressive") else ""

        # NOTE: config setup should only appear in main ipsec.conf, not in included files
        # Each included file should only contain conn blocks
        # IMPORTANT: strongSwan requires TAB indentation, not spaces!
        t = "\t"  # Tab character for proper ipsec.conf formatting

        # Build config lines, only including non-empty values
        lines = [
            f"# Generated by OpenSploit strongSwan MCP server",
            f"",
            f"conn {connection_name}",
            f"{t}type=tunnel",
            f"{t}keyexchange=ikev{ike_version}",
        ]

        # Add optional aggressive mode
        if aggressive:
            lines.append(f"{t}{aggressive}")

        # Core settings
        lines.extend([
            f"{t}left=%defaultroute",
            f"{t}leftsubnet=0.0.0.0/0",
            f"{t}{leftid}",
            f"{t}{leftauth}",
            f"{t}right={target}",
            f"{t}rightsubnet=0.0.0.0/0",
        ])

        # Add optional rightid
        if rightid:
            lines.append(f"{t}{rightid}")

        # More settings
        lines.extend([
            f"{t}rightauth={rightauth.split('=')[1]}",
            f"{t}ike={ike_proposal}",
            f"{t}esp={esp_proposal}",
            f"{t}auto=add",
        ])

        # Add optional EAP identity
        if eap_identity:
            lines.append(f"{t}{eap_identity}")

        # Add certificate paths if using cert auth
        if auth_method == "cert":
            lines.append(f"{t}leftcert={cert}")

        return "\n".join(lines) + "\n"

    def _generate_ipsec_secrets(
        self,
        target: str,
        auth_method: str,
        psk: Optional[str],
        group_name: Optional[str],
        username: Optional[str],
        password: Optional[str],
        key: Optional[str],
    ) -> str:
        """Generate ipsec.secrets content."""

        if auth_method == "psk":
            # PSK format: <local_id> <remote_id> : PSK "<secret>"
            local_id = f'"{group_name}"' if group_name else "%any"
            return f'{local_id} {target} : PSK "{psk}"\n'

        elif auth_method == "eap":
            # EAP format: <username> : EAP "<password>"
            return f'{username} : EAP "{password}"\n'

        elif auth_method == "cert":
            # RSA key format: : RSA <keyfile>
            return f': RSA "{key}"\n'

        return ""

    async def _ensure_ipsec_running(self):
        """Ensure ipsec daemon is running."""
        # Check if ipsec is running
        result = await self.run_command(["ipsec", "status"], timeout=5)
        if result.returncode != 0:
            # Start ipsec
            self.logger.info("Starting ipsec daemon")
            await self.run_command(["ipsec", "start"], timeout=10)
            await asyncio.sleep(2)  # Wait for daemon to start

    async def connect(
        self,
        target: str,
        psk: Optional[str] = None,
        group_name: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        cert: Optional[str] = None,
        key: Optional[str] = None,
        ike_version: int = 1,
        mode: str = "aggressive",
        transforms: Optional[str] = None,
        connection_name: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Establish an IPsec VPN connection."""

        self.logger.info(f"Connecting to VPN gateway {target}")

        try:
            # Detect auth method
            auth_method = self._detect_auth_method(psk, username, password, cert, key)
            self.logger.info(f"Using authentication method: {auth_method}")

            # Generate connection name if not provided
            if not connection_name:
                connection_name = self._generate_connection_name(target)

            # Generate config files
            ipsec_conf = self._generate_ipsec_conf(
                connection_name, target, auth_method, ike_version, mode,
                group_name, username, transforms, cert, key
            )
            ipsec_secrets = self._generate_ipsec_secrets(
                target, auth_method, psk, group_name, username, password, key
            )

            # Write config directly to main ipsec.conf (includes don't reload properly)
            main_conf = "/etc/ipsec.conf"

            with open(main_conf, 'r') as f:
                main_content = f.read()

            # Check if this connection already exists
            conn_marker = f"conn {connection_name}"
            if conn_marker not in main_content:
                with open(main_conf, 'a') as f:
                    f.write(f"\n{ipsec_conf}\n")
                self.logger.info(f"Added connection {connection_name} to ipsec.conf")

            # Write secrets directly to main ipsec.secrets
            main_secrets = "/etc/ipsec.secrets"

            try:
                with open(main_secrets, 'r') as f:
                    secrets_content = f.read()
            except FileNotFoundError:
                secrets_content = ""

            # Check if this secret already exists (by checking for the target)
            if ipsec_secrets.strip() not in secrets_content:
                with open(main_secrets, 'a') as f:
                    f.write(f"\n{ipsec_secrets}")
                os.chmod(main_secrets, 0o600)
                self.logger.info(f"Added secrets for {connection_name}")

            # Restart ipsec to ensure new config is loaded
            # (ipsec update/reload don't properly load new connections)
            self.logger.info("Restarting ipsec to load new configuration")
            await self.run_command(["ipsec", "restart"], timeout=15)
            await asyncio.sleep(3)  # Wait for daemon to fully start

            # Bring up the connection
            self.logger.info(f"Bringing up connection {connection_name} (timeout: {timeout}s)")
            result = await self.run_command(
                ["ipsec", "up", connection_name],
                timeout=timeout
            )

            output = result.stdout + result.stderr

            # Check if connection succeeded - look for specific success indicators
            # and ensure no failure indicators are present
            output_lower = output.lower()
            has_established = "established successfully" in output_lower or "connection established" in output_lower
            has_sa_established = "ike_sa" in output_lower and "established" in output_lower
            has_child_sa = "child_sa" in output_lower and "established" in output_lower
            has_failure = "failed" in output_lower or "no_proposal_chosen" in output_lower or "timeout" in output_lower

            success = (has_established or has_sa_established or has_child_sa) and not has_failure

            if success:
                # Get assigned IP if any
                status_result = await self.run_command(["ipsec", "statusall"], timeout=10)
                status_output = status_result.stdout

                # Parse for virtual IP
                virtual_ip = None
                for line in status_output.split('\n'):
                    if 'virtual-ip' in line.lower() or 'vip' in line.lower():
                        # Try to extract IP
                        import re
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            virtual_ip = ip_match.group(1)
                            break

                # Store connection info
                self.connections[connection_name] = {
                    "target": target,
                    "auth_method": auth_method,
                    "ike_version": ike_version,
                    "virtual_ip": virtual_ip,
                }

                return ToolResult(
                    success=True,
                    data={
                        "connection_name": connection_name,
                        "target": target,
                        "auth_method": auth_method,
                        "ike_version": ike_version,
                        "mode": mode if ike_version == 1 else "n/a",
                        "virtual_ip": virtual_ip,
                        "status": "connected",
                    },
                    raw_output=sanitize_output(output),
                )
            else:
                return ToolResult(
                    success=False,
                    data={
                        "connection_name": connection_name,
                        "target": target,
                        "status": "failed",
                    },
                    error=f"Failed to establish VPN connection",
                    raw_output=sanitize_output(output),
                )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"target": target},
                error=str(e),
            )
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            return ToolResult(
                success=False,
                data={"target": target},
                error=str(e),
            )

    async def disconnect(
        self,
        connection: str = "all",
    ) -> ToolResult:
        """Disconnect a VPN connection."""

        self.logger.info(f"Disconnecting: {connection}")

        try:
            if connection == "all":
                # Disconnect all known connections
                disconnected = []
                for conn_name in list(self.connections.keys()):
                    result = await self.run_command(
                        ["ipsec", "down", conn_name],
                        timeout=10
                    )
                    disconnected.append(conn_name)
                    del self.connections[conn_name]

                return ToolResult(
                    success=True,
                    data={
                        "disconnected": disconnected,
                        "count": len(disconnected),
                    },
                    raw_output=f"Disconnected {len(disconnected)} connection(s)",
                )
            else:
                # Disconnect specific connection
                result = await self.run_command(
                    ["ipsec", "down", connection],
                    timeout=10
                )

                if connection in self.connections:
                    del self.connections[connection]

                return ToolResult(
                    success=True,
                    data={
                        "disconnected": connection,
                    },
                    raw_output=sanitize_output(result.stdout + result.stderr),
                )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def status(self) -> ToolResult:
        """Get status of active VPN connections."""

        self.logger.info("Getting VPN status")

        try:
            # Get ipsec status
            result = await self.run_command(["ipsec", "statusall"], timeout=10)
            output = result.stdout + result.stderr

            # Parse active connections
            active_connections = []

            # Also check our tracked connections
            for conn_name, info in self.connections.items():
                active_connections.append({
                    "name": conn_name,
                    "target": info.get("target"),
                    "auth_method": info.get("auth_method"),
                    "virtual_ip": info.get("virtual_ip"),
                })

            # Get routing info
            route_result = await self.run_command(["ip", "route"], timeout=5)
            routes = route_result.stdout

            return ToolResult(
                success=True,
                data={
                    "connections": active_connections,
                    "count": len(active_connections),
                    "routes": routes,
                },
                raw_output=sanitize_output(output),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    StrongSwanServer.main()
