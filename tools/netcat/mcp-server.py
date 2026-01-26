#!/usr/bin/env python3
"""
OpenSploit MCP Server: netcat

Network utility for reverse shells, HTTP callback capture, and port testing.
Provides TCP listeners, HTTP servers for CSRF/XSS capture, and UDP support.

Key features:
- TCP listeners with non-blocking mode for reverse shells
- HTTP server for serving files and capturing requests (cookies, callbacks)
- UDP listener for packet capture
- TLS/HTTPS support with auto-generated or custom certificates
- Session directory integration for large captures
"""

import asyncio
import base64
import json
import os
import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mcp_common import BaseMCPServer, ToolResult


# Session directory for persistent storage
SESSION_DIR = Path("/session/netcat")

# Thresholds for persisting to session files
REQUEST_COUNT_THRESHOLD = 50
DATA_SIZE_THRESHOLD = 100 * 1024  # 100KB


def generate_id(prefix: str) -> str:
    """Generate unique ID with prefix."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def get_timestamp() -> str:
    """Get ISO format timestamp."""
    return datetime.utcnow().isoformat() + "Z"


def ensure_session_dir() -> Path:
    """Ensure session directory exists."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    return SESSION_DIR


@dataclass
class TCPListener:
    """TCP listener state."""
    id: str
    port: int
    server: Optional[asyncio.Server] = None
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    remote_addr: Optional[Tuple[str, int]] = None
    response_template: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    connected_at: Optional[float] = None
    buffer: str = ""
    status: str = "listening"  # listening, connected, closed

    def is_connected(self) -> bool:
        """Check if client is connected."""
        if self.writer is None:
            return False
        return not self.writer.is_closing()


@dataclass
class HTTPRequest:
    """Captured HTTP request."""
    timestamp: str
    method: str
    path: str
    query: Dict[str, str]
    headers: Dict[str, str]
    body: str
    source_ip: str
    source_port: int


@dataclass
class HTTPServer:
    """HTTP server state."""
    id: str
    port: int
    runner: Optional[web.AppRunner] = None
    site: Optional[web.TCPSite] = None
    files: Dict[str, Tuple[str, str]] = field(default_factory=dict)  # path -> (content, content_type)
    requests: List[HTTPRequest] = field(default_factory=list)
    tls: bool = False
    ssl_context: Optional[ssl.SSLContext] = None
    created_at: float = field(default_factory=time.time)
    keepalive_minutes: int = 5
    last_access: float = field(default_factory=time.time)
    persisted_file: Optional[str] = None

    def touch(self):
        """Update last access time."""
        self.last_access = time.time()


@dataclass
class UDPPacket:
    """Captured UDP packet."""
    timestamp: str
    source_ip: str
    source_port: int
    data: str
    data_hex: str


@dataclass
class UDPListener:
    """UDP listener state."""
    id: str
    port: int
    transport: Optional[asyncio.DatagramTransport] = None
    protocol: Optional["UDPProtocol"] = None
    packets: List[UDPPacket] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    persisted_file: Optional[str] = None


class UDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol for packet capture."""

    def __init__(self, listener: UDPListener):
        self.listener = listener

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle received UDP packet."""
        packet = UDPPacket(
            timestamp=get_timestamp(),
            source_ip=addr[0],
            source_port=addr[1],
            data=data.decode("utf-8", errors="replace"),
            data_hex=data.hex(),
        )
        self.listener.packets.append(packet)


class NetcatServer(BaseMCPServer):
    """
    MCP server for network utilities.

    Provides TCP listeners, HTTP servers, and UDP support for penetration testing.
    """

    def __init__(self):
        super().__init__(
            name="netcat",
            description="Network utility for reverse shells, HTTP capture, and port testing",
            version="2.0.0",
        )

        # State storage
        self.tcp_listeners: Dict[str, TCPListener] = {}
        self.http_servers: Dict[str, HTTPServer] = {}
        self.udp_listeners: Dict[str, UDPListener] = {}

        # Register TCP methods
        self.register_method(
            name="listen",
            description="Start TCP listener for reverse shell or connection capture",
            params={
                "port": {"type": "integer", "required": True, "description": "Port to listen on (>1024 for non-privileged)"},
                "timeout": {"type": "integer", "default": 300, "description": "Wait timeout in seconds (0=non-blocking, returns immediately)"},
                "response": {"type": "string", "description": "Data to send upon connection (e.g., fake HTTP response)"},
            },
            handler=self.listen,
        )

        self.register_method(
            name="listener_status",
            description="Check status of a TCP listener",
            params={
                "listener_id": {"type": "string", "required": True, "description": "Listener ID from listen()"},
            },
            handler=self.listener_status,
        )

        self.register_method(
            name="listener_read",
            description="Read data from connected TCP client",
            params={
                "listener_id": {"type": "string", "required": True, "description": "Listener ID"},
                "timeout": {"type": "integer", "default": 30, "description": "Read timeout in seconds"},
            },
            handler=self.listener_read,
        )

        self.register_method(
            name="listener_write",
            description="Write data to connected TCP client",
            params={
                "listener_id": {"type": "string", "required": True, "description": "Listener ID"},
                "data": {"type": "string", "required": True, "description": "Data to send"},
            },
            handler=self.listener_write,
        )

        self.register_method(
            name="exec",
            description="One-shot TCP capture: listen, wait for connection, capture output",
            params={
                "port": {"type": "integer", "required": True, "description": "Port to listen on"},
                "timeout": {"type": "integer", "default": 60, "description": "Total timeout in seconds"},
            },
            handler=self.exec_capture,
        )

        # Register HTTP methods
        self.register_method(
            name="http_listen",
            description="Start HTTP server for serving files and capturing requests (cookies, XSS callbacks)",
            params={
                "port": {"type": "integer", "required": True, "description": "Port to listen on"},
                "files": {"type": "object", "description": "Files to serve: {'/path': 'content', ...}"},
                "tls": {"type": "boolean", "default": False, "description": "Enable HTTPS with auto-generated cert"},
                "cert": {"type": "string", "description": "PEM certificate (base64 or raw)"},
                "key": {"type": "string", "description": "PEM private key (base64 or raw)"},
                "timeout": {"type": "integer", "default": 0, "description": "Server timeout (0=indefinite until stop)"},
                "keepalive": {"type": "integer", "default": 5, "description": "Keepalive minutes (1-30, resets on MCP calls)"},
            },
            handler=self.http_listen,
        )

        self.register_method(
            name="http_requests",
            description="Get captured HTTP requests from server",
            params={
                "server_id": {"type": "string", "required": True, "description": "Server ID from http_listen()"},
                "since": {"type": "string", "description": "Only requests after this ISO timestamp"},
                "clear": {"type": "boolean", "default": False, "description": "Clear requests after reading"},
            },
            handler=self.http_requests,
        )

        self.register_method(
            name="http_file",
            description="Add, update, or remove a file on HTTP server",
            params={
                "server_id": {"type": "string", "required": True, "description": "Server ID"},
                "path": {"type": "string", "required": True, "description": "URL path (e.g., '/exploit.html')"},
                "content": {"type": "string", "description": "File content (omit to delete)"},
                "content_type": {"type": "string", "description": "MIME type (auto-detected if omitted)"},
            },
            handler=self.http_file,
        )

        # Register UDP methods
        self.register_method(
            name="udp_listen",
            description="Start UDP listener for packet capture",
            params={
                "port": {"type": "integer", "required": True, "description": "Port to listen on"},
                "timeout": {"type": "integer", "default": 0, "description": "Listener timeout (0=indefinite)"},
            },
            handler=self.udp_listen,
        )

        self.register_method(
            name="udp_packets",
            description="Get captured UDP packets",
            params={
                "listener_id": {"type": "string", "required": True, "description": "Listener ID from udp_listen()"},
                "clear": {"type": "boolean", "default": False, "description": "Clear packets after reading"},
            },
            handler=self.udp_packets,
        )

        self.register_method(
            name="udp_send",
            description="Send UDP packet to remote host",
            params={
                "host": {"type": "string", "required": True, "description": "Target host"},
                "port": {"type": "integer", "required": True, "description": "Target port"},
                "data": {"type": "string", "required": True, "description": "Data to send"},
            },
            handler=self.udp_send,
        )

        # Register shared methods
        self.register_method(
            name="connect",
            description="Connect to remote TCP host",
            params={
                "host": {"type": "string", "required": True, "description": "Target host"},
                "port": {"type": "integer", "required": True, "description": "Target port"},
                "data": {"type": "string", "description": "Data to send after connecting"},
                "timeout": {"type": "integer", "default": 30, "description": "Connection timeout"},
            },
            handler=self.connect,
        )

        self.register_method(
            name="check_port",
            description="Check if TCP port is open",
            params={
                "host": {"type": "string", "required": True, "description": "Target host"},
                "port": {"type": "integer", "required": True, "description": "Target port"},
                "timeout": {"type": "integer", "default": 5, "description": "Connection timeout"},
            },
            handler=self.check_port,
        )

        self.register_method(
            name="get_interfaces",
            description="Get network interfaces and IP addresses (for LHOST)",
            params={},
            handler=self.get_interfaces,
        )

        self.register_method(
            name="list",
            description="List all active listeners and servers",
            params={},
            handler=self.list_all,
        )

        self.register_method(
            name="stop",
            description="Stop a listener or server by ID",
            params={
                "id": {"type": "string", "required": True, "description": "Listener/server ID to stop"},
            },
            handler=self.stop,
        )

    # =========================================================================
    # TCP Listener Methods
    # =========================================================================

    async def listen(
        self,
        port: int,
        timeout: int = 300,
        response: Optional[str] = None,
    ) -> ToolResult:
        """Start TCP listener."""
        # Validate port range
        if not isinstance(port, int) or port < 1 or port > 65535:
            return ToolResult(
                success=False,
                data={"port": port},
                error=f"Invalid port: must be 1-65535, got {port}",
            )

        self.logger.info(f"Starting TCP listener on port {port}")

        listener_id = generate_id("tcp")

        try:
            # Create listener state
            listener = TCPListener(
                id=listener_id,
                port=port,
                response_template=response,
            )

            # Connection handler
            async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                addr = writer.get_extra_info("peername")
                self.logger.info(f"Connection from {addr}")

                listener.reader = reader
                listener.writer = writer
                listener.remote_addr = addr
                listener.connected_at = time.time()
                listener.status = "connected"

                # Send response template if configured
                if listener.response_template:
                    writer.write(listener.response_template.encode())
                    await writer.drain()

            # Start server
            server = await asyncio.start_server(
                handle_connection,
                "0.0.0.0",
                port,
                reuse_address=True,
            )
            listener.server = server

            self.tcp_listeners[listener_id] = listener

            # Non-blocking mode: return immediately
            if timeout == 0:
                return ToolResult(
                    success=True,
                    data={
                        "listener_id": listener_id,
                        "port": port,
                        "status": "listening",
                        "mode": "non-blocking",
                    },
                    raw_output=f"Listener started on port {port} (non-blocking mode)\nUse listener_status() to check for connections",
                )

            # Blocking mode: wait for connection
            try:
                start = time.time()
                while time.time() - start < timeout:
                    if listener.status == "connected":
                        # Read initial data
                        initial_data = ""
                        try:
                            data = await asyncio.wait_for(
                                listener.reader.read(4096),
                                timeout=2.0,
                            )
                            initial_data = data.decode("utf-8", errors="replace")
                            listener.buffer = initial_data
                        except asyncio.TimeoutError:
                            pass

                        return ToolResult(
                            success=True,
                            data={
                                "listener_id": listener_id,
                                "port": port,
                                "status": "connected",
                                "remote_ip": listener.remote_addr[0],
                                "remote_port": listener.remote_addr[1],
                                "initial_data": initial_data,
                            },
                            raw_output=f"Connection from {listener.remote_addr[0]}:{listener.remote_addr[1]}\n{initial_data}",
                        )
                    await asyncio.sleep(0.1)

                # Timeout reached
                return ToolResult(
                    success=False,
                    data={"listener_id": listener_id, "port": port},
                    error=f"No connection received within {timeout} seconds",
                )

            except Exception as e:
                return ToolResult(
                    success=False,
                    data={"listener_id": listener_id, "port": port},
                    error=str(e),
                )

        except OSError as e:
            if "Address already in use" in str(e):
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"Port {port} is already in use",
                )
            return ToolResult(
                success=False,
                data={"port": port},
                error=str(e),
            )

    async def listener_status(self, listener_id: str) -> ToolResult:
        """Check TCP listener status."""
        listener = self.tcp_listeners.get(listener_id)

        if not listener:
            return ToolResult(
                success=False,
                data={"listener_id": listener_id},
                error=f"Listener not found: {listener_id}",
            )

        data = {
            "listener_id": listener_id,
            "port": listener.port,
            "status": listener.status,
            "created_at": datetime.fromtimestamp(listener.created_at).isoformat(),
        }

        if listener.status == "connected" and listener.remote_addr:
            data["remote_ip"] = listener.remote_addr[0]
            data["remote_port"] = listener.remote_addr[1]
            data["connected_at"] = datetime.fromtimestamp(listener.connected_at).isoformat()
            data["connected"] = listener.is_connected()

            if listener.buffer:
                data["buffered_data"] = listener.buffer

        return ToolResult(
            success=True,
            data=data,
            raw_output=f"Listener {listener_id}: {listener.status}",
        )

    async def listener_read(
        self,
        listener_id: str,
        timeout: int = 30,
    ) -> ToolResult:
        """Read from connected TCP client."""
        listener = self.tcp_listeners.get(listener_id)

        if not listener:
            return ToolResult(
                success=False,
                data={"listener_id": listener_id},
                error=f"Listener not found: {listener_id}",
            )

        if listener.status != "connected" or not listener.reader:
            return ToolResult(
                success=False,
                data={"listener_id": listener_id, "status": listener.status},
                error="No active connection",
            )

        try:
            data = await asyncio.wait_for(
                listener.reader.read(65536),
                timeout=timeout,
            )

            if not data:
                listener.status = "closed"
                return ToolResult(
                    success=False,
                    data={"listener_id": listener_id},
                    error="Connection closed by remote",
                )

            text = data.decode("utf-8", errors="replace")
            listener.buffer += text

            return ToolResult(
                success=True,
                data={
                    "listener_id": listener_id,
                    "data": text,
                    "bytes": len(data),
                },
                raw_output=text,
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={"listener_id": listener_id},
                error=f"Read timeout after {timeout} seconds",
            )

    async def listener_write(
        self,
        listener_id: str,
        data: str,
    ) -> ToolResult:
        """Write to connected TCP client."""
        listener = self.tcp_listeners.get(listener_id)

        if not listener:
            return ToolResult(
                success=False,
                data={"listener_id": listener_id},
                error=f"Listener not found: {listener_id}",
            )

        if listener.status != "connected" or not listener.writer:
            return ToolResult(
                success=False,
                data={"listener_id": listener_id, "status": listener.status},
                error="No active connection",
            )

        try:
            encoded = data.encode()
            listener.writer.write(encoded)
            await listener.writer.drain()

            return ToolResult(
                success=True,
                data={
                    "listener_id": listener_id,
                    "bytes_sent": len(encoded),
                },
                raw_output=f"Sent {len(encoded)} bytes",
            )

        except Exception as e:
            listener.status = "closed"
            return ToolResult(
                success=False,
                data={"listener_id": listener_id},
                error=f"Write failed: {e}",
            )

    async def exec_capture(
        self,
        port: int,
        timeout: int = 60,
    ) -> ToolResult:
        """One-shot TCP capture."""
        self.logger.info(f"Starting one-shot capture on port {port}")

        try:
            # Create socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("0.0.0.0", port))
            server_socket.listen(1)
            server_socket.settimeout(timeout)

            self.logger.info(f"Listening on port {port}, waiting for connection...")

            try:
                client_socket, client_addr = server_socket.accept()
                self.logger.info(f"Connection from {client_addr}")

                # Capture all output
                client_socket.settimeout(5.0)
                output = b""
                try:
                    while True:
                        chunk = client_socket.recv(4096)
                        if not chunk:
                            break
                        output += chunk
                except socket.timeout:
                    pass

                client_socket.close()
                server_socket.close()

                text = output.decode("utf-8", errors="replace")

                return ToolResult(
                    success=True,
                    data={
                        "port": port,
                        "remote_ip": client_addr[0],
                        "remote_port": client_addr[1],
                        "output": text,
                        "bytes": len(output),
                    },
                    raw_output=f"Captured from {client_addr[0]}:{client_addr[1]}:\n{text}",
                )

            except socket.timeout:
                server_socket.close()
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"No connection within {timeout} seconds",
                )

        except OSError as e:
            if "Address already in use" in str(e):
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"Port {port} is already in use",
                )
            return ToolResult(
                success=False,
                data={"port": port},
                error=str(e),
            )

    # =========================================================================
    # HTTP Server Methods
    # =========================================================================

    def _generate_self_signed_cert(self) -> Tuple[bytes, bytes]:
        """Generate self-signed certificate."""
        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenSploit"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime(2099, 12, 31))
            .sign(key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem

    def _detect_content_type(self, path: str) -> str:
        """Detect MIME type from path."""
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        types = {
            "html": "text/html",
            "htm": "text/html",
            "js": "application/javascript",
            "css": "text/css",
            "json": "application/json",
            "xml": "application/xml",
            "txt": "text/plain",
            "png": "image/png",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "gif": "image/gif",
            "svg": "image/svg+xml",
            "ico": "image/x-icon",
        }
        return types.get(ext, "text/plain")

    async def http_listen(
        self,
        port: int,
        files: Optional[Dict[str, str]] = None,
        tls: bool = False,
        cert: Optional[str] = None,
        key: Optional[str] = None,
        timeout: int = 0,
        keepalive: int = 5,
    ) -> ToolResult:
        """Start HTTP server."""
        # Validate port range
        if not isinstance(port, int) or port < 1 or port > 65535:
            return ToolResult(
                success=False,
                data={"port": port},
                error=f"Invalid port: must be 1-65535, got {port}",
            )

        self.logger.info(f"Starting HTTP server on port {port} (TLS: {tls})")

        server_id = generate_id("http")
        keepalive = max(1, min(30, keepalive))  # Clamp to 1-30

        try:
            # Create server state
            server = HTTPServer(
                id=server_id,
                port=port,
                tls=tls,
                keepalive_minutes=keepalive,
            )

            # Process initial files
            if files:
                for path, content in files.items():
                    if not path.startswith("/"):
                        path = "/" + path
                    content_type = self._detect_content_type(path)
                    server.files[path] = (content, content_type)

            # Setup TLS if requested
            if tls:
                if cert and key:
                    # Use provided cert
                    try:
                        cert_data = base64.b64decode(cert) if not cert.startswith("-----") else cert.encode()
                        key_data = base64.b64decode(key) if not key.startswith("-----") else key.encode()
                    except Exception:
                        cert_data = cert.encode()
                        key_data = key.encode()
                else:
                    # Generate self-signed
                    cert_data, key_data = self._generate_self_signed_cert()

                # Write temp files for ssl context
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
                    cf.write(cert_data)
                    cert_file = cf.name
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
                    kf.write(key_data)
                    key_file = kf.name

                server.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server.ssl_context.load_cert_chain(cert_file, key_file)

                os.unlink(cert_file)
                os.unlink(key_file)

            # Create aiohttp app
            app = web.Application()

            async def handle_request(request: web.Request) -> web.Response:
                """Handle incoming HTTP request."""
                # Capture request details
                query = dict(request.query)
                headers = dict(request.headers)
                body = ""
                try:
                    body = await request.text()
                except Exception:
                    pass

                peername = request.transport.get_extra_info("peername")
                source_ip = peername[0] if peername else "unknown"
                source_port = peername[1] if peername else 0

                captured = HTTPRequest(
                    timestamp=get_timestamp(),
                    method=request.method,
                    path=request.path,
                    query=query,
                    headers=headers,
                    body=body,
                    source_ip=source_ip,
                    source_port=source_port,
                )
                server.requests.append(captured)
                self.logger.info(f"HTTP {request.method} {request.path} from {source_ip}")

                # Check for persistence threshold
                self._check_persistence(server)

                # Serve file if exists
                if request.path in server.files:
                    content, content_type = server.files[request.path]
                    return web.Response(text=content, content_type=content_type)

                # Check for index
                if request.path == "/" and "/index.html" in server.files:
                    content, content_type = server.files["/index.html"]
                    return web.Response(text=content, content_type=content_type)

                # Default 404 that still captures the request
                return web.Response(text="Not Found", status=404)

            app.router.add_route("*", "/{path:.*}", handle_request)

            # Start server
            runner = web.AppRunner(app)
            await runner.setup()

            site = web.TCPSite(
                runner,
                "0.0.0.0",
                port,
                ssl_context=server.ssl_context,
            )
            await site.start()

            server.runner = runner
            server.site = site

            self.http_servers[server_id] = server

            # Get interface for URL
            interfaces = await self._get_interface_ips()
            host = interfaces[0] if interfaces else "0.0.0.0"
            protocol = "https" if tls else "http"
            url = f"{protocol}://{host}:{port}"

            return ToolResult(
                success=True,
                data={
                    "server_id": server_id,
                    "port": port,
                    "url": url,
                    "tls": tls,
                    "files": list(server.files.keys()),
                    "keepalive_minutes": keepalive,
                },
                raw_output=f"HTTP server started: {url}\nServer ID: {server_id}",
            )

        except OSError as e:
            if "Address already in use" in str(e):
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"Port {port} is already in use",
                )
            return ToolResult(
                success=False,
                data={"port": port},
                error=str(e),
            )

    def _check_persistence(self, server: HTTPServer):
        """Check if requests should be persisted to file."""
        if server.persisted_file:
            # Already persisting, append new requests
            self._persist_requests(server)
            return

        # Check thresholds
        request_count = len(server.requests)
        data_size = sum(
            len(r.body) + len(str(r.headers)) + len(r.path)
            for r in server.requests
        )

        if request_count > REQUEST_COUNT_THRESHOLD or data_size > DATA_SIZE_THRESHOLD:
            self._persist_requests(server)

    def _persist_requests(self, server: HTTPServer):
        """Persist requests to session file."""
        if not server.requests:
            return

        ensure_session_dir()
        filename = f"http-{server.id}.jsonl"
        filepath = SESSION_DIR / filename
        server.persisted_file = str(filepath)

        with open(filepath, "a") as f:
            for req in server.requests:
                f.write(json.dumps({
                    "timestamp": req.timestamp,
                    "method": req.method,
                    "path": req.path,
                    "query": req.query,
                    "headers": req.headers,
                    "body": req.body,
                    "source_ip": req.source_ip,
                    "source_port": req.source_port,
                }) + "\n")

        # Keep only last 10 requests in memory
        server.requests = server.requests[-10:]

    async def http_requests(
        self,
        server_id: str,
        since: Optional[str] = None,
        clear: bool = False,
    ) -> ToolResult:
        """Get captured HTTP requests."""
        server = self.http_servers.get(server_id)

        if not server:
            return ToolResult(
                success=False,
                data={"server_id": server_id},
                error=f"Server not found: {server_id}",
            )

        server.touch()  # Reset keepalive

        # Collect requests
        requests = []

        # Read from persisted file if exists
        if server.persisted_file and os.path.exists(server.persisted_file):
            with open(server.persisted_file) as f:
                for line in f:
                    try:
                        requests.append(json.loads(line.strip()))
                    except Exception:
                        pass

        # Add in-memory requests
        for req in server.requests:
            requests.append({
                "timestamp": req.timestamp,
                "method": req.method,
                "path": req.path,
                "query": req.query,
                "headers": req.headers,
                "body": req.body,
                "source_ip": req.source_ip,
                "source_port": req.source_port,
            })

        # Filter by timestamp if specified
        if since:
            requests = [r for r in requests if r["timestamp"] > since]

        # Clear if requested
        if clear:
            server.requests = []
            if server.persisted_file and os.path.exists(server.persisted_file):
                os.unlink(server.persisted_file)
                server.persisted_file = None

        # Determine if we should return summary vs full
        persisted = server.persisted_file is not None
        return_requests = requests[:50] if len(requests) > 50 else requests

        return ToolResult(
            success=True,
            data={
                "server_id": server_id,
                "requests": return_requests,
                "request_count": len(requests),
                "persisted": persisted,
                "file": server.persisted_file if persisted else None,
            },
            raw_output=f"Captured {len(requests)} requests" + (f" (persisted to {server.persisted_file})" if persisted else ""),
        )

    async def http_file(
        self,
        server_id: str,
        path: str,
        content: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> ToolResult:
        """Add/update/remove file on HTTP server."""
        server = self.http_servers.get(server_id)

        if not server:
            return ToolResult(
                success=False,
                data={"server_id": server_id},
                error=f"Server not found: {server_id}",
            )

        server.touch()

        if not path.startswith("/"):
            path = "/" + path

        if content is None:
            # Delete file
            if path in server.files:
                del server.files[path]
                return ToolResult(
                    success=True,
                    data={"server_id": server_id, "path": path, "action": "deleted"},
                    raw_output=f"Deleted {path}",
                )
            else:
                return ToolResult(
                    success=False,
                    data={"server_id": server_id, "path": path},
                    error=f"File not found: {path}",
                )
        else:
            # Add/update file
            if not content_type:
                content_type = self._detect_content_type(path)

            server.files[path] = (content, content_type)

            return ToolResult(
                success=True,
                data={
                    "server_id": server_id,
                    "path": path,
                    "content_type": content_type,
                    "size": len(content),
                    "action": "updated",
                },
                raw_output=f"Added/updated {path} ({len(content)} bytes, {content_type})",
            )

    # =========================================================================
    # UDP Methods
    # =========================================================================

    async def udp_listen(
        self,
        port: int,
        timeout: int = 0,
    ) -> ToolResult:
        """Start UDP listener."""
        # Validate port range
        if not isinstance(port, int) or port < 1 or port > 65535:
            return ToolResult(
                success=False,
                data={"port": port},
                error=f"Invalid port: must be 1-65535, got {port}",
            )

        self.logger.info(f"Starting UDP listener on port {port}")

        listener_id = generate_id("udp")

        try:
            listener = UDPListener(
                id=listener_id,
                port=port,
            )

            # Create UDP endpoint
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPProtocol(listener),
                local_addr=("0.0.0.0", port),
            )

            listener.transport = transport
            listener.protocol = protocol

            self.udp_listeners[listener_id] = listener

            return ToolResult(
                success=True,
                data={
                    "listener_id": listener_id,
                    "port": port,
                    "status": "listening",
                },
                raw_output=f"UDP listener started on port {port}\nListener ID: {listener_id}",
            )

        except OSError as e:
            if "Address already in use" in str(e):
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"Port {port} is already in use",
                )
            return ToolResult(
                success=False,
                data={"port": port},
                error=str(e),
            )

    async def udp_packets(
        self,
        listener_id: str,
        clear: bool = False,
    ) -> ToolResult:
        """Get captured UDP packets."""
        listener = self.udp_listeners.get(listener_id)

        if not listener:
            return ToolResult(
                success=False,
                data={"listener_id": listener_id},
                error=f"Listener not found: {listener_id}",
            )

        packets = [
            {
                "timestamp": p.timestamp,
                "source_ip": p.source_ip,
                "source_port": p.source_port,
                "data": p.data,
                "data_hex": p.data_hex,
            }
            for p in listener.packets
        ]

        # Check persistence threshold
        if len(packets) > REQUEST_COUNT_THRESHOLD:
            ensure_session_dir()
            filename = f"udp-{listener_id}.jsonl"
            filepath = SESSION_DIR / filename
            listener.persisted_file = str(filepath)

            with open(filepath, "w") as f:
                for pkt in packets:
                    f.write(json.dumps(pkt) + "\n")

        if clear:
            listener.packets = []

        persisted = listener.persisted_file is not None
        return_packets = packets[:50] if len(packets) > 50 else packets

        return ToolResult(
            success=True,
            data={
                "listener_id": listener_id,
                "packets": return_packets,
                "packet_count": len(packets),
                "persisted": persisted,
                "file": listener.persisted_file if persisted else None,
            },
            raw_output=f"Captured {len(packets)} UDP packets",
        )

    async def udp_send(
        self,
        host: str,
        port: int,
        data: str,
    ) -> ToolResult:
        """Send UDP packet."""
        self.logger.info(f"Sending UDP packet to {host}:{port}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            encoded = data.encode()
            sock.sendto(encoded, (host, port))
            sock.close()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "port": port,
                    "bytes_sent": len(encoded),
                },
                raw_output=f"Sent {len(encoded)} bytes to {host}:{port}",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=str(e),
            )

    # =========================================================================
    # Shared Methods
    # =========================================================================

    async def connect(
        self,
        host: str,
        port: int,
        data: Optional[str] = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Connect to remote TCP host."""
        self.logger.info(f"Connecting to {host}:{port}")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

            # Send data if provided
            if data:
                writer.write(data.encode())
                await writer.drain()

            # Read response
            try:
                response = await asyncio.wait_for(
                    reader.read(65536),
                    timeout=10.0,
                )
                response_text = response.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                response_text = ""

            writer.close()
            await writer.wait_closed()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "port": port,
                    "data_sent": len(data) if data else 0,
                    "response": response_text,
                    "response_bytes": len(response_text),
                },
                raw_output=response_text if response_text else f"Connected to {host}:{port}, no response",
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=f"Connection timeout after {timeout} seconds",
            )
        except ConnectionRefusedError:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error="Connection refused",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=str(e),
            )

    async def check_port(
        self,
        host: str,
        port: int,
        timeout: int = 5,
    ) -> ToolResult:
        """Check if TCP port is open."""
        self.logger.info(f"Checking port {host}:{port}")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

            # Try to grab banner
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            writer.close()
            await writer.wait_closed()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "port": port,
                    "open": True,
                    "banner": banner if banner else None,
                },
                raw_output=f"Port {port} is OPEN" + (f" - {banner}" if banner else ""),
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=True,
                data={"host": host, "port": port, "open": False, "status": "filtered"},
                raw_output=f"Port {port} is FILTERED (timeout)",
            )
        except ConnectionRefusedError:
            return ToolResult(
                success=True,
                data={"host": host, "port": port, "open": False, "status": "closed"},
                raw_output=f"Port {port} is CLOSED",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=str(e),
            )

    async def _get_interface_ips(self) -> List[str]:
        """Get non-loopback IPv4 addresses."""
        ips = []
        try:
            result = await self.run_command(["ip", "-j", "addr"], timeout=5)
            interfaces = json.loads(result.stdout)
            for iface in interfaces:
                if iface.get("ifname") == "lo":
                    continue
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        ips.append(addr_info.get("local"))
        except Exception:
            pass
        return ips

    async def get_interfaces(self) -> ToolResult:
        """Get network interfaces."""
        self.logger.info("Getting network interfaces")

        try:
            result = await self.run_command(["ip", "-j", "addr"], timeout=5)
            interfaces = json.loads(result.stdout)

            output = []
            for iface in interfaces:
                ifname = iface.get("ifname")
                if ifname == "lo":
                    continue

                addrs = []
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        addrs.append(addr_info.get("local"))

                if addrs:
                    output.append({
                        "interface": ifname,
                        "addresses": addrs,
                    })

            raw = "\n".join(
                f"{i['interface']}: {', '.join(i['addresses'])}"
                for i in output
            )

            return ToolResult(
                success=True,
                data={"interfaces": output},
                raw_output=raw if raw else "No interfaces found",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def list_all(self) -> ToolResult:
        """List all active listeners and servers."""
        items = []

        # TCP listeners
        for lid, listener in self.tcp_listeners.items():
            items.append({
                "id": lid,
                "type": "tcp",
                "port": listener.port,
                "status": listener.status,
                "created_at": datetime.fromtimestamp(listener.created_at).isoformat(),
                "remote": f"{listener.remote_addr[0]}:{listener.remote_addr[1]}" if listener.remote_addr else None,
            })

        # HTTP servers
        for sid, server in self.http_servers.items():
            items.append({
                "id": sid,
                "type": "http",
                "port": server.port,
                "tls": server.tls,
                "files": list(server.files.keys()),
                "request_count": len(server.requests),
                "created_at": datetime.fromtimestamp(server.created_at).isoformat(),
            })

        # UDP listeners
        for uid, listener in self.udp_listeners.items():
            items.append({
                "id": uid,
                "type": "udp",
                "port": listener.port,
                "packet_count": len(listener.packets),
                "created_at": datetime.fromtimestamp(listener.created_at).isoformat(),
            })

        return ToolResult(
            success=True,
            data={
                "listeners": items,
                "total": len(items),
            },
            raw_output=f"Active listeners: {len(items)}",
        )

    async def stop(self, id: str) -> ToolResult:
        """Stop a listener or server."""
        self.logger.info(f"Stopping {id}")

        # Check TCP listeners
        if id in self.tcp_listeners:
            listener = self.tcp_listeners.pop(id)
            if listener.writer:
                listener.writer.close()
            if listener.server:
                listener.server.close()
                await listener.server.wait_closed()

            return ToolResult(
                success=True,
                data={
                    "id": id,
                    "type": "tcp",
                    "port": listener.port,
                    "buffered_data": listener.buffer,
                },
                raw_output=f"TCP listener {id} stopped",
            )

        # Check HTTP servers
        if id in self.http_servers:
            server = self.http_servers.pop(id)

            # Get final requests
            final_requests = []
            if server.persisted_file and os.path.exists(server.persisted_file):
                with open(server.persisted_file) as f:
                    for line in f:
                        try:
                            final_requests.append(json.loads(line.strip()))
                        except Exception:
                            pass

            for req in server.requests:
                final_requests.append({
                    "timestamp": req.timestamp,
                    "method": req.method,
                    "path": req.path,
                    "query": req.query,
                    "headers": req.headers,
                    "body": req.body,
                    "source_ip": req.source_ip,
                    "source_port": req.source_port,
                })

            # Stop server
            if server.runner:
                await server.runner.cleanup()

            uptime = int(time.time() - server.created_at)

            return ToolResult(
                success=True,
                data={
                    "id": id,
                    "type": "http",
                    "port": server.port,
                    "requests": final_requests[:50],
                    "total_requests": len(final_requests),
                    "uptime_seconds": uptime,
                    "persisted_file": server.persisted_file,
                },
                raw_output=f"HTTP server {id} stopped after {uptime}s, {len(final_requests)} total requests",
            )

        # Check UDP listeners
        if id in self.udp_listeners:
            listener = self.udp_listeners.pop(id)

            packets = [
                {
                    "timestamp": p.timestamp,
                    "source_ip": p.source_ip,
                    "source_port": p.source_port,
                    "data": p.data,
                }
                for p in listener.packets
            ]

            if listener.transport:
                listener.transport.close()

            return ToolResult(
                success=True,
                data={
                    "id": id,
                    "type": "udp",
                    "port": listener.port,
                    "packets": packets[:50],
                    "total_packets": len(packets),
                },
                raw_output=f"UDP listener {id} stopped, {len(packets)} packets captured",
            )

        return ToolResult(
            success=False,
            data={"id": id},
            error=f"Listener/server not found: {id}",
        )


if __name__ == "__main__":
    NetcatServer.main()
