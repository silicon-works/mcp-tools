#!/usr/bin/env python3
"""
OpenSploit MCP Server: mongodb

MongoDB client for database enumeration and data extraction.
Supports both authenticated and unauthenticated access.
"""

import json
from datetime import datetime
from typing import Optional
from urllib.parse import quote_plus

from mcp_common import BaseMCPServer, ToolResult, ToolError

# Import pymongo for direct MongoDB access
try:
    from pymongo import MongoClient
    from pymongo.errors import (
        ConnectionFailure,
        OperationFailure,
        ServerSelectionTimeoutError,
    )
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


# Common connection params shared by all methods
_CONNECTION_PARAMS = {
    "host": {
        "type": "string",
        "description": "MongoDB host (not required if uri is provided)",
    },
    "port": {
        "type": "integer",
        "default": 27017,
        "description": "MongoDB port",
    },
    "username": {
        "type": "string",
        "description": "Username for authentication (optional)",
    },
    "password": {
        "type": "string",
        "description": "Password for authentication (optional)",
    },
    "auth_db": {
        "type": "string",
        "default": "admin",
        "description": "Authentication database",
    },
    "uri": {
        "type": "string",
        "description": "Full MongoDB connection string URI (e.g., 'mongodb://user:pass@host:27017/db?authSource=admin'). If provided, overrides host/port/username/password/auth_db params.",
    },
    "tls": {
        "type": "boolean",
        "default": False,
        "description": "Enable TLS for the connection",
    },
    "tls_insecure": {
        "type": "boolean",
        "default": False,
        "description": "Allow invalid TLS certificates and hostnames (for self-signed certs)",
    },
}


def _conn_params(**overrides):
    """Return a copy of connection params with optional overrides."""
    params = {}
    for k, v in _CONNECTION_PARAMS.items():
        params[k] = dict(v)
    for k, v in overrides.items():
        if k in params:
            params[k].update(v)
        else:
            params[k] = v
    return params


class MongoDBServer(BaseMCPServer):
    """MCP server wrapping MongoDB client for database operations."""

    def __init__(self):
        super().__init__(
            name="mongodb",
            description="MongoDB client for database enumeration and data extraction",
            version="1.0.0",
        )

        self.register_method(
            name="connect",
            description="Test connection to a MongoDB server",
            params={
                **_conn_params(),
                "timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "Connection timeout in seconds",
                },
            },
            handler=self.connect,
        )

        self.register_method(
            name="list_databases",
            description="List all databases on the MongoDB server",
            params=_conn_params(),
            handler=self.list_databases,
        )

        self.register_method(
            name="list_collections",
            description="List all collections in a database",
            params={
                **_conn_params(),
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Database name",
                },
            },
            handler=self.list_collections,
        )

        self.register_method(
            name="query",
            description="Query documents from a collection",
            params={
                **_conn_params(),
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Database name",
                },
                "collection": {
                    "type": "string",
                    "required": True,
                    "description": "Collection name",
                },
                "filter": {
                    "type": "object",
                    "default": {},
                    "description": "MongoDB query filter (JSON)",
                },
                "projection": {
                    "type": "object",
                    "description": "Fields to include/exclude",
                },
                "sort": {
                    "type": "object",
                    "description": "Sort order as JSON object. Example: {'created_at': -1} for newest first, {'username': 1} for alphabetical",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum documents to return",
                },
            },
            handler=self.query,
        )

        self.register_method(
            name="dump_collection",
            description="Dump all documents from a collection",
            params={
                **_conn_params(),
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Database name",
                },
                "collection": {
                    "type": "string",
                    "required": True,
                    "description": "Collection name",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum documents to return",
                },
            },
            handler=self.dump_collection,
        )

        self.register_method(
            name="find_credentials",
            description="Search for credential-like data across collections",
            params={
                **_conn_params(),
                "database": {
                    "type": "string",
                    "description": "Database to search (all if not specified)",
                },
            },
            handler=self.find_credentials,
        )

        self.register_method(
            name="server_info",
            description="Get MongoDB server information and version",
            params=_conn_params(),
            handler=self.server_info,
        )

    def _get_client(
        self,
        host: Optional[str] = None,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        timeout: int = 5,
        uri: Optional[str] = None,
        tls: bool = False,
        tls_insecure: bool = False,
    ) -> MongoClient:
        """Create a MongoDB client connection."""
        if not PYMONGO_AVAILABLE:
            raise ToolError("pymongo is not installed")

        # Build connection URI
        if uri:
            connection_uri = uri
        elif host:
            if username and password:
                connection_uri = f"mongodb://{quote_plus(username)}:{quote_plus(password)}@{host}:{port}/?authSource={auth_db}"
            else:
                connection_uri = f"mongodb://{host}:{port}/"
        else:
            raise ToolError("Either 'host' or 'uri' must be provided")

        kwargs = {
            "serverSelectionTimeoutMS": timeout * 1000,
            "connectTimeoutMS": timeout * 1000,
        }

        if tls:
            kwargs["tls"] = True
            if tls_insecure:
                kwargs["tlsAllowInvalidCertificates"] = True
                kwargs["tlsAllowInvalidHostnames"] = True

        try:
            client = MongoClient(connection_uri, **kwargs)
            # Force connection check
            client.admin.command("ping")
            return client
        except ServerSelectionTimeoutError:
            target = uri or f"{host}:{port}"
            raise ToolError(f"Connection timed out to {target}")
        except ConnectionFailure as e:
            raise ToolError(f"Connection failed: {e}")
        except OperationFailure as e:
            raise ToolError(f"Authentication failed: {e}")

    def _serialize_value(self, value):
        """Serialize a single MongoDB value to JSON-compatible format."""
        if isinstance(value, dict):
            return self._serialize_doc(value)
        elif isinstance(value, list):
            return [self._serialize_value(v) for v in value]
        elif isinstance(value, bytes):
            return value.hex()
        elif isinstance(value, datetime):
            return value.isoformat()
        elif type(value).__name__ == "ObjectId":
            return str(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            return value
        else:
            return str(value)

    def _serialize_doc(self, doc: dict) -> dict:
        """Serialize MongoDB document to JSON-compatible format."""
        result = {}
        for key, value in doc.items():
            if key == "_id":
                result[key] = str(value)
            else:
                result[key] = self._serialize_value(value)
        return result

    async def connect(
        self,
        host: Optional[str] = None,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        timeout: int = 5,
        uri: Optional[str] = None,
        tls: bool = False,
        tls_insecure: bool = False,
    ) -> ToolResult:
        """Test connection to MongoDB server."""
        target = uri or f"{host}:{port}"
        self.logger.info(f"Testing connection to {target}")

        try:
            client = self._get_client(host, port, username, password, auth_db, timeout, uri, tls, tls_insecure)
            info = client.server_info()
            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host or uri,
                    "port": port,
                    "connected": True,
                    "version": info.get("version", "unknown"),
                    "authenticated": bool(username) or bool(uri and "@" in uri),
                    "tls": tls,
                },
                raw_output=f"Connected to MongoDB {info.get('version', 'unknown')} at {target}",
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host or uri, "port": port, "connected": False},
                error=str(e),
            )

    async def list_databases(
        self,
        host: Optional[str] = None,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        uri: Optional[str] = None,
        tls: bool = False,
        tls_insecure: bool = False,
    ) -> ToolResult:
        """List all databases on the server."""
        target = uri or f"{host}:{port}"
        self.logger.info(f"Listing databases on {target}")

        try:
            client = self._get_client(host, port, username, password, auth_db, uri=uri, tls=tls, tls_insecure=tls_insecure)
            databases = []

            for db_info in client.list_databases():
                databases.append({
                    "name": db_info["name"],
                    "sizeOnDisk": db_info.get("sizeOnDisk", 0),
                    "empty": db_info.get("empty", False),
                })

            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host or uri,
                    "databases": databases,
                    "count": len(databases),
                },
                raw_output="\n".join([
                    f"{db['name']} ({db['sizeOnDisk']} bytes)"
                    for db in databases
                ]),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host or uri},
                error=str(e),
            )

    async def list_collections(
        self,
        host: Optional[str] = None,
        database: str = "",
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        uri: Optional[str] = None,
        tls: bool = False,
        tls_insecure: bool = False,
    ) -> ToolResult:
        """List all collections in a database."""
        target = uri or f"{host}:{port}"
        self.logger.info(f"Listing collections in {database} on {target}")

        try:
            client = self._get_client(host, port, username, password, auth_db, uri=uri, tls=tls, tls_insecure=tls_insecure)
            db = client[database]
            collections = db.list_collection_names()
            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host or uri,
                    "database": database,
                    "collections": collections,
                    "count": len(collections),
                },
                raw_output="\n".join(collections),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host or uri, "database": database},
                error=str(e),
            )

    async def query(
        self,
        host: Optional[str] = None,
        database: str = "",
        collection: str = "",
        filter: Optional[dict] = None,
        projection: Optional[dict] = None,
        sort: Optional[dict] = None,
        limit: int = 100,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        uri: Optional[str] = None,
        tls: bool = False,
        tls_insecure: bool = False,
    ) -> ToolResult:
        """Query documents from a collection."""
        target = uri or f"{host}:{port}"
        self.logger.info(f"Querying {database}.{collection} on {target}")

        try:
            client = self._get_client(host, port, username, password, auth_db, uri=uri, tls=tls, tls_insecure=tls_insecure)
            db = client[database]
            coll = db[collection]

            query_filter = filter or {}
            cursor = coll.find(query_filter, projection)
            if sort:
                cursor = cursor.sort(list(sort.items()))
            cursor = cursor.limit(limit)
            documents = [self._serialize_doc(doc) for doc in cursor]

            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host or uri,
                    "database": database,
                    "collection": collection,
                    "filter": query_filter,
                    "documents": documents,
                    "count": len(documents),
                },
                raw_output=json.dumps(documents, indent=2, default=str),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host or uri, "database": database, "collection": collection},
                error=str(e),
            )

    async def dump_collection(
        self,
        host: Optional[str] = None,
        database: str = "",
        collection: str = "",
        limit: int = 100,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        uri: Optional[str] = None,
        tls: bool = False,
        tls_insecure: bool = False,
    ) -> ToolResult:
        """Dump all documents from a collection."""
        return await self.query(
            host=host,
            database=database,
            collection=collection,
            filter={},
            limit=limit,
            port=port,
            username=username,
            password=password,
            auth_db=auth_db,
            uri=uri,
            tls=tls,
            tls_insecure=tls_insecure,
        )

    async def find_credentials(
        self,
        host: Optional[str] = None,
        database: Optional[str] = None,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        uri: Optional[str] = None,
        tls: bool = False,
        tls_insecure: bool = False,
    ) -> ToolResult:
        """Search for credential-like data across collections."""
        target = uri or f"{host}:{port}"
        self.logger.info(f"Searching for credentials on {target}")

        findings = []

        # Collection name patterns that might contain credentials
        credential_collections = [
            "users", "accounts", "members", "admins", "admin",
            "credentials", "auth", "authentication", "login",
            "user", "account", "member", "passwords",
        ]

        # Field name patterns to look for
        credential_fields = [
            "password", "passwd", "pass", "pwd", "secret",
            "hash", "token", "api_key", "apikey", "key",
            "credential", "auth",
        ]

        try:
            client = self._get_client(host, port, username, password, auth_db, uri=uri, tls=tls, tls_insecure=tls_insecure)

            # Get databases to search
            if database:
                databases = [database]
            else:
                databases = [
                    db["name"] for db in client.list_databases()
                    if db["name"] not in ("admin", "config", "local")
                ]

            for db_name in databases:
                db = client[db_name]
                collections = db.list_collection_names()
                processed_collections = set()

                # First pass: collections with credential-like names
                for coll_name in collections:
                    is_credential_collection = any(
                        pattern in coll_name.lower()
                        for pattern in credential_collections
                    )

                    if is_credential_collection:
                        processed_collections.add(coll_name)
                        coll = db[coll_name]
                        docs = list(coll.find().limit(20))

                        if docs:
                            sample = docs[0]
                            has_credential_fields = any(
                                any(field in key.lower() for field in credential_fields)
                                for key in sample.keys()
                            )

                            findings.append({
                                "database": db_name,
                                "collection": coll_name,
                                "document_count": coll.count_documents({}),
                                "has_credential_fields": has_credential_fields,
                                "match_type": "collection_name",
                                "sample_documents": [
                                    self._serialize_doc(doc)
                                    for doc in docs[:5]
                                ],
                            })

                # Second pass: scan remaining collections for credential-like fields
                for coll_name in collections:
                    if coll_name in processed_collections:
                        continue

                    try:
                        coll = db[coll_name]
                        sample = coll.find_one()
                        if sample:
                            has_credential_fields = any(
                                any(field in key.lower() for field in credential_fields)
                                for key in sample.keys()
                            )
                            if has_credential_fields:
                                docs = list(coll.find().limit(20))
                                findings.append({
                                    "database": db_name,
                                    "collection": coll_name,
                                    "document_count": coll.count_documents({}),
                                    "has_credential_fields": True,
                                    "match_type": "field_pattern",
                                    "sample_documents": [
                                        self._serialize_doc(doc)
                                        for doc in docs[:5]
                                    ],
                                })
                    except Exception:
                        continue

            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host or uri,
                    "findings": findings,
                    "databases_searched": databases,
                    "total_findings": len(findings),
                },
                raw_output=f"Found {len(findings)} potential credential collections",
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host or uri},
                error=str(e),
            )

    async def server_info(
        self,
        host: Optional[str] = None,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        uri: Optional[str] = None,
        tls: bool = False,
        tls_insecure: bool = False,
    ) -> ToolResult:
        """Get MongoDB server information."""
        target = uri or f"{host}:{port}"
        self.logger.info(f"Getting server info from {target}")

        try:
            client = self._get_client(host, port, username, password, auth_db, uri=uri, tls=tls, tls_insecure=tls_insecure)
            info = client.server_info()

            # Get build info
            try:
                build_info = client.admin.command("buildInfo")
            except Exception:
                build_info = {}

            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host or uri,
                    "port": port,
                    "version": info.get("version", "unknown"),
                    "git_version": info.get("gitVersion", "unknown"),
                    "modules": info.get("modules", []),
                    "bits": info.get("bits", 64),
                    "max_bson_object_size": info.get("maxBsonObjectSize", 0),
                    "storage_engines": build_info.get("storageEngines", []),
                    "javascript_engine": info.get("javascriptEngine", "unknown"),
                },
                raw_output=f"MongoDB {info.get('version', 'unknown')} ({info.get('bits', 64)}-bit)",
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host or uri, "port": port},
                error=str(e),
            )


if __name__ == "__main__":
    MongoDBServer.main()
