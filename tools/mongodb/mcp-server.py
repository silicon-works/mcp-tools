#!/usr/bin/env python3
"""
OpenSploit MCP Server: mongodb

MongoDB client for database enumeration and data extraction.
Supports both authenticated and unauthenticated access.
"""

import json
from typing import Optional

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
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "MongoDB host",
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
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "MongoDB host",
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
            },
            handler=self.list_databases,
        )

        self.register_method(
            name="list_collections",
            description="List all collections in a database",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "MongoDB host",
                },
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Database name",
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
            },
            handler=self.list_collections,
        )

        self.register_method(
            name="query",
            description="Query documents from a collection",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "MongoDB host",
                },
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
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum documents to return",
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
            },
            handler=self.query,
        )

        self.register_method(
            name="dump_collection",
            description="Dump all documents from a collection",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "MongoDB host",
                },
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
            },
            handler=self.dump_collection,
        )

        self.register_method(
            name="find_credentials",
            description="Search for credential-like data across collections",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "MongoDB host",
                },
                "database": {
                    "type": "string",
                    "description": "Database to search (all if not specified)",
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
            },
            handler=self.find_credentials,
        )

        self.register_method(
            name="server_info",
            description="Get MongoDB server information and version",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "MongoDB host",
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
            },
            handler=self.server_info,
        )

    def _get_client(
        self,
        host: str,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        timeout: int = 5,
    ) -> MongoClient:
        """Create a MongoDB client connection."""
        if not PYMONGO_AVAILABLE:
            raise ToolError("pymongo is not installed")

        # Build connection URI
        if username and password:
            uri = f"mongodb://{username}:{password}@{host}:{port}/?authSource={auth_db}"
        else:
            uri = f"mongodb://{host}:{port}/"

        try:
            client = MongoClient(
                uri,
                serverSelectionTimeoutMS=timeout * 1000,
                connectTimeoutMS=timeout * 1000,
            )
            # Force connection check
            client.admin.command("ping")
            return client
        except ServerSelectionTimeoutError:
            raise ToolError(f"Connection timed out to {host}:{port}")
        except ConnectionFailure as e:
            raise ToolError(f"Connection failed: {e}")
        except OperationFailure as e:
            raise ToolError(f"Authentication failed: {e}")

    def _serialize_doc(self, doc: dict) -> dict:
        """Serialize MongoDB document to JSON-compatible format."""
        result = {}
        for key, value in doc.items():
            if key == "_id":
                result[key] = str(value)
            elif isinstance(value, bytes):
                result[key] = value.hex()
            elif isinstance(value, dict):
                result[key] = self._serialize_doc(value)
            elif isinstance(value, list):
                result[key] = [
                    self._serialize_doc(v) if isinstance(v, dict) else str(v)
                    for v in value
                ]
            else:
                result[key] = value
        return result

    async def connect(
        self,
        host: str,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
        timeout: int = 5,
    ) -> ToolResult:
        """Test connection to MongoDB server."""
        self.logger.info(f"Testing connection to {host}:{port}")

        try:
            client = self._get_client(host, port, username, password, auth_db, timeout)
            info = client.server_info()
            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "port": port,
                    "connected": True,
                    "version": info.get("version", "unknown"),
                    "authenticated": bool(username),
                },
                raw_output=f"Connected to MongoDB {info.get('version', 'unknown')} at {host}:{port}",
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host, "port": port, "connected": False},
                error=str(e),
            )

    async def list_databases(
        self,
        host: str,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
    ) -> ToolResult:
        """List all databases on the server."""
        self.logger.info(f"Listing databases on {host}:{port}")

        try:
            client = self._get_client(host, port, username, password, auth_db)
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
                    "host": host,
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
                data={"host": host},
                error=str(e),
            )

    async def list_collections(
        self,
        host: str,
        database: str,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
    ) -> ToolResult:
        """List all collections in a database."""
        self.logger.info(f"Listing collections in {database} on {host}:{port}")

        try:
            client = self._get_client(host, port, username, password, auth_db)
            db = client[database]
            collections = db.list_collection_names()
            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "database": database,
                    "collections": collections,
                    "count": len(collections),
                },
                raw_output="\n".join(collections),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host, "database": database},
                error=str(e),
            )

    async def query(
        self,
        host: str,
        database: str,
        collection: str,
        filter: Optional[dict] = None,
        projection: Optional[dict] = None,
        limit: int = 100,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
    ) -> ToolResult:
        """Query documents from a collection."""
        self.logger.info(f"Querying {database}.{collection} on {host}:{port}")

        try:
            client = self._get_client(host, port, username, password, auth_db)
            db = client[database]
            coll = db[collection]

            query_filter = filter or {}
            cursor = coll.find(query_filter, projection).limit(limit)
            documents = [self._serialize_doc(doc) for doc in cursor]

            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host,
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
                data={"host": host, "database": database, "collection": collection},
                error=str(e),
            )

    async def dump_collection(
        self,
        host: str,
        database: str,
        collection: str,
        limit: int = 100,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
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
        )

    async def find_credentials(
        self,
        host: str,
        database: Optional[str] = None,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
    ) -> ToolResult:
        """Search for credential-like data across collections."""
        self.logger.info(f"Searching for credentials on {host}:{port}")

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
            client = self._get_client(host, port, username, password, auth_db)

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

                for coll_name in collections:
                    # Check if collection name matches credential patterns
                    is_credential_collection = any(
                        pattern in coll_name.lower()
                        for pattern in credential_collections
                    )

                    if is_credential_collection:
                        coll = db[coll_name]
                        # Get sample documents
                        docs = list(coll.find().limit(20))

                        if docs:
                            # Check for credential-like fields
                            sample = docs[0] if docs else {}
                            has_credential_fields = any(
                                any(field in key.lower() for field in credential_fields)
                                for key in sample.keys()
                            )

                            findings.append({
                                "database": db_name,
                                "collection": coll_name,
                                "document_count": coll.count_documents({}),
                                "has_credential_fields": has_credential_fields,
                                "sample_documents": [
                                    self._serialize_doc(doc)
                                    for doc in docs[:5]
                                ],
                            })

            client.close()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "findings": findings,
                    "databases_searched": databases,
                    "total_findings": len(findings),
                },
                raw_output=f"Found {len(findings)} potential credential collections",
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host},
                error=str(e),
            )

    async def server_info(
        self,
        host: str,
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_db: str = "admin",
    ) -> ToolResult:
        """Get MongoDB server information."""
        self.logger.info(f"Getting server info from {host}:{port}")

        try:
            client = self._get_client(host, port, username, password, auth_db)
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
                    "host": host,
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
                data={"host": host, "port": port},
                error=str(e),
            )


if __name__ == "__main__":
    MongoDBServer.main()
