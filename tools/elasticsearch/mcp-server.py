#!/usr/bin/env python3
"""
OpenSploit MCP Server: elasticsearch

Elasticsearch enumeration and data extraction via REST API.
Supports cluster info, index enumeration, full Query DSL search,
bulk data dump with scroll API, and snapshot enumeration.
"""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class ElasticsearchServer(BaseMCPServer):
    """MCP server for Elasticsearch enumeration and data extraction."""

    def __init__(self):
        super().__init__(
            name="elasticsearch",
            description="Elasticsearch enumeration and data extraction via REST API",
            version="1.0.0",
        )

        _conn_params = {
            "host": {
                "type": "string",
                "required": True,
                "description": "Elasticsearch host (e.g., 'http://10.10.10.5:9200')",
            },
            "username": {
                "type": "string",
                "description": "HTTP Basic auth username (omit for unauthenticated access)",
            },
            "password": {
                "type": "string",
                "description": "HTTP Basic auth password",
            },
            "verify_ssl": {
                "type": "boolean",
                "default": False,
                "description": "Verify SSL certificates (default: false for pentest use)",
            },
        }

        self.register_method(
            name="cluster_info",
            description="Get Elasticsearch cluster health, version, node info, and installed plugins",
            params=_conn_params,
            handler=self.cluster_info,
        )

        self.register_method(
            name="enum_indices",
            description="List all indices with size, document count, and status",
            params=_conn_params,
            handler=self.enum_indices,
        )

        self.register_method(
            name="get_mappings",
            description="Get field mappings for a specific index",
            params={
                **_conn_params,
                "index": {
                    "type": "string",
                    "required": True,
                    "description": "Index name to get mappings for",
                },
            },
            handler=self.get_mappings,
        )

        self.register_method(
            name="search",
            description="Search an Elasticsearch index using Query DSL",
            params={
                **_conn_params,
                "index": {
                    "type": "string",
                    "default": "_all",
                    "description": "Index to search (default: all indices)",
                },
                "query": {
                    "type": "object",
                    "description": "Elasticsearch Query DSL body (e.g., {'match_all': {}} or {'match': {'field': 'value'}}). Default: match_all.",
                },
                "size": {
                    "type": "integer",
                    "default": 20,
                    "description": "Number of results to return (max per request)",
                },
                "from_offset": {
                    "type": "integer",
                    "default": 0,
                    "description": "Offset for pagination",
                },
                "source_fields": {
                    "type": "array",
                    "description": "List of fields to return (default: all fields)",
                },
            },
            handler=self.search,
        )

        self.register_method(
            name="dump",
            description="Bulk dump all documents from an index using scroll API (no 10K limit)",
            params={
                **_conn_params,
                "index": {
                    "type": "string",
                    "required": True,
                    "description": "Index to dump",
                },
                "max_docs": {
                    "type": "integer",
                    "default": 1000,
                    "description": "Maximum documents to retrieve (safety limit)",
                },
                "scroll_time": {
                    "type": "string",
                    "default": "5m",
                    "description": "Scroll context time (e.g., '5m', '10m')",
                },
            },
            handler=self.dump,
        )

        self.register_method(
            name="enum_snapshots",
            description="List snapshot repositories and snapshots",
            params=_conn_params,
            handler=self.enum_snapshots,
        )

    def _get_auth(self, username: str = None, password: str = None):
        """Get auth tuple if credentials provided."""
        if username and password:
            return HTTPBasicAuth(username, password)
        return None

    def _api_call(
        self,
        host: str,
        path: str,
        method: str = "GET",
        data: dict = None,
        username: str = None,
        password: str = None,
        verify_ssl: bool = False,
        timeout: int = 10,
    ) -> dict:
        """Make an Elasticsearch REST API call."""
        url = f"{host.rstrip('/')}/{path.lstrip('/')}"
        auth = self._get_auth(username, password)

        kwargs = {
            "auth": auth,
            "verify": verify_ssl,
            "timeout": timeout,
            "headers": {"Content-Type": "application/json"},
        }

        if method == "GET":
            resp = requests.get(url, **kwargs)
        elif method == "POST":
            resp = requests.post(url, json=data, **kwargs)
        elif method == "DELETE":
            resp = requests.delete(url, **kwargs)
        else:
            resp = requests.get(url, **kwargs)

        resp.raise_for_status()
        return resp.json()

    async def cluster_info(
        self,
        host: str,
        username: str = None,
        password: str = None,
        verify_ssl: bool = False,
    ) -> ToolResult:
        """Get cluster health, version, nodes, and plugins."""
        self.logger.info(f"ES cluster info: {host}")

        try:
            info = {}

            # Root info (version, cluster name)
            root = self._api_call(host, "/", username=username, password=password, verify_ssl=verify_ssl)
            info["cluster_name"] = root.get("cluster_name", "unknown")
            info["version"] = root.get("version", {}).get("number", "unknown")
            info["tagline"] = root.get("tagline", "")

            # Cluster health
            try:
                health = self._api_call(host, "/_cluster/health", username=username, password=password, verify_ssl=verify_ssl)
                info["status"] = health.get("status")
                info["number_of_nodes"] = health.get("number_of_nodes")
                info["number_of_data_nodes"] = health.get("number_of_data_nodes")
                info["active_shards"] = health.get("active_shards")
            except Exception:
                info["health"] = "could not retrieve"

            # Nodes
            try:
                nodes = self._api_call(host, "/_cat/nodes?format=json", username=username, password=password, verify_ssl=verify_ssl)
                info["nodes"] = nodes
            except Exception:
                pass

            # Plugins
            try:
                plugins = self._api_call(host, "/_cat/plugins?format=json", username=username, password=password, verify_ssl=verify_ssl)
                info["plugins"] = plugins
            except Exception:
                info["plugins"] = []

            return ToolResult(
                success=True,
                data=info,
                raw_output=json.dumps(info, indent=2),
            )

        except requests.exceptions.ConnectionError:
            return ToolResult(success=False, data={}, error=f"Cannot connect to {host}")
        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Cluster info failed: {e}")

    async def enum_indices(
        self,
        host: str,
        username: str = None,
        password: str = None,
        verify_ssl: bool = False,
    ) -> ToolResult:
        """List all indices."""
        self.logger.info(f"ES enum indices: {host}")

        try:
            indices = self._api_call(
                host, "/_cat/indices?format=json&h=index,status,health,docs.count,store.size,pri,rep",
                username=username, password=password, verify_ssl=verify_ssl,
            )

            return ToolResult(
                success=True,
                data={
                    "indices": indices,
                    "index_count": len(indices),
                    "index_names": [i.get("index", "") for i in indices],
                },
                raw_output=json.dumps(indices, indent=2),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Index enumeration failed: {e}")

    async def get_mappings(
        self,
        host: str,
        index: str,
        username: str = None,
        password: str = None,
        verify_ssl: bool = False,
    ) -> ToolResult:
        """Get field mappings for an index."""
        self.logger.info(f"ES get mappings: {host}/{index}")

        try:
            mappings = self._api_call(
                host, f"/{index}/_mapping",
                username=username, password=password, verify_ssl=verify_ssl,
            )

            return ToolResult(
                success=True,
                data={"index": index, "mappings": mappings},
                raw_output=json.dumps(mappings, indent=2),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Get mappings failed: {e}")

    async def search(
        self,
        host: str,
        index: str = "_all",
        query: dict = None,
        size: int = 20,
        from_offset: int = 0,
        source_fields: list = None,
        username: str = None,
        password: str = None,
        verify_ssl: bool = False,
    ) -> ToolResult:
        """Search an index using Query DSL."""
        self.logger.info(f"ES search: {host}/{index}")

        body = {
            "query": query or {"match_all": {}},
            "size": size,
            "from": from_offset,
        }

        if source_fields:
            body["_source"] = source_fields

        try:
            result = self._api_call(
                host, f"/{index}/_search",
                method="POST", data=body,
                username=username, password=password, verify_ssl=verify_ssl,
                timeout=30,
            )

            hits = result.get("hits", {})
            documents = [h.get("_source", {}) for h in hits.get("hits", [])]
            total = hits.get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", 0)
            else:
                total_count = total

            return ToolResult(
                success=True,
                data={
                    "index": index,
                    "documents": documents,
                    "returned": len(documents),
                    "total": total_count,
                },
                raw_output=sanitize_output(json.dumps(documents, indent=2), max_length=30000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Search failed: {e}")

    async def dump(
        self,
        host: str,
        index: str,
        max_docs: int = 1000,
        scroll_time: str = "5m",
        username: str = None,
        password: str = None,
        verify_ssl: bool = False,
    ) -> ToolResult:
        """Bulk dump an index using scroll API."""
        self.logger.info(f"ES dump: {host}/{index} max={max_docs}")

        all_docs = []
        scroll_id = None

        try:
            # Initial search with scroll
            body = {"query": {"match_all": {}}, "size": min(100, max_docs)}
            result = self._api_call(
                host, f"/{index}/_search?scroll={scroll_time}",
                method="POST", data=body,
                username=username, password=password, verify_ssl=verify_ssl,
                timeout=60,
            )

            scroll_id = result.get("_scroll_id")
            hits = result.get("hits", {}).get("hits", [])
            all_docs.extend([h.get("_source", {}) for h in hits])

            # Continue scrolling
            while hits and len(all_docs) < max_docs and scroll_id:
                result = self._api_call(
                    host, "/_search/scroll",
                    method="POST",
                    data={"scroll": scroll_time, "scroll_id": scroll_id},
                    username=username, password=password, verify_ssl=verify_ssl,
                    timeout=60,
                )
                scroll_id = result.get("_scroll_id")
                hits = result.get("hits", {}).get("hits", [])
                all_docs.extend([h.get("_source", {}) for h in hits])

            # Clean up scroll context
            if scroll_id:
                try:
                    self._api_call(
                        host, "/_search/scroll",
                        method="DELETE",
                        data={"scroll_id": scroll_id},
                        username=username, password=password, verify_ssl=verify_ssl,
                    )
                except Exception:
                    pass

            # Trim to max
            all_docs = all_docs[:max_docs]

            return ToolResult(
                success=True,
                data={
                    "index": index,
                    "documents": all_docs,
                    "document_count": len(all_docs),
                },
                raw_output=sanitize_output(json.dumps(all_docs, indent=2), max_length=50000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Dump failed: {e}")

    async def enum_snapshots(
        self,
        host: str,
        username: str = None,
        password: str = None,
        verify_ssl: bool = False,
    ) -> ToolResult:
        """List snapshot repositories and snapshots."""
        self.logger.info(f"ES enum snapshots: {host}")

        try:
            repos = self._api_call(
                host, "/_snapshot",
                username=username, password=password, verify_ssl=verify_ssl,
            )

            snapshots = {}
            for repo_name in repos:
                try:
                    snaps = self._api_call(
                        host, f"/_snapshot/{repo_name}/_all",
                        username=username, password=password, verify_ssl=verify_ssl,
                    )
                    snapshots[repo_name] = snaps.get("snapshots", [])
                except Exception:
                    snapshots[repo_name] = "access denied or empty"

            return ToolResult(
                success=True,
                data={
                    "repositories": list(repos.keys()),
                    "repository_count": len(repos),
                    "snapshots": snapshots,
                },
                raw_output=json.dumps({"repositories": repos, "snapshots": snapshots}, indent=2),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Snapshot enumeration failed: {e}")


if __name__ == "__main__":
    ElasticsearchServer.main()
