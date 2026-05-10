#!/bin/bash
set -e

# Defensive: if /session is bind-mounted by ContainerManager, the bind-mount
# overlays the image-time mkdir. Re-creating /session/output here ensures the
# `export` tool's default exportsPath resolves under the host-shared volume.
mkdir -p /session/output 2>/dev/null || true

# ── Offensive tuning (parallel to aws's UA-strip + telemetry kill in tools/aws) ──
#
#   MDB_MCP_TELEMETRY=disabled  — kill MongoDB usage telemetry. Upstream sends
#                                  product-analytics events to MongoDB Inc by
#                                  default; offensive engagements MUST NOT.
#   DO_NOT_TRACK=1              — secondary kill switch (DNT spec); some
#                                  upstream telemetry libraries honor it.
#   MDB_MCP_DISABLED_TOOLS=atlas,create,update,delete — restrict surface to
#                                  read+connect+metadata only by disabling the
#                                  destructive operation-type categories. NOT
#                                  using --readOnly because upstream's
#                                  read-only flag (verified live 2026-05-08
#                                  against mongodb-mcp-server@^0) ALSO drops
#                                  the `connect` tool, which makes the server
#                                  unusable when no MDB_MCP_CONNECTION_STRING
#                                  is preset (every offensive engagement). The
#                                  operation-type disable avoids that bug
#                                  while still removing insert-many,
#                                  update-many, delete-many, drop-collection,
#                                  drop-database, rename-collection,
#                                  create-collection, create-index, drop-index
#                                  from tools/list. The `atlas` category
#                                  silences ~21 always-failing Atlas tools
#                                  when no MDB_MCP_API_CLIENT_ID/_SECRET creds
#                                  are configured (typical engagement). Override
#                                  per engagement: pass a different value via
#                                  cli_in_container env arg — e.g. unset to get
#                                  full write surface for post-ex (insert
#                                  malicious user into a captured creds
#                                  collection), or set to "atlas" alone if
#                                  Atlas tools are in scope (with API creds).
#
# CRITICAL OFFENSIVE GOTCHA — connection appName fingerprint:
#   Upstream sets connection metadata `appName=mongodb-mcp-server X.Y.Z--<deviceId>--<clientName>`
#   (verified in src/common/connectionManager.ts via setAppNameParamIfMissing).
#   Defenders running `db.currentOp({"$ownOps": true})` or scanning the
#   slow-query / audit log see this fingerprint as the connection identifier.
#   Upstream ONLY sets appName if the connection URI doesn't already have one,
#   so the agent should ALWAYS pass `?appName=mongo` (or another generic value
#   like the actual mongosh shell name) in the URI it sends to the `connect`
#   tool. Documented in tool.yaml gotchas + scenarios.md.
export MDB_MCP_TELEMETRY="${MDB_MCP_TELEMETRY:-disabled}"
export DO_NOT_TRACK="${DO_NOT_TRACK:-1}"
export MDB_MCP_DISABLED_TOOLS="${MDB_MCP_DISABLED_TOOLS:-atlas,create,update,delete}"

# Conservative query limits. Large collections (think production user table
# with 10M docs) shouldn't blow up the agent context. 100 docs / 1 MB / 30 s
# matches the rough scale of one tool-call's worth of evidence. Override per
# call via env arg if a wider scan is needed.
export MDB_MCP_MAX_DOCUMENTS_PER_QUERY="${MDB_MCP_MAX_DOCUMENTS_PER_QUERY:-100}"
export MDB_MCP_MAX_BYTES_PER_QUERY="${MDB_MCP_MAX_BYTES_PER_QUERY:-1048576}"
export MDB_MCP_MAX_TIME_MS="${MDB_MCP_MAX_TIME_MS:-30000}"

# MDB_MCP_EXPORTS_PATH=/session/output: the `export` tool's default exportsPath
# is /root/.mongodb/mongodb-mcp/exports/<uuid>/ (verified live 2026-05-08, the
# vendor never read the bind-mount). Re-pointing to /session/output makes
# exports visible on the host filesystem under ${sessionDir}/output/, so
# opensploit's report agent can pick up `find`/`aggregate` cursor exports
# as evidence without copying through the container. Set via env var because
# `--loggers <values...>` is multi-value and eats the following `--exportsPath`
# CLI flag (verified live 2026-05-08: server crashed with
# `Error: Invalid logger: --exportsPath`).
export MDB_MCP_EXPORTS_PATH="${MDB_MCP_EXPORTS_PATH:-/session/output}"

# stdio transport matches opensploit's ContainerManager.
# --loggers stderr keeps server diagnostics out of the JSON-RPC channel
# (otherwise the MCP framing breaks).
exec npx mongodb-mcp-server --transport stdio --loggers stderr
