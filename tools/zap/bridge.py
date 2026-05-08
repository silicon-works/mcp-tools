#!/usr/bin/env python3
"""
ZAP MCP stdio↔HTTP bridge.

ZAP's MCP add-on speaks MCP-over-HTTP on http://127.0.0.1:8282/. OpenSploit's
ContainerManager speaks MCP-over-stdio. This bridge sits in between:

  stdin  (newline-delimited JSON-RPC)  →  POST http://127.0.0.1:8282/
  HTTP response (JSON body)            →  stdout (newline-delimited JSON-RPC)

Auth:
  ZAP's McpHttpMessageHandler does a raw byte-compare of the Authorization
  header value against the configured securityKey (NO `Bearer ` prefix).
  We pass the value directly.

Sessions:
  ZAP's MCP server is stateless across HTTP requests — there's no
  MCP-Session-Id header in either direction (verified against
  McpHttpMessageHandler.java). We don't need to track one.

Notifications:
  JSON-RPC notifications (no `id` field) get HTTP 202 + empty body from ZAP.
  We POST them and DO NOT write a response back to stdout (per JSON-RPC 2.0
  spec: notifications never receive responses).

Errors:
  Any HTTP-level failure (5xx, connection refused, timeout) gets translated
  to a JSON-RPC error frame. This way opensploit always sees a structured
  response and never a broken pipe.

All diagnostic logging goes to stderr — stdout is reserved for protocol
traffic.
"""

import json
import os
import sys
import urllib.error
import urllib.request


def log(msg: str) -> None:
    """Write a diagnostic line to stderr."""
    sys.stderr.write(f"[bridge] {msg}\n")
    sys.stderr.flush()


def write_response(obj: dict) -> None:
    """Emit one JSON-RPC frame to stdout (newline-delimited)."""
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def make_error(req_id, code: int, message: str) -> dict:
    """Build a JSON-RPC 2.0 error response object."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def post_to_zap(url: str, key: str, body: bytes, timeout: float) -> tuple[int, bytes]:
    """POST raw JSON bytes to ZAP. Returns (status_code, response_bytes).

    Raises urllib.error.URLError on connection failures.
    """
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        # Server returned 4xx/5xx — read the body and surface it.
        body = e.read() if hasattr(e, "read") else b""
        return e.code, body


def main() -> int:
    port = os.environ.get("ZAP_MCP_PORT", "8282")
    url = f"http://127.0.0.1:{port}/"
    key = os.environ.get("ZAP_MCP_KEY", "")
    if not key:
        log("ZAP_MCP_KEY env var is empty — auth WILL fail")
    # ZAP scans / spider runs can be long; allow generous per-request timeout.
    # Most calls (initialize, tools/list, status polls) return in < 1s.
    request_timeout = float(os.environ.get("ZAP_MCP_REQUEST_TIMEOUT", "300"))

    log(f"ready, forwarding stdin → {url} (timeout={request_timeout}s)")

    # Read JSON-RPC frames from stdin. The MCP framing in opensploit's
    # ContainerManager (and the test client) is newline-delimited JSON.
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        # Parse just enough to know whether it's a notification (no id) and
        # what id to attach to error responses.
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log(f"stdin parse error: {e}; line={line!r}")
            write_response(make_error(None, -32700, f"Parse error: {e}"))
            continue

        is_notification = "id" not in msg
        req_id = msg.get("id")
        method = msg.get("method", "<unknown>")

        # Forward the original line bytes verbatim — ZAP parses JSON itself
        # and we don't want to re-serialize and risk subtle changes.
        try:
            status, body = post_to_zap(url, key, line.encode("utf-8"), request_timeout)
        except urllib.error.URLError as e:
            log(f"upstream error on {method}: {e}")
            if not is_notification:
                write_response(make_error(
                    req_id, -32000, f"ZAP upstream unreachable: {e.reason if hasattr(e, 'reason') else e}"
                ))
            continue
        except Exception as e:  # noqa: BLE001 - last-resort safety net
            log(f"unexpected error on {method}: {e!r}")
            if not is_notification:
                write_response(make_error(req_id, -32603, f"Bridge internal error: {e}"))
            continue

        # Notifications: ZAP returns 202 + empty body. Per JSON-RPC 2.0 we
        # MUST NOT emit a response. Even if ZAP unexpectedly returns a body,
        # we drop it.
        if is_notification:
            if status not in (200, 202):
                log(f"notification {method} got HTTP {status} (continuing)")
            continue

        # Regular request → expect JSON body. Even on 4xx/5xx ZAP emits a
        # JSON-RPC-shaped error body (per McpHttpMessageHandler.setErrorResponse).
        if not body:
            log(f"empty body from ZAP on {method} (HTTP {status})")
            write_response(make_error(req_id, -32603, f"Empty response from ZAP (HTTP {status})"))
            continue

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as e:
            log(f"non-JSON body from ZAP on {method} (HTTP {status}): {body[:200]!r}")
            write_response(make_error(req_id, -32603, f"Invalid response from ZAP: {e}"))
            continue

        # ZAP's error responses don't always carry the original request id —
        # patch it back in so the test client's id-match check passes.
        if isinstance(parsed, dict) and "id" not in parsed and req_id is not None:
            parsed["id"] = req_id

        write_response(parsed)

    log("stdin closed, exiting")
    return 0


if __name__ == "__main__":
    sys.exit(main())
