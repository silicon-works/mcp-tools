"""
Output parsers for common security tool formats.

Provides utilities to parse output from tools like nmap, gobuster, etc.
into structured data for the MCP response.
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def sanitize_output(output: str, max_length: int = 10000) -> str:
    """
    Sanitize and truncate tool output for safe transmission.

    Args:
        output: Raw tool output
        max_length: Maximum output length

    Returns:
        Sanitized output string
    """
    # Remove ANSI color codes
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    output = ansi_escape.sub("", output)

    # Remove null bytes and other control characters (except newlines/tabs)
    output = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", output)

    # Truncate if too long
    if len(output) > max_length:
        output = output[:max_length] + f"\n\n... (truncated, {len(output) - max_length} bytes omitted)"

    return output


def parse_json_output(output: str) -> Optional[Dict[str, Any]]:
    """
    Parse JSON output from a tool.

    Args:
        output: Raw output that may contain JSON

    Returns:
        Parsed JSON as dict, or None if parsing fails
    """
    # Try to find JSON in the output (some tools mix text with JSON)
    json_match = re.search(r"(\{.*\}|\[.*\])", output, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass
    return None


def parse_table_output(
    output: str,
    delimiter: str = r"\s{2,}",
    header_row: int = 0,
) -> List[Dict[str, str]]:
    """
    Parse table-formatted output into a list of dicts.

    Args:
        output: Raw output with table data
        delimiter: Regex pattern for column delimiter
        header_row: Which row contains headers (0-indexed)

    Returns:
        List of dicts with column headers as keys
    """
    lines = [line.strip() for line in output.strip().split("\n") if line.strip()]
    if len(lines) <= header_row:
        return []

    # Parse header
    headers = re.split(delimiter, lines[header_row])
    headers = [h.strip().lower().replace(" ", "_") for h in headers]

    # Parse data rows
    results = []
    for line in lines[header_row + 1 :]:
        values = re.split(delimiter, line)
        if len(values) >= len(headers):
            row = {headers[i]: values[i].strip() for i in range(len(headers))}
            results.append(row)

    return results


def parse_nmap_xml(xml_output: str) -> Dict[str, Any]:
    """
    Parse nmap XML output into structured data.

    Args:
        xml_output: nmap XML output string

    Returns:
        Structured dict with hosts, ports, services, etc.
    """
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return {"error": "Failed to parse nmap XML output", "raw": xml_output[:500]}

    result = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start_time": root.get("startstr", ""),
        "hosts": [],
    }

    for host in root.findall(".//host"):
        host_data = {
            "status": "unknown",
            "addresses": [],
            "hostnames": [],
            "ports": [],
            "os_matches": [],
        }

        # Status
        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "unknown")

        # Addresses
        for addr in host.findall("address"):
            host_data["addresses"].append({
                "addr": addr.get("addr", ""),
                "type": addr.get("addrtype", ""),
            })

        # Hostnames
        for hostname in host.findall(".//hostname"):
            host_data["hostnames"].append({
                "name": hostname.get("name", ""),
                "type": hostname.get("type", ""),
            })

        # Ports
        for port in host.findall(".//port"):
            port_data = {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "state": "unknown",
                "service": {},
            }

            state = port.find("state")
            if state is not None:
                port_data["state"] = state.get("state", "unknown")
                port_data["reason"] = state.get("reason", "")

            service = port.find("service")
            if service is not None:
                port_data["service"] = {
                    "name": service.get("name", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extrainfo": service.get("extrainfo", ""),
                    "ostype": service.get("ostype", ""),
                }

            # Scripts (NSE results)
            scripts = []
            for script in port.findall("script"):
                scripts.append({
                    "id": script.get("id", ""),
                    "output": script.get("output", ""),
                })
            if scripts:
                port_data["scripts"] = scripts

            host_data["ports"].append(port_data)

        # OS detection
        for osmatch in host.findall(".//osmatch"):
            host_data["os_matches"].append({
                "name": osmatch.get("name", ""),
                "accuracy": int(osmatch.get("accuracy", 0)),
            })

        result["hosts"].append(host_data)

    # Summary
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        hosts_stat = runstats.find("hosts")
        if finished is not None:
            result["elapsed"] = finished.get("elapsed", "")
        if hosts_stat is not None:
            result["hosts_up"] = int(hosts_stat.get("up", 0))
            result["hosts_down"] = int(hosts_stat.get("down", 0))

    return result


def parse_gobuster_output(output: str) -> Dict[str, Any]:
    """
    Parse gobuster output into structured data.

    Args:
        output: gobuster stdout

    Returns:
        Structured dict with discovered paths
    """
    results = {
        "paths": [],
        "errors": [],
    }

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Match found paths: /path (Status: 200) [Size: 1234]
        match = re.match(
            r"(/[^\s]*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?",
            line,
        )
        if match:
            results["paths"].append({
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)) if match.group(3) else None,
            })
            continue

        # Check for errors
        if line.startswith("Error:") or "error" in line.lower():
            results["errors"].append(line)

    return results


def parse_sqlmap_output(output: str) -> Dict[str, Any]:
    """
    Parse sqlmap output into structured data.

    Args:
        output: sqlmap stdout

    Returns:
        Structured dict with injection findings
    """
    results = {
        "vulnerable": False,
        "injection_type": None,
        "dbms": None,
        "databases": [],
        "tables": [],
        "data": [],
        "info": [],
    }

    lines = output.split("\n")

    for line in lines:
        line = line.strip()

        # Check for vulnerability confirmation
        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            results["vulnerable"] = True

        # Detect injection type
        type_match = re.search(r"Type:\s*(.+)", line)
        if type_match:
            results["injection_type"] = type_match.group(1).strip()

        # Detect DBMS
        dbms_match = re.search(r"back-end DBMS:\s*(.+)", line, re.IGNORECASE)
        if dbms_match:
            results["dbms"] = dbms_match.group(1).strip()

        # Detect databases
        if line.startswith("[*]") and "database" not in line.lower():
            # This might be a database/table name
            item = line.lstrip("[*]").strip()
            if item:
                results["databases"].append(item)

        # Collect important info lines
        if line.startswith("[INFO]") or line.startswith("[WARNING]"):
            results["info"].append(line)

    return results


def parse_hydra_output(output: str) -> Dict[str, Any]:
    """
    Parse hydra output into structured data.

    Args:
        output: hydra stdout

    Returns:
        Structured dict with found credentials
    """
    results = {
        "credentials": [],
        "attempts": 0,
        "service": None,
        "target": None,
    }

    for line in output.split("\n"):
        line = line.strip()

        # Match found credentials: [22][ssh] host: 10.0.0.1   login: admin   password: secret
        cred_match = re.search(
            r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
            line,
        )
        if cred_match:
            results["credentials"].append({
                "port": int(cred_match.group(1)),
                "service": cred_match.group(2),
                "host": cred_match.group(3),
                "username": cred_match.group(4),
                "password": cred_match.group(5),
            })
            if not results["service"]:
                results["service"] = cred_match.group(2)
            if not results["target"]:
                results["target"] = cred_match.group(3)
            continue

        # Match attempt count
        attempts_match = re.search(r"(\d+)\s+valid\s+password", line)
        if attempts_match:
            results["attempts"] = int(attempts_match.group(1))

    return results
