#!/usr/bin/env python3
"""
OpenSploit MCP Server: git-dumper

Extract git repositories from exposed .git directories on web servers.
Reconstructs full repos with commit history from accessible .git objects.
"""

import asyncio
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class GitDumperServer(BaseMCPServer):
    """MCP server wrapping git-dumper for exposed .git directory extraction."""

    def __init__(self):
        super().__init__(
            name="git-dumper",
            description="Extract git repositories from exposed .git directories on web servers",
            version="1.0.0",
        )

        self.register_method(
            name="dump",
            description="Dump an exposed .git directory from a URL and reconstruct the full repository",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Base URL of the website with exposed .git (e.g., 'http://10.10.10.5/' or 'http://target.htb/.git/')",
                },
                "jobs": {
                    "type": "integer",
                    "default": 10,
                    "description": "Number of simultaneous download requests",
                },
                "retry": {
                    "type": "integer",
                    "default": 3,
                    "description": "Number of retry attempts per request",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Timeout per request in seconds",
                },
                "user_agent": {
                    "type": "string",
                    "description": "Custom User-Agent header",
                },
                "headers": {
                    "type": "array",
                    "description": "Additional HTTP headers as 'NAME=VALUE' strings",
                },
                "proxy": {
                    "type": "string",
                    "description": "HTTP proxy to use (e.g., 'http://127.0.0.1:8080')",
                },
            },
            handler=self.dump,
        )

        self.register_method(
            name="analyze",
            description="Analyze a previously dumped git repository — show log, branches, interesting files, and secrets in history",
            params={
                "repo_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to the dumped repository (returned by dump method)",
                },
                "log_count": {
                    "type": "integer",
                    "default": 20,
                    "description": "Number of recent commits to show",
                },
                "show_diff": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include diffs in commit log (shows what changed in each commit)",
                },
                "grep_secrets": {
                    "type": "boolean",
                    "default": True,
                    "description": "Search commit history for potential secrets (passwords, keys, tokens)",
                },
            },
            handler=self.analyze,
        )

    async def dump(
        self,
        url: str,
        jobs: int = 10,
        retry: int = 3,
        timeout: int = 30,
        user_agent: str = None,
        headers: list = None,
        proxy: str = None,
    ) -> ToolResult:
        """Dump an exposed .git directory from a URL."""
        # Normalize URL
        url = url.rstrip("/")
        if url.endswith("/.git"):
            url = url[:-5]

        self.logger.info(f"git-dumper: dumping {url}")

        # Create output directory under /session/ for persistence
        output_dir = f"/session/git-dump-{url.split('/')[-1].replace('.', '_').replace(':', '_')}"
        os.makedirs(output_dir, exist_ok=True)

        cmd = ["git-dumper"]

        if jobs:
            cmd.extend(["-j", str(jobs)])
        if retry:
            cmd.extend(["-r", str(retry)])
        if timeout:
            cmd.extend(["-t", str(timeout)])
        if user_agent:
            cmd.extend(["-u", user_agent])
        if headers:
            for h in headers:
                cmd.extend(["-H", h])
        if proxy:
            cmd.extend(["--proxy", proxy])

        cmd.append(url)
        cmd.append(output_dir)

        try:
            result = await self.run_command(cmd, timeout=timeout * 10 + 60)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            # Check if the dump succeeded by looking for .git directory
            git_dir = os.path.join(output_dir, ".git")
            if not os.path.isdir(git_dir):
                return ToolResult(
                    success=False,
                    data={"url": url},
                    error=f"No .git directory found — target may not have an exposed .git or URL is incorrect",
                    raw_output=combined,
                )

            # Get basic repo info
            file_count = 0
            files = []
            for root, dirs, filenames in os.walk(output_dir):
                # Skip .git directory itself
                dirs[:] = [d for d in dirs if d != ".git"]
                for f in filenames:
                    rel = os.path.relpath(os.path.join(root, f), output_dir)
                    files.append(rel)
                    file_count += 1

            # Get branch info
            branch_result = await self.run_command(
                ["git", "-C", output_dir, "branch", "-a"],
                timeout=10,
            )
            branches = [
                b.strip().lstrip("* ")
                for b in (branch_result.stdout or "").split("\n")
                if b.strip()
            ]

            # Get commit count
            log_result = await self.run_command(
                ["git", "-C", output_dir, "log", "--oneline"],
                timeout=10,
            )
            commit_count = len([
                l for l in (log_result.stdout or "").split("\n") if l.strip()
            ])

            # Auto-analyze: get commit log with diffs
            log_cmd = ["git", "-C", output_dir, "log", "-20", "--format=%H|%an|%ae|%s|%ci", "-p"]
            log_detail = await self.run_command(log_cmd, timeout=30)
            commit_log = sanitize_output(log_detail.stdout or "", max_length=20000)

            # Search for secrets in current files
            secret_patterns = "password|passwd|secret|token|api_key|apikey|access_key|private_key|AWS_SECRET|BEGIN RSA|BEGIN PRIVATE"
            grep_cmd = ["git", "-C", output_dir, "grep", "-i", "-n", "-E", secret_patterns]
            grep_result = await self.run_command(grep_cmd, timeout=15)
            secrets_in_files = [
                l.strip() for l in (grep_result.stdout or "").split("\n")
                if l.strip()
            ]

            # List interesting files
            interesting_files = []
            interesting_pats = [
                r"\.env$", r"\.config$", r"config\.", r"settings\.",
                r"\.key$", r"\.pem$", r"id_rsa", r"\.htpasswd",
                r"wp-config", r"database\.", r"credentials", r"secret",
            ]
            for f in files:
                for pat in interesting_pats:
                    if re.search(pat, f, re.IGNORECASE):
                        interesting_files.append(f)
                        break

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "repo_path": output_dir,
                    "files": files[:100],
                    "file_count": file_count,
                    "branches": branches,
                    "commit_count": commit_count,
                    "commit_log": commit_log,
                    "secrets_in_files": secrets_in_files[:50],
                    "secrets_count": len(secrets_in_files),
                    "interesting_files": interesting_files,
                },
                raw_output=sanitize_output(combined, max_length=5000),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"git-dumper failed: {e}",
            )

    async def analyze(
        self,
        repo_path: str,
        log_count: int = 20,
        show_diff: bool = True,
        grep_secrets: bool = True,
    ) -> ToolResult:
        """Analyze a dumped git repository."""
        self.logger.info(f"Analyzing repo at {repo_path}")

        if not os.path.isdir(os.path.join(repo_path, ".git")):
            return ToolResult(
                success=False,
                data={},
                error=f"No .git directory found at {repo_path} — run dump first",
            )

        analysis = {}

        # Git log with optional diffs
        log_cmd = ["git", "-C", repo_path, "log", f"-{log_count}", "--format=%H|%an|%ae|%s|%ci"]
        if show_diff:
            log_cmd.append("-p")

        log_result = await self.run_command(log_cmd, timeout=30)
        log_output = log_result.stdout or ""

        # Parse structured commits
        commits = []
        if not show_diff:
            for line in log_output.split("\n"):
                parts = line.strip().split("|", 4)
                if len(parts) == 5:
                    commits.append({
                        "hash": parts[0][:8],
                        "author": parts[1],
                        "email": parts[2],
                        "message": parts[3],
                        "date": parts[4],
                    })
        analysis["log"] = sanitize_output(log_output, max_length=20000)
        if commits:
            analysis["commits"] = commits

        # Search for secrets in all commits
        if grep_secrets:
            secret_patterns = [
                "password", "passwd", "pwd", "secret", "token",
                "api_key", "apikey", "api-key", "access_key",
                "private_key", "AWS_SECRET", "AWS_ACCESS",
                "BEGIN RSA", "BEGIN PRIVATE", "BEGIN OPENSSH",
                "jdbc:", "mysql://", "postgres://", "mongodb://",
            ]
            pattern = "|".join(secret_patterns)

            grep_result = await self.run_command(
                ["git", "-C", repo_path, "log", "-p", "--all", "-S", "password",
                 "--format=%H %s"],
                timeout=30,
            )
            grep_output = grep_result.stdout or ""

            # Also search with git grep across all commits
            grep2_result = await self.run_command(
                ["git", "-C", repo_path, "grep", "-i", "-n", "-E",
                 pattern, "--", "*.py", "*.php", "*.js", "*.conf",
                 "*.env", "*.yml", "*.yaml", "*.json", "*.xml",
                 "*.ini", "*.cfg", "*.txt", "*.config"],
                timeout=15,
            )
            grep2_output = grep2_result.stdout or ""

            secrets_found = []
            for line in grep2_output.split("\n"):
                line = line.strip()
                if line:
                    secrets_found.append(line)

            analysis["secrets_in_history"] = sanitize_output(grep_output, max_length=5000)
            analysis["secrets_in_files"] = secrets_found[:50]
            analysis["secrets_count"] = len(secrets_found)

        # List interesting files
        interesting_patterns = [
            r"\.env$", r"\.config$", r"config\.", r"settings\.",
            r"\.key$", r"\.pem$", r"id_rsa", r"\.htpasswd",
            r"wp-config", r"database\.", r"credentials",
            r"secret", r"password", r"\.sql$",
        ]
        interesting_files = []
        for root, dirs, filenames in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d != ".git"]
            for f in filenames:
                rel = os.path.relpath(os.path.join(root, f), repo_path)
                for pat in interesting_patterns:
                    if re.search(pat, rel, re.IGNORECASE):
                        interesting_files.append(rel)
                        break

        analysis["interesting_files"] = interesting_files

        return ToolResult(
            success=True,
            data=analysis,
            raw_output=analysis.get("log", ""),
        )


if __name__ == "__main__":
    GitDumperServer.main()
