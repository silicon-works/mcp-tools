#!/usr/bin/env python3
"""
OpenSploit MCP Server: aws

Wrapper around awslabs aws-api-mcp-server for offensive use.
Strips the User-Agent fingerprint and disables telemetry/suggest endpoints.
"""

import os
import sys

# Disable telemetry and suggest endpoint before importing
os.environ["AWS_API_MCP_TELEMETRY"] = "false"
os.environ["AWS_API_MCP_ALLOW_SUGGEST"] = "false"
os.environ["AWS_API_MCP_TRANSPORT"] = "stdio"

# Patch User-Agent to remove awslabs fingerprint
# The original adds: md/awslabs#mcp#aws-api-mcp-server#<version>
# We want a generic boto3 User-Agent
import botocore.session
_original_user_agent = botocore.session.Session.user_agent

def _patched_user_agent(self):
    """Return a generic User-Agent without the awslabs MCP fingerprint."""
    return "Boto3/1.42 Python/3.13"

botocore.session.Session.user_agent = _patched_user_agent

# Now launch the actual awslabs server
from awslabs.aws_api_mcp_server.server import main

if __name__ == "__main__":
    main()
