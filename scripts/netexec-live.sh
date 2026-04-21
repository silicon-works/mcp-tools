#!/bin/bash
# Live testing helper for netexec MCP server
# Handles volume mounts and hostname resolution for Kerberos
#
# Usage: ./netexec-live.sh <method> '<json_args>'
# Example: ./netexec-live.sh smb '{"target":"10.129.242.196","username":"natalie.a","kerberos":true,"ccache_path":"/session/credentials/natalie.a.ccache","kdc_host":"dc.hercules.htb","domain":"hercules.htb"}'

SESSION_DIR="${SESSION_DIR:-$HOME/netexec-live-session}"
METHOD="$1"
ARGS="$2"

if [ -z "$METHOD" ] || [ -z "$ARGS" ]; then
    echo "Usage: $0 <method> '<json_args>'"
    exit 1
fi

mkdir -p "$SESSION_DIR/credentials"

python3 - <<PYEOF
import json, asyncio, sys, os

SESSION_DIR = "$SESSION_DIR"
METHOD = "$METHOD"
ARGS = json.loads(r'''$ARGS''')

async def call():
    # Extract kdc_host to use as --add-host if target is IP
    kdc_host = ARGS.get('kdc_host')
    target = ARGS.get('target', '')

    docker_args = [
        'docker', 'run', '-i', '--rm', '--network=host',
        '-v', f'{SESSION_DIR}:/session',
    ]
    # Add hostname mapping if kdc_host specified and target is IP
    if kdc_host and target and all(c.isdigit() or c == '.' for c in target):
        docker_args.extend(['--add-host', f'{kdc_host}:{target}'])
    # For SMB SPN resolution, also add the simple hostname if kdc_host is FQDN
    if kdc_host and '.' in kdc_host:
        short = kdc_host.split('.')[0]
        if short != kdc_host:
            docker_args.extend(['--add-host', f'{short}:{target}'])
    # KRB5CCNAME for kerberos auth
    ccache = ARGS.get('ccache_path')
    if ccache:
        docker_args.extend(['-e', f'KRB5CCNAME={ccache}'])
    docker_args.append('mcp-test-netexec')

    proc = await asyncio.create_subprocess_exec(
        *docker_args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=10 * 1024 * 1024,  # 10 MB — some error responses include big tracebacks
    )

    async def send(m):
        proc.stdin.write((json.dumps(m) + '\n').encode())
        await proc.stdin.drain()

    async def recv():
        while True:
            line = await proc.stdout.readline()
            if not line:
                return None
            try:
                return json.loads(line)
            except:
                continue

    await send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'t','version':'1'}}})
    await recv()
    await send({'jsonrpc':'2.0','method':'notifications/initialized'})
    await send({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':METHOD,'arguments':ARGS}})
    r = await recv()
    sc = r.get('result',{}).get('structuredContent',{})
    print(json.dumps(sc, indent=2))
    proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        proc.kill()

asyncio.run(call())
PYEOF
