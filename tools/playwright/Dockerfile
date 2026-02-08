# OpenSploit MCP Server: playwright
# Browser automation for web application testing, form interaction, and JavaScript-rendered pages
# Includes VNC/noVNC for human CAPTCHA solving — user connects at http://localhost:6080/vnc.html

FROM node:22-bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Playwright MCP server for OpenSploit (with VNC)"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install the Playwright MCP server and its matching Chromium browser
# Running install from the MCP package dir ensures Chromium version matches playwright-core
RUN npm install -g @playwright/mcp@latest
RUN cd /usr/local/lib/node_modules/@playwright/mcp && npx playwright install --with-deps chromium

# Install VNC stack for human CAPTCHA solving
# Xvfb: virtual framebuffer (headless display server)
# x11vnc: VNC server that shares the Xvfb display
# noVNC + websockify: web-based VNC client accessible via browser
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb x11vnc novnc websockify procps socat && \
    rm -rf /var/lib/apt/lists/*

# Two config files — both use bundled Chromium with channel:"" (NOT Chrome channel, which breaks VPN)
# - headless (default): for normal browsing
# - headed: renders on Xvfb display :99 for VNC access
RUN echo '{"browser":{"browserName":"chromium","launchOptions":{"channel":"","headless":true,"chromiumSandbox":false}},"imageResponses":"allow"}' > /config.json
RUN echo '{"browser":{"browserName":"chromium","launchOptions":{"channel":"","headless":false,"chromiumSandbox":false,"args":["--window-size=1920,1080","--window-position=0,0"]}},"imageResponses":"allow"}' > /config-headed.json

# Entrypoint starts Xvfb + VNC + noVNC, then launches Playwright MCP via stdio
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 6080

ENTRYPOINT ["/entrypoint.sh"]
