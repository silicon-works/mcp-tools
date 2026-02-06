# OpenSploit MCP Server: playwright
# Browser automation for web application testing, form interaction, and JavaScript-rendered pages

FROM node:22-bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Playwright MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install the Playwright MCP server and its matching Chromium browser
# Running install from the MCP package dir ensures Chromium version matches playwright-core
RUN npm install -g @playwright/mcp@latest
RUN cd /usr/local/lib/node_modules/@playwright/mcp && npx playwright install --with-deps chromium

# Configure MCP server to use bundled Chromium (not Chrome channel, which has VPN routing bugs)
# defaultConfig hardcodes channel:"chrome" — override with "" to use bundled Chromium
RUN echo '{"browser":{"browserName":"chromium","launchOptions":{"channel":"","headless":true,"chromiumSandbox":false}}}' > /config.json

# MCP servers communicate via stdio
# --caps enables additional capabilities: testing (verify_*), tracing, pdf
CMD ["npx", "@playwright/mcp", "--config", "/config.json", "--caps=testing,tracing,pdf"]
