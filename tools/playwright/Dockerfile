# OpenSploit MCP Server: playwright
# Browser automation for web application testing, form interaction, and JavaScript-rendered pages

FROM mcr.microsoft.com/playwright:v1.50.0-noble

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Playwright MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install the Playwright MCP server globally
RUN npm install -g @playwright/mcp@latest

# Install Chrome browser (the MCP server defaults to Chrome)
RUN npx playwright install chrome

# MCP servers communicate via stdio - run headless with no sandbox for container use
# --no-sandbox is required when running as root in Docker
# Proxy can be configured via PLAYWRIGHT_MCP_PROXY_SERVER env var (e.g., "http://zap:8080")
# --caps enables additional capabilities: testing (verify_*), tracing, pdf
CMD ["npx", "@playwright/mcp", "--headless", "--no-sandbox", "--caps=testing,tracing,pdf"]
