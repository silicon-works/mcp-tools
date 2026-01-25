# Playwright MCP Server

Browser automation for web application testing using Microsoft's Playwright MCP.

## What This Does

Wraps the official `@playwright/mcp` npm package in a Docker container hosted on GHCR. This avoids the need to pull from Microsoft Container Registry (MCR), which can fail due to DNS/network issues.

## When to Use

- **Login forms** - Fill and submit authentication forms
- **JavaScript-rendered pages** - Pages that return empty when fetched with curl
- **Single Page Applications (SPAs)** - React, Vue, Angular apps
- **Complex web interactions** - Multi-step workflows, clicking, hovering
- **Visual confirmation** - Screenshots to verify page state

## When NOT to Use

- Simple API requests (use `curl`)
- File downloads (use `curl`)
- Directory fuzzing (use `ffuf`)

## Key Methods

| Method | Purpose |
|--------|---------|
| `browser_navigate` | Go to a URL |
| `browser_snapshot` | Get accessibility tree (call first to get element refs) |
| `browser_click` | Click an element |
| `browser_type` | Type text into an input |
| `browser_fill_form` | Fill multiple form fields at once |
| `browser_take_screenshot` | Capture visual screenshot |
| `browser_network_requests` | See XHR/fetch calls made by the page |
| `browser_console_messages` | See console.log output |
| `browser_evaluate` | Run arbitrary JavaScript |

## Typical Workflow

```
1. browser_navigate(url="http://target/login")
2. browser_snapshot()  # Get element refs
3. browser_fill_form(fields=[...])  # Fill login form
4. browser_click(ref="submit_button_ref")  # Submit
5. browser_snapshot()  # Check result
```

## Image

- **GHCR**: `ghcr.io/silicon-works/mcp-tools-playwright:latest`
- **Base**: `mcr.microsoft.com/playwright:v1.50.0-noble`
- **Size**: ~1.5GB (includes Chromium, Firefox, WebKit browsers)

## License

Apache-2.0 (Microsoft's @playwright/mcp license)
