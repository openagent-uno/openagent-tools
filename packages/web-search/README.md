# Web Search MCP

Independent MCP server. Install the published package, provision Chromium explicitly with `npm run install-browser` when using browser-backed engines, then run `openagent-web-search-mcp`. Package installation does not download browsers or start listeners.

Browser-backed search and page extraction share the same Chromium executable resolver: `OPENAGENT_CHROME_BINARY`, then `CHROME_PATH`, then a supported system Chrome/Chromium installation, then Playwright's managed Chromium. The pool defaults to Chromium. Use `BROWSER_TYPES=chromium` for an explicitly Chromium-only runtime; additional engines run only when configured and separately provisioned. Firefox/WebKit never receive the Chrome executable path. Installations do not download browsers automatically.
