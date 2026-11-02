# Web Search MCP

Independent MCP server. Install the published package, provision Chromium explicitly with `npm run install-browser` when using browser-backed engines, then run `openagent-web-search-mcp`. Package installation does not download browsers or start listeners.

Browser-backed search and page extraction share the same Chromium executable resolver: `OPENAGENT_CHROME_BINARY`, then `CHROME_PATH`, then a supported system Chrome/Chromium installation, then Playwright's managed Chromium. The pool defaults to Chromium. Use `BROWSER_TYPES=chromium` for an explicitly Chromium-only runtime; additional engines run only when configured and separately provisioned. Firefox/WebKit never receive the Chrome executable path. Installations do not download browsers automatically.

Page extraction only fetches `http` and `https` URLs whose host resolves exclusively to public unicast addresses. Loopback, private (RFC 1918), carrier-grade NAT/Tailscale (`100.64.0.0/10`), link-local and cloud-metadata (`169.254.0.0/16`), unique-local IPv6 and IPv4-embedding IPv6 forms of those ranges are refused with `BlockedUrlError`. Every redirect hop is validated before it is requested, in both the HTTP client and the browser fallback; the HTTP client's sockets connect only to the addresses that were checked, and it connects directly rather than through `HTTP(S)_PROXY`. A refused URL is never retried in the browser.

Browser extraction runs at most two isolated contexts concurrently per extractor.
Every request releases its context on success, refusal, navigation failure and
HTTP fallback failure. Concurrent requests share one in-flight launch per browser
type, and pool shutdown drains those launches before closing their browsers.
Batch extraction awaits each operation and its cleanup instead of reporting a
timeout while leaving browser work running in the background. HTTP and navigation
operations retain their own configured timeouts; this is not an eight-second
deadline for an entire batch. See [resource lifecycle](https://github.com/openagent-uno/openagent-tools/blob/main/docs/web-search-browser-resources.md).
