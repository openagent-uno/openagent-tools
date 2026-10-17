package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type keylessDoer struct {
	t          *testing.T
	requests   []*http.Request
	calls      []map[string]any
	quota      bool
	sse        bool
	result     string
	initResult string
}

func (d *keylessDoer) Do(request *http.Request) (*http.Response, error) {
	d.requests = append(d.requests, request)
	if request.Header.Get("Authorization") != "" || request.Header.Get("X-API-Key") != "" || request.Header.Get("Cookie") != "" {
		d.t.Fatal("keyless request carried credentials")
	}
	if request.URL.Host != "mcp.exa.ai" && request.URL.Host != "mcp.firecrawl.dev" {
		d.t.Fatal("unreviewed endpoint")
	}
	if request.URL.Host == "mcp.exa.ai" && request.URL.String() != "https://mcp.exa.ai/mcp?tools=web_search_exa,web_fetch_exa" {
		d.t.Fatal("Exa tool exposure widened")
	}
	if request.URL.Host == "mcp.firecrawl.dev" && request.URL.String() != "https://mcp.firecrawl.dev/v2/mcp" {
		d.t.Fatal("Firecrawl endpoint changed")
	}
	var payload map[string]any
	if json.NewDecoder(request.Body).Decode(&payload) != nil {
		d.t.Fatal("invalid request JSON")
	}
	d.calls = append(d.calls, payload)
	status := http.StatusOK
	body := ""
	header := http.Header{"Content-Type": []string{"application/json"}}
	if d.quota {
		status = http.StatusTooManyRequests
		body = `{"error":"daily keyless limit"}`
	} else {
		switch payload["method"] {
		case "initialize":
			if request.Header.Get("MCP-Session-Id") != "" {
				d.t.Fatal("session reused across invocations")
			}
			result := d.initResult
			if result == "" {
				result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}`
			}
			body = fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"result":%s}`, payload["id"], result)
			header.Set("MCP-Session-Id", "session-fixture")
		case "notifications/initialized":
			status = http.StatusAccepted
		case "tools/call":
			if request.Header.Get("MCP-Session-Id") != "session-fixture" {
				d.t.Fatal("initialized session not used")
			}
			result := d.result
			if result == "" {
				result = `{"content":[{"type":"text","text":"public fixture"}]}`
			}
			body = fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"result":%s}`, payload["id"], result)
		default:
			d.t.Fatal("unexpected RPC method")
		}
	}
	if d.sse && body != "" && !d.quota {
		header.Set("Content-Type", "text/event-stream")
		body = "event: message\ndata: " + body + "\n\n"
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func keylessInvocation(t *testing.T, adapter *KeylessMCPAdapter, index int, args string) domain.Invocation {
	t.Helper()
	credential, err := domain.NewCredential(domain.CredentialNone, "", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return domain.Invocation{ID: "invocation-one", Principal: domain.Principal{WorkspaceID: "workspace-one", ActorID: "owner"},
		Connection: domain.Connection{ID: "connection-one", WorkspaceID: "workspace-one", Provider: adapter.Provider(), Capability: domain.Files, Enabled: true, Config: json.RawMessage(`{}`)},
		Credential: credential, Operation: adapter.Operations()[index], Arguments: json.RawMessage(args)}
}

func TestKeylessMCPCompiledToolsAndJSONSSE(t *testing.T) {
	for _, test := range []struct {
		provider     string
		index        int
		args, remote string
	}{
		{"exa", 0, `{"query":"public research","numResults":2,"connection_id":"connection-one","provider":"exa"}`, "web_search_exa"},
		{"exa", 1, `{"urls":["https://example.com/page"],"maxCharacters":3000}`, "web_fetch_exa"},
		{"firecrawl", 0, `{"query":"public research","limit":2}`, "firecrawl_search"},
		{"firecrawl", 1, `{"url":"https://example.com/page","onlyMainContent":true}`, "firecrawl_scrape"},
	} {
		t.Run(test.remote, func(t *testing.T) {
			doer := &keylessDoer{t: t, sse: test.provider == "firecrawl"}
			adapter, err := NewKeylessMCPAdapter(test.provider, doer)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range adapter.Operations() {
				if op.Validate() != nil || op.Risk != domain.RiskRead || op.Retry.MaxAttempts != 1 {
					t.Fatal("invalid compiled read tool")
				}
			}
			inv := keylessInvocation(t, adapter, test.index, test.args)
			result, err := adapter.Invoke(context.Background(), inv)
			if err != nil || result.Attempts != 1 || len(doer.requests) != 3 {
				t.Fatalf("invoke: %v requests=%d", err, len(doer.requests))
			}
			params := doer.calls[2]["params"].(map[string]any)
			args := params["arguments"].(map[string]any)
			if params["name"] != test.remote || args["connection_id"] != nil || args["provider"] != nil {
				t.Fatal("mapping or bound metadata escaped")
			}
			if test.remote == "firecrawl_scrape" {
				formats := args["formats"].([]any)
				if len(formats) != 1 || formats[0] != "markdown" {
					t.Fatal("scrape escaped Markdown profile")
				}
			}
			inv.ID = "invocation-two"
			inv.Connection.ID = "connection-two"
			inv.Arguments = json.RawMessage(strings.ReplaceAll(test.args, "connection-one", "connection-two"))
			if _, err := adapter.Invoke(context.Background(), inv); err != nil || len(doer.requests) != 6 {
				t.Fatalf("isolated second connection: %v", err)
			}
		})
	}
}

func TestKeylessMCPRejectsCredentialAndConnectionEscapesBeforeIO(t *testing.T) {
	for _, mutate := range []func(*domain.Invocation){
		func(inv *domain.Invocation) { inv.Credential = domain.Credential{} },
		func(inv *domain.Invocation) {
			inv.Credential, _ = domain.NewCredential(domain.CredentialAPIToken, "token", "", "", "", nil)
		},
		func(inv *domain.Invocation) { inv.Connection.WorkspaceID = "other-workspace" },
		func(inv *domain.Invocation) { inv.Connection.Provider = "firecrawl" },
		func(inv *domain.Invocation) { inv.Connection.Enabled = false },
		func(inv *domain.Invocation) { inv.Operation.Name = "files.exa.agent_run" },
		func(inv *domain.Invocation) { inv.Operation.Risk = domain.RiskSpend },
		func(inv *domain.Invocation) {
			inv.Connection.Config = json.RawMessage(`{"endpoint":"https://evil.example"}`)
		},
		func(inv *domain.Invocation) { inv.Arguments = json.RawMessage(`{"query":"x","connection_id":"other"}`) },
		func(inv *domain.Invocation) { inv.Arguments = json.RawMessage(`{"query":"x","provider":"firecrawl"}`) },
		func(inv *domain.Invocation) {
			inv.Arguments = json.RawMessage(`{"query":"x","headers":{"Authorization":"token"}}`)
		},
		func(inv *domain.Invocation) { inv.Arguments = json.RawMessage(`{"query":"x","numResults":11}`) },
		func(inv *domain.Invocation) { inv.Arguments = json.RawMessage(`{"query":"x","numResults":1.5}`) },
		func(inv *domain.Invocation) { inv.Arguments = json.RawMessage(`{"query":" "}`) },
	} {
		doer := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("exa", doer)
		inv := keylessInvocation(t, adapter, 0, `{"query":"fixture"}`)
		mutate(&inv)
		if _, err := adapter.Invoke(context.Background(), inv); err == nil || len(doer.requests) != 0 {
			t.Fatal("invalid invocation reached provider")
		}
	}
	for _, raw := range []string{"http://localhost/", "https://127.0.0.1/", "https://[::1]/", "file:///etc/passwd", "https://a.local/", "https://user:secret@example.com/", "https://example.com:9000/"} {
		doer := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("firecrawl", doer)
		inv := keylessInvocation(t, adapter, 1, fmt.Sprintf(`{"url":%q}`, raw))
		if _, err := adapter.Invoke(context.Background(), inv); err == nil || len(doer.requests) != 0 {
			t.Fatal("non-public URL reached provider")
		}
	}
}

func TestKeylessMCPErrorsAreBoundedAndNeverRetried(t *testing.T) {
	for _, test := range []struct {
		name         string
		quota        bool
		result, init string
		requests     int
	}{
		{"quota", true, "", "", 1},
		{"operation-error", false, `{"isError":true,"content":[{"type":"text","text":"limit"}]}`, "", 3},
		{"structured-error", false, `{"structuredContent":{"error":"limit"}}`, "", 3},
		{"protocol", false, "", `{"protocolVersion":"future"}`, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			doer := &keylessDoer{t: t, quota: test.quota, result: test.result, initResult: test.init}
			adapter, _ := NewKeylessMCPAdapter("exa", doer)
			_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"query":"fixture"}`))
			var providerError *domain.ProviderError
			if !errors.As(err, &providerError) || providerError.Attempts != 1 || len(doer.requests) != test.requests {
				t.Fatalf("error/retry contract: %v", err)
			}
			if test.quota && providerError.StatusCode != 429 {
				t.Fatal("quota status lost")
			}
		})
	}
	if _, err := keylessMCPResult(json.RawMessage(`{"jsonrpc":"2.0","id":"i","result":{},"error":{"code":-1}}`), "i"); err == nil {
		t.Fatal("envelope result+error accepted")
	}
	if _, err := NewKeylessMCPAdapter("custom", &keylessDoer{t: t}); err == nil {
		t.Fatal("arbitrary provider accepted")
	}
}

type keylessResponseDoer func(*http.Request) (*http.Response, error)

func (f keylessResponseDoer) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestKeylessMCPTransportFencesDoNotLeakProviderPayloads(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*http.Response)
	}{
		{"redirect-status", func(r *http.Response) { r.StatusCode = 307; r.Header.Set("Location", "https://unreviewed.example/mcp") }},
		{"redirect-followed-by-host-doer", func(r *http.Response) {
			r.Request, _ = http.NewRequest(http.MethodPost, "https://unreviewed.example/mcp", nil)
		}},
		{"oversized-response", func(r *http.Response) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", keylessMCPMaxResponse+1)))
		}},
		{"unsafe-session", func(r *http.Response) { r.Header.Set("MCP-Session-Id", "session\r\nAuthorization: bad") }},
		{"oversized-session", func(r *http.Response) { r.Header.Set("MCP-Session-Id", strings.Repeat("x", 257)) }},
		{"malformed-sse", func(r *http.Response) {
			r.Header.Set("Content-Type", "text/event-stream")
			r.Body = io.NopCloser(strings.NewReader("data: private-provider-payload\n\n"))
		}},
		{"missing-body", func(r *http.Response) { r.Body = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			doer := keylessResponseDoer(func(request *http.Request) (*http.Response, error) {
				calls++
				response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Request: request, Body: io.NopCloser(strings.NewReader("private-provider-payload"))}
				test.mutate(response)
				return response, nil
			})
			adapter, _ := NewKeylessMCPAdapter("exa", doer)
			_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"query":"private-input-query"}`))
			if err == nil || calls != 1 || strings.Contains(err.Error(), "private-provider-payload") || strings.Contains(err.Error(), "private-input-query") {
				t.Fatalf("transport failure retried or leaked: %v calls=%d", err, calls)
			}
		})
	}
}
