package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// This fixture mirrors Replio Platform backend/org_mcp_server.py:mcp_context.
// It deliberately contains only synthetic identifiers, never a real API key.
func testReplioContext() map[string]any {
	return map[string]any{
		"organization_id": testReplioOrganization, "api_key_id": "test-key-id", "api_key_name": "test organization key",
		"scopes": []string{"mcp:read"}, "app_ids": []string{}, "channel_ids": []string{},
	}
}

func testReplioContextResponse(t *testing.T, scope map[string]any, textOnly, eventStream bool) *http.Response {
	t.Helper()
	result := map[string]any{"structuredContent": scope, "isError": false}
	if textOnly {
		encoded, _ := json.Marshal(scope)
		delete(result, "structuredContent")
		result["content"] = []map[string]string{{"type": "text", "text": string(encoded)}}
	}
	encoded, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": replioContextID, "result": result})
	if err != nil {
		t.Fatal(err)
	}
	if eventStream {
		return jsonResponse(http.StatusOK, "event: message\ndata: "+string(encoded)+"\n\n", map[string]string{"Content-Type": "text/event-stream"})
	}
	return jsonResponse(http.StatusOK, string(encoded), nil)
}

func assertReplioContextRequest(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.String() != replioContextURL || request.Header.Get("Authorization") != "Bearer rpl_"+strings.Repeat("a", 48) {
		t.Fatal("preflight did not use the fixed Replio endpoint and same ephemeral organization key")
	}
	if request.Header.Get("Cookie") != "" || request.Header.Get("MCP-Session-Id") != "" || request.Header.Get("X-Replio-Organization-Id") != "" || request.Header.Get("X-OpenAgent-Workspace-ID") != "" {
		t.Fatal("preflight received ambient identity, session, or untrusted org headers")
	}
	if request.Header.Get("Accept") != "application/json, text/event-stream" || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("MCP-Protocol-Version") != "2025-03-26" {
		t.Fatal("preflight did not negotiate stateless MCP JSON/SSE")
	}
	deadline, hasDeadline := request.Context().Deadline()
	if !hasDeadline || time.Until(deadline) > 10*time.Second {
		t.Fatal("preflight has no bounded deadline")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != replioContextRequest {
		t.Fatal("preflight body was not the fixed read-only mcp_context call")
	}
}

func TestReplioContextAllowsOnlyVerifiedBroadOrganizationKeys(t *testing.T) {
	t.Parallel()
	for _, textOnly := range []bool{false, true} {
		for _, eventStream := range []bool{false, true} {
			for _, scopes := range [][]string{{}, {"*"}, {"mcp:read"}, {"mcp:read", "mcp:write"}} {
				contextCalls, restCalls := 0, 0
				manifest := replioManifest()
				adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == "/mcp/" {
						contextCalls++
						assertReplioContextRequest(t, request)
						scope := testReplioContext()
						scope["scopes"] = scopes
						return testReplioContextResponse(t, scope, textOnly, eventStream), nil
					}
					restCalls++
					if contextCalls != restCalls {
						t.Fatal("Replio REST ran without a fresh context check")
					}
					return jsonResponse(http.StatusOK, `{"apps":[]}`, nil), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				invocation := platformInvocation(t, adapter, manifest, "outreach.replio.apps.list", `{}`)
				for repeat := 0; repeat < 2; repeat++ {
					result, err := adapter.Invoke(context.Background(), invocation)
					if err != nil {
						t.Fatalf("valid stateless MCP context rejected: %v", err)
					}
					if result.RequestBytes != int64(len(replioContextRequest)) || result.ResponseBytes <= int64(len(`{"apps":[]}`)) {
						t.Fatal("result did not account for scope preflight traffic")
					}
				}
				if contextCalls != 2 || restCalls != 2 {
					t.Fatal("scope context was cached or REST was not executed")
				}
			}
		}
	}
}

func TestReplioContextRejectsRestrictedMissingOrMismatchedScopesBeforeREST(t *testing.T) {
	t.Parallel()
	tests := map[string]func(map[string]any){
		"wrong organization":        func(scope map[string]any) { scope["organization_id"] = testReplioThread },
		"missing organization":      func(scope map[string]any) { delete(scope, "organization_id") },
		"restricted app":            func(scope map[string]any) { scope["app_ids"] = []string{testReplioThread} },
		"restricted channel":        func(scope map[string]any) { scope["channel_ids"] = []string{testReplioThread} },
		"scope app restriction":     func(scope map[string]any) { scope["scopes"] = []string{"mcp:read", "app:" + testReplioThread} },
		"scope channel restriction": func(scope map[string]any) { scope["scopes"] = []string{"*", "channel:" + testReplioThread} },
		"malformed restriction":     func(scope map[string]any) { scope["scopes"] = []string{"mcp:read", "app:invalid"} },
		"unknown scope":             func(scope map[string]any) { scope["scopes"] = []string{"mcp:read", "future:limited"} },
		"missing apps":              func(scope map[string]any) { delete(scope, "app_ids") },
		"null apps":                 func(scope map[string]any) { scope["app_ids"] = nil },
		"missing channels":          func(scope map[string]any) { delete(scope, "channel_ids") },
		"null channels":             func(scope map[string]any) { scope["channel_ids"] = nil },
		"missing scopes":            func(scope map[string]any) { delete(scope, "scopes") },
		"null scopes":               func(scope map[string]any) { scope["scopes"] = nil },
		"scope string":              func(scope map[string]any) { scope["scopes"] = "mcp:read" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := replioManifest()
			calls := 0
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				assertReplioContextRequest(t, request)
				scope := testReplioContext()
				mutate(scope)
				return testReplioContextResponse(t, scope, false, false), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			invocation := platformInvocation(t, adapter, manifest, "outreach.replio.apps.list", `{}`)
			if _, err := adapter.Invoke(context.Background(), invocation); !errors.Is(err, domain.ErrProviderPermission) || calls != 1 {
				t.Fatalf("restricted scope reached REST: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestReplioContextFailsClosedOnProtocolTransportAndSizeErrors(t *testing.T) {
	t.Parallel()
	secret := "rpl_" + strings.Repeat("a", 48)
	good, _ := io.ReadAll(testReplioContextResponse(t, testReplioContext(), false, false).Body)
	tests := []struct {
		name   string
		status int
		body   string
		err    error
	}{
		{"http error with key echo", 403, secret, nil},
		{"network error with key echo", 0, "", errors.New(secret)},
		{"invalid JSON", 200, secret, nil},
		{"oversized body", 200, strings.Repeat("a", replioContextMaxBytes+1), nil},
		{"wrong RPC id", 200, strings.Replace(string(good), replioContextID, "unrelated", 1), nil},
		{"wrong RPC version", 200, strings.Replace(string(good), `"2.0"`, `"1.0"`, 1), nil},
		{"tool error", 200, strings.Replace(string(good), `"isError":false`, `"isError":true`, 1), nil},
		{"RPC error with result", 200, `{"error":{"message":"` + secret + `"},` + string(good)[1:], nil},
		{"empty envelope", 200, `{}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			manifest := replioManifest()
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				assertReplioContextRequest(t, request)
				if tt.err != nil {
					return nil, tt.err
				}
				return jsonResponse(tt.status, tt.body, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			invocation := platformInvocation(t, adapter, manifest, "outreach.replio.apps.list", `{}`)
			result, err := adapter.Invoke(context.Background(), invocation)
			if !errors.Is(err, domain.ErrProviderPermission) || calls != 1 || strings.Contains(err.Error(), secret) || result.Data != nil {
				t.Fatalf("preflight failure leaked details or reached REST: calls=%d err=%v", calls, err)
			}
			var providerErr *domain.ProviderError
			if !errors.As(err, &providerErr) || providerErr.RequestBytes != int64(len(replioContextRequest)) || providerErr.ResponseBytes > replioContextMaxBytes+1 {
				t.Fatal("failed scope check did not preserve bounded traffic accounting")
			}
		})
	}
}

func TestReplioContextUsesInvocationCancellationAndChecksEveryRetry(t *testing.T) {
	t.Parallel()
	manifest := replioManifest()
	contextCalls, restCalls := 0, 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/mcp/" {
			contextCalls++
			if request.Context().Err() != nil {
				return nil, request.Context().Err()
			}
			scope := testReplioContext()
			if contextCalls > 1 {
				scope["app_ids"] = []string{testReplioThread}
			}
			return testReplioContextResponse(t, scope, false, false), nil
		}
		restCalls++
		return jsonResponse(http.StatusServiceUnavailable, `{}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error { return nil }
	invocation := platformInvocation(t, adapter, manifest, "outreach.replio.apps.list", `{}`)
	if _, err := adapter.Invoke(context.Background(), invocation); !errors.Is(err, domain.ErrProviderPermission) || contextCalls != 2 || restCalls != 1 {
		t.Fatalf("retry skipped renewed scope validation: context=%d REST=%d err=%v", contextCalls, restCalls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.Invoke(ctx, invocation); !errors.Is(err, domain.ErrProviderPermission) || restCalls != 1 {
		t.Fatal("cancelled invocation escaped through preflight")
	}
}
