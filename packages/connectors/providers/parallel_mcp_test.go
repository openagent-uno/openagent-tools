package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// Contract examples exercise the frozen advertised schema, not captured tool
// responses. Only metadata was acquired from the live service before this edit.
func parallelOutput(remote string) map[string]any {
	payload := map[string]any{"session_id": "fixture-session", "results": []any{
		map[string]any{"url": "https://example.com/page", "excerpts": []any{"Public documentation excerpt."}},
	}}
	if remote == "web_fetch" {
		payload["extract_id"] = "extract-fixture"
		payload["errors"] = []any{}
	} else {
		payload["search_id"] = "search-fixture"
	}
	return payload
}

func parallelResultJSON(t *testing.T, payload map[string]any, text bool) string {
	t.Helper()
	var envelope map[string]any
	if text {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		envelope = map[string]any{"content": []any{map[string]any{"type": "text", "text": string(body)}}}
	} else {
		envelope = map[string]any{"structuredContent": payload}
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestParallelCompiledReadMappingAndConnectionIsolation(t *testing.T) {
	for _, text := range []bool{false, true} {
		for index, remote := range []string{"web_search", "web_fetch"} {
			t.Run(fmt.Sprintf("%s/text=%v", remote, text), func(t *testing.T) {
				doer := &keylessDoer{t: t, sse: text, result: parallelResultJSON(t, parallelOutput(remote), text)}
				adapter, err := NewKeylessMCPAdapter("parallel_search", doer)
				if err != nil {
					t.Fatal(err)
				}
				args := `{"objective":"Find public docs","search_queries":["official documentation"],"connection_id":"connection-one","provider":"parallel_search"}`
				if index == 1 {
					args = `{"urls":["https://example.com/page"],"objective":"Read public docs","search_queries":["official documentation"]}`
				}
				inv := keylessInvocation(t, adapter, index, args)
				inv.Principal.SessionID = "trusted-session-not-forwarded"
				for i := 0; i < 2; i++ {
					result, err := adapter.Invoke(context.Background(), inv)
					if err != nil || result.Attempts != 1 || result.ProviderStatus != 200 || len(doer.requests) != 3*(i+1) {
						t.Fatalf("compiled invocation: %v", err)
					}
					params := doer.calls[3*i+2]["params"].(map[string]any)
					forwarded := params["arguments"].(map[string]any)
					if params["name"] != remote || forwarded["connection_id"] != nil || forwarded["provider"] != nil ||
						forwarded["session_id"] != nil || forwarded["model_name"] != nil {
						t.Fatal("remote tool or connection metadata escaped")
					}
					if index == 1 && (forwarded["full_content"] != false || forwarded["allow_live_fetch"] != true) {
						t.Fatal("fetch profile is not fixed")
					}
					inv.ID = "invocation-two"
					inv.Connection.ID = "connection-two"
					inv.Arguments = json.RawMessage(strings.ReplaceAll(args, "connection-one", "connection-two"))
				}
				for _, operation := range adapter.Operations() {
					if operation.Validate() != nil || operation.Risk != domain.RiskRead || operation.Retry.MaxAttempts != 1 {
						t.Fatal("Parallel operation is not a valid one-attempt typed read")
					}
					var schema struct {
						Properties           map[string]any `json:"properties"`
						AdditionalProperties bool           `json:"additionalProperties"`
					}
					if json.Unmarshal(operation.InputSchema, &schema) != nil || schema.AdditionalProperties ||
						schema.Properties["session_id"] != nil || schema.Properties["model_name"] != nil ||
						schema.Properties["full_content"] != nil || schema.Properties["allow_live_fetch"] != nil {
						t.Fatal("schema exposes a host-controlled profile or identity")
					}
				}
			})
		}
	}
}

func TestParallelRejectsEscapesAndBoundsBeforeIO(t *testing.T) {
	validSearch := `{"objective":"Find documentation","search_queries":["public docs"]}`
	for _, mutate := range []func(*domain.Invocation){
		func(i *domain.Invocation) { i.Credential = domain.Credential{} },
		func(i *domain.Invocation) {
			i.Credential, _ = domain.NewCredential(domain.CredentialAPIToken, "secret", "", "", "", nil)
		},
		func(i *domain.Invocation) {
			i.Credential, _ = domain.NewCredential(domain.CredentialOAuth2Bearer, "secret", "Authorization", "Bearer", "", nil)
		},
		func(i *domain.Invocation) { i.Connection.WorkspaceID = "another-workspace" },
		func(i *domain.Invocation) { i.Connection.Provider = "exa" },
		func(i *domain.Invocation) { i.Connection.Enabled = false },
		func(i *domain.Invocation) { i.Operation.Name = "files.parallel.raw" },
		func(i *domain.Invocation) { i.Operation.Risk = domain.RiskWrite },
		func(i *domain.Invocation) {
			i.Connection.Config = json.RawMessage(`{"endpoint":"https://example.com/mcp"}`)
		},
		func(i *domain.Invocation) { i.Connection.Config = json.RawMessage(`{"session_id":"chosen"}`) },
	} {
		doer := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("parallel_search", doer)
		inv := keylessInvocation(t, adapter, 0, validSearch)
		mutate(&inv)
		if _, err := adapter.Invoke(context.Background(), inv); err == nil || len(doer.requests) != 0 {
			t.Fatal("identity or endpoint escape reached provider")
		}
	}
	for _, raw := range []string{
		`{}`, `{"objective":"x"}`, `{"objective":"x","search_queries":[]}`,
		`{"objective":"x","search_queries":["a","b","c","d"]}`,
		`{"objective":"x","search_queries":[null]}`, `{"objective":"x","search_queries":[" "]}`,
		`{"objective":" ","search_queries":["q"]}`,
		fmt.Sprintf(`{"objective":%q,"search_queries":["q"]}`, strings.Repeat("x", 2049)),
		fmt.Sprintf(`{"objective":"x","search_queries":[%q]}`, strings.Repeat("x", 513)),
		`{"objective":"x","search_queries":["q"],"session_id":"model-chosen"}`,
		`{"objective":"x","search_queries":["q"],"model_name":"model-chosen"}`,
		`{"objective":"x","search_queries":["q"],"mode":"paid"}`,
		`{"objective":"x","search_queries":["q"],"headers":{"Authorization":"secret"}}`,
		`{"objective":"x","search_queries":["q"],"connection_id":"another-connection"}`,
		`{"objective":"x","search_queries":["q"],"provider":"exa"}`,
	} {
		doer := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("parallel_search", doer)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, raw)); err == nil || len(doer.requests) != 0 {
			t.Fatal("invalid search arguments reached provider")
		}
	}
	for _, raw := range []string{
		`{"urls":[]}`, `{"urls":["https://example.com/page","https://example.com/page"]}`,
		`{"urls":["https://example.com/1","https://example.com/2","https://example.com/3","https://example.com/4","https://example.com/5","https://example.com/6"]}`,
		`{"urls":["https://127.0.0.1/"]}`, `{"urls":["file:///etc/passwd"]}`,
		`{"urls":["https://example.com/page"],"full_content":true}`,
		`{"urls":["https://example.com/page"],"allow_live_fetch":false}`,
		fmt.Sprintf(`{"urls":["https://example.com/page"],"objective":%q}`, strings.Repeat("x", 201)),
	} {
		doer := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("parallel_search", doer)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, raw)); err == nil || len(doer.requests) != 0 {
			t.Fatal("invalid fetch profile reached provider")
		}
	}
}

func TestParallelOutputCannotClaimSuccessFromHTTP200(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { delete(p, "extract_id") },
		func(p map[string]any) { delete(p, "session_id") },
		func(p map[string]any) { delete(p, "errors") },
		func(p map[string]any) {
			p["errors"] = []any{map[string]any{"url": "https://example.com/page", "error_type": "private-provider-diagnostic"}}
		},
		func(p map[string]any) { p["results"] = []any{} },
		func(p map[string]any) { p["results"] = "private-provider-diagnostic" },
		func(p map[string]any) {
			p["results"].([]any)[0].(map[string]any)["url"] = "https://example.com/another-page"
		},
		func(p map[string]any) { p["results"].([]any)[0].(map[string]any)["excerpts"] = []any{} },
		func(p map[string]any) { p["results"].([]any)[0].(map[string]any)["excerpts"] = []any{nil} },
		func(p map[string]any) {
			p["results"].([]any)[0].(map[string]any)["full_content"] = "private-provider-diagnostic"
		},
	} {
		payload := parallelOutput("web_fetch")
		mutate(payload)
		doer := &keylessDoer{t: t, result: parallelResultJSON(t, payload, false)}
		adapter, _ := NewKeylessMCPAdapter("parallel_search", doer)
		_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{"urls":["https://example.com/page"]}`))
		var providerError *domain.ProviderError
		if !errors.As(err, &providerError) || providerError.StatusCode != 200 || providerError.Attempts != 1 || len(doer.requests) != 3 || strings.Contains(err.Error(), "private-provider-diagnostic") {
			t.Fatalf("failed output was accepted, leaked or retried: %v", err)
		}
	}
	for _, result := range []string{`{"content":[{"type":"text","text":"unstructured prose"}]}`, `{"structuredContent":null}`,
		`{"isError":true,"content":[{"type":"text","text":"private-provider-diagnostic"}]}`,
		`{"content":[{"type":"text","text":"{\"error\":\"private-provider-diagnostic\"}"}]}`} {
		doer := &keylessDoer{t: t, result: result}
		adapter, _ := NewKeylessMCPAdapter("parallel_search", doer)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"objective":"Find docs","search_queries":["public docs"]}`)); err == nil || len(doer.requests) != 3 {
			t.Fatal("untyped or MCP error output accepted")
		}
	}
	// No matches is a valid search result, not proof of useful provider content.
	payload := parallelOutput("web_search")
	payload["results"] = []any{}
	doer := &keylessDoer{t: t, result: parallelResultJSON(t, payload, false)}
	adapter, _ := NewKeylessMCPAdapter("parallel_search", doer)
	if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"objective":"Find docs","search_queries":["public docs"]}`)); err != nil {
		t.Fatal("valid no-match search rejected")
	}
}

func TestParallelQuotaIsNeverRetriedOrUpgraded(t *testing.T) {
	for _, method := range []string{"initialize", "tools/call"} {
		doer := &keylessDoer{t: t, quota: true, quotaMethod: method}
		adapter, _ := NewKeylessMCPAdapter("parallel_search", doer)
		_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"objective":"Find docs","search_queries":["public docs"]}`))
		var providerError *domain.ProviderError
		expected := 1
		if method == "tools/call" {
			expected = 3
		}
		if !errors.As(err, &providerError) || providerError.StatusCode != 429 || providerError.Attempts != 1 || len(doer.requests) != expected {
			t.Fatalf("quota was retried or lost: %v", err)
		}
	}
}
