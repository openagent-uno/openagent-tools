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

func TestContext7TypedMappingSSEAndNoSession(t *testing.T) {
	for index, remote := range []string{"resolve-library-id", "query-docs"} {
		t.Run(remote, func(t *testing.T) {
			doer := &keylessDoer{t: t, sse: true, sessionless: true, result: `{"content":[{"type":"text","text":"Public documentation fixture"}],"structuredContent":{"not_a_contract":"ignored"}}`}
			adapter, err := NewKeylessMCPAdapter("context7", doer)
			if err != nil {
				t.Fatal(err)
			}
			args := `{"query":"How to use routing","library_name":"Next.js"}`
			if index == 1 {
				args = `{"library_id":"/vercel/next.js/v16.2.9","query":"How to use routing","language":"TypeScript"}`
			}
			inv := keylessInvocation(t, adapter, index, args)
			inv.Principal.SessionID = "not-forwarded"
			for i := 0; i < 2; i++ {
				result, err := adapter.Invoke(context.Background(), inv)
				if err != nil || result.ProviderStatus != 200 || result.Attempts != 1 || len(doer.requests) != 3*(i+1) {
					t.Fatalf("Context7 invocation: %v", err)
				}
				data, ok := result.Data.(map[string]any)
				if !ok || len(data) != 1 || data["content"] == nil {
					t.Fatal("unadvertised output forwarded")
				}
				params := doer.calls[3*i+2]["params"].(map[string]any)
				forwarded := params["arguments"].(map[string]any)
				if params["name"] != remote || forwarded["library_name"] != nil || forwarded["library_id"] != nil || forwarded["session_id"] != nil {
					t.Fatal("typed name or session mapping changed")
				}
				if index == 0 && (forwarded["libraryName"] != "Next.js" || len(forwarded) != 2) {
					t.Fatal("resolver arguments changed")
				}
				if index == 1 && (forwarded["libraryId"] != "/vercel/next.js/v16.2.9" || forwarded["language"] != "TypeScript" || len(forwarded) != 3) {
					t.Fatal("query arguments changed")
				}
				inv.ID = "invocation-two"
				inv.Connection.ID = "connection-two"
			}
			for _, op := range adapter.Operations() {
				if op.Validate() != nil || op.Risk != domain.RiskRead || op.Retry.MaxAttempts != 1 {
					t.Fatal("invalid Context7 typed read")
				}
				var schema map[string]any
				if json.Unmarshal(op.InputSchema, &schema) != nil || schema["additionalProperties"] != false {
					t.Fatal("non-strict local schema")
				}
			}
		})
	}
}

func TestContext7RejectsIdentityAndArgumentsBeforeIO(t *testing.T) {
	for _, mutate := range []func(*domain.Invocation){
		func(i *domain.Invocation) { i.Credential = domain.Credential{} },
		func(i *domain.Invocation) {
			i.Credential, _ = domain.NewCredential(domain.CredentialAPIToken, "secret", "", "", "", nil)
		},
		func(i *domain.Invocation) { i.Connection.WorkspaceID = "other-workspace" },
		func(i *domain.Invocation) { i.Connection.Provider = "exa" },
		func(i *domain.Invocation) { i.Connection.Enabled = false },
		func(i *domain.Invocation) { i.Operation.Name = "files.context7.raw" },
		func(i *domain.Invocation) { i.Operation.Risk = domain.RiskWrite },
		func(i *domain.Invocation) {
			i.Connection.Config = json.RawMessage(`{"endpoint":"https://mcp.context7.com/mcp/oauth"}`)
		},
		func(i *domain.Invocation) { i.Connection.Config = json.RawMessage(`{"api_key":"secret"}`) },
	} {
		doer := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("context7", doer)
		inv := keylessInvocation(t, adapter, 0, `{"query":"Public docs","library_name":"Next.js"}`)
		mutate(&inv)
		if _, err := adapter.Invoke(context.Background(), inv); err == nil || len(doer.requests) != 0 {
			t.Fatal("invalid binding reached Context7")
		}
	}
	for _, raw := range []string{
		`{}`, `{"query":"x"}`, `{"query":" ","library_name":"Next.js"}`, `{"query":"x","library_name":""}`,
		fmt.Sprintf(`{"query":%q,"library_name":"Next.js"}`, strings.Repeat("x", 2049)),
		fmt.Sprintf(`{"query":"x","library_name":%q}`, strings.Repeat("x", 257)),
		`{"query":"x","library_name":"Next.js","session_id":"caller"}`,
		`{"query":"x","library_name":"Next.js","api_key":"secret"}`,
		`{"query":"x","library_name":"Next.js","libraryName":"different"}`,
		`{"query":"x","library_name":"Next.js","connection_id":"another"}`,
		`{"query":"x","library_name":"Next.js","provider":"exa"}`,
	} {
		doer := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("context7", doer)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, raw)); err == nil || len(doer.requests) != 0 {
			t.Fatal("invalid resolver arguments reached Context7")
		}
	}
	for _, raw := range []string{
		`{"library_id":"https://context7.com/vercel/next.js","query":"x"}`,
		`{"library_id":"/vercel/../next.js","query":"x"}`,
		`{"library_id":"/vercel/next.js?token=x","query":"x"}`,
		`{"library_id":"/a/b/c/d","query":"x"}`,
		`{"library_id":"/vercel/next.js","query":"x","language":null}`,
		`{"library_id":"/vercel/next.js","query":"x","language":" "}`,
		fmt.Sprintf(`{"library_id":"/vercel/next.js","query":"x","language":%q}`, strings.Repeat("x", 65)),
		`{"library_id":"/vercel/next.js","query":"x","libraryId":"/another/project"}`,
	} {
		doer := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("context7", doer)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, raw)); err == nil || len(doer.requests) != 0 {
			t.Fatal("invalid library query reached Context7")
		}
	}
}

func TestContext7OnlyNonemptyBoundedTextAndNoQuotaRetry(t *testing.T) {
	for _, result := range []string{
		`{}`, `{"content":[]}`, `{"content":[{"type":"text","text":" "}]}`,
		`{"content":[{"type":"text","text":null}]}`, `{"content":[{"type":"image","data":"private-payload"}]}`,
		`{"content":[{"type":"resource","resource":{"uri":"https://another.example"}}]}`,
		`{"isError":true,"content":[{"type":"text","text":"private-payload"}]}`,
		`{"content":[{"type":"text","text":"{\"error\":\"private-payload\"}"}]}`,
		`{"structuredContent":{"error":"private-payload"},"content":[{"type":"text","text":"unrelated"}]}`,
	} {
		doer := &keylessDoer{t: t, sse: true, sessionless: true, result: result}
		adapter, _ := NewKeylessMCPAdapter("context7", doer)
		_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"query":"Public docs","library_name":"Next.js"}`))
		var failure *domain.ProviderError
		if !errors.As(err, &failure) || failure.Attempts != 1 || failure.StatusCode != 200 || len(doer.requests) != 3 || strings.Contains(err.Error(), "private-payload") {
			t.Fatalf("failed output accepted, leaked or retried: %v", err)
		}
	}
	for _, method := range []string{"initialize", "tools/call"} {
		doer := &keylessDoer{t: t, sessionless: true, quota: true, quotaMethod: method}
		adapter, _ := NewKeylessMCPAdapter("context7", doer)
		_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"query":"Public docs","library_name":"Next.js"}`))
		var failure *domain.ProviderError
		count := 1
		if method == "tools/call" {
			count = 3
		}
		if !errors.As(err, &failure) || failure.StatusCode != 429 || failure.Attempts != 1 || len(doer.requests) != count {
			t.Fatalf("quota retried or lost: %v", err)
		}
	}
}
