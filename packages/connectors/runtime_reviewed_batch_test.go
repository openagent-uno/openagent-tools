package connectors

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/definitions"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type reviewedRuntimeDoer struct {
	status int
	body   string
	calls  int
}

func (d *reviewedRuntimeDoer) Do(request *http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{StatusCode: d.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(d.body))}, nil
}

// Host API tokens have scopes=[]: these are designed vendor-response fixtures,
// not live provider acceptance or fabricated OAuth grants. Exercise the public
// runtime admission and invocation boundary for every admitted batch provider.
func TestReviewedRuntimeManualTokensHaveNoAttestedOAuthScopes(t *testing.T) {
	docs, err := definitions.Documents()
	if err != nil {
		t.Fatal(err)
	}
	admitted := map[string]bool{}
	for _, raw := range docs {
		var doc struct {
			Providers []struct {
				Catalog definitions.Catalog `json:"catalog"`
			} `json:"providers"`
		}
		if err = json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, def := range doc.Providers {
			admitted[def.Catalog.Provider] = true
		}
	}
	if len(admitted) != 90 {
		t.Fatalf("expected exact 90 manual-token providers, got %d", len(admitted))
	}
	files, err := filepath.Glob("definitions/batch*/response-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	doer := &reviewedRuntimeDoer{}
	runtime, err := NewRuntime(doer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := domain.NewCredential(domain.CredentialAPIToken, "c2FtcGxlLXVzZXI6c2FtcGxlLXRva2Vu", "", "", "host-v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Cases []struct {
				Provider  string          `json:"provider"`
				Operation string          `json:"operation"`
				Arguments json.RawMessage `json:"arguments"`
				Response  json.RawMessage `json:"response"`
			} `json:"cases"`
		}
		if err = json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, entry := range doc.Cases {
			entry := entry
			t.Run(entry.Provider, func(t *testing.T) {
				var item Item
				found := false
				for _, candidate := range Catalog() {
					if candidate.Provider == entry.Provider {
						item = candidate.Item
						found = true
						break
					}
				}
				if !admitted[entry.Provider] || !found || !item.Available || item.Auth != "token" {
					t.Fatal("not an admitted manual-token provider")
				}
				binding := Binding{CatalogID: item.ID, Principal: domain.Principal{WorkspaceID: "host-workspace", ActorID: "host-owner"}, Connection: domain.Connection{ID: "host-connection", WorkspaceID: "host-workspace", Provider: entry.Provider, Capability: domain.Capability(item.Capability), Enabled: true, ExternalID: "host-account", Config: json.RawMessage(`{}`), Scopes: nil}}
				tools, err := runtime.Tools(binding)
				if err != nil || len(tools) != len(item.ReadTools) {
					t.Fatal("host scopes=[] hid reviewed manual-token tools", err)
				}
				var selected domain.Operation
				for _, tool := range tools {
					if len(tool.RequiredScopes) != 0 || tool.Risk != domain.RiskRead {
						t.Fatal("manual token acquired OAuth scope claims or write tool")
					}
					if tool.Name == entry.Operation {
						selected = tool
					}
				}
				if selected.Name == "" {
					t.Fatal("documented operation not visible")
				}
				var args map[string]any
				if err = json.Unmarshal(entry.Arguments, &args); err != nil {
					t.Fatal(err)
				}
				var schema struct {
					Properties map[string]json.RawMessage `json:"properties"`
				}
				if err = json.Unmarshal(selected.InputSchema, &schema); err != nil {
					t.Fatal(err)
				}
				for key, value := range map[string]string{"connection_id": binding.Connection.ID, "provider": entry.Provider, "expected_external_id": binding.Connection.ExternalID} {
					if _, ok := schema.Properties[key]; ok {
						args[key] = value
					}
				}
				arguments, _ := json.Marshal(args)
				call := Call{Binding: binding, Tool: entry.Operation, Arguments: arguments, Credential: credential, InvocationID: "host-manual-token-fixture"}
				doer.status, doer.body, doer.calls = 200, string(entry.Response), 0
				result, err := runtime.Invoke(context.Background(), call)
				if err != nil || result.Data == nil || result.Attempts != 1 || doer.calls != 1 {
					t.Fatal("normal host personal token could not invoke documented read", err)
				}
				doer.status, doer.body, doer.calls = 403, `{"error":"provider permission denied"}`, 0
				result, err = runtime.Invoke(context.Background(), call)
				if err == nil || result.Data != nil || doer.calls != 1 {
					t.Fatal("provider 403 was ignored or retried")
				}
				covered[entry.Provider] = true
			})
		}
	}
	if len(covered) != 90 {
		t.Fatalf("runtime token coverage %d/90", len(covered))
	}
	// The new manual-token rule does not relax existing provider-specific OAuth.
	for _, id := range []string{"google-calendar", "outlook-mail", "outlook-calendar", "onedrive", "sharepoint"} {
		item, ok := Lookup(id)
		if !ok {
			t.Fatal("missing OAuth connector", id)
		}
		binding := Binding{CatalogID: id, Principal: domain.Principal{WorkspaceID: "host-workspace", ActorID: "host-owner"}, Connection: domain.Connection{ID: "host-connection", WorkspaceID: "host-workspace", Provider: item.Provider, Capability: domain.Capability(item.Capability), Enabled: true, ExternalID: "host-account", Config: json.RawMessage(`{}`)}}
		tools, err := runtime.Tools(binding)
		if err != nil || len(tools) != 0 {
			t.Fatal("OAuth scope requirements were relaxed", id, err)
		}
	}
}
