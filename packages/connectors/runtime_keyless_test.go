package connectors

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestRuntimeNoAuthIsOptInAndNeverWeakensExistingProviders(t *testing.T) {
	doer := &localDoer{}
	runtime, err := NewRuntime(doer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := domain.NewCredential(domain.CredentialNone, "", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range Catalog() {
		if !item.Available || item.NativeKind != "" {
			continue
		}
		binding := Binding{CatalogID: item.ID, Principal: domain.Principal{WorkspaceID: "workspace-one", ActorID: "owner"}, AllowWrite: true,
			Connection: domain.Connection{ID: "connection-one", WorkspaceID: "workspace-one", Provider: item.Provider, Capability: domain.Capability(item.Capability), Enabled: true, Config: json.RawMessage(`{}`)}}
		if item.Auth == "none" {
			if item.ID != "exa" && item.ID != "firecrawl" && item.ID != "parallel-search" && item.ID != "context7" && item.ID != "coingecko" {
				t.Fatalf("unexpected no-auth provider: %s", item.ID)
			}
			tools, err := runtime.Tools(binding)
			if err != nil || len(tools) != 2 {
				t.Fatalf("keyless tools: %s %v", item.ID, err)
			}
			for _, tool := range tools {
				if tool.Risk != domain.RiskRead {
					t.Fatal("keyless provider exposed a write")
				}
			}
			for _, absent := range []domain.Credential{{}, mustRuntimeToken(t)} {
				_, err := runtime.Invoke(context.Background(), Call{Binding: binding, Tool: tools[0].Name, Credential: absent, InvocationID: "invocation-one", Arguments: json.RawMessage(`{"query":"fixture"}`)})
				if err == nil {
					t.Fatal("keyless adapter accepted implicit/secret credential")
				}
			}
		} else {
			// Every prior connector must reject None even when host write access is enabled.
			if len(item.ReadTools) == 0 {
				t.Fatal("existing provider has no read fixture")
			}
			_, err := runtime.Invoke(context.Background(), Call{Binding: binding, Tool: item.ReadTools[0], Credential: credential, InvocationID: "invocation-one", Arguments: json.RawMessage(`{}`)})
			if err == nil {
				t.Fatalf("no-auth accepted for existing provider %s", item.ID)
			}
		}
	}
	if doer.calls != 0 {
		t.Fatal("rejected credential reached a provider")
	}
}

func mustRuntimeToken(t *testing.T) domain.Credential {
	t.Helper()
	credential, err := domain.NewCredential(domain.CredentialAPIToken, "host-token", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func TestCandidateCatalogIncludesNextKeylessProvidersWithoutChangingPriorIdentities(t *testing.T) {
	items := Catalog()
	if len(items) != 115 {
		t.Fatal("candidate catalog must contain 114 official entries and Custom MCP")
	}
	for _, test := range []struct{ id, provider, first, second string }{
		{"parallel-search", "parallel_search", "files.parallel.search", "files.parallel.fetch"},
		{"context7", "context7", "files.context7.resolve_library", "files.context7.query_docs"},
		{"coingecko", "coingecko", "files.coingecko.price", "files.coingecko.global"},
	} {
		item, ok := Lookup(test.id)
		if !ok || !item.Available || item.Auth != "none" || item.Provider != test.provider || item.Capability != "files" ||
			len(item.ReadTools) != 2 || item.ReadTools[0] != test.first || item.ReadTools[1] != test.second || len(item.AgentTools) != 0 {
			t.Fatal("candidate connector contract changed")
		}
		runtime, err := NewRuntime(&localDoer{})
		if err != nil {
			t.Fatal(err)
		}
		binding := Binding{CatalogID: test.id, Principal: domain.Principal{WorkspaceID: "workspace-one", ActorID: "owner"},
			Connection: domain.Connection{ID: "connection-one", WorkspaceID: "workspace-one", Provider: test.provider, Capability: domain.Files, Enabled: true, Config: json.RawMessage(`{}`)}}
		tools, err := runtime.Tools(binding)
		if err != nil || len(tools) != 2 {
			t.Fatal("new candidate not registered in runtime")
		}
		binding.CatalogID = "exa"
		if _, err := runtime.Tools(binding); err == nil {
			t.Fatal("catalog identity can substitute provider")
		}
	}
	custom, ok := Lookup("custom-mcp")
	if !ok || custom.NativeKind != "custom_mcp" || custom.Auth != "custom_mcp" {
		t.Fatal("Custom MCP identity changed")
	}
}
