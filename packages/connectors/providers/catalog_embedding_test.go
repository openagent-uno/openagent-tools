package providers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// Embedding hosts require every adapter to validate previews before admission.
// Read-only providers validate audit previews without credentials or provider I/O.
func TestFullCatalogEmbeddingContractAndKeylessActionRefusal(t *testing.T) {
	d := doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("embedding discovery/preview made a provider call")
		return nil, nil
	})
	adapters, err := CatalogWithDoer(d)
	if err != nil {
		t.Fatal(err)
	}
	keyless := 0
	for _, adapter := range adapters {
		preview, ok := adapter.(domain.ActionPreviewer)
		if !ok {
			t.Fatalf("provider %s cannot be admitted by a preview-validating host", adapter.Provider())
		}
		if _, free := adapter.(domain.CredentialFreeAdapter); !free {
			continue
		}
		keyless++
		for _, risk := range []domain.Risk{domain.RiskRead, domain.RiskWrite, domain.RiskDestructive, domain.RiskPublish} {
			_, err := preview.Preview(domain.Invocation{Operation: domain.Operation{Provider: adapter.Provider(), Capability: adapter.Capability(), Risk: risk, Name: "forged.write"}})
			if !errors.Is(err, domain.ErrDenied) {
				t.Fatal("keyless provider admitted an action preview")
			}
		}
		for _, op := range adapter.Operations() {
			if op.Risk != domain.RiskRead {
				t.Fatal("keyless provider advertised a write")
			}
		}
	}
	if keyless != 5 {
		t.Fatal("keyless embedding cohort changed")
	}
}

func TestKeylessReadAuditPreviewBeforeCredentialResolution(t *testing.T) {
	for _, tc := range []struct{ provider, operation, args string }{
		{"exa", "files.exa.search", `{"query":"public documentation"}`},
		{"firecrawl", "files.firecrawl.search", `{"query":"public documentation"}`},
		{"parallel_search", "files.parallel.search", `{"objective":"Find documentation","search_queries":["public docs"]}`},
		{"context7", "files.context7.resolve_library", `{"library_name":"react","query":"effect cleanup"}`},
		{"coingecko", "files.coingecko.global", `{}`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			d := doerFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("preview attempted provider I/O")
				return nil, nil
			})
			a, err := NewKeylessMCPAdapter(tc.provider, d)
			if err != nil {
				t.Fatal(err)
			}
			var operation domain.Operation
			for _, op := range a.Operations() {
				if op.Name == tc.operation {
					operation = op
				}
			}
			inv := domain.Invocation{ID: "preview-one", Principal: domain.Principal{WorkspaceID: "workspace-one", ActorID: "owner"}, Connection: domain.Connection{ID: "connection-one", WorkspaceID: "workspace-one", Capability: domain.Files, Provider: tc.provider, Enabled: true, Config: []byte(`{}`)}, Operation: operation, Arguments: []byte(tc.args)}
			preview, err := a.Preview(inv)
			if err != nil || preview != operation.Preview {
				t.Fatalf("credential-free audit preview: %#v %v", preview, err)
			}
			// Unresolved credentials may be used for metadata only. Invoke never
			// treats that absence as an authorization or a no-auth downgrade.
			if _, err := a.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrDenied) {
				t.Fatal("preview weakened execution credentials")
			}
			inv.Arguments = []byte(`{"url":"http://127.0.0.1/","headers":{"Authorization":"secret"}}`)
			if _, err := a.Preview(inv); err == nil {
				t.Fatal("preview accepted unreviewed arguments")
			}
		})
	}
}
