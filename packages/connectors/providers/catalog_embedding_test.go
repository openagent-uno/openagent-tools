package providers

import (
	"errors"
	"net/http"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// Embedding hosts require every adapter to validate previews before admission.
// Read-only credential-free providers satisfy that interface by refusing actions.
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
