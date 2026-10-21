package central

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func fixtureDescriptor(id string) Descriptor {
	op := domain.Operation{Name: "files." + id + ".list", Description: "List fixture resources", Capability: domain.Files,
		Provider: id, Risk: domain.RiskRead, Mode: domain.OperationTyped,
		InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`), Retry: domain.RetryPolicy{MaxAttempts: 1}}
	return Descriptor{Item: connectors.Item{ID: id, Name: "Fixture " + id, Category: "Data", Auth: "none", Capability: "files",
		Provider: id, Available: true, ReadTools: []string{op.Name}, AgentTools: []string{}}, Operations: []domain.Operation{op},
		Setup: Setup{Mode: "none", CredentialCustody: "service", Execution: "service"}}
}

func fixtureSigningKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func fixtureRegistry(t *testing.T, key ed25519.PrivateKey, revision uint64, items ...Descriptor) *Registry {
	t.Helper()
	registry, err := NewRegistry(revision, "fixture-key", key, items)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestContractBindsAuthorityNotPresentation(t *testing.T) {
	d := fixtureDescriptor("fixture")
	original := ComputeContract(d)
	d.Item.Name, d.Item.Available, d.Item.UnavailableReason = "Changed title", false, "Unavailable"
	if ComputeContract(d) != original {
		t.Fatal("presentation changed authority")
	}
	d.Operations[0].RequiredScopes = []string{"resource:read"}
	if ComputeContract(d) == original {
		t.Fatal("scope policy was not bound")
	}
	d = fixtureDescriptor("fixture")
	d.Setup.Execution = "host"
	if ComputeContract(d) == original {
		t.Fatal("executor was not bound")
	}
}

func TestRegistryOwnsEveryAuthorizationSlice(t *testing.T) {
	public, key := fixtureSigningKey(t)
	d := fixtureDescriptor("fixture")
	registry := fixtureRegistry(t, key, 1, d)
	d.Operations[0].Name = "attacker.operation"
	d.Item.ReadTools[0] = "attacker.operation"
	key[0] ^= 1
	first, ok := registry.Lookup("fixture")
	if !ok || first.Operations[0].Name != "files.fixture.list" {
		t.Fatal("registry aliased source")
	}
	first.Operations[0].Name = "attacker.operation"
	second, _ := registry.Lookup("fixture")
	if second.Operations[0].Name != "files.fixture.list" {
		t.Fatal("lookup aliased registry")
	}
	snapshot := registry.Snapshot(time.Now())
	signature, err := base64.RawURLEncoding.DecodeString(snapshot.Signature)
	if err != nil || !ed25519.Verify(public, snapshot.Payload, signature) {
		t.Fatal("registry signing key was aliased")
	}
}

func TestRegistryRejectsUnsafeOrAmbiguousDescriptors(t *testing.T) {
	_, key := fixtureSigningKey(t)
	cases := map[string]func(*Descriptor){
		"raw":                 func(d *Descriptor) { d.Operations[0].Mode = domain.OperationRaw },
		"raw-risk":            func(d *Descriptor) { d.Operations[0].Risk = domain.RiskRaw },
		"internal":            func(d *Descriptor) { d.Operations[0].InternalOnly = true },
		"wrong-provider":      func(d *Descriptor) { d.Operations[0].Provider = "other" },
		"hidden-operation":    func(d *Descriptor) { d.Item.ReadTools = nil },
		"read-downgrade":      func(d *Descriptor) { d.Operations[0].Risk = domain.RiskWrite },
		"duplicate-operation": func(d *Descriptor) { d.Operations = append(d.Operations, d.Operations[0]) },
		"duplicate-tool":      func(d *Descriptor) { d.Item.AgentTools = append(d.Item.AgentTools, d.Item.ReadTools[0]) },
		"schema-not-object":   func(d *Descriptor) { d.Operations[0].InputSchema = json.RawMessage(`[]`) },
		"duplicate-schema-key": func(d *Descriptor) {
			d.Operations[0].InputSchema = json.RawMessage(`{"type":"object","type":"string"}`)
		},
		"custody":    func(d *Descriptor) { d.Setup.CredentialCustody = "host" },
		"wrong-hash": func(d *Descriptor) { d.ContractSHA256 = string(make([]byte, 64)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := fixtureDescriptor("fixture")
			mutate(&d)
			if _, err := NewRegistry(1, "fixture-key", key, []Descriptor{d}); err == nil {
				t.Fatal("unsafe descriptor accepted")
			}
		})
	}
	d := fixtureDescriptor("fixture")
	if _, err := NewRegistry(1, "fixture-key", key, []Descriptor{d, d}); err == nil {
		t.Fatal("duplicate catalog identity accepted")
	}
}

func TestCatalogRefreshAndAddedConnectorNeedNoClientRebuild(t *testing.T) {
	public, key := fixtureSigningKey(t)
	registry := fixtureRegistry(t, key, 1, fixtureDescriptor("first"))
	now := time.Now()
	snapshot := registry.Snapshot(now)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/registry/catalog" {
			t.Error("unexpected catalog route")
		}
		_ = json.NewEncoder(w).Encode(snapshot)
	}))
	defer server.Close()
	client := &Client{Origin: server.URL, AllowLoopback: true, TrustKeys: map[string]ed25519.PublicKey{"fixture-key": public}}
	ctx := context.Background()
	first, err := client.Catalog(ctx)
	if err != nil || len(first.Connectors) != 1 {
		t.Fatalf("initial catalog: %v", err)
	}
	snapshot = registry.Snapshot(now.Add(time.Second))
	if _, err := client.Catalog(ctx); err != nil {
		t.Fatalf("fresh signature on same revision: %v", err)
	}
	registry = fixtureRegistry(t, key, 2, fixtureDescriptor("first"), fixtureDescriptor("second"))
	snapshot = registry.Snapshot(time.Now())
	second, err := client.Catalog(ctx)
	if err != nil || len(second.Connectors) != 2 {
		t.Fatalf("new connector did not arrive through stable protocol: %v", err)
	}
	snapshot = fixtureRegistry(t, key, 1, fixtureDescriptor("first")).Snapshot(time.Now())
	if _, err := client.Catalog(ctx); !errors.Is(err, ErrCatalogRollback) {
		t.Fatalf("rollback accepted: %v", err)
	}
	snapshot = fixtureRegistry(t, key, 2, fixtureDescriptor("changed")).Snapshot(time.Now())
	if _, err := client.Catalog(ctx); !errors.Is(err, ErrCatalogRollback) {
		t.Fatalf("same-revision drift accepted: %v", err)
	}
}

func TestCatalogRejectsUntrustedInvalidAndExpiredSnapshots(t *testing.T) {
	public, key := fixtureSigningKey(t)
	base := fixtureRegistry(t, key, 1, fixtureDescriptor("fixture"))
	cases := map[string]func() SignedCatalog{
		"unknown-key":   func() SignedCatalog { s := base.Snapshot(time.Now()); s.KeyID = "unknown"; return s },
		"bad-signature": func() SignedCatalog { s := base.Snapshot(time.Now()); s.Signature = "bad"; return s },
		"expired":       func() SignedCatalog { return base.Snapshot(time.Now().Add(-time.Hour)) },
		"future":        func() SignedCatalog { return base.Snapshot(time.Now().Add(time.Hour)) },
		"wrong-protocol": func() SignedCatalog {
			s := base.Snapshot(time.Now())
			var catalog Catalog
			_ = json.Unmarshal(s.Payload, &catalog)
			catalog.Protocol = "unsupported/v9"
			s.Payload, _ = json.Marshal(catalog)
			s.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, s.Payload))
			return s
		},
		"tampered": func() SignedCatalog { s := base.Snapshot(time.Now()); s.Payload = json.RawMessage(`{}`); return s },
	}
	for name, snapshot := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(snapshot()) }))
			defer server.Close()
			client := &Client{Origin: server.URL, AllowLoopback: true, TrustKeys: map[string]ed25519.PublicKey{"fixture-key": public}}
			if _, err := client.Catalog(context.Background()); err == nil {
				t.Fatal("invalid signed catalog accepted")
			}
		})
	}
}
