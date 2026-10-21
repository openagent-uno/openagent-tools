//go:build darwin || linux

package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// The provider is deliberately synthetic. Registration, signatures, HTTP
// routing, descriptor pins, central admission and encrypted storage are real.
type centralTestAdapter struct {
	provider   string
	operations []domain.Operation
	calls      int
	fail       bool
}

func (e *centralTestAdapter) Provider() string {
	if e.provider != "" {
		return e.provider
	}
	return "fixture"
}
func (*centralTestAdapter) Capability() domain.Capability    { return domain.Files }
func (*centralTestAdapter) CredentialFree()                  {}
func (e *centralTestAdapter) Operations() []domain.Operation { return e.operations }

func (e *centralTestAdapter) Invoke(_ context.Context, call domain.Invocation) (domain.Result, error) {
	e.calls++
	if !call.Credential.IsNone() || call.Principal.BoundConnectionID != call.Connection.ID || call.Principal.WorkspaceID != call.Connection.WorkspaceID {
		return domain.Result{}, errors.New("unexpected fixture credential")
	}
	if e.fail {
		return domain.Result{}, errors.New("synthetic-provider-secret")
	}
	return domain.Result{Data: map[string]any{"ok": true}, Attempts: 1}, nil
}

type centralServerFixture struct {
	vault      *Vault
	http       *httptest.Server
	executor   *centralTestAdapter
	broker     *auth.Server
	key        ed25519.PrivateKey
	backend    atomic.Pointer[Server]
	descriptor Descriptor
	client     *Client
	other      *Client
	recipient  Recipient
}

func newCentralServerFixture(t *testing.T) *centralServerFixture {
	t.Helper()
	dir := t.TempDir()
	store, err := auth.NewStore(filepath.Join(dir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewServer(store, oauth.Engine{AllowLoopback: true}, nil, "http://127.0.0.1", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	public, key := fixtureSigningKey(t)
	d := fixtureDescriptor("fixture")
	write := d.Operations[0]
	write.Name, write.Risk = "files.fixture.create", domain.RiskWrite
	d.Item.AgentTools = []string{write.Name}
	d.Operations = append(d.Operations, write)
	d.ContractSHA256 = ComputeContract(d)
	executor := &centralTestAdapter{operations: append([]domain.Operation(nil), d.Operations...)}
	runtime, err := connectors.NewRuntimeWithCatalog([]connectors.CatalogEntry{{Item: d.Item}}, []domain.Adapter{executor})
	if err != nil {
		t.Fatal(err)
	}
	vault := vaultTestOpen(t, filepath.Join(dir, "vault.json"))
	central, err := NewServer(Config{Auth: broker, Vault: vault, Registry: fixtureRegistry(t, key, 1, d), Executor: runtime})
	if err != nil {
		t.Fatal(err)
	}
	f := &centralServerFixture{vault: vault, executor: executor, broker: broker, key: key, descriptor: d, recipient: Recipient{"workspace", "owner"}}
	f.backend.Store(central)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/installations" {
			broker.ServeHTTP(w, r)
			return
		}
		f.backend.Load().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	broker.Origin = server.URL
	f.http = server
	for _, target := range []**Client{&f.client, &f.other} {
		identity, err := auth.NewIdentity("fixture-host", "Fixture host")
		if err != nil {
			t.Fatal(err)
		}
		registration := &auth.Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
		if err := registration.Register(context.Background()); err != nil {
			t.Fatal(err)
		}
		*target = &Client{Origin: server.URL, Identity: identity, AllowLoopback: true, TrustKeys: map[string]ed25519.PublicKey{"fixture-key": public}}
	}
	return f
}

func TestCentralServerAddsConnectorBehindUnchangedClient(t *testing.T) {
	f := newCentralServerFixture(t)
	ctx := context.Background()
	first, err := f.client.Catalog(ctx)
	if err != nil || len(first.Connectors) != 1 {
		t.Fatal("initial catalog unavailable")
	}
	later := fixtureDescriptor("later")
	later.ContractSHA256 = ComputeContract(later)
	if _, exists := connectors.Lookup(later.Item.ID); exists {
		t.Fatal("fixture must not exist in compiled consumer catalog")
	}
	adapter := &centralTestAdapter{provider: "later", operations: later.Operations}
	runtime, err := connectors.NewRuntimeWithCatalog([]connectors.CatalogEntry{{Item: f.descriptor.Item}, {Item: later.Item}}, []domain.Adapter{f.executor, adapter})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewServer(Config{Auth: f.broker, Vault: f.vault, Registry: fixtureRegistry(t, f.key, 2, f.descriptor, later), Executor: runtime})
	if err != nil {
		t.Fatal(err)
	}
	f.backend.Store(backend)
	second, err := f.client.Catalog(ctx)
	if err != nil || second.Revision != 2 || len(second.Connectors) != 2 {
		t.Fatal("unchanged client failed catalog refresh")
	}
	var discovered Descriptor
	for _, d := range second.Connectors {
		if d.Item.ID == "later" {
			discovered = d
		}
	}
	if discovered.Item.ID == "" {
		t.Fatal("new descriptor not discovered")
	}
	c, err := f.client.Create(ctx, CreateRequest{CatalogID: discovered.Item.ID, ContractSHA256: discovered.ContractSHA256, Recipient: f.recipient, Operations: discovered.Item.ReadTools})
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.client.Invoke(ctx, c.ID, f.invocation(c, "later-one", discovered.Item.ReadTools[0]))
	if err != nil || result.Status != "succeeded" || !result.ResultAvailable || adapter.calls != 1 {
		t.Fatalf("new server adapter failed through unchanged client: %v", err)
	}
}

func (f *centralServerFixture) create(t *testing.T, names ...string) Connection {
	t.Helper()
	if len(names) == 0 {
		names = []string{"files.fixture.list"}
	}
	value, err := f.client.Create(context.Background(), CreateRequest{CatalogID: "fixture", ContractSHA256: f.descriptor.ContractSHA256, Recipient: f.recipient, Operations: names})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func (f *centralServerFixture) invocation(c Connection, id, operation string) InvokeRequest {
	return InvokeRequest{Recipient: f.recipient, ContractSHA256: c.ContractSHA256, GrantRevision: c.GrantRevision,
		InvocationID: id, Operation: operation, Arguments: json.RawMessage(`{}`)}
}

func TestCentralServerRealClientLifecycleAndRecipientIsolation(t *testing.T) {
	f := newCentralServerFixture(t)
	ctx := context.Background()
	if catalog, err := f.client.Catalog(ctx); err != nil || len(catalog.Connectors) != 1 {
		t.Fatal("signed catalog roundtrip failed")
	}
	c := f.create(t)
	for _, call := range []func(context.Context, string, Recipient) (Connection, error){f.client.Connection, f.client.Complete, f.client.Refresh} {
		if value, err := call(ctx, c.ID, f.recipient); err != nil || value.Status != "connected" {
			t.Fatalf("connection action failed: %v", err)
		}
	}
	if _, err := f.other.Connection(ctx, c.ID, f.recipient); err == nil {
		t.Fatal("other installation read connection")
	}
	if _, err := f.client.Connection(ctx, c.ID, Recipient{"workspace", "other"}); err == nil {
		t.Fatal("other recipient read connection")
	}
	input := f.invocation(c, "read-one", "files.fixture.list")
	result, err := f.client.Invoke(ctx, c.ID, input)
	if err != nil || result.Status != "succeeded" || !result.ResultAvailable || result.Result == nil {
		t.Fatalf("read failed: %v", err)
	}
	if status, err := f.client.Invocation(ctx, c.ID, input.InvocationID, f.recipient); err != nil || status.Status != "succeeded" || status.Result != nil {
		t.Fatal("durable invocation lookup failed")
	}
	if disconnected, err := f.client.Disconnect(ctx, c.ID, f.recipient); err != nil || disconnected.Status != "disconnected" {
		t.Fatalf("disconnect failed: %v", err)
	}
	input.InvocationID = "after-disconnect"
	if _, err := f.client.Invoke(ctx, c.ID, input); err == nil || f.executor.calls != 1 {
		t.Fatal("disconnected grant executed")
	}
}

func TestCentralServerInvocationReplayConflictAndExactGrant(t *testing.T) {
	f := newCentralServerFixture(t)
	c := f.create(t)
	ctx := context.Background()
	input := f.invocation(c, "read-one", "files.fixture.list")
	if _, err := f.client.Invoke(ctx, c.ID, input); err != nil {
		t.Fatal(err)
	}
	if replay, err := f.client.Invoke(ctx, c.ID, input); err != nil || replay.Status != "succeeded" || replay.ResultAvailable || replay.Result != nil {
		t.Fatal("replay did not return metadata only")
	}
	input.Arguments = json.RawMessage(`{"changed":true}`)
	if _, err := f.client.Invoke(ctx, c.ID, input); err == nil {
		t.Fatal("idempotency body conflict admitted")
	}
	input.InvocationID = "read-two"
	input.GrantRevision++
	if _, err := f.client.Invoke(ctx, c.ID, input); err == nil {
		t.Fatal("wrong grant revision admitted")
	}
	input.GrantRevision = c.GrantRevision
	input.ContractSHA256 = string(bytes.Repeat([]byte{'a'}, 64))
	if _, err := f.client.Invoke(ctx, c.ID, input); err == nil {
		t.Fatal("wrong contract admitted")
	}
	if f.executor.calls != 1 {
		t.Fatal("replay or mismatched authority reached executor")
	}
}

func TestCentralServerWritesRequirePerActionApprovalAndNeverRetryUnknown(t *testing.T) {
	f := newCentralServerFixture(t)
	c := f.create(t, "files.fixture.list", "files.fixture.create")
	input := f.invocation(c, "write-one", "files.fixture.create")
	if _, err := f.client.Invoke(context.Background(), c.ID, input); err == nil || f.executor.calls != 0 {
		t.Fatal("write executed without approval")
	}
	input.ApprovalID = "host-admission-one"
	f.executor.fail = true
	result, err := f.client.Invoke(context.Background(), c.ID, input)
	if err != nil || result.Status != "outcome_unknown" || result.Result != nil {
		t.Fatalf("write outcome must remain unknown: %v", err)
	}
	if replay, err := f.client.Invoke(context.Background(), c.ID, input); err != nil || replay.Status != "outcome_unknown" || f.executor.calls != 1 {
		t.Fatal("uncertain write was retried")
	}
	state, _ := f.vault.View()
	data, _ := json.Marshal(state)
	if bytes.Contains(data, []byte("synthetic-provider-secret")) {
		t.Fatal("provider failure text persisted")
	}
}

func TestCentralServerRefusesExecutorContractDriftBeforeIO(t *testing.T) {
	for _, mutate := range []func(*domain.Operation){
		func(op *domain.Operation) { op.Risk = domain.RiskWrite },
		func(op *domain.Operation) { op.RequiredScopes = []string{"extra:write"} },
		func(op *domain.Operation) {
			op.InputSchema = json.RawMessage(`{"type":"object","required":["new_field"]}`)
		},
	} {
		f := newCentralServerFixture(t)
		c := f.create(t)
		mutate(&f.executor.operations[0])
		if _, err := f.client.Invoke(context.Background(), c.ID, f.invocation(c, "drift", "files.fixture.list")); err == nil || f.executor.calls != 0 {
			t.Fatal("executor drift executed under old descriptor")
		}
	}
}

func TestCentralServerSignedRawConfigCannotSmuggleCredentialFields(t *testing.T) {
	f := newCentralServerFixture(t)
	for _, config := range []json.RawMessage{json.RawMessage(`{"api_key":"synthetic-secret"}`), json.RawMessage(`{"nested":{"apikey":"synthetic-secret"}}`)} {
		input := CreateRequest{CatalogID: "fixture", ContractSHA256: f.descriptor.ContractSHA256, Recipient: f.recipient, Operations: []string{"files.fixture.list"}, Config: config}
		body, _ := json.Marshal(input)
		req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v1/execution/connections", bytes.NewReader(body))
		f.client.Identity.Sign(req, body)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("raw signed config introduced credential material")
		}
	}
}

func TestCentralServerRestartRetainsInvocationWithoutProviderReplay(t *testing.T) {
	f := newCentralServerFixture(t)
	c := f.create(t)
	input := f.invocation(c, "before-restart", "files.fixture.list")
	if _, err := f.client.Invoke(context.Background(), c.ID, input); err != nil {
		t.Fatal(err)
	}
	old := f.backend.Load()
	path := f.vault.path
	if err := f.vault.Close(); err != nil {
		t.Fatal(err)
	}
	newVault := vaultTestOpen(t, path)
	config := old.config
	config.Vault = newVault
	backend, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	f.backend.Store(backend)
	result, err := f.client.Invoke(context.Background(), c.ID, input)
	if err != nil || result.Status != "succeeded" || result.ResultAvailable || f.executor.calls != 1 {
		t.Fatal("restart replay executed provider or returned old content")
	}
	if _, err := f.client.Connection(context.Background(), c.ID, f.recipient); err != nil {
		t.Fatal("connection lost at restart")
	}
}

func TestCentralServerAuthenticatesExactSignedBodyAndNonce(t *testing.T) {
	f := newCentralServerFixture(t)
	input := CreateRequest{CatalogID: "fixture", ContractSHA256: f.descriptor.ContractSHA256, Recipient: f.recipient, Operations: []string{"files.fixture.list"}}
	body, _ := json.Marshal(input)
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v1/execution/connections", bytes.NewReader(body))
	f.client.Identity.Sign(req, body)
	send := func(data []byte) int {
		request := req.Clone(context.Background())
		request.Body = io.NopCloser(bytes.NewReader(data))
		request.ContentLength = int64(len(data))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return response.StatusCode
	}
	if status := send(body); status != 201 {
		t.Fatalf("valid signed request status %d", status)
	}
	if status := send(body); status != 401 {
		t.Fatal("same nonce replay admitted")
	}
	// Fresh nonce: rejection below must follow body/signature mismatch, not
	// the nonce consumed by the successful first request.
	f.client.Identity.Sign(req, body)
	input.Recipient.SubjectID = "other"
	changed, _ := json.Marshal(input)
	if status := send(changed); status != 401 {
		t.Fatal("signature did not bind exact recipient/body")
	}
	state, _ := f.vault.View()
	if len(state.Connections) != 1 {
		t.Fatal("invalid signature created connection")
	}
}

func TestCentralCompiledCatalogDescriptorsRemainConstructibleAndHonest(t *testing.T) {
	runtime, err := connectors.NewRuntime(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, key := fixtureSigningKey(t)
	items := BuildDescriptors(runtime, map[string]bool{}, map[string]oauth.Provider{})
	if len(items) != len(connectors.Catalog()) {
		t.Fatal("unqualified cards disappeared")
	}
	for _, d := range items {
		if d.Item.Available {
			t.Fatal("operator-unqualified connector advertised available")
		}
	}
	if _, err := NewRegistry(1, "fixture-key", key, items); err != nil {
		t.Fatalf("compiled catalog cannot form signed registry: %v", err)
	}
}
