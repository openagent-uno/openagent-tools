package central

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

func TestClientSignsRecipientBodiesAndUsesOpaqueHandleRoutes(t *testing.T) {
	identity, err := auth.NewIdentity("fixture-host", "Fixture host")
	if err != nil {
		t.Fatal(err)
	}
	recipient := Recipient{WorkspaceID: "workspace", SubjectID: "owner"}
	descriptor := fixtureDescriptor("fixture")
	contract := ComputeContract(descriptor)
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		message := r.Method + "\n" + r.URL.EscapedPath() + "\n" + r.URL.RawQuery + "\n" + r.Header.Get("X-OpenAgent-Time") + "\n" + r.Header.Get("X-OpenAgent-Nonce") + "\n" + hex.EncodeToString(digest[:])
		signature, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-OpenAgent-Signature"))
		if r.Method != http.MethodPost || r.Header.Get("X-OpenAgent-Installation") != identity.ID() || !ed25519.Verify(identity.PrivateKey.Public().(ed25519.PublicKey), []byte(message), signature) {
			t.Error("request not signed over exact recipient/body/route")
		}
		var binding struct {
			Recipient Recipient `json:"recipient"`
		}
		if json.Unmarshal(body, &binding) != nil || binding.Recipient != recipient {
			t.Error("recipient not carried in signed request")
		}
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/invoke") || strings.Contains(r.URL.Path, "/invocations/") {
			_ = json.NewEncoder(w).Encode(InvocationResult{InvocationID: "invoke-one", Status: "pending"})
			return
		}
		status := "connected"
		if strings.HasSuffix(r.URL.Path, "/disconnect") {
			status = "disconnected"
		}
		_ = json.NewEncoder(w).Encode(Connection{Protocol: Protocol, ID: "opaque-one", CatalogID: "fixture", ContractSHA256: contract,
			Recipient: recipient, Operations: []string{"files.fixture.list"}, GrantRevision: 1, Status: status})
	}))
	defer server.Close()
	client := &Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
	ctx := context.Background()
	if _, err := client.Create(ctx, CreateRequest{CatalogID: "fixture", ContractSHA256: contract, Recipient: recipient, Operations: []string{"files.fixture.list"}}); err != nil {
		t.Fatal(err)
	}
	for _, method := range []func(context.Context, string, Recipient) (Connection, error){client.Connection, client.Complete, client.Refresh, client.Disconnect} {
		if _, err := method(ctx, "opaque-one", recipient); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Invoke(ctx, "opaque-one", InvokeRequest{Recipient: recipient, ContractSHA256: contract, GrantRevision: 1,
		InvocationID: "invoke-one", Operation: "files.fixture.list", Arguments: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Invocation(ctx, "opaque-one", "invoke-one", recipient); err != nil {
		t.Fatal(err)
	}
	expected := []string{"/v1/execution/connections", "/v1/execution/connections/opaque-one/status", "/v1/execution/connections/opaque-one/complete",
		"/v1/execution/connections/opaque-one/refresh", "/v1/execution/connections/opaque-one/disconnect", "/v1/execution/connections/opaque-one/invoke", "/v1/execution/connections/opaque-one/invocations/invoke-one"}
	if strings.Join(paths, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("wrong public routes: %v", paths)
	}
}

func TestClientRejectsRecipientDriftSecretsAndGrantExpansion(t *testing.T) {
	identity, _ := auth.NewIdentity("fixture", "Fixture")
	r := Recipient{"workspace", "owner"}
	contract := ComputeContract(fixtureDescriptor("fixture"))
	base := Connection{Protocol: Protocol, ID: "opaque", CatalogID: "fixture", ContractSHA256: contract,
		Recipient: r, Operations: []string{"files.fixture.list"}, Status: "pending"}
	for _, mode := range []string{"recipient", "contract", "operation", "secret", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				value := base
				switch mode {
				case "recipient":
					value.Recipient.SubjectID = "other"
				case "contract":
					value.ContractSHA256 = strings.Repeat("f", 64)
				case "operation":
					value.Operations = []string{"files.fixture.delete"}
				case "secret":
					data, _ := json.Marshal(value)
					_, _ = w.Write(append(data[:len(data)-1], []byte(`,"access_token":"PRIVATE_CANARY"}`)...))
					return
				case "duplicate":
					data, _ := json.Marshal(value)
					_, _ = w.Write(append(data[:len(data)-1], []byte(`,"status":"connected"}`)...))
					return
				}
				_ = json.NewEncoder(w).Encode(value)
			}))
			defer server.Close()
			client := &Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
			_, err := client.Create(context.Background(), CreateRequest{CatalogID: "fixture", ContractSHA256: contract, Recipient: r, Operations: base.Operations})
			if !errors.Is(err, ErrInvalidResponse) || strings.Contains(err.Error(), "PRIVATE_CANARY") {
				t.Fatalf("unsafe response accepted or leaked: %v", err)
			}
		})
	}
}

func TestClientNeverFollowsRedirectOrRetriesUnknownOutcome(t *testing.T) {
	identity, _ := auth.NewIdentity("fixture", "Fixture")
	redirectCalls, firstCalls := 0, 0
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirectCalls++ }))
	defer redirect.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstCalls++
		w.Header().Set("Location", redirect.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = w.Write([]byte(`{"error":"PRIVATE_CANARY"}`))
	}))
	defer server.Close()
	// A caller-supplied redirect policy cannot weaken this boundary.
	client := &Client{Origin: server.URL, Identity: identity, AllowLoopback: true, HTTP: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}}
	_, err := client.Connection(context.Background(), "opaque", Recipient{"workspace", "owner"})
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Status != 307 || remote.Code != "request_failed" || firstCalls != 1 || redirectCalls != 0 || strings.Contains(err.Error(), "PRIVATE_CANARY") {
		t.Fatalf("redirect/retry/redaction boundary failed: %v", err)
	}
}

func TestClientBoundsBodiesAndRejectsUnsafeOriginsBeforeNetwork(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = io.WriteString(w, strings.Repeat(" ", maxDocument+1))
	}))
	defer server.Close()
	client := &Client{Origin: server.URL, AllowLoopback: true}
	if _, err := client.Catalog(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("unbounded response accepted")
	}
	client.AllowLoopback = false
	if _, err := client.Catalog(context.Background()); !errors.Is(err, auth.ErrDenied) {
		t.Fatal("cleartext origin accepted")
	}
	client.Origin = "https://example.invalid/prefix"
	if _, err := client.Catalog(context.Background()); !errors.Is(err, auth.ErrDenied) {
		t.Fatal("origin path accepted")
	}
	client.Origin, client.AllowLoopback = server.URL, true
	if _, err := client.Connection(context.Background(), "../other", Recipient{"workspace", "owner"}); !errors.Is(err, auth.ErrDenied) {
		t.Fatal("path injection accepted")
	}
	if calls != 1 {
		t.Fatalf("invalid input reached network: %d", calls)
	}
}
