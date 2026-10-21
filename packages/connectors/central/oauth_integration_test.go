//go:build darwin || linux

package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

const centralOAuthModify = "https://www.googleapis.com/auth/gmail.modify"
const centralOAuthSend = "https://www.googleapis.com/auth/gmail.send"

func centralOAuthHasSecret(data []byte) bool {
	return bytes.Contains(data, []byte("CENTRAL-ACCESS-")) || bytes.Contains(data, []byte("CENTRAL-REFRESH-"))
}

// Only the host/browser HTTP client uses this transport. The OAuth engine's
// provider connection must receive tokens, and deliberately does not use it.
type centralOAuthWireGuard struct {
	leaked    atomic.Bool
	transport http.RoundTripper
}

func (g *centralOAuthWireGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.GetBody != nil {
		copy, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(copy, (1<<20)+1))
		_ = copy.Close()
		if err != nil {
			return nil, err
		}
		if centralOAuthHasSecret(data) {
			g.leaked.Store(true)
		}
	}
	response, err := g.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	_ = response.Body.Close()
	if err != nil {
		return nil, err
	}
	if centralOAuthHasSecret(data) {
		g.leaked.Store(true)
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	return response, nil
}

// This trusted adapter receives only the credential bound by the real Runtime.
// It deliberately echoes it in synthetic provider data to test final redaction.
type centralOAuthAdapter struct {
	operations []domain.Operation
	calls      atomic.Int64
	version    atomic.Int64
}

func (*centralOAuthAdapter) Provider() string                 { return "gmail" }
func (*centralOAuthAdapter) Capability() domain.Capability    { return domain.Outreach }
func (a *centralOAuthAdapter) Operations() []domain.Operation { return a.operations }
func (a *centralOAuthAdapter) Invoke(_ context.Context, call domain.Invocation) (domain.Result, error) {
	version := a.version.Load()
	headers := http.Header{}
	if call.Connection.Provider != "gmail" || call.Principal.WorkspaceID != "workspace" ||
		call.Principal.ActorID != "owner" || call.Principal.BoundConnectionID != call.Connection.ID ||
		call.Credential.Apply(headers, "Authorization", "Bearer", time.Now()) != nil ||
		headers.Get("Authorization") != fmt.Sprintf("Bearer CENTRAL-ACCESS-%d", version) {
		return domain.Result{}, errors.New("fixture credential or recipient mismatch")
	}
	a.calls.Add(1)
	return domain.Result{Data: map[string]string{"access_echo": fmt.Sprintf("CENTRAL-ACCESS-%d", version), "refresh_echo": fmt.Sprintf("CENTRAL-REFRESH-%d", version), "value": "synthetic-result"}, Attempts: 1}, nil
}

type centralOAuthFixture struct {
	http       *httptest.Server
	client     *Client
	backend    atomic.Pointer[Server]
	adapter    *centralOAuthAdapter
	vault      *Vault
	stateDir   string
	descriptor Descriptor
	recipient  Recipient
	wire       *centralOAuthWireGuard
	exchanges  atomic.Int64
	refreshes  atomic.Int64
}

func newCentralOAuthFixture(t *testing.T, partial bool) *centralOAuthFixture {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if os.Mkdir(stateDir, 0700) != nil {
		t.Fatal("fixture state directory")
	}
	secretPath := filepath.Join(root, "app-secret")
	if os.WriteFile(secretPath, []byte("synthetic-app-secret"), 0600) != nil {
		t.Fatal("fixture app secret")
	}
	f := &centralOAuthFixture{stateDir: stateDir, recipient: Recipient{"workspace", "owner"}, wire: &centralOAuthWireGuard{}}
	f.adapter = &centralOAuthAdapter{}
	f.http = httptest.NewUnstartedServer(nil)
	base := "https://" + f.http.Listener.Addr().String()
	scopes := []string{centralOAuthModify}
	read := domain.Operation{Name: "outreach.fixture_gmail.read", Description: "Read synthetic fixture", Provider: "gmail", Capability: domain.Outreach, Risk: domain.RiskRead, Mode: domain.OperationTyped,
		InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`), RequiredScopes: []string{centralOAuthModify}, Retry: domain.RetryPolicy{MaxAttempts: 1}}
	f.adapter.operations = []domain.Operation{read}
	item := connectors.Item{ID: "fixture-gmail", Name: "Fixture Gmail", Provider: "gmail", Capability: "outreach", Auth: "oauth", Available: true, ReadTools: []string{read.Name}, AgentTools: []string{}}
	if partial {
		write := read
		write.Name = "outreach.fixture_gmail.send"
		write.Risk = domain.RiskWrite
		write.RequiredScopes = []string{centralOAuthSend}
		f.adapter.operations = append(f.adapter.operations, write)
		item.AgentTools = []string{write.Name}
		scopes = append(scopes, centralOAuthSend)
	}
	f.descriptor = Descriptor{Item: item, Operations: f.adapter.operations, Setup: Setup{Mode: "oauth", CredentialCustody: "service", Execution: "service"}}
	f.descriptor.ContractSHA256 = ComputeContract(f.descriptor)
	provider := oauth.Provider{ID: "gmail", AppID: "fixture-google-app", ClientID: "fixture-client", SecretFile: secretPath, AuthorizationURL: base + "/provider/authorize", TokenURL: base + "/provider/token", RedirectURI: base + "/v1/oauth/gmail/callback", Scopes: scopes, PKCE: true}
	store, err := auth.NewStore(filepath.Join(stateDir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewServer(store, oauth.Engine{AllowLoopback: true}, []oauth.Provider{provider}, base, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := connectors.NewRuntimeWithCatalog([]connectors.CatalogEntry{{Item: item}}, []domain.Adapter{f.adapter})
	if err != nil {
		t.Fatal(err)
	}
	f.vault = vaultTestOpen(t, filepath.Join(stateDir, "vault.json"))
	public, key := fixtureSigningKey(t)
	server, err := NewServer(Config{Auth: broker, Vault: f.vault, Registry: fixtureRegistry(t, key, 1, f.descriptor), Executor: runtime})
	if err != nil {
		t.Fatal(err)
	}
	f.backend.Store(server)
	f.http.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/provider/token" {
			if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("client_secret") != "synthetic-app-secret" || r.Form.Get("client_id") != "fixture-client" {
				t.Error("OAuth provider request lost configured secret/client binding")
				w.WriteHeader(400)
				return
			}
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				if r.Form.Get("code") != "fixture-code" || r.Form.Get("code_verifier") == "" || r.Form.Get("redirect_uri") != provider.RedirectURI {
					t.Error("exchange context mismatch")
					w.WriteHeader(400)
					return
				}
				f.exchanges.Add(1)
			case "refresh_token":
				if r.Form.Get("refresh_token") != fmt.Sprintf("CENTRAL-REFRESH-%d", f.adapter.version.Load()) {
					t.Error("refresh did not use held credential")
					w.WriteHeader(400)
					return
				}
				f.refreshes.Add(1)
			default:
				t.Error("unexpected OAuth grant request")
				w.WriteHeader(400)
				return
			}
			version := f.adapter.version.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("CENTRAL-ACCESS-%d", version), "refresh_token": fmt.Sprintf("CENTRAL-REFRESH-%d", version), "expires_in": 3600, "scope": centralOAuthModify})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/registry/") || strings.HasPrefix(r.URL.Path, "/v1/execution/") {
			f.backend.Load().ServeHTTP(w, r)
			return
		}
		broker.ServeHTTP(w, r)
	})
	f.http.StartTLS()
	t.Cleanup(f.http.Close)
	// Trust the fixture's actual TLS certificate, rather than weakening the
	// central client's HTTPS authorization-URL contract or skipping verification.
	providerClient := f.http.Client()
	broker.Engine.Client = providerClient
	f.wire.transport = providerClient.Transport
	identity, err := auth.NewIdentity("fixture-host", "Fixture recipient host")
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: f.wire, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	registration := &auth.Client{Origin: base, Identity: identity, HTTP: httpClient, AllowLoopback: true}
	if err := registration.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.client = &Client{Origin: base, Identity: identity, HTTP: httpClient, AllowLoopback: true, TrustKeys: map[string]ed25519.PublicKey{"fixture-key": public}}
	return f
}

func (f *centralOAuthFixture) connect(t *testing.T) Connection {
	t.Helper()
	names := append(append([]string{}, f.descriptor.Item.ReadTools...), f.descriptor.Item.AgentTools...)
	c, err := f.client.Create(context.Background(), CreateRequest{CatalogID: f.descriptor.Item.ID, ContractSHA256: f.descriptor.ContractSHA256, Recipient: f.recipient, Operations: names})
	if err != nil || c.Status != "pending" || c.AuthorizationURL == "" {
		t.Fatalf("pending OAuth connection unavailable: %v", err)
	}
	if _, err := f.client.Complete(context.Background(), c.ID, f.recipient); err == nil || f.exchanges.Load() != 0 {
		t.Fatal("unapproved transaction exchanged")
	}
	browser := f.client.HTTP
	page, err := browser.Get(c.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	disclosure, readErr := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if readErr != nil || page.StatusCode != 200 || len(page.Cookies()) != 1 || !bytes.Contains(disclosure, []byte("central credential vault")) || page.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatal("central consent disclosure/fence unavailable")
	}
	cookie := page.Cookies()[0]
	form := url.Values{"csrf": {cookie.Value}}
	req, _ := http.NewRequest(http.MethodPost, c.AuthorizationURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.http.URL)
	req.AddCookie(cookie)
	approved, err := browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(approved.Body)
	_ = approved.Body.Close()
	if readErr != nil || approved.StatusCode != 200 || approved.Header.Get("Location") != "" {
		t.Fatal("CSRF form not accepted")
	}
	match := regexp.MustCompile(`<a href="([^"]+)"`).FindSubmatch(body)
	if len(match) != 2 {
		t.Fatal("provider authorization link unavailable")
	}
	providerLink, err := url.Parse(html.UnescapeString(string(match[1])))
	if err != nil {
		t.Fatal("invalid provider link")
	}
	if providerLink.Scheme+"://"+providerLink.Host != f.http.URL || providerLink.Path != "/provider/authorize" || providerLink.Query().Get("state") == "" || providerLink.Query().Get("code_challenge") == "" {
		t.Fatal("provider link/state/PKCE binding changed")
	}
	callback, err := browser.Get(f.http.URL + "/v1/oauth/gmail/callback?" + url.Values{"state": {providerLink.Query().Get("state")}, "code": {"fixture-code"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, callback.Body)
	_ = callback.Body.Close()
	if callback.StatusCode != 200 {
		t.Fatal("provider callback rejected")
	}
	connected, err := f.client.Connection(context.Background(), c.ID, f.recipient)
	if err != nil || connected.Status != "connected" || connected.AuthorizationURL != "" || f.exchanges.Load() != 1 {
		t.Fatalf("completion failed: %v", err)
	}
	if _, err := f.client.Complete(context.Background(), c.ID, f.recipient); err != nil || f.exchanges.Load() != 1 {
		t.Fatal("completed consent exchanged twice")
	}
	return connected
}

func (f *centralOAuthFixture) assertPrivate(t *testing.T) {
	t.Helper()
	if f.wire.leaked.Load() {
		t.Fatal("host/browser HTTP exposed reusable credential")
	}
	err := filepath.WalkDir(f.stateDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if centralOAuthHasSecret(data) {
			return errors.New("credential persisted in plaintext state")
		}
		return nil
	})
	if err != nil {
		t.Fatal("private-state invariant failed")
	}
}

func TestCentralOAuthHTTPToVaultRuntimeRefreshRestartDisconnect(t *testing.T) {
	f := newCentralOAuthFixture(t, false)
	c := f.connect(t)
	invoke := func(id string) {
		t.Helper()
		result, err := f.client.Invoke(context.Background(), c.ID, InvokeRequest{Recipient: f.recipient, ContractSHA256: c.ContractSHA256, GrantRevision: c.GrantRevision, InvocationID: id, Operation: c.Operations[0], Arguments: json.RawMessage(`{}`)})
		if err != nil || result.Status != "succeeded" || !result.ResultAvailable || result.Result == nil {
			t.Fatalf("credential-bound read failed: %v", err)
		}
		data, _ := json.Marshal(result)
		if centralOAuthHasSecret(data) || !bytes.Contains(data, []byte("[REDACTED]")) {
			t.Fatal("provider credential echoes were not redacted")
		}
	}
	invoke("before-refresh")
	f.assertPrivate(t)
	refreshed, err := f.client.Refresh(context.Background(), c.ID, f.recipient)
	if err != nil || refreshed.GrantRevision != c.GrantRevision || f.refreshes.Load() != 1 || f.exchanges.Load() != 1 {
		t.Fatalf("held-credential refresh failed: %v", err)
	}
	invoke("after-refresh")
	f.assertPrivate(t)
	old := f.backend.Load()
	path := f.vault.path
	_ = f.vault.Close()
	f.vault = vaultTestOpen(t, path)
	config := old.config
	config.Vault = f.vault
	restarted, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	f.backend.Store(restarted)
	invoke("after-restart")
	if _, err := f.client.Disconnect(context.Background(), c.ID, f.recipient); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Refresh(context.Background(), c.ID, f.recipient); err == nil {
		t.Fatal("disconnected credential refreshed")
	}
	if _, err := f.client.Invoke(context.Background(), c.ID, InvokeRequest{Recipient: f.recipient, ContractSHA256: c.ContractSHA256, GrantRevision: c.GrantRevision, InvocationID: "after-disconnect", Operation: c.Operations[0], Arguments: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("disconnected credential invoked")
	}
	state, _ := f.vault.View()
	token := state.Connections[c.ID].Token
	if token.AccessToken != "" || token.RefreshToken != "" || f.adapter.calls.Load() != 3 || f.refreshes.Load() != 1 {
		t.Fatal("disconnect retained usable credential or performed provider IO")
	}
	f.assertPrivate(t)
}

func TestCentralOAuthPartialConsentNarrowsAdvertisedOperations(t *testing.T) {
	f := newCentralOAuthFixture(t, true)
	c := f.connect(t)
	if len(c.Operations) != 1 || c.Operations[0] != f.descriptor.Item.ReadTools[0] {
		t.Fatal("partial consent advertised ungranted operation")
	}
	_, err := f.client.Invoke(context.Background(), c.ID, InvokeRequest{Recipient: f.recipient, ContractSHA256: c.ContractSHA256, GrantRevision: c.GrantRevision, InvocationID: "ungranted-send", Operation: f.descriptor.Item.AgentTools[0], Arguments: json.RawMessage(`{}`), ApprovalID: "host-approved-action"})
	if err == nil || f.adapter.calls.Load() != 0 {
		t.Fatal("local approval expanded partial provider grant")
	}
	f.assertPrivate(t)
}
