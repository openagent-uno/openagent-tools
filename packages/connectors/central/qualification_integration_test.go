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

// The catalog, Runtime, Gmail adapter, broker signature/consent/PKCE exchange,
// credential vault, and public client are real. Only provider HTTP is synthetic;
// these tests neither enroll a real account nor qualify live Gmail access.
type qualificationFixture struct {
	http       *httptest.Server
	client     *Client
	backend    atomic.Pointer[Server]
	clock      atomic.Int64
	version    atomic.Int64
	exchanges  atomic.Int64
	refreshes  atomic.Int64
	apiCalls   atomic.Int64
	tokenHook  atomic.Pointer[func()]
	apiHook    atomic.Pointer[func()]
	vault      *Vault
	config     Config
	rule       QualificationAdmission
	descriptor Descriptor
	key        ed25519.PrivateKey
	wire       *centralOAuthWireGuard
	stateDir   string
}

type qualificationHTTP struct{ fixture *qualificationFixture }

func (d qualificationHTTP) Do(r *http.Request) (*http.Response, error) {
	f := d.fixture
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "www.googleapis.com" ||
		r.URL.Path != "/gmail/v1/users/me/messages" ||
		r.Header.Get("Authorization") != fmt.Sprintf("Bearer CENTRAL-ACCESS-%d", f.version.Load()) {
		return nil, errors.New("unexpected synthetic Gmail boundary request")
	}
	f.apiCalls.Add(1)
	if hook := f.apiHook.Load(); hook != nil {
		(*hook)()
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"messages":[{"id":"synthetic-message","threadId":"synthetic-thread"}],"resultSizeEstimate":1}`)), Request: r}, nil
}

func newQualificationFixture(t *testing.T) *qualificationFixture {
	t.Helper()
	root := t.TempDir()
	f := &qualificationFixture{stateDir: filepath.Join(root, "state"), wire: &centralOAuthWireGuard{}}
	f.clock.Store(time.Now().UTC().UnixNano())
	if err := os.Mkdir(f.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "app-secret")
	if err := os.WriteFile(secret, []byte("synthetic-app-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	f.http = httptest.NewUnstartedServer(nil)
	base := "https://" + f.http.Listener.Addr().String()
	provider := oauth.Provider{ID: "gmail", AppID: "fixture-google-app", ClientID: "fixture-client", SecretFile: secret,
		AuthorizationURL: base + "/provider/authorize", TokenURL: base + "/provider/token", RedirectURI: base + "/v1/oauth/gmail/callback",
		Scopes: []string{gmailReadScope, gmailComposeScope}, PKCE: true}
	store, err := auth.NewStore(filepath.Join(f.stateDir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewServer(store, oauth.Engine{AllowLoopback: true}, []oauth.Provider{provider}, base, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := connectors.NewRuntime(qualificationHTTP{f})
	if err != nil {
		t.Fatal(err)
	}
	public, key := fixtureSigningKey(t)
	f.key = key
	registry := fixtureRegistry(t, key, 9, BuildDescriptors(runtime, nil, broker.Providers)...)
	f.descriptor, _ = registry.Lookup("gmail")
	if !qualificationDescriptor(f.descriptor) || f.descriptor.Item.Available {
		t.Fatal("fixture must use the seven compiled Gmail operations, publicly unavailable")
	}
	f.vault = vaultTestOpen(t, filepath.Join(f.stateDir, "vault.json"))
	f.config = Config{Auth: broker, Vault: f.vault, Registry: registry, Executor: runtime}
	f.http.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/provider/token" {
			if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("client_id") != provider.ClientID || r.Form.Get("client_secret") != "synthetic-app-secret" {
				t.Error("OAuth client/secret boundary changed")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				if r.Form.Get("code") != "fixture-code" || r.Form.Get("code_verifier") == "" || r.Form.Get("redirect_uri") != provider.RedirectURI {
					t.Error("OAuth code/PKCE/callback boundary changed")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				f.exchanges.Add(1)
			case "refresh_token":
				if r.Form.Get("refresh_token") != fmt.Sprintf("CENTRAL-REFRESH-%d", f.version.Load()) {
					t.Error("refresh did not use the current vault credential")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				f.refreshes.Add(1)
			default:
				t.Error("unexpected synthetic OAuth grant")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if hook := f.tokenHook.Load(); hook != nil {
				(*hook)()
			}
			version := f.version.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("CENTRAL-ACCESS-%d", version),
				"refresh_token": fmt.Sprintf("CENTRAL-REFRESH-%d", version), "expires_in": 3600, "scope": gmailReadScope + " " + gmailComposeScope})
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
	providerClient := f.http.Client()
	broker.Engine.Client = providerClient
	f.wire.transport = providerClient.Transport
	identity, err := auth.NewIdentity("qualification-host", "Qualification fixture host")
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Client{Transport: f.wire, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	registration := &auth.Client{Origin: base, Identity: identity, HTTP: transport, AllowLoopback: true}
	if err := registration.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.client = &Client{Origin: base, Identity: identity, HTTP: transport, AllowLoopback: true, TrustKeys: map[string]ed25519.PublicKey{"fixture-key": public}}
	f.rule = QualificationAdmission{ID: "gmail-qa-fixture", Revision: 1, CatalogID: "gmail", InstallationID: identity.ID(),
		Recipient: Recipient{"workspace", "owner"}, ExpiresAt: f.now().Add(time.Hour)}
	f.replace(t, &f.rule, registry)
	return f
}

func (f *qualificationFixture) now() time.Time { return time.Unix(0, f.clock.Load()).UTC() }

func (f *qualificationFixture) replace(t *testing.T, rule *QualificationAdmission, registry *Registry) {
	t.Helper()
	config := f.config
	config.Vault, config.Registry, config.GmailQualification = f.vault, registry, rule
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	server.now = f.now
	f.backend.Store(server)
}

func (f *qualificationFixture) createRequest() CreateRequest {
	return CreateRequest{CatalogID: "gmail", ContractSHA256: f.descriptor.ContractSHA256, Recipient: f.rule.Recipient,
		QualificationID: f.rule.ID, Operations: append(append([]string{}, f.descriptor.Item.ReadTools...), f.descriptor.Item.AgentTools...)}
}

func (f *qualificationFixture) pending(t *testing.T) Connection {
	t.Helper()
	c, err := f.client.Create(context.Background(), f.createRequest())
	if err != nil || c.Status != "pending" || c.QualificationID != f.rule.ID || c.AuthorizationURL == "" {
		t.Fatalf("qualification did not start the normal OAuth transaction: %v", err)
	}
	return c
}

func (f *qualificationFixture) approve(t *testing.T, c Connection) {
	t.Helper()
	page, err := f.client.HTTP.Get(c.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if readErr != nil || page.StatusCode != 200 || len(page.Cookies()) != 1 || !bytes.Contains(body, []byte("central credential vault")) {
		t.Fatal("normal central consent disclosure unavailable")
	}
	cookie := page.Cookies()[0]
	req, _ := http.NewRequest(http.MethodPost, c.AuthorizationURL, strings.NewReader(url.Values{"csrf": {cookie.Value}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.http.URL)
	req.AddCookie(cookie)
	response, err := f.client.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr = io.ReadAll(response.Body)
	_ = response.Body.Close()
	match := regexp.MustCompile(`<a href="([^"]+)"`).FindSubmatch(body)
	if readErr != nil || response.StatusCode != 200 || len(match) != 2 {
		t.Fatal("normal consent form rejected")
	}
	link, err := url.Parse(html.UnescapeString(string(match[1])))
	if err != nil || link.Scheme+"://"+link.Host != f.http.URL || link.Path != "/provider/authorize" || link.Query().Get("state") == "" || link.Query().Get("code_challenge") == "" {
		t.Fatal("OAuth state/PKCE/endpoint mismatch")
	}
	callback, err := f.client.HTTP.Get(f.http.URL + "/v1/oauth/gmail/callback?" + url.Values{"state": {link.Query().Get("state")}, "code": {"fixture-code"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, callback.Body)
	_ = callback.Body.Close()
	if callback.StatusCode != 200 {
		t.Fatal("normal provider callback rejected")
	}
}

func (f *qualificationFixture) connect(t *testing.T) Connection {
	t.Helper()
	c := f.pending(t)
	f.approve(t, c)
	connected, err := f.client.Connection(context.Background(), c.ID, f.rule.Recipient)
	if err != nil || connected.Status != "connected" || len(connected.Operations) != 7 || connected.QualificationID != f.rule.ID || f.exchanges.Load() != 1 {
		t.Fatalf("normal qualification completion failed: %v", err)
	}
	return connected
}

func (f *qualificationFixture) invokeRequest(c Connection, id string) InvokeRequest {
	return InvokeRequest{Recipient: f.rule.Recipient, ContractSHA256: c.ContractSHA256, GrantRevision: c.GrantRevision,
		InvocationID: id, Operation: "outreach.gmail.messages.list", Arguments: json.RawMessage(`{"max_results":1}`)}
}

func (f *qualificationFixture) assertPrivate(t *testing.T) {
	t.Helper()
	if f.wire.leaked.Load() {
		t.Fatal("host/browser wire received reusable credentials")
	}
	err := filepath.WalkDir(f.stateDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil && centralOAuthHasSecret(data) {
			return errors.New("plaintext credential in persisted state")
		}
		return err
	})
	if err != nil {
		t.Fatal("private credential persistence invariant failed")
	}
}

func TestGmailQualificationRealRuntimeLifecycleAndVaultRestart(t *testing.T) {
	f := newQualificationFixture(t)
	c := f.connect(t)
	ctx := context.Background()
	request := f.invokeRequest(c, "first-read")
	result, err := f.client.Invoke(ctx, c.ID, request)
	if err != nil || result.Status != "succeeded" || !result.ResultAvailable || f.apiCalls.Load() != 1 {
		t.Fatalf("compiled Gmail read failed: %v", err)
	}
	state, err := f.vault.View()
	if err != nil || state.Connections[c.ID].QualificationSHA256 != qualificationHash(f.rule) || !validHash(state.Connections[c.ID].QualificationSHA256) {
		t.Fatal("vault did not bind the complete qualification rule")
	}
	if _, err := f.client.Refresh(ctx, c.ID, f.rule.Recipient); err != nil || f.refreshes.Load() != 1 {
		t.Fatalf("normal held-token refresh failed: %v", err)
	}
	f.assertPrivate(t)
	if err := f.vault.Close(); err != nil {
		t.Fatal(err)
	}
	f.vault = vaultTestOpen(t, filepath.Join(f.stateDir, "vault.json"))
	f.replace(t, &f.rule, f.config.Registry)
	if replay, err := f.client.Invoke(ctx, c.ID, request); err != nil || replay.Status != "succeeded" || replay.ResultAvailable || f.apiCalls.Load() != 1 {
		t.Fatal("restart repeated provider IO or persisted provider content")
	}
	if status, err := f.client.Invocation(ctx, c.ID, request.InvocationID, f.rule.Recipient); err != nil || status.Status != "succeeded" {
		t.Fatal("restart lost durable invocation status")
	}
	if result, err := f.client.Invoke(ctx, c.ID, f.invokeRequest(c, "post-restart")); err != nil || result.Status != "succeeded" || f.apiCalls.Load() != 2 {
		t.Fatalf("compiled Gmail post-restart read failed: %v", err)
	}
	if disconnected, err := f.client.Disconnect(ctx, c.ID, f.rule.Recipient); err != nil || disconnected.Status != "disconnected" {
		t.Fatal("normal disconnect failed")
	}
	state, _ = f.vault.View()
	record := state.Connections[c.ID]
	if record.Token.AccessToken != "" || record.Token.RefreshToken != "" || record.Binding.Enabled || record.TransactionID != "" {
		t.Fatal("disconnect retained usable credential or pending consent")
	}
	f.assertPrivate(t)
}

func TestGmailQualificationChangedPolicyNeverFallsBackToPublic(t *testing.T) {
	for _, change := range []string{"expired", "removed", "revision", "expiry", "recipient", "installation", "id", "snapshot-tamper"} {
		t.Run(change, func(t *testing.T) {
			f := newQualificationFixture(t)
			c := f.connect(t)
			ctx := context.Background()
			request := f.invokeRequest(c, "prior-result")
			if _, err := f.client.Invoke(ctx, c.ID, request); err != nil {
				t.Fatal(err)
			}
			policy := f.rule
			var next *QualificationAdmission = &policy
			switch change {
			case "expired":
				f.clock.Store(f.rule.ExpiresAt.UnixNano())
			case "removed":
				next = nil
			case "revision":
				policy.Revision++
			case "expiry":
				policy.ExpiresAt = policy.ExpiresAt.Add(time.Minute)
			case "recipient":
				policy.Recipient.SubjectID = "another-owner"
			case "installation":
				policy.InstallationID = strings.Repeat("a", 64)
			case "id":
				policy.ID = "another-qualification"
			case "snapshot-tamper":
				if err := f.vault.Update(func(state *VaultState) error {
					record := state.Connections[c.ID]
					record.QualificationSHA256 = strings.Repeat("0", 64)
					state.Connections[c.ID] = record
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			// Deliberately promote Gmail publicly: this must not repair an old
			// private grant whose immutable admission was removed or changed.
			runtime := f.config.Executor.(*connectors.Runtime)
			public := fixtureRegistry(t, f.key, 10, BuildDescriptors(runtime, map[string]bool{"gmail": true}, f.config.Auth.Providers)...)
			f.replace(t, next, public)
			if _, err := f.client.Connection(ctx, c.ID, f.rule.Recipient); err == nil {
				t.Fatal("changed qualification remained readable")
			}
			if _, err := f.client.Complete(ctx, c.ID, f.rule.Recipient); err == nil {
				t.Fatal("changed qualification remained completable")
			}
			if _, err := f.client.Refresh(ctx, c.ID, f.rule.Recipient); err == nil {
				t.Fatal("changed qualification refreshed")
			}
			if _, err := f.client.Invoke(ctx, c.ID, request); err == nil {
				t.Fatal("changed qualification replayed a durable result")
			}
			if _, err := f.client.Invocation(ctx, c.ID, request.InvocationID, f.rule.Recipient); err == nil {
				t.Fatal("changed qualification exposed invocation status")
			}
			if f.apiCalls.Load() != 1 || f.refreshes.Load() != 0 || f.exchanges.Load() != 1 {
				t.Fatal("denied private operation performed provider IO")
			}
			if _, err := f.client.Disconnect(ctx, c.ID, Recipient{"workspace", "intruder"}); err == nil {
				t.Fatal("wrong recipient disconnected a private grant")
			}
			if disconnected, err := f.client.Disconnect(ctx, c.ID, f.rule.Recipient); err != nil || disconnected.Status != "disconnected" {
				t.Fatal("owned disconnect was blocked by retired qualification")
			}
			f.assertPrivate(t)
		})
	}
}

func TestGmailQualificationPendingExchangeAdmission(t *testing.T) {
	for _, stage := range []string{"before-consent", "before-exchange", "during-exchange"} {
		t.Run(stage, func(t *testing.T) {
			f := newQualificationFixture(t)
			c := f.pending(t)
			if stage != "before-consent" {
				f.approve(t, c)
			}
			if stage == "during-exchange" {
				hook := func() { f.clock.Store(f.rule.ExpiresAt.UnixNano()) }
				f.tokenHook.Store(&hook)
			} else {
				f.clock.Store(f.rule.ExpiresAt.UnixNano())
			}
			if stage == "before-consent" {
				page, err := f.client.HTTP.Get(c.AuthorizationURL)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, page.Body)
				_ = page.Body.Close()
				if page.StatusCode == http.StatusOK {
					t.Fatal("expired qualification still offered provider consent")
				}
			}
			if _, err := f.client.Complete(context.Background(), c.ID, f.rule.Recipient); err == nil {
				t.Fatal("expired pending qualification became a grant")
			}
			state, _ := f.vault.View()
			if state.Connections[c.ID].Token.AccessToken != "" || state.Connections[c.ID].Public.Status == "connected" || f.apiCalls.Load() != 0 {
				t.Fatal("expired pending qualification persisted or used a token")
			}
			want := int64(0)
			if stage == "during-exchange" {
				want = 1
			}
			if f.exchanges.Load() != want {
				t.Fatal("code exchange did not respect admission boundary")
			}
			f.assertPrivate(t)
		})
	}
}

func TestGmailQualificationRechecksAfterProviderIO(t *testing.T) {
	for _, operation := range []string{"read", "refresh"} {
		t.Run(operation, func(t *testing.T) {
			f := newQualificationFixture(t)
			c := f.connect(t)
			before, _ := f.vault.View()
			hook := func() { f.clock.Store(f.rule.ExpiresAt.UnixNano()) }
			if operation == "read" {
				f.apiHook.Store(&hook)
				if _, err := f.client.Invoke(context.Background(), c.ID, f.invokeRequest(c, "expires-during-io")); err == nil {
					t.Fatal("expired qualification published provider result")
				}
				after, _ := f.vault.View()
				if after.Invocations[c.ID+":expires-during-io"].Status == "succeeded" || f.apiCalls.Load() != 1 {
					t.Fatal("expired qualification durably accepted provider success")
				}
			} else {
				f.tokenHook.Store(&hook)
				if _, err := f.client.Refresh(context.Background(), c.ID, f.rule.Recipient); err == nil {
					t.Fatal("expired qualification accepted refreshed credential")
				}
				after, _ := f.vault.View()
				if after.Connections[c.ID].Token.AccessToken != before.Connections[c.ID].Token.AccessToken || f.refreshes.Load() != 1 {
					t.Fatal("expired qualification replaced its held token")
				}
			}
			f.assertPrivate(t)
		})
	}
}

type qualificationToolsFence struct {
	Executor
	afterTools func()
}

func (e qualificationToolsFence) Tools(binding connectors.Binding) ([]domain.Operation, error) {
	tools, err := e.Executor.Tools(binding)
	e.afterTools()
	return tools, err
}

func TestGmailQualificationCompletionRechecksAfterActualToolBinding(t *testing.T) {
	f := newQualificationFixture(t)
	c := f.pending(t)
	f.approve(t, c)
	// Keep the compiled Runtime's actual binding/schema/scope validation, but
	// advance admission time immediately after it returns, inside acceptance.
	f.config.Executor = qualificationToolsFence{Executor: f.config.Executor, afterTools: func() {
		f.clock.Store(f.rule.ExpiresAt.UnixNano())
	}}
	f.replace(t, &f.rule, f.config.Registry)
	if _, err := f.client.Complete(context.Background(), c.ID, f.rule.Recipient); err == nil {
		t.Fatal("tool binding crossed admission expiry before vault commit")
	}
	state, err := f.vault.View()
	if err != nil {
		t.Fatal(err)
	}
	record := state.Connections[c.ID]
	if record.Public.Status != "pending" || record.Token.AccessToken != "" || record.Token.RefreshToken != "" || f.exchanges.Load() != 1 || f.apiCalls.Load() != 0 {
		t.Fatal("failed final completion fence persisted a usable grant")
	}
	f.assertPrivate(t)
}
