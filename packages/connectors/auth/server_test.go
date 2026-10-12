package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

type fixture struct {
	server   *Server
	http     *httptest.Server
	provider *httptest.Server
	path     string
	calls    atomic.Int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte("test-app-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	f.provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := f.calls.Add(1)
		writeJSON(w, 200, map[string]any{"access_token": "user-access-" + strconv.FormatInt(n, 10), "refresh_token": "user-refresh-" + strconv.FormatInt(n, 10), "expires_in": 3600, "refresh_token_expires_in": 7776000, "scope": "read_products,read_inventory"})
	}))
	t.Cleanup(f.provider.Close)
	f.path = filepath.Join(dir, "metadata.json")
	store, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	p := oauth.Provider{ID: "shopify", AppID: "openagent-shopify-production", ClientID: "test-client", SecretFile: secretPath, AuthorizationURL: f.provider.URL + "/authorize", TokenURL: f.provider.URL + "/token", RedirectURI: "http://127.0.0.1/v1/oauth/shopify/callback", Scopes: []string{"read_products", "read_inventory"}}
	f.server, err = NewServer(store, oauth.Engine{AllowLoopback: true}, []oauth.Provider{p}, "http://127.0.0.1", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.http = httptest.NewServer(f.server)
	t.Cleanup(f.http.Close)
	f.server.Origin = f.http.URL
	p.RedirectURI = f.http.URL + "/v1/oauth/shopify/callback"
	f.server.Providers[p.ID] = p
	return f
}
func (f *fixture) client(t *testing.T, name string) *Client {
	t.Helper()
	identity, err := NewIdentity("test-product", name)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{Origin: f.http.URL, Identity: identity, AllowLoopback: true}
	if err = client.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}
func (f *fixture) consent(t *testing.T, c *Client) Transaction {
	t.Helper()
	tx, err := c.Start(context.Background(), Start{Provider: "shopify", Shop: "example.myshopify.com"})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the real disclosure form and its cookie/Origin fence.
	browser := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	page, err := browser.Get(tx.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, page.Body)
	_ = page.Body.Close()
	cookies := page.Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing consent cookie")
	}
	form := url.Values{"csrf": {cookies[0].Value}, "shop": {"example.myshopify.com"}}
	request, _ := http.NewRequest("POST", tx.AuthorizationURL, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", f.http.URL)
	request.AddCookie(cookies[0])
	consent, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = consent.Body.Close()
	if consent.StatusCode != 303 {
		t.Fatalf("consent status %d", consent.StatusCode)
	}
	launch, _ := url.Parse(consent.Header.Get("Location"))
	// Verify the signed provider callback over real HTTP, not by modifying the transaction.
	q := url.Values{"state": {launch.Query().Get("state")}, "code": {"provider-code"}, "shop": {"example.myshopify.com"}, "timestamp": {strconv.FormatInt(time.Now().Unix(), 10)}}
	mac := hmac.New(sha256.New, []byte("test-app-secret"))
	mac.Write([]byte(q.Encode()))
	q.Set("hmac", hex.EncodeToString(mac.Sum(nil)))
	res, err := http.Get(f.http.URL + "/v1/oauth/shopify/callback?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("callback status %d", res.StatusCode)
	}
	return tx
}
func TestOAuthRedeemIsInstallationBoundAndSingleUse(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "Server A")
	b := f.client(t, "Server B")
	tx := f.consent(t, a)
	if _, err := b.Redeem(context.Background(), tx.ID); err == nil {
		t.Fatal("other installation redeemed consent")
	}
	rotation, err := a.Redeem(context.Background(), tx.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Token.AppID != "openagent-shopify-production" || rotation.Token.Version != 1 {
		t.Fatal("app binding or generation missing")
	}
	if _, err = a.Redeem(context.Background(), tx.ID); err == nil {
		t.Fatal("consent replay accepted")
	}
	if f.calls.Load() != 1 {
		t.Fatal("provider exchange repeated")
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"user-access", "user-refresh", "provider-code", "test-app-secret"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("persisted secret category %s", secret)
		}
	}
}
func TestTwoServersRotateAndRecoverWithoutBrokerTokenStorage(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "Server A")
	b := f.client(t, "Server B")
	ctx := context.Background()
	first, err := a.Redeem(ctx, f.consent(t, a).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := b.Redeem(ctx, f.consent(t, b).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Publish(ctx, second); err != nil {
		t.Fatal(err)
	}
	mail, err := a.Mail(ctx)
	if err != nil || len(mail.Envelopes) != 1 {
		t.Fatalf("missing synchronization: %v", err)
	}
	data, err := Open(a.Identity, mail.Installations[b.Identity.ID()], mail.Envelopes[0], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var current oauth.Token
	if json.Unmarshal(data, &current) != nil {
		t.Fatal("invalid token wire")
	}
	if err = a.Commit(ctx, second.Group, current.Version); err != nil {
		t.Fatal(err)
	}
	third, err := a.Refresh(ctx, "shopify", current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Refresh(ctx, "shopify", second.Token); err == nil {
		t.Fatal("parallel renewal accepted before durable commit")
	}
	if err = a.Publish(ctx, third); err != nil {
		t.Fatal(err)
	}
	// Simulate broker restart losing its temporary encrypted mailbox.
	f.server.mu.Lock()
	f.server.mail = map[string][]Envelope{}
	f.server.mu.Unlock()
	recovery, err := b.Recover(ctx, third.Group)
	if err != nil || recovery.Reconnect || len(recovery.Members) != 1 {
		t.Fatalf("cannot locate updated peer: %v", err)
	}
	requests, err := a.Mail(ctx)
	if err != nil || len(requests.Recoveries) != 1 {
		t.Fatalf("peer did not receive recovery request: %v", err)
	}
	body, _ := json.Marshal(third.Token)
	e, err := Seal(a.Identity, requests.Recoveries[0].Recipient, third.Group, third.Token.Version, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Send(ctx, e); err != nil {
		t.Fatal(err)
	}
	received, err := b.Mail(ctx)
	if err != nil || len(received.Envelopes) != 1 {
		t.Fatalf("peer response unavailable: %v", err)
	}
	if _, err = Open(b.Identity, received.Installations[a.Identity.ID()], received.Envelopes[0], time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = b.Disconnect(ctx, third.Group); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Recover(ctx, third.Group); err == nil {
		t.Fatal("disconnected installation retained group access")
	}
}
func TestEnvelopeBindsRecipientVersionAndExpiry(t *testing.T) {
	a, _ := NewIdentity("a", "A")
	b, _ := NewIdentity("b", "B")
	other, _ := NewIdentity("c", "C")
	now := time.Now().UTC()
	e, err := Seal(a, b.Installation(), "group", 8, []byte("secret"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(other, a.Installation(), e, now); err == nil {
		t.Fatal("wrong recipient decrypted")
	}
	tampered := e
	tampered.Version++
	if _, err = Open(b, a.Installation(), tampered, now); err == nil {
		t.Fatal("generation not signed")
	}
	if _, err = Open(b, a.Installation(), e, now.Add(11*time.Minute)); err == nil {
		t.Fatal("expired envelope decrypted")
	}
}
func TestSignedRequestsRejectReplayAndBodySubstitution(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "A")
	body := []byte(`{"provider":"shopify","shop":"example.myshopify.com"}`)
	r, _ := http.NewRequest("POST", f.http.URL+"/v1/transactions", strings.NewReader(string(body)))
	c.Identity.Sign(r, body)
	headers := r.Header.Clone()
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatal(res.StatusCode)
	}
	replay, _ := http.NewRequest("POST", f.http.URL+"/v1/transactions", strings.NewReader(string(body)))
	replay.Header = headers
	res, err = http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("signature replay accepted")
	}
}
func TestWebhookIsDurableDeduplicatedAndScoped(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "A")
	other := f.client(t, "Unrelated")
	rotation, err := a.Redeem(context.Background(), f.consent(t, a).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Publish(context.Background(), rotation); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"shop_id":123,"shop_domain":"example.myshopify.com","customer":{"id":7,"email":"private@example.com"},"orders_to_redact":[9],"irrelevant":"not-retained"}`)
	for n := 0; n < 2; n++ {
		r, _ := http.NewRequest("POST", f.http.URL+"/v1/webhooks/shopify", strings.NewReader(string(body)))
		mac := hmac.New(sha256.New, []byte("test-app-secret"))
		mac.Write(body)
		r.Header.Set("X-Shopify-Hmac-Sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		r.Header.Set("X-Shopify-Shop-Domain", "example.myshopify.com")
		r.Header.Set("X-Shopify-Topic", "customers/redact")
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode)
		}
	}
	store, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.snapshot().Events) != 1 {
		t.Fatal("webhook not deduplicated")
	}
	events, err := a.Events(context.Background())
	if err != nil || len(events) != 1 {
		t.Fatalf("missing delivery: %v", err)
	}
	unauthorized, err := other.Events(context.Background())
	if err != nil || len(unauthorized) != 0 {
		t.Fatal("webhook leaked to unrelated installation")
	}
	data, _ := os.ReadFile(f.path)
	if strings.Contains(string(data), "private@example.com") || strings.Contains(string(data), "not-retained") {
		t.Fatal("webhook was not minimized and encrypted")
	}
	if err = a.Acknowledge(context.Background(), events[0].ID); err != nil {
		t.Fatal(err)
	}
	if events, err = a.Events(context.Background()); err != nil || len(events) != 0 {
		t.Fatal("acknowledged delivery repeated")
	}
}

func TestExpiredExchangeIsPersistedAndSavedCheckpointCanRecover(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "A")
	ctx := context.Background()
	first, err := a.Redeem(ctx, f.consent(t, a).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	p := f.server.Providers["shopify"]
	id, err := f.server.beginRotation(p, "example.myshopify.com", a.Identity.ID(), "crashed-exchange", first.Token.Version, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.server.Store.update(func(st *State) error { st.Groups[id].PendingUntil = time.Now().Add(-time.Minute); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Refresh(ctx, "shopify", first.Token); err == nil {
		t.Fatal("crashed exchange reused prior generation")
	}
	restarted, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.snapshot().Groups[id].Reconnect {
		t.Fatal("recovery requirement was rolled back on denial")
	}
	recovery, err := a.Recover(ctx, id)
	if err != nil || !recovery.Reconnect {
		t.Fatal("missing new-consent requirement")
	}
	second, err := a.Redeem(ctx, f.consent(t, a).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.server.Store.update(func(st *State) error { st.Groups[id].PendingUntil = time.Now().Add(-time.Minute); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Recover(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(ctx, id, second.Token.Version); err != nil {
		t.Fatal(err)
	}
	if f.server.Store.snapshot().Groups[id].Reconnect {
		t.Fatal("durably saved checkpoint did not recover")
	}
}
func TestPeerTokenMustMatchBrokerGenerationAndPermissions(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "A")
	b := f.client(t, "B")
	ctx := context.Background()
	first, err := a.Redeem(ctx, f.consent(t, a).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	current, err := b.Redeem(ctx, f.consent(t, b).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Publish(ctx, current); err != nil {
		t.Fatal(err)
	}
	mail, err := a.Mail(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info := mail.Groups[current.Group]
	if !info.Validates(current.Token) {
		t.Fatal("valid generation rejected")
	}
	altered := current.Token
	altered.AccessToken = "unissued-token"
	if info.Validates(altered) {
		t.Fatal("unissued peer token accepted")
	}
	altered = current.Token
	altered.Scopes = []string{"read_products"}
	if info.Validates(altered) {
		t.Fatal("peer reduced permissions without provider confirmation")
	}
	altered = current.Token
	future := time.Now().Add(time.Hour)
	altered.AuthorizedAt = &future
	if info.Validates(altered) {
		t.Fatal("peer forged authorization timestamp")
	}
}

func TestConcurrentShopifyRenewalsReachProviderOnce(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "A")
	b := f.client(t, "B")
	ctx := context.Background()
	first, err := a.Redeem(ctx, f.consent(t, a).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	current, err := b.Redeem(ctx, f.consent(t, b).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Publish(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err = a.Commit(ctx, current.Group, current.Token.Version); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 20)
	before := f.calls.Load()
	for i := 0; i < 20; i++ {
		client := a
		if i%2 == 1 {
			client = b
		}
		go func(c *Client) { <-start; _, err := c.Refresh(ctx, "shopify", current.Token); results <- err }(client)
	}
	close(start)
	successes := 0
	for i := 0; i < 20; i++ {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 || f.calls.Load() != before+1 {
		t.Fatalf("successes=%d provider requests=%d", successes, f.calls.Load()-before)
	}
}
