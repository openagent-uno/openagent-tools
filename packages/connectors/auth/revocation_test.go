package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func fixtureResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func nonShopifyGrant(t *testing.T, f *fixture, c *Client) oauth.Token {
	t.Helper()
	p := f.server.Providers["shopify"]
	p.ID, p.AppID = "gmail", "google-test-registration"
	p.RedirectURI = f.http.URL + "/v1/oauth/gmail/callback"
	p.RevocationURL = f.provider.URL + "/revoke"
	p.Scopes = []string{"https://www.googleapis.com/auth/gmail.modify"}
	f.server.Providers[p.ID] = p
	token := oauth.Token{AccessToken: "google-access", RefreshToken: "google-refresh", AppID: p.AppID, Scopes: p.Scopes}
	if err := f.server.bindToken(c.Identity.ID(), p.ID, token); err != nil {
		t.Fatal(err)
	}
	return token
}

func revokeGrant(ctx context.Context, c *Client, token oauth.Token) error {
	return c.call(ctx, "POST", "/v1/revoke", map[string]any{"provider": "gmail", "app_id": token.AppID, "token": token.AccessToken, "global": true}, nil)
}

func TestRevocationFencesInFlightRefreshAndSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "A")
	other := f.client(t, "B")
	token := nonShopifyGrant(t, f, c)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	f.server.Engine.Client = doerFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.URL.Path == "/revoke" {
			return fixtureResponse(200, `{}`), nil
		}
		close(started)
		<-release
		return fixtureResponse(200, `{"access_token":"late-access","refresh_token":"late-refresh","expires_in":3600,"scope":"https://www.googleapis.com/auth/gmail.modify"}`), nil
	})
	ctx := context.Background()
	if err := revokeGrant(ctx, other, token); err == nil || calls.Load() != 0 {
		t.Fatal("another installation could revoke the grant")
	}
	result := make(chan error, 1)
	go func() { _, err := c.Refresh(ctx, "gmail", token); result <- err }()
	<-started
	if err := revokeGrant(ctx, c, token); err != nil {
		t.Fatal(err)
	}
	close(release)
	var remote *RemoteError
	if err := <-result; !errors.As(err, &remote) || remote.Status != 409 || remote.Code != "token_grant_revoked" {
		t.Fatal("in-flight refresh escaped revocation", err)
	}
	store, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Store = store
	for _, binding := range store.snapshot().TokenBindings {
		if !binding.Revoked {
			t.Fatal("revocation fence was not durable")
		}
	}
	if _, err := c.Refresh(ctx, "gmail", token); err == nil || calls.Load() != 2 {
		t.Fatal("revoked refresh reached the provider after restart")
	}
	if len(store.snapshot().TokenBindings) != 2 {
		t.Fatal("late credential was rebound")
	}
}

func TestFailedProviderRevocationRemainsFencedAndCanRetry(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "A")
	token := nonShopifyGrant(t, f, c)
	// Load the legacy shape to prove upgrades do not bypass the fence.
	if err := f.server.Store.update(func(state *State) error {
		for hash, binding := range state.TokenBindings {
			binding.GrantID = ""
			state.TokenBindings[hash] = binding
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	f.server.Engine.Client = doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/revoke" {
			t.Error("fenced refresh reached provider")
		}
		if calls.Add(1) == 1 {
			return fixtureResponse(503, `{}`), nil
		}
		return fixtureResponse(200, `{}`), nil
	})
	ctx := context.Background()
	if err := revokeGrant(ctx, c, token); err == nil {
		t.Fatal("provider revocation failure reported as success")
	}
	if _, err := c.Refresh(ctx, "gmail", token); err == nil || calls.Load() != 1 {
		t.Fatal("failed revocation restored refresh admission")
	}
	store, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Store = store
	if err := revokeGrant(ctx, c, token); err != nil || calls.Load() != 2 {
		t.Fatal("provider revocation retry unavailable", err)
	}
	if err := f.server.bindToken(c.Identity.ID(), "gmail", token); err == nil {
		t.Fatal("an old token erased its revocation tombstone")
	}
	// Fresh consent with new credentials remains possible after revocation.
	token.AccessToken, token.RefreshToken = "new-consent-access", "new-consent-refresh"
	if err := f.server.bindToken(c.Identity.ID(), "gmail", token); err != nil {
		t.Fatal("fresh grant was blocked", err)
	}
}

func TestTokenBindingCannotMoveToAnotherInstallation(t *testing.T) {
	f := newFixture(t)
	a, b := f.client(t, "A"), f.client(t, "B")
	token := nonShopifyGrant(t, f, a)
	if err := f.server.bindToken(b.Identity.ID(), "gmail", token); err == nil {
		t.Fatal("shared token association moved to another installation")
	}
	for _, binding := range f.server.Store.snapshot().TokenBindings {
		if binding.Installation != a.Identity.ID() {
			t.Fatal("original recipient lost its binding")
		}
	}
}

func TestRefreshScopeReductionRetainsRevocationGrant(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "A")
	token := nonShopifyGrant(t, f, c)
	token.AccessToken, token.RefreshToken = "both-scope-access", "both-scope-refresh"
	token.Scopes = append(token.Scopes, "https://www.googleapis.com/auth/gmail.send")
	p := f.server.Providers["gmail"]
	p.Scopes = token.Scopes
	f.server.Providers["gmail"] = p
	if err := f.server.bindToken(c.Identity.ID(), "gmail", token); err != nil {
		t.Fatal(err)
	}
	f.server.Engine.Client = doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/revoke" {
			return fixtureResponse(200, `{}`), nil
		}
		return fixtureResponse(200, `{"access_token":"reduced-access","expires_in":3600,"scope":"https://www.googleapis.com/auth/gmail.modify"}`), nil
	})
	ctx := context.Background()
	refreshed, err := c.Refresh(ctx, "gmail", token)
	if err != nil || refreshed.Token.RefreshToken != token.RefreshToken || len(refreshed.Token.Scopes) != 1 {
		t.Fatal("reduced scope refresh failed", err)
	}
	if _, err := c.Refresh(ctx, "gmail", token); err == nil {
		t.Fatal("old wider scope binding remained active")
	}
	if _, err := c.Refresh(ctx, "gmail", refreshed.Token); err != nil {
		t.Fatal("retained refresh token lost the new scopes", err)
	}
	if err := revokeGrant(ctx, c, token); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(ctx, "gmail", refreshed.Token); err == nil {
		t.Fatal("scope reduction lost the grant revocation fence")
	}
}

func TestShopifyUninstallFencesInFlightRotation(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "A")
	ctx := context.Background()
	first, err := c.Redeem(ctx, f.consent(t, c).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	f.server.Engine.Client = doerFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-release
		return fixtureResponse(200, `{"access_token":"late-access","refresh_token":"late-refresh","expires_in":3600,"refresh_token_expires_in":7776000,"scope":"read_inventory,read_products"}`), nil
	})
	result := make(chan error, 1)
	go func() { _, err := c.Refresh(ctx, "shopify", first.Token); result <- err }()
	<-started
	if status := webhookRequest(t, f, "app/uninstalled", "example.myshopify.com", `{"id":123}`); status != 200 {
		t.Fatal("uninstall not accepted", status)
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("rotated credential escaped uninstall fence")
	}
	group := f.server.Store.snapshot().Groups[first.Group]
	if !group.Revoked || group.Version != first.Token.Version || group.Pending != "" {
		t.Fatal("late rotation restored a revoked group")
	}
	if _, err := c.Recover(ctx, first.Group); err == nil {
		t.Fatal("revoked group still offered peer recovery")
	}
}
