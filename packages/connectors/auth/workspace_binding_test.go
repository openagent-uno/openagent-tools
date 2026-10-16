package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func TestSlackRefreshTeamBindingRejectsForgeryBeforeProviderIO(t *testing.T) {
	f := newFixture(t)
	a, b := f.client(t, "A"), f.client(t, "B")
	p := f.server.Providers["shopify"]
	p.ID = "slack_import"
	p.AppID = "slack:fixture"
	p.Scopes = []string{"channels:read"}
	p.PKCE = false
	f.server.Providers[p.ID] = p
	token := oauth.Token{AccessToken: "xoxp-old", RefreshToken: "slack-refresh", AppID: p.AppID, Scopes: p.Scopes, ExternalID: "T12345678"}
	if err := f.server.bindToken(a.Identity.ID(), p.ID, token); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Store = store
	calls := 0
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return fixtureResponse(200, `{"ok":true,"access_token":"xoxe.xoxp-new","refresh_token":"slack-new-refresh","expires_in":43200,"token_type":"user","scope":"channels:read"}`), nil
	})
	for _, forged := range []string{"T87654321", ""} {
		altered := token
		altered.ExternalID = forged
		_, err := a.Refresh(context.Background(), p.ID, altered)
		var remote *RemoteError
		if !errors.As(err, &remote) {
			t.Fatalf("forged team refresh: error_type=%T provider_calls=%d", err, calls)
		}
		// Client.call deliberately masks internal binding errors; verify the
		// public denial and that no request reached the provider.
		if remote.Status != 403 || remote.Code != "request_failed" || calls != 0 {
			t.Fatalf("forged team refresh: status=%d code=%q provider_calls=%d", remote.Status, remote.Code, calls)
		}
	}
	if _, err := b.Refresh(context.Background(), p.ID, token); err == nil || calls != 0 {
		t.Fatal("another recipient refreshed Slack")
	}
	next, err := a.Refresh(context.Background(), p.ID, token)
	if err != nil || calls != 1 || next.Token.ExternalID != "T12345678" {
		t.Fatal("verified team not retained")
	}
	altered := next.Token
	altered.ExternalID = "T87654321"
	if err := f.server.bindToken(a.Identity.ID(), p.ID, altered); err == nil {
		t.Fatal("existing token moved to another team")
	}
}

func TestLegacyEmptyExternalBindingRemainsEmptyAndUsable(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "A")
	token := nonShopifyGrant(t, f, a)
	calls := 0
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return fixtureResponse(200, `{"access_token":"legacy-next","refresh_token":"legacy-refresh-next","scope":"https://www.googleapis.com/auth/gmail.modify"}`), nil
	})
	forged := token
	forged.ExternalID = "caller-supplied-account"
	if _, err := a.Refresh(context.Background(), "gmail", forged); err == nil || calls != 0 {
		t.Fatal("legacy empty binding adopted caller context")
	}
	next, err := a.Refresh(context.Background(), "gmail", token)
	if err != nil || next.Token.ExternalID != "" || calls != 1 {
		t.Fatal("legacy empty binding lost compatibility")
	}
}

func TestLocalSlackRefreshForwardsHostTokenTeam(t *testing.T) {
	f := newFixture(t)
	p := f.server.Providers["shopify"]
	p.ID = "slack_import"
	p.AppID = "slack:local"
	p.Scopes = []string{"channels:read"}
	calls := 0
	flow := &LocalOAuth{providers: map[string]oauth.Provider{p.ID: p}, engine: oauth.Engine{AllowLoopback: true, Client: doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return fixtureResponse(200, `{"ok":true,"access_token":"xoxe.xoxp-local-next","refresh_token":"next","expires_in":43200,"token_type":"user","scope":"channels:read","team":{"id":"T12345678"}}`), nil
	})}}
	token := oauth.Token{AppID: p.AppID, RefreshToken: "local-refresh", Scopes: p.Scopes, ExternalID: "T12345678"}
	rotation, err := flow.Refresh(context.Background(), p.ID, token)
	if err != nil || rotation.Token.ExternalID != token.ExternalID || calls != 1 {
		t.Fatal("own-app refresh dropped team binding")
	}
	bad := token
	bad.ExternalID = ""
	if _, err := flow.Refresh(context.Background(), p.ID, bad); err == nil || calls != 1 {
		t.Fatal("missing team reached Slack")
	}
}
