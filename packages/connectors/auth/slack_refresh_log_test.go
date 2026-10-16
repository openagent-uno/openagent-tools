package auth

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func TestSlackRefreshFailureLogIsQAOnlyAndContainsNoSecrets(t *testing.T) {
	original := log.Writer()
	defer log.SetOutput(original)
	for _, qa := range []bool{false, true} {
		for _, provider := range []string{"slack_import", "gmail"} {
			f := newFixture(t)
			a := f.client(t, "A")
			p := f.server.Providers["shopify"]
			delete(f.server.Providers, "shopify")
			p.ID, p.AppID, p.Scopes = provider, provider+":fixture", []string{"channels:read"}
			f.server.Providers[p.ID] = p
			if qa {
				if err := f.server.ConfigureQAEnrollment(QAEnrollment{Installations: []string{a.Identity.ID()}}); err != nil {
					t.Fatal(err)
				}
			}
			token := oauth.Token{AccessToken: "xoxp-SECRET-ACCESS", RefreshToken: "SECRET-REFRESH", AppID: p.AppID, Scopes: p.Scopes, ExternalID: "T12345678"}
			if err := f.server.bindToken(a.Identity.ID(), p.ID, token); err != nil {
				t.Fatal(err)
			}
			f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
				return fixtureResponse(200, `{"ok":true,"access_token":"xoxp-SECRET-NEXT","refresh_token":"SECRET-NEXT-REFRESH","expires_in":43200,"token_type":"bot","scope":"channels:read"}`), nil
			})
			var captured bytes.Buffer
			log.SetOutput(&captured)
			_, err := a.Refresh(context.Background(), p.ID, token)
			var remote *RemoteError
			if !errors.As(err, &remote) || remote.Status != 502 || remote.Code != "provider_refresh_failed" {
				t.Fatal("public failure contract changed")
			}
			body := captured.String()
			if qa && provider == "slack_import" {
				if !strings.Contains(body, "provider=slack_import stage=token reason=token_type provider_error=none") {
					t.Fatal("QA diagnostic missing")
				}
			} else if body != "" {
				t.Fatal("non-QA or other provider diagnostic emitted")
			}
			for _, secret := range []string{"SECRET", "T12345678", a.Identity.ID(), "test-app-secret"} {
				if strings.Contains(body, secret) {
					t.Fatal("sensitive value logged")
				}
			}
		}
	}
}

func TestSlackScopeLessRefreshKeepsReplacementBinding(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "A")
	p := f.server.Providers["shopify"]
	p.ID, p.AppID, p.Scopes = "slack_import", "slack:fixture", []string{"channels:read", "channels:history"}
	f.server.Providers[p.ID] = p
	token := oauth.Token{AccessToken: "xoxp-old", RefreshToken: "refresh-old", AppID: p.AppID, Scopes: p.Scopes, ExternalID: "T12345678"}
	if err := f.server.bindToken(a.Identity.ID(), p.ID, token); err != nil {
		t.Fatal(err)
	}
	calls := 0
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return fixtureResponse(200, `{"ok":true,"access_token":"xoxe.xoxp-next","refresh_token":"refresh-next","expires_in":43200,"token_type":"user"}`), nil
	})
	next, err := a.Refresh(context.Background(), p.ID, token)
	if err != nil || calls != 1 || !sameScopes(next.Token.Scopes, token.Scopes) || next.Token.ExternalID != token.ExternalID {
		t.Fatal("scope-less refresh did not preserve the authorized binding")
	}
	for _, raw := range []string{next.Token.AccessToken, next.Token.RefreshToken} {
		binding, found := f.server.Store.snapshot().TokenBindings[f.server.tokenHash(p.AppID, p.ID, raw)]
		if !found || !sameScopes(binding.Scopes, token.Scopes) || binding.Installation != a.Identity.ID() || binding.Provider != p.ID || binding.ExternalID != token.ExternalID {
			t.Fatal("replacement token binding changed the approved scope or recipient")
		}
	}
}

func TestSlackImplicitIdentifyRefreshKeepsReplacementBinding(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "A")
	p := f.server.Providers["shopify"]
	p.ID, p.AppID = "slack_import", "slack:fixture"
	p.Scopes = []string{"channels:read", "channels:history", "groups:read", "groups:history", "im:read", "im:history", "mpim:read", "mpim:history", "users:read", "chat:write"}
	f.server.Providers[p.ID] = p
	token := oauth.Token{AccessToken: "xoxp-old", RefreshToken: "refresh-old", AppID: p.AppID, Scopes: p.Scopes, ExternalID: "T12345678"}
	if err := f.server.bindToken(a.Identity.ID(), p.ID, token); err != nil {
		t.Fatal(err)
	}
	calls := 0
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return fixtureResponse(200, `{"ok":true,"access_token":"xoxe.xoxp-next","refresh_token":"refresh-next","expires_in":43200,"token_type":"user","scope":"channels:read,channels:history,groups:read,groups:history,im:read,im:history,mpim:read,mpim:history,users:read,chat:write,identify"}`), nil
	})
	next, err := a.Refresh(context.Background(), p.ID, token)
	if err != nil || calls != 1 || !sameScopes(next.Token.Scopes, token.Scopes) || next.Token.ExternalID != token.ExternalID {
		t.Fatal("implicit identify changed the approved grant")
	}
	for _, raw := range []string{next.Token.AccessToken, next.Token.RefreshToken} {
		binding, found := f.server.Store.snapshot().TokenBindings[f.server.tokenHash(p.AppID, p.ID, raw)]
		if !found || !sameScopes(binding.Scopes, token.Scopes) || binding.Installation != a.Identity.ID() || binding.Provider != p.ID || binding.ExternalID != token.ExternalID {
			t.Fatal("replacement binding changed after implicit identify")
		}
	}
}
