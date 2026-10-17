package auth

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// Own-app enrollment remains a separately supplied provider set. Supporting
// these provider IDs does not configure or enable any common broker provider.
func TestOwnAppCalendarAndMicrosoftRemainExplicitAndAccountBound(t *testing.T) {
	for _, id := range []string{"google_calendar", "outlook_mail", "outlook_calendar"} {
		t.Run(id, func(t *testing.T) {
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := reservation.Addr().String()
			_ = reservation.Close()
			dir := t.TempDir()
			secretPath := filepath.Join(dir, "secret")
			if os.WriteFile(secretPath, []byte("fixture-own-secret"), 0600) != nil {
				t.Fatal("secret fixture")
			}
			p := oauth.Provider{ID: id, AppID: id + ":own-fixture", ClientID: "own-fixture", SecretFile: secretPath,
				RedirectURI: "http://" + address + "/oauth/" + id, PKCE: true}
			if id == "google_calendar" {
				p.AuthorizationURL, p.TokenURL = "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token"
				p.Scopes = []string{oauth.GoogleCalendarListScope, oauth.GoogleCalendarEventsScope}
			} else {
				p.AuthorizationURL, p.TokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "https://login.microsoftonline.com/common/oauth2/v2.0/token"
				scope := "Mail.ReadWrite"
				if id == "outlook_calendar" {
					scope = "Calendars.ReadWrite"
				}
				p.Scopes = []string{"offline_access", oauth.MicrosoftGraphScopePrefix + "User.Read", oauth.MicrosoftGraphScopePrefix + scope}
			}
			data, _ := json.Marshal([]oauth.Provider{p})
			config := filepath.Join(dir, "providers.json")
			if os.WriteFile(config, data, 0600) != nil {
				t.Fatal("configuration fixture")
			}
			flow, err := NewLocalOAuth(config)
			if err != nil {
				t.Fatal(err)
			}
			defer flow.Close()
			if !flow.HasProvider(id) || flow.HasProvider("unconfigured-provider") {
				t.Fatal("own-app enrollment widened")
			}
			calls, identityCalls := 0, 0
			flow.engine.Client = doerFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" {
					identityCalls++
					if r.URL.String() != "https://graph.microsoft.com/v1.0/me?$select=id" {
						t.Fatal("identity escaped fixed Graph/me")
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"verified-account-23"}`))}, nil
				}
				calls++
				if r.URL.String() != p.TokenURL {
					t.Fatal("token endpoint changed")
				}
				_ = r.ParseForm()
				if calls == 1 && (r.Form.Get("code_verifier") == "" || r.Form.Get("code") != "fixture-code") {
					t.Fatal("local PKCE code missing")
				}
				if calls == 2 && r.Form.Get("refresh_token") != "fixture-refresh" {
					t.Fatal("local refresh credential changed")
				}
				scope := strings.Join(p.Scopes, " ")
				body, _ := json.Marshal(map[string]any{"access_token": "fixture-access", "refresh_token": "fixture-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": scope, "id_token": "ignored-unverified-not-an-identity"})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})
			tx, err := flow.Start(Start{Provider: id})
			if err != nil || tx.Mode != "own-app" {
				t.Fatal("local flow start failed")
			}
			launch, _ := url.Parse(tx.AuthorizationURL)
			callback, err := http.Get(p.RedirectURI + "?" + url.Values{"state": {launch.Query().Get("state")}, "code": {"fixture-code"}}.Encode())
			if err != nil {
				t.Fatal(err)
			}
			_ = callback.Body.Close()
			if callback.StatusCode != 200 {
				t.Fatal("callback rejected")
			}
			rotation, err := flow.Redeem(context.Background(), tx.ID)
			if err != nil || rotation.Token.AppID != p.AppID {
				t.Fatal("local exchange failed")
			}
			if _, err = flow.Redeem(context.Background(), tx.ID); err == nil {
				t.Fatal("consent replay accepted")
			}
			if id == "google_calendar" {
				if rotation.Token.ExternalID != "" || identityCalls != 0 {
					t.Fatal("Google identity scope invented")
				}
			} else if rotation.Token.ExternalID != "verified-account-23" || identityCalls != 1 {
				t.Fatal("Microsoft account not verified by Graph")
			}
			next, err := flow.Refresh(context.Background(), id, rotation.Token)
			if err != nil || next.Token.ExternalID != rotation.Token.ExternalID || calls != 2 {
				t.Fatal("own-app issuer/account binding changed")
			}
			bad := rotation.Token
			bad.AppID = "other-app"
			if _, err = flow.Refresh(context.Background(), id, bad); err == nil || calls != 2 {
				t.Fatal("foreign app refreshed")
			}
		})
	}
}
