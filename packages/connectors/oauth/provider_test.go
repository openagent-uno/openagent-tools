package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderExchangeProtocolAndRefreshScopes(t *testing.T) {
	for _, provider := range []string{"clickup", "gmail", "google_drive", "google_analytics", "postiz"} {
		t.Run(provider, func(t *testing.T) {
			secretPath := filepath.Join(t.TempDir(), "client-secret")
			if err := os.WriteFile(secretPath, []byte("application-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, _ := io.ReadAll(r.Body)
				var fields map[string]string
				if provider == "clickup" {
					if r.Header.Get("Content-Type") != "application/json" || json.Unmarshal(body, &fields) != nil {
						t.Error("ClickUp exchange must use JSON")
					}
				} else {
					form, _ := url.ParseQuery(string(body))
					fields = map[string]string{}
					for key := range form {
						fields[key] = form.Get(key)
					}
				}
				if fields["client_secret"] != "application-secret" || fields["client_id"] != "public-client" {
					t.Error("missing confidential client binding")
				}
				if calls == 1 {
					if fields["code"] != "code" {
						t.Error("missing code")
					}
					if provider == "clickup" {
						if fields["grant_type"] != "" || fields["redirect_uri"] != "" {
							t.Error("unexpected ClickUp token fields")
						}
					} else if fields["code_verifier"] != "verifier" || fields["grant_type"] != "authorization_code" {
						t.Error("missing PKCE exchange")
					}
				}
				if calls == 2 && fields["refresh_token"] != "initial-refresh" {
					t.Error("wrong local refresh token")
				}
				refresh := "initial-refresh"
				if calls == 2 {
					refresh = ""
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "refresh_token": refresh, "scope": "read", "expires_in": 3600, "token_type": "Bearer"})
			}))
			defer endpoint.Close()
			p := Provider{ID: provider, AppID: "openagent-test", ClientID: "public-client", SecretFile: secretPath, AuthorizationURL: endpoint.URL, TokenURL: endpoint.URL, RedirectURI: "https://auth.openagent.uno/v1/oauth/" + provider + "/callback", Scopes: []string{"read"}, PKCE: provider != "clickup"}
			engine := Engine{AllowLoopback: true}
			authURL, err := engine.Authorize(p, "state", "challenge", "", p.Scopes)
			if err != nil {
				t.Fatal(err)
			}
			launch, _ := url.Parse(authURL)
			if provider == "gmail" || provider == "google_drive" || provider == "google_analytics" {
				if launch.Query().Get("access_type") != "offline" || launch.Query().Get("prompt") != "consent" {
					t.Fatal("missing offline consent")
				}
			}
			token, err := engine.Exchange(context.Background(), p, "code", "verifier", "", p.Scopes)
			if err != nil {
				t.Fatal(err)
			}
			refreshed, err := engine.Refresh(context.Background(), p, token.RefreshToken, "", p.Scopes)
			if err != nil || refreshed.RefreshToken != "initial-refresh" {
				t.Fatalf("refresh retention: %v", err)
			}
			if _, err := engine.Refresh(context.Background(), p, token.RefreshToken, "", []string{"write"}); err == nil {
				t.Fatal("unapproved scope escalation")
			}
			if calls != 2 {
				t.Fatal("rejected scope reached provider or request retried")
			}
		})
	}
}
