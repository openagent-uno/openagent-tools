package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderExchangeProtocolAndRefreshScopes(t *testing.T) {
	for _, provider := range []string{"clickup", "gmail", "google_drive", "google_analytics"} {
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

// The Postiz contract is distinct from the expiring Google grant contract:
// https://docs.postiz.com/oauth (registered callback, JSON exchange, no refresh).
func TestPostizRegisteredCallbackAndJSONExchange(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretPath, []byte("pcs_test-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/oauth/token" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("Postiz requires a JSON POST to its token endpoint")
		}
		var fields map[string]string
		if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
			t.Error("Postiz token body is not JSON")
		}
		if len(fields) != 4 || fields["grant_type"] != "authorization_code" || fields["code"] != "code+ &=value" || fields["client_id"] != "pca_test-client" || fields["client_secret"] != "pcs_test-secret" {
			t.Error("unexpected Postiz confidential exchange contract")
		}
		if _, exists := fields["redirect_uri"]; exists {
			t.Error("Postiz callback must come from the registered app, not token fields")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "org_test", "access_token": "pos_test-access", "token_type": "bearer"})
	}))
	defer endpoint.Close()
	p := Provider{ID: "postiz", AppID: "postiz:pca_test-client", ClientID: "pca_test-client", SecretFile: secretPath, AuthorizationURL: endpoint.URL + "/oauth/authorize", TokenURL: endpoint.URL + "/oauth/token", RedirectURI: "https://auth.openagent.uno/v1/oauth/postiz/callback"}
	engine := Engine{AllowLoopback: true}
	authorization, err := engine.Authorize(p, "recipient-bound-state", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := url.Parse(authorization)
	if err != nil || len(launch.Query()) != 3 || launch.Query().Get("client_id") != p.ClientID || launch.Query().Get("response_type") != "code" || launch.Query().Get("state") != "recipient-bound-state" {
		t.Fatal("Postiz authorization must use the registered callback and preserve state")
	}
	token, err := engine.Exchange(context.Background(), p, "code+ &=value", "", "", nil)
	if err != nil || token.AccessToken != "pos_test-access" || token.AppID != p.AppID || token.ExpiresAt != nil || token.RefreshExpiresAt != nil || token.RefreshToken != "" {
		t.Fatalf("non-expiring Postiz exchange: %v", err)
	}
	if _, err := engine.Refresh(context.Background(), p, token.RefreshToken, "", nil); !errors.Is(err, ErrAuthentication) {
		t.Fatal("missing Postiz refresh credential must be rejected locally")
	}
	if calls != 1 {
		t.Fatal("Postiz exchange was retried or a nonexistent refresh reached the provider")
	}
}

func TestPostizExchangeFailuresAreSanitizedAndNotRetried(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"invalid_client", http.StatusBadRequest, `{"error":"invalid_client","client_secret":"pcs_test-secret"}`},
		{"invalid_grant", http.StatusBadRequest, `{"error":"invalid_grant","code":"one-use-code"}`},
		{"upstream_unavailable", http.StatusServiceUnavailable, `{"access_token":"pos_should-not-return"}`},
		{"redirect", http.StatusTemporaryRedirect, `{"access_token":"pos_should-not-return"}`},
		{"invalid_json", http.StatusOK, `not-json`},
		{"missing_access", http.StatusOK, `{"id":"org_test","token_type":"bearer"}`},
		{"invalid_token_type", http.StatusOK, `{"access_token":"pos_should-not-return","token_type":"basic"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			secretPath := filepath.Join(t.TempDir(), "client-secret")
			if err := os.WriteFile(secretPath, []byte("pcs_test-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/untrusted-redirect")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer endpoint.Close()
			p := Provider{ID: "postiz", AppID: "postiz:pca_test-client", ClientID: "pca_test-client", SecretFile: secretPath, TokenURL: endpoint.URL, RedirectURI: "https://auth.openagent.uno/v1/oauth/postiz/callback"}
			token, err := (Engine{AllowLoopback: true}).Exchange(context.Background(), p, "one-use-code", "", "", nil)
			if !errors.Is(err, ErrAuthentication) || err.Error() != ErrAuthentication.Error() || token.AccessToken != "" || token.RefreshToken != "" {
				t.Fatal("failed exchange leaked provider credentials or unsanitized errors")
			}
			if calls != 1 {
				t.Fatal("non-idempotent Postiz exchange was retried or redirected")
			}
		})
	}
}
