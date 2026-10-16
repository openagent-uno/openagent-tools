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
	"strings"
	"testing"
)

func workspaceProtocolFixture(t *testing.T, id string, handler http.HandlerFunc) (Provider, Engine, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("fixture-client-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	p := Provider{ID: id, AppID: id + ":fixture", ClientID: "fixture-client", SecretFile: path, AuthorizationURL: s.URL + "/authorize", TokenURL: s.URL + "/token", RedirectURI: "https://auth.openagent.uno/v1/oauth/" + id + "/callback"}
	if id == "slack_import" {
		p.Scopes = []string{"channels:read", "channels:history"}
	} else if id == "atlassian" {
		p.Scopes = []string{"read:jira-work", "offline_access"}
	}
	return p, Engine{AllowLoopback: true}, s
}

func TestAtlassianConfidentialJSONCodeAndRotatingRefresh(t *testing.T) {
	calls := 0
	p, e, _ := workspaceProtocolFixture(t, "atlassian", func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]string
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" || json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("Atlassian JSON exchange contract")
		}
		if body["client_id"] != "fixture-client" || body["client_secret"] != "fixture-client-secret" || body["code_verifier"] != "" {
			t.Error("Atlassian confidential client binding")
		}
		if calls == 1 && (len(body) != 5 || body["grant_type"] != "authorization_code" || body["code"] != "fixture-code" || body["redirect_uri"] == "") {
			t.Error("Atlassian code fields")
		}
		if calls == 2 && (len(body) != 4 || body["grant_type"] != "refresh_token" || body["refresh_token"] != "refresh-one") {
			t.Error("Atlassian refresh fields")
		}
		refresh := "refresh-one"
		if calls == 2 {
			refresh = "refresh-two"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "refresh_token": refresh, "expires_in": 3600, "scope": "read:jira-work offline_access", "token_type": "Bearer"})
	})
	launch, err := e.Authorize(p, "bound-state", "unused", "", p.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(launch)
	if u.Query().Get("audience") != "api.atlassian.com" || u.Query().Get("prompt") != "consent" || u.Query().Get("state") != "bound-state" || u.Query().Get("scope") != "read:jira-work offline_access" || u.Query().Get("code_challenge") != "" {
		t.Fatal("Atlassian authorize contract")
	}
	token, err := e.Exchange(context.Background(), p, "fixture-code", "unused", "", p.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.Refresh(context.Background(), p, token.RefreshToken, "", token.Scopes)
	if err != nil || next.RefreshToken != "refresh-two" || next.ExpiresAt == nil || calls != 2 {
		t.Fatal("Atlassian rotation failed")
	}
	p.PKCE = true
	if e.ValidateConfiguration(p) == nil {
		t.Fatal("undocumented Atlassian PKCE accepted")
	}
	if _, err := e.Exchange(context.Background(), p, "fixture-code", "verifier", "", p.Scopes); !errors.Is(err, ErrAuthentication) || calls != 2 {
		t.Fatal("unsupported protocol reached provider")
	}
}

func TestSlackUserOnlyExchangeAndRefreshPreserveTeam(t *testing.T) {
	calls := 0
	p, e, _ := workspaceProtocolFixture(t, "slack_import", func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = r.ParseForm()
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Form.Get("client_id") != "fixture-client" || r.Form.Get("client_secret") != "fixture-client-secret" {
			t.Error("Slack confidential form contract")
		}
		if calls == 1 {
			if r.Form.Get("code") != "fixture-code" || r.Form.Get("grant_type") != "" || r.Form.Get("redirect_uri") == "" || r.Form.Get("code_verifier") != "" {
				t.Error("Slack initial fields")
			}
			_, _ = io.WriteString(w, `{"ok":true,"access_token":"xoxb-never-use-this","token_type":"bot","scope":"commands","team":{"id":"T12345678"},"is_enterprise_install":false,"authed_user":{"id":"U12345678","access_token":"xoxe.xoxp-user-one","refresh_token":"refresh-one","expires_in":43200,"token_type":"user","scope":"channels:read,channels:history"}}`)
		} else {
			if len(r.Form) != 4 || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-one" {
				t.Error("Slack refresh fields")
			}
			// Slack may omit team on refresh; the prior host binding is retained.
			_, _ = io.WriteString(w, `{"ok":true,"access_token":"xoxe.xoxp-user-two","refresh_token":"refresh-two","expires_in":43200,"token_type":"user","scope":"channels:read,channels:history"}`)
		}
	})
	p.AuthorizationURL += "?scope=commands&response_type=token&code_challenge=old"
	launch, err := e.Authorize(p, "state", "unused", "", p.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(launch)
	q := u.Query()
	if q.Get("user_scope") != "channels:read,channels:history" || q.Get("scope") != "" || q.Get("response_type") != "" || q.Get("code_challenge") != "" || q.Get("state") != "state" {
		t.Fatal("Slack user-only authorization changed")
	}
	token, err := e.Exchange(context.Background(), p, "fixture-code", "unused", "", p.Scopes)
	if err != nil || token.AccessToken != "xoxe.xoxp-user-one" || token.ExternalID != "T12345678" || token.ExpiresAt == nil {
		t.Fatal("Slack nested user token not selected")
	}
	if _, err := e.Refresh(context.Background(), p, token.RefreshToken, "", token.Scopes); !errors.Is(err, ErrAuthentication) || calls != 1 {
		t.Fatal("missing trusted team reached Slack")
	}
	next, err := e.Refresh(context.Background(), p, token.RefreshToken, token.ExternalID, token.Scopes)
	if err != nil || next.AccessToken != "xoxe.xoxp-user-two" || next.RefreshToken != "refresh-two" || next.ExternalID != token.ExternalID || calls != 2 {
		t.Fatal("Slack user refresh lost identity or rotation")
	}
	p.PKCE = true
	if _, err := e.Authorize(p, "state", "challenge", "", p.Scopes); !errors.Is(err, ErrAuthentication) {
		t.Fatal("app PKCE capability guessed")
	}
}

func TestSlackMalformedBotEnterpriseAndScopeEscalationFailClosed(t *testing.T) {
	valid := `{"ok":true,"team":{"id":"T12345678"},"authed_user":{"access_token":"xoxp-user","token_type":"user","scope":"channels:read,channels:history"}}`
	for name, body := range map[string]string{
		"ok absent":           strings.Replace(valid, `"ok":true,`, "", 1),
		"ok false":            strings.Replace(valid, `"ok":true`, `"ok":false`, 1),
		"missing user":        `{"ok":true,"team":{"id":"T12345678"},"access_token":"xoxb-bot","token_type":"bot"}`,
		"nil team":            strings.Replace(valid, `{"id":"T12345678"}`, `null`, 1),
		"org install":         strings.Replace(valid, `"ok":true`, `"ok":true,"is_enterprise_install":true`, 1),
		"enterprise ID":       strings.Replace(valid, "T12345678", "E12345678", 1),
		"bot type":            strings.Replace(valid, `"token_type":"user"`, `"token_type":"bot"`, 1),
		"bot token disguised": strings.Replace(valid, "xoxp-user", "xoxb-bot", 1),
		"scope escalation":    strings.Replace(valid, "channels:read,channels:history", "channels:read,chat:write", 1),
		"rotation incomplete": strings.Replace(valid, `"token_type":"user"`, `"expires_in":43200,"token_type":"user"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			p, e, _ := workspaceProtocolFixture(t, "slack_import", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
			if _, err := e.Exchange(context.Background(), p, "code", "", "", p.Scopes); !errors.Is(err, ErrAuthentication) {
				t.Fatal("invalid Slack credential accepted")
			}
		})
	}
	for _, body := range []string{
		`{"ok":true,"access_token":"xoxe.xoxp-user","refresh_token":"new","expires_in":43200,"token_type":"user","scope":"channels:read","team":{"id":"T87654321"}}`,
		`{"ok":true,"access_token":"xoxe.xoxp-user","refresh_token":"new","expires_in":43200,"token_type":"user","scope":"channels:read","is_enterprise_install":true}`,
		`{"ok":true,"access_token":"xoxe.xoxb-bot","refresh_token":"new","expires_in":43200,"token_type":"bot","scope":"channels:read"}`,
	} {
		p, e, _ := workspaceProtocolFixture(t, "slack_import", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
		if _, err := e.Refresh(context.Background(), p, "refresh", "T12345678", p.Scopes); !errors.Is(err, ErrAuthentication) {
			t.Fatal("Slack refresh switched team or token type")
		}
	}
}

func TestProviderSpecificNotionAndGitHubRevocation(t *testing.T) {
	for _, id := range []string{"notion", "github"} {
		t.Run(id, func(t *testing.T) {
			calls := 0
			p, e, s := workspaceProtocolFixture(t, id, func(w http.ResponseWriter, r *http.Request) {
				calls++
				client, secret, ok := r.BasicAuth()
				if !ok || client != "fixture-client" || secret != "fixture-client-secret" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("revocation app binding")
				}
				var body map[string]string
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("revocation JSON")
				}
				if id == "notion" {
					if r.Method != "POST" || r.URL.Path != "/v1/oauth/revoke" || r.Header.Get("Notion-Version") != "2026-03-11" || len(body) != 1 || body["token"] != "access-to-revoke" {
						t.Error("Notion revoke contract")
					}
					_, _ = io.WriteString(w, `{"request_id":"fixture"}`)
				} else {
					if r.Method != "DELETE" || r.URL.Path != "/applications/fixture-client/token" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("Accept") != "application/vnd.github+json" || len(body) != 1 || body["access_token"] != "access-to-revoke" {
						t.Error("GitHub revoke contract")
					}
					w.WriteHeader(204)
				}
			})
			p.RevocationURL = s.URL + "/v1/oauth/revoke"
			if id == "github" {
				p.RevocationURL = s.URL + "/applications/fixture-client/token"
			}
			if err := e.Revoke(context.Background(), p, "access-to-revoke", ""); err != nil || calls != 1 {
				t.Fatal("provider-specific revocation failed")
			}
			p.RevocationURL = s.URL + "/arbitrary"
			if err := e.Revoke(context.Background(), p, "access-to-revoke", ""); !errors.Is(err, ErrAuthentication) || calls != 1 {
				t.Fatal("arbitrary authenticated revocation endpoint reached")
			}
		})
	}
}

func TestWorkspaceOAuthResponseBoundsAndRevokeNoRetry(t *testing.T) {
	calls := 0
	p, e, s := workspaceProtocolFixture(t, "notion", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/v1/oauth/revoke" {
			w.WriteHeader(503)
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("x", (1<<20)+1))
	})
	if _, err := e.Exchange(context.Background(), p, "code", "", "", nil); !errors.Is(err, ErrAuthentication) || calls != 1 {
		t.Fatal("oversized token reply accepted")
	}
	p.RevocationURL = s.URL + "/v1/oauth/revoke"
	if err := e.Revoke(context.Background(), p, "access", ""); !errors.Is(err, ErrAuthentication) || calls != 2 {
		t.Fatal("failed revoke retried or claimed success")
	}
}
