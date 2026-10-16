package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// These protocol fixtures do not imply provider registration or live consent.
func TestGitHubConfidentialPKCEExchangeRequestsJSON(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("fixture-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method != "POST" || r.Header.Get("Accept") != "application/json" ||
			r.Form.Get("client_id") != "fixture-client" || r.Form.Get("client_secret") != "fixture-secret" ||
			r.Form.Get("code_verifier") != "fixture-verifier" || r.Form.Get("grant_type") != "" ||
			r.Form.Get("redirect_uri") != "https://auth.openagent.uno/v1/oauth/github/callback" {
			t.Error("GitHub exchange contract changed")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fixture-access", "token_type": "bearer", "scope": "read:user"})
	}))
	defer endpoint.Close()
	p := Provider{ID: "github", AppID: "github:fixture-client", ClientID: "fixture-client", SecretFile: secretPath,
		AuthorizationURL: endpoint.URL + "/authorize", TokenURL: endpoint.URL + "/token",
		RedirectURI: "https://auth.openagent.uno/v1/oauth/github/callback", Scopes: []string{"read:user"}, PKCE: true}
	e := Engine{AllowLoopback: true}
	authorize, err := e.Authorize(p, "bound-state", "fixture-challenge", "", p.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authorize)
	if u.Query().Get("state") != "bound-state" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("GitHub state or PKCE lost")
	}
	token, err := e.Exchange(context.Background(), p, "fixture-code", "fixture-verifier", "", p.Scopes)
	if err != nil || token.AppID != p.AppID || token.AccessToken != "fixture-access" || calls != 1 {
		t.Fatalf("GitHub exchange: %v", err)
	}
	if _, err := e.Exchange(context.Background(), p, "fixture-code", "fixture-verifier", "", []string{"repo"}); !errors.Is(err, ErrAuthentication) || calls != 1 {
		t.Fatal("unapproved scope reached GitHub")
	}
}

func TestNotionBasicJSONExchangeAndRotatingRefresh(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("fixture-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		client, secret, ok := r.BasicAuth()
		if !ok || client != "fixture-client" || secret != "fixture-secret" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Notion-Version") != "2026-03-11" {
			t.Error("Notion requires confidential Basic authentication and JSON")
		}
		var fields map[string]string
		if json.NewDecoder(r.Body).Decode(&fields) != nil {
			t.Error("invalid Notion JSON")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if fields["client_secret"] != "" || fields["client_id"] != "" {
			t.Error("Notion app credentials leaked into JSON body")
		}
		if calls == 1 && (len(fields) != 3 || fields["grant_type"] != "authorization_code" || fields["code"] != "fixture-code" || fields["redirect_uri"] == "") {
			t.Error("unexpected Notion authorization code fields")
		}
		if calls == 2 && (len(fields) != 2 || fields["grant_type"] != "refresh_token" || fields["refresh_token"] != "refresh-one") {
			t.Error("unexpected Notion refresh fields")
		}
		refresh := "refresh-one"
		if calls == 2 {
			refresh = "refresh-two"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "refresh_token": refresh, "token_type": "bearer"})
	}))
	defer endpoint.Close()
	p := Provider{ID: "notion", AppID: "notion:fixture-client", ClientID: "fixture-client", SecretFile: secretPath,
		AuthorizationURL: endpoint.URL + "/authorize", TokenURL: endpoint.URL + "/token",
		RedirectURI: "https://auth.openagent.uno/v1/oauth/notion/callback"}
	e := Engine{AllowLoopback: true}
	if err := e.ValidateConfiguration(p); err != nil {
		t.Fatal(err)
	}
	authorize, err := e.Authorize(p, "bound-state", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authorize)
	if u.Query().Get("owner") != "user" || u.Query().Get("state") != "bound-state" || u.Query().Get("scope") != "" {
		t.Fatal("Notion page selection consent contract changed")
	}
	token, err := e.Exchange(context.Background(), p, "fixture-code", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.Refresh(context.Background(), p, token.RefreshToken, "", nil)
	if err != nil || next.RefreshToken != "refresh-two" || next.AppID != p.AppID || calls != 2 {
		t.Fatalf("Notion rotation: %v", err)
	}
	p.Scopes = []string{"invented:scope"}
	if err := e.ValidateConfiguration(p); !errors.Is(err, ErrAuthentication) {
		t.Fatal("Notion configured with nonexistent OAuth scopes")
	}
	if _, err := e.Authorize(p, "bound-state", "", "", p.Scopes); !errors.Is(err, ErrAuthentication) || calls != 2 {
		t.Fatal("Notion consent accepted invented scopes")
	}
}
