package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGmailLeastPrivilegeConsentPreservesOnlyBoundLegacyRefresh(t *testing.T) {
	const prefix = "https://www.googleapis.com/auth/gmail."
	secret := filepath.Join(t.TempDir(), "app-secret")
	if err := os.WriteFile(secret, []byte("synthetic-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	calls, returnedScopes := 0, prefix+"modify "+prefix+"send"
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("scope") != "" {
			t.Error("legacy refresh changed grant or requested new scopes")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access", "expires_in": 3600, "scope": returnedScopes})
	}))
	defer endpoint.Close()
	p := Provider{ID: "gmail", AppID: "original-app", ClientID: "original-client", SecretFile: secret, AuthorizationURL: endpoint.URL, TokenURL: endpoint.URL,
		RedirectURI: "https://auth.openagent.uno/v1/oauth/gmail/callback", Scopes: []string{prefix + "readonly", prefix + "compose"}, PKCE: true}
	engine := Engine{AllowLoopback: true}
	for _, scopes := range [][]string{{prefix + "readonly"}, {prefix + "compose"}, p.Scopes} {
		launch, err := engine.Authorize(p, "state", "challenge", "", scopes)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(launch)
		if u.Query().Get("scope") != strings.Join(scopes, " ") || u.Query().Has("include_granted_scopes") {
			t.Fatal("new consent did not preserve its exact minimal scope set")
		}
	}
	legacy := []string{prefix + "modify", prefix + "send"}
	if _, err := engine.Authorize(p, "state", "challenge", "", legacy); err == nil {
		t.Fatal("legacy refresh exception enabled broader new consent")
	}
	if _, err := engine.Exchange(context.Background(), p, "code", "verifier", "", legacy); err == nil || calls != 0 {
		t.Fatal("legacy refresh exception enabled broader code exchange")
	}
	token, err := engine.Refresh(context.Background(), p, "held-refresh", "", legacy)
	if err != nil || token.AppID != p.AppID || token.RefreshToken != "held-refresh" || len(token.Scopes) != 2 || calls != 1 {
		t.Fatalf("original bound legacy grant failed to refresh: %v", err)
	}
	returnedScopes = prefix + "modify https://mail.google.com/"
	if _, err := engine.Refresh(context.Background(), p, "held-refresh", "", legacy); err == nil {
		t.Fatal("legacy refresh accepted provider scope expansion")
	}
	returnedScopes = prefix + "send"
	sendOnly := []string{returnedScopes}
	if token, err := engine.Refresh(context.Background(), p, "held-send-only-refresh", "", sendOnly); err != nil || len(token.Scopes) != 1 || token.Scopes[0] != sendOnly[0] {
		t.Fatalf("legacy send-only refresh failed: %v", err)
	}
	returnedScopes = prefix + "modify"
	if _, err := engine.Refresh(context.Background(), p, "held-send-only-refresh", "", sendOnly); err == nil {
		t.Fatal("legacy send-only refresh expanded to modify")
	}
	before := calls
	for _, scopes := range [][]string{{"https://mail.google.com/"}, {prefix + "modify", prefix + "modify"}, {prefix + "modify", prefix + "readonly"}} {
		if _, err := engine.Refresh(context.Background(), p, "held-refresh", "", scopes); err == nil || calls != before {
			t.Fatal("unapproved or ambiguous refresh reached provider")
		}
	}
}
