package auth

import (
	"context"
	"encoding/json"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnAppLoopbackFlowSurvivesCentralUnavailability(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	_ = reservation.Close()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err = os.WriteFile(secret, []byte("own-app-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "own-token", "refresh_token": "own-refresh", "scope": "read", "expires_in": 3600})
	}))
	defer endpoint.Close()
	p := oauth.Provider{ID: "google_drive", AppID: "own-google-client", ClientID: "own-client", SecretFile: secret, AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: endpoint.URL, RedirectURI: "http://" + address + "/oauth/google_drive", PKCE: true, Scopes: []string{"read"}}
	data, _ := json.Marshal([]oauth.Provider{p})
	config := filepath.Join(dir, "providers.json")
	if err = os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	flow, err := NewLocalOAuth(config)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	flow.engine.AllowLoopback = true
	tx, err := flow.Start(Start{Provider: p.ID})
	if err != nil || tx.Mode != "own-app" {
		t.Fatalf("own app start: %v", err)
	}
	launch, _ := url.Parse(tx.AuthorizationURL)
	q := url.Values{"state": {launch.Query().Get("state")}, "code": {"own-provider-code"}}
	bad, err := http.Get(p.RedirectURI + "?state=wrong&code=code")
	if err != nil {
		t.Fatal(err)
	}
	_ = bad.Body.Close()
	if bad.StatusCode != 400 {
		t.Fatal("wrong state accepted")
	}
	callback, err := http.Get(p.RedirectURI + "?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = callback.Body.Close()
	if callback.StatusCode != 200 {
		t.Fatal(callback.StatusCode)
	}
	rotation, err := flow.Redeem(context.Background(), tx.ID)
	if err != nil || rotation.Token.AppID != p.AppID || rotation.Group != "" {
		t.Fatalf("own app exchange: %v", err)
	}
	if _, err = flow.Redeem(context.Background(), tx.ID); err == nil {
		t.Fatal("own app consent replay")
	}
	if _, err = flow.Refresh(context.Background(), p.ID, rotation.Token); err != nil {
		t.Fatal(err)
	}
	altered := rotation.Token
	altered.AppID = "another-app"
	if _, err = flow.Refresh(context.Background(), p.ID, altered); err == nil {
		t.Fatal("own app issuer mismatch accepted")
	}
	tx, err = flow.Start(Start{Provider: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	launch, _ = url.Parse(tx.AuthorizationURL)
	cancelled, err := http.Get(p.RedirectURI + "?" + url.Values{"state": {launch.Query().Get("state")}, "error": {"access_denied"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = cancelled.Body.Close()
	status, err := flow.Transaction(tx.ID)
	if err != nil || status.Status != "cancelled" {
		t.Fatal("cancelled OAuth was not terminal")
	}
	p.RedirectURI = "http://0.0.0.0:8766/callback"
	data, _ = json.Marshal([]oauth.Provider{p})
	_ = os.WriteFile(config, data, 0600)
	if invalid, err := NewLocalOAuth(config); err == nil {
		invalid.Close()
		t.Fatal("callback exposed beyond loopback")
	}
}
