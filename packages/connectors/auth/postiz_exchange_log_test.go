package auth

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostizRedeemLogsOnlyClosedExchangeFailureLabels(t *testing.T) {
	f := newFixture(t)
	client := f.client(t, "synthetic-owner")
	p := f.server.Providers["shopify"]
	p.ID, p.AppID, p.ClientID = "postiz", "synthetic-postiz", "pca_synthetic"
	p.PKCE, p.Scopes = false, nil
	p.RedirectURI = f.server.Origin + "/v1/oauth/postiz/callback"
	p.SecretFile = filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p.SecretFile, []byte("PRIVATE-POSTIZ-CLIENT-SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	f.server.Providers[p.ID] = p
	calls := 0
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return fixtureResponse(400, `{"error":"invalid_client","error_description":"PRIVATE-DESCRIPTION","access_token":"PRIVATE-ACCESS","refresh_token":"PRIVATE-REFRESH","client_secret":"PRIVATE-POSTIZ-CLIENT-SECRET","code":"PRIVATE-CODE"}`), nil
	})
	id := "owned-synthetic-postiz-transaction"
	f.server.transactions[id] = &Transaction{ID: id, Installation: client.Identity.ID(), Provider: p.ID, AppID: p.AppID, Status: "ready", ExpiresAt: time.Now().Add(time.Minute), code: "PRIVATE-CODE"}
	var captured bytes.Buffer
	original := log.Writer()
	log.SetOutput(&captured)
	defer log.SetOutput(original)
	response := httptest.NewRecorder()
	f.server.redeem(response, httptest.NewRequest("POST", "/v1/transactions/test/redeem", nil), Installation{ID: client.Identity.ID()}, id)
	want := "connector_oauth_exchange_failed provider=postiz stage=response reason=http_status provider_error=invalid_client http_status=400"
	if response.Code != 502 || !strings.Contains(response.Body.String(), "provider_exchange_failed") || calls != 1 || !strings.Contains(captured.String(), want) {
		t.Fatal("Postiz redeem lost its generic error, fixed diagnostic, or single attempt")
	}
	for _, sentinel := range []string{"PRIVATE-", client.Identity.ID(), id, p.ClientID, p.TokenURL, p.RedirectURI} {
		if strings.Contains(captured.String()+response.Body.String(), sentinel) {
			t.Fatal("Postiz diagnostic exported a credential, identity, body or URL")
		}
	}
	if len(f.server.Store.snapshot().TokenBindings) != 0 {
		t.Fatal("failed Postiz exchange persisted a token")
	}
}

func TestPostizConsentDisclosesAppWideWriteAccess(t *testing.T) {
	var page bytes.Buffer
	if err := consentPage.Execute(&page, map[string]string{"Provider": "postiz", "Name": "Synthetic owner", "Scopes": ""}); err != nil {
		t.Fatal(err)
	}
	for _, disclosure := range []string{"app-wide read and write access", "mcp:read and mcp:write", "does not offer granular permission selection"} {
		if !strings.Contains(page.String(), disclosure) {
			t.Fatal("Postiz consent omitted its app-wide permission disclosure")
		}
	}
	page.Reset()
	if err := consentPage.Execute(&page, map[string]string{"Provider": "clickup", "Scopes": "existing-permission"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "Permissions: existing-permission") || strings.Contains(page.String(), "app-wide") {
		t.Fatal("Postiz disclosure changed another provider")
	}
}
