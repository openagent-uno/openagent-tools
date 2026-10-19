package auth

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMicrosoftRedeemLogsOnlyFixedExchangeFailureLabels(t *testing.T) {
	f := newFixture(t)
	client := f.client(t, "test-owner")
	p := f.server.Providers["shopify"]
	p.ID = "outlook_mail"
	p.AppID = "synthetic-mail"
	p.PKCE = true
	p.Scopes = []string{"offline_access", "User.Read", "Mail.ReadWrite"}
	p.RedirectURI = f.server.Origin + "/v1/oauth/outlook_mail/callback"
	f.server.Providers[p.ID] = p
	calls := 0
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return fixtureResponse(200, `{"access_token":"PRIVATE-ACCESS","refresh_token":"PRIVATE-REFRESH","token_type":"Bearer","expires_in":3600,"scope":"User.Read Mail.ReadWrite Calendars.ReadWrite"}`), nil
	})
	id := "owned-test-transaction"
	f.server.transactions[id] = &Transaction{ID: id, Installation: client.Identity.ID(), Provider: p.ID, AppID: p.AppID, Scopes: p.Scopes, Status: "ready", ExpiresAt: time.Now().Add(time.Minute), code: "PRIVATE-CODE", verifier: strings.Repeat("v", 43)}
	var captured bytes.Buffer
	original := log.Writer()
	log.SetOutput(&captured)
	defer log.SetOutput(original)
	response := httptest.NewRecorder()
	f.server.redeem(response, httptest.NewRequest("POST", "/v1/transactions/test/redeem", nil), Installation{ID: client.Identity.ID()}, id)
	want := "connector_oauth_exchange_failed provider=outlook_mail stage=scopes reason=scope_config provider_error=none"
	if response.Code != 502 || !strings.Contains(response.Body.String(), "provider_exchange_failed") || calls != 1 || !strings.Contains(captured.String(), want) {
		t.Fatal("redeem did not preserve generic failure and fixed diagnostic")
	}
	for _, sensitive := range []string{"PRIVATE-ACCESS", "PRIVATE-REFRESH", "PRIVATE-CODE", client.Identity.ID(), id, "Calendars.ReadWrite"} {
		if strings.Contains(captured.String()+response.Body.String(), sensitive) {
			t.Fatal("diagnostic exported credential, identity or raw response")
		}
	}
	if len(f.server.Store.snapshot().TokenBindings) != 0 {
		t.Fatal("rejected wider token was bound")
	}
}
