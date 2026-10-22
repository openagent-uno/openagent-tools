package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func beginAdmissionFixture(t *testing.T, f *fixture, installation Installation, admitted *atomic.Bool) Transaction {
	t.Helper()
	tx, err := f.server.BeginCentralWithAdmission(installation, Start{Provider: "gmail"}, centralRecipient, admitted.Load)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestCentralAdmissionRejectsNilFalseAndPanicsWithoutCreatingConsent(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	for _, admit := range []func() bool{nil, func() bool { return false }, func() bool { panic("synthetic-private-predicate-detail") }} {
		if _, err := f.server.BeginCentralWithAdmission(installation, Start{Provider: "gmail"}, centralRecipient, admit); !errors.Is(err, ErrDenied) || strings.Contains(err.Error(), "synthetic") {
			t.Fatal("missing or failed private admission did not fail closed")
		}
	}
	f.server.mu.Lock()
	count := len(f.server.transactions)
	f.server.mu.Unlock()
	if count != 0 || f.calls.Load() != 0 {
		t.Fatal("failed private admission created a transaction or contacted provider")
	}
	// The additive API must not impose a private predicate on ordinary callers.
	tx, err := f.server.BeginCentral(installation, Start{Provider: "gmail"}, centralRecipient)
	if err != nil || tx.Mode != CentralMode {
		t.Fatal("ordinary central start changed")
	}
	if response, _ := getConsent(t, tx); response.StatusCode != 200 {
		t.Fatal("ordinary central disclosure became unavailable")
	}
}

func TestCentralAdmissionCopyAndPublicMetadataCannotRemovePrivateFence(t *testing.T) {
	f, client, installation := newCentralFixture(t)
	var admitted atomic.Bool
	admitted.Store(true)
	tx := beginAdmissionFixture(t, f, installation, &admitted)
	data, err := json.Marshal(tx)
	if err != nil || strings.Contains(string(data), "centralAdmission") || strings.Contains(string(data), "central_admission") {
		t.Fatal("private admission predicate crossed the public JSON contract")
	}
	tx.centralAdmission = nil // Mutates only the returned copy, not the broker.
	admitted.Store(false)
	if _, err := f.server.CentralTransaction(installation, tx.ID, centralRecipient); !errors.Is(err, ErrDenied) {
		t.Fatal("metadata polling bypassed private admission")
	}
	if _, err := client.Transaction(context.Background(), tx.ID); err == nil {
		t.Fatal("legacy metadata route bypassed private admission")
	}
	if response, body := getConsent(t, tx); response.StatusCode == 200 || strings.Contains(body, "<form") || strings.Contains(body, "<a href=") {
		t.Fatal("returned transaction copy removed the server's private fence")
	}
}

func TestCentralAdmissionRevocationFencesBrowserConsentAndCallback(t *testing.T) {
	for _, phase := range []string{"get", "post", "approved-get", "callback"} {
		t.Run(phase, func(t *testing.T) {
			f, _, installation := newCentralFixture(t)
			var admitted atomic.Bool
			admitted.Store(true)
			tx := beginAdmissionFixture(t, f, installation, &admitted)
			var cookie *http.Cookie
			if phase != "get" {
				response, _ := getConsent(t, tx)
				if response.StatusCode != 200 || len(response.Cookies()) != 1 {
					t.Fatal("fixture disclosure missing")
				}
				cookie = response.Cookies()[0]
			}
			var state string
			if phase == "approved-get" || phase == "callback" {
				response, body := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
				if response.StatusCode != 200 {
					t.Fatal("fixture consent POST failed")
				}
				state = providerLink(t, body).Query().Get("state")
			}
			admitted.Store(false)
			var status int
			switch phase {
			case "get", "approved-get":
				response, body := getConsent(t, tx)
				status = response.StatusCode
				if strings.Contains(body, "<form") || strings.Contains(body, "<a href=") {
					t.Fatal("revoked rule rendered usable consent/navigation")
				}
			case "post":
				response, _ := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
				status = response.StatusCode
			case "callback":
				response, err := http.Get(f.http.URL + "/v1/oauth/gmail/callback?" + url.Values{"state": {state}, "code": {"fixture-code"}}.Encode())
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				status = response.StatusCode
			}
			if status == 200 || f.calls.Load() != 0 {
				t.Fatal("browser phase passed revoked admission or contacted provider")
			}
			f.server.mu.Lock()
			stored := *f.server.transactions[tx.ID]
			f.server.mu.Unlock()
			if stored.Status != "pending" || stored.code != "" {
				t.Fatal("revoked consent accepted an authorization code")
			}
		})
	}
}

func TestCentralAdmissionRevokedReadyConsentNeverExchanges(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	var admitted atomic.Bool
	admitted.Store(true)
	tx := beginAdmissionFixture(t, f, installation, &admitted)
	tx, _ = approveCentralFixtureTransaction(t, f, tx)
	admitted.Store(false)
	accepted := false
	err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error { accepted = true; return nil })
	if !errors.Is(err, ErrDenied) || accepted || f.calls.Load() != 0 || len(f.server.Store.snapshot().TokenBindings) != 0 {
		t.Fatal("revoked ready consent reached exchange or credential acceptance")
	}
}

func TestCentralAdmissionRemovedDuringExchangeCannotBindOrAcceptToken(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	var admitted atomic.Bool
	admitted.Store(true)
	tx := beginAdmissionFixture(t, f, installation, &admitted)
	tx, _ = approveCentralFixtureTransaction(t, f, tx)
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		f.calls.Add(1)
		admitted.Store(false) // Rule removed while the provider owns the code.
		return fixtureResponse(200, `{"access_token":"CENTRAL-ACCESS","refresh_token":"CENTRAL-REFRESH","expires_in":3600,"scope":"`+centralScope+`"}`), nil
	})
	accepted := false
	err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error { accepted = true; return nil })
	if !errors.Is(err, ErrDenied) || accepted || f.calls.Load() != 1 || len(f.server.Store.snapshot().TokenBindings) != 0 {
		t.Fatal("in-flight provider result bypassed the current private admission")
	}
	// Re-enabling a predicate cannot replay the already consumed OAuth code.
	admitted.Store(true)
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error { accepted = true; return nil }); err == nil || accepted || f.calls.Load() != 1 {
		t.Fatal("consumed code was retried after admission returned")
	}
}

func TestCentralAdmissionSuccessfulNormalExchangeAcceptsOnce(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	var admitted atomic.Bool
	admitted.Store(true)
	tx := beginAdmissionFixture(t, f, installation, &admitted)
	tx, _ = approveCentralFixtureTransaction(t, f, tx)
	if _, err := f.server.CentralTransaction(installation, tx.ID, "wrong recipient"); !errors.Is(err, ErrDenied) {
		t.Fatal("private predicate bypassed the existing recipient fence")
	}
	accepted := 0
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(token oauth.Token) error {
		if token.AccessToken == "" || !admitted.Load() {
			t.Fatal("credential acceptance did not retain live admission")
		}
		accepted++
		return nil
	}); err != nil || accepted != 1 || f.calls.Load() != 1 {
		t.Fatal("valid private consent did not use normal central exchange")
	}
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error { accepted++; return nil }); err == nil || accepted != 1 || f.calls.Load() != 1 {
		t.Fatal("successful private code was accepted more than once")
	}
}
