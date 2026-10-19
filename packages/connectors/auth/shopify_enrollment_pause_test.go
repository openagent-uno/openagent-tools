package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestShopifyEnrollmentPauseRejectsOnlyNewStartsAndPreservesRefresh(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "existing-recipient")
	rotation, err := c.Redeem(context.Background(), f.consent(t, c).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Publish(context.Background(), rotation); err != nil {
		t.Fatal(err)
	}
	if err = f.server.ConfigureShopifyNewConsentsDisabled(); err != nil {
		t.Fatal(err)
	}
	before := f.calls.Load()
	_, err = c.Start(context.Background(), Start{Provider: "shopify", Shop: "example.myshopify.com"})
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Status != 503 || remote.Code != "authorization_not_ready" || f.calls.Load() != before {
		t.Fatal("paused start reached provider or was admitted")
	}
	next, err := c.Refresh(context.Background(), "shopify", rotation.Token)
	if err != nil || next.Token.Version <= rotation.Token.Version {
		t.Fatal("existing refresh was paused", err)
	}
	// An unrelated provider still uses its ordinary start/disclosure path.
	p := f.server.Providers["shopify"]
	p.ID = "clickup"
	p.AppID = "clickup-existing"
	p.RedirectURI = f.http.URL + "/v1/oauth/clickup/callback"
	p.Scopes = []string{}
	f.server.Providers[p.ID] = p
	if _, err := c.Start(context.Background(), Start{Provider: "clickup"}); err != nil {
		t.Fatal("unrelated provider paused", err)
	}
	r, err := http.Get(f.http.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var health map[string]any
	if err = json.NewDecoder(r.Body).Decode(&health); err != nil || r.StatusCode != 200 || health["shopify_enrollment"] != "paused" || health["enrollment"] != "public" {
		t.Fatal("pause health is misleading")
	}
	// The body-authenticated privacy endpoint is unaffected by start admission.
	if status := webhookRequest(t, f, "customers/redact", "example.myshopify.com", `{"shop_id":123,"customer":{"id":7},"orders_to_redact":[]}`); status != 200 {
		t.Fatal("privacy webhook paused", status)
	}
}

func TestShopifyEnrollmentPauseDoesNotRevokeValidPendingCallback(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "already-approved")
	tx, state := f.approval(t, c)
	if err := f.server.ConfigureShopifyNewConsentsDisabled(); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"state": {state}, "code": {"provider-code"}, "shop": {"example.myshopify.com"}, "timestamp": {strconv.FormatInt(time.Now().Unix(), 10)}}
	mac := hmac.New(sha256.New, []byte("test-app-secret"))
	mac.Write([]byte(q.Encode()))
	q.Set("hmac", hex.EncodeToString(mac.Sum(nil)))
	r, err := http.Get(f.http.URL + "/v1/oauth/shopify/callback?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("valid pending callback revoked", r.StatusCode)
	}
	rotation, err := c.Redeem(context.Background(), tx.ID)
	if err != nil || rotation.Token.AccessToken == "" {
		t.Fatal("valid pending redeem revoked", err)
	}
}

func TestShopifyEnrollmentPauseRequiresConfiguredShopifyProvider(t *testing.T) {
	f := newFixture(t)
	delete(f.server.Providers, "shopify")
	if err := f.server.ConfigureShopifyNewConsentsDisabled(); !errors.Is(err, ErrDenied) {
		t.Fatal("pause without Shopify provider accepted")
	}
}
