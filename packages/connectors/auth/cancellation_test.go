package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func signedCallback(t *testing.T, f *fixture, provider string, q url.Values) int {
	t.Helper()
	q.Del("hmac")
	mac := hmac.New(sha256.New, []byte("test-app-secret"))
	mac.Write([]byte(q.Encode()))
	q.Set("hmac", hex.EncodeToString(mac.Sum(nil)))
	response, err := http.Get(f.http.URL + "/v1/oauth/" + provider + "/callback?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode
}

func TestCancelledConsentCannotExchangeOrAcceptLaterCallback(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "A")
	tx, state := f.approval(t, c)
	q := url.Values{"state": {state}, "error": {"access_denied"}, "shop": {"example.myshopify.com"}, "timestamp": {strconv.FormatInt(time.Now().Unix(), 10)}}
	if status := signedCallback(t, f, "shopify", q); status != 200 {
		t.Fatal("cancellation rejected", status)
	}
	current, err := c.Transaction(context.Background(), tx.ID)
	if err != nil || current.Status != "cancelled" {
		t.Fatal("cancelled state unavailable", err)
	}
	if _, err := c.Redeem(context.Background(), tx.ID); err == nil {
		t.Fatal("cancelled consent exchanged")
	}
	q.Del("error")
	q.Set("code", "late-provider-code")
	if status := signedCallback(t, f, "shopify", q); status != 400 {
		t.Fatal("callback resurrected cancelled consent", status)
	}
	if f.calls.Load() != 0 {
		t.Fatal("cancelled consent reached provider token endpoint")
	}
}

func TestCallbackRejectsWrongProviderStoreAndExpiredConsent(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "A")
	tx, state := f.approval(t, c)
	q := url.Values{"state": {state}, "code": {"provider-code"}, "shop": {"example.myshopify.com"}, "timestamp": {strconv.FormatInt(time.Now().Unix(), 10)}}
	if status := signedCallback(t, f, "gmail", q); status != 400 {
		t.Fatal("wrong provider accepted consent", status)
	}
	q.Set("shop", "another.myshopify.com")
	if status := signedCallback(t, f, "shopify", q); status != 401 {
		t.Fatal("wrong signed shop accepted consent", status)
	}
	f.server.now = func() time.Time { return time.Now().UTC().Add(11 * time.Minute) }
	q.Set("shop", "example.myshopify.com")
	if status := signedCallback(t, f, "shopify", q); status != 400 {
		t.Fatal("expired callback accepted", status)
	}
	if _, err := c.Redeem(context.Background(), tx.ID); err == nil || f.calls.Load() != 0 {
		t.Fatal("expired consent exchanged")
	}
}
