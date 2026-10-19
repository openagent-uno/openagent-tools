package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLegacyRelayFreshDeliveryAuthenticatesOriginalOccurrence(t *testing.T) {
	now := time.Date(2026, 10, 19, 15, 0, 0, 0, time.UTC)
	audience := "https://legacy.example.invalid/webhooks/shopify/app-uninstalled"
	secret := []byte("legacy-relay-test-key-at-least-32-bytes")
	body := []byte(`{"id":123}`)
	if err := SignLegacyShopifyDelivery(&http.Request{}, body, secret, now); err == nil {
		t.Fatal("invalid request accepted")
	}
	invalid, _ := http.NewRequest(http.MethodPost, audience, nil)
	invalid.Header = nil
	if err := SignLegacyShopifyDelivery(invalid, body, secret, now); err == nil {
		t.Fatal("nil header accepted")
	}
	makeRequest := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPost, audience, strings.NewReader(string(body)))
		r.Header.Set("X-Shopify-Topic", "app/uninstalled")
		r.Header.Set("X-Shopify-Shop-Domain", "legacy.myshopify.com")
		r.Header.Set("X-Shopify-Webhook-Id", "7b292bd9-7605-440c-9404-a10b2bc3b7cb")
		r.Header.Set("X-Shopify-Api-Version", "2026-07")
		r.Header.Set("X-Shopify-Triggered-At", now.Add(-48*time.Hour).Format(time.RFC3339Nano))
		if err := SignLegacyShopifyDelivery(r, body, secret, now); err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := makeRequest()
	if ok, err := VerifyLegacyShopifyDelivery(r, body, secret, audience, now); err != nil || !ok {
		t.Fatal("fresh relay rejected", err)
	}
	if r.Header.Get("X-Shopify-Triggered-At") != now.Add(-48*time.Hour).Format(time.RFC3339Nano) {
		t.Fatal("original occurrence rewritten")
	}
	for _, header := range []string{"X-Shopify-Topic", "X-Shopify-Shop-Domain", "X-Shopify-Webhook-Id", "X-Shopify-Api-Version", "X-Shopify-Triggered-At", legacyRelayTime, legacyRelayAudience, legacyRelayVersion, legacyRelaySignature} {
		t.Run("tampered_"+header, func(t *testing.T) {
			r := makeRequest()
			r.Header.Set(header, "tampered")
			if ok, err := VerifyLegacyShopifyDelivery(r, body, secret, audience, now); err == nil || ok {
				t.Fatal("tampered relay accepted")
			}
		})
		t.Run("duplicate_"+header, func(t *testing.T) {
			r := makeRequest()
			r.Header.Add(header, r.Header.Get(header))
			if ok, err := VerifyLegacyShopifyDelivery(r, body, secret, audience, now); err == nil || ok {
				t.Fatal("duplicate header accepted")
			}
		})
	}
	for _, tc := range []struct {
		name      string
		body, key []byte
		audience  string
		at        time.Time
	}{
		{"body", []byte(`{"id":124}`), secret, audience, now},
		{"key", body, []byte("wrong-key-at-least-32-bytes-long"), audience, now},
		{"audience_host", body, secret, "https://other.example.invalid/webhooks/shopify/app-uninstalled", now},
		{"audience_path", body, secret, "https://legacy.example.invalid/other", now},
		{"expired_delivery", body, secret, audience, now.Add(2*time.Minute + time.Nanosecond)},
		{"future_delivery", body, secret, audience, now.Add(-time.Minute - time.Nanosecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ok, err := VerifyLegacyShopifyDelivery(makeRequest(), tc.body, tc.key, tc.audience, tc.at); err == nil || ok {
				t.Fatal("invalid relay accepted")
			}
		})
	}
	direct, _ := http.NewRequest(http.MethodPost, audience, nil)
	if ok, err := VerifyLegacyShopifyDelivery(direct, body, secret, audience, now); err != nil || ok {
		t.Fatal("direct request changed")
	}
	direct.Header.Set(legacyRelayVersion, "1")
	if ok, err := VerifyLegacyShopifyDelivery(direct, body, secret, audience, now); err == nil || ok {
		t.Fatal("partial relay treated as direct")
	}
	// A delayed retry gets fresh transport authentication, never a new event time.
	r = makeRequest()
	later := now.Add(72 * time.Hour)
	if err := SignLegacyShopifyDelivery(r, body, secret, later); err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyLegacyShopifyDelivery(r, body, secret, audience, later); err != nil || !ok {
		t.Fatal("durable retry rejected", err)
	}
	if r.Header.Get("X-Shopify-Triggered-At") != now.Add(-48*time.Hour).Format(time.RFC3339Nano) {
		t.Fatal("retry occurrence rewritten")
	}
}
