package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// A synthetic receiver enforces the checked-in GlassPalace wire contract.
// This does not claim Shopify delivery or production receiver acceptance.
func TestLegacyShopifyReceiverVersionAndMinimalUninstallContract(t *testing.T) {
	for _, tc := range []struct{ topic, body string }{
		{"app/uninstalled", `{"id":123,"shop_domain":"legacy.myshopify.com","irrelevant":"not-retained"}`},
		{"customers/data_request", `{"shop_id":123,"shop_domain":"legacy.myshopify.com","customer":{"id":7,"email":"qa@example.invalid"},"orders_requested":[],"data_request":{"id":9}}`},
		{"customers/redact", `{"shop_id":123,"shop_domain":"legacy.myshopify.com","customer":{"id":7},"orders_to_redact":[]}`},
		{"shop/redact", `{"shop_id":123,"shop_domain":"legacy.myshopify.com"}`},
	} {
		t.Run(tc.topic, func(t *testing.T) {
			f := newLegacyRelayFixture(t)
			// Designed known-order history tests the relay wire, rather than
			// treating absent historical acquisition evidence as verified.
			now := time.Now().UTC()
			group := groupID(f.server.Providers["shopify"].AppID, "legacy.myshopify.com")
			if err := f.server.Store.update(func(state *State) error {
				state.Groups[group] = &Group{ID: group, AppID: f.server.Providers["shopify"].AppID,
					Shop: "legacy.myshopify.com", ShopID: 123, AuthorizedAt: now.Add(-60 * time.Hour),
					LastAuthorizationAcquiredAt: now.Add(-60 * time.Hour), Members: map[string]uint64{}, PrivacyRecipients: map[string]bool{}}
				if tc.topic == "shop/redact" {
					counterpart := testNativeEvent("known-relay-uninstall", group, "app/uninstalled", now.Add(-49*time.Hour))
					state.Events[counterpart.ID] = counterpart
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			const webhookID = "7b292bd9-7605-440c-9404-a10b2bc3b7cb"
			at := time.Now().UTC().Format(time.RFC3339Nano)
			var calls atomic.Int64
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil || r.Header.Get("Content-Type") != "application/json" ||
					len(r.Header.Values("X-Shopify-Api-Version")) != 1 || r.Header.Get("X-Shopify-Api-Version") != "2026-07" ||
					r.Header.Get("X-Shopify-Topic") != tc.topic || r.Header.Get("X-Shopify-Shop-Domain") != "legacy.myshopify.com" ||
					r.Header.Get("X-Shopify-Webhook-Id") != webhookID || r.Header.Get("X-Shopify-Triggered-At") != at {
					t.Error("legacy receiver routing/version contract differs")
					w.WriteHeader(400)
					return
				}
				if oauth.VerifyShopifyWebhook(f.server.Providers["shopify"], body, r.Header.Get("X-Shopify-Hmac-Sha256")) != nil {
					t.Error("signature was not recomputed over the exact forwarded body")
					w.WriteHeader(401)
					return
				}
				secret, readErr := os.ReadFile(f.server.Providers["shopify"].SecretFile)
				verified, verifyErr := VerifyLegacyShopifyDelivery(r, body, secret, endpointAudience(r), time.Now())
				if readErr != nil || verifyErr != nil || !verified {
					t.Error("relay envelope not authenticated")
					w.WriteHeader(401)
					return
				}
				if tc.topic == "app/uninstalled" {
					var payload struct {
						ID uint64 `json:"id"`
					}
					decoder := json.NewDecoder(bytes.NewReader(body))
					decoder.DisallowUnknownFields()
					var extra any
					if decoder.Decode(&payload) != nil || payload.ID != 123 || decoder.Decode(&extra) != io.EOF {
						t.Error("uninstall is not the legacy receiver's exact minimal id object")
						w.WriteHeader(400)
						return
					}
				}
				w.WriteHeader(200)
			}))
			defer endpoint.Close()
			routes := map[string]string{}
			for _, topic := range []string{"app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"} {
				routes[topic] = endpoint.URL + "/webhook"
			}
			if err := f.server.ConfigureLegacyShopifyWebhooks(routes); err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest("POST", f.http.URL+"/v1/webhooks/shopify", strings.NewReader(tc.body))
			secret, err := os.ReadFile(f.server.Providers["shopify"].SecretFile)
			if err != nil {
				t.Fatal(err)
			}
			mac := hmac.New(sha256.New, secret)
			mac.Write([]byte(tc.body))
			req.Header.Set("X-Shopify-Hmac-Sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
			req.Header.Set("X-Shopify-Shop-Domain", "legacy.myshopify.com")
			req.Header.Set("X-Shopify-Topic", tc.topic)
			req.Header.Set("X-Shopify-Webhook-Id", webhookID)
			req.Header.Set("X-Shopify-Triggered-At", at)
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("signed synthetic notification rejected", response.StatusCode)
			}
			for _, event := range f.server.Store.snapshot().Events {
				if event.Legacy == nil {
					continue
				}
				body, err := f.server.decryptEvent(event)
				if err != nil || !bytes.Contains(body, []byte(`"shop_domain":"legacy.myshopify.com"`)) {
					t.Fatal("native receipt lost its authenticated shop binding")
				}
			}
			f.server.DeliverLegacyShopifyWebhooks(context.Background())
			if calls.Load() != 1 {
				t.Fatal("expected one legacy delivery")
			}
			for _, event := range f.server.Store.snapshot().Events {
				if event.Legacy != nil && !event.Legacy.Acknowledged {
					t.Fatal("strict synthetic recipient did not acknowledge delivery")
				}
			}
		})
	}
}

func TestLegacyMinimalUninstallRejectsInvalidIdentity(t *testing.T) {
	for _, body := range []string{`{}`, `{"id":0}`, `{"id":-1}`, `{"id":"123"}`, `{"id":123} {}`, `null`} {
		if _, err := legacyShopifyBody("app/uninstalled", []byte(body)); err == nil {
			t.Fatal("invalid uninstall identity accepted")
		}
	}
}

func endpointAudience(r *http.Request) string { return "http://" + r.Host + r.URL.Path }
