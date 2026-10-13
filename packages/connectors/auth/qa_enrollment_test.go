package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestQAAdmissionPinsIdentityAndStoreBeforeOAuthStart(t *testing.T) {
	f := newFixture(t)
	a := f.client(t, "A")
	b := f.client(t, "same operator label")
	if err := f.server.ConfigureQAEnrollment(QAEnrollment{Installations: []string{a.Identity.ID()}, ShopifyStores: []string{"example.myshopify.com"}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var remote *RemoteError
	if _, err := b.Start(ctx, Start{Provider: "shopify", Shop: "example.myshopify.com"}); !errors.As(err, &remote) || remote.Status != 403 || remote.Code != "qa_installation_not_admitted" {
		t.Fatal("registered non-QA identity started OAuth", err)
	}
	if err := b.Register(ctx); !errors.As(err, &remote) || remote.Status != 403 {
		t.Fatal("registration bypassed QA gate", err)
	}
	for _, shop := range []string{"", "production.myshopify.com"} {
		if _, err := a.Start(ctx, Start{Provider: "shopify", Shop: shop}); !errors.As(err, &remote) || remote.Status != 403 || remote.Code != "qa_shop_not_admitted" {
			t.Fatal("unreviewed shop started OAuth", shop, err)
		}
	}
	if len(f.server.transactions) != 0 || f.calls.Load() != 0 {
		t.Fatal("denied request allocated OAuth state or contacted provider")
	}
	if _, err := a.Start(ctx, Start{Provider: "shopify", Shop: "example.myshopify.com"}); err != nil {
		t.Fatal("QA recipient cannot start reviewed shop", err)
	}
	res, err := http.Get(f.http.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var health map[string]any
	if json.NewDecoder(res.Body).Decode(&health) != nil || health["enrollment"] != "qa" || !f.server.QAEnrollmentEnabled() {
		t.Fatal("QA mistaken for public activation")
	}
	if status := webhookRequest(t, f, "customers/redact", "production.myshopify.com", `{"shop_id":123,"shop_domain":"production.myshopify.com"}`); status != 403 {
		t.Fatal("QA received a production shop notification", status)
	}
}

func TestQAConfigurationRefusesLegacyDeliveryAndMixedGroups(t *testing.T) {
	for _, test := range []string{"legacy-before", "legacy-after", "production-group", "empty-identities", "duplicate-identities", "invalid-identity", "missing-stores"} {
		t.Run(test, func(t *testing.T) {
			f := newFixture(t)
			a := f.client(t, "A")
			config := QAEnrollment{Installations: []string{a.Identity.ID()}, ShopifyStores: []string{"example.myshopify.com"}}
			routes := map[string]string{}
			for _, topic := range []string{"app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"} {
				routes[topic] = "https://legacy.example.invalid/webhook"
			}
			switch test {
			case "legacy-before":
				if err := f.server.ConfigureLegacyShopifyWebhooks(routes); err != nil {
					t.Fatal(err)
				}
			case "legacy-after":
				if err := f.server.ConfigureQAEnrollment(config); err != nil {
					t.Fatal(err)
				}
				if err := f.server.ConfigureLegacyShopifyWebhooks(routes); err == nil {
					t.Fatal("QA mixed with legacy deliveries")
				}
				return
			case "production-group":
				if err := f.server.Store.update(func(state *State) error {
					state.Groups["production"] = &Group{Shop: "production.myshopify.com", PrivacyRecipients: map[string]bool{a.Identity.ID(): true}}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case "empty-identities":
				config.Installations = nil
			case "duplicate-identities":
				config.Installations = append(config.Installations, a.Identity.ID())
			case "invalid-identity":
				config.Installations = []string{strings.Repeat("z", 64)}
			case "missing-stores":
				config.ShopifyStores = nil
			}
			if err := f.server.ConfigureQAEnrollment(config); err == nil {
				t.Fatal("invalid QA isolation accepted")
			}
		})
	}
}
