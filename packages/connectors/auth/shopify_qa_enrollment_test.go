package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func TestShopifyQAAdmissionPreservesOtherProvidersAndPublicEnrollment(t *testing.T) {
	f := newFixture(t)
	a, b := f.client(t, "QA A"), f.client(t, "QA B")
	outside := f.client(t, "Existing production host")
	p := f.server.Providers["shopify"]
	p.ID, p.AppID, p.Scopes = "clickup", "clickup:existing", []string{}
	p.RedirectURI = f.http.URL + "/v1/oauth/clickup/callback"
	f.server.Providers[p.ID] = p
	binding := TokenBinding{Installation: outside.Identity.ID(), Provider: "clickup", AppID: p.AppID, ExternalID: "existing-account"}
	if err := f.server.Store.update(func(state *State) error { state.TokenBindings["existing-grant-hash"] = binding; return nil }); err != nil {
		t.Fatal(err)
	}
	before := f.server.Store.snapshot()
	if err := f.server.ConfigureShopifyQAEnrollment(QAEnrollment{Installations: []string{a.Identity.ID(), b.Identity.ID()}, ShopifyStores: []string{"example.myshopify.com"}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.server.Store.snapshot()) || f.server.QAEnrollmentEnabled() {
		t.Fatal("scoped QA changed metadata or global enrollment")
	}
	ctx := context.Background()
	outside = f.client(t, "New unrelated host after scoped startup")
	if err := outside.Register(ctx); err != nil {
		t.Fatal("public registration blocked", err)
	}
	if _, err := outside.Start(ctx, Start{Provider: "clickup"}); err != nil {
		t.Fatal("unrelated provider blocked", err)
	}
	var remote *RemoteError
	for _, shop := range []string{"example.myshopify.com", "production.myshopify.com"} {
		if _, err := outside.Start(ctx, Start{Provider: "shopify", Shop: shop}); !errors.As(err, &remote) || remote.Status != 403 {
			t.Fatal("unlisted Shopify installation admitted", err)
		}
	}
	for _, shop := range []string{"", "production.myshopify.com"} {
		if _, err := a.Start(ctx, Start{Provider: "shopify", Shop: shop}); !errors.As(err, &remote) || remote.Code != "qa_shop_not_admitted" {
			t.Fatal("unreviewed Shopify store admitted", err)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("denied admission contacted provider")
	}
	res, err := http.Get(f.http.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var health map[string]any
	if json.NewDecoder(res.Body).Decode(&health) != nil || health["enrollment"] != "public" || health["shopify_enrollment"] != "qa" {
		t.Fatal("scoped enrollment not reported truthfully")
	}
	// Exercise actual Shopify exchange, peer publication, refresh and privacy ACKs.
	first, err := a.Redeem(ctx, f.consent(t, a).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := b.Redeem(ctx, f.consent(t, b).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Publish(ctx, second); err != nil {
		t.Fatal(err)
	}
	mail, err := a.Mail(ctx)
	if err != nil || len(mail.Envelopes) != 1 {
		t.Fatal("peer synchronization blocked", err)
	}
	wire, err := Open(a.Identity, mail.Installations[b.Identity.ID()], mail.Envelopes[0], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var updated oauth.Token
	if json.Unmarshal(wire, &updated) != nil {
		t.Fatal("invalid peer token wire")
	}
	if err = a.Commit(ctx, second.Group, updated.Version); err != nil {
		t.Fatal(err)
	}
	next, err := a.Refresh(ctx, "shopify", updated)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Publish(ctx, next); err != nil {
		t.Fatal(err)
	}
	if status := webhookRequest(t, f, "customers/data_request", "production.myshopify.com", `{"shop_id":123}`); status != 403 {
		t.Fatal("foreign shop webhook admitted", status)
	}
	if status := webhookRequest(t, f, "customers/data_request", "example.myshopify.com", `{"shop_id":123,"customer":{"id":7},"orders_requested":[],"data_request":{"id":9}}`); status != 200 {
		t.Fatal("QA webhook rejected", status)
	}
	for _, c := range []*Client{a, b} {
		events, err := c.Events(ctx)
		if err != nil || len(events) != 1 {
			t.Fatal("missing QA privacy recipient", err)
		}
		if err = c.Acknowledge(ctx, events[0].ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, call := range []func() error{
		func() error { _, err := outside.Mail(ctx); return err },
		func() error { _, err := outside.Events(ctx); return err },
		func() error { return outside.Commit(ctx, first.Group, 1) },
		func() error { _, err := outside.Refresh(ctx, "shopify", next.Token); return err },
	} {
		if err := call(); !errors.As(err, &remote) || remote.Status != 403 {
			t.Fatal("Shopify coordination bypassed scoped admission", err)
		}
	}
	if got := f.server.Store.snapshot().TokenBindings["existing-grant-hash"]; !reflect.DeepEqual(got, binding) {
		t.Fatal("unrelated grant changed")
	}
}

func TestShopifyQAConfigurationRejectsMixedAuthority(t *testing.T) {
	for _, name := range []string{"missing-provider", "global-before", "global-after", "legacy-before", "legacy-after", "empty-identities", "duplicate-identities", "invalid-identity", "empty-stores", "duplicate-stores", "invalid-store", "foreign-group", "foreign-member", "foreign-recipient", "foreign-pending", "foreign-binding", "legacy-queue", "orphan-event", "foreign-event-recipient", "configure-twice"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			a := f.client(t, "QA")
			other := f.client(t, "Production")
			config := QAEnrollment{Installations: []string{a.Identity.ID()}, ShopifyStores: []string{"example.myshopify.com"}}
			routes := map[string]string{}
			for _, topic := range []string{"app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"} {
				routes[topic] = "https://legacy.example.invalid/webhook"
			}
			switch name {
			case "missing-provider":
				delete(f.server.Providers, "shopify")
			case "global-before":
				if err := f.server.ConfigureQAEnrollment(config); err != nil {
					t.Fatal(err)
				}
			case "global-after", "legacy-after", "configure-twice":
				if err := f.server.ConfigureShopifyQAEnrollment(config); err != nil {
					t.Fatal(err)
				}
				var err error
				if name == "global-after" {
					err = f.server.ConfigureQAEnrollment(config)
				} else if name == "legacy-after" {
					err = f.server.ConfigureLegacyShopifyWebhooks(routes)
				} else {
					err = f.server.ConfigureShopifyQAEnrollment(config)
				}
				if err == nil {
					t.Fatal("mixed or repeated startup configuration accepted")
				}
				return
			case "legacy-before":
				if err := f.server.ConfigureLegacyShopifyWebhooks(routes); err != nil {
					t.Fatal(err)
				}
			case "empty-identities":
				config.Installations = nil
			case "duplicate-identities":
				config.Installations = append(config.Installations, a.Identity.ID())
			case "invalid-identity":
				config.Installations = []string{strings.Repeat("A", 64)}
			case "empty-stores":
				config.ShopifyStores = nil
			case "duplicate-stores":
				config.ShopifyStores = append(config.ShopifyStores, "example.myshopify.com")
			case "invalid-store":
				config.ShopifyStores = []string{"example.com"}
			default:
				if err := f.server.Store.update(func(state *State) error {
					g := &Group{AppID: f.server.Providers["shopify"].AppID, Shop: "example.myshopify.com", Members: map[string]uint64{a.Identity.ID(): 1}, PrivacyRecipients: map[string]bool{a.Identity.ID(): true}}
					switch name {
					case "foreign-group":
						g.Shop = "production.myshopify.com"
					case "foreign-member":
						g.Members[other.Identity.ID()] = 1
					case "foreign-recipient":
						g.PrivacyRecipients[other.Identity.ID()] = true
					case "foreign-pending":
						g.Pending = other.Identity.ID()
					case "foreign-binding":
						state.TokenBindings["foreign"] = TokenBinding{Provider: "shopify", AppID: g.AppID, Installation: other.Identity.ID(), ExternalID: g.Shop}
					case "legacy-queue":
						state.Events["pending"] = &Event{Legacy: &LegacyDelivery{}}
					case "orphan-event":
						state.Events["orphan"] = &Event{Group: "missing"}
					case "foreign-event-recipient":
						state.Events["pending"] = &Event{Group: "existing", Acknowledged: map[string]bool{other.Identity.ID(): false}}
					}
					state.Groups["existing"] = g
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.server.ConfigureShopifyQAEnrollment(config); err == nil {
				t.Fatal("mixed scoped QA configuration accepted")
			}
		})
	}
}

func TestShopifyQARejectsPreexistingForeignTransactionsBeforeProviderIO(t *testing.T) {
	f := newFixture(t)
	admitted := f.client(t, "QA")
	foreign := f.client(t, "Outside scoped cohort")
	ready := f.consent(t, foreign)
	pending, state := f.approval(t, foreign)
	if err := f.server.ConfigureShopifyQAEnrollment(QAEnrollment{Installations: []string{admitted.Identity.ID()}, ShopifyStores: []string{"example.myshopify.com"}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := foreign.Transaction(ctx, ready.ID); err == nil {
		t.Fatal("foreign transaction poll admitted")
	}
	if _, err := foreign.Redeem(ctx, ready.ID); err == nil {
		t.Fatal("foreign ready transaction redeemed")
	}
	for _, target := range []string{pending.AuthorizationURL, f.http.URL + "/v1/oauth/shopify/callback?state=" + state} {
		response, err := http.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal("foreign browser transaction admitted", response.StatusCode)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("denied preexisting transaction contacted provider")
	}
	if f.server.transactions[ready.ID].Status != "ready" || f.server.transactions[pending.ID].Status != "pending" || len(f.server.Store.snapshot().Groups) != 0 {
		t.Fatal("denied transaction changed credential state")
	}
}
