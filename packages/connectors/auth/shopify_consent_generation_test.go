package auth

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func TestShopifyAdditionalInstallationPreservesAuthenticatedConsentGeneration(t *testing.T) {
	f := newFixture(t)
	a, b := f.client(t, "Server A"), f.client(t, "Server B")
	ctx := context.Background()
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
	if first.Token.AuthorizedAt == nil || second.Token.AuthorizedAt == nil ||
		!first.Token.AuthorizedAt.Equal(*second.Token.AuthorizedAt) || second.Token.Version <= first.Token.Version {
		t.Fatal("joining the same active grant changed its consent generation")
	}
	if err = b.Publish(ctx, second); err != nil {
		t.Fatal(err)
	}
	mail, err := a.Mail(ctx)
	if err != nil || len(mail.Envelopes) != 1 {
		t.Fatalf("missing authenticated peer envelope: %v", err)
	}
	body, err := Open(a.Identity, mail.Installations[b.Identity.ID()], mail.Envelopes[0], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var token oauth.Token
	if json.Unmarshal(body, &token) != nil || !mail.Groups[second.Group].Validates(token) ||
		token.AuthorizedAt == nil || !token.AuthorizedAt.Equal(*first.Token.AuthorizedAt) {
		t.Fatal("peer token lost its verified consent binding")
	}
	// The host can durably save the same-consent token before acknowledging it.
	if err = a.Commit(ctx, second.Group, token.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Refresh(ctx, "shopify", token); err != nil {
		t.Fatalf("updated peer could not renew: %v", err)
	}
}

func TestShopifyConsentGenerationResetsOnlyForNewGrant(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutate    func(*Group)
		authorize bool
		reset     bool
	}{
		{"additional-installation", func(*Group) {}, true, false},
		{"same-scopes-reordered", func(g *Group) { g.Scopes = []string{"read_inventory", "read_products"} }, true, false},
		{"ordinary-refresh", func(*Group) {}, false, false},
		{"first-consent", func(g *Group) { g.AuthorizedAt = time.Time{}; g.ShopID = 0 }, true, true},
		{"revoked-consent", func(g *Group) { g.Revoked = true }, true, true},
		{"changed-scopes", func(g *Group) { g.Scopes = []string{"read_products"} }, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			old := time.Now().UTC().Add(-time.Hour)
			now := old.Add(30 * time.Minute)
			f.server.now = func() time.Time { return now }
			g := &Group{ID: "fixture-group", AppID: "fixture-app", Shop: "example.myshopify.com", ShopID: 123,
				Version: 5, AuthorizedAt: old, Scopes: []string{"read_products", "read_inventory"},
				Pending: "fixture-operation", PendingUntil: now.Add(time.Minute), PendingAuthorization: tc.authorize,
				Members: map[string]uint64{}, PrivacyRecipients: map[string]bool{}}
			tc.mutate(g)
			if err := f.server.Store.update(func(s *State) error { s.Groups[g.ID] = g; return nil }); err != nil {
				t.Fatal(err)
			}
			token := oauth.Token{AppID: g.AppID, ExternalID: g.Shop, ShopID: 123,
				Scopes: []string{"read_products", "read_inventory"}, AccessToken: "fixture-access", RefreshToken: "fixture-refresh"}
			if _, err := f.server.finishRotation(g.ID, "fixture-operation", "fixture-installation", &token); err != nil {
				t.Fatal(err)
			}
			want := old
			if tc.reset {
				want = now
			}
			if token.AuthorizedAt == nil || !token.AuthorizedAt.Equal(want) || token.Version != 6 {
				t.Fatal("incorrect consent generation or credential version")
			}
		})
	}
}
