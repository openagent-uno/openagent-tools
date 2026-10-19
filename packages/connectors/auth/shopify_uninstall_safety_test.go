package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// Historical fixture evidence is explicit; production never backfills these
// fields from AuthorizedAt, token refresh or current group membership.
func knownAuthorizationBefore(t *testing.T, f *fixture, group string, at time.Time) {
	t.Helper()
	if err := f.server.Store.update(func(s *State) error {
		g := s.Groups[group]
		g.AuthorizedAt = at
		g.LastAuthorizationAcquiredAt = at
		g.AuthorizationAcquisitionUncertain = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func safetyRelay(t *testing.T, f *fixture) *atomic.Int64 {
	t.Helper()
	calls := new(atomic.Int64)
	if err := os.WriteFile(f.server.Providers["shopify"].SecretFile, []byte("safety-relay-test-key-at-least-32-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	t.Cleanup(endpoint.Close)
	routes := map[string]string{}
	for _, topic := range []string{"app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"} {
		routes[topic] = endpoint.URL + "/fixed"
	}
	if err := f.server.ConfigureLegacyShopifyWebhooks(routes); err != nil {
		t.Fatal(err)
	}
	return calls
}
func assertUninstallHeld(t *testing.T, f *fixture, c *Client, id, reason string) {
	t.Helper()
	e := f.server.Store.snapshot().Events[id]
	if e == nil || e.PendingReason != reason || !e.UninstallSafetyChecked || e.NativeEmitted || e.Ciphertext == "" {
		t.Fatal("unsafe uninstall not durably quarantined")
	}
	rows, err := c.EventsV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID == id {
			t.Fatal("unsafe native receipt emitted")
		}
	}
	if err := c.Acknowledge(context.Background(), id); err == nil {
		t.Fatal("unsafe receipt acknowledged")
	}
}
func TestShopifyLateUninstallAfterUnobservedReauthorizationRemainsPending(t *testing.T) {
	for _, newMember := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing_member", true: "new_member"}[newMember], func(t *testing.T) {
			f, a, group := receiptRecipient(t)
			calls := safetyRelay(t, f)
			ctx := context.Background()
			now := time.Now().UTC()
			old := now.Add(-100 * time.Hour)
			uninstall := now.Add(-49 * time.Hour)
			knownAuthorizationBefore(t, f, group, old)
			target := a
			if newMember {
				target = f.client(t, "new member")
			}
			rotation, err := target.Redeem(ctx, f.consent(t, target).ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = target.Publish(ctx, rotation); err != nil {
				t.Fatal(err)
			}
			g := f.server.Store.snapshot().Groups[group]
			if g.Revoked || !g.AuthorizedAt.Equal(old) || !g.LastAuthorizationAcquiredAt.After(uninstall) || g.AuthorizationAcquisitionUncertain {
				t.Fatal("fixture did not reproduce unseen uninstall before successful acquisition")
			}
			id := receiptWebhook(t, f, "app/uninstalled", "late-unseen", uninstall)
			assertUninstallHeld(t, f, target, id, uninstallAfterAcquisition)
			// A duplicate cannot change the first safety decision, original
			// occurrence, encrypted payload or receipt identity.
			before := f.server.Store.snapshot().Events[id]
			receiptWebhook(t, f, "app/uninstalled", "late-unseen", uninstall)
			after := f.server.Store.snapshot().Events[id]
			if after.PendingReason != before.PendingReason || after.Ciphertext != before.Ciphertext || after.Nonce != before.Nonce || after.BodySHA256 != before.BodySHA256 || !after.OccurredAt.Equal(before.OccurredAt) {
				t.Fatal("duplicate changed quarantine")
			}
			redactID := receiptWebhook(t, f, "shop/redact", "paired-with-unsafe", now)
			if _, err = target.EventsV2(ctx); err != nil {
				t.Fatal(err)
			}
			e := f.server.Store.snapshot().Events[redactID]
			if e.UninstallEventID != "" || e.AuthorizationCutoffAt != nil || e.PendingReason != uninstallPairPending {
				t.Fatal("unsafe uninstall authorized delayed redaction")
			}
			if err = target.Acknowledge(ctx, redactID); err == nil {
				t.Fatal("unsafe redaction acknowledged")
			}
			f.server.DeliverLegacyShopifyWebhooks(ctx)
			if calls.Load() != 0 {
				t.Fatal("unsafe cutoff relayed")
			}
			if f.server.Store.snapshot().Groups[group].Revoked {
				t.Fatal("late uninstall revoked newer pair")
			}
			restarted, err := NewStore(f.path)
			if err != nil {
				t.Fatal(err)
			}
			f.server.Store = restarted
			assertUninstallHeld(t, f, target, id, uninstallAfterAcquisition)
			current := receiptWebhook(t, f, "app/uninstalled", "current-T3", time.Now().UTC())
			if !f.server.Store.snapshot().Groups[group].Revoked {
				t.Fatal("current ordered uninstall did not revoke")
			}
			rows, err := target.EventsV2(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range rows {
				found = found || r.ID == current
			}
			if !found {
				t.Fatal("current uninstall not emitted")
			}
			f.server.DeliverLegacyShopifyWebhooks(ctx)
			if calls.Load() != 1 {
				t.Fatal("current uninstall not relayed exactly once")
			}
		})
	}
}

func TestShopifyPendingUninstallCannotDisambiguateAnotherCounterpart(t *testing.T) {
	now := time.Now().UTC()
	group := groupID("fixture-app", "example.myshopify.com")
	safe := testNativeEvent("safe-old-uninstall", group, "app/uninstalled", now.Add(-70*time.Hour))
	uncertain := testNativeEvent("uncertain-uninstall", group, "app/uninstalled", now.Add(-60*time.Hour))
	uncertain.PendingReason = uninstallAfterAcquisition
	redact := testNativeEvent("redact-with-uncertain-counterpart", group, "shop/redact", now)
	state := State{Events: map[string]*Event{safe.ID: safe, uncertain.ID: uncertain, redact.ID: redact}}
	reconcileShopRedacts(&state)
	if redact.PendingReason != uninstallPairPending || redact.UninstallEventID != "" || redact.AuthorizationCutoffAt != nil || cutoffDeliveryReady(&state, redact) {
		t.Fatal("pending uninstall made another counterpart appear uniquely safe")
	}
}

func TestShopifyHistoricalSealedPairIsHeldWithoutRebinding(t *testing.T) {
	f, c, group := receiptRecipient(t)
	now := time.Now().UTC()
	u := testNativeEvent("unverified-historical-uninstall", group, "app/uninstalled", now.Add(-60*time.Hour))
	u.UninstallSafetyChecked = false
	r := testNativeEvent("historical-sealed-redact", group, "shop/redact", now)
	r.UninstallEventID, r.AuthorizationCutoffAt, r.NativeEmitted = u.ID, u.AuthorizationCutoffAt, true
	u.Acknowledged[c.Identity.ID()] = false
	r.Acknowledged[c.Identity.ID()] = false
	if err := f.server.Store.update(func(state *State) error {
		state.Events[u.ID], state.Events[r.ID] = u, r
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Store = restarted
	actual := restarted.snapshot().Events[r.ID]
	if actual.PendingReason != uninstallPairPending || !actual.NativeEmitted || actual.UninstallEventID != u.ID || !actual.AuthorizationCutoffAt.Equal(u.OccurredAt) {
		t.Fatal("historical sealed pair was changed or released")
	}
	if err := c.Acknowledge(context.Background(), r.ID); err == nil {
		t.Fatal("historical unverified pair acknowledged")
	}
}
func TestShopifyUninstallDuringAuthorizationAndFailedAcquisitionRemainPending(t *testing.T) {
	f, c, group := receiptRecipient(t)
	calls := safetyRelay(t, f)
	ctx := context.Background()
	p := f.server.Providers["shopify"]
	operation := "inflight-authorization"
	if _, err := f.server.beginRotation(p, "example.myshopify.com", c.Identity.ID(), operation, 0, true); err != nil {
		t.Fatal(err)
	}
	id := receiptWebhook(t, f, "app/uninstalled", "during-provider-io", time.Now().UTC())
	assertUninstallHeld(t, f, c, id, uninstallAcquisitionPending)
	g := f.server.Store.snapshot().Groups[group]
	if g.Revoked || g.Pending != operation || !g.AuthorizationAcquisitionUncertain {
		t.Fatal("uninstall interrupted in-flight acquisition")
	}
	f.server.failedRotation(group, operation)
	restarted, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Store = restarted
	if !restarted.snapshot().Groups[group].AuthorizationAcquisitionUncertain {
		t.Fatal("failure/restart erased acquisition uncertainty")
	}
	later := receiptWebhook(t, f, "app/uninstalled", "after-uncertain-provider-result", time.Now().UTC())
	assertUninstallHeld(t, f, c, later, uninstallAcquisitionPending)
	// A successful later authorization establishes only its actual acquisition
	// time. It never unblocks the earlier ambiguous obligations.
	op := "resolved-authorization"
	if _, err = f.server.beginRotation(p, "example.myshopify.com", c.Identity.ID(), op, 0, true); err != nil {
		t.Fatal(err)
	}
	token := oauth.Token{ShopID: 123, AppID: p.AppID, ExternalID: "example.myshopify.com", Scopes: p.Scopes, AccessToken: "fresh-access", RefreshToken: "fresh-refresh"}
	if _, err = f.server.finishRotation(group, op, c.Identity.ID(), &token); err != nil {
		t.Fatal(err)
	}
	assertUninstallHeld(t, f, c, id, uninstallAcquisitionPending)
	f.server.DeliverLegacyShopifyWebhooks(ctx)
	if calls.Load() != 0 {
		t.Fatal("ambiguity silently resolved into relay")
	}
}
func TestShopifyUnknownHistoricalAuthorizationIsNotBackfilled(t *testing.T) {
	f, c, group := receiptRecipient(t)
	calls := safetyRelay(t, f)
	if err := f.server.Store.update(func(s *State) error { s.Groups[group].LastAuthorizationAcquiredAt = time.Time{}; return nil }); err != nil {
		t.Fatal(err)
	}
	id := receiptWebhook(t, f, "app/uninstalled", "unknown-group-acquisition", time.Now().UTC())
	assertUninstallHeld(t, f, c, id, uninstallHistoryUnknown)
	if f.server.Store.snapshot().Groups[group].Revoked {
		t.Fatal("unknown history revoked a pair")
	}
	// Old stored receipts do not acquire safety merely because a new release
	// can see today's group. Loading records an explicit pending decision.
	if err := f.server.Store.update(func(s *State) error {
		e := s.Events[id]
		e.UninstallSafetyChecked = false
		e.PendingReason = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Store = restarted
	assertUninstallHeld(t, f, c, id, uninstallHistoryUnknown)
	f.server.DeliverLegacyShopifyWebhooks(context.Background())
	if calls.Load() != 0 {
		t.Fatal("unknown historical receipt relayed")
	}
}
func TestShopifyObservedUninstallBeforeNewConsentRemainsDeliverable(t *testing.T) {
	f, c, group := receiptRecipient(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-50 * time.Hour)
	knownAuthorizationBefore(t, f, group, old.Add(-time.Hour))
	id := receiptWebhook(t, f, "app/uninstalled", "known-ordered", old)
	if !f.server.Store.snapshot().Groups[group].Revoked {
		t.Fatal("ordered uninstall not applied")
	}
	next, err := c.Redeem(ctx, f.consent(t, c).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Publish(ctx, next); err != nil {
		t.Fatal(err)
	}
	if next.Token.AuthorizedAt == nil || !next.Token.AuthorizedAt.After(old) {
		t.Fatal("observed new consent not advanced")
	}
	redact := receiptWebhook(t, f, "shop/redact", "ordered-redact", now)
	rows, err := c.EventsV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, r := range rows {
		found[r.ID] = true
	}
	if !found[id] || !found[redact] || f.server.Store.snapshot().Groups[group].Revoked {
		t.Fatal("ordered historical receipts lost or new consent revoked")
	}
}
