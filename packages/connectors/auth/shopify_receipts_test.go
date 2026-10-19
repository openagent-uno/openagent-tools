package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func receiptWebhook(t *testing.T, f *fixture, topic, id string, at time.Time) string {
	t.Helper()
	body := `{"shop_id":123}`
	if topic == "app/uninstalled" {
		body = `{"id":123}`
	}
	req, _ := http.NewRequest("POST", f.http.URL+"/v1/webhooks/shopify", strings.NewReader(body))
	secret, err := os.ReadFile(f.server.Providers["shopify"].SecretFile)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	req.Header.Set("X-Shopify-Hmac-Sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Shopify-Shop-Domain", "example.myshopify.com")
	req.Header.Set("X-Shopify-Topic", topic)
	req.Header.Set("X-Shopify-Webhook-Id", id)
	req.Header.Set("X-Shopify-Triggered-At", at.UTC().Format(time.RFC3339Nano))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("webhook status %d", res.StatusCode)
	}
	sum := sha256.Sum256([]byte(groupID(f.server.Providers["shopify"].AppID, "example.myshopify.com") + "/" + topic + "/" + id))
	return hex.EncodeToString(sum[:])
}

func receiptRecipient(t *testing.T) (*fixture, *Client, string) {
	t.Helper()
	f := newFixture(t)
	c := f.client(t, "receipt-v2")
	rotation, err := c.Redeem(context.Background(), f.consent(t, c).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Publish(context.Background(), rotation); err != nil {
		t.Fatal(err)
	}
	return f, c, rotation.Group
}

func requireReceiptRemote(t *testing.T, err error, status int) {
	t.Helper()
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Status != status {
		t.Fatalf("expected remote status %d, got %v", status, err)
	}
}

func TestShopifyReceiptCapabilityIsExplicitAndQueryClosed(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, "capability")
	c.ShopifyReceiptVersion = 0
	for _, version := range []int{0, 1} {
		_, err := c.Start(context.Background(), Start{Provider: "shopify", Shop: "example.myshopify.com", ReceiptVersion: version})
		requireReceiptRemote(t, err, 426)
	}
	if f.calls.Load() != 0 {
		t.Fatal("unsupported host made provider call")
	}
	for _, query := range []string{"receipt_version=1", "receipt_version=3", "receipt_version=2&receipt_version=2", "receipt_version=2&extra=1", "receipt_version=%32"} {
		err := c.call(context.Background(), "GET", "/v1/events?"+query, nil, nil)
		requireReceiptRemote(t, err, 400)
	}
	if _, err := c.Start(context.Background(), Start{Provider: "shopify", Shop: "example.myshopify.com", ReceiptVersion: 2}); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptV2DelayedRedactPreservesFreshConsentAndOriginalTime(t *testing.T) {
	f, c, group := receiptRecipient(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-49 * time.Hour)
	uninstallID := receiptWebhook(t, f, "app/uninstalled", "old-uninstall", old)
	redactID := receiptWebhook(t, f, "shop/redact", "delayed-redact", now)
	// Old hosts cannot consume or ACK unsafe notifications, including a guessed ID.
	_, err := c.Events(ctx)
	requireReceiptRemote(t, err, 426)
	if err = c.Acknowledge(ctx, redactID); err == nil {
		t.Fatal("unemitted redact acknowledged")
	}
	events, err := c.EventsV2(ctx)
	if err != nil || len(events) != 2 {
		t.Fatalf("v2 deliveries: %d %v", len(events), err)
	}
	var redact Delivery
	for _, event := range events {
		if event.ID == redactID {
			redact = event
		}
	}
	if redact.UninstallEventID != uninstallID || redact.AuthorizationCutoffAt == nil || !redact.AuthorizationCutoffAt.Equal(old) || !redact.OccurredAt.Equal(now) {
		t.Fatal("pair changed original notification or cutoff")
	}
	if f.server.Store.snapshot().Groups[group].Revoked {
		t.Fatal("old uninstall revoked newer consent")
	}
	// New older evidence arriving after first emission cannot rebind this receipt.
	receiptWebhook(t, f, "app/uninstalled", "even-older", old.Add(-time.Hour))
	stored, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Store = stored
	again, err := c.EventsV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range again {
		if event.ID == redactID && event.UninstallEventID != uninstallID {
			t.Fatal("emitted pair changed after restart")
		}
	}
	if err = c.Acknowledge(ctx, redactID); err != nil {
		t.Fatal(err)
	}
	before := len(stored.snapshot().Events)
	receiptWebhook(t, f, "shop/redact", "delayed-redact", now)
	if len(stored.snapshot().Events) != before || stored.snapshot().Events[redactID].UninstallEventID != uninstallID {
		t.Fatal("duplicate changed pair")
	}
}

func TestReceiptV2OutOfOrderStaysDurableUntilVerifiedUninstall(t *testing.T) {
	f, c, _ := receiptRecipient(t)
	ctx := context.Background()
	now := time.Now().UTC()
	redactID := receiptWebhook(t, f, "shop/redact", "first-redact", now)
	events, err := c.EventsV2(ctx)
	if err != nil || len(events) != 0 {
		t.Fatal("unpaired redact emitted", err)
	}
	if err = c.Acknowledge(ctx, redactID); err == nil {
		t.Fatal("unpaired redact acknowledged")
	}
	if f.server.Store.snapshot().Events[redactID].Ciphertext == "" {
		t.Fatal("pending payload lost")
	}
	// Too-recent uninstall cannot be substituted for the required old generation.
	receiptWebhook(t, f, "app/uninstalled", "recent-uninstall", now.Add(-time.Hour))
	events, err = c.EventsV2(ctx)
	if err != nil || len(events) != 1 || events[0].Topic != "app/uninstalled" {
		t.Fatal("recent uninstall paired", err)
	}
	uninstallID := receiptWebhook(t, f, "app/uninstalled", "late-old-uninstall", now.Add(-48*time.Hour))
	events, err = c.EventsV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.ID == redactID {
			found = true
			if event.UninstallEventID != uninstallID {
				t.Fatal("wrong uninstall")
			}
		}
	}
	if !found {
		t.Fatal("late verified uninstall did not unblock")
	}
}

func testNativeEvent(id, group, topic string, at time.Time) *Event {
	sum := sha256.Sum256([]byte(id))
	cutoff := at
	e := &Event{ShopID: 123, ID: hex.EncodeToString(sum[:]), Group: group, Topic: topic, ReceiptVersion: 2, OccurredAt: at, CreatedAt: at, AuthorizationCutoffAt: &cutoff, Acknowledged: map[string]bool{}}
	if topic == "shop/redact" {
		e.AuthorizationCutoffAt = nil
	}
	return e
}

func TestReceiptV2UniquePairMigrationAndImmutableEmission(t *testing.T) {
	group := groupID("app", "example.myshopify.com")
	now := time.Now().UTC()
	state := State{Events: map[string]*Event{}}
	old := testNativeEvent("historical-v1", group, "app/uninstalled", now.Add(-100*time.Hour))
	old.ReceiptVersion = 0
	old.AuthorizationCutoffAt = nil
	old.Acknowledged = map[string]bool{"retired": true}
	historicalRedact := testNativeEvent("historical-redact", group, "shop/redact", now.Add(-50*time.Hour))
	historicalRedact.ReceiptVersion = 0
	historicalRedact.Acknowledged = map[string]bool{"retired": true}
	u1 := testNativeEvent("u1", group, "app/uninstalled", now.Add(-60*time.Hour))
	r1 := testNativeEvent("r1", group, "shop/redact", now)
	for _, e := range []*Event{old, historicalRedact, u1, r1} {
		state.Events[e.ID] = e
	}
	reconcileShopRedacts(&state)
	if r1.UninstallEventID != u1.ID || historicalRedact.AuthorizationCutoffAt != nil {
		t.Fatal("historical v1 event was reinterpreted")
	}
	r1.NativeEmitted = true
	earlier := testNativeEvent("earlier", group, "app/uninstalled", now.Add(-70*time.Hour))
	state.Events[earlier.ID] = earlier
	reconcileShopRedacts(&state)
	if r1.UninstallEventID != u1.ID {
		t.Fatal("sealed pair changed")
	}
	r2 := testNativeEvent("r2", group, "shop/redact", now.Add(time.Hour))
	state.Events[r2.ID] = r2
	reconcileShopRedacts(&state)
	if r2.UninstallEventID != earlier.ID {
		t.Fatal("sealed pair's uninstall was reused")
	}
	// Exactly the documented 5-minute tolerance; no broader age relaxation.
	at := now.Add(-48*time.Hour + 5*time.Minute)
	boundary := testNativeEvent("boundary", group, "app/uninstalled", at)
	single := testNativeEvent("single", group, "shop/redact", now)
	boundaryState := State{Events: map[string]*Event{boundary.ID: boundary, single.ID: single}}
	reconcileShopRedacts(&boundaryState)
	if single.UninstallEventID != boundary.ID {
		t.Fatal("documented boundary rejected")
	}
	boundary.OccurredAt = at.Add(time.Nanosecond)
	cutoff := boundary.OccurredAt
	boundary.AuthorizationCutoffAt = &cutoff
	reconcileShopRedacts(&boundaryState)
	if single.AuthorizationCutoffAt != nil {
		t.Fatal("delay boundary widened")
	}
}

func TestReceiptV2AmbiguityNeverGuessesPair(t *testing.T) {
	f, c, _ := receiptRecipient(t)
	now := time.Now().UTC()
	receiptWebhook(t, f, "app/uninstalled", "candidate-one", now.Add(-60*time.Hour))
	receiptWebhook(t, f, "app/uninstalled", "candidate-two", now.Add(-55*time.Hour))
	redactID := receiptWebhook(t, f, "shop/redact", "ambiguous", now)
	events, err := c.EventsV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.ID == redactID {
			t.Fatal("ambiguous receipt emitted")
		}
	}
	if err = c.Acknowledge(context.Background(), redactID); err == nil {
		t.Fatal("ambiguous receipt acknowledged")
	}
	event := f.server.Store.snapshot().Events[redactID]
	if event.AuthorizationCutoffAt != nil || event.UninstallEventID != "" || event.NativeEmitted || event.Ciphertext == "" {
		t.Fatal("ambiguous receipt lost or guessed metadata")
	}
}

func TestReceiptV2PairRejectsTamperAndRevokesOnlyOldGrant(t *testing.T) {
	f, c, group := receiptRecipient(t)
	now := time.Now().UTC()
	old := now.Add(-49 * time.Hour)
	receiptWebhook(t, f, "app/uninstalled", "old-generation", old)
	redactID := receiptWebhook(t, f, "shop/redact", "old-generation-redact", now)
	// Exercise the old-grant branch without a provider call or fabricated receipt.
	if err := f.server.Store.update(func(state *State) error { state.Groups[group].AuthorizedAt = old.Add(-time.Second); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EventsV2(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := f.server.Store.snapshot()
	if !state.Groups[group].Revoked {
		t.Fatal("old grant survived authenticated cutoff")
	}
	redact := state.Events[redactID]
	cutoff := now
	redact.AuthorizationCutoffAt = &cutoff
	if validNativeReceipt(&state, redact) {
		t.Fatal("altered cutoff accepted")
	}
	redact.AuthorizationCutoffAt = &old
	redact.UninstallEventID = strings.Repeat("a", 64)
	if validNativeReceipt(&state, redact) {
		t.Fatal("unknown pair accepted")
	}
}
