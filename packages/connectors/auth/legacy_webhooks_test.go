package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func webhookRequest(t *testing.T, f *fixture, topic, shop, body string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", f.http.URL+"/v1/webhooks/shopify", strings.NewReader(body))
	mac := hmac.New(sha256.New, []byte("test-app-secret"))
	mac.Write([]byte(body))
	req.Header.Set("X-Shopify-Hmac-Sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Shopify-Shop-Domain", shop)
	req.Header.Set("X-Shopify-Topic", topic)
	req.Header.Set("X-Shopify-Webhook-Id", "legacy-webhook")
	req.Header.Set("X-Shopify-Triggered-At", time.Now().UTC().Format(time.RFC3339Nano))
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode
}

func TestSignedWebhookCannotRevokeAnotherShopByChangingHeaders(t *testing.T) {
	f := newFixture(t)
	client := f.client(t, "recipient")
	if _, err := client.Redeem(context.Background(), f.consent(t, client).ID); err != nil {
		t.Fatal(err)
	}
	before := f.server.Store.snapshot()
	status := webhookRequest(t, f, "app/uninstalled", "example.myshopify.com", `{"id":456}`)
	if status != 400 {
		t.Fatal("signed ID mismatch accepted", status)
	}
	for id, g := range f.server.Store.snapshot().Groups {
		if g.Revoked || g.Version != before.Groups[id].Version {
			t.Fatal("wrong shop grant was modified")
		}
	}
	status = webhookRequest(t, f, "shop/redact", "example.myshopify.com", `{"shop_id":123,"shop_domain":"another.myshopify.com"}`)
	if status != 400 {
		t.Fatal("signed domain mismatch accepted", status)
	}
}

func TestLegacyWebhookQueueSurvivesOfflineRecipientRestartAndDuplicates(t *testing.T) {
	f := newFixture(t)
	var calls atomic.Int64
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if oauth.VerifyShopifyWebhook(f.server.Providers["shopify"], body, r.Header.Get("X-Shopify-Hmac-Sha256")) != nil {
			t.Error("forwarded notification signature invalid")
		}
		if strings.Contains(string(body), "not-retained") {
			t.Error("legacy queue retained unrelated source payload")
		}
		if r.Header.Get("X-Shopify-Webhook-Id") != "legacy-webhook" {
			t.Error("deduplication ID changed")
		}
		if count == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer endpoint.Close()
	routes := map[string]string{}
	for _, topic := range []string{"app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"} {
		routes[topic] = endpoint.URL + "/webhook"
	}
	if err := f.server.ConfigureLegacyShopifyWebhooks(routes); err != nil {
		t.Fatal(err)
	}
	body := `{"shop_id":123,"shop_domain":"legacy.myshopify.com","customer":{"id":7,"email":"private@example.com"},"irrelevant":"not-retained"}`
	for i := 0; i < 2; i++ {
		if status := webhookRequest(t, f, "customers/redact", "legacy.myshopify.com", body); status != 200 {
			t.Fatal(status)
		}
	}
	f.server.DeliverLegacyShopifyWebhooks(context.Background())
	if calls.Load() != 1 {
		t.Fatal("duplicate source notification forwarded twice")
	}
	state := f.server.Store.snapshot()
	if len(state.Events) != 1 {
		t.Fatal("legacy delivery missing without broker recipient group")
	}
	for _, event := range state.Events {
		if event.Legacy.Acknowledged || event.Ciphertext == "" {
			t.Fatal("offline recipient lost durable payload")
		}
	}
	store, err := NewStore(f.path)
	if err != nil {
		t.Fatal(err)
	}
	provider := f.server.Providers["shopify"]
	restarted, err := NewServer(store, oauth.Engine{AllowLoopback: true}, []oauth.Provider{provider}, f.server.Origin, f.server.EventKey)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return time.Now().UTC().Add(time.Minute) }
	restarted.DeliverLegacyShopifyWebhooks(context.Background())
	restarted.DeliverLegacyShopifyWebhooks(context.Background())
	if calls.Load() != 2 {
		t.Fatal("delivery not recovered or acknowledged delivery repeated")
	}
	for _, event := range store.snapshot().Events {
		if !event.Legacy.Acknowledged || event.Ciphertext != "" {
			t.Fatal("acknowledged payload retained")
		}
	}
}

func TestLegacyWebhookRoutesRejectPartialOrUnsafeReceiver(t *testing.T) {
	f := newFixture(t)
	if f.server.ConfigureLegacyShopifyWebhooks(map[string]string{"shop/redact": "https://example.com/hook"}) == nil {
		t.Fatal("partial privacy migration accepted")
	}
	routes := map[string]string{}
	for _, topic := range []string{"app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"} {
		routes[topic] = "https://example.com/hook"
	}
	routes["shop/redact"] = "https://user:credential@example.com/hook"
	if f.server.ConfigureLegacyShopifyWebhooks(routes) == nil {
		t.Fatal("credential-bearing destination accepted")
	}
}

func TestNativeAcknowledgmentKeepsPayloadForOfflineLegacyProcessor(t *testing.T) {
	f := newFixture(t)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer endpoint.Close()
	routes := map[string]string{}
	for _, topic := range []string{"app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"} {
		routes[topic] = endpoint.URL + "/webhook"
	}
	if err := f.server.ConfigureLegacyShopifyWebhooks(routes); err != nil {
		t.Fatal(err)
	}
	client := f.client(t, "new-recipient")
	rotation, err := client.Redeem(context.Background(), f.consent(t, client).ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Publish(context.Background(), rotation); err != nil {
		t.Fatal(err)
	}
	status := webhookRequest(t, f, "customers/redact", "example.myshopify.com", `{"shop_id":123,"shop_domain":"example.myshopify.com","customer":{"id":7}}`)
	if status != 200 {
		t.Fatal(status)
	}
	events, err := client.Events(context.Background())
	if err != nil || len(events) != 1 {
		t.Fatal(err, len(events))
	}
	if err = client.Acknowledge(context.Background(), events[0].ID); err != nil {
		t.Fatal(err)
	}
	f.server.DeliverLegacyShopifyWebhooks(context.Background())
	event := f.server.Store.snapshot().Events[events[0].ID]
	if event.Ciphertext == "" || event.Legacy.Acknowledged {
		t.Fatal("native acknowledgment erased legacy obligation")
	}
}
