package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func receiptFixture() Delivery {
	cutoff := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	return Delivery{ID: strings.Repeat("a", 64), Group: strings.Repeat("b", 64), Topic: "shop/redact", Payload: json.RawMessage(`{"shop_id":123}`), CreatedAt: cutoff.Add(49 * time.Hour), OccurredAt: cutoff.Add(48 * time.Hour), ReceiptVersion: 2, AuthorizationCutoffAt: &cutoff, UninstallEventID: strings.Repeat("c", 64)}
}

func TestReceiptClientExplicitNegotiationAndSignedQuery(t *testing.T) {
	identity, err := NewIdentity("fixture", "receipt-v2")
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{}
	starts := []Start{}
	event := receiptFixture()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if verifySignature(r, body, identity.Installation(), time.Now()) != nil {
			t.Error("unsigned request")
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/transactions" {
			var s Start
			if json.Unmarshal(body, &s) != nil {
				t.Error("invalid start")
			}
			starts = append(starts, s)
			io.WriteString(w, `{}`)
			return
		}
		queries = append(queries, r.URL.RawQuery)
		if r.URL.RawQuery != "" {
			altered := r.Clone(r.Context())
			u := *r.URL
			u.RawQuery = "receipt_version=1"
			altered.URL = &u
			if verifySignature(altered, body, identity.Installation(), time.Now()) == nil {
				t.Error("query not authenticated")
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"events": []Delivery{event}})
	}))
	defer server.Close()
	client := &Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
	if _, err = client.Events(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := client.EventsV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ReceiptVersion != 2 || got[0].UninstallEventID != event.UninstallEventID || !got[0].AuthorizationCutoffAt.Equal(*event.AuthorizationCutoffAt) || !got[0].OccurredAt.Equal(event.OccurredAt) {
		t.Fatal("receipt fields lost")
	}
	for _, capability := range []int{0, 2} {
		client.ShopifyReceiptVersion = capability
		if _, err = client.Start(context.Background(), Start{Provider: "shopify", Shop: "fixture.myshopify.com"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(queries) != 2 || queries[0] != "" || queries[1] != "receipt_version=2" || len(starts) != 2 || starts[0].ReceiptVersion != 0 || starts[1].ReceiptVersion != 2 {
		t.Fatal("implicit version upgrade or wrong negotiation")
	}
}

func TestReceiptClientRejectsMalformedGenerationContract(t *testing.T) {
	cases := map[string]func(*Delivery){
		"created-pre-epoch": func(e *Delivery) { e.CreatedAt = time.Unix(-1, 0) },
		"created-non-UTC":   func(e *Delivery) { e.CreatedAt = e.CreatedAt.In(time.FixedZone("offset", 3600)) },
		"occurred-non-UTC":  func(e *Delivery) { e.OccurredAt = e.OccurredAt.In(time.FixedZone("offset", 3600)) },
		"cutoff-non-UTC": func(e *Delivery) {
			v := e.AuthorizationCutoffAt.In(time.FixedZone("offset", 3600))
			e.AuthorizationCutoffAt = &v
		},
		"version": func(e *Delivery) { e.ReceiptVersion = 1 }, "missing-cutoff": func(e *Delivery) { e.AuthorizationCutoffAt = nil },
		"missing-pair": func(e *Delivery) { e.UninstallEventID = "" }, "same-id": func(e *Delivery) { e.UninstallEventID = e.ID },
		"noncanonical-id": func(e *Delivery) { e.ID = strings.Repeat("A", 64) }, "future-cutoff": func(e *Delivery) { v := e.OccurredAt.Add(time.Second); e.AuthorizationCutoffAt = &v },
		"not-delayed": func(e *Delivery) { e.OccurredAt = e.OccurredAt.Add(-6 * time.Minute) }, "array-payload": func(e *Delivery) { e.Payload = json.RawMessage(`[]`) },
		"unknown-topic": func(e *Delivery) { e.Topic = "other" }, "unpaired-other-topic": func(e *Delivery) { e.Topic = "customers/redact" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := receiptFixture()
			mutate(&e)
			if validDeliveryV2(e) {
				t.Fatal("unsafe receipt accepted")
			}
		})
	}
	for _, topic := range []string{"app/uninstalled", "customers/redact", "customers/data_request"} {
		e := receiptFixture()
		e.Topic = topic
		e.UninstallEventID = ""
		at := e.OccurredAt
		e.AuthorizationCutoffAt = &at
		if !validDeliveryV2(e) {
			t.Fatal("valid topic rejected", topic)
		}
	}
}

func TestReceiptClientUnsupportedVersionIsSafeRemoteError(t *testing.T) {
	identity, _ := NewIdentity("fixture", "receipt-v1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(426)
		io.WriteString(w, `{"error":"unsupported_receipt_version","private":"discard"}`)
	}))
	defer server.Close()
	client := &Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
	_, err := client.Events(context.Background())
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Status != 426 || remote.Code != "unsupported_receipt_version" {
		t.Fatalf("unexpected bounded error %T", err)
	}
}
