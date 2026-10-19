package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

func TestReceiptParamsClosedExplicitVersion(t *testing.T) {
	for raw, want := range map[string]int{"": 1, `null`: 1, `{}`: 1, `{"receipt_version":1}`: 1, `{"receipt_version":2}`: 2} {
		got, err := eventsReceiptVersion(json.RawMessage(raw))
		if err != nil || got != want {
			t.Fatal(raw, got, err)
		}
	}
	for _, raw := range []string{`[]`, `true`, `{"receipt_version":true}`, `{"receipt_version":2.0}`, `{"receipt_version":"2"}`, `{"receipt_version":null}`, `{"receipt_version":0}`, `{"receipt_version":3}`, `{"receipt_version":2,"receipt_version":1}`, `{"receipt_version":2,"other":1}`, `{} {}`} {
		if _, err := eventsReceiptVersion(json.RawMessage(raw)); err == nil {
			t.Fatal("accepted", raw)
		}
	}
	for raw, want := range map[string]int{`{"provider":"shopify"}`: 0, `{"provider":"shopify","receipt_version":1}`: 1, `{"provider":"shopify","receipt_version":2}`: 2} {
		s, err := startReceiptParams(json.RawMessage(raw))
		if err != nil || s.ReceiptVersion != want {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{`{"provider":"shopify","receipt_version":true}`, `{"provider":"shopify","receipt_version":null}`, `{"provider":"shopify","receipt_version":2,"receipt_version":1}`, `{"provider":"shopify","receipt_version":2,"extra":true}`, `{"provider":"shopify","receipt_version":3}`} {
		if _, err := startReceiptParams(json.RawMessage(raw)); err == nil {
			t.Fatal("accepted start", raw)
		}
	}
}

func TestReceiptDispatchPreservesLegacyAndRejectsBeforeHTTP(t *testing.T) {
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RawQuery)
		io.WriteString(w, `{"events":[]}`)
	}))
	defer server.Close()
	identity, _ := auth.NewIdentity("fixture", "dispatch")
	client := &auth.Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
	for _, raw := range []string{`{}`, `{"receipt_version":2}`} {
		if _, err := dispatchEvents(context.Background(), client, json.RawMessage(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dispatchEvents(context.Background(), client, json.RawMessage(`{"receipt_version":false}`)); err == nil {
		t.Fatal("invalid version")
	}
	if len(requests) != 2 || requests[0] != "" || requests[1] != "receipt_version=2" {
		t.Fatal("wrong query or unexpected HTTP")
	}
}
