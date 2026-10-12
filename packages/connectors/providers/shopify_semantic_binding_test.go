package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestShopifyAdapterConsumesSemanticBindingWithoutRequiringIt(t *testing.T) {
	manifest := shopifyManifest()
	var requests []struct {
		body  []byte
		query string
		path  string
	}
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		var body json.RawMessage
		if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
			t.Fatalf("decode Shopify request: %v", decodeErr)
		}
		requests = append(requests, struct {
			body  []byte
			query string
			path  string
		}{body: append([]byte(nil), body...), query: request.URL.RawQuery, path: request.URL.EscapedPath()})
		return jsonResponse(http.StatusOK, `{"data":{"products":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}},"productsCount":{"count":0,"precision":"EXACT"}}}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "commerce.shopify.products.list")
	for name, arguments := range map[string]json.RawMessage{
		"agent call consumes binding":               json.RawMessage(`{"first":1,"expected_external_id":"snow-globe.myshopify.com"}`),
		"direct syncworker call remains compatible": json.RawMessage(`{"first":1}`),
	} {
		t.Run(name, func(t *testing.T) {
			invocation := testInvocation(t, manifest, operation, arguments)
			if _, invokeErr := adapter.Invoke(context.Background(), invocation); invokeErr != nil {
				t.Fatalf("Invoke: %v", invokeErr)
			}
		})
	}
	if len(requests) != 2 {
		t.Fatalf("Shopify requests=%d want=2", len(requests))
	}
	for index, request := range requests {
		body := string(request.body)
		if strings.Contains(body, "expected_external_id") || strings.Contains(request.query, "expected_external_id") ||
			strings.Contains(request.path, "expected_external_id") {
			t.Fatalf("request %d leaked semantic binding: body=%s query=%q path=%q", index, body, request.query, request.path)
		}
		var envelope struct {
			Variables map[string]any `json:"variables"`
		}
		if json.Unmarshal(request.body, &envelope) != nil || envelope.Variables["first"] != float64(1) {
			t.Fatalf("request %d lost provider variables: %s", index, body)
		}
	}
}
