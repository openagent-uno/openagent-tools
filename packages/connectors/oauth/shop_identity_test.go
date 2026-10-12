package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestShopifyExchangeBindsProviderVerifiedShopIdentity(t *testing.T) {
	for _, test := range []struct {
		domain, id string
		valid      bool
	}{
		{"example.myshopify.com", "gid://shopify/Shop/123", true},
		{"another.myshopify.com", "gid://shopify/Shop/123", false},
		{"example.myshopify.com", "gid://shopify/Customer/123", false},
		{"example.myshopify.com", "gid://shopify/Shop/0", false},
	} {
		t.Run(test.domain+test.id, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			os.WriteFile(path, []byte("app-secret"), 0600)
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin/api/2026-07/graphql.json" {
					if r.Header.Get("X-Shopify-Access-Token") != "access" {
						t.Error("identity check lost confidential token binding")
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"shop": map[string]any{"id": test.id, "myshopifyDomain": test.domain}}})
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "expires_in": 3600, "refresh_token_expires_in": 7776000, "scope": "read_products"})
			}))
			defer endpoint.Close()
			provider := Provider{ID: "shopify", AppID: "existing-app", ClientID: "client", SecretFile: path, TokenURL: endpoint.URL + "/token", Scopes: []string{"read_products"}}
			token, err := (Engine{AllowLoopback: true}).Exchange(context.Background(), provider, "code", "", "example.myshopify.com", provider.Scopes)
			if test.valid {
				if err != nil || token.ShopID != 123 {
					t.Fatalf("identity was not verified: %v", err)
				}
			} else if err == nil || token.AccessToken != "" {
				t.Fatal("mismatched identity exposed credentials")
			}
		})
	}
}
