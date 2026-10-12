package domain

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSessionIdentifierAllowsOnlyDurableNamespaceSeparator(t *testing.T) {
	for _, value := range []string{"session-private", "ses_123", "automation:1b340e59-fc97-50d6-b09a-fdcdfcb4fb0a"} {
		if !ValidSessionID(value) {
			t.Fatalf("valid session id rejected: %q", value)
		}
	}
	for _, value := range []string{"", ":automation", "session/other", "session\nother"} {
		if ValidSessionID(value) {
			t.Fatalf("invalid session id accepted: %q", value)
		}
	}
	if ValidResourceID("automation:run") {
		t.Fatal("session namespace widened ordinary resource identifiers")
	}
}

func TestCredentialIsRedactedAndCanOnlyUseManifestHeader(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	credential, err := NewCredential(CredentialOAuth2Bearer, "provider-secret-token", "Authorization", "Bearer", "v7", &expires)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "provider-secret-token") || !strings.Contains(string(encoded), "\"redacted\":true") {
		t.Fatalf("credential serialization leaked or omitted redaction: %s", encoded)
	}
	headers := make(http.Header)
	if err := credential.Apply(headers, "Authorization", "Bearer", time.Now()); err != nil {
		t.Fatal(err)
	}
	if headers.Get("Authorization") != "Bearer provider-secret-token" {
		t.Fatalf("credential was not applied: %#v", headers)
	}
	if err := credential.Apply(make(http.Header), "X-Shopify-Access-Token", "", time.Now()); err == nil {
		t.Fatal("control-plane credential crossed provider header styles")
	}
	if redacted := string(credential.Redact([]byte("echo provider-secret-token"))); redacted != "echo [REDACTED]" {
		t.Fatalf("credential echo was not redacted: %q", redacted)
	}
}

func TestCredentialRedactsJSONEscapedSecretAndRejectsUnsafeHeaderBytes(t *testing.T) {
	credential, err := NewCredential(CredentialAPIToken, `token<\"\\value`, "X-API-Key", "", "v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(map[string]string{"echo": `token<\"\\value`})
	redacted := credential.Redact(encoded)
	if bytes.Contains(redacted, []byte("token")) || !bytes.Contains(redacted, []byte("[REDACTED]")) {
		t.Fatalf("JSON-escaped credential survived redaction: %s", redacted)
	}
	for _, secret := range []string{"token with space", "token\nnewline", "tökén"} {
		if _, err := NewCredential(CredentialAPIToken, secret, "X-API-Key", "", "v1", nil); err == nil {
			t.Fatalf("unsafe header credential accepted: %q", secret)
		}
	}
}

func TestCredentialJSONValidationAndExpiry(t *testing.T) {
	var credential Credential
	if err := json.Unmarshal([]byte("{\"kind\":\"oauth2_bearer\",\"secret\":\"secret-value\",\"header\":\"Authorization\",\"scheme\":\"Bearer\",\"version\":\"1\"}"), &credential); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Minute)
	expiredCredential, err := NewCredential(CredentialOAuth2Bearer, "secret-value", "Authorization", "Bearer", "1", &expired)
	if err != nil {
		t.Fatal(err)
	}
	if err := expiredCredential.Apply(make(http.Header), "Authorization", "Bearer", time.Now()); err == nil {
		t.Fatal("expired credential was applied")
	}
	for _, wire := range []string{
		"{\"kind\":\"unknown\",\"secret\":\"x\"}",
		"{\"kind\":\"api_token\",\"secret\":\"\"}",
		"{\"kind\":\"api_token\",\"secret\":\"bad\\nvalue\"}",
		"{\"kind\":\"api_token\",\"secret\":\"x\",\"header\":\"Bad Header\"}",
	} {
		if err := json.Unmarshal([]byte(wire), &credential); err == nil {
			t.Fatalf("invalid credential was accepted: %s", wire)
		}
	}
}

func TestCredentialSecretAccessIsCallbackScopedAndUsesACopy(t *testing.T) {
	t.Parallel()
	credential, err := NewCredential(
		CredentialAPIToken, "callback-secret", "", "", "v1", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.WithSecret(time.Now(), func(
		kind CredentialKind,
		secret []byte,
	) error {
		if kind != CredentialAPIToken || string(secret) != "callback-secret" {
			t.Fatalf("kind=%s secret=%q", kind, secret)
		}
		clear(secret)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	headers := make(http.Header)
	if err := credential.Apply(headers, "X-API-Key", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if headers.Get("X-API-Key") != "callback-secret" {
		t.Fatal("callback mutation changed the credential's internal secret")
	}
	encoded, _ := json.Marshal(credential)
	if bytes.Contains(encoded, []byte("callback-secret")) {
		t.Fatalf("credential JSON leaked secret: %s", encoded)
	}
}

func TestConnectionScopeValidation(t *testing.T) {
	connection := Connection{
		ID: "conn-shopify-1", WorkspaceID: "ws-1", Capability: Commerce,
		Provider: "shopify", Enabled: true, Config: json.RawMessage("{\"shop_domain\":\"shop.myshopify.com\"}"),
		Scopes: []string{"read_products", "https://www.googleapis.com/auth/drive"},
	}
	if err := connection.Validate("ws-1", Commerce); err != nil {
		t.Fatal(err)
	}
	if err := connection.Validate("ws-victim", Commerce); err == nil {
		t.Fatal("cross-workspace connection was accepted")
	}
	connection.Enabled = false
	if err := connection.Validate("ws-1", Commerce); err == nil {
		t.Fatal("disabled connection was accepted")
	}
	connection.Enabled = true
	for _, scopes := range [][]string{
		{"read_products", "read_products"},
		{"read products"},
		{""},
	} {
		connection.Scopes = scopes
		if err := connection.Validate("ws-1", Commerce); err == nil {
			t.Fatalf("invalid scopes were accepted: %#v", scopes)
		}
	}
	if !GrantsScopes([]string{"read_products", "read_orders"}, []string{"read_products"}) ||
		GrantsScopes([]string{"read_products"}, []string{"write_products"}) ||
		GrantsScopes([]string{"read_products"}, []string{"READ_PRODUCTS"}) {
		t.Fatal("provider scope matching was not exact and fail-closed")
	}
}

func TestOperationRejectsInvalidRequiredScopes(t *testing.T) {
	operation := Operation{
		Name: "commerce.shopify.products.list", Description: "List products",
		Capability: Commerce, Provider: "shopify", Risk: RiskRead, Mode: OperationTyped,
		InputSchema: json.RawMessage(`{"type":"object"}`), RequiredScopes: []string{"read_products"},
		Retry: RetryPolicy{MaxAttempts: 1},
	}
	if err := operation.Validate(); err != nil {
		t.Fatal(err)
	}
	operation.RequiredScopes = []string{"read_products", "read_products"}
	if err := operation.Validate(); err == nil {
		t.Fatal("duplicate operation scopes were accepted")
	}
}

func TestShopifyWebhookBindingRequiresCanonicalShopIdentity(t *testing.T) {
	valid := `{"workspace_id":"ws-1","connection_id":"conn-1","provider":"shopify","shop_domain":"store.myshopify.com","version":"v1","secret":"shopify-webhook-secret-123"}`
	var binding WebhookBinding
	if err := json.Unmarshal([]byte(valid), &binding); err != nil || binding.ShopDomain != "store.myshopify.com" {
		t.Fatalf("valid Shopify binding was rejected: binding=%#v err=%v", binding, err)
	}
	for _, shopDomain := range []string{"", "STORE.myshopify.com", "store.example.com", "-bad.myshopify.com"} {
		wire := strings.Replace(valid, "store.myshopify.com", shopDomain, 1)
		if err := json.Unmarshal([]byte(wire), &binding); err == nil {
			t.Fatalf("invalid Shopify shop identity was accepted: %q", shopDomain)
		}
	}
}
