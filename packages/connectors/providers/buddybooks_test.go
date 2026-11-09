package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestBuddyBooksPreviewAndRegistrationHaveDistinctFixedConfirmation(t *testing.T) {
	const company = "11111111-1111-4111-8111-111111111111"
	const requestID = "33333333-3333-4333-8333-333333333333"
	const args = `{"partyId":"22222222-2222-4222-8222-222222222222","number":"TEST-1","date":"2026-11-09","gross":350,"subject":"Example video","workFrom":"2026-11-02","workTo":"2026-11-06","stampDutyBorneBy":"payee","withholdingRate":20}`

	manifest := buddyBooksManifest()
	for _, confirm := range []string{"false", "true"} {
		t.Run("confirm="+confirm, func(t *testing.T) {
			action := "preview"
			if confirm == "true" {
				action = "register"
			}
			key := "sps_live_" + strings.Repeat("a", 43)
			calls := 0
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				var body map[string]any
				if req.Method != http.MethodPost || req.URL.Path != "/api/receipts" ||
					req.URL.RawQuery != "confirm="+confirm || req.Header.Get("X-API-Key") != key ||
					json.NewDecoder(req.Body).Decode(&body) != nil {
					t.Fatal("unexpected receipt request")
				}
				if body["tenantId"] != company || body["kind"] != "occasionalWork" ||
					body["gross"] != float64(350) || body["withholdingRate"] != float64(20) {
					t.Fatal("receipt request lost its binding or terms")
				}
				if confirm == "true" && body["requestId"] != requestID || confirm == "false" && body["requestId"] != nil {
					t.Fatal("receipt request identifier does not match the action")
				}
				return jsonResponse(200, `{"ok":true}`, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			inv := testInvocation(t, manifest, domain.Operation{Name: buddyBooksPrefix + "receipts." + action}, []byte(args))
			inv.Connection.ExternalID = company
			inv.Idempotency = requestID
			inv.Credential, err = domain.NewCredential(domain.CredentialAPIToken, key, "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = adapter.Invoke(context.Background(), inv); err != nil {
				t.Fatalf("receipt action rejected: %v", err)
			}
			for _, extra := range []string{`"tenantId":"other"`, `"kind":"royalty"`, `"confirm":true`, `"requestId":"other"`, `"body":{}`} {
				inv.Arguments = []byte(strings.TrimSuffix(args, "}") + "," + extra + "}")
				if _, err = adapter.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrInvalidArguments) {
					t.Fatalf("accepted an override: %s, %v", extra, err)
				}
			}
			if calls != 1 {
				t.Fatalf("invalid requests reached transport: calls=%d", calls)
			}
		})
	}
}

func TestBuddyBooksRequestsStayWithinTheCompanyPublicAPI(t *testing.T) {
	manifest := buddyBooksManifest()
	cases := []struct{ resource, input, query string }{
		{"documents", `{"direction":"incoming","page":2,"page_size":50}`, "direction=incoming&page=2&pageSize=50"},
		{"invoices", `{"direction":"incoming"}`, "direction=incoming"},
		{"parties", `{"role":"supplier"}`, "role=supplier"},
	}
	for _, c := range cases {
		t.Run(c.resource, func(t *testing.T) {
			key := "sps_live_" + strings.Repeat("a", 43)
			calls := 0
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodGet || req.URL.Host != "api.spicysparks.com" ||
					req.URL.Path != "/public/v1/"+c.resource || req.URL.RawQuery != c.query ||
					req.Header.Get("X-API-Key") != key || req.Header.Get("X-Tenant-Id") != "" {
					t.Fatal("request escaped the expected company API contract")
				}
				return jsonResponse(200, `{"items":[],"page":1,"pageSize":50,"total":0}`, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			op := domain.Operation{Name: buddyBooksPrefix + c.resource + ".list"}
			inv := testInvocation(t, manifest, op, []byte(c.input))
			inv.Credential, err = domain.NewCredential(domain.CredentialAPIToken, key, "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.Invoke(context.Background(), inv); err != nil || calls != 1 {
				t.Fatalf("valid request failed: %v, calls=%d", err, calls)
			}
			for _, invalid := range []string{`{"tenant":"other"}`, `{"url":"https://example.test"}`, `{"page_size":201}`, `{"page":"1"}`, `{"page":1,"page":2}`, `{"direction":"invalid"}`} {
				inv.Arguments = []byte(invalid)
				if _, err := adapter.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrInvalidArguments) {
					t.Fatalf("accepted invalid arguments %s: %v", invalid, err)
				}
			}
			inv.Arguments = []byte(c.input)
			inv.Credential, err = domain.NewCredential(domain.CredentialAPIToken, "installation-wide-secret", "", "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrProviderPermission) || calls != 1 {
				t.Fatalf("non-company key reached transport: %v, calls=%d", err, calls)
			}
		})
	}
}
