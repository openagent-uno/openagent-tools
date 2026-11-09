package providers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

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
				if req.Method != http.MethodGet || req.URL.Host != "os.spicysparks.com" ||
					req.URL.Path != "/public/v1/"+c.resource || req.URL.RawQuery != c.query ||
					req.Header.Get("Authorization") != "Bearer "+key || req.Header.Get("X-Tenant-Id") != "" {
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
