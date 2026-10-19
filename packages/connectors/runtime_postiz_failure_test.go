package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type postizOAuthProbeDoer struct {
	calls int
	t     *testing.T
}

func (d *postizOAuthProbeDoer) Do(r *http.Request) (*http.Response, error) {
	d.calls++
	if r.Method != "GET" || r.URL.String() != "https://api.postiz.com/public/v1/integrations" || r.Header.Get("Authorization") != "pos_synthetic_nonexpiring" {
		d.t.Fatal("Postiz request did not retain its fixed target and exact raw OAuth credential")
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`[]`))}, nil
}
func TestPostizOAuthNoExpiryRawAuthorizationContract(t *testing.T) {
	d := &postizOAuthProbeDoer{t: t}
	r, err := NewRuntime(d)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{CatalogID: "postiz", Principal: domain.Principal{WorkspaceID: "qa-workspace", ActorID: "qa-owner", Role: "owner"}, Connection: domain.Connection{ID: "qa-connection", WorkspaceID: "qa-workspace", Provider: "postiz", Capability: domain.Social, Enabled: true, Config: json.RawMessage(`{}`), Scopes: []string{}}}
	tools, err := r.Tools(b)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, op := range tools {
		if op.Name == "social.postiz.integrations.list" {
			found = true
		}
	}
	if !found {
		t.Fatal("reviewed read operation was not advertised")
	}
	c, err := domain.NewCredential(domain.CredentialOAuth2Bearer, "pos_synthetic_nonexpiring", "Authorization", "", "0", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Invoke(context.Background(), Call{Binding: b, Tool: "social.postiz.integrations.list", Arguments: json.RawMessage(`{}`), Credential: c, InvocationID: "qa-read-once"})
	if err != nil || d.calls != 1 || result.ProviderStatus != 200 {
		t.Fatal("no-expiry OAuth read contract failed")
	}
}

func TestPostizRuntimeCopiesOnlyClosedProviderFailureSignals(t *testing.T) {
	for _, test := range []struct {
		kind   string
		status int
		valid  bool
	}{
		{"provider_error", 401, true}, {"provider_error", 402, true}, {"provider_error", 403, true},
		{"provider_error", 500, true}, {"rate_limited", 429, true}, {"network_error", 0, true},
		{"provider_error", 99, false}, {"provider_error", 600, false},
		{"rate_limited", 402, false}, {"network_error", 200, false},
		{"credential_error", 0, false}, {"provider_permission", 401, false},
		{"sync_reset_required", 410, false}, {"PRIVATE secret-token", 403, false},
	} {
		t.Run(fmt.Sprintf("%s-%d", test.kind, test.status), func(t *testing.T) {
			r, err := NewRuntime(&postizOAuthProbeDoer{t: t})
			if err != nil {
				t.Fatal(err)
			}
			original := &domain.ProviderError{Kind: test.kind, StatusCode: test.status, ProviderID: "PRIVATE provider-request-secret", Attempts: 3, RequestBytes: 123, ResponseBytes: 456}
			r.adapters["postiz"] = injectedProviderFailure{Adapter: r.adapters["postiz"], failure: errors.Join(errors.New("PRIVATE raw-response credential-secret https://private.example"), original)}
			call := providerFailureCall(t, "postiz", "social.postiz.integrations.list", `{}`)
			call.Binding.Connection.Scopes = []string{}
			result, err := r.Invoke(context.Background(), call)
			var safe *domain.ProviderError
			if err == nil || errors.As(err, &safe) != test.valid || result.Data != nil {
				t.Fatal("Postiz failure was accepted, leaked a result or lost its finite classification")
			}
			encoded, _ := json.Marshal(err)
			formatted := fmt.Sprintf("%v|%+v|%#v|%s", err, err, err, encoded)
			for _, sentinel := range []string{"PRIVATE", "credential-secret", "private.example", "provider-request-secret"} {
				if strings.Contains(formatted, sentinel) {
					t.Fatal("Postiz error exported a provider body, credential, URL or identifier")
				}
			}
			if test.valid {
				if safe == original || safe.Kind != test.kind || safe.StatusCode != test.status || safe.ProviderID != "" || safe.Attempts != 0 || safe.RequestBytes != 0 || safe.ResponseBytes != 0 {
					t.Fatal("Postiz error retained unreviewed metadata or an alias")
				}
				original.Kind = "PRIVATE-mutated"
				if safe.Kind != test.kind {
					t.Fatal("Postiz diagnostic retained a mutable provider object")
				}
			} else if err.Error() != "connector provider request failed" {
				t.Fatal("unknown Postiz error changed its generic fallback")
			}
		})
	}
}
