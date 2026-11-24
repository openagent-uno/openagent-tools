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

func TestBillingBearManifestExposesOnlyReviewedReadTools(t *testing.T) {
	t.Parallel()
	manifest := billingbearManifest()
	if err := manifest.validate(); err != nil {
		t.Fatalf("%s manifest: %v", manifest.Provider, err)
	}
	if !manifest.ReadOnly || manifest.OriginKind != OriginFixed || manifest.CredentialHeader != "Authorization" || manifest.CredentialScheme != "Bearer" {
		t.Fatalf("unsafe provider manifest: %+v", manifest)
	}
	for _, operation := range manifest.Operations {
		if operation.Risk != domain.RiskRead || operation.Method != http.MethodGet || operation.Raw != nil || operation.Body != BodyNone || operation.Sync != nil {
			t.Fatalf("operation can mutate, sync or escape its fixed request: %+v", operation)
		}
		var schema struct {
			AdditionalProperties bool                       `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(operation.InputSchema, &schema); err != nil || schema.AdditionalProperties || schema.Properties["project_id"] != nil || schema.Properties["token"] != nil {
			t.Fatalf("unsafe input schema for %s: %s", operation.Name, operation.InputSchema)
		}
	}
}

func TestBillingBearReadToolsUseExactFixedOriginsAndConnectionScopes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		operation string
		arguments string
		path      string
	}{
		{"commerce.billingbear.project.stats", `{}`, "/v1/projects/project-test/stats"},
		{"commerce.billingbear.customers.stats", `{"app_user_id":"customer-one"}`, "/v1/customers/customer-one/stats"},
		{"commerce.billingbear.customers.history", `{"app_user_id":"customer-one"}`, "/v1/customers/customer-one/history"},
	}
	manifest := billingbearManifest()
	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			calls := 0
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Scheme+"://"+request.URL.Host != manifest.Origin || request.URL.Path != tt.path || request.URL.RawQuery != "" || request.Method != http.MethodGet {
					t.Fatalf("unexpected provider request: %s %s", request.Method, request.URL)
				}
				if request.Header.Get("Cookie") != "" || request.Header.Get("X-OpenAgent-Workspace-ID") != "" || request.ContentLength > 0 {
					t.Fatal("ambient identity or unexpected body reached provider")
				}
				secret := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
				if err := validateBillingBearCredential(request.Header.Get("Authorization")); err != nil {
					t.Fatalf("wrong provider credential: %v", err)
				}
				return jsonResponse(http.StatusOK, `{"data":[],"echo":"`+secret+`"}`, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			invocation := testInvocation(t, manifest, findOperation(t, adapter, tt.operation), json.RawMessage(tt.arguments))
			preview, err := adapter.Preview(invocation)
			if err != nil || preview.Method != http.MethodGet || !strings.HasPrefix(preview.Path, tt.path) || calls != 0 {
				t.Fatalf("credential-free preview failed: %+v err=%v calls=%d", preview, err, calls)
			}
			result, err := adapter.Invoke(context.Background(), invocation)
			if err != nil || calls != 1 {
				t.Fatalf("read failed: err=%v calls=%d", err, calls)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), strings.Repeat("b", 32)) || !strings.Contains(string(encoded), "REDACTED") {
				t.Fatal("provider credential echo was not redacted")
			}
		})
	}
}

func TestBillingBearRejectsScopeOverridesRawCallsAndInvalidInputBeforeIO(t *testing.T) {
	t.Parallel()
	manifest := billingbearManifest()
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid provider request reached the network")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	name := manifest.Operations[0].Name
	for _, arguments := range []string{
		`{"project_id":"project-test"}`,
		`{"provider":"another"}`, `{"url":"https://attacker.invalid"}`, `{"path":"/admin"}`,
		`{"method":"POST"}`, `{"headers":{"Authorization":"bad"}}`, `{"body":{}}`, `{"token":"bad"}`,
	} {
		invocation := testInvocation(t, manifest, findOperation(t, adapter, name), json.RawMessage(arguments))
		if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Errorf("%s accepted %s: %v", manifest.Provider, arguments, err)
		}
	}
	for _, config := range []string{`{}`, `null`, `{"project_id":"../other"}`, `{"project_id":"project-test","origin":"https://attacker.invalid"}`, `{"project_id":"project-test","token":"bad"}`} {
		invocation := testInvocation(t, manifest, findOperation(t, adapter, name), json.RawMessage(`{}`))
		invocation.Connection.Config = json.RawMessage(config)
		if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Errorf("%s accepted config %s: %v", manifest.Provider, config, err)
		}
	}
}

func TestBillingBearRejectsCustomerPathEscapesAndBroadKeys(t *testing.T) {
	t.Parallel()
	manifest := billingbearManifest()
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe customer key reached BillingBear")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../other", "customer/../../projects/other", "x?project_id=other", "x%2fother", "", strings.Repeat("x", 257)} {
		encoded, _ := json.Marshal(map[string]string{"app_user_id": id})
		invocation := testInvocation(t, manifest, findOperation(t, adapter, "commerce.billingbear.customers.stats"), json.RawMessage(encoded))
		if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Errorf("accepted customer id %q: %v", id, err)
		}
	}
	for _, secret := range []string{"sk_admin_" + strings.Repeat("a", 32), "sk_ADMIN_" + strings.Repeat("a", 32), "pk_live_" + strings.Repeat("a", 32), "other-key"} {
		invocation := testInvocation(t, manifest, findOperation(t, adapter, "commerce.billingbear.customers.stats"), json.RawMessage(`{"app_user_id":"customer-one"}`))
		invocation.Credential = credentialWithSecret(t, secret, "Authorization", "Bearer")
		if _, err := adapter.Invoke(context.Background(), invocation); !errors.Is(err, domain.ErrProviderPermission) {
			t.Errorf("accepted broad or public key: %v", err)
		}
	}
}
