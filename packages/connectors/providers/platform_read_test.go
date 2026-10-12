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

const testReplioOrganization = "11111111-1111-4111-8111-111111111111"
const testReplioThread = "22222222-2222-4222-8222-222222222222"

func platformInvocation(t *testing.T, adapter *HTTPAdapter, manifest Manifest, name string, arguments string) domain.Invocation {
	t.Helper()
	invocation := testInvocation(t, manifest, findOperation(t, adapter, name), json.RawMessage(arguments))
	if manifest.Provider == "replio" {
		invocation.Connection.Config = json.RawMessage(`{"organization_id":"` + testReplioOrganization + `"}`)
		invocation.Credential = credentialWithSecret(t, "rpl_"+strings.Repeat("a", 48), "Authorization", "Bearer")
	} else {
		invocation.Connection.Config = json.RawMessage(`{"project_id":"project-test"}`)
		invocation.Credential = credentialWithSecret(t, "sk_live_"+strings.Repeat("b", 32), "Authorization", "Bearer")
	}
	return invocation
}

func TestPlatformReadManifestsExposeOnlyReviewedReadTools(t *testing.T) {
	t.Parallel()
	for _, manifest := range []Manifest{replioManifest(), billingbearManifest()} {
		if err := manifest.validate(); err != nil {
			t.Fatalf("%s manifest: %v", manifest.Provider, err)
		}
		if !manifest.ReadOnly || manifest.OriginKind != OriginFixed || manifest.CredentialHeader != "Authorization" || manifest.CredentialScheme != "Bearer" {
			t.Fatalf("unsafe platform manifest: %+v", manifest)
		}
		for _, operation := range manifest.Operations {
			if operation.Risk != domain.RiskRead || operation.Method != http.MethodGet || operation.Raw != nil || operation.Body != BodyNone || operation.Sync != nil {
				t.Fatalf("operation can mutate, sync or escape its fixed request: %+v", operation)
			}
			var schema struct {
				AdditionalProperties bool                       `json:"additionalProperties"`
				Properties           map[string]json.RawMessage `json:"properties"`
			}
			if err := json.Unmarshal(operation.InputSchema, &schema); err != nil || schema.AdditionalProperties || schema.Properties["organization_id"] != nil || schema.Properties["project_id"] != nil || schema.Properties["token"] != nil {
				t.Fatalf("unsafe input schema for %s: %s", operation.Name, operation.InputSchema)
			}
		}
	}
}

func TestPlatformReadToolsUseExactFixedOriginsAndConnectionScopes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		manifest  Manifest
		operation string
		arguments string
		path      string
		query     string
	}{
		{replioManifest(), "outreach.replio.apps.list", `{}`, "/api/v1/orgs/" + testReplioOrganization + "/apps", ""},
		{replioManifest(), "outreach.replio.stats.overview", `{}`, "/api/v1/orgs/" + testReplioOrganization + "/stats", ""},
		{replioManifest(), "outreach.replio.threads.list", `{"query":"refund requested","limit":20,"status":"open","waiting_for_team":true,"cursor":"page2"}`, "/api/v1/orgs/" + testReplioOrganization + "/threads", "cursor=page2&limit=20&q=refund+requested&status=open&waiting_for_team=true"},
		{replioManifest(), "outreach.replio.threads.get", `{"thread_id":"` + testReplioThread + `"}`, "/api/v1/orgs/" + testReplioOrganization + "/threads/" + testReplioThread, ""},
		{billingbearManifest(), "commerce.billingbear.project.stats", `{}`, "/v1/projects/project-test/stats", ""},
		{billingbearManifest(), "commerce.billingbear.customers.stats", `{"app_user_id":"customer-one"}`, "/v1/customers/customer-one/stats", ""},
		{billingbearManifest(), "commerce.billingbear.customers.history", `{"app_user_id":"customer-one"}`, "/v1/customers/customer-one/history", ""},
	}
	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			calls := 0
			contextCalls := 0
			adapter, err := NewHTTPAdapter(tt.manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
				if tt.manifest.Provider == "replio" && request.URL.String() == replioContextURL {
					contextCalls++
					assertReplioContextRequest(t, request)
					return testReplioContextResponse(t, testReplioContext(), false, false), nil
				}
				calls++
				if request.URL.Scheme+"://"+request.URL.Host != tt.manifest.Origin || request.URL.Path != tt.path || request.URL.RawQuery != tt.query || request.Method != http.MethodGet {
					t.Fatalf("unexpected provider request: %s %s", request.Method, request.URL)
				}
				if request.Header.Get("Cookie") != "" || request.Header.Get("X-OpenAgent-Workspace-ID") != "" || request.ContentLength > 0 {
					t.Fatal("ambient identity or unexpected body reached provider")
				}
				secret := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
				if err := validatePlatformCredential(tt.manifest.Provider, request.Header.Get("Authorization")); err != nil {
					t.Fatalf("wrong provider credential: %v", err)
				}
				return jsonResponse(http.StatusOK, `{"data":[],"echo":"`+secret+`"}`, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			invocation := platformInvocation(t, adapter, tt.manifest, tt.operation, tt.arguments)
			preview, err := adapter.Preview(invocation)
			if err != nil || preview.Method != http.MethodGet || !strings.HasPrefix(preview.Path, tt.path) || calls != 0 || contextCalls != 0 {
				t.Fatalf("credential-free preview failed: %+v err=%v calls=%d", preview, err, calls)
			}
			result, err := adapter.Invoke(context.Background(), invocation)
			if err != nil || calls != 1 {
				t.Fatalf("read failed: err=%v calls=%d", err, calls)
			}
			if tt.manifest.Provider == "replio" && contextCalls != 1 {
				t.Fatalf("Replio read did not validate its key scope: context calls=%d", contextCalls)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), strings.Repeat("a", 48)) || strings.Contains(string(encoded), strings.Repeat("b", 32)) || !strings.Contains(string(encoded), "REDACTED") {
				t.Fatal("provider credential echo was not redacted")
			}
		})
	}
}

func TestPlatformReadRejectsScopeOverridesRawCallsAndInvalidInputBeforeIO(t *testing.T) {
	t.Parallel()
	for _, manifest := range []Manifest{replioManifest(), billingbearManifest()} {
		adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid platform request reached the network")
			return nil, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		name := manifest.Operations[0].Name
		for _, arguments := range []string{
			`{"organization_id":"` + testReplioOrganization + `"}`, `{"project_id":"project-test"}`,
			`{"provider":"another"}`, `{"url":"https://attacker.invalid"}`, `{"path":"/admin"}`,
			`{"method":"POST"}`, `{"headers":{"Authorization":"bad"}}`, `{"body":{}}`, `{"token":"bad"}`,
		} {
			invocation := platformInvocation(t, adapter, manifest, name, arguments)
			if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Errorf("%s accepted %s: %v", manifest.Provider, arguments, err)
			}
		}
		for _, config := range []string{`{}`, `null`, `{"organization_id":"../other"}`, `{"project_id":"../other"}`, `{"project_id":"project-test","origin":"https://attacker.invalid"}`, `{"organization_id":"` + testReplioOrganization + `","token":"bad"}`} {
			invocation := platformInvocation(t, adapter, manifest, name, `{}`)
			invocation.Connection.Config = json.RawMessage(config)
			if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Errorf("%s accepted config %s: %v", manifest.Provider, config, err)
			}
		}
	}
}

func TestReplioBoundsSearchAndThreadIdentifiers(t *testing.T) {
	t.Parallel()
	manifest := replioManifest()
	adapter, err := NewHTTPAdapter(manifest, successDoer())
	if err != nil {
		t.Fatal(err)
	}
	for _, arguments := range []string{`{"limit":0}`, `{"limit":201}`, `{"limit":1.5}`, `{"limit":null}`, `{"app_id":"../../other"}`, `{"query":null}`, `{"query":"a\r\nb"}`, `{"status":"invalid"}`, `{"waiting_for_team":"true"}`, `{"waiting_for_team":null}`, `{"query":"` + strings.Repeat("x", 1025) + `"}`} {
		invocation := platformInvocation(t, adapter, manifest, "outreach.replio.threads.list", arguments)
		if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Errorf("accepted query %s: %v", arguments, err)
		}
	}
	for _, id := range []string{"../other", "abc", testReplioThread + "?org=other", "https://attacker.invalid"} {
		encoded, _ := json.Marshal(map[string]string{"thread_id": id})
		invocation := platformInvocation(t, adapter, manifest, "outreach.replio.threads.get", string(encoded))
		if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Errorf("accepted thread %q: %v", id, err)
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
		invocation := platformInvocation(t, adapter, manifest, "commerce.billingbear.customers.stats", string(encoded))
		if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Errorf("accepted customer id %q: %v", id, err)
		}
	}
	for _, secret := range []string{"sk_admin_" + strings.Repeat("a", 32), "sk_ADMIN_" + strings.Repeat("a", 32), "pk_live_" + strings.Repeat("a", 32), "other-key"} {
		invocation := platformInvocation(t, adapter, manifest, "commerce.billingbear.customers.stats", `{"app_user_id":"customer-one"}`)
		invocation.Credential = credentialWithSecret(t, secret, "Authorization", "Bearer")
		if _, err := adapter.Invoke(context.Background(), invocation); !errors.Is(err, domain.ErrProviderPermission) {
			t.Errorf("accepted broad or public key: %v", err)
		}
	}
}

func TestReplioRejectsInternalPlatformKeysAndAcceptsOrgKeyVersions(t *testing.T) {
	t.Parallel()
	for _, token := range []string{"rpl_" + strings.Repeat("a", 48), "rpl_" + strings.Repeat("_-A", 16)} {
		if err := validatePlatformCredential("replio", "Bearer "+token); err != nil {
			t.Fatalf("valid organization key format rejected: %v", err)
		}
	}
	manifest := replioManifest()
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("internal platform key reached Replio")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	invocation := platformInvocation(t, adapter, manifest, "outreach.replio.apps.list", `{}`)
	invocation.Credential = credentialWithSecret(t, "internal-platform-key", "Authorization", "Bearer")
	if _, err := adapter.Invoke(context.Background(), invocation); !errors.Is(err, domain.ErrProviderPermission) {
		t.Fatalf("internal key accepted: %v", err)
	}
}
