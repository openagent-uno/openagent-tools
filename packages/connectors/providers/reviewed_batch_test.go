package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/definitions"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func reviewedFixture(t *testing.T) reviewedDefinition {
	t.Helper()
	schema := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"org_id":{"type":"string","minLength":1,"maxLength":32,"pattern":"^[a-z0-9-]+$"},"limit":{"type":"integer","minimum":1,"maximum":10},"cursor":{"type":"string","minLength":1,"maxLength":256},"connection_id":{"type":"string","maxLength":128}},"required":["org_id"]}`)
	return reviewedDefinition{Catalog: definitions.Catalog{ID: "reviewed-fixture", Name: "Reviewed fixture", Description: "Read fixture", Category: "Developer", Icon: "code", Auth: "token", Provider: "reviewed_fixture", Capability: "files", ReadTools: []string{"files.reviewed_fixture.items.list"}}, Authentication: reviewedAuthentication{Mode: "manual_token", PrimarySources: []string{"https://docs.example.com/api"}, Permissions: []string{"read"}, FixedHeaders: map[string]string{"X-API-Version": "2026-10"}}, Manifest: Manifest{Provider: "reviewed_fixture", Capability: domain.Files, APIVersion: "v1", OriginKind: OriginFixed, Origin: "https://api.example.com", CredentialHeader: "X-API-Key", MaxRequestBytes: 8192, MaxResponseBytes: 65536, ReadOnly: true, TypedOnly: true, Operations: []OperationManifest{{Name: "files.reviewed_fixture.items.list", Description: "Read bounded items", Risk: domain.RiskRead, Method: "GET", Path: "/v1/orgs/{org_id}/items", Query: map[string]string{"limit": "limit", "cursor": "cursor"}, Required: []string{"org_id"}, Body: BodyNone, Retry: noRetry, InputSchema: schema}}}, Contracts: map[string]reviewedOperationContract{"files.reviewed_fixture.items.list": {PrimarySources: []string{"https://docs.example.com/api/items"}, Pagination: reviewedPagination{Mode: "cursor", RequestArguments: []string{"cursor"}, ResponseFields: []string{"next_cursor"}}, Response: reviewedResponse{JSONType: "object", RequiredFields: []string{"data"}, OutputProjection: []string{"data[].id", "data[].name", "next_cursor"}, ApplicationErrorFields: []string{"error"}}}}}
}
func reviewedInvocation(t *testing.T, a *ReviewedBatchAdapter, args string) domain.Invocation {
	t.Helper()
	credential, e := domain.NewCredential(domain.CredentialAPIToken, "FIXTURE-TOKEN", "", "", "fixture", nil)
	if e != nil {
		t.Fatal(e)
	}
	return domain.Invocation{ID: "inv-reviewed", Principal: domain.Principal{WorkspaceID: "workspace-one", ActorID: "owner"}, Connection: domain.Connection{ID: "connection-one", WorkspaceID: "workspace-one", Provider: a.Provider(), Capability: domain.Files, Enabled: true, Config: json.RawMessage(`{}`), ExternalID: "verified-account"}, Operation: a.Operations()[0], Arguments: json.RawMessage(args), Credential: credential, RequestedAt: time.Now()}
}
func reviewedResponseBody(status int, raw string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(raw))}
}
func TestReviewedDefinitionsAreActuallyAdmitted(t *testing.T) {
	defs, e := loadReviewedDefinitions()
	if e != nil || len(defs) == 0 {
		t.Fatal("missing compiled definitions", e)
	}
	for _, def := range defs {
		a, e := newReviewedBatchAdapter(def, doerFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("admission/preview performed IO")
			return nil, nil
		}))
		if e != nil {
			t.Fatalf("definition %s not admitted: %v", def.Catalog.ID, e)
		}
		for _, op := range a.Operations() {
			raw := def.Contracts[op.Name].ExampleArguments
			if len(raw) == 0 {
				continue
			}
			value, err := microsoftGraphJSON(raw)
			args, ok := value.(map[string]any)
			if err != nil || !ok {
				t.Fatalf("invalid source example %s", op.Name)
			}
			for key, value := range map[string]string{"connection_id": "fixture-connection", "provider": a.Provider(), "expected_external_id": "fixture-account"} {
				if a.operations[op.Name].publicSchema.properties[key] != nil {
					args[key] = value
				}
			}
			arguments, _ := json.Marshal(args)
			inv := domain.Invocation{ID: "fixture-preview", Principal: domain.Principal{WorkspaceID: "fixture-workspace", ActorID: "fixture-owner"}, Connection: domain.Connection{ID: "fixture-connection", WorkspaceID: "fixture-workspace", Provider: a.Provider(), Capability: a.Capability(), Enabled: true, ExternalID: "fixture-account", Config: json.RawMessage(`{}`), Scopes: append([]string(nil), op.RequiredScopes...)}, Operation: op, Arguments: arguments}
			if _, err := a.Preview(inv); err != nil {
				t.Fatalf("documented source example %s cannot preview: %v", op.Name, err)
			}
		}
	}
}
func TestReviewedPreviewAndInvokeEnforceIdenticalClosedSchemaBeforeIO(t *testing.T) {
	a, e := newReviewedBatchAdapter(reviewedFixture(t), doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached provider")
		return nil, nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	for _, args := range []string{`{}`, `{"org_id":"x","unknown":"secret"}`, `{"org_id":"x","limit":11}`, `{"org_id":"x","limit":1.2}`, `{"org_id":"x","org_id":"other"}`, `{"org_id":"../other"}`, `{"org_id":"x","cursor":"raw-provider-cursor"}`, `{"org_id":"x","connection_id":"other"}`} {
		inv := reviewedInvocation(t, a, args)
		if _, e := a.Preview(inv); e == nil {
			t.Fatal("invalid preview admitted", args)
		}
		if _, e := a.Invoke(context.Background(), inv); e == nil {
			t.Fatal("invalid invocation admitted", args)
		}
	}
}
func TestReviewedFixedHeaderProjectionAndBoundOpaqueCursor(t *testing.T) {
	calls := 0
	a, e := newReviewedBatchAdapter(reviewedFixture(t), doerFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.URL.Host != "api.example.com" || r.URL.Path != "/v1/orgs/org-one/items" || r.Header.Get("X-API-Key") != "FIXTURE-TOKEN" || r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Version") != "2026-10" {
			t.Fatal("fixed credential/transport target changed")
		}
		if calls == 2 && r.URL.Query().Get("cursor") != "provider-next" {
			t.Fatal("cursor not unwrapped internally")
		}
		return reviewedResponseBody(200, `{"data":[{"id":"1","name":"One","secret":"not returned"}],"next_cursor":"provider-next","credential":"not returned"}`), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	inv := reviewedInvocation(t, a, `{"org_id":"org-one","limit":2}`)
	out, e := a.Invoke(context.Background(), inv)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(out.Data)
	if strings.Contains(string(encoded), "not returned") || strings.Contains(string(encoded), `"next_cursor"`) {
		t.Fatal("raw provider payload/cursor exposed")
	}
	token := out.Data.(map[string]any)["next_page_token"].(string)
	args, _ := json.Marshal(map[string]any{"org_id": "org-one", "limit": 2, "page_token": token})
	next := inv
	next.Arguments = args
	if _, e = a.Invoke(context.Background(), next); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*domain.Invocation){func(i *domain.Invocation) { i.Connection.ID = "other" }, func(i *domain.Invocation) { i.Connection.ExternalID = "other" }, func(i *domain.Invocation) {
		i.Arguments = json.RawMessage(strings.Replace(string(args), "org-one", "org-other", 1))
	}, func(i *domain.Invocation) {
		i.Connection.Config = json.RawMessage(`{"endpoint":"https://evil.invalid"}`)
	}, func(i *domain.Invocation) { i.Connection.Enabled = false }} {
		candidate := next
		mutate(&candidate)
		before := calls
		if _, e = a.Invoke(context.Background(), candidate); e == nil || calls != before {
			t.Fatal("cursor/connection escaped binding")
		}
	}
}
func TestReviewedProviderFailuresAndRawJSONNeverBecomeFakeSuccess(t *testing.T) {
	for _, raw := range []string{`{"data":[],"error":"private error"}`, `{"data":[],"errors":[{"message":"private error"}]}`, `{"data":[],"data":[{"id":"duplicate"}]}`, `{"other":[]}`, `"raw text"`, `{"data":[{"id":{"private":"object"}}]}`} {
		calls := 0
		a, e := newReviewedBatchAdapter(reviewedFixture(t), doerFunc(func(*http.Request) (*http.Response, error) { calls++; return reviewedResponseBody(200, raw), nil }))
		if e != nil {
			t.Fatal(e)
		}
		_, e = a.Invoke(context.Background(), reviewedInvocation(t, a, `{"org_id":"org-one"}`))
		if e == nil || calls != 1 || strings.Contains(e.Error(), "private error") {
			t.Fatal("response error admitted or leaked")
		}
	}
	for _, status := range []int{302, 401, 429, 500} {
		calls := 0
		a, _ := newReviewedBatchAdapter(reviewedFixture(t), doerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return reviewedResponseBody(status, `{"error":"private"}`), nil
		}))
		if _, e := a.Invoke(context.Background(), reviewedInvocation(t, a, `{"org_id":"org-one"}`)); e == nil || calls != 1 {
			t.Fatal("provider failure retried or admitted")
		}
	}
}
func TestReviewedAdmissionRejectsUnsupportedContractRatherThanListingCard(t *testing.T) {
	changes := []func(*reviewedDefinition){
		func(d *reviewedDefinition) { d.Authentication.CommonOAuthEnabled = true },
		func(d *reviewedDefinition) { d.Authentication.FixedHeaders["Authorization"] = "static-secret" },
		func(d *reviewedDefinition) { d.Manifest.Origin = "https://127.0.0.1" },
		func(d *reviewedDefinition) { d.Manifest.Operations[0].Risk = domain.RiskWrite },
		func(d *reviewedDefinition) { d.Manifest.Operations[0].Retry.MaxAttempts = 2 },
		func(d *reviewedDefinition) {
			d.Manifest.Operations[0].InputSchema = json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false,"oneOf":[]}`)
		},
		func(d *reviewedDefinition) {
			c := d.Contracts[d.Manifest.Operations[0].Name]
			c.Response.OutputProjection = []string{"*"}
			d.Contracts[d.Manifest.Operations[0].Name] = c
		},
		func(d *reviewedDefinition) {
			c := d.Contracts[d.Manifest.Operations[0].Name]
			c.Pagination.AutomaticFollow = true
			d.Contracts[d.Manifest.Operations[0].Name] = c
		},
	}
	for _, change := range changes {
		d := reviewedFixture(t)
		change(&d)
		if _, e := newReviewedBatchAdapter(d, successDoer()); e == nil {
			t.Fatal("unsupported definition admitted")
		}
	}
}
func TestReviewedReadPOSTGraphQLCannotAcceptDocumentOrMutationInjection(t *testing.T) {
	d := reviewedFixture(t)
	op := &d.Manifest.Operations[0]
	op.Method = "POST"
	op.Path = "/graphql"
	op.Query = nil
	op.Required = []string{"variables"}
	op.Body = BodyGraphQL
	op.GraphQLDocument = `query ReadItems($first: Int!) { items(first: $first) { id name } }`
	op.InputSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"variables":{"type":"object","additionalProperties":false,"properties":{"first":{"type":"integer","minimum":1,"maximum":10}},"required":["first"]}},"required":["variables"]}`)
	c := d.Contracts[op.Name]
	c.Pagination = reviewedPagination{Mode: "first_page"}
	c.Response = reviewedResponse{JSONType: "object", RequiredFields: []string{"data.items"}, OutputProjection: []string{"data.items[].id"}, ApplicationErrorFields: []string{"errors"}}
	d.Contracts[op.Name] = c
	calls := 0
	a, e := newReviewedBatchAdapter(d, doerFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if json.Unmarshal(raw, &body) != nil || body["query"] != op.GraphQLDocument || r.Method != "POST" {
			t.Fatal("compiled query changed")
		}
		return reviewedResponseBody(200, `{"data":{"items":[{"id":"one","secret":"hidden"}]}}`), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Invoke(context.Background(), reviewedInvocation(t, a, `{"variables":{"first":2}}`)); e != nil {
		t.Fatal(e)
	}
	before := calls
	for _, args := range []string{`{"variables":{"first":2},"query":"mutation { deleteAll }"}`, `{"variables":{"first":100}}`, `{"variables":{"first":2,"query":"mutation"}}`} {
		if _, e = a.Invoke(context.Background(), reviewedInvocation(t, a, args)); e == nil || calls != before {
			t.Fatal("GraphQL injection reached provider")
		}
	}
	for _, document := range []string{`mutation { deleteAll }`, `subscription { changes }`, `query { __schema { types { name } } }`} {
		bad := d
		bad.Manifest = cloneManifest(d.Manifest)
		bad.Manifest.Operations[0].GraphQLDocument = document
		if _, e = newReviewedBatchAdapter(bad, successDoer()); e == nil {
			t.Fatal("non-read document admitted")
		}
	}
	a.http.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		return reviewedResponseBody(200, `{"data":{"items":[]},"errors":[{"message":"private"}]}`), nil
	})
	if _, e = a.Invoke(context.Background(), reviewedInvocation(t, a, `{"variables":{"first":2}}`)); e == nil {
		t.Fatal("partial GraphQL failure reported success")
	}
}
func TestReviewedSuccessFlagAndEmptyLists(t *testing.T) {
	d := reviewedFixture(t)
	name := d.Manifest.Operations[0].Name
	c := d.Contracts[name]
	c.Response.SuccessField = &struct {
		Path  string `json:"path"`
		Value any    `json:"value"`
	}{Path: "success", Value: true}
	d.Contracts[name] = c
	for _, success := range []string{"true", "false"} {
		a, e := newReviewedBatchAdapter(d, doerFunc(func(*http.Request) (*http.Response, error) {
			return reviewedResponseBody(200, `{"data":[],"success":`+success+`}`), nil
		}))
		if e != nil {
			t.Fatal(e)
		}
		_, e = a.Invoke(context.Background(), reviewedInvocation(t, a, `{"org_id":"org-one"}`))
		if (e == nil) != (success == "true") {
			t.Fatal("application success flag ignored")
		}
	}
	if reviewedTruthy(json.Number("0")) || !reviewedTruthy(json.Number("1")) {
		t.Fatal("numeric application error semantics")
	}
}
func TestReviewedProjectionRetainsExactLargeIntegerAndNoGenericAuthOverride(t *testing.T) {
	a, e := newReviewedBatchAdapter(reviewedFixture(t), doerFunc(func(*http.Request) (*http.Response, error) {
		return reviewedResponseBody(200, `{"data":[{"id":9007199254740993}]}`), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	out, e := a.Invoke(context.Background(), reviewedInvocation(t, a, `{"org_id":"org-one"}`))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(out.Data)
	if !strings.Contains(string(raw), "9007199254740993") {
		t.Fatal("provider integer rounded")
	}
	inv := reviewedInvocation(t, a, `{"org_id":"org-one"}`)
	inv.Credential, _ = domain.NewCredential(domain.CredentialAPIToken, "FIXTURE-TOKEN", "Authorization", "Bearer", "fixture", nil)
	_, e = a.Invoke(context.Background(), inv)
	if e == nil {
		t.Fatal("credential header override accepted")
	}
	var providerError *domain.ProviderError
	if !errors.As(e, &providerError) {
		t.Fatal("error contract changed")
	}
}

func TestReviewedCursorTamperRotationAndRestart(t *testing.T) {
	calls := 0
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return reviewedResponseBody(200, `{"data":[],"next_cursor":"provider-next"}`), nil
	})
	a, e := newReviewedBatchAdapter(reviewedFixture(t), doer)
	if e != nil {
		t.Fatal(e)
	}
	inv := reviewedInvocation(t, a, `{"org_id":"org-one"}`)
	result, e := a.Invoke(context.Background(), inv)
	if e != nil {
		t.Fatal(e)
	}
	token := result.Data.(map[string]any)["next_page_token"].(string)
	next := inv
	b, _ := json.Marshal(map[string]any{"org_id": "org-one", "page_token": token})
	next.Arguments = b
	// Restarting the adapter preserves validation with the same credential; there
	// is no process-global random key or authorization cache.
	restarted, e := newReviewedBatchAdapter(reviewedFixture(t), doer)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restarted.Invoke(context.Background(), next); e != nil {
		t.Fatal("valid token did not survive restart", e)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(token)
	var forged map[string]any
	_ = json.Unmarshal(raw, &forged)
	forged["value"] = "forged-provider-cursor"
	payload, _ := json.Marshal(forged)
	bad := next
	b, _ = json.Marshal(map[string]any{"org_id": "org-one", "page_token": base64.RawURLEncoding.EncodeToString(payload)})
	bad.Arguments = b
	before := calls
	if _, e = a.Invoke(context.Background(), bad); e == nil || calls != before {
		t.Fatal("decoded/reencoded token bypassed HMAC")
	}
	for _, credential := range []struct{ secret, version string }{{"FIXTURE-TOKEN", "changed-version"}, {"rotated-token", "fixture"}} {
		bad := next
		bad.Credential, _ = domain.NewCredential(domain.CredentialAPIToken, credential.secret, "", "", credential.version, nil)
		before := calls
		if _, e = a.Invoke(context.Background(), bad); e == nil || calls != before {
			t.Fatal("credential rotation did not invalidate cursor")
		}
	}
	// Preview validates structure and connection/query fences without obtaining
	// credentials. Invoke alone authenticates the cursor before any HTTP IO.
	preview := next
	preview.Credential = domain.Credential{}
	if _, e = a.Preview(preview); e != nil {
		t.Fatal("preview unexpectedly required a secret", e)
	}
}

func TestReviewedManualSetupMetadataIsSourceBoundAndDoesNotPromiseOAuth(t *testing.T) {
	def := reviewedFixture(t)
	link, instructions := reviewedSetup(def)
	if link != def.Authentication.PrimarySources[0] || !strings.Contains(instructions, "read") || !strings.Contains(instructions, "supplied manually") || strings.Contains(instructions, "FIXTURE-TOKEN") {
		t.Fatal("missing or unsafe setup guidance")
	}
	def.Manifest.CredentialScheme = "Bearer"
	_, instructions = reviewedSetup(def)
	if !strings.Contains(instructions, "without the Bearer prefix") {
		t.Fatal("token prefix guidance missing")
	}
	def.Manifest.CredentialScheme = "Basic"
	_, instructions = reviewedSetup(def)
	if !strings.Contains(instructions, "Base64-encoded") || !strings.Contains(instructions, "provider documentation") {
		t.Fatal("Basic representation unspecified")
	}
}

func TestReviewedDocumentationAnchorsAreNotExecutionOrigins(t *testing.T) {
	if !reviewedSourceURLs([]string{"https://docs.gitlab.com/api/projects/#list-projects"}) {
		t.Fatal("valid primary documentation anchor rejected")
	}
	if _, e := fixedHTTPSOrigin("https://api.example.com/#execution-fragment"); e == nil {
		t.Fatal("documentation exception weakened execution origin")
	}
}

func TestReviewedLiteralTrailingSlashAndUnderscoreCredentialHeader(t *testing.T) {
	def := reviewedFixture(t)
	def.Manifest.CredentialHeader = "X-CMC_PRO_API_KEY"
	def.Manifest.Operations[0].Path += "/"
	calls := 0
	a, e := newReviewedBatchAdapter(def, doerFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v1/orgs/org-one/items/" || r.Header.Get("X-CMC_PRO_API_KEY") != "FIXTURE-TOKEN" || r.Header.Get("Authorization") != "" {
			t.Fatal("documented path/header was normalized or overridden")
		}
		return reviewedResponseBody(200, `{"data":[]}`), nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	inv := reviewedInvocation(t, a, `{"org_id":"org-one"}`)
	if _, e = a.Invoke(context.Background(), inv); e != nil || calls != 1 {
		t.Fatal("documented literal path failed", e)
	}
	for _, args := range []string{`{"org_id":"../other"}`, `{"org_id":"org-one","path":"/v1/other/"}`, `{"org_id":"org-one","url":"https://evil.invalid/"}`} {
		inv.Arguments = json.RawMessage(args)
		if _, e = a.Preview(inv); e == nil || calls != 1 {
			t.Fatal("literal slash compatibility permitted model route selection")
		}
	}
	for _, path := range []string{"/api/../other/", "//evil.invalid/", "/api/%2e%2e/", "/api/path/?next=evil", "/api/path/#fragment"} {
		bad := def
		bad.Manifest = cloneManifest(def.Manifest)
		bad.Manifest.Operations[0].Path = path
		if _, e = newReviewedBatchAdapter(bad, successDoer()); e == nil {
			t.Fatal("unsafe path admitted")
		}
	}
}

func TestReviewedManualTokenVendorPermissionsAreNotFabricatedOAuthScopes(t *testing.T) {
	def := reviewedFixture(t)
	def.Manifest.Operations[0].RequiredScopes = []string{"vendor-read-permission"}
	def.Authentication.Permissions = []string{"vendor-read-permission"}
	a, err := newReviewedBatchAdapter(def, doerFunc(func(*http.Request) (*http.Response, error) {
		return reviewedResponseBody(403, `{"error":"insufficient_provider_permission"}`), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range a.Operations() {
		if len(op.RequiredScopes) != 0 {
			t.Fatal("manual token was treated as OAuth scope attestation")
		}
	}
	if len(def.Manifest.Operations[0].RequiredScopes) != 1 || len(a.definition.Authentication.Permissions) != 1 {
		t.Fatal("reviewed source/setup permission information was mutated")
	}
	inv := reviewedInvocation(t, a, `{"org_id":"example"}`)
	inv.Connection.Scopes = nil
	if _, err = a.Preview(inv); err != nil {
		t.Fatal("host's unscoped personal token was hidden", err)
	}
	if result, err := a.Invoke(context.Background(), inv); err == nil || result.Data != nil {
		t.Fatal("provider denial became success")
	}
}
