package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const notionTestID = "b55c9c91-384d-452b-81db-d1ef79372b75"
const notionTestCursor = "cursor_opaque:next/v2=+"
const notionTestText = `[{"type":"text","text":{"content":"Hello — 世界"}}]`
const notionTestChildren = `[{"object":"block","type":"paragraph","paragraph":{"rich_text":` + notionTestText + `}}]`

func TestNotionManifestFixedOriginVersionTypedBoundedOperations(t *testing.T) {
	manifest := notionManifest()
	if err := manifest.validate(); err != nil {
		t.Fatal(err)
	}
	if manifest.Provider != "notion" || manifest.Capability != domain.Files || manifest.OriginKind != OriginFixed ||
		manifest.Origin != "https://api.notion.com" || manifest.APIVersion != "2026-03-11" || !manifest.TypedOnly || manifest.ReadOnly ||
		manifest.CredentialHeader != "Authorization" || manifest.CredentialScheme != "Bearer" || manifest.MaxRequestBytes != 500000 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	expected := map[string]bool{"search": true, "pages.get": true, "pages.create": true, "pages.update": true,
		"blocks.children.list": true, "blocks.children.append": true, "users.get": true, "users.list": true}
	if len(manifest.Operations) != len(expected) {
		t.Fatalf("operations=%d", len(manifest.Operations))
	}
	for _, operation := range manifest.Operations {
		name := strings.TrimPrefix(operation.Name, "files.notion.")
		if !expected[name] || operation.Raw != nil || operation.IdempotencyHeader != "" {
			t.Fatalf("unexpected operation: %+v", operation)
		}
		delete(expected, name)
		if operation.Risk != domain.RiskRead && (operation.Retry.MaxAttempts != 1 || operation.Retry.RetryableWrite) {
			t.Fatalf("Notion write retries: %+v", operation)
		}
		var schema map[string]any
		if json.Unmarshal(operation.InputSchema, &schema) != nil || schema["additionalProperties"] != false {
			t.Fatalf("non-strict schema %s", operation.InputSchema)
		}
	}
}

func TestNotionCallsDocumentedEndpointsAndPreservesPagination(t *testing.T) {
	for _, test := range []struct{ name, arguments, method, path, query, body string }{
		{"search", `{"body":{"query":"Roadmap","page_size":50,"start_cursor":"` + notionTestCursor + `","filter":{"property":"object","value":"page"},"sort":{"timestamp":"last_edited_time","direction":"descending"}}}`, "POST", "/v1/search", "", `{"query":"Roadmap","page_size":50,"start_cursor":"` + notionTestCursor + `","filter":{"property":"object","value":"page"},"sort":{"timestamp":"last_edited_time","direction":"descending"}}`},
		{"pages.get", `{"page_id":"` + notionTestID + `"}`, "GET", "/v1/pages/" + notionTestID, "", ""},
		{"blocks.children.list", `{"block_id":"` + notionTestID + `","page_size":1,"start_cursor":"` + notionTestCursor + `"}`, "GET", "/v1/blocks/" + notionTestID + "/children", "page_size=1&start_cursor=" + url.QueryEscape(notionTestCursor), ""},
		{"users.get", `{"user_id":"` + notionTestID + `"}`, "GET", "/v1/users/" + notionTestID, "", ""},
		{"users.list", `{"page_size":100}`, "GET", "/v1/users", "page_size=100", ""},
		{"pages.create", `{"body":{"parent":{"page_id":"` + notionTestID + `"},"properties":{"title":{"title":` + notionTestText + `}},"children":` + notionTestChildren + `}}`, "POST", "/v1/pages", "", `{"parent":{"page_id":"` + notionTestID + `"},"properties":{"title":{"title":` + notionTestText + `}},"children":` + notionTestChildren + `}`},
		{"pages.update", `{"page_id":"` + notionTestID + `","body":{"properties":{"Notes":{"rich_text":` + notionTestText + `}}}}`, "PATCH", "/v1/pages/" + notionTestID, "", `{"properties":{"Notes":{"rich_text":` + notionTestText + `}}}`},
		{"blocks.children.append", `{"block_id":"` + notionTestID + `","body":{"children":` + notionTestChildren + `}}`, "PATCH", "/v1/blocks/" + notionTestID + "/children", "", `{"children":` + notionTestChildren + `}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			response := `{"object":"list","results":[{"id":"` + notionTestID + `","label":"notion-test-secret"}],"has_more":true,"next_cursor":"` + notionTestCursor + `"}`
			manifest := notionManifest()
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != test.method || request.URL.Scheme != "https" || request.URL.Host != "api.notion.com" || request.URL.Path != test.path || request.URL.RawQuery != test.query {
					t.Fatalf("unexpected target: %s %s", request.Method, request.URL)
				}
				if request.Header.Get("Notion-Version") != notionAPIVersion || request.Header.Get("Authorization") != "Bearer notion-test-secret" || request.Header.Get("Idempotency-Key") != "" {
					t.Fatal("missing pinned version/credential or invented idempotency support")
				}
				body, _ := io.ReadAll(request.Body)
				if string(body) != test.body {
					t.Fatalf("body=%s want=%s", body, test.body)
				}
				return jsonResponse(200, response, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			invocation := testInvocation(t, manifest, findOperation(t, adapter, "files.notion."+test.name), json.RawMessage(test.arguments))
			invocation.Credential = credentialWithSecret(t, "notion-test-secret", "Authorization", "Bearer")
			result, err := adapter.Invoke(context.Background(), invocation)
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			serialized, _ := json.Marshal(result.Data)
			var expected any
			_ = json.Unmarshal([]byte(strings.ReplaceAll(response, "notion-test-secret", "[REDACTED]")), &expected)
			encodedExpected, _ := json.Marshal(expected)
			if string(serialized) != string(encodedExpected) {
				t.Fatalf("response lost pagination or leaked credential: %s", serialized)
			}
		})
	}
}

func TestNotionRejectsUnsafeOrUnsupportedArgumentsBeforeHTTP(t *testing.T) {
	manifest := notionManifest()
	calls := 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) { calls++; return jsonResponse(200, `{}`, nil), nil }))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, args string }{
		{"pages.get", `{"page_id":"../users"}`},
		{"pages.get", `{"page_id":"https://attacker.invalid"}`},
		{"pages.get", `{"page_id":"%2e%2e"}`},
		{"pages.get", `{"page_id":42}`},
		{"pages.get", `{"page_id":null}`},
		{"pages.get", `{"page_id":"` + notionTestID + `","headers":{"Notion-Version":"2022-06-28"}}`},
		{"pages.get", `{"page_id":"` + notionTestID + `","origin":"https://attacker.invalid"}`},
		{"pages.get", `{"page_id":"` + notionTestID + `","body":{}}`},
		{"users.list", `{"provider":"clickup"}`},
		{"users.list", `{"page_size":0}`},
		{"users.list", `{"page_size":101}`},
		{"users.list", `{"page_size":1.5}`},
		{"users.list", `{"start_cursor":"cursor\ninvalid"}`},
		{"search", `{"body":null}`},
		{"search", `{"body":{"query":null}}`},
		{"search", `{"body":{"query":"a","query":"b"}}`},
		{"search", `{"body":{"query|start_cursor":"ignored"}}`},
		{"search", `{"body":{"filter":{"property":"object","value":"database"}}}`},
		{"search", `{"body":{"sort":{"timestamp":"created_time","direction":"ascending"}}}`},
		{"pages.create", `{"body":{"parent":{"workspace":true},"properties":{"title":{"title":[]}}}}`},
		{"pages.create", `{"body":{"parent":{"page_id":"` + notionTestID + `","data_source_id":"` + notionTestID + `"},"properties":{"title":{"title":[]}}}}`},
		{"pages.create", `{"body":{"parent":{"page_id":"` + notionTestID + `"},"properties":{"Notes":{"rich_text":[]}}}}`},
		{"pages.create", `{"body":{"parent":{"page_id":"` + notionTestID + `"},"properties":{"title":{"title":[]}},"template":{"type":"default"}}}`},
		{"pages.update", `{"page_id":"` + notionTestID + `","body":{"properties":{}}}`},
		{"pages.update", `{"page_id":"` + notionTestID + `","body":{"properties":{"title":{"title":null}}}}`},
		{"pages.update", `{"page_id":"` + notionTestID + `","body":{"in_trash":true}}`},
		{"pages.update", `{"page_id":"` + notionTestID + `","body":{"properties":{"title":{"title":[{"text":{"content":"x","link":{"url":"https://attacker.invalid"}}}]}}}}`},
		{"blocks.children.append", `{"block_id":"` + notionTestID + `","body":{"children":[]}}`},
		{"blocks.children.append", `{"block_id":"` + notionTestID + `","body":{"children":[{"type":"image","image":{"external":{"url":"https://attacker.invalid"}}}]}}`},
		{"blocks.children.append", `{"block_id":"` + notionTestID + `","body":{"children":[{"type":"paragraph","paragraph":{"rich_text":[],"children":[]}}]}}`},
		{"blocks.children.append", `{"block_id":"` + notionTestID + `","body":{"children":[{"type":"to_do","to_do":{"rich_text":[],"checked":null}}]}}`},
		{"blocks.children.append", `{"block_id":"` + notionTestID + `","body":{"children":[{"type":"paragraph","quote":{"rich_text":[]}}]}}`},
	}
	for _, test := range cases {
		invocation := testInvocation(t, manifest, findOperation(t, adapter, "files.notion."+test.name), json.RawMessage(test.args))
		if _, err := adapter.Invoke(context.Background(), invocation); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("accepted %s %s: %v", test.name, test.args, err)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid inputs reached HTTP: %d", calls)
	}
}

func TestNotionBodyBoundsAndValidTextSubset(t *testing.T) {
	for _, raw := range []json.RawMessage{json.RawMessage(`""`), json.RawMessage(`null`), json.RawMessage(`"cursor\u0000"`), json.RawMessage(`"cursor\n"`), json.RawMessage(`"` + strings.Repeat("c", 2049) + `"`)} {
		if notionCursor(raw) {
			t.Fatalf("invalid opaque cursor accepted: %s", raw)
		}
	}
	if !notionCursor(json.RawMessage(`"` + strings.Repeat("c", 2048) + `"`)) {
		t.Fatal("bounded opaque cursor rejected")
	}
	if notionBody("files.notion.search", json.RawMessage(`{"query":"a"} {"query":"b"}`)) {
		t.Fatal("trailing JSON accepted")
	}
	if notionBody("files.notion.pages.update", json.RawMessage(`{"properties":{"title":{"title":[],"title":[]}}}`)) {
		t.Fatal("nested duplicate field accepted")
	}
	for _, body := range []string{
		`{"parent":{"data_source_id":"` + notionTestID + `"},"properties":{"Name":{"title":` + notionTestText + `},"Notes":{"rich_text":[]}}}`,
		`{"parent":{"page_id":"` + strings.ReplaceAll(notionTestID, "-", "") + `"},"properties":{"title":{"title":[]}}}`,
	} {
		if !notionBody("files.notion.pages.create", json.RawMessage(body)) {
			t.Fatalf("valid create rejected: %s", body)
		}
	}
	for _, kind := range notionTextBlocks {
		body := `{"children":[{"type":"` + kind + `","` + kind + `":{"rich_text":` + notionTestText + `}}]}`
		if !notionBody("files.notion.blocks.children.append", json.RawMessage(body)) {
			t.Fatalf("valid %s rejected", kind)
		}
	}
	tooLong := `{"query":"` + strings.Repeat("x", 2001) + `"}`
	if notionBody("files.notion.search", json.RawMessage(tooLong)) {
		t.Fatal("unbounded query accepted")
	}
	tooMany := `{"children":[` + strings.TrimSuffix(strings.Repeat(`{"type":"paragraph","paragraph":{"rich_text":[]}},`, 101), ",") + `]}`
	if notionBody("files.notion.blocks.children.append", json.RawMessage(tooMany)) {
		t.Fatal("101 blocks accepted")
	}
}

func TestNotionReadRetryButNeverDuplicateWrites(t *testing.T) {
	for _, test := range []struct {
		name, args string
		want       int
	}{
		{"search", `{"body":{}}`, 2},
		{"users.list", `{}`, 2},
		{"pages.create", `{"body":{"parent":{"page_id":"` + notionTestID + `"},"properties":{"title":{"title":[]}}}}`, 1},
		{"pages.update", `{"page_id":"` + notionTestID + `","body":{"properties":{"title":{"title":[]}}}}`, 1},
		{"blocks.children.append", `{"block_id":"` + notionTestID + `","body":{"children":` + notionTestChildren + `}}`, 1},
	} {
		for _, failure := range []string{"429", "network"} {
			t.Run(test.name+failure, func(t *testing.T) {
				calls := 0
				manifest := notionManifest()
				adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						if failure == "network" {
							return nil, errors.New("connection reset after dispatch")
						}
						return jsonResponse(429, `{"code":"rate_limited"}`, map[string]string{"Retry-After": "0"}), nil
					}
					return jsonResponse(200, `{"object":"list","results":[]}`, nil), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				adapter.sleep = func(context.Context, time.Duration) error { return nil }
				inv := testInvocation(t, manifest, findOperation(t, adapter, "files.notion."+test.name), json.RawMessage(test.args))
				inv.Idempotency = "caller-key-must-not-enable-retry"
				_, err = adapter.Invoke(context.Background(), inv)
				if calls != test.want || (test.want == 1 && err == nil) || (test.want == 2 && err != nil) {
					t.Fatalf("calls=%d want=%d err=%v", calls, test.want, err)
				}
			})
		}
	}
}
