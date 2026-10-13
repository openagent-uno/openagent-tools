package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestClickUpCatalogCoversReadsWritesAndOneRawEscape(t *testing.T) {
	adapters, err := CatalogWithDoer(successDoer())
	if err != nil {
		t.Fatal(err)
	}
	var operations []domain.Operation
	for _, adapter := range adapters {
		if adapter.Provider() == "clickup" {
			if adapter.Capability() != domain.Files {
				t.Fatal("wrong ClickUp capability")
			}
			operations = adapter.Operations()
		}
	}
	if len(operations) != len(clickupOperations)+1 || len(operations) < 80 {
		t.Fatalf("ClickUp catalog has %d tools", len(operations))
	}
	byName := make(map[string]domain.Operation, len(operations))
	raw, reads, writes, destructive := 0, 0, 0, 0
	for _, operation := range operations {
		byName[operation.Name] = operation
		if !strings.HasPrefix(operation.Name, "files.clickup.") || len(operation.RequiredScopes) != 0 {
			t.Fatalf("ClickUp operation outside its namespace or scope-bound: %+v", operation)
		}
		switch {
		case operation.Mode == domain.OperationRaw:
			raw++
		case operation.Risk == domain.RiskRead:
			reads++
		case operation.Risk == domain.RiskDestructive:
			destructive++
		default:
			writes++
		}
	}
	if raw != 1 || reads < 30 || writes < 30 || destructive < 10 {
		t.Fatalf("unexpected ClickUp risk mix: raw=%d reads=%d writes=%d destructive=%d", raw, reads, writes, destructive)
	}
	for _, name := range []string{"files.clickup.workspaces.list", "files.clickup.tasks.list", "files.clickup.tasks.create", "files.clickup.tasks.update", "files.clickup.tasks.delete", "files.clickup.docs.list", "files.clickup.doc_pages.update", "files.clickup.raw"} {
		if _, exists := byName[name]; !exists {
			t.Fatalf("ClickUp catalog lacks %s", name)
		}
	}
	for _, operation := range clickupOperations {
		if operation.method == http.MethodGet && operation.risk != domain.RiskRead {
			t.Fatalf("ClickUp read %s carries a write risk", operation.name)
		}
		if operation.method == http.MethodDelete && operation.body != "" {
			t.Fatalf("ClickUp delete %s declares a body", operation.name)
		}
		if operation.method != http.MethodGet && operation.risk == domain.RiskRead {
			t.Fatalf("ClickUp write %s is classified as a read", operation.name)
		}
		for _, name := range append(clickupPathParameters(operation.path), operation.query...) {
			if _, known := clickupArguments[name]; !known {
				t.Fatalf("ClickUp operation %s uses undeclared argument %s", operation.name, name)
			}
		}
	}
	manifest := clickupManifest()
	if manifest.ReadOnly || manifest.OriginKind != OriginFixed || manifest.Origin != "https://api.clickup.com" ||
		manifest.CredentialHeader != "Authorization" || manifest.CredentialScheme != "Bearer" || manifest.MaxRequestBytes != 4<<20 {
		t.Fatalf("unexpected ClickUp manifest bounds: %+v", manifest)
	}
	var schema struct {
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(byName["files.clickup.tasks.create"].InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AdditionalProperties || strings.Join(schema.Required, ",") != "list_id,body" || schema.Properties["body"] == nil || schema.Properties["team_id"] == nil {
		t.Fatalf("tasks.create schema=%s", byName["files.clickup.tasks.create"].InputSchema)
	}
}

func TestClickUpCallsFixedDocumentedEndpoints(t *testing.T) {
	cases := []struct{ name, args, method, path, query, body, response string }{
		{"files.clickup.user.get", `{}`, "GET", "/api/v2/user", "", "", `{"user":{"id":1,"username":"ada"}}`},
		{"files.clickup.workspaces.list", `{"connection_id":"conn-1","provider":"clickup"}`, "GET", "/api/v2/team", "", "", `{"teams":[{"id":"9012432693","name":"QA workspace"}]}`},
		{"files.clickup.tasks.list", `{"list_id":"901200","page":2,"statuses":["to do","in progress"],"include_closed":true,"due_date_gt":1700000000000,"order_by":"due_date","custom_fields":"[{\"field_id\":\"abc\",\"operator\":\"=\",\"value\":1}]"}`, "GET", "/api/v2/list/901200/task", "custom_fields=%5B%7B%22field_id%22%3A%22abc%22%2C%22operator%22%3A%22%3D%22%2C%22value%22%3A1%7D%5D&due_date_gt=1700000000000&include_closed=true&order_by=due_date&page=2&statuses%5B%5D=to+do&statuses%5B%5D=in+progress", "", `{"tasks":[{"id":"86b1","name":"Ship it","echo":"clickup-test-secret"}]}`},
		{"files.clickup.tasks.get", `{"task_id":"PROJ-12","custom_task_ids":true,"team_id":"9012432693"}`, "GET", "/api/v2/task/PROJ-12", "custom_task_ids=true&team_id=9012432693", "", `{"id":"86b1","custom_id":"PROJ-12"}`},
		{"files.clickup.spaces.list", `{"team_id":9012432693,"archived":false}`, "GET", "/api/v2/team/9012432693/space", "archived=false", "", `{"spaces":[]}`},
		{"files.clickup.tasks.search", `{"team_id":9012432693,"list_ids":[901205277267,"901205277266"],"custom_fields":[{"field_id":"abc","operator":"=","value":1}]}`, "GET", "/api/v2/team/9012432693/task", "custom_fields=%5B%7B%22field_id%22%3A%22abc%22%2C%22operator%22%3A%22%3D%22%2C%22value%22%3A1%7D%5D&list_ids%5B%5D=901205277267&list_ids%5B%5D=901205277266", "", `{"tasks":[]}`},
		{"files.clickup.tasks.create", `{"list_id":"901200","body":{"name":"Write release notes","priority":2,"assignees":[42]}}`, "POST", "/api/v2/list/901200/task", "", `{"name":"Write release notes","priority":2,"assignees":[42]}`, `{"id":"86b2","name":"Write release notes"}`},
		{"files.clickup.tasks.update", `{"task_id":"86b2","body":{"status":"complete"}}`, "PUT", "/api/v2/task/86b2", "", `{"status":"complete"}`, `{"id":"86b2","status":{"status":"complete"}}`},
		{"files.clickup.tasks.delete", `{"task_id":"86b2"}`, "DELETE", "/api/v2/task/86b2", "", "", `{}`},
		{"files.clickup.tags.add", `{"task_id":"86b2","tag_name":"release"}`, "POST", "/api/v2/task/86b2/tag/release", "", "", `{}`},
		{"files.clickup.dependencies.remove", `{"task_id":"86b2","depends_on":"86b3"}`, "DELETE", "/api/v2/task/86b2/dependency", "depends_on=86b3", "", `{}`},
		{"files.clickup.task_templates.list", `{"team_id":"9012432693"}`, "GET", "/api/v2/team/9012432693/taskTemplate", "page=0", "", `{"templates":[]}`},
		{"files.clickup.docs.list", `{"workspace_id":"9012432693","parent_type":"SPACE","limit":10,"next_cursor":"abc=="}`, "GET", "/api/v3/workspaces/9012432693/docs", "limit=10&next_cursor=abc%3D%3D&parent_type=SPACE", "", `{"docs":[],"next_cursor":null}`},
		{"files.clickup.doc_pages.update", `{"workspace_id":"9012432693","doc_id":"8cd2mnf-1","page_id":"8cd2mnf-2","body":{"content":"# Hello","content_edit_mode":"append","content_format":"text/md"}}`, "PUT", "/api/v3/workspaces/9012432693/docs/8cd2mnf-1/pages/8cd2mnf-2", "", `{"content":"# Hello","content_edit_mode":"append","content_format":"text/md"}`, `{}`},
		{"files.clickup.raw", `{"method":"GET","path":"/api/v2/team/9012432693/space","query":{"archived":false}}`, "GET", "/api/v2/team/9012432693/space", "archived=false", "", `{"spaces":[]}`},
		{"files.clickup.raw", `{"method":"POST","path":"/api/v3/workspaces/9012432693/docs","body":{"name":"Notes"}}`, "POST", "/api/v3/workspaces/9012432693/docs", "", `{"name":"Notes"}`, `{"id":"8cd2mnf-3"}`},
	}
	for _, test := range cases {
		t.Run(test.name+" "+test.method+" "+test.path, func(t *testing.T) {
			manifest := clickupManifest()
			var body []byte
			calls := 0
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != test.method || req.URL.Scheme != "https" || req.URL.Host != "api.clickup.com" || req.URL.Path != test.path || req.URL.RawQuery != test.query {
					t.Fatalf("wrong provider route: %s %s", req.Method, req.URL)
				}
				if req.Header.Get("Authorization") != "Bearer clickup-test-secret" {
					t.Fatal("incorrect fixed credential header")
				}
				body, _ = io.ReadAll(req.Body)
				return jsonResponse(http.StatusOK, test.response, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			inv := testInvocation(t, manifest, findOperation(t, adapter, test.name), json.RawMessage(test.args))
			inv.Credential = credentialWithSecret(t, "clickup-test-secret", "Authorization", "Bearer")
			// A secret-free config with URL-like values cannot reroute the fixed origin.
			inv.Connection.Config = json.RawMessage(`{"origin":"https://attacker.invalid","team_id":"other"}`)
			preview, err := adapter.Preview(inv)
			if err != nil || !strings.HasPrefix(preview.Path, test.path) {
				t.Fatalf("preview=%+v err=%v", preview, err)
			}
			result, err := adapter.Invoke(context.Background(), inv)
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if string(body) != test.body {
				t.Fatalf("body=%s want=%s", body, test.body)
			}
			serialized, _ := json.Marshal(result.Data)
			if strings.Contains(string(serialized), "clickup-test-secret") {
				t.Fatal("secret reflected into result")
			}
			var expected any
			_ = json.Unmarshal([]byte(strings.ReplaceAll(test.response, "clickup-test-secret", "[REDACTED]")), &expected)
			expectedJSON, _ := json.Marshal(expected)
			if string(serialized) != string(expectedJSON) {
				t.Fatalf("response lost data: %s want=%s", serialized, expectedJSON)
			}
		})
	}
}

func TestClickUpRejectsUnsafeArgumentsBeforeHTTP(t *testing.T) {
	manifest := clickupManifest()
	calls := 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) { calls++; return jsonResponse(200, `{}`, nil), nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []any{"../1", "86b2/comment", "https://attacker.invalid", "%2e%2e", "a b", "1?x=y", "1#f", "1\n", " 1", "", strings.Repeat("1", 129), -86, 8.5, nil, true, []any{"86b2"}} {
		args, _ := json.Marshal(map[string]any{"task_id": id})
		inv := testInvocation(t, manifest, findOperation(t, adapter, "files.clickup.tasks.get"), args)
		if _, err := adapter.Preview(inv); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("task_id=%v error=%v", id, err)
		}
	}
	cases := []struct{ operation, args string }{
		{"tasks.list", `{"list_id":"1","page":-1}`},
		{"tasks.list", `{"list_id":"1","page":"2"}`},
		{"tasks.list", `{"list_id":"1","page":null}`},
		{"tasks.list", `{"list_id":"1","order_by":"name"}`},
		{"tasks.list", `{"list_id":"1","statuses":"open"}`},
		{"tasks.list", `{"list_id":"1","statuses":["open\n"]}`},
		{"tasks.list", `{"list_id":"1","assignees":["../x"]}`},
		{"tasks.list", `{"list_id":"1","custom_fields":""}`},
		{"tasks.list", `{"list_id":"1","custom_fields":"not json"}`},
		{"tasks.list", `{"list_id":"1","custom_fields":{"field_id":"abc"}}`},
		{"tasks.list", `{"list_id":"1","assignees":[42.5]}`},
		{"tasks.list", `{"list_id":"1","due_date_gt":-5}`},
		{"tasks.list", `{"list_id":"1","include_closed":"yes"}`},
		{"tasks.list", `{"list_id":"1","origin":"https://attacker.invalid"}`},
		{"tasks.list", `{"list_id":"1","headers":{"Authorization":"evil"}}`},
		{"tasks.list", `{"list_id":"1","method":"DELETE"}`},
		{"tasks.list", `{"list_id":"1","body":{}}`},
		{"tasks.list", `{"list_id":"1","provider":"google_drive"}`},
		{"tasks.list", `{"list_id":"1","connection_id":"../conn"}`},
		{"tasks.create", `{"list_id":"1","body":"Write notes"}`},
		{"tasks.create", `{"list_id":"1","body":["Write notes"]}`},
		{"tasks.create", `{"list_id":"1","body":null}`},
		{"tasks.create", `{"list_id":"1","name":"Write notes"}`},
		{"tasks.create", `{"list_id":"1"}`},
		{"tasks.delete", `{"task_id":"1","body":{}}`},
		{"dependencies.remove", `{"task_id":"1"}`},
		{"dependencies.remove", `{"task_id":"1","depends_on":"2","dependency_of":"3"}`},
		{"docs.list", `{"workspace_id":"1","parent_type":"TASK"}`},
		{"docs.list", `{"workspace_id":"1","limit":0}`},
		{"doc_pages.list", `{"workspace_id":"1","doc_id":"2","content_format":"text/xml"}`},
		{"raw", `{"method":"POST","path":"/api/v2/oauth/token","body":{}}`},
		{"raw", `{"method":"GET","path":"/api/v1/team"}`},
		{"raw", `{"method":"PATCH","path":"/api/v2/team"}`},
		{"raw", `{"method":"GET","path":"https://api.clickup.com/api/v2/team"}`},
		{"raw", `{"method":"GET","path":"/api/v2/../v1/team"}`},
		{"raw", `{"method":"GET","path":"/api/v2/team","headers":{"Authorization":"evil"}}`},
		{"raw", `{"method":"GET","path":"/api/v2/team","query":{"access_token":"evil"}}`},
	}
	for _, test := range cases {
		inv := testInvocation(t, manifest, findOperation(t, adapter, "files.clickup."+test.operation), json.RawMessage(test.args))
		if _, err := adapter.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("accepted %s %s: %v", test.operation, test.args, err)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid arguments reached HTTP %d times", calls)
	}
}

func TestClickUpRetriesReadsOnRateLimitsButNeverRepeatsCreatesOrDeletes(t *testing.T) {
	manifest := clickupManifest()
	calls := 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(http.StatusTooManyRequests, `{"err":"Rate limit reached"}`, map[string]string{"Retry-After": "0"}), nil
		}
		return jsonResponse(http.StatusOK, `{"tasks":[]}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error { return nil }
	inv := testInvocation(t, manifest, findOperation(t, adapter, "files.clickup.tasks.list"), json.RawMessage(`{"list_id":"1"}`))
	inv.Idempotency = ""
	if _, err := adapter.Invoke(context.Background(), inv); err != nil || calls != 2 {
		t.Fatalf("read retry calls=%d err=%v", calls, err)
	}
	for _, test := range []struct{ operation, args string }{
		{"files.clickup.tasks.create", `{"list_id":"1","body":{"name":"once"}}`},
		{"files.clickup.tasks.delete", `{"task_id":"1"}`},
		{"files.clickup.raw", `{"method":"POST","path":"/api/v2/list/1/task","body":{"name":"once"}}`},
	} {
		calls = 0
		adapter.doer = doerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(http.StatusBadGateway, `{"err":"upstream"}`, nil), nil
		})
		inv := testInvocation(t, manifest, findOperation(t, adapter, test.operation), json.RawMessage(test.args))
		_, err := adapter.Invoke(context.Background(), inv)
		var providerError *domain.ProviderError
		if !errors.As(err, &providerError) || providerError.StatusCode != http.StatusBadGateway || calls != 1 {
			t.Fatalf("%s: calls=%d err=%v", test.operation, calls, err)
		}
	}
	updateCalls := 0
	adapter.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		updateCalls++
		if updateCalls == 1 {
			return jsonResponse(http.StatusServiceUnavailable, `{}`, nil), nil
		}
		return jsonResponse(http.StatusOK, `{"id":"1"}`, nil), nil
	})
	update := testInvocation(t, manifest, findOperation(t, adapter, "files.clickup.tasks.update"), json.RawMessage(`{"task_id":"1","body":{"name":"twice"}}`))
	if _, err := adapter.Invoke(context.Background(), update); err != nil || updateCalls != 2 {
		t.Fatalf("idempotent update retry calls=%d err=%v", updateCalls, err)
	}
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusUnauthorized, http.StatusForbidden} {
		adapter.doer = doerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(status, `{"token":"secret"}`, map[string]string{"Location": "https://attacker.invalid"}), nil
		})
		_, err := adapter.Invoke(context.Background(), inv)
		var providerError *domain.ProviderError
		if !errors.As(err, &providerError) || providerError.StatusCode != status || strings.Contains(err.Error(), "secret") {
			t.Fatalf("status=%d err=%v", status, err)
		}
	}
}
