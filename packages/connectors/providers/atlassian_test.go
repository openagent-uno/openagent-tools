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

const atlassianTestCloudID = "1324a887-45db-1bf4-1e99-ef0ff456d421"
const atlassianTestConfig = `{"cloud_id":"` + atlassianTestCloudID + `"}`
const atlassianTestADF = `{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"QA text — 世界"}]}]}`

func atlassianTestInvocation(t *testing.T, a *HTTPAdapter, name, args string) domain.Invocation {
	t.Helper()
	m := atlassianManifest()
	inv := testInvocation(t, m, findOperation(t, a, "files.atlassian."+name), json.RawMessage(args))
	inv.Connection.Config = json.RawMessage(atlassianTestConfig)
	return inv
}

func TestAtlassianManifestTypedHostBoundAndScoped(t *testing.T) {
	m := atlassianManifest()
	if err := m.validate(); err != nil {
		t.Fatal(err)
	}
	if m.Provider != "atlassian" || m.Capability != domain.Files || m.Origin != "https://api.atlassian.com" || m.OriginKind != OriginFixed || !m.TypedOnly || m.APIVersion != "v3" || len(m.Operations) != 9 || m.MaxRequestBytes != 1<<20 || m.MaxResponseBytes != 4<<20 {
		t.Fatal("invalid Jira contract")
	}
	for _, op := range m.Operations {
		var schema struct {
			AdditionalProperties bool
			Properties           map[string]json.RawMessage
		}
		if json.Unmarshal(op.InputSchema, &schema) != nil || schema.AdditionalProperties || schema.Properties["cloud_id"] != nil || schema.Properties["origin"] != nil || schema.Properties["headers"] != nil {
			t.Fatalf("unbounded schema %s", op.Name)
		}
		if op.Raw != nil || op.Origin != "" || op.Sync != nil {
			t.Fatalf("unbounded endpoint %s", op.Name)
		}
		for _, required := range op.Required {
			if required == "cloud_id" {
				t.Fatal("site exposed as caller requirement")
			}
		}
		if op.Name == "files.atlassian.resources.list" {
			if op.Path != "/oauth/token/accessible-resources" || len(op.RequiredScopes) != 0 {
				t.Fatal("site discovery bound to invented scope")
			}
			continue
		}
		if !strings.HasPrefix(op.Path, "/ex/jira/{cloud_id}/rest/api/3/") || len(op.RequiredScopes) != 1 {
			t.Fatalf("invalid site or scope %s", op.Name)
		}
		if op.Method == http.MethodGet {
			if op.Risk != domain.RiskRead || op.RequiredScopes[0] != "read:jira-work" {
				t.Fatal("read scope/risk mismatch")
			}
		} else {
			if op.Risk != domain.RiskWrite || op.RequiredScopes[0] != "write:jira-work" || op.Retry.MaxAttempts != 1 || op.Retry.RetryableWrite || op.IdempotencyHeader != "" {
				t.Fatal("write risk/scope/retry mismatch")
			}
		}
	}
}

func TestAtlassianFixedEndpointsAndExplicitPagination(t *testing.T) {
	base := "/ex/jira/" + atlassianTestCloudID + "/rest/api/3"
	cases := []struct{ name, args, method, path, query, body string }{
		{"resources.list", `{}`, "GET", "/oauth/token/accessible-resources", "", ""},
		{"projects.list", `{"start_at":20,"max_results":50,"query":"Road map"}`, "GET", base + "/project/search", "maxResults=50&query=Road+map&startAt=20", ""},
		{"projects.get", `{"project_id_or_key":"QA"}`, "GET", base + "/project/QA", "", ""},
		{"issues.search", `{"jql":"project = QA ORDER BY updated DESC","max_results":10,"next_page_token":"opaque+/=next","fields":"summary,status,customfield_10001"}`, "GET", base + "/search/jql", "fields=summary%2Cstatus%2Ccustomfield_10001&jql=project+%3D+QA+ORDER+BY+updated+DESC&maxResults=10&nextPageToken=opaque%2B%2F%3Dnext", ""},
		{"issues.get", `{"issue_id_or_key":"QA-12","fields":"summary,description"}`, "GET", base + "/issue/QA-12", "fields=summary%2Cdescription", ""},
		{"issues.create", `{"body":{"fields":{"project":{"key":"QA"},"issuetype":{"name":"Task"},"summary":"QA issue","description":` + atlassianTestADF + `,"labels":["openagent-qa"],"assignee":{"accountId":"abc:123-def"},"priority":{"id":"3"}}}}`, "POST", base + "/issue", "", `{"fields":{"project":{"key":"QA"},"issuetype":{"name":"Task"},"summary":"QA issue","description":` + atlassianTestADF + `,"labels":["openagent-qa"],"assignee":{"accountId":"abc:123-def"},"priority":{"id":"3"}}}`},
		{"issues.update", `{"issue_id_or_key":"10001","body":{"fields":{"summary":"Updated QA","description":null,"assignee":null,"labels":[]}}}`, "PUT", base + "/issue/10001", "", `{"fields":{"summary":"Updated QA","description":null,"assignee":null,"labels":[]}}`},
		{"issue_comments.list", `{"issue_id_or_key":"QA-12","start_at":5,"max_results":20}`, "GET", base + "/issue/QA-12/comment", "maxResults=20&startAt=5", ""},
		{"issue_comments.create", `{"issue_id_or_key":"QA-12","body":{"body":` + atlassianTestADF + `}}`, "POST", base + "/issue/QA-12/comment", "", `{"body":` + atlassianTestADF + `}`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			response := `{"nextPageToken":"opaque-next","isLast":false,"values":[{"id":"123"}],"echo":"provider-secret"}`
			a, err := NewHTTPAdapter(atlassianManifest(), doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Scheme != "https" || req.URL.Host != "api.atlassian.com" || req.Method != tt.method || req.URL.Path != tt.path || req.URL.RawQuery != tt.query {
					t.Fatalf("wrong fixed route %s %s", req.Method, req.URL)
				}
				if req.Header.Get("Authorization") != "Bearer provider-secret" || req.Header.Get("Cookie") != "" || req.Header.Get("Idempotency-Key") != "" {
					t.Fatal("incorrect host credential or unsupported header")
				}
				body, _ := io.ReadAll(req.Body)
				if tt.body == "" {
					if len(body) != 0 {
						t.Fatal("read sent a body")
					}
				} else {
					var got, want any
					if json.Unmarshal(body, &got) != nil || json.Unmarshal([]byte(tt.body), &want) != nil {
						t.Fatal("invalid body")
					}
					g, _ := json.Marshal(got)
					w, _ := json.Marshal(want)
					if string(g) != string(w) || req.Header.Get("Content-Type") != "application/json" {
						t.Fatal("write body changed")
					}
				}
				return jsonResponse(200, response, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			inv := atlassianTestInvocation(t, a, tt.name, tt.args)
			if tt.name == "resources.list" {
				inv.Connection.Config = json.RawMessage(`{}`)
			}
			if _, err := a.Preview(inv); err != nil {
				t.Fatal(err)
			}
			r, err := a.Invoke(context.Background(), inv)
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			var want any
			_ = json.Unmarshal([]byte(strings.ReplaceAll(response, "provider-secret", "[REDACTED]")), &want)
			g, _ := json.Marshal(r.Data)
			w, _ := json.Marshal(want)
			if string(g) != string(w) {
				t.Fatal("pagination lost or credential reflected")
			}
		})
	}
}

func TestAtlassianRejectsCallerSiteOverridesAndUnsafeArgumentsBeforeHTTP(t *testing.T) {
	calls := 0
	a, err := NewHTTPAdapter(atlassianManifest(), doerFunc(func(*http.Request) (*http.Response, error) { calls++; return jsonResponse(200, `{}`, nil), nil }))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, args string }{
		{"resources.list", `{"cloud_id":"` + atlassianTestCloudID + `"}`},
		{"projects.list", `{"cloud_id":"` + atlassianTestCloudID + `"}`},
		{"projects.list", `{"cloudId":"other"}`},
		{"projects.list", `{"url":"https://other.atlassian.net"}`},
		{"projects.list", `{"headers":{"Authorization":"other"}}`},
		{"projects.list", `{"provider":"other"}`},
		{"projects.list", `{"connection_id":"../other"}`},
		{"projects.list", `{"max_results":101}`},
		{"projects.list", `{"start_at":-1}`},
		{"projects.list", `{"start_at":null}`},
		{"projects.list", `{"max_results":"20"}`},
		{"projects.get", `{"project_id_or_key":"../other"}`},
		{"projects.get", `{"project_id_or_key":"QA?x=1"}`},
		{"projects.get", `{"project_id_or_key":1}`},
		{"issues.search", `{"jql":""}`},
		{"issues.search", `{"jql":"project=QA","start_at":1}`},
		{"issues.search", `{"jql":"project=QA","next_page_token":null}`},
		{"issues.search", `{"jql":"project=QA","fields":"summary,,status"}`},
		{"issues.search", `{"jql":"project=QA","fields":"*all"}`},
		{"issues.get", `{"issue_id_or_key":"QA-0"}`},
		{"issues.get", `{"issue_id_or_key":"QA-1/comment"}`},
		{"issues.get", `{"issue_id_or_key":"%2e%2e"}`},
		{"issues.create", `{"body":{"fields":{"summary":"Missing project"}}}`},
		{"issues.create", `{"body":{"fields":{"summary":"QA","project":{"key":"QA","id":"1"},"issuetype":{"id":"10001"}}}}`},
		{"issues.create", `{"body":{"fields":{"summary":"QA","project":{"key":"QA"},"issuetype":{"id":"10001"},"customfield_10001":"unsupported"}}}`},
		{"issues.update", `{"issue_id_or_key":"QA-1","body":{"fields":{}}}`},
		{"issues.update", `{"issue_id_or_key":"QA-1","body":{"fields":{"project":{"key":"OTHER"}}}}`},
		{"issues.update", `{"issue_id_or_key":"QA-1","body":{"fields":{"summary":"ok"},"update":{"labels":[{"add":"other"}]}}}`},
		{"issues.update", `{"issue_id_or_key":"QA-1","body":{"fields":{"description":"not ADF"}}}`},
		{"issues.update", `{"issue_id_or_key":"QA-1","body":{"fields":{"labels":["has space"]}}}`},
		{"issues.update", `{"issue_id_or_key":"QA-1","body":{"fields":{"assignee":{"accountId":"https://other"}}}}`},
		{"issue_comments.create", `{"issue_id_or_key":"QA-1","body":{"body":` + atlassianTestADF + `,"visibility":{"type":"role","value":"Admins"}}}`},
		{"issue_comments.create", `{"issue_id_or_key":"QA-1","body":{"body":{"version":1,"type":"doc","content":[{"type":"media","attrs":{"url":"https://other"}}]}}}`},
		{"issue_comments.create", `{"issue_id_or_key":"QA-1","body":{"body":{"version":1,"type":"doc","content":[]}}}`},
	}
	for _, tt := range cases {
		t.Run(tt.name+tt.args, func(t *testing.T) {
			inv := atlassianTestInvocation(t, a, tt.name, tt.args)
			if _, err := a.Preview(inv); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Fatalf("unsafe preview: %v", err)
			}
			if _, err := a.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Fatalf("unsafe invoke: %v", err)
			}
		})
	}
	for _, config := range []string{`{}`, `null`, `{"cloud_id":"../other"}`, `{"cloud_id":"https://other.atlassian.net"}`, `{"cloud_id":"00000000-0000-0000-0000-000000000000"}`, `{"cloud_id":"` + atlassianTestCloudID + `","origin":"https://other"}`} {
		inv := atlassianTestInvocation(t, a, "projects.list", `{}`)
		inv.Connection.Config = json.RawMessage(config)
		if _, err := a.Preview(inv); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("unsafe server configuration admitted: %v", err)
		}
	}
	if calls != 0 {
		t.Fatal("invalid input reached provider")
	}
}

func TestAtlassianWriteNeverRetriesAndReadRetries(t *testing.T) {
	for _, tt := range []struct{ name, args string }{
		{"issues.create", `{"body":{"fields":{"project":{"id":"10000"},"issuetype":{"id":"10001"},"summary":"QA"}}}`},
		{"issues.update", `{"issue_id_or_key":"QA-1","body":{"fields":{"summary":"QA"}}}`},
		{"issue_comments.create", `{"issue_id_or_key":"QA-1","body":{"body":` + atlassianTestADF + `}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			a, err := NewHTTPAdapter(atlassianManifest(), doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return jsonResponse(503, `{"errorMessages":["later"]}`, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			inv := atlassianTestInvocation(t, a, tt.name, tt.args)
			inv.Idempotency = "caller-idempotency-does-not-enable-retry"
			_, err = a.Invoke(context.Background(), inv)
			var pe *domain.ProviderError
			if !errors.As(err, &pe) || calls != 1 || pe.Attempts != 1 {
				t.Fatalf("write retried: %d %v", calls, err)
			}
		})
	}
	calls := 0
	a, err := NewHTTPAdapter(atlassianManifest(), doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(503, `{}`, nil), nil
		}
		return jsonResponse(200, `{"values":[],"isLast":true}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	a.sleep = func(context.Context, time.Duration) error { return nil }
	if r, err := a.Invoke(context.Background(), atlassianTestInvocation(t, a, "projects.list", `{}`)); err != nil || calls != 2 || r.Attempts != 2 {
		t.Fatalf("read retry failed: %d %v", calls, err)
	}
	a.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(403, `{"errorMessages":["denied"]}`, nil), nil
	})
	if _, err := a.Invoke(context.Background(), atlassianTestInvocation(t, a, "projects.list", `{}`)); !errors.Is(err, domain.ErrProviderPermission) {
		t.Fatalf("permission not classified: %v", err)
	}
}

func TestAtlassianADFAndFieldsBudgets(t *testing.T) {
	if !atlassianADF(json.RawMessage(atlassianTestADF)) {
		t.Fatal("documented flat ADF rejected")
	}
	for _, adf := range []string{
		strings.Replace(atlassianTestADF, `"version":1`, `"version":2`, 1),
		strings.Replace(atlassianTestADF, `"type":"text"`, `"type":"text","marks":[{"type":"link","attrs":{"href":"https://other"}}]`, 1),
		`{"version":1,"type":"doc","content":[` + strings.TrimSuffix(strings.Repeat(`{"type":"paragraph","content":[]},`, 101), ",") + `]}`,
		`{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"` + strings.Repeat("x", 2001) + `"}]}]}`,
	} {
		if atlassianADF(json.RawMessage(adf)) {
			t.Fatal("unsupported or over-budget ADF accepted")
		}
	}
}
