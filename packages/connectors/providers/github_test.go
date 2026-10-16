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

func TestGitHubTypedManifestAndClosedSchemas(t *testing.T) {
	m := githubManifest()
	if err := m.validate(); err != nil {
		t.Fatal(err)
	}
	if m.Provider != "github" || m.Capability != domain.Files || m.Origin != "https://api.github.com" || m.APIVersion != "2026-03-10" || !m.TypedOnly || m.ReadOnly || len(m.Operations) != 17 || m.MaxResponseBytes != 4<<20 {
		t.Fatal("unexpected GitHub manifest contract")
	}
	for _, op := range m.Operations {
		if op.Raw != nil || op.Sync != nil || op.Origin != "" || !strings.HasPrefix(op.Name, "files.github.") {
			t.Fatalf("unbounded operation %s", op.Name)
		}
		if op.Method != http.MethodGet && (op.Retry.MaxAttempts != 1 || op.Retry.RetryableWrite || op.IdempotencyHeader != "" || op.Risk != domain.RiskWrite) {
			t.Fatalf("write retry contract %s", op.Name)
		}
		var schema struct {
			AdditionalProperties bool
			Properties           map[string]json.RawMessage
		}
		if json.Unmarshal(op.InputSchema, &schema) != nil || schema.AdditionalProperties || schema.Properties["provider"] == nil {
			t.Fatalf("schema not closed for %s", op.Name)
		}
		if op.Body == BodyJSON {
			var body struct {
				AdditionalProperties bool
				MinProperties        int
				Properties           map[string]json.RawMessage
			}
			if json.Unmarshal(schema.Properties["body"], &body) != nil || body.AdditionalProperties || body.MinProperties != 1 || body.Properties["body"] == nil {
				t.Fatalf("body schema not closed for %s", op.Name)
			}
		}
	}
	// TypedOnly is an explicit opt-in, not a relaxation of existing manifests.
	m.TypedOnly = false
	if m.validate() == nil {
		t.Fatal("mutating manifest without raw or typed-only accepted")
	}
	m = githubManifest()
	raw := driveManifest().Operations[len(driveManifest().Operations)-1]
	raw.Name = "files.github.raw"
	m.Operations = append(m.Operations, raw)
	if m.validate() == nil {
		t.Fatal("typed-only manifest admitted raw escape")
	}
}

func TestGitHubDocumentedRequestsAndPageArguments(t *testing.T) {
	cases := []struct{ name, args, method, path, query, body string }{
		{"user.get", `{}`, "GET", "/user", "", ""},
		{"repositories.list", `{"visibility":"private","affiliation":"owner,collaborator","sort":"pushed","direction":"asc","per_page":100,"page":2}`, "GET", "/user/repos", "affiliation=owner%2Ccollaborator&direction=asc&page=2&per_page=100&sort=pushed&visibility=private", ""},
		{"repositories.user.list", `{"username":"octocat","type":"owner","sort":"full_name","page":3}`, "GET", "/users/octocat/repos", "page=3&sort=full_name&type=owner", ""},
		{"repositories.get", `{"owner":"octocat","repo":"hello-world"}`, "GET", "/repos/octocat/hello-world", "", ""},
		{"repositories.branches.list", `{"owner":"octocat","repo":"hello-world","protected":false,"per_page":100,"page":2}`, "GET", "/repos/octocat/hello-world/branches", "page=2&per_page=100&protected=false", ""},
		{"git.commits.get", `{"owner":"octocat","repo":"hello-world","commit_sha":"0123456789abcdef0123456789abcdef01234567"}`, "GET", "/repos/octocat/hello-world/git/commits/0123456789abcdef0123456789abcdef01234567", "", ""},
		{"git.trees.get", `{"owner":"octocat","repo":"hello-world","tree_sha":"0123456789abcdef0123456789abcdef01234567","recursive":"1"}`, "GET", "/repos/octocat/hello-world/git/trees/0123456789abcdef0123456789abcdef01234567", "recursive=1", ""},
		{"git.blobs.get", `{"owner":"octocat","repo":"hello-world","file_sha":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`, "GET", "/repos/octocat/hello-world/git/blobs/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "", ""},
		{"issues.list", `{"owner":"octocat","repo":"hello-world","state":"all","milestone":"none","assignee":"*","creator":"octocat","mentioned":"other-user","labels":"bug,help wanted","since":"2026-10-16T00:00:00Z","sort":"comments","direction":"desc","page":2,"per_page":50}`, "GET", "/repos/octocat/hello-world/issues", "assignee=%2A&creator=octocat&direction=desc&labels=bug%2Chelp+wanted&mentioned=other-user&milestone=none&page=2&per_page=50&since=2026-10-16T00%3A00%3A00Z&sort=comments&state=all", ""},
		{"issues.get", `{"owner":"octocat","repo":"hello-world","issue_number":12}`, "GET", "/repos/octocat/hello-world/issues/12", "", ""},
		{"issues.create", `{"owner":"octocat","repo":"hello-world","body":{"title":"QA issue","body":"Line one\nLine two","labels":["bug"],"assignees":["octocat"],"milestone":1}}`, "POST", "/repos/octocat/hello-world/issues", "", `{"title":"QA issue","body":"Line one\nLine two","labels":["bug"],"assignees":["octocat"],"milestone":1}`},
		{"issues.update", `{"owner":"octocat","repo":"hello-world","issue_number":12,"body":{"body":null,"milestone":null,"assignees":[],"labels":[],"state":"closed","state_reason":"completed"}}`, "PATCH", "/repos/octocat/hello-world/issues/12", "", `{"body":null,"milestone":null,"assignees":[],"labels":[],"state":"closed","state_reason":"completed"}`},
		{"issue_comments.list", `{"owner":"octocat","repo":"hello-world","issue_number":12,"per_page":100,"page":2}`, "GET", "/repos/octocat/hello-world/issues/12/comments", "page=2&per_page=100", ""},
		{"issue_comments.create", `{"owner":"octocat","repo":"hello-world","issue_number":12,"body":{"body":"QA comment"}}`, "POST", "/repos/octocat/hello-world/issues/12/comments", "", `{"body":"QA comment"}`},
		{"pulls.list", `{"owner":"octocat","repo":"hello-world","state":"open","head":"octocat:feature/test","base":"release/v1","sort":"long-running","direction":"asc","per_page":25,"page":2}`, "GET", "/repos/octocat/hello-world/pulls", "base=release%2Fv1&direction=asc&head=octocat%3Afeature%2Ftest&page=2&per_page=25&sort=long-running&state=open", ""},
		{"pulls.get", `{"owner":"octocat","repo":"hello-world","pull_number":7}`, "GET", "/repos/octocat/hello-world/pulls/7", "", ""},
		{"pulls.files.list", `{"owner":"octocat","repo":"hello-world","pull_number":7,"per_page":100,"page":2}`, "GET", "/repos/octocat/hello-world/pulls/7/files", "page=2&per_page=100", ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			m := githubManifest()
			a, err := NewHTTPAdapter(m, doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Scheme != "https" || req.URL.Host != "api.github.com" || req.Method != tt.method || req.URL.Path != tt.path || req.URL.RawQuery != tt.query {
					t.Fatalf("wrong typed route %s %s", req.Method, req.URL)
				}
				if req.Header.Get("Authorization") != "Bearer provider-secret" || req.Header.Get("Accept") != "application/vnd.github+json" || req.Header.Get("X-GitHub-Api-Version") != GitHubAPIVersion || req.Header.Get("Cookie") != "" {
					t.Fatal("wrong fixed GitHub headers")
				}
				body, _ := io.ReadAll(req.Body)
				if tt.body == "" {
					if len(body) != 0 {
						t.Fatal("read sent body")
					}
				} else {
					var got, want any
					if json.Unmarshal(body, &got) != nil || json.Unmarshal([]byte(tt.body), &want) != nil {
						t.Fatal("invalid request JSON")
					}
					gotJSON, _ := json.Marshal(got)
					wantJSON, _ := json.Marshal(want)
					if string(gotJSON) != string(wantJSON) || req.Header.Get("Content-Type") != "application/json" {
						t.Fatal("wrong typed body")
					}
				}
				return jsonResponse(200, `{"items":[{"id":7}],"echo":"provider-secret"}`, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			inv := testInvocation(t, m, findOperation(t, a, "files.github."+tt.name), json.RawMessage(tt.args))
			inv.Connection.Config = json.RawMessage(`{"origin":"https://attacker.invalid","api_version":"other"}`)
			if _, err = a.Preview(inv); err != nil {
				t.Fatal(err)
			}
			r, err := a.Invoke(context.Background(), inv)
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			encoded, _ := json.Marshal(r.Data)
			if strings.Contains(string(encoded), "provider-secret") || !strings.Contains(string(encoded), "[REDACTED]") {
				t.Fatal("response credential was not redacted")
			}
			if r.Metadata["api_version"] != GitHubAPIVersion {
				t.Fatal("API version missing from receipt")
			}
		})
	}
}

func TestGitHubRejectsInvalidArgumentsBeforeHTTP(t *testing.T) {
	cases := []struct{ name, args string }{
		{"repositories.get", `{"owner":"../octocat","repo":"hello"}`},
		{"repositories.get", `{"owner":"a--b","repo":"hello"}`},
		{"repositories.get", `{"owner":"-bad","repo":"hello"}`},
		{"repositories.get", `{"owner":"octocat","repo":".."}`},
		{"repositories.get", `{"owner":"octocat","repo":"%2fetc"}`},
		{"repositories.get", `{"owner":"octocat","repo":"hello/../other"}`},
		{"repositories.branches.list", `{"owner":"octocat","repo":"hello","protected":"true"}`},
		{"repositories.branches.list", `{"owner":"octocat","repo":"hello","protected":null}`},
		{"git.trees.get", `{"owner":"octocat","repo":"hello","tree_sha":"main"}`},
		{"git.trees.get", `{"owner":"octocat","repo":"hello","tree_sha":"0123456"}`},
		{"git.commits.get", `{"owner":"octocat","repo":"hello","commit_sha":"main"}`},
		{"git.trees.get", `{"owner":"octocat","repo":"hello","tree_sha":"0123456789abcdef0123456789abcdef01234567","recursive":false}`},
		{"git.trees.get", `{"owner":"octocat","repo":"hello","tree_sha":"0123456789abcdef0123456789abcdef01234567","recursive":"0"}`},
		{"git.trees.get", `{"owner":"octocat","repo":"hello","tree_sha":"0123456789abcdef0123456789abcdef01234567","recursive":1}`},
		{"git.blobs.get", `{"owner":"octocat","repo":"hello","file_sha":"0123456789abcdef0123456789abcdef0123456z"}`},
		{"git.blobs.get", `{"owner":"octocat","repo":"hello","file_sha":"0123456789abcdef0123456789abcdef01234567","path":"README.md"}`},
		{"issues.get", `{"owner":"octocat","repo":"hello","issue_number":"1"}`},
		{"issues.get", `{"owner":"octocat","repo":"hello","issue_number":0}`},
		{"pulls.get", `{"owner":"octocat","repo":"hello","pull_number":1.5}`},
		{"pulls.get", `{"owner":"octocat","repo":"hello","pull_number":null}`},
		{"repositories.list", `{"per_page":101}`},
		{"repositories.list", `{"page":0}`},
		{"repositories.list", `{"page":true}`},
		{"repositories.list", `{"type":"all","visibility":"private"}`},
		{"repositories.list", `{"affiliation":"owner,admin"}`},
		{"repositories.list", `{"affiliation":"owner,owner"}`},
		{"repositories.user.list", `{"username":"octocat","type":"private"}`},
		{"issues.list", `{"owner":"octocat","repo":"hello","state":"merged"}`},
		{"issues.list", `{"owner":"octocat","repo":"hello","sort":"popularity"}`},
		{"issues.list", `{"owner":"octocat","repo":"hello","since":"yesterday"}`},
		{"issues.list", `{"owner":"octocat","repo":"hello","milestone":"1?x=y"}`},
		{"pulls.list", `{"owner":"octocat","repo":"hello","base":"refs/../main"}`},
		{"pulls.list", `{"owner":"octocat","repo":"hello","head":"octocat:feature\nbranch"}`},
		{"pulls.list", `{"owner":"octocat","repo":"hello","head":"https://attacker.invalid"}`},
		{"issues.create", `{"owner":"octocat","repo":"hello","body":{}}`},
		{"issues.create", `{"owner":"octocat","repo":"hello","body":{"title":""}}`},
		{"issues.create", `{"owner":"octocat","repo":"hello","body":{"title":"ok","state":"closed"}}`},
		{"issues.create", `{"owner":"octocat","repo":"hello","body":{"title":"ok","assignees":["../user"]}}`},
		{"issues.create", `{"owner":"octocat","repo":"hello","body":{"title":"ok","labels":null}}`},
		{"issues.update", `{"owner":"octocat","repo":"hello","issue_number":1,"body":{"state":"merged"}}`},
		{"issues.update", `{"owner":"octocat","repo":"hello","issue_number":1,"body":{"state_reason":"unknown"}}`},
		{"issues.update", `{"owner":"octocat","repo":"hello","issue_number":1,"body":{"milestone":0}}`},
		{"issue_comments.create", `{"owner":"octocat","repo":"hello","issue_number":1,"body":{"body":null}}`},
		{"issue_comments.create", `{"owner":"octocat","repo":"hello","issue_number":1,"body":{"body":""}}`},
		{"user.get", `{"url":"https://attacker.invalid"}`},
		{"user.get", `{"headers":{"Authorization":"other"}}`},
		{"user.get", `{"provider":"other"}`},
		{"user.get", `{"connection_id":"../other"}`},
		{"user.get", `{"access_token":"not-accepted"}`},
		{"repositories.get", `{"owner":"first-owner","owner":"octocat","repo":"hello"}`},
		{"issues.create", `{"owner":"octocat","repo":"hello","body":{"title":"First title","title":"Second title"}}`},
		{"issue_comments.create", `{"owner":"octocat","repo":"hello","issue_number":1,"body":{"body":"First comment","body":"Second comment"}}`},
	}
	calls := 0
	m := githubManifest()
	a, err := NewHTTPAdapter(m, doerFunc(func(*http.Request) (*http.Response, error) { calls++; return jsonResponse(200, `{}`, nil), nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range cases {
		t.Run(tt.name+tt.args, func(t *testing.T) {
			inv := testInvocation(t, m, findOperation(t, a, "files.github."+tt.name), json.RawMessage(tt.args))
			if _, err := a.Preview(inv); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Fatalf("preview admitted invalid args: %v", err)
			}
			if _, err := a.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Fatalf("invoke admitted invalid args: %v", err)
			}
		})
	}
	if calls != 0 {
		t.Fatal("invalid args reached network")
	}
}

func TestGitHubContentPreservesBase64AndTreeTruncation(t *testing.T) {
	for _, tt := range []struct{ name, args, response string }{
		{"git.commits.get", `{"owner":"octocat","repo":"hello","commit_sha":"0123456789abcdef0123456789abcdef01234567"}`, `{"sha":"0123456789abcdef0123456789abcdef01234567","tree":{"sha":"89abcdef0123456789abcdef0123456789abcdef","url":"https://api.github.com/repos/octocat/hello/git/trees/89abcdef0123456789abcdef0123456789abcdef"}}`},
		{"git.trees.get", `{"owner":"octocat","repo":"hello","tree_sha":"0123456789abcdef0123456789abcdef01234567"}`, `{"sha":"0123456789abcdef0123456789abcdef01234567","tree":[{"path":"README.md","type":"blob","sha":"89abcdef0123456789abcdef0123456789abcdef"}],"truncated":true}`},
		{"git.blobs.get", `{"owner":"octocat","repo":"hello","file_sha":"89abcdef0123456789abcdef0123456789abcdef"}`, `{"sha":"89abcdef0123456789abcdef0123456789abcdef","encoding":"base64","content":"SGVsbG8=\n","size":5}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := githubManifest()
			a, err := NewHTTPAdapter(m, doerFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, tt.response, nil), nil }))
			if err != nil {
				t.Fatal(err)
			}
			inv := testInvocation(t, m, findOperation(t, a, "files.github."+tt.name), json.RawMessage(tt.args))
			r, err := a.Invoke(context.Background(), inv)
			if err != nil {
				t.Fatal(err)
			}
			var want any
			if json.Unmarshal([]byte(tt.response), &want) != nil {
				t.Fatal("invalid fixture")
			}
			gotJSON, _ := json.Marshal(r.Data)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) {
				t.Fatal("base64 or completeness fields changed")
			}
		})
	}
}

func TestGitHubContentResponseBound(t *testing.T) {
	m := githubManifest()
	calls := 0
	a, err := NewHTTPAdapter(m, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(200, strings.Repeat("x", int(githubMaxResponseBytes)+1), nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	inv := testInvocation(t, m, findOperation(t, a, "files.github.git.blobs.get"), json.RawMessage(`{"owner":"octocat","repo":"hello","file_sha":"89abcdef0123456789abcdef0123456789abcdef"}`))
	_, err = a.Invoke(context.Background(), inv)
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "response_too_large" || calls != 1 {
		t.Fatalf("response bound not enforced: %d %v", calls, err)
	}
}

func TestGitHubWriteIsNotRetriedEvenWithIdempotency(t *testing.T) {
	for _, name := range []string{"issues.create", "issues.update", "issue_comments.create"} {
		t.Run(name, func(t *testing.T) {
			m := githubManifest()
			calls := 0
			a, err := NewHTTPAdapter(m, doerFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Idempotency-Key") != "" {
					t.Fatal("unsupported idempotency header")
				}
				return jsonResponse(503, `{"message":"retry later"}`, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			args := `{"owner":"octocat","repo":"hello","issue_number":1,"body":{"title":"QA"}}`
			if name == "issues.create" {
				args = `{"owner":"octocat","repo":"hello","body":{"title":"QA"}}`
			}
			if name == "issue_comments.create" {
				args = `{"owner":"octocat","repo":"hello","issue_number":1,"body":{"body":"QA"}}`
			}
			inv := testInvocation(t, m, findOperation(t, a, "files.github."+name), json.RawMessage(args))
			inv.Idempotency = "same-call"
			_, err = a.Invoke(context.Background(), inv)
			var providerErr *domain.ProviderError
			if !errors.As(err, &providerErr) || calls != 1 || providerErr.Attempts != 1 {
				t.Fatalf("write retried: %d %v", calls, err)
			}
		})
	}
}

func TestGitHubReadRetriesAndPermissionClassification(t *testing.T) {
	m := githubManifest()
	calls := 0
	a, err := NewHTTPAdapter(m, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(503, `{}`, nil), nil
		}
		return jsonResponse(200, `{"login":"octocat"}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	a.sleep = func(context.Context, time.Duration) error { return nil }
	inv := testInvocation(t, m, findOperation(t, a, "files.github.user.get"), json.RawMessage(`{}`))
	if r, err := a.Invoke(context.Background(), inv); err != nil || calls != 2 || r.Attempts != 2 {
		t.Fatalf("read retry failed: %d %v", calls, err)
	}
	a.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(403, `{"message":"denied"}`, nil), nil
	})
	if _, err := a.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrProviderPermission) {
		t.Fatalf("permission not classified: %v", err)
	}
}
