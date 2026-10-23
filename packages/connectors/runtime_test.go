package connectors

import (
	"context"
	"encoding/json"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"io"
	"net/http"
	"strings"
	"testing"
)

type localDoer struct {
	calls   int
	request *http.Request
}

func TestGmailRuntimeKeepsReadOnlyAndLegacyGrantsBound(t *testing.T) {
	d := &localDoer{}
	runtime, err := NewRuntime(d)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{CatalogID: "gmail", AllowWrite: true,
		Principal:  domain.Principal{WorkspaceID: "workspace", ActorID: "owner"},
		Connection: domain.Connection{ID: "gmail-connection", WorkspaceID: "workspace", Provider: "gmail", Capability: domain.Outreach, Enabled: true}}
	for _, tc := range []struct {
		scope string
		count int
	}{
		{"https://www.googleapis.com/auth/gmail.readonly", 4},
		{"https://www.googleapis.com/auth/gmail.compose", 3},
		{"https://www.googleapis.com/auth/gmail.modify", 7},
		{"https://www.googleapis.com/auth/gmail.send", 1},
	} {
		binding.Connection.Scopes = []string{tc.scope}
		tools, err := runtime.Tools(binding)
		if err != nil || len(tools) != tc.count {
			t.Fatalf("scope %s exposes %d tools, want %d: %v", tc.scope, len(tools), tc.count, err)
		}
	}
	binding.Connection.Scopes = []string{"https://www.googleapis.com/auth/gmail.readonly"}
	_, err = runtime.Invoke(context.Background(), Call{Binding: binding, Tool: "outreach.gmail.messages.send", InvocationID: "denied-write", Arguments: json.RawMessage(`{}`)})
	if err == nil || d.calls != 0 {
		t.Fatal("read-only grant reached the send provider")
	}
}

func (d *localDoer) Do(r *http.Request) (*http.Response, error) {
	d.calls++
	d.request = r
	body := `{"teams":[]}`
	if r.URL.Host == "slack.com" {
		body = `{"ok":true,"team_id":"T012ABCDE9"}`
	} else if r.URL.Host == "api.atlassian.com" {
		body = `{"values":[],"startAt":0,"maxResults":50,"isLast":true}`
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
}
func TestRuntimeBindsCatalogPermissionsAndLocalExecution(t *testing.T) {
	d := &localDoer{}
	r, err := NewRuntime(d)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{CatalogID: "clickup", Principal: domain.Principal{WorkspaceID: "tenant-one", ActorID: "owner"}, Connection: domain.Connection{ID: "connection-one", WorkspaceID: "tenant-one", Provider: "clickup", Capability: domain.Files, Enabled: true, Config: json.RawMessage(`{}`)}}
	tools, err := r.Tools(b)
	if err != nil || len(tools) == 0 {
		t.Fatalf("catalog discovery: %v", err)
	}
	for _, tool := range tools {
		if tool.Risk != domain.RiskRead {
			t.Fatal("write tool exposed without permission")
		}
	}
	var credential domain.Credential
	if err = json.Unmarshal([]byte(`{"kind":"oauth2_bearer","secret":"host-token","header":"Authorization","scheme":"Bearer","version":"1"}`), &credential); err != nil {
		t.Fatal(err)
	}
	call := Call{Binding: b, Tool: "files.clickup.workspaces.list", Credential: credential, InvocationID: "invocation-one", Arguments: json.RawMessage(`{}`)}
	if _, err = r.Invoke(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	if d.calls != 1 || d.request.URL.Host != "api.clickup.com" || d.request.Header.Get("Authorization") != "Bearer host-token" {
		t.Fatal("provider call did not execute through the host doer")
	}
	call.Arguments = json.RawMessage(`{"connection_id":"another-connection"}`)
	if _, err = r.Invoke(context.Background(), call); err == nil {
		t.Fatal("tool selected another credential")
	}
	call.Arguments = json.RawMessage(`{}`)
	call.Tool = "files.clickup.tasks.create"
	if _, err = r.Invoke(context.Background(), call); err == nil {
		t.Fatal("unauthorized write reached provider")
	}
	b.Connection.WorkspaceID = "tenant-two"
	if _, err = r.Tools(b); err == nil {
		t.Fatal("cross-tenant binding accepted")
	}
	if d.calls != 1 {
		t.Fatal("denied call reached provider")
	}
	for _, item := range Catalog() {
		if item.ID == "slack-import" {
			if !item.Available || item.Name != "Slack" || item.Provider != "slack_import" || item.Capability != "social" {
				t.Fatal("implemented Slack connector lost its existing identity")
			}
		}
	}
}

func TestWorkspaceConnectorsUseHostCredentialsAndWriteAuthorization(t *testing.T) {
	for _, tc := range []struct {
		id, read, write, host string
	}{
		{"github", "files.github.repositories.list", "files.github.issues.create", "api.github.com"},
		{"notion", "files.notion.users.list", "files.notion.pages.create", "api.notion.com"},
		{"slack-import", "social.slack_import.auth.test", "social.slack_import.chat.post_message", "slack.com"},
		{"atlassian", "files.atlassian.projects.list", "files.atlassian.issues.create", "api.atlassian.com"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			d := &localDoer{}
			runtime, err := NewRuntime(d)
			if err != nil {
				t.Fatal(err)
			}
			item, ok := Lookup(tc.id)
			if !ok || !item.Available || item.Auth != "oauth" {
				t.Fatal("implemented OAuth connector missing from catalog")
			}
			config := json.RawMessage(`{}`)
			scopes := []string{}
			if tc.id == "atlassian" {
				config = json.RawMessage(`{"cloud_id":"11111111-1111-4111-8111-111111111111"}`)
				scopes = []string{"read:jira-work", "write:jira-work"}
			} else if tc.id == "slack-import" {
				scopes = []string{"chat:write", "users:read"}
			}
			binding := Binding{CatalogID: tc.id, Principal: domain.Principal{WorkspaceID: "workspace-a", ActorID: "owner"},
				Connection: domain.Connection{ID: "held-connection", WorkspaceID: "workspace-a", Provider: item.Provider, Capability: domain.Capability(item.Capability), Enabled: true, Config: config, Scopes: scopes}}
			tools, err := runtime.Tools(binding)
			if err != nil || len(tools) != len(item.ReadTools) {
				t.Fatalf("read-only discovery: %v", err)
			}
			for _, tool := range tools {
				if tool.Risk != domain.RiskRead {
					t.Fatal("write exposed without host authorization")
				}
			}
			var credential domain.Credential
			if err := json.Unmarshal([]byte(`{"kind":"oauth2_bearer","secret":"host-held-token","header":"Authorization","scheme":"Bearer","version":"1"}`), &credential); err != nil {
				t.Fatal(err)
			}
			call := Call{Binding: binding, Credential: credential, InvocationID: "read-once", Tool: tc.read, Arguments: json.RawMessage(`{}`)}
			if _, err := runtime.Invoke(context.Background(), call); err != nil {
				t.Fatal(err)
			}
			if d.calls != 1 || d.request.URL.Host != tc.host || d.request.Header.Get("Authorization") != "Bearer host-held-token" {
				t.Fatal("provider request did not use host transport and local credential")
			}
			call.Arguments = json.RawMessage(`{"connection_id":"another-connection"}`)
			if _, err := runtime.Invoke(context.Background(), call); err == nil {
				t.Fatal("argument selected another connection")
			}
			call.Arguments = json.RawMessage(`{}`)
			call.Tool = tc.write
			if _, err := runtime.Invoke(context.Background(), call); err == nil || d.calls != 1 {
				t.Fatal("unauthorized write reached the provider")
			}
			binding.AllowWrite = true
			tools, err = runtime.Tools(binding)
			if err != nil || len(tools) != len(item.ReadTools)+len(item.AgentTools) {
				t.Fatalf("explicit write authorization did not expose declared tools: %v", err)
			}
			if tc.id == "slack-import" || tc.id == "atlassian" {
				scopeDenied := binding
				scopeDenied.Connection.Scopes = nil
				call.Binding = scopeDenied
				if _, err := runtime.Invoke(context.Background(), call); err == nil || d.calls != 1 {
					t.Fatal("host write authorization bypassed missing provider scopes")
				}
			}
			if tc.id == "atlassian" {
				invalidSite := binding
				invalidSite.Connection.Config = json.RawMessage(`{}`)
				call.Binding = invalidSite
				call.Tool = tc.read
				if _, err := runtime.Invoke(context.Background(), call); err == nil || d.calls != 1 {
					t.Fatal("Jira request reached provider without a host-selected site")
				}
			}
			binding.Connection.WorkspaceID = "workspace-b"
			if _, err := runtime.Tools(binding); err == nil {
				t.Fatal("cross-workspace binding accepted")
			}
		})
	}
}
