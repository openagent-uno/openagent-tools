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

func (d *localDoer) Do(r *http.Request) (*http.Response, error) {
	d.calls++
	d.request = r
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"teams":[]}`))}, nil
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
		if item.ID == "github" || item.ID == "slack-import" {
			if item.Available {
				t.Fatal("placeholder declared implemented")
			}
		}
	}
}
