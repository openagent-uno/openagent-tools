package connectors

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type accountCalendarMailDoer struct {
	calls      int
	host, path string
}

func (d *accountCalendarMailDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	d.host, d.path = req.URL.Host, req.URL.Path
	body := `{"value":[{"id":"calendar-one","name":"QA"}]}`
	if d.host == "www.googleapis.com" {
		body = `{"kind":"calendar#calendarList","items":[{"kind":"calendar#calendarListEntry","id":"qa@example.com","etag":"\"v1\""}]}`
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
}

// Discovery and execution must agree on each provider's scope implications;
// read/write permission alone must never grant mail delivery or another account.
func TestCalendarMailRuntimeAccountScopeAndWriteFences(t *testing.T) {
	for _, tc := range []struct {
		id, provider, scope, first, host, path string
		readCount, writeCount                  int
	}{
		{"google-calendar", "google_calendar", "https://www.googleapis.com/auth/calendar", "files.google_calendar.calendars.list", "www.googleapis.com", "/calendar/v3/users/me/calendarList", 4, 7},
		{"outlook-mail", "outlook_mail", "Mail.ReadWrite", "outreach.outlook_mail.folders.list", "graph.microsoft.com", "/v1.0/me/mailFolders", 6, 8},
		{"outlook-calendar", "outlook_calendar", "Calendars.ReadWrite", "files.outlook_calendar.calendars.list", "graph.microsoft.com", "/v1.0/me/calendars", 4, 7},
	} {
		t.Run(tc.id, func(t *testing.T) {
			d := &accountCalendarMailDoer{}
			r, err := NewRuntime(d)
			if err != nil {
				t.Fatal(err)
			}
			item, ok := Lookup(tc.id)
			if !ok || !item.Available || item.Auth != "oauth" {
				t.Fatal("missing OAuth catalog entry")
			}
			b := Binding{CatalogID: tc.id, Principal: domain.Principal{WorkspaceID: "workspace-one", ActorID: "owner", BoundConnectionID: "account-one"}, Connection: domain.Connection{ID: "account-one", WorkspaceID: "workspace-one", Provider: tc.provider, ExternalID: "verified-provider-account", Capability: domain.Capability(item.Capability), Enabled: true, Config: json.RawMessage(`{}`), Scopes: []string{tc.scope}}}
			tools, err := r.Tools(b)
			if err != nil || len(tools) != tc.readCount {
				t.Fatalf("read discovery: %d %v", len(tools), err)
			}
			for _, tool := range tools {
				if tool.Risk != domain.RiskRead {
					t.Fatal("write exposed without local permission")
				}
			}
			credential, err := domain.NewCredential(domain.CredentialOAuth2Bearer, "host-held-token", "Authorization", "Bearer", "1", nil)
			if err != nil {
				t.Fatal(err)
			}
			call := Call{Binding: b, Tool: tc.first, Credential: credential, InvocationID: "read-one", Arguments: json.RawMessage(`{}`)}
			if _, err := r.Invoke(context.Background(), call); err != nil {
				t.Fatal(err)
			}
			if d.calls != 1 || d.host != tc.host || d.path != tc.path {
				t.Fatal("account request did not use fixed local transport")
			}
			call.Binding.Principal.BoundConnectionID = "account-two"
			if _, err := r.Invoke(context.Background(), call); err == nil {
				t.Fatal("cross-account invocation accepted")
			}
			call.Binding = b
			call.Binding.Connection.Scopes = nil
			if _, err := r.Invoke(context.Background(), call); err == nil {
				t.Fatal("missing scope accepted")
			}
			call.Binding = b
			call.Tool = item.AgentTools[0]
			if _, err := r.Invoke(context.Background(), call); err == nil {
				t.Fatal("write accepted without host permission")
			}
			if d.calls != 1 {
				t.Fatal("denied request reached provider")
			}
			b.AllowWrite = true
			tools, err = r.Tools(b)
			if err != nil || len(tools) != tc.writeCount {
				t.Fatalf("write discovery: %d %v", len(tools), err)
			}
			if tc.id == "outlook-mail" {
				for _, tool := range tools {
					if tool.Risk == domain.RiskPublish {
						t.Fatal("Mail.ReadWrite granted delivery")
					}
				}
				b.Connection.Scopes = append(b.Connection.Scopes, "Mail.Send")
				tools, err = r.Tools(b)
				if err != nil || len(tools) != 9 {
					t.Fatal("separate send consent not recognized")
				}
			}
		})
	}
}
