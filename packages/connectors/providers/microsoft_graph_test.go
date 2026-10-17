package providers

import (
	"context"
	"encoding/base64"
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

func microsoftGraphInvocation(t *testing.T, a *MicrosoftGraphAdapter, suffix, arguments string) domain.Invocation {
	t.Helper()
	for _, op := range a.Operations() {
		if strings.HasSuffix(op.Name, "."+suffix) {
			return domain.Invocation{ID: "inv-graph-1", Principal: domain.Principal{WorkspaceID: "ws-1", ActorID: "actor-1", Role: "agent"},
				Connection: domain.Connection{ID: "conn-1", WorkspaceID: "ws-1", Provider: a.Provider(), Capability: a.Capability(), Enabled: true, ExternalID: "verified-graph-account", Scopes: append([]string(nil), op.RequiredScopes...), Config: json.RawMessage(`{}`)},
				Operation:  op, Arguments: json.RawMessage(arguments), Credential: credential(t, "Authorization", "Bearer"), RequestedAt: time.Now()}
		}
	}
	t.Fatalf("unknown fixture operation %s", suffix)
	return domain.Invocation{}
}

func TestMicrosoftGraphFiniteOperationsAndScopeImplications(t *testing.T) {
	for _, provider := range []string{"outlook_mail", "outlook_calendar"} {
		a, err := NewMicrosoftGraphAdapter(provider, doerFunc(func(*http.Request) (*http.Response, error) { t.Fatal("discovery performed IO"); return nil, nil }))
		if err != nil {
			t.Fatal(err)
		}
		want := 9
		if provider == "outlook_calendar" {
			want = 7
		}
		if len(a.Operations()) != want {
			t.Fatal("wrong operation inventory")
		}
		if err := a.manifest.validate(); err != nil {
			t.Fatal(err)
		}
		for _, op := range a.Operations() {
			if err := op.Validate(); err != nil {
				t.Fatal(err)
			}
			if op.Mode != domain.OperationTyped || op.Retry.MaxAttempts != 1 || op.Retry.SupportsIdempotency || len(op.RequiredScopes) != 1 {
				t.Fatal("unbounded contract")
			}
			var schema map[string]any
			if json.Unmarshal(op.InputSchema, &schema) != nil || schema["additionalProperties"] != false {
				t.Fatal("open input schema")
			}
			if !a.OperationScopesGranted(op.RequiredScopes, op.Name) || a.OperationScopesGranted(nil, op.Name) {
				t.Fatal("scope admission mismatch")
			}
		}
		if a.OperationScopesGranted([]string{"Mail.ReadWrite", "Calendars.ReadWrite"}, "outreach.outlook_mail.unknown") {
			t.Fatal("unknown operation authorized")
		}
	}
	a, _ := NewMicrosoftGraphAdapter("outlook_mail", successDoer())
	for _, name := range []string{"folders.list", "messages.get", "drafts.create"} {
		if !a.OperationScopesGranted([]string{"Mail.ReadWrite"}, "outreach.outlook_mail."+name) {
			t.Fatal("documented Mail.ReadWrite implication denied")
		}
	}
	if a.OperationScopesGranted([]string{"Mail.ReadWrite"}, "outreach.outlook_mail.messages.send") || a.OperationScopesGranted([]string{"mail.read"}, "outreach.outlook_mail.messages.get") || a.OperationScopesGranted([]string{"https://attacker.invalid/Mail.Read"}, "outreach.outlook_mail.messages.get") {
		t.Fatal("scope alias or send escalation")
	}
	c, _ := NewMicrosoftGraphAdapter("outlook_calendar", successDoer())
	if !c.OperationScopesGranted([]string{"Calendars.ReadWrite"}, "files.outlook_calendar.calendars.get") || !c.OperationScopesGranted([]string{"Calendars.Read"}, "files.outlook_calendar.events.get") || c.OperationScopesGranted([]string{"Calendars.ReadBasic"}, "files.outlook_calendar.events.get") {
		t.Fatal("calendar scope hierarchy mismatch")
	}
}

func TestMicrosoftGraphDocumentedRoutesBodiesAndVersionHeaders(t *testing.T) {
	cases := []struct {
		provider, operation, args, method, path string
		status                                  int
	}{
		{"outlook_mail", "folders.list", `{"top":100}`, "GET", "/v1.0/me/mailFolders", 200},
		{"outlook_mail", "folders.get", `{"folder_id":"AAMk+/=!_"}`, "GET", "/v1.0/me/mailFolders/AAMk+%2F=%21_", 200},
		{"outlook_mail", "messages.list", `{}`, "GET", "/v1.0/me/messages", 200},
		{"outlook_mail", "messages.get", `{"message_id":"AAMk=="}`, "GET", "/v1.0/me/messages/AAMk==", 200},
		{"outlook_mail", "attachments.list", `{"message_id":"AAMk=="}`, "GET", "/v1.0/me/messages/AAMk==/attachments", 200},
		{"outlook_mail", "attachments.get", `{"message_id":"AAMk==","attachment_id":"AAAb=="}`, "GET", "/v1.0/me/messages/AAMk==/attachments/AAAb==", 200},
		{"outlook_mail", "drafts.create", `{"body":{"subject":"QA draft","body":{"contentType":"Text","content":"Line one\nLine two"},"toRecipients":[{"emailAddress":{"address":"qa@example.com"}}]}}`, "POST", "/v1.0/me/messages", 201},
		{"outlook_mail", "drafts.update", `{"message_id":"AAMk==","etag":"W/\"version==\"","body":{"subject":"QA changed"}}`, "PATCH", "/v1.0/me/messages/AAMk==", 200},
		{"outlook_mail", "messages.send", `{"message_id":"AAMk=="}`, "POST", "/v1.0/me/messages/AAMk==/send", 202},
		{"outlook_calendar", "calendars.list", `{}`, "GET", "/v1.0/me/calendars", 200},
		{"outlook_calendar", "calendars.get", `{"calendar_id":"CAL=="}`, "GET", "/v1.0/me/calendars/CAL==", 200},
		{"outlook_calendar", "events.list", `{"calendar_id":"CAL=="}`, "GET", "/v1.0/me/calendars/CAL==/events", 200},
		{"outlook_calendar", "events.get", `{"calendar_id":"CAL==","event_id":"EVENT=="}`, "GET", "/v1.0/me/calendars/CAL==/events/EVENT==", 200},
		{"outlook_calendar", "events.create", `{"calendar_id":"CAL==","body":{"subject":"QA event","start":{"dateTime":"2026-10-17T12:00:00","timeZone":"UTC"},"end":{"dateTime":"2026-10-17T13:00:00","timeZone":"UTC"}}}`, "POST", "/v1.0/me/calendars/CAL==/events", 201},
		{"outlook_calendar", "events.update", `{"calendar_id":"CAL==","event_id":"EVENT==","etag":"\"version==\"","body":{"subject":"QA changed"}}`, "PATCH", "/v1.0/me/calendars/CAL==/events/EVENT==", 200},
		{"outlook_calendar", "events.delete", `{"calendar_id":"CAL==","event_id":"EVENT==","etag":"W/\"version==\""}`, "DELETE", "/v1.0/me/calendars/CAL==/events/EVENT==", 204},
	}
	for _, tt := range cases {
		t.Run(tt.provider+"/"+tt.operation, func(t *testing.T) {
			calls := 0
			a, err := NewMicrosoftGraphAdapter(tt.provider, doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Scheme != "https" || req.URL.Host != "graph.microsoft.com" || req.URL.EscapedPath() != tt.path || req.Method != tt.method {
					t.Fatalf("wrong fixed typed route %s %s", req.Method, req.URL.EscapedPath())
				}
				if req.Header.Get("Authorization") != "Bearer provider-secret" || req.Header.Get("Accept") != "application/json" || req.Header.Get("Prefer") != `IdType="ImmutableId", outlook.body-content-type="text"` {
					t.Fatal("wrong fixed headers")
				}
				if tt.method == "PATCH" || tt.method == "DELETE" {
					if req.Header.Get("If-Match") == "" {
						t.Fatal("precondition absent")
					}
				}
				b, _ := io.ReadAll(req.Body)
				if strings.Contains(tt.args, `"body"`) && tt.method != "GET" {
					if len(b) == 0 || req.Header.Get("Content-Type") != "application/json" {
						t.Fatal("JSON body missing")
					}
				} else if len(b) != 0 {
					t.Fatal("unexpected body")
				}
				body := `{"id":"resource","echo":"provider-secret"}`
				if strings.HasSuffix(tt.operation, ".list") {
					body = `{"value":[],"echo":"provider-secret"}`
				}
				if tt.status == 202 || tt.status == 204 {
					body = ""
				}
				return jsonResponse(tt.status, body, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			inv := microsoftGraphInvocation(t, a, tt.operation, tt.args)
			if _, err = a.Preview(inv); err != nil {
				t.Fatal(err)
			}
			r, err := a.Invoke(context.Background(), inv)
			if err != nil || calls != 1 || r.Attempts != 1 || r.ProviderStatus != tt.status {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			b, _ := json.Marshal(r.Data)
			if strings.Contains(string(b), "provider-secret") {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestMicrosoftGraphValidationRejectsBeforeTransport(t *testing.T) {
	cases := []struct{ provider, operation, args string }{
		{"outlook_mail", "messages.get", `{"message_id":"../users/other"}`},
		{"outlook_mail", "messages.get", `{"message_id":"A%2Fusers"}`},
		{"outlook_mail", "messages.get", `{"message_id":"https://other.invalid"}`},
		{"outlook_mail", "messages.list", `{"next_link":"https://other.invalid"}`},
		{"outlook_mail", "messages.list", `{"$expand":"attachments"}`},
		{"outlook_mail", "messages.list", `{"top":101}`},
		{"outlook_mail", "messages.list", `{"top":1.5}`},
		{"outlook_mail", "messages.list", `{"top":1,"top":2}`},
		{"outlook_mail", "messages.get", `{"message_id":"abc","expected_external_id":"other-account"}`},
		{"outlook_mail", "drafts.update", `{"message_id":"abc","body":{"subject":"changed"}}`},
		{"outlook_mail", "drafts.update", `{"message_id":"abc","etag":"*","body":{"subject":"changed"}}`},
		{"outlook_mail", "drafts.update", `{"message_id":"abc","etag":"\"x\"\r\nX-Evil: yes","body":{"subject":"changed"}}`},
		{"outlook_mail", "drafts.create", `{"body":{"subject":"QA","body":{"contentType":"HTML","content":"<script/>"},"toRecipients":[]}}`},
		{"outlook_mail", "drafts.create", `{"body":{"subject":"QA","body":{"contentType":"Text","content":"x"},"toRecipients":[],"from":{"emailAddress":{"address":"other@example.com"}}}}`},
		{"outlook_mail", "drafts.create", `{"body":{"subject":"QA","body":{"contentType":"Text","content":"x"},"toRecipients":[{"emailAddress":{"address":"Display <qa@example.com>"}}]}}`},
		{"outlook_mail", "drafts.update", `{"message_id":"abc","etag":"\"x\"","body":{"subject":"QA","subject":"other"}}`},
		{"outlook_calendar", "events.create", `{"calendar_id":"CAL","body":{"subject":"QA","start":{"dateTime":"2026-10-17T13:00:00","timeZone":"UTC"},"end":{"dateTime":"2026-10-17T12:00:00","timeZone":"UTC"}}}`},
		{"outlook_calendar", "events.create", `{"calendar_id":"CAL","body":{"subject":"QA","start":{"dateTime":"2026-10-17T12:00:00","timeZone":"Europe/Rome"},"end":{"dateTime":"2026-10-17T13:00:00","timeZone":"Europe/Rome"}}}`},
		{"outlook_calendar", "events.update", `{"calendar_id":"CAL","event_id":"EVENT","etag":"\"x\"","body":{"body":{"contentType":"Text","content":"overwrite meeting blob"}}}`},
		{"outlook_calendar", "events.update", `{"calendar_id":"CAL","event_id":"EVENT","etag":"\"x\"","body":{"start":{"dateTime":"2026-10-17T12:00:00","timeZone":"UTC"}}}`},
	}
	for _, tt := range cases {
		t.Run(tt.operation+tt.args, func(t *testing.T) {
			a, _ := NewMicrosoftGraphAdapter(tt.provider, doerFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid input reached transport")
				return nil, nil
			}))
			inv := microsoftGraphInvocation(t, a, tt.operation, tt.args)
			if _, err := a.Preview(inv); err == nil {
				t.Fatal("invalid preview accepted")
			}
			if _, err := a.Invoke(context.Background(), inv); err == nil {
				t.Fatal("invalid invocation accepted")
			}
		})
	}
}

func TestMicrosoftGraphContinuationBoundToAccountOperationAndPath(t *testing.T) {
	var token string
	calls := 0
	a, _ := NewMicrosoftGraphAdapter("outlook_mail", doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 2 {
			if req.URL.Query().Get("$skip") != "42" {
				t.Fatal("opaque provider skip not preserved")
			}
			return jsonResponse(200, `{"value":[]}`, nil), nil
		}
		next := microsoftGraphOrigin + req.URL.EscapedPath() + "?" + url.Values{"$top": {"25"}, "$select": {microsoftGraphSelect("outreach.outlook_mail.messages.list")}, "$skip": {"42"}}.Encode()
		b, _ := json.Marshal(map[string]any{"value": []any{}, "@odata.nextLink": next})
		return jsonResponse(200, string(b), nil), nil
	}))
	inv := microsoftGraphInvocation(t, a, "messages.list", `{}`)
	r, err := a.Invoke(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	m := r.Data.(map[string]any)
	if m["@odata.nextLink"] != nil {
		t.Fatal("raw nextLink exposed")
	}
	token = m["next_page_token"].(string)
	b, _ := json.Marshal(map[string]any{"page_token": token})
	inv.Arguments = b
	if _, err = a.Invoke(context.Background(), inv); err != nil || calls != 2 {
		t.Fatal("valid continuation rejected")
	}
	for _, change := range []string{"account", "external-account", "operation", "origin", "path", "expand", "top"} {
		raw, _ := base64.RawURLEncoding.DecodeString(token)
		var c microsoftGraphCursor
		_ = json.Unmarshal(raw, &c)
		switch change {
		case "account":
			c.Connection = "other-connection"
		case "external-account":
			c.ExternalID = "reconnected-other-account"
		case "operation":
			c.Operation = "outreach.outlook_mail.folders.list"
		case "origin":
			c.URL = strings.Replace(c.URL, "graph.microsoft.com", "graph.microsoft.com.attacker.invalid", 1)
		case "path":
			c.URL = strings.Replace(c.URL, "/me/messages", "/users/other/messages", 1)
		case "expand":
			c.URL += "&%24expand=attachments"
		case "top":
			c.URL += "&%24top=1000"
		}
		raw, _ = json.Marshal(c)
		b, _ = json.Marshal(map[string]any{"page_token": base64.RawURLEncoding.EncodeToString(raw)})
		inv.Arguments = b
		if _, err = a.Preview(inv); err == nil {
			t.Fatalf("forged %s cursor accepted", change)
		}
	}
	// A retained cursor must also fail after the same connection changes account.
	b, _ = json.Marshal(map[string]any{"page_token": token})
	inv.Arguments = b
	inv.Connection.ExternalID = "reconnected-other-account"
	if _, err = a.Preview(inv); err == nil {
		t.Fatal("cursor survived account replacement")
	}
	inv.Connection.ExternalID = "verified-graph-account"
	raw, _ := base64.RawURLEncoding.DecodeString(token)
	raw = append([]byte(`{"connection":"conn-1",`), raw[1:]...)
	b, _ = json.Marshal(map[string]any{"page_token": base64.RawURLEncoding.EncodeToString(raw)})
	inv.Arguments = b
	if _, err = a.Preview(inv); err == nil {
		t.Fatal("duplicate cursor field accepted")
	}
}

func TestMicrosoftGraphScopeAndIdentityFenceAtInvoke(t *testing.T) {
	a, _ := NewMicrosoftGraphAdapter("outlook_mail", doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("denied credential reached transport")
		return nil, nil
	}))
	for _, kind := range []string{"read-only", "no-send", "duplicate-scope", "invalid-scope", "account", "workspace", "bound-connection", "config", "config-null", "none", "risk"} {
		inv := microsoftGraphInvocation(t, a, "messages.send", `{"message_id":"draft"}`)
		switch kind {
		case "read-only":
			inv.Connection.Scopes = []string{"Mail.Read"}
		case "no-send":
			inv.Connection.Scopes = []string{"Mail.ReadWrite"}
		case "duplicate-scope":
			inv.Connection.Scopes = []string{"Mail.Send", "Mail.Send"}
		case "invalid-scope":
			inv.Connection.Scopes = []string{"Mail.Send", "bad scope"}
		case "account":
			inv.Connection.ExternalID = ""
		case "workspace":
			inv.Connection.WorkspaceID = "another"
		case "bound-connection":
			inv.Principal.BoundConnectionID = "another-connection"
		case "config":
			inv.Connection.Config = json.RawMessage(`{"origin":"https://attacker.invalid"}`)
		case "config-null":
			inv.Connection.Config = json.RawMessage(`null`)
		case "none":
			inv.Credential = domain.Credential{}
		case "risk":
			inv.Operation.Risk = domain.RiskRead
		}
		if _, err := a.Invoke(context.Background(), inv); err == nil {
			t.Fatalf("missing %s fence", kind)
		}
	}
	if a.OperationScopesGranted([]string{"Mail.Send", "Mail.Send"}, "outreach.outlook_mail.messages.send") || a.OperationScopesGranted([]string{"Mail.Send", "bad scope"}, "outreach.outlook_mail.messages.send") {
		t.Fatal("policy accepted invalid scope metadata")
	}
}

func TestMicrosoftGraphDirectAdapterDeadlineAndEmptyAcknowledgements(t *testing.T) {
	for _, tt := range []struct {
		provider, name, args string
		status               int
	}{
		{"outlook_mail", "messages.send", `{"message_id":"draft"}`, 202},
		{"outlook_calendar", "events.delete", `{"calendar_id":"CAL","event_id":"EVENT","etag":"\"x\""}`, 204},
	} {
		for _, body := range []string{"", " ", `{"accepted":true}`, `{"error":null}`} {
			a, _ := NewMicrosoftGraphAdapter(tt.provider, doerFunc(func(req *http.Request) (*http.Response, error) {
				deadline, ok := req.Context().Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
					t.Fatal("direct request timeout absent")
				}
				return jsonResponse(tt.status, body, nil), nil
			}))
			inv := microsoftGraphInvocation(t, a, tt.name, tt.args)
			inv.Principal.BoundConnectionID = inv.Connection.ID
			r, err := a.Invoke(context.Background(), inv)
			if body != "" {
				if err == nil {
					t.Fatal("nonempty acknowledgement accepted")
				}
				continue
			}
			if err != nil || r.Data != nil || (r.Metadata["accepted"] != "true" && r.Metadata["completed"] != "true") {
				t.Fatal("acknowledgement exposed provider data or lost status")
			}
		}
	}
}

func TestMicrosoftGraphStrictSuccessfulResponseShapesAndBudget(t *testing.T) {
	cases := []struct{ name, args, body string }{
		{"messages.get", `{"message_id":"abc"}`, `{}`},
		{"messages.get", `{"message_id":"abc"}`, `{"id":"abc","id":"other"}`},
		{"messages.get", `{"message_id":"abc"}`, string([]byte{'{', '"', 'i', 'd', '"', ':', '"', 'a', 'b', 'c', '"', ',', '"', 'x', '"', ':', '"', 0xff, '"', '}'})},
		{"messages.get", `{"message_id":"abc"}`, `{"id":"abc","nested":{"x":1,"x":2}}`},
		{"messages.get", `{"message_id":"abc"}`, `{"id":"abc","error":null}`},
		{"messages.get", `{"message_id":"abc"}`, `{"id":"abc","@odata.etag":"*"}`},
		{"messages.list", `{"top":1}`, `{"value":[{"id":"one"},{"id":"two"}]}`},
		{"messages.list", `{}`, `{"value":[null]}`},
		{"messages.list", `{}`, `{"value":[{}]}`},
		{"messages.list", `{}`, `{"value":[{"id":"../other"}]}`},
	}
	for _, tt := range cases {
		a, _ := NewMicrosoftGraphAdapter("outlook_mail", doerFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, tt.body, nil), nil }))
		if _, err := a.Invoke(context.Background(), microsoftGraphInvocation(t, a, tt.name, tt.args)); err == nil {
			t.Fatal("malformed successful response accepted")
		}
	}
	// A legitimate100-item page exceeds the input parser's4096-node budget.
	items := make([]any, 100)
	for i := range items {
		nested := make([]any, 50)
		for j := range nested {
			nested[j] = map[string]any{"name": "QA", "value": "bounded"}
		}
		items[i] = map[string]any{"id": "resource", "metadata": nested}
	}
	page, _ := json.Marshal(map[string]any{"value": items})
	a, _ := NewMicrosoftGraphAdapter("outlook_mail", doerFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, string(page), nil), nil }))
	if _, err := a.Invoke(context.Background(), microsoftGraphInvocation(t, a, "messages.list", `{"top":100}`)); err != nil {
		t.Fatal("bounded100-item Graph page rejected")
	}
	// Folder responses do not need an ETag unless the API actually emits one.
	a, _ = NewMicrosoftGraphAdapter("outlook_mail", doerFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, `{"id":"folder"}`, nil), nil }))
	if _, err := a.Invoke(context.Background(), microsoftGraphInvocation(t, a, "folders.get", `{"folder_id":"folder"}`)); err != nil {
		t.Fatal("folder ETag invented as prerequisite")
	}
}

func TestMicrosoftGraphFailuresAreTypedSanitizedAndNeverRetried(t *testing.T) {
	for _, status := range []int{301, 401, 403, 412, 429, 500} {
		calls := 0
		a, _ := NewMicrosoftGraphAdapter("outlook_mail", doerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(status, `{"error":{"message":"provider-secret private-content"}}`, map[string]string{"Retry-After": "1"}), nil
		}))
		inv := microsoftGraphInvocation(t, a, "messages.send", `{"message_id":"draft"}`)
		_, err := a.Invoke(context.Background(), inv)
		var providerErr *domain.ProviderError
		if !errors.As(err, &providerErr) || providerErr.StatusCode != status || providerErr.Attempts != 1 || calls != 1 || strings.Contains(err.Error(), "private-content") || strings.Contains(err.Error(), "provider-secret") {
			t.Fatal("unsafe failure or retry")
		}
		if status == 429 && providerErr.Kind != "rate_limited" {
			t.Fatal("quota classification lost")
		}
		if status == 412 && providerErr.Kind != "version_conflict" {
			t.Fatal("precondition conflict lost")
		}
	}
	calls := 0
	a, _ := NewMicrosoftGraphAdapter("outlook_mail", doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("provider-secret arbitrary failure")
	}))
	inv := microsoftGraphInvocation(t, a, "messages.send", `{"message_id":"draft"}`)
	if _, err := a.Invoke(context.Background(), inv); err == nil || calls != 1 || strings.Contains(err.Error(), "provider-secret") {
		t.Fatal("ambiguous send retried or leaked")
	}
}

func TestMicrosoftGraphResponseBoundsAndNoRedirect(t *testing.T) {
	client := &http.Client{}
	a, err := NewMicrosoftGraphAdapter("outlook_mail", client)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(a.doer.(*http.Client).CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) || client.CheckRedirect != nil {
		t.Fatal("redirect policy mutated caller or followed redirect")
	}
	for _, body := range []string{strings.Repeat("x", microsoftGraphMaxResponse+1), `{"error":{"message":"private"}}`, `<html>not Graph JSON</html>`} {
		a, _ := NewMicrosoftGraphAdapter("outlook_mail", doerFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, body, nil), nil }))
		inv := microsoftGraphInvocation(t, a, "messages.get", `{"message_id":"abc"}`)
		if _, err := a.Invoke(context.Background(), inv); err == nil {
			t.Fatal("invalid or oversized response accepted")
		}
	}
}
