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

const calendarTestEvent = `{"kind":"calendar#event","id":"event_20261017T120000Z","etag":"\"revision-2\"","summary":"Revisione — 世界","start":{"dateTime":"2026-10-17T14:00:00+02:00","timeZone":"Europe/Rome"},"end":{"dateTime":"2026-10-17T15:00:00+02:00","timeZone":"Europe/Rome"}}`
const calendarTestBody = `{"summary":"Revisione — 世界","start":{"dateTime":"2026-10-17T14:00:00+02:00","timeZone":"Europe/Rome"},"end":{"dateTime":"2026-10-17T15:00:00+02:00","timeZone":"Europe/Rome"}}`

func calendarTestInvocation(t *testing.T, a *GoogleCalendarAdapter, name, args string) domain.Invocation {
	t.Helper()
	var operation domain.Operation
	for _, candidate := range a.Operations() {
		if candidate.Name == "files.google_calendar."+name {
			operation = candidate
			break
		}
	}
	if operation.Name == "" {
		t.Fatal("unknown test operation")
	}
	return domain.Invocation{
		ID: "calendar-inv-1", Principal: domain.Principal{WorkspaceID: "ws-1", ActorID: "workspace-agent", Role: "agent"},
		Connection: domain.Connection{ID: "calendar-conn-1", WorkspaceID: "ws-1", Capability: domain.Files, Provider: "google_calendar", Config: json.RawMessage(`{}`), Enabled: true, Scopes: []string{GoogleCalendarListScope, GoogleCalendarEventsScope}},
		Credential: credential(t, "Authorization", "Bearer"), Operation: operation, Arguments: json.RawMessage(args), RequestedAt: time.Now().UTC(),
	}
}

func TestGoogleCalendarCanonicalSevenTypedTools(t *testing.T) {
	a, err := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) { t.Fatal("metadata made an HTTP call"); return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if a.Provider() != "google_calendar" || a.Capability() != domain.Files || len(a.Operations()) != 7 {
		t.Fatal("invalid adapter contract")
	}
	names := map[string]bool{}
	for _, op := range a.Operations() {
		if err := op.Validate(); err != nil {
			t.Fatal(err)
		}
		if names[op.Name] || op.Mode != domain.OperationTyped || op.Retry.MaxAttempts != 1 || op.Retry.SupportsIdempotency {
			t.Fatal("unexpected operation or retry policy")
		}
		names[op.Name] = true
		scope := GoogleCalendarEventsScope
		if strings.Contains(op.Name, ".calendars.") {
			scope = GoogleCalendarListScope
		}
		if len(op.RequiredScopes) != 1 || op.RequiredScopes[0] != scope {
			t.Fatal("scope contract changed")
		}
		var schema map[string]any
		if json.Unmarshal(op.InputSchema, &schema) != nil || schema["additionalProperties"] != false {
			t.Fatal("invalid tool schema")
		}
		if _, ok := schema["required"].([]any); !ok {
			t.Fatal("required must be an array, including for optional-only lists")
		}
		properties := schema["properties"].(map[string]any)
		for _, forbidden := range []string{"url", "headers", "method", "account_id", "operation", "send_updates", "attendees"} {
			if _, exists := properties[forbidden]; exists {
				t.Fatal("unreviewed provider escape hatch")
			}
		}
	}
	for _, name := range []string{"calendars.list", "calendars.get", "events.list", "events.get", "events.create", "events.update", "events.delete"} {
		if !names["files.google_calendar."+name] {
			t.Fatal("missing typed operation")
		}
	}
	if _, err := NewGoogleCalendarAdapter(nil); err == nil {
		t.Fatal("nil transport accepted")
	}
}

func TestGoogleCalendarFixedRoutesETagsAndBodies(t *testing.T) {
	cases := []struct {
		name, args, method, path, query, etag, body, response string
		status                                                int
	}{
		{"calendars.list", `{"max_results":25,"page_token":"opaque+/=cursor"}`, "GET", "/calendar/v3/users/me/calendarList", "maxResults=25&pageToken=opaque%2B%2F%3Dcursor&showDeleted=true&showHidden=true", "", "", `{"kind":"calendar#calendarList","items":[{"kind":"calendar#calendarListEntry","id":"qa@example.com","etag":"\"v1\""}],"nextSyncToken":"sync+/=next"}`, 200},
		{"calendars.get", `{"calendar_id":"qa@example.com"}`, "GET", "/calendar/v3/users/me/calendarList/qa@example.com", "", "", "", `{"kind":"calendar#calendarListEntry","id":"qa@example.com","etag":"\"v1\""}`, 200},
		{"events.list", `{"calendar_id":"primary","sync_token":"sync+/=old","page_token":"next-page","max_results":10}`, "GET", "/calendar/v3/calendars/primary/events", "maxResults=10&pageToken=next-page&showDeleted=true&singleEvents=false&syncToken=sync%2B%2F%3Dold", "", "", `{"kind":"calendar#events","items":[{"id":"deleted-event","status":"cancelled"}],"nextPageToken":"next-page-2"}`, 200},
		{"events.get", `{"calendar_id":"primary","event_id":"event_20261017T120000Z"}`, "GET", "/calendar/v3/calendars/primary/events/event_20261017T120000Z", "", "", "", calendarTestEvent, 200},
		{"events.create", `{"calendar_id":"primary","body":` + calendarTestBody + `}`, "POST", "/calendar/v3/calendars/primary/events", "", "", calendarTestBody, calendarTestEvent, 200},
		{"events.update", `{"calendar_id":"primary","event_id":"event_20261017T120000Z","etag":"\"revision-1\"","body":{"summary":"Nuovo titolo"}}`, "PATCH", "/calendar/v3/calendars/primary/events/event_20261017T120000Z", "", "\"revision-1\"", `{"summary":"Nuovo titolo"}`, calendarTestEvent, 200},
		{"events.delete", `{"calendar_id":"primary","event_id":"event_20261017T120000Z","etag":"\"revision-1\""}`, "DELETE", "/calendar/v3/calendars/primary/events/event_20261017T120000Z", "", "\"revision-1\"", "", "", 204},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			a, _ := NewGoogleCalendarAdapter(doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != tt.method || req.URL.Scheme != "https" || req.URL.Host != "www.googleapis.com" || req.URL.EscapedPath() != tt.path || req.URL.RawQuery != tt.query {
					t.Fatalf("wrong fixed route %s %s", req.Method, req.URL)
				}
				if req.Header.Get("Authorization") != "Bearer provider-secret" || req.Header.Get("If-Match") != tt.etag || req.Header.Get("Idempotency-Key") != "" || req.Header.Get("Cookie") != "" {
					t.Fatal("wrong credential, ETag or unsupported header")
				}
				got, _ := io.ReadAll(req.Body)
				if tt.body == "" {
					if len(got) != 0 {
						t.Fatal("unexpected body")
					}
				} else {
					var left, right any
					if json.Unmarshal(got, &left) != nil || json.Unmarshal([]byte(tt.body), &right) != nil {
						t.Fatal("invalid event body")
					}
					l, _ := json.Marshal(left)
					r, _ := json.Marshal(right)
					if string(l) != string(r) || req.Header.Get("Content-Type") != "application/json" {
						t.Fatal("event body changed")
					}
				}
				if deadline, ok := req.Context().Deadline(); !ok || time.Until(deadline) > 31*time.Second {
					t.Fatal("request has no bounded deadline")
				}
				return jsonResponse(tt.status, tt.response, nil), nil
			}))
			inv := calendarTestInvocation(t, a, tt.name, tt.args)
			inv.Idempotency = "not-a-provider-retry-license"
			if _, err := a.Preview(inv); err != nil {
				t.Fatal(err)
			}
			if calls != 0 {
				t.Fatal("preview called provider")
			}
			result, err := a.Invoke(context.Background(), inv)
			if err != nil || result.Attempts != 1 || result.ProviderStatus != tt.status || calls != 1 {
				t.Fatalf("request failed: %v", err)
			}
			if result.Data == nil {
				t.Fatal("missing typed data")
			}
		})
	}
}

func TestGoogleCalendarOpaqueIDsAreSingleEscapedSegments(t *testing.T) {
	calls := 0
	a, _ := NewGoogleCalendarAdapter(doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host != "www.googleapis.com" || req.URL.RawQuery != "" || req.URL.Fragment != "" || req.URL.EscapedPath() != "/calendar/v3/calendars/qa+%2F=group@example.com/events/%2F%2Fevil.example%2F%3Fx=%23frag" {
			t.Fatal("opaque ID escaped the fixed route")
		}
		return jsonResponse(200, calendarTestEvent, nil), nil
	}))
	_, err := a.Invoke(context.Background(), calendarTestInvocation(t, a, "events.get", `{"calendar_id":"qa+/=group@example.com","event_id":"//evil.example/?x=#frag"}`))
	if err != nil || calls != 1 {
		t.Fatal("opaque identifiers rejected or route changed")
	}
}

func TestGoogleCalendarConnectionAndScopeIsolation(t *testing.T) {
	for _, kind := range []string{"workspace", "provider", "capability", "disabled", "bound", "connection_arg", "provider_arg", "endpoint_config", "missing_scope", "empty_credential", "none_credential", "operation_risk"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			a, _ := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return jsonResponse(200, calendarTestEvent, nil), nil
			}))
			inv := calendarTestInvocation(t, a, "events.get", `{"calendar_id":"primary","event_id":"event"}`)
			switch kind {
			case "workspace":
				inv.Principal.WorkspaceID = "other-workspace"
			case "provider":
				inv.Connection.Provider = "drive"
			case "capability":
				inv.Connection.Capability = domain.Outreach
			case "disabled":
				inv.Connection.Enabled = false
			case "bound":
				inv.Principal.BoundConnectionID = "other-connection"
			case "connection_arg":
				inv.Arguments = json.RawMessage(`{"calendar_id":"primary","event_id":"event","connection_id":"other-connection"}`)
			case "provider_arg":
				inv.Arguments = json.RawMessage(`{"calendar_id":"primary","event_id":"event","provider":"gmail"}`)
			case "endpoint_config":
				inv.Connection.Config = json.RawMessage(`{"origin":"https://evil.example"}`)
			case "missing_scope":
				inv.Connection.Scopes = []string{GoogleCalendarListScope}
			case "empty_credential":
				inv.Credential = domain.Credential{}
			case "none_credential":
				var err error
				inv.Credential, err = domain.NewCredential(domain.CredentialNone, "", "", "", "", nil)
				if err != nil {
					t.Fatal(err)
				}
			case "operation_risk":
				inv.Operation.Risk = domain.RiskWrite
			}
			if _, err := a.Invoke(context.Background(), inv); err == nil || calls != 0 {
				t.Fatal("invalid binding reached provider")
			}
		})
	}
	// Each connection uses its own token; no account-global credential cache.
	seen := []string{}
	a, _ := NewGoogleCalendarAdapter(doerFunc(func(req *http.Request) (*http.Response, error) {
		seen = append(seen, req.Header.Get("Authorization"))
		return jsonResponse(200, calendarTestEvent, nil), nil
	}))
	for _, account := range []string{"account-a", "account-b"} {
		inv := calendarTestInvocation(t, a, "events.get", `{"calendar_id":"primary","event_id":"event"}`)
		inv.Connection.ID = account
		inv.Credential = credentialWithSecret(t, account, "Authorization", "Bearer")
		if _, err := a.Invoke(context.Background(), inv); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 || seen[0] != "Bearer account-a" || seen[1] != "Bearer account-b" {
		t.Fatal("cross-account credential use")
	}
}

func TestGoogleCalendarProviderSpecificScopeAlternatives(t *testing.T) {
	a, _ := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, calendarTestEvent, nil), nil }))
	for _, tt := range []struct {
		scope                    string
		calendars, reads, writes bool
	}{
		{GoogleCalendarListScope, true, false, false},
		{"https://www.googleapis.com/auth/calendar.calendarlist", true, false, false},
		{GoogleCalendarEventsScope, false, true, true},
		{"https://www.googleapis.com/auth/calendar.events.readonly", false, true, false},
		{"https://www.googleapis.com/auth/calendar.readonly", true, true, false},
		{"https://www.googleapis.com/auth/calendar", true, true, true},
		{"https://www.googleapis.com/auth/drive", false, false, false},
		{"https://www.googleapis.com/auth/calendar.events.attacker", false, false, false},
	} {
		for _, op := range a.Operations() {
			want := tt.writes
			if strings.Contains(op.Name, ".calendars.") {
				want = tt.calendars
			} else if op.Risk == domain.RiskRead {
				want = tt.reads
			}
			if a.OperationScopesGranted([]string{tt.scope}, op.Name) != want {
				t.Fatalf("wrong scope alternative for %s", op.Name)
			}
		}
	}
	if a.OperationScopesGranted([]string{"https://www.googleapis.com/auth/calendar"}, "files.google_calendar.events.raw") || a.OperationScopesGranted([]string{"https://www.googleapis.com/auth/calendar"}, "files.drive.files.get") || a.OperationScopesGranted(nil, "files.google_calendar.events.get") {
		t.Fatal("unknown operation or empty scopes allowed")
	}
	inv := calendarTestInvocation(t, a, "events.get", `{"calendar_id":"primary","event_id":"event"}`)
	inv.Connection.Scopes = []string{"https://www.googleapis.com/auth/calendar.events.readonly"}
	if _, err := a.Invoke(context.Background(), inv); err != nil {
		t.Fatal("documented read alternative hidden at invocation")
	}
	inv = calendarTestInvocation(t, a, "events.create", `{"calendar_id":"primary","body":`+calendarTestBody+`}`)
	inv.Connection.Scopes = []string{"https://www.googleapis.com/auth/calendar.events.readonly"}
	if _, err := a.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrDenied) {
		t.Fatal("read-only scope allowed write")
	}
}

func TestGoogleCalendarIncrementalSyncAndConflictsNeverRetry(t *testing.T) {
	for _, tt := range []struct {
		name, args string
		status     int
		kind       string
	}{
		{"events.list", `{"calendar_id":"primary","sync_token":"expired"}`, 410, "sync_reset_required"},
		{"calendars.list", `{"sync_token":"expired"}`, 410, "sync_reset_required"},
		{"events.get", `{"calendar_id":"primary","event_id":"gone"}`, 410, "resource_gone"},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{"summary":"Change"}}`, 412, "version_conflict"},
		{"events.delete", `{"calendar_id":"primary","event_id":"event","etag":"\"old\""}`, 412, "version_conflict"},
		{"events.create", `{"calendar_id":"primary","body":` + calendarTestBody + `}`, 429, "rate_limited"},
		{"events.create", `{"calendar_id":"primary","body":` + calendarTestBody + `}`, 503, "provider_error"},
	} {
		t.Run(tt.name+tt.kind, func(t *testing.T) {
			calls := 0
			a, _ := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return jsonResponse(tt.status, `{"error":{"message":"private input provider-secret"}}`, map[string]string{"Retry-After": "0"}), nil
			}))
			inv := calendarTestInvocation(t, a, tt.name, tt.args)
			inv.Idempotency = "still-no-retry"
			result, err := a.Invoke(context.Background(), inv)
			var providerErr *domain.ProviderError
			if !errors.As(err, &providerErr) || providerErr.Kind != tt.kind || providerErr.Attempts != 1 || providerErr.StatusCode != tt.status || calls != 1 || result.Data != nil {
				t.Fatal("wrong error or hidden retry/resync")
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "provider-secret") {
				t.Fatal("provider error leaked content")
			}
		})
	}
	calls := 0
	a, _ := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private socket error with provider-secret")
	}))
	_, err := a.Invoke(context.Background(), calendarTestInvocation(t, a, "events.create", `{"calendar_id":"primary","body":`+calendarTestBody+`}`))
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "network_error" || calls != 1 || strings.Contains(err.Error(), "secret") {
		t.Fatal("ambiguous write was retried or leaked")
	}
}

func TestGoogleCalendarStrictArgumentsAndWriteAllowlist(t *testing.T) {
	cases := []struct{ name, args string }{
		{"events.get", `{"calendar_id":"primary","event_id":"event","url":"https://evil.example"}`},
		{"events.get", `{"calendar_id":"primary","calendar_id":"other","event_id":"event"}`},
		{"events.get", `{"calendar_id":"..","event_id":"event"}`},
		{"events.get", `{"calendar_id":"primary","event_id":"event\r\nX-Header: attack"}`},
		{"events.list", `{"calendar_id":"primary","sync_token":"token","query":"filtered"}`},
		{"events.list", `{"calendar_id":"primary","sync_token":"token","time_min":"2026-10-17T12:00:00Z"}`},
		{"events.list", `{"calendar_id":"primary","show_deleted":false}`},
		{"events.list", `{"calendar_id":"primary","max_results":251}`},
		{"events.list", `{"calendar_id":"primary","max_results":1.5}`},
		{"events.list", `{"calendar_id":"primary","time_min":"2026-10-17T12:00:00"}`},
		{"events.list", `{"calendar_id":"primary","time_min":"2026-10-17T12:00:00Z","time_max":"2026-10-16T12:00:00Z"}`},
		{"events.create", `{"calendar_id":"primary","body":{"attendees":[{"email":"someone@example.com"}]}}`},
		{"events.create", `{"calendar_id":"primary","body":{"start":{"date":"2026-10-17","date":"2026-10-18"},"end":{"date":"2026-10-19"}}}`},
		{"events.create", `{"calendar_id":"primary","body":{"start":{"date":"2026-10-17"},"end":{"date":"2026-10-18"},"conferenceData":{}}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","body":{"summary":"No ETag"}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"*","body":{"summary":"Wildcard"}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"W/\"weak\"","body":{"summary":"Weak"}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"one\",\"two\"","body":{"summary":"List"}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{"start":{"date":"2026-10-17"}}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{"summary":null}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{"status":"confirmed|tentative"}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{"visibility":"public|private"}}`},
		{"events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{"transparency":"opaque|transparent"}}`},
		{"events.delete", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","headers":{"If-Match":"*"}}`},
	}
	for _, tt := range cases {
		calls := 0
		a, _ := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(200, calendarTestEvent, nil), nil
		}))
		if _, err := a.Invoke(context.Background(), calendarTestInvocation(t, a, tt.name, tt.args)); err == nil || calls != 0 {
			t.Fatalf("invalid arguments reached provider for %s", tt.name)
		}
	}
}

func TestGoogleCalendarTimeZonesAndBoundedRecurrence(t *testing.T) {
	cases := []struct {
		body  string
		valid bool
	}{
		{calendarTestBody, true},
		{`{"start":{"date":"2026-10-17"},"end":{"date":"2026-10-18"}}`, true},
		{`{"start":{"date":"2026-10-17"},"end":{"date":"2026-10-17"}}`, false},
		{`{"start":{"date":"2026-02-30"},"end":{"date":"2026-03-01"}}`, false},
		{`{"start":{"dateTime":"2026-10-17T14:00:00+02:00","timeZone":"UTC"},"end":{"dateTime":"2026-10-17T15:00:00+02:00","timeZone":"UTC"}}`, false},
		{`{"start":{"dateTime":"2026-10-17T14:00:00+02:00","timeZone":"Unknown/Zone"},"end":{"dateTime":"2026-10-17T15:00:00+02:00","timeZone":"Unknown/Zone"}}`, false},
		{`{"start":{"date":"2026-10-17","dateTime":"2026-10-17T12:00:00Z"},"end":{"date":"2026-10-18"}}`, false},
		{`{"start":{"dateTime":"2026-10-17T12:00:00Z"},"end":{"dateTime":"2026-10-17T13:00:00Z"},"recurrence":["RRULE:FREQ=WEEKLY;COUNT=4"]}`, false},
	}
	for _, tt := range cases {
		object, err := calendarJSON([]byte(tt.body), googleCalendarMaxRequest)
		if err != nil {
			t.Fatal(err)
		}
		if calendarValidEvent(object, true) != tt.valid {
			t.Fatal("time validation mismatch")
		}
	}
	for _, line := range []string{"RRULE:FREQ=WEEKLY;COUNT=4;BYDAY=MO,WE;WKST=MO", "RRULE:FREQ=MONTHLY;BYDAY=-1FR;COUNT=12", "RDATE;TZID=Europe/Rome:20261018T140000", "EXDATE:20261018T120000Z", "EXDATE;VALUE=DATE:20261018"} {
		if !calendarRecurrence(line) {
			t.Fatalf("valid recurrence rejected: %s", line)
		}
	}
	for _, line := range []string{"DTSTART:20261017T120000Z", "RRULE:FREQ=DAILY\r\nATTENDEE:mailto:someone@example.com", "RRULE:FREQ=DAILY;COUNT=0", "RRULE:FREQ=DAILY;COUNT=4;UNTIL=20261020T120000Z", "RRULE:FREQ=DAILY;FREQ=MONTHLY", "RRULE:FREQ=WEEKLY;BYDAY=99MO", "RRULE:FREQ=DAILY;BYHOUR=24", "RDATE;VALUE=PERIOD:20261018T120000Z/20261018T130000Z", "EXDATE;TZID=Unknown/Zone:20261018T120000", "EXDATE:https://evil.example"} {
		if calendarRecurrence(line) {
			t.Fatalf("invalid recurrence accepted: %s", line)
		}
	}
	object, _ := calendarJSON([]byte(calendarTestBody), googleCalendarMaxRequest)
	object["recurrence"] = []any{"RRULE:FREQ=WEEKLY;COUNT=4"}
	if !calendarValidEvent(object, true) {
		t.Fatal("explicit IANA-zone recurrence rejected")
	}
}

func TestGoogleCalendarResponseValidationAndTombstones(t *testing.T) {
	cases := []struct {
		name, response string
		valid          bool
	}{
		{"events.get", calendarTestEvent, true},
		{"events.get", `{"id":"cancelled-event","status":"cancelled"}`, true},
		{"calendars.get", `{"id":"deleted-calendar","deleted":true}`, true},
		{"events.list", `{"kind":"calendar#events","items":[],"nextSyncToken":"persist-me"}`, true},
		{"calendars.list", `{"kind":"calendar#calendarList","items":[],"nextPageToken":"next-page"}`, true},
		{"events.get", `{"error":{"code":403}}`, false},
		{"events.get", `{"kind":"calendar#event","id":"event","etag":"\"v1\"","error":null}`, false},
		{"events.get", `{"kind":"calendar#event","id":"event"}`, false},
		{"events.get", `{"kind":"calendar#event","id":"one","id":"two","etag":"\"v1\""}`, false},
		{"events.list", `{"kind":"calendar#events","items":[],"nextPageToken":"page","nextSyncToken":"sync"}`, false},
		{"events.list", `{"kind":"calendar#events","items":[{"summary":"missing ID"}]}`, false},
		{"events.list", `{"kind":"calendar#events","items":[],"nextPageToken":null}`, false},
		{"events.get", `[]`, false},
		{"events.get", calendarTestEvent + `{}`, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) { return jsonResponse(200, tt.response, nil), nil }))
			args := `{"calendar_id":"primary","event_id":"event"}`
			if strings.HasSuffix(tt.name, ".list") {
				args = `{"calendar_id":"primary"}`
				if tt.name == "calendars.list" {
					args = `{}`
				}
			}
			if tt.name == "calendars.get" {
				args = `{"calendar_id":"primary"}`
			}
			result, err := a.Invoke(context.Background(), calendarTestInvocation(t, a, tt.name, args))
			if (err == nil) != tt.valid || (!tt.valid && result.Data != nil) {
				t.Fatal("untrusted response accepted or valid data rejected")
			}
		})
	}
}

func TestGoogleCalendarResponseBoundsAndPermissionErrors(t *testing.T) {
	for _, status := range []int{401, 403} {
		a, _ := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(status, `{"error":{"message":"provider-secret"}}`, nil), nil
		}))
		if _, err := a.Invoke(context.Background(), calendarTestInvocation(t, a, "events.get", `{"calendar_id":"primary","event_id":"event"}`)); !errors.Is(err, domain.ErrProviderPermission) {
			t.Fatal("permission error lost")
		}
	}
	a, _ := NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, strings.Repeat("x", int(googleCalendarMaxResponse)+1), nil), nil
	}))
	if _, err := a.Invoke(context.Background(), calendarTestInvocation(t, a, "events.get", `{"calendar_id":"primary","event_id":"event"}`)); err == nil {
		t.Fatal("oversized response accepted")
	}
	a, _ = NewGoogleCalendarAdapter(doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, strings.Replace(calendarTestEvent, "Revisione", "provider-secret", 1), nil), nil
	}))
	result, err := a.Invoke(context.Background(), calendarTestInvocation(t, a, "events.get", `{"calendar_id":"primary","event_id":"event"}`))
	encoded, _ := json.Marshal(result.Data)
	if err != nil || strings.Contains(string(encoded), "provider-secret") || !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatal("credential echoed in provider data")
	}
}
