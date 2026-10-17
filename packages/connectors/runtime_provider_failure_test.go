package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type providerFailureDoer struct{ status, calls int }

func (d *providerFailureDoer) Do(*http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{StatusCode: d.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":{"message":"PRIVATE raw provider body token-secret"}}`))}, nil
}

func providerFailureCall(t *testing.T, id, tool, args string) Call {
	t.Helper()
	item, ok := Lookup(id)
	if !ok {
		t.Fatal("missing fixture catalog entry")
	}
	scope := "https://www.googleapis.com/auth/calendar.events"
	if item.Provider == "outlook_mail" {
		scope = "Mail.ReadWrite"
	} else if item.Provider == "outlook_calendar" {
		scope = "Calendars.ReadWrite"
	}
	credential, err := domain.NewCredential(domain.CredentialOAuth2Bearer, "token-secret", "Authorization", "Bearer", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	return Call{Binding: Binding{CatalogID: id, AllowWrite: true, Principal: domain.Principal{WorkspaceID: "workspace-one", ActorID: "owner"}, Connection: domain.Connection{ID: "connection-one", WorkspaceID: "workspace-one", Provider: item.Provider, Capability: domain.Capability(item.Capability), Enabled: true, ExternalID: "verified-account", Config: json.RawMessage(`{}`), Scopes: []string{scope}}}, Tool: tool, Arguments: json.RawMessage(args), Credential: credential, InvocationID: "failure-fixture"}
}

func TestCalendarMailRuntimePreservesOnlySafeProviderSignal(t *testing.T) {
	for _, tt := range []struct {
		id, tool, args, kind string
		status               int
	}{
		{"google-calendar", "files.google_calendar.events.list", `{"calendar_id":"primary","sync_token":"expired"}`, "sync_reset_required", 410},
		{"google-calendar", "files.google_calendar.events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{"summary":"Change"}}`, "version_conflict", 412},
		{"outlook-mail", "outreach.outlook_mail.messages.list", `{}`, "rate_limited", 429},
		{"outlook-calendar", "files.outlook_calendar.calendars.list", `{}`, "provider_error", 503},
	} {
		t.Run(tt.id+tt.kind, func(t *testing.T) {
			d := &providerFailureDoer{status: tt.status}
			r, err := NewRuntime(d)
			if err != nil {
				t.Fatal(err)
			}
			result, err := r.Invoke(context.Background(), providerFailureCall(t, tt.id, tt.tool, tt.args))
			var safe *domain.ProviderError
			if !errors.As(err, &safe) || safe.Kind != tt.kind || safe.StatusCode != tt.status || d.calls != 1 {
				t.Fatal("typed failure lost or provider retried")
			}
			if safe.ProviderID != "" || safe.Attempts != 0 || safe.RequestBytes != 0 || safe.ResponseBytes != 0 || result.Data != nil || result.Attempts != 0 {
				t.Fatal("non-allowlisted error metadata escaped")
			}
			if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "token-secret") {
				t.Fatal("raw provider error escaped")
			}
		})
	}
}

type injectedProviderFailure struct {
	domain.Adapter
	failure error
}

func (a injectedProviderFailure) Invoke(context.Context, domain.Invocation) (domain.Result, error) {
	return domain.Result{Data: "PRIVATE result"}, a.failure
}

func TestCalendarMailRuntimeCopiesWrappedErrorsAndRejectsUnknownKinds(t *testing.T) {
	for _, tt := range []struct {
		kind   string
		status int
		valid  bool
	}{
		{"sync_reset_required", 410, true}, {"resource_gone", 410, true}, {"version_conflict", 412, true},
		{"provider_permission", 401, true}, {"provider_permission", 403, true}, {"network_error", 0, true},
		{"invalid_response", 200, true}, {"provider_error", 599, true},
		{"PRIVATE token-secret", 410, false}, {"sync_reset_required", 412, false}, {"rate_limited", 200, false},
		{"provider_permission", 500, false}, {"network_error", 200, false}, {"invalid_response", 0, false},
		{"provider_error", 99, false}, {"provider_error", 600, false},
	} {
		r, err := NewRuntime(&providerFailureDoer{status: 200})
		if err != nil {
			t.Fatal(err)
		}
		original := &domain.ProviderError{Kind: tt.kind, StatusCode: tt.status, ProviderID: "PRIVATE token-secret", Attempts: 4, RequestBytes: 123, ResponseBytes: 456}
		r.adapters["google_calendar"] = injectedProviderFailure{Adapter: r.adapters["google_calendar"], failure: errors.Join(errors.New("PRIVATE wrapped token-secret"), original)}
		result, err := r.Invoke(context.Background(), providerFailureCall(t, "google-calendar", "files.google_calendar.events.get", `{"calendar_id":"primary","event_id":"event"}`))
		var safe *domain.ProviderError
		if errors.As(err, &safe) != tt.valid || result.Data != nil || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "token-secret") {
			t.Fatal("unreviewed failure class or data escaped")
		}
		if tt.valid {
			if safe == original || safe.Kind != tt.kind || safe.StatusCode != tt.status || safe.ProviderID != "" || safe.Attempts != 0 || safe.RequestBytes != 0 || safe.ResponseBytes != 0 {
				t.Fatal("error object was not reduced to a bounded copy")
			}
			original.Kind = "mutated-secret"
			if safe.Kind != tt.kind {
				t.Fatal("error alias retained")
			}
		} else if err.Error() != "connector provider request failed" {
			t.Fatal("legacy generic failure changed")
		}
	}
}

func TestLegacyProviderRuntimeErrorRemainsGeneric(t *testing.T) {
	r, err := NewRuntime(&providerFailureDoer{status: 429})
	if err != nil {
		t.Fatal(err)
	}
	r.adapters["clickup"] = injectedProviderFailure{Adapter: r.adapters["clickup"], failure: &domain.ProviderError{Kind: "rate_limited", StatusCode: 429, ProviderID: "PRIVATE token-secret"}}
	call := providerFailureCall(t, "clickup", "files.clickup.workspaces.list", `{}`)
	_, err = r.Invoke(context.Background(), call)
	var typed *domain.ProviderError
	if err == nil || err.Error() != "connector provider request failed" || errors.As(err, &typed) {
		t.Fatal("legacy provider error contract changed")
	}
}
