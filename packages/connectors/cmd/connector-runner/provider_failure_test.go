package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	connectors "github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type runnerFailureHTTP struct{ status, calls int }

func (d *runnerFailureHTTP) Do(*http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{StatusCode: d.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":{"message":"PRIVATE token-secret"}}`))}, nil
}

func TestRuntimeFailureSerializesAsLegacyStringAndBoundedStatus(t *testing.T) {
	for _, tt := range []struct {
		status           int
		tool, args, code string
	}{
		{410, "files.google_calendar.events.list", `{"calendar_id":"primary","sync_token":"expired"}`, "sync_reset_required"},
		{412, "files.google_calendar.events.update", `{"calendar_id":"primary","event_id":"event","etag":"\"old\"","body":{"summary":"Change"}}`, "version_conflict"},
	} {
		d := &runnerFailureHTTP{status: tt.status}
		r, err := connectors.NewRuntime(d)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := domain.NewCredential(domain.CredentialOAuth2Bearer, "token-secret", "Authorization", "Bearer", "fixture", nil)
		if err != nil {
			t.Fatal(err)
		}
		call := connectors.Call{Binding: connectors.Binding{CatalogID: "google-calendar", AllowWrite: true, Principal: domain.Principal{WorkspaceID: "workspace", ActorID: "owner"}, Connection: domain.Connection{ID: "connection", WorkspaceID: "workspace", Provider: "google_calendar", Capability: domain.Files, Enabled: true, Config: json.RawMessage(`{}`), Scopes: []string{"https://www.googleapis.com/auth/calendar.events"}}}, Tool: tt.tool, Arguments: json.RawMessage(tt.args), Credential: credential, InvocationID: "runner-failure"}
		_, err = r.Invoke(context.Background(), call)
		if err == nil {
			t.Fatal("fixture did not fail")
		}
		code, status := runnerFailure(err)
		raw, marshalErr := json.Marshal(response{ID: "request-one", Error: code, ProviderStatus: status})
		var wire map[string]any
		if marshalErr != nil || json.Unmarshal(raw, &wire) != nil || wire["error"] != tt.code || wire["provider_status"] != float64(tt.status) || wire["id"] != "request-one" || len(wire) != 3 || d.calls != 1 {
			t.Fatal("legacy string envelope or typed status lost")
		}
		if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "token-secret") {
			t.Fatal("raw provider content serialized")
		}
	}
}

func TestRunnerFailureClosedClassesAndLegacyAuthentication(t *testing.T) {
	for _, tt := range []struct {
		err    error
		code   string
		status int
	}{
		{&domain.ProviderError{Kind: "network_error", StatusCode: 0, ProviderID: "PRIVATE"}, "network_error", 0},
		{&domain.ProviderError{Kind: "rate_limited", StatusCode: 429}, "rate_limited", 429},
		{&domain.ProviderError{Kind: "provider_permission", StatusCode: 403}, "provider_permission", 403},
		{&domain.ProviderError{Kind: "provider_error", StatusCode: 600}, "connector_request_failed", 0},
		{&domain.ProviderError{Kind: "sync_reset_required", StatusCode: 412}, "connector_request_failed", 0},
		{&domain.ProviderError{Kind: "PRIVATE token-secret", StatusCode: 410}, "connector_request_failed", 0},
		{errors.New("PRIVATE token-secret"), "connector_request_failed", 0},
		{&auth.RemoteError{Code: "authorization_expired"}, "authorization_expired", 0},
	} {
		code, status := runnerFailure(tt.err)
		if code != tt.code || status != tt.status {
			t.Fatal("error boundary changed")
		}
		raw, _ := json.Marshal(response{ID: "request", Error: code, ProviderStatus: status})
		var wire map[string]any
		_ = json.Unmarshal(raw, &wire)
		if status == 0 {
			if _, exists := wire["provider_status"]; exists {
				t.Fatal("absent provider HTTP status invented")
			}
		}
		if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "token-secret") {
			t.Fatal("untrusted error serialized")
		}
	}
}
