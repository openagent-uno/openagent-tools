package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestMicrosoftExchangeDiagnosticsKeepPermissionRefusalsAndSecretsClosed(t *testing.T) {
	const sensitive = "PRIVATE-token-or-provider-message"
	cases := []struct {
		name, raw, stage, reason, code string
		status, identities             int
	}{
		{"cumulative-calendar", `{"access_token":"PRIVATE-token-or-provider-message","refresh_token":"r","token_type":"Bearer","expires_in":3600,"scope":"User.Read Mail.ReadWrite Calendars.ReadWrite"}`, "scopes", "scope_config", "none", 200, 0},
		{"scope-subset", `{"access_token":"opaque","refresh_token":"r","token_type":"Bearer","expires_in":3600,"scope":"User.Read Mail.ReadWrite Mail.Send"}`, "scopes", "scope_subset", "none", 200, 0},
		{"duplicate-alias", `{"access_token":"opaque","refresh_token":"r","token_type":"Bearer","expires_in":3600,"scope":"User.Read Mail.ReadWrite https://graph.microsoft.com/Mail.ReadWrite"}`, "scopes", "scope_format", "none", 200, 0},
		{"missing-scope", `{"access_token":"opaque","refresh_token":"r","token_type":"Bearer","expires_in":3600}`, "token", "scope_missing", "none", 200, 0},
		{"missing-refresh", `{"access_token":"opaque","token_type":"Bearer","expires_in":3600,"scope":"User.Read Mail.ReadWrite"}`, "token", "refresh_missing", "none", 200, 0},
		{"missing-expiry", `{"access_token":"opaque","refresh_token":"r","token_type":"Bearer","scope":"User.Read Mail.ReadWrite"}`, "token", "expiry_invalid", "none", 200, 0},
		{"token-type", `{"access_token":"opaque","refresh_token":"r","token_type":"PRIVATE-token-or-provider-message","expires_in":3600,"scope":"User.Read Mail.ReadWrite"}`, "token", "token_type", "none", 200, 0},
		{"provider-known", `{"error":"invalid_grant","error_description":"PRIVATE-token-or-provider-message"}`, "response", "http_status", "invalid_grant", 400, 0},
		{"provider-unknown", `{"error":"PRIVATE-token-or-provider-message"}`, "response", "http_status", "other", 400, 0},
		{"duplicate-json", `{"error":"invalid_grant","error":"PRIVATE-token-or-provider-message"}`, "response", "json", "none", 200, 0},
		{"provider-error-200", `{"error":"invalid_scope","error_description":"PRIVATE-token-or-provider-message"}`, "response", "provider_error", "invalid_scope", 200, 0},
		{"identity", `{"access_token":"opaque","refresh_token":"r","token_type":"Bearer","expires_in":3600,"scope":"User.Read Mail.ReadWrite"}`, "identity", "account_verification", "none", 200, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := apiOnlyProvider(t, "outlook_mail")
			if tc.name == "scope-subset" {
				p.Scopes = append(p.Scopes, MicrosoftGraphScopePrefix+"Mail.Send")
			}
			requested := []string{"offline_access", "User.Read", "Mail.ReadWrite"}
			calls, identities := 0, 0
			e := Engine{Client: apiOnlyOAuthDoer(func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" {
					identities++
					return apiOnlyOAuthResponse(403, `{"error":{"message":"PRIVATE-token-or-provider-message"}}`), nil
				}
				calls++
				return apiOnlyOAuthResponse(tc.status, tc.raw), nil
			})}
			token, err := e.Exchange(context.Background(), p, "PRIVATE-code", strings.Repeat("v", 43), "", requested)
			var rejection *MicrosoftExchangeError
			if !errors.Is(err, ErrAuthentication) || !errors.As(err, &rejection) || rejection.Stage() != tc.stage || rejection.Reason() != tc.reason || rejection.ProviderCode() != tc.code || calls != 1 || identities != tc.identities || token.AccessToken != "" {
				t.Fatalf("diagnostic or fail-closed contract mismatch: case=%s calls=%d identity_calls=%d", tc.name, calls, identities)
			}
			if err.Error() != ErrAuthentication.Error() || strings.Contains(fmt.Sprintf("%+v %#v", err, err), sensitive) {
				t.Fatal("sensitive error escaped")
			}
		})
	}
}

func TestMicrosoftExchangePreflightAndLabelSanitization(t *testing.T) {
	p := apiOnlyProvider(t, "outlook_mail")
	calls := 0
	e := Engine{Client: apiOnlyOAuthDoer(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("PRIVATE") })}
	_, err := e.Exchange(context.Background(), p, "code", strings.Repeat("v", 43), "unexpected-account", p.Scopes)
	var rejection *MicrosoftExchangeError
	if !errors.As(err, &rejection) || rejection.Stage() != "preflight" || rejection.Reason() != "request_context" || calls != 0 {
		t.Fatal("preflight reached provider or lost reason")
	}
	forged := &MicrosoftExchangeError{"PRIVATE", "PRIVATE", "PRIVATE"}
	if forged.Stage() != "unknown" || forged.Reason() != "unknown" || forged.ProviderCode() != "other" || strings.Contains(fmt.Sprintf("%#v", forged), "PRIVATE") {
		t.Fatal("untrusted labels escaped")
	}
	_, err = e.Refresh(context.Background(), p, "refresh", "account23", p.Scopes)
	if errors.As(err, &rejection) || !errors.Is(err, ErrAuthentication) || calls != 1 {
		t.Fatal("exchange diagnostic changed refresh error contract")
	}
}
