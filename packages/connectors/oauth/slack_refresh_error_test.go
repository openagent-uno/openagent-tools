package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestSlackRefreshRejectionsStayGenericAndSanitized(t *testing.T) {
	const sensitive = "xoxp-NEVER-LOG-THIS-credential"
	cases := []struct{ name, reason string }{
		{"nested", "unexpected_nested"}, {"type", "token_type"},
		{"prefix", "token_prefix"}, {"refresh", "refresh_missing"}, {"expiry", "expiry_invalid"},
		{"team", "team_mismatch"}, {"scope", "scope_subset"}, {"json", "json"},
		{"http", "http_status"}, {"error", "ok_false"}, {"unknown_error", "ok_false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			p, e, _ := workspaceProtocolFixture(t, "slack_import", func(w http.ResponseWriter, r *http.Request) {
				calls++
				body := map[string]any{"ok": true, "access_token": sensitive, "refresh_token": sensitive, "expires_in": 43200, "token_type": "user", "scope": "channels:read"}
				switch tc.name {
				case "nested":
					body["authed_user"] = map[string]string{"access_token": sensitive}
				case "type":
					body["token_type"] = "bot"
				case "prefix":
					body["access_token"] = "xoxb-NEVER-LOG-THIS"
				case "refresh":
					delete(body, "refresh_token")
				case "expiry":
					delete(body, "expires_in")
				case "team":
					body["team"] = map[string]string{"id": "T87654321"}
				case "scope":
					body["scope"] = "channels:history"
				case "json":
					_, _ = w.Write([]byte("invalid-json-" + sensitive))
					return
				case "http":
					w.WriteHeader(503)
				case "error":
					body["ok"], body["error"] = false, "invalid_refresh_token"
				case "unknown_error":
					body["ok"], body["error"] = false, sensitive
				}
				_ = json.NewEncoder(w).Encode(body)
			})
			_, err := e.Refresh(context.Background(), p, sensitive, "T12345678", []string{"channels:read"})
			var rejection *SlackRefreshError
			if !errors.Is(err, ErrAuthentication) || !errors.As(err, &rejection) || rejection.Reason() != tc.reason || calls != 1 {
				t.Fatalf("rejection classification mismatch: case=%s calls=%d", tc.name, calls)
			}
			if err.Error() != ErrAuthentication.Error() || strings.Contains(fmt.Sprintf("%+v", err), sensitive) || strings.Contains(rejection.ProviderCode(), sensitive) {
				t.Fatal("credential leaked through authentication error")
			}
			if tc.name == "error" && rejection.ProviderCode() != "invalid_refresh_token" || tc.name == "unknown_error" && rejection.ProviderCode() != "other" {
				t.Fatal("provider code was not allowlisted")
			}
		})
	}
}

func TestSlackRefreshPreflightDiagnosticsNeverReachProvider(t *testing.T) {
	p, e, _ := workspaceProtocolFixture(t, "slack_import", func(http.ResponseWriter, *http.Request) { t.Error("preflight reached provider") })
	for _, tc := range []struct{ team, scope, reason string }{{"bad-team", "channels:read", "team_invalid"}, {"T12345678", "admin", "scope_config"}} {
		_, err := e.Refresh(context.Background(), p, "private-refresh", tc.team, []string{tc.scope})
		var rejection *SlackRefreshError
		if !errors.As(err, &rejection) || rejection.Stage() != "preflight" || rejection.Reason() != tc.reason {
			t.Fatal("preflight diagnostic missing")
		}
	}
	forged := &SlackRefreshError{stage: "private-refresh", reason: "private-refresh", providerCode: "private-refresh"}
	if forged.Stage() != "unknown" || forged.Reason() != "unknown" || forged.ProviderCode() != "other" {
		t.Fatal("diagnostic labels were not sanitized")
	}
}

func TestSlackRefreshWithoutScopeRetainsPriorApprovedScopes(t *testing.T) {
	calls := 0
	p, e, _ := workspaceProtocolFixture(t, "slack_import", func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "access_token": "xoxe.xoxp-next", "refresh_token": "next-refresh", "expires_in": 43200, "token_type": "user"})
	})
	prior := []string{"channels:read", "channels:history"}
	token, err := e.Refresh(context.Background(), p, "prior-refresh", "T12345678", prior)
	if err != nil || calls != 1 || !reflect.DeepEqual(token.Scopes, []string{"channels:history", "channels:read"}) || token.ExternalID != "T12345678" || token.RefreshToken != "next-refresh" {
		t.Fatal("scope-less rotation did not preserve the prior approved grant")
	}
	if !reflect.DeepEqual(prior, []string{"channels:read", "channels:history"}) {
		t.Fatal("rotation mutated the host scope input")
	}
}

func TestSlackInitialExchangeStillRequiresUserScopes(t *testing.T) {
	calls := 0
	p, e, _ := workspaceProtocolFixture(t, "slack_import", func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "team": map[string]string{"id": "T12345678"}, "authed_user": map[string]any{"access_token": "xoxe.xoxp-initial", "refresh_token": "initial-refresh", "expires_in": 43200, "token_type": "user"}})
	})
	if _, err := e.Exchange(context.Background(), p, "fixture-code", "", "", []string{"channels:read"}); !errors.Is(err, ErrAuthentication) || calls != 1 {
		t.Fatal("initial exchange accepted missing user scopes")
	}
}
