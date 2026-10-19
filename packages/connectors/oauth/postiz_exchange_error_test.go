package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func postizDiagnosticProvider(t *testing.T) Provider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("PRIVATE-POSTIZ-CLIENT-SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	return Provider{ID: "postiz", AppID: "synthetic-postiz", ClientID: "pca_synthetic", SecretFile: path,
		TokenURL: "https://postiz.example/oauth/token", RedirectURI: "https://auth.example/v1/oauth/postiz/callback"}
}

func TestPostizExchangeDiagnosticLabelsAndSingleAttempt(t *testing.T) {
	for _, test := range []struct {
		name, body, stage, reason, code string
		status                          int
	}{
		{"invalid-client", `{"error":"invalid_client","client_secret":"PRIVATE-POSTIZ-CLIENT-SECRET"}`, "response", "http_status", "invalid_client", 400},
		{"invalid-grant", `{"error":"invalid_grant","code":"PRIVATE-CODE"}`, "response", "http_status", "invalid_grant", 400},
		{"upstream", `{"error":"server_error","error_description":"PRIVATE-DESCRIPTION"}`, "response", "http_status", "server_error", 503},
		{"unexpected-created-status", `{"access_token":"PRIVATE-ACCESS","token_type":"bearer"}`, "response", "http_status", "none", 201},
		{"unknown-error", `{"error":"PRIVATE-PROVIDER-CODE"}`, "response", "http_status", "other", 403},
		{"invalid-json", `PRIVATE-NOT-JSON`, "response", "json", "none", 200},
		{"missing-token", `{"error":"invalid_scope","error_description":"PRIVATE-DESCRIPTION"}`, "token", "token_bounds", "invalid_scope", 200},
		{"token-type", `{"access_token":"PRIVATE-ACCESS","refresh_token":"PRIVATE-REFRESH","token_type":"basic"}`, "token", "token_type", "none", 200},
		{"scope", `{"access_token":"PRIVATE-ACCESS","scope":"PRIVATE-SCOPE"}`, "scopes", "scope_config", "none", 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := postizDiagnosticProvider(t)
			calls := 0
			e := Engine{Client: oauthDiagnosticDoer(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})}
			token, err := e.Exchange(context.Background(), p, "PRIVATE-CODE", "", "", nil)
			var failure *PostizExchangeError
			if !errors.Is(err, ErrAuthentication) || !errors.As(err, &failure) || calls != 1 || token.AccessToken != "" || token.RefreshToken != "" {
				t.Fatal("exchange rejection lost its sanitized type, retried, or returned credentials")
			}
			if failure.Stage() != test.stage || failure.Reason() != test.reason || failure.ProviderCode() != test.code || failure.HTTPStatus() != test.status {
				t.Fatal("unexpected closed Postiz diagnostic labels")
			}
			encoded, _ := json.Marshal(failure)
			formatted := fmt.Sprintf("%v|%+v|%#v|%s", err, err, err, encoded)
			for _, sentinel := range []string{"PRIVATE-", p.ClientID, p.TokenURL, p.RedirectURI} {
				if strings.Contains(formatted, sentinel) {
					t.Fatal("error formatting exported private authentication context")
				}
			}
		})
	}
}

type oauthDiagnosticDoer func(*http.Request) (*http.Response, error)

func (f oauthDiagnosticDoer) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestPostizExchangePreflightAndNetworkDiagnostics(t *testing.T) {
	p := postizDiagnosticProvider(t)
	calls := 0
	e := Engine{Client: oauthDiagnosticDoer(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("PRIVATE-NETWORK-URL-CODE")
	})}
	for _, test := range []struct {
		code, stage, reason string
		calls               int
	}{
		{"", "preflight", "code_or_scopes", 0},
		{"PRIVATE-CODE", "request", "network", 1},
	} {
		_, err := e.Exchange(context.Background(), p, test.code, "", "", nil)
		var failure *PostizExchangeError
		if !errors.As(err, &failure) || !errors.Is(err, ErrAuthentication) || failure.Stage() != test.stage || failure.Reason() != test.reason || failure.HTTPStatus() != 0 || calls != test.calls {
			t.Fatal("preflight/network diagnostic was missing, leaked, or retried")
		}
	}
}

func TestPostizExchangeDiagnosticEnumAndHTTPBounds(t *testing.T) {
	err := postizExchangeFailure("PRIVATE-STAGE", "PRIVATE-REASON", "PRIVATE-CODE", 999)
	var failure *PostizExchangeError
	if !errors.As(err, &failure) || failure.Stage() != "unknown" || failure.Reason() != "unknown" || failure.ProviderCode() != "other" || failure.HTTPStatus() != 0 {
		t.Fatal("untrusted diagnostic labels were not closed")
	}
	for _, body := range []string{`{"error":"PRIVATE"}`, `{"error":{"message":"PRIVATE"}}`, `{"error":"invalid_client","error":"PRIVATE"}`, strings.Repeat("x", (1<<20)+1)} {
		code := postizExchangeProviderCode([]byte(body))
		if code != "none" && code != "other" {
			t.Fatal("malformed or arbitrary provider error escaped its enum")
		}
	}
}

func TestPostizExchangeDiagnosticDoesNotWrapOtherProviders(t *testing.T) {
	p := postizDiagnosticProvider(t)
	p.ID = "clickup"
	e := Engine{Client: oauthDiagnosticDoer(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"error":"invalid_client"}`))}, nil
	})}
	_, err := e.Exchange(context.Background(), p, "PRIVATE-CODE", "", "", nil)
	var failure *PostizExchangeError
	if !errors.Is(err, ErrAuthentication) || errors.As(err, &failure) {
		t.Fatal("Postiz diagnostics changed another provider's error contract")
	}
}

func TestPostizStaticAppImplicitScopeBundle(t *testing.T) {
	for _, test := range []struct {
		name, scope string
		accepted    bool
	}{
		{"legacy-absent", "", true},
		{"documented-bundle", "mcp:read mcp:write", true},
		{"same-bundle-reordered", "mcp:write mcp:read", true},
		{"partial-read", "mcp:read", false},
		{"partial-write", "mcp:write", false},
		{"duplicate", "mcp:read mcp:write mcp:read", false},
		{"duplicate-only", "mcp:read mcp:read", false},
		{"extra", "mcp:read mcp:write arbitrary", false},
		{"oidc", "mcp:read mcp:write email", false},
		{"comma", "mcp:read,mcp:write", false},
		{"unknown", "PRIVATE-SCOPE", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := postizDiagnosticProvider(t)
			calls := 0
			body, _ := json.Marshal(map[string]string{"access_token": "PRIVATE-ACCESS", "token_type": "bearer", "scope": test.scope})
			e := Engine{Client: oauthDiagnosticDoer(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			token, err := e.Exchange(context.Background(), p, "PRIVATE-CODE", "", "", nil)
			if calls != 1 {
				t.Fatal("Postiz scope handling retried")
			}
			if test.accepted {
				if err != nil || token.AccessToken != "PRIVATE-ACCESS" || len(token.Scopes) != 0 || token.RefreshToken != "" {
					t.Fatal("documented app-wide bundle did not retain the existing no-granular-scopes token contract")
				}
			} else {
				var failure *PostizExchangeError
				if !errors.Is(err, ErrAuthentication) || !errors.As(err, &failure) || failure.Reason() != "scope_config" || token.AccessToken != "" || strings.Contains(fmt.Sprintf("%#v", err), "PRIVATE-") {
					t.Fatal("unknown, partial or duplicate scope was accepted or leaked")
				}
			}
		})
	}
}
