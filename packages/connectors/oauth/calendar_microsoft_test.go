package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type apiOnlyOAuthDoer func(*http.Request) (*http.Response, error)

func (d apiOnlyOAuthDoer) Do(r *http.Request) (*http.Response, error) { return d(r) }
func apiOnlyOAuthResponse(status int, raw string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(raw))}
}
func apiOnlyProvider(t *testing.T, id string) Provider {
	t.Helper()
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("fixture-client-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	p := Provider{ID: id, AppID: id + ":fixture-client", ClientID: "fixture-client", SecretFile: secretPath, RedirectURI: "https://auth.openagent.uno/v1/oauth/" + id + "/callback", PKCE: true}
	if id == "google_calendar" {
		p.AuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
		p.TokenURL = "https://oauth2.googleapis.com/token"
		p.Scopes = []string{GoogleCalendarListScope, GoogleCalendarEventsScope}
		p.RevocationURL = "https://oauth2.googleapis.com/revoke"
	} else {
		p.AuthorizationURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
		p.TokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		scope := "Mail.ReadWrite"
		if id == "outlook_calendar" {
			scope = "Calendars.ReadWrite"
		}
		p.Scopes = []string{"offline_access", MicrosoftGraphScopePrefix + "User.Read", MicrosoftGraphScopePrefix + scope}
	}
	return p
}

func TestAPIOnlyCalendarAndMicrosoftAuthorization(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, id := range []string{"google_calendar", "outlook_mail", "outlook_calendar"} {
		p := apiOnlyProvider(t, id)
		e := Engine{}
		if err := e.ValidateConfiguration(p); err != nil {
			t.Fatal(err)
		}
		raw, err := e.Authorize(p, "receiver-bound-state", challenge, "", p.Scopes)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(raw)
		q := u.Query()
		if q.Get("state") != "receiver-bound-state" || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != challenge || q.Get("redirect_uri") != p.RedirectURI || q.Get("nonce") != "" {
			t.Fatal("state, PKCE or API-only flow changed")
		}
		if id == "google_calendar" {
			if q.Get("access_type") != "offline" || q.Get("prompt") != "consent" || q.Get("scope") != strings.Join(p.Scopes, " ") {
				t.Fatal("Google model changed")
			}
		} else {
			if strings.Contains(q.Get("scope"), "openid") || q.Get("response_mode") != "query" || !strings.Contains(q.Get("scope"), MicrosoftGraphScopePrefix+"User.Read") {
				t.Fatal("unexpected OIDC or non-Graph request")
			}
		}
		if _, err = e.Authorize(p, "state", "not-a-valid-S256-challenge", "", p.Scopes); !errors.Is(err, ErrAuthentication) {
			t.Fatal("invalid PKCE accepted")
		}
		p.PKCE = false
		if err = e.ValidateConfiguration(p); !errors.Is(err, ErrAuthentication) {
			t.Fatal("PKCE disabled")
		}
	}
}

func TestGoogleCalendarExchangeRefreshPreservesExistingGoogleModel(t *testing.T) {
	p := apiOnlyProvider(t, "google_calendar")
	calls := 0
	e := Engine{Client: apiOnlyOAuthDoer(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != p.TokenURL || r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatal("unexpected Calendar token route")
		}
		_ = r.ParseForm()
		if r.Form.Get("client_id") != p.ClientID || r.Form.Get("client_secret") != "fixture-client-secret" {
			t.Fatal("client binding missing")
		}
		if calls == 1 && (r.Form.Get("code_verifier") != strings.Repeat("v", 43) || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != p.RedirectURI) {
			t.Fatal("PKCE code exchange changed")
		}
		refresh := "fixture-refresh"
		if calls == 2 {
			refresh = ""
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "fixture-refresh" {
				t.Fatal("refresh changed")
			}
		}
		b, _ := json.Marshal(map[string]any{"access_token": "fixture-access", "refresh_token": refresh, "scope": strings.Join(p.Scopes, " "), "token_type": "Bearer", "expires_in": 3600})
		return apiOnlyOAuthResponse(200, string(b)), nil
	})}
	token, err := e.Exchange(context.Background(), p, "code", strings.Repeat("v", 43), "", p.Scopes)
	if err != nil || token.ExternalID != "" {
		t.Fatal("Calendar invented identity or extra call")
	}
	next, err := e.Refresh(context.Background(), p, token.RefreshToken, "", token.Scopes)
	if err != nil || next.RefreshToken != token.RefreshToken || calls != 2 {
		t.Fatal("Google refresh preservation failed")
	}
	if _, err = e.Exchange(context.Background(), p, "code", strings.Repeat("v", 43), "", []string{"email"}); !errors.Is(err, ErrAuthentication) || calls != 2 {
		t.Fatal("extra identity scope reached provider")
	}
}

func TestMicrosoftTokenScopeNormalizationAndVerifiedAccountRotation(t *testing.T) {
	for _, id := range []string{"outlook_mail", "outlook_calendar"} {
		p := apiOnlyProvider(t, id)
		calls, identities := 0, 0
		apiScope := "Mail.ReadWrite"
		if id == "outlook_calendar" {
			apiScope = "Calendars.ReadWrite"
		}
		e := Engine{Client: apiOnlyOAuthDoer(func(r *http.Request) (*http.Response, error) {
			if r.Method == "GET" {
				identities++
				if r.URL.String() != "https://graph.microsoft.com/v1.0/me?$select=id" || r.Header.Get("Authorization") != "Bearer opaque-access-not-a-jwt" || r.Header.Get("Cookie") != "" {
					t.Fatal("identity route or credential target changed")
				}
				return apiOnlyOAuthResponse(200, `{"id":"00000000-0000-4000-8000-000000000023","displayName":"not persisted"}`), nil
			}
			calls++
			_ = r.ParseForm()
			requested := map[string]bool{}
			for _, scope := range strings.Fields(r.Form.Get("scope")) {
				requested[scope] = true
			}
			if r.URL.String() != p.TokenURL || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Form.Get("client_id") != p.ClientID || r.Form.Get("client_secret") != "fixture-client-secret" || len(requested) != 3 || !requested["offline_access"] || !requested[MicrosoftGraphScopePrefix+"User.Read"] || !requested[MicrosoftGraphScopePrefix+apiScope] {
				t.Fatal("fixed confidential Graph form changed")
			}
			if calls == 1 && (r.Form.Get("code_verifier") != strings.Repeat("v", 43) || r.Form.Get("grant_type") != "authorization_code") {
				t.Fatal("PKCE lost")
			}
			if calls == 2 && (r.Form.Get("refresh_token") != "refresh-one" || r.Form.Get("grant_type") != "refresh_token") {
				t.Fatal("refresh token binding lost")
			}
			refresh, scope := "refresh-one", "User.Read "+apiScope
			if calls == 2 {
				refresh = "refresh-two"
				scope = MicrosoftGraphScopePrefix + "User.Read " + MicrosoftGraphScopePrefix + apiScope
			}
			b, _ := json.Marshal(map[string]any{"access_token": "opaque-access-not-a-jwt", "refresh_token": refresh, "scope": scope, "expires_in": 3600, "token_type": "Bearer"})
			return apiOnlyOAuthResponse(200, string(b)), nil
		})}
		token, err := e.Exchange(context.Background(), p, "code", strings.Repeat("v", 43), "", p.Scopes)
		want := []string{apiScope, "User.Read", "offline_access"}
		if id == "outlook_calendar" {
			want = []string{"Calendars.ReadWrite", "User.Read", "offline_access"}
		}
		if err != nil || token.ExternalID != "00000000-0000-4000-8000-000000000023" || !reflect.DeepEqual(token.Scopes, want) || token.ExpiresAt == nil || token.RefreshToken != "refresh-one" {
			t.Fatalf("initial verified account failed: %v", err)
		}
		next, err := e.Refresh(context.Background(), p, token.RefreshToken, token.ExternalID, token.Scopes)
		if err != nil || next.ExternalID != token.ExternalID || next.RefreshToken != "refresh-two" || !reflect.DeepEqual(next.Scopes, token.Scopes) || calls != 2 || identities != 2 {
			t.Fatal("rotation changed identity or canonical scopes")
		}
	}
}

func TestMicrosoftRefusalsFailClosedWithoutRetryOrSecretErrors(t *testing.T) {
	cases := []struct {
		name, token, identity             string
		tokenStatus                       int
		refresh                           bool
		wantTokenCalls, wantIdentityCalls int
	}{
		{"scope-widened", `{"access_token":"opaque","refresh_token":"r","expires_in":3600,"token_type":"Bearer","scope":"User.Read Mail.ReadWrite Mail.Send"}`, `{"id":"account23"}`, 200, false, 1, 0},
		{"scope-duplicate-alias", `{"access_token":"opaque","refresh_token":"r","expires_in":3600,"token_type":"Bearer","scope":"User.Read Mail.ReadWrite https://graph.microsoft.com/Mail.ReadWrite"}`, `{"id":"account23"}`, 200, false, 1, 0},
		{"unexpected-oidc", `{"access_token":"opaque","refresh_token":"r","expires_in":3600,"token_type":"Bearer","scope":"User.Read Mail.ReadWrite openid"}`, `{"id":"account23"}`, 200, false, 1, 0},
		{"missing-scope", `{"access_token":"opaque","refresh_token":"r","expires_in":3600,"token_type":"Bearer"}`, `{"id":"account23"}`, 200, false, 1, 0},
		{"missing-renewal", `{"access_token":"opaque","expires_in":3600,"token_type":"Bearer","scope":"User.Read Mail.ReadWrite"}`, `{"id":"account23"}`, 200, false, 1, 0},
		{"duplicate-token-key", `{"access_token":"opaque","access_token":"different","refresh_token":"r","expires_in":3600,"token_type":"Bearer","scope":"User.Read Mail.ReadWrite"}`, `{"id":"account23"}`, 200, false, 1, 0},
		{"arbitrary-provider-error", `{"error":"client-secret private-provider-message"}`, `{"id":"account23"}`, 400, false, 1, 0},
		{"identity-duplicate", `{"access_token":"opaque","refresh_token":"r","expires_in":3600,"token_type":"Bearer","scope":"User.Read Mail.ReadWrite"}`, `{"id":"account23","id":"other"}`, 200, false, 1, 1},
		{"identity-error", `{"access_token":"opaque","refresh_token":"r","expires_in":3600,"token_type":"Bearer","scope":"User.Read Mail.ReadWrite"}`, `{"id":"account23","error":null}`, 200, false, 1, 1},
		{"refresh-account-switch", `{"access_token":"opaque","refresh_token":"r","expires_in":3600,"token_type":"Bearer","scope":"User.Read Mail.ReadWrite"}`, `{"id":"other-account"}`, 200, true, 1, 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := apiOnlyProvider(t, "outlook_mail")
			calls, identities := 0, 0
			e := Engine{Client: apiOnlyOAuthDoer(func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" {
					identities++
					return apiOnlyOAuthResponse(200, tt.identity), nil
				}
				calls++
				return apiOnlyOAuthResponse(tt.tokenStatus, tt.token), nil
			})}
			var err error
			if tt.refresh {
				_, err = e.Refresh(context.Background(), p, "old-refresh", "account23", []string{"offline_access", "User.Read", "Mail.ReadWrite"})
			} else {
				_, err = e.Exchange(context.Background(), p, "code", strings.Repeat("v", 43), "", p.Scopes)
			}
			if !errors.Is(err, ErrAuthentication) || calls != tt.wantTokenCalls || identities != tt.wantIdentityCalls || strings.Contains(err.Error(), "private-provider-message") || strings.Contains(err.Error(), "opaque") {
				t.Fatal("unsafe error, identity adoption or retry")
			}
		})
	}
}

func TestMicrosoftRefreshRetainsOnlyBoundPriorScopeAndCredential(t *testing.T) {
	p := apiOnlyProvider(t, "outlook_mail")
	calls := 0
	e := Engine{Client: apiOnlyOAuthDoer(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method == "GET" {
			return apiOnlyOAuthResponse(200, `{"id":"account23"}`), nil
		}
		return apiOnlyOAuthResponse(200, `{"access_token":"opaque","expires_in":3600,"token_type":"Bearer"}`), nil
	})}
	scopes := []string{"Mail.ReadWrite", "User.Read", "offline_access"}
	token, err := e.Refresh(context.Background(), p, "prior-refresh", "account23", scopes)
	if err != nil || calls != 2 || token.RefreshToken != "prior-refresh" || token.ExternalID != "account23" || !reflect.DeepEqual(token.Scopes, scopes) {
		t.Fatal("prior refresh scope/credential not retained exactly")
	}
}

func TestMicrosoftFixedProtocolAndRefreshPreflightNeverCallProvider(t *testing.T) {
	for _, kind := range []string{"token-origin", "auth-origin", "tenant", "no-pkce", "no-offline", "openid", "mixed-api", "duplicate", "bad-verifier", "bad-account"} {
		p := apiOnlyProvider(t, "outlook_mail")
		scopes := append([]string(nil), p.Scopes...)
		e := Engine{Client: apiOnlyOAuthDoer(func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid protocol reached provider")
			return nil, nil
		})}
		switch kind {
		case "token-origin":
			p.TokenURL = "https://attacker.invalid/token"
		case "auth-origin":
			p.AuthorizationURL = "https://attacker.invalid/authorize"
		case "tenant":
			p.TokenURL = "https://login.microsoftonline.com/other-tenant/oauth2/v2.0/token"
		case "no-pkce":
			p.PKCE = false
		case "no-offline":
			scopes = scopes[1:]
		case "openid":
			scopes = append(scopes, "openid")
			p.Scopes = scopes
		case "mixed-api":
			scopes = append(scopes, MicrosoftGraphScopePrefix+"Calendars.ReadWrite")
			p.Scopes = scopes
		case "duplicate":
			scopes = append(scopes, "Mail.ReadWrite")
			p.Scopes = scopes
		}
		if kind == "bad-account" {
			if _, err := e.Refresh(context.Background(), p, "refresh", "../other", scopes); !errors.Is(err, ErrAuthentication) {
				t.Fatal("invalid account accepted")
			}
			continue
		}
		verifier := strings.Repeat("v", 43)
		if kind == "bad-verifier" {
			verifier = "short"
		}
		if _, err := e.Exchange(context.Background(), p, "code", verifier, "", scopes); !errors.Is(err, ErrAuthentication) {
			t.Fatal("invalid protocol accepted")
		}
	}
	// No cross-provider or case-normalization change to existing Google grants.
	if approvedScopes(Provider{ID: "gmail", Scopes: []string{"User.Read"}}, []string{MicrosoftGraphScopePrefix + "User.Read"}) {
		t.Fatal("Microsoft aliases escaped provider boundary")
	}
}
