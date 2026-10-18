package oauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func microsoftFilesOAuthProvider(t *testing.T, id string) Provider {
	t.Helper()
	p := apiOnlyProvider(t, id)
	scope := "Files.Read"
	if id == "sharepoint" {
		scope = "Sites.Read.All"
	}
	p.Scopes = []string{"offline_access", MicrosoftGraphScopePrefix + "User.Read", MicrosoftGraphScopePrefix + scope}
	return p
}
func TestMicrosoftFilesOAuthUsesExistingPKCEAndExactReadScopes(t *testing.T) {
	for _, id := range []string{"onedrive", "sharepoint"} {
		p := microsoftFilesOAuthProvider(t, id)
		e := Engine{}
		if err := e.ValidateConfiguration(p); err != nil {
			t.Fatal(err)
		}
		raw, err := e.Authorize(p, "receiver-bound-state", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "", p.Scopes)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(raw)
		q := u.Query()
		if u.Host != "login.microsoftonline.com" || q.Get("code_challenge_method") != "S256" || q.Get("state") != "receiver-bound-state" || q.Get("scope") != strings.Join(p.Scopes, " ") || strings.Contains(q.Get("scope"), "Write") {
			t.Fatal("unexpected protocol/scope")
		}
		for _, scope := range []string{"Sites.Selected", "Sites.FullControl.All", "Mail.Read", "Calendars.Read", "https://evil.invalid/Files.Read"} {
			candidate := p
			candidate.Scopes = []string{"offline_access", "User.Read", scope}
			if err := e.ValidateConfiguration(candidate); !errors.Is(err, ErrAuthentication) {
				t.Fatal("broad fallback or unrelated permission accepted", id, scope)
			}
		}
		p.PKCE = false
		if err := e.ValidateConfiguration(p); !errors.Is(err, ErrAuthentication) {
			t.Fatal("PKCE disabled")
		}
	}
	// Accepting files scopes does not widen old Outlook protocol boundaries.
	for _, id := range []string{"outlook_mail", "outlook_calendar"} {
		p := apiOnlyProvider(t, id)
		p.Scopes = append(p.Scopes, MicrosoftGraphScopePrefix+"Files.Read")
		if err := (&Engine{}).ValidateConfiguration(p); !errors.Is(err, ErrAuthentication) {
			t.Fatal("files scopes escaped into Outlook")
		}
	}
}
func TestMicrosoftFilesOAuthVerifiesAccountAtExchangeAndRefresh(t *testing.T) {
	for _, id := range []string{"onedrive", "sharepoint"} {
		p := microsoftFilesOAuthProvider(t, id)
		scope := "Files.Read"
		if id == "sharepoint" {
			scope = "Sites.Read.All"
		}
		tokens, identities := 0, 0
		e := Engine{Client: apiOnlyOAuthDoer(func(r *http.Request) (*http.Response, error) {
			if r.Method == "GET" {
				identities++
				if r.URL.String() != "https://graph.microsoft.com/v1.0/me?$select=id" || r.Header.Get("Authorization") != "Bearer opaque-graph-access" {
					t.Fatal("account verification bypassed")
				}
				return apiOnlyOAuthResponse(200, `{"id":"account23"}`), nil
			}
			tokens++
			_ = r.ParseForm()
			if r.URL.String() != p.TokenURL || r.Form.Get("client_id") != p.ClientID || !func() bool {
				got, ok := microsoftScopes(strings.Fields(r.Form.Get("scope")))
				if !ok || len(got) != 3 {
					return false
				}
				return hasOAuthScope(got, "offline_access") && hasOAuthScope(got, "User.Read") && hasOAuthScope(got, scope)
			}() {
				t.Fatal("app or scope binding changed")
			}
			return apiOnlyOAuthResponse(200, `{"access_token":"opaque-graph-access","refresh_token":"refresh-rotated","scope":"User.Read `+scope+`","expires_in":3600,"token_type":"Bearer"}`), nil
		})}
		first, err := e.Exchange(context.Background(), p, "code", strings.Repeat("v", 43), "", p.Scopes)
		if err != nil || first.ExternalID != "account23" {
			t.Fatal("exchange account verification failed", err)
		}
		next, err := e.Refresh(context.Background(), p, first.RefreshToken, first.ExternalID, first.Scopes)
		if err != nil || next.ExternalID != first.ExternalID || !reflect.DeepEqual(first.Scopes, next.Scopes) || identities != 2 || tokens != 2 {
			t.Fatal("refresh identity/scopes changed", err)
		}
		e.Client = apiOnlyOAuthDoer(func(r *http.Request) (*http.Response, error) {
			if r.Method == "GET" {
				return apiOnlyOAuthResponse(200, `{"id":"another-account"}`), nil
			}
			return apiOnlyOAuthResponse(200, `{"access_token":"opaque-graph-access","refresh_token":"r","scope":"User.Read `+scope+`","expires_in":3600,"token_type":"Bearer"}`), nil
		})
		if _, err = e.Refresh(context.Background(), p, next.RefreshToken, next.ExternalID, next.Scopes); !errors.Is(err, ErrAuthentication) {
			t.Fatal("account switched during refresh")
		}
	}
}
