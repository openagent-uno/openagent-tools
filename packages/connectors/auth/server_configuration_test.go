package auth

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

type startupNoNetwork struct{ calls int }

func (d *startupNoNetwork) Do(*http.Request) (*http.Response, error) {
	d.calls++
	return nil, errors.New("startup must not contact a provider")
}

func TestNewServerValidatesProviderSpecificStartupContext(t *testing.T) {
	const origin = "https://auth.openagent.uno"
	secretPath := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretPath, []byte("synthetic-startup-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	providers := []oauth.Provider{
		{ID: "google_calendar", AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", Scopes: []string{oauth.GoogleCalendarListScope, oauth.GoogleCalendarEventsScope}, PKCE: true},
		{ID: "outlook_mail", Scopes: []string{"offline_access", oauth.MicrosoftGraphScopePrefix + "User.Read", oauth.MicrosoftGraphScopePrefix + "Mail.ReadWrite"}, PKCE: true},
		{ID: "outlook_calendar", Scopes: []string{"offline_access", oauth.MicrosoftGraphScopePrefix + "User.Read", oauth.MicrosoftGraphScopePrefix + "Calendars.ReadWrite"}, PKCE: true},
		{ID: "onedrive", Scopes: []string{"offline_access", oauth.MicrosoftGraphScopePrefix + "User.Read", oauth.MicrosoftGraphScopePrefix + "Files.Read"}, PKCE: true},
		{ID: "sharepoint", Scopes: []string{"offline_access", oauth.MicrosoftGraphScopePrefix + "User.Read", oauth.MicrosoftGraphScopePrefix + "Sites.Read.All"}, PKCE: true},
		{ID: "clickup", AuthorizationURL: "https://app.clickup.com/api", TokenURL: "https://api.clickup.com/api/v2/oauth/token"},
		{ID: "github", AuthorizationURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", PKCE: true},
		{ID: "notion", AuthorizationURL: "https://api.notion.com/v1/oauth/authorize", TokenURL: "https://api.notion.com/v1/oauth/token"},
		{ID: "shopify", AuthorizationURL: "https://{shop}/admin/oauth/authorize", TokenURL: "https://{shop}/admin/oauth/access_token", Scopes: []string{"read_products"}},
	}
	for i := range providers {
		p := &providers[i]
		p.AppID, p.ClientID, p.SecretFile = p.ID+":synthetic-app", "synthetic-client", secretPath
		p.RedirectURI = origin + "/v1/oauth/" + p.ID + "/callback"
		if p.AuthorizationURL == "" {
			p.AuthorizationURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
			p.TokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		}
	}
	noNetwork := &startupNoNetwork{}
	engine := oauth.Engine{Client: noNetwork}
	store, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range providers {
		t.Run(p.ID, func(t *testing.T) {
			server, err := NewServer(store, engine, []oauth.Provider{p}, origin, make([]byte, 32))
			if err != nil || server == nil || len(server.Providers) != 1 || server.Providers[p.ID].ID != p.ID {
				t.Fatal("valid provider startup rejected")
			}
		})
	}
	if server, err := NewServer(store, engine, providers, origin, make([]byte, 32)); err != nil || server == nil || len(server.Providers) != len(providers) {
		t.Fatal("combined provider startup rejected")
	}
	for _, p := range providers[:5] {
		if _, err := engine.Authorize(p, "state", "challenge", "configuration-check.myshopify.com", p.Scopes); !errors.Is(err, oauth.ErrAuthentication) {
			t.Fatal("non-Shopify tenant context accepted")
		}
	}
	shopify := providers[len(providers)-1]
	for _, shop := range []string{"", "example.com", "evil.myshopify.com/path", "UPPER.myshopify.com"} {
		if _, err := engine.Authorize(shopify, "state", "challenge", shop, shopify.Scopes); !errors.Is(err, oauth.ErrAuthentication) {
			t.Fatal("invalid Shopify shop accepted")
		}
	}
	invalid := providers[0]
	invalid.PKCE = false
	if _, err := NewServer(store, engine, []oauth.Provider{invalid}, origin, make([]byte, 32)); !errors.Is(err, oauth.ErrAuthentication) {
		t.Fatal("startup bypassed mandatory PKCE")
	}
	invalid = providers[1]
	invalid.TokenURL = "https://example.invalid/token"
	if _, err := NewServer(store, engine, []oauth.Provider{invalid}, origin, make([]byte, 32)); !errors.Is(err, oauth.ErrAuthentication) {
		t.Fatal("startup bypassed fixed Microsoft authority")
	}
	if noNetwork.calls != 0 {
		t.Fatal("startup or validation contacted a provider")
	}
}
