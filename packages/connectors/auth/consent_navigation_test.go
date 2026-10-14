package auth

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const unchangedConsentCSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func clickUpConsent(t *testing.T) (*fixture, Transaction, *http.Cookie) {
	t.Helper()
	f := newFixture(t)
	p := f.server.Providers["shopify"]
	p.ID, p.AppID, p.AuthorizationURL, p.Scopes = "clickup", "openagent-clickup", "https://app.clickup.com/api", nil
	f.server.Providers[p.ID] = p
	client := f.client(t, "Recipient server")
	tx, err := client.Start(context.Background(), Start{Provider: "clickup"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := http.Get(tx.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, page.Body)
	_ = page.Body.Close()
	if page.StatusCode != 200 || page.Header.Get("Content-Security-Policy") != unchangedConsentCSP || len(page.Cookies()) != 1 {
		t.Fatal("consent disclosure or CSP changed")
	}
	return f, tx, page.Cookies()[0]
}

func postConsent(t *testing.T, f *fixture, tx Transaction, cookie *http.Cookie, csrf, origin string) (*http.Response, string) {
	t.Helper()
	form := url.Values{"csrf": {csrf}}
	request, err := http.NewRequest("POST", tx.AuthorizationURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	browser := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

func TestConsentUsesExplicitProviderNavigationWithUnchangedCSP(t *testing.T) {
	f, tx, cookie := clickUpConsent(t)
	response, body := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
	if response.StatusCode != 200 || response.Header.Get("Location") != "" || response.Header.Get("Content-Security-Policy") != unchangedConsentCSP || response.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("consent must return HTML without an external POST redirect or relaxed policy")
	}
	if !strings.Contains(response.Header.Get("Content-Type"), "text/html") || !strings.Contains(body, "Open ClickUp authorization") || !strings.Contains(body, `rel="noreferrer" referrerpolicy="no-referrer"`) || strings.Contains(body, "<form") || strings.Contains(body, "<script") || strings.Contains(body, "http-equiv") {
		t.Fatal("missing explicit, no-referrer provider navigation")
	}
	link := providerLink(t, body)
	if link.Scheme != "https" || link.Host != "app.clickup.com" || link.Path != "/api" || link.Query().Get("state") == "" || link.Query().Get("client_id") != "test-client" {
		t.Fatal("provider link lost its validated OAuth parameters")
	}
	replay, body := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
	if replay.StatusCode != 403 || strings.Contains(body, "<a href=") {
		t.Fatal("a consent POST cannot be replayed to produce another provider link")
	}
}

func TestProviderNavigationKeepsConsentCSRFAndOriginFences(t *testing.T) {
	for _, scenario := range []string{"missing cookie", "wrong cookie", "wrong csrf", "wrong origin", "null origin", "missing origin"} {
		t.Run(scenario, func(t *testing.T) {
			f, tx, cookie := clickUpConsent(t)
			csrf, origin := cookie.Value, f.http.URL
			switch scenario {
			case "missing cookie":
				cookie = nil
			case "wrong cookie":
				cookie.Value = "other-browser"
			case "wrong csrf":
				csrf = "other-form"
			case "wrong origin":
				origin = "https://other.example"
			case "null origin":
				origin = "null"
			case "missing origin":
				origin = ""
			}
			response, body := postConsent(t, f, tx, cookie, csrf, origin)
			if response.StatusCode != 403 || strings.Contains(body, "<a href=") {
				t.Fatal("invalid consent reached provider navigation")
			}
		})
	}
}

func TestProviderNavigationValidatesTargetsAndEscapesParameters(t *testing.T) {
	for _, target := range []string{"javascript:alert(1)", "http://app.clickup.com/api", "https://user:password@app.clickup.com/api", "https://app.clickup.com/api#fragment"} {
		t.Run(target, func(t *testing.T) {
			f, tx, cookie := clickUpConsent(t)
			p := f.server.Providers["clickup"]
			p.AuthorizationURL = target
			f.server.Providers[p.ID] = p
			response, body := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
			if response.StatusCode != 400 || strings.Contains(body, "<a href=") {
				t.Fatal("unvalidated provider target reached HTML")
			}
		})
	}
	f, tx, cookie := clickUpConsent(t)
	p := f.server.Providers["clickup"]
	p.ClientID = `"><script>alert(1)</script><a onmouseover="alert(2)`
	f.server.Providers[p.ID] = p
	response, body := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
	if response.StatusCode != 200 || strings.Contains(body, "<script>") || strings.Contains(body, ` onmouseover="`) {
		t.Fatal("OAuth parameter was interpreted as HTML")
	}
	if providerLink(t, body).Query().Get("client_id") != p.ClientID {
		t.Fatal("escaped OAuth parameter changed")
	}
}
