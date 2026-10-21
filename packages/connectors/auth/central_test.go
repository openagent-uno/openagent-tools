package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

const centralRecipient = `{"workspace_id":"workspace-fixture","subject_id":"subject-fixture"}`
const centralScope = "https://www.googleapis.com/auth/gmail.modify"

func newCentralFixture(t *testing.T) (*fixture, *Client, Installation) {
	t.Helper()
	f := newFixture(t)
	c := f.client(t, "Destination host")
	p := f.server.Providers["shopify"]
	delete(f.server.Providers, "shopify")
	p.ID, p.AppID, p.Scopes = "gmail", "central-google-fixture", []string{centralScope}
	p.RedirectURI = f.http.URL + "/v1/oauth/gmail/callback"
	p.PKCE = true
	f.server.Providers[p.ID] = p
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		f.calls.Add(1)
		return fixtureResponse(200, `{"access_token":"CENTRAL-ACCESS","refresh_token":"CENTRAL-REFRESH","expires_in":3600,"scope":"`+centralScope+`"}`), nil
	})
	return f, c, f.server.Store.snapshot().Installations[c.Identity.ID()]
}

func readyCentral(t *testing.T, f *fixture, installation Installation, recipient string) (Transaction, string) {
	t.Helper()
	tx, err := f.server.BeginCentral(installation, Start{Provider: "gmail"}, recipient)
	if err != nil {
		t.Fatal(err)
	}
	return approveCentralFixtureTransaction(t, f, tx)
}

func approveCentralFixtureTransaction(t *testing.T, f *fixture, tx Transaction) (Transaction, string) {
	t.Helper()
	page, err := http.Get(tx.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(page.Body)
	page.Body.Close()
	if err != nil || page.StatusCode != 200 || len(page.Cookies()) != 1 {
		t.Fatal("central disclosure unavailable", err)
	}
	cookie := page.Cookies()[0]
	form := url.Values{"csrf": {cookie.Value}}
	req, _ := http.NewRequest("POST", tx.AuthorizationURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", f.http.URL)
	req.AddCookie(cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	launchBody, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 {
		t.Fatal("central consent failed", err)
	}
	state := providerLink(t, string(launchBody)).Query().Get("state")
	callback, err := http.Get(f.http.URL + "/v1/oauth/gmail/callback?" + url.Values{"state": {state}, "code": {"CENTRAL-CODE"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, callback.Body)
	callback.Body.Close()
	if callback.StatusCode != 200 {
		t.Fatal("central callback rejected", callback.StatusCode)
	}
	return tx, string(body)
}

func TestCentralCannotCaptureLegacyConsentWithoutCentralCustodyDisclosure(t *testing.T) {
	f, c, installation := newCentralFixture(t)
	tx, err := c.Start(context.Background(), Start{Provider: "gmail"})
	if err != nil {
		t.Fatal(err)
	}
	tx, page := approveCentralFixtureTransaction(t, f, tx)
	if tx.Mode != "" || !strings.Contains(page, "Credentials and API data are stored on that server") {
		t.Fatal("ordinary consent was not legacy custody mode")
	}
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error {
		t.Error("legacy consent captured by central vault")
		return nil
	}); err == nil || f.calls.Load() != 0 {
		t.Fatal("central completion consumed legacy consent")
	}
	if _, err := c.Redeem(context.Background(), tx.ID); err != nil || f.calls.Load() != 1 {
		t.Fatal("central refusal changed ordinary legacy redemption", err)
	}
}

func acceptCentral(t *testing.T, f *fixture, installation Installation, tx Transaction) oauth.Token {
	t.Helper()
	var stored oauth.Token
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(token oauth.Token) error {
		stored = token
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestCentralAuthenticationUsesExactBodyNonceRateAndQAFences(t *testing.T) {
	f, c, installation := newCentralFixture(t)
	body := []byte(`{"recipient":"one"}`)
	req, _ := http.NewRequest("POST", f.http.URL+"/v1/central/connections", nil)
	c.Identity.Sign(req, body)
	if _, err := f.server.AuthenticateInstallation(req, []byte(`{"recipient":"two"}`)); err == nil {
		t.Fatal("a different body authenticated")
	}
	got, err := f.server.AuthenticateInstallation(req, body)
	if err != nil || got != installation {
		t.Fatal("signed installation unavailable", err)
	}
	if _, err := f.server.AuthenticateInstallation(req, body); err == nil {
		t.Fatal("signed nonce was reusable")
	}
	other := f.client(t, "Other host")
	if err := f.server.ConfigureQAEnrollment(QAEnrollment{Installations: []string{installation.ID}}); err != nil {
		t.Fatal(err)
	}
	otherReq, _ := http.NewRequest("POST", f.http.URL+"/v1/central/connections", nil)
	other.Identity.Sign(otherReq, body)
	if _, err := f.server.AuthenticateInstallation(otherReq, body); err == nil {
		t.Fatal("QA-unadmitted installation authenticated")
	}
	f.server.mu.Lock()
	f.server.rates[installation.ID] = make([]time.Time, 120)
	for i := range f.server.rates[installation.ID] {
		f.server.rates[installation.ID][i] = f.server.now()
	}
	f.server.mu.Unlock()
	rateReq, _ := http.NewRequest("POST", f.http.URL+"/v1/central/connections", nil)
	c.Identity.Sign(rateReq, body)
	if _, err := f.server.AuthenticateInstallation(rateReq, body); err == nil {
		t.Fatal("request rate fence was bypassed")
	}
	if f.calls.Load() != 0 {
		t.Fatal("authentication contacted a provider")
	}
}

func TestWithCentralInstallationRechecksRegistrationAfterSignedKeylessAdmission(t *testing.T) {
	f, c, installation := newCentralFixture(t)
	body := []byte(`{"operation":"keyless-fixture"}`)
	req, _ := http.NewRequest("POST", f.http.URL+"/v1/central/invoke", nil)
	c.Identity.Sign(req, body)
	authenticated, err := f.server.AuthenticateInstallation(req, body)
	if err != nil || authenticated != installation {
		t.Fatal("fixture signature authentication failed", err)
	}
	accepted := 0
	if err := f.server.WithCentralInstallation(authenticated, func() error { accepted++; return nil }); err != nil || accepted != 1 {
		t.Fatal("current keyless installation was rejected", err)
	}
	if err := f.server.Store.update(func(state *State) error { delete(state.Installations, installation.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	// The already verified request must not outlive its current registration,
	// including when used a second time for post-IO durable result publication.
	if err := f.server.WithCentralInstallation(authenticated, func() error { accepted++; return nil }); err == nil || accepted != 1 {
		t.Fatal("removed installation reached keyless admission/delivery")
	}
	if f.calls.Load() != 0 {
		t.Fatal("keyless metadata fence contacted a provider")
	}
}

func TestWithCentralInstallationSerializesRemovalWithVaultCallback(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var callbackComplete atomic.Bool
	accepted := make(chan error, 1)
	go func() {
		accepted <- f.server.WithCentralInstallation(installation, func() error {
			close(entered)
			<-release
			callbackComplete.Store(true)
			return nil
		})
	}()
	<-entered
	removing := make(chan struct{})
	removed := make(chan error, 1)
	go func() {
		close(removing)
		removed <- f.server.Store.update(func(state *State) error {
			if !callbackComplete.Load() {
				return errors.New("installation removal crossed an active vault callback")
			}
			delete(state.Installations, installation.ID)
			return nil
		})
	}()
	<-removing
	close(release)
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	if err := f.server.WithCentralInstallation(installation, func() error { t.Error("removed installation callback ran"); return nil }); err == nil {
		t.Fatal("installation removal was not effective")
	}
	if f.calls.Load() != 0 {
		t.Fatal("registration race test contacted a provider")
	}
}

func TestWithCentralInstallationRejectsChangedRegistrationAndUnadmittedQAIdentity(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	other := f.client(t, "QA-excluded host")
	otherInstallation := f.server.Store.snapshot().Installations[other.Identity.ID()]
	if err := f.server.ConfigureQAEnrollment(QAEnrollment{Installations: []string{installation.ID}}); err != nil {
		t.Fatal(err)
	}
	changed := installation
	changed.PublicKey = "forged-key"
	for _, candidate := range []Installation{changed, otherInstallation, {ID: installation.ID}} {
		if err := f.server.WithCentralInstallation(candidate, func() error { t.Error("unverified installation callback ran"); return nil }); err == nil {
			t.Fatal("changed or QA-unadmitted registration accepted")
		}
	}
	if err := f.server.WithCentralInstallation(installation, nil); err == nil {
		t.Fatal("nil installation callback accepted")
	}
}

func TestCentralConsentBindsRecipientAndCannotBeRedeemedByLegacyHTTP(t *testing.T) {
	f, c, installation := newCentralFixture(t)
	tx, page := readyCentral(t, f, installation, centralRecipient)
	if tx.Mode != CentralMode || !strings.Contains(page, "credentials encrypted in the central credential vault") ||
		!strings.Contains(page, "executes provider API requests there") || !strings.Contains(page, "workspace-fixture") ||
		!strings.Contains(page, "subject-fixture") || !strings.Contains(page, "Destination host") ||
		strings.Contains(page, "Credentials and API data are stored on that server") {
		t.Fatal("custody or destination disclosure is incorrect")
	}
	public, _ := json.Marshal(tx)
	if strings.Contains(string(public), "workspace-fixture") || strings.Contains(string(public), "CENTRAL-CODE") {
		t.Fatal("internal transaction recipient/code leaked into public transaction")
	}
	tx.Mode = ""
	tx.Scopes[0] = "caller-mutated-scope"
	if _, err := c.Redeem(context.Background(), tx.ID); err == nil || f.calls.Load() != 0 {
		t.Fatal("legacy HTTP redeemed a central transaction")
	}
	f.server.mu.Lock()
	stored := *f.server.transactions[tx.ID]
	f.server.mu.Unlock()
	if stored.Status != "ready" || stored.code != "CENTRAL-CODE" ||
		stored.Mode != CentralMode || !sameScopes(stored.Scopes, []string{centralScope}) {
		t.Fatal("legacy rejection or returned transaction mutation consumed/changed central consent")
	}
	token := acceptCentral(t, f, installation, tx)
	if token.AccessToken != "CENTRAL-ACCESS" || token.RefreshToken != "CENTRAL-REFRESH" || f.calls.Load() != 1 {
		t.Fatal("central callback did not receive the in-memory exchange")
	}
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error {
		t.Fatal("replayed central code was delivered")
		return nil
	}); err == nil || f.calls.Load() != 1 {
		t.Fatal("central code was reusable")
	}
	metadata, _ := json.Marshal(f.server.Store.snapshot())
	for _, value := range []string{"CENTRAL-ACCESS", "CENTRAL-REFRESH", "CENTRAL-CODE", "workspace-fixture"} {
		if strings.Contains(string(metadata), value) {
			t.Fatal("auth State persisted central token/code/recipient")
		}
	}
	legacy, err := c.Start(context.Background(), Start{Provider: "gmail"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Get(legacy.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	legacyPage, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(legacyPage), "Credentials and API data are stored on that server") ||
		strings.Contains(string(legacyPage), "central credential vault") {
		t.Fatal("legacy consent wording changed")
	}
}

func TestCentralTransactionReturnsOnlyBoundMetadataWithoutConsumingConsent(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	tx, _ := readyCentral(t, f, installation, centralRecipient)
	metadata, err := f.server.CentralTransaction(installation, tx.ID, centralRecipient)
	if err != nil || metadata.Mode != CentralMode || metadata.ID != tx.ID || metadata.Status != "ready" ||
		metadata.Installation != installation.ID || metadata.Provider != "gmail" || metadata.AppID != tx.AppID ||
		metadata.AuthorizationURL != tx.AuthorizationURL || !metadata.ExpiresAt.Equal(tx.ExpiresAt) ||
		!sameScopes(metadata.Scopes, []string{centralScope}) {
		t.Fatal("central metadata unavailable or incorrectly bound", err)
	}
	if metadata.code != "" || metadata.state != "" || metadata.verifier != "" || metadata.csrf != "" ||
		metadata.recipient != "" || metadata.busy || metadata.approved {
		t.Fatal("central metadata copied private transaction fields")
	}
	metadata.Scopes[0] = "caller-modified"
	f.server.mu.Lock()
	stored := f.server.transactions[tx.ID]
	intact := stored.Status == "ready" && stored.code == "CENTRAL-CODE" && sameScopes(stored.Scopes, []string{centralScope})
	f.server.mu.Unlock()
	if !intact || f.calls.Load() != 0 {
		t.Fatal("metadata polling consumed consent, altered scopes or contacted provider")
	}
	if _, err := f.server.CentralTransaction(installation, tx.ID, "wrong recipient"); err == nil {
		t.Fatal("metadata polling accepted another recipient")
	}
	f.server.mu.Lock()
	stored.Mode = ""
	f.server.mu.Unlock()
	if _, err := f.server.CentralTransaction(installation, tx.ID, centralRecipient); err == nil {
		t.Fatal("metadata polling accepted a legacy transaction")
	}
	f.server.mu.Lock()
	stored.Mode, stored.AppID = CentralMode, "changed-app"
	f.server.mu.Unlock()
	if _, err := f.server.CentralTransaction(installation, tx.ID, centralRecipient); err == nil {
		t.Fatal("metadata polling accepted a changed app binding")
	}
	f.server.mu.Lock()
	stored.AppID, stored.ExpiresAt = tx.AppID, f.server.now().Add(-time.Second)
	f.server.mu.Unlock()
	if _, err := f.server.CentralTransaction(installation, tx.ID, centralRecipient); err == nil {
		t.Fatal("metadata polling accepted an expired transaction")
	}
	f.server.mu.Lock()
	stored.ExpiresAt = tx.ExpiresAt
	f.server.mu.Unlock()
	if err := f.server.Store.update(func(state *State) error { delete(state.Installations, installation.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.server.CentralTransaction(installation, tx.ID, centralRecipient); err == nil {
		t.Fatal("metadata polling accepted a removed registration")
	}
}

func TestCentralRejectsWrongRecipientInstallationAppAndShopifyBeforeExchange(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	tx, _ := readyCentral(t, f, installation, centralRecipient)
	other := f.client(t, "Other host")
	otherInstallation := f.server.Store.snapshot().Installations[other.Identity.ID()]
	for _, attempt := range []struct {
		installation Installation
		recipient    string
	}{{installation, centralRecipient + " "}, {otherInstallation, centralRecipient},
		{Installation{ID: installation.ID}, centralRecipient}, {installation, "other-recipient"}} {
		if err := f.server.CompleteCentral(context.Background(), attempt.installation, tx.ID, attempt.recipient, func(oauth.Token) error {
			t.Fatal("wrong context reached credential vault")
			return nil
		}); err == nil {
			t.Fatal("wrong context accepted")
		}
	}
	p := f.server.Providers["gmail"]
	p.AppID = "another-app"
	f.server.Providers["gmail"] = p
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error { return nil }); err == nil {
		t.Fatal("changed app exchanged old consent")
	}
	if _, err := f.server.BeginCentral(installation, Start{Provider: "shopify", ReceiptVersion: 2, Shop: "example.myshopify.com"}, centralRecipient); err == nil {
		t.Fatal("unqualified central Shopify start admitted")
	}
	if _, err := f.server.RefreshCentral(context.Background(), installation, "shopify", oauth.Token{}); err == nil {
		t.Fatal("unqualified central Shopify refresh admitted")
	}
	if f.calls.Load() != 0 {
		t.Fatal("denied central operation reached provider")
	}
	if _, err := f.server.AuthenticateInstallation(nil, nil); err == nil {
		t.Fatal("missing signed request accepted")
	}
}

func TestWithCentralTokenRechecksLiveGrantBeforeAdmissionAndAfterProviderIO(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	tx, _ := readyCentral(t, f, installation, centralRecipient)
	token := acceptCentral(t, f, installation, tx)
	admitted := 0
	if err := f.server.WithCentralToken(installation, "gmail", token, func() error { admitted++; return nil }); err != nil || admitted != 1 {
		t.Fatal("current grant cannot admit durable invocation", err)
	}
	for _, mutate := range []func(*oauth.Token){func(token *oauth.Token) { token.AppID = "wrong-app" },
		func(token *oauth.Token) { token.AccessToken = "unbound-access" },
		func(token *oauth.Token) { token.ExternalID = "wrong-account" },
		func(token *oauth.Token) { token.Scopes = []string{"unapproved"} },
		func(token *oauth.Token) { expired := time.Now().Add(-time.Hour); token.ExpiresAt = &expired }} {
		copy := token
		mutate(&copy)
		if err := f.server.WithCentralToken(installation, "gmail", copy, func() error { admitted++; return nil }); err == nil {
			t.Fatal("invalid token reached durable admission")
		}
	}
	if err := f.server.WithCentralToken(installation, "shopify", token, func() error { admitted++; return nil }); err == nil {
		t.Fatal("unqualified central Shopify token admitted")
	}
	// Model the provider call occurring outside the metadata fence, followed by
	// a revoked grant before the caller tries to persist/deliver its result.
	if err := f.server.Store.update(func(state *State) error {
		for hash, binding := range state.TokenBindings {
			binding.Revoked = true
			state.TokenBindings[hash] = binding
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.server.WithCentralToken(installation, "gmail", token, func() error { admitted++; return nil }); err == nil || admitted != 1 {
		t.Fatal("revoked grant delivered a late provider result")
	}
	if f.calls.Load() != 1 {
		t.Fatal("grant metadata checks contacted provider")
	}
}

func TestCentralBeginPreservesStartScopeAndProviderQAGuards(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	for _, input := range []Start{{Provider: "gmail", Scopes: []string{"unapproved"}},
		{Provider: "gmail", Shop: "example.myshopify.com"}, {Provider: "gmail", ReceiptVersion: 2},
		{Provider: "not-configured"}} {
		if _, err := f.server.BeginCentral(installation, input, centralRecipient); err == nil {
			t.Fatal("invalid ordinary start contract accepted centrally")
		}
	}
	for _, recipient := range []string{"", " leading", "line\nbreak", strings.Repeat("x", 1025)} {
		if _, err := f.server.BeginCentral(installation, Start{Provider: "gmail"}, recipient); err == nil {
			t.Fatal("invalid recipient admitted")
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("start preflight contacted provider")
	}
	other := f.client(t, "QA-denied host")
	otherInstallation := f.server.Store.snapshot().Installations[other.Identity.ID()]
	if err := f.server.ConfigureQAEnrollment(QAEnrollment{Installations: []string{installation.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.server.BeginCentral(otherInstallation, Start{Provider: "gmail"}, centralRecipient); err == nil {
		t.Fatal("central start bypassed provider QA admission")
	}
}

func TestCentralExpiredReadyConsentCannotExchangeOrCallVault(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	tx, _ := readyCentral(t, f, installation, centralRecipient)
	now := time.Now().UTC().Add(11 * time.Minute)
	f.server.now = func() time.Time { return now }
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error {
		t.Error("expired central consent called vault")
		return nil
	}); err == nil || f.calls.Load() != 0 {
		t.Fatal("expired central consent exchanged")
	}
}

func TestCentralConcurrentCompletionConsumesOnceAndVaultFailureCannotReplay(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	tx, _ := readyCentral(t, f, installation, centralRecipient)
	started, release := make(chan struct{}), make(chan struct{})
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		f.calls.Add(1)
		close(started)
		<-release
		return fixtureResponse(200, `{"access_token":"ONE-ACCESS","refresh_token":"ONE-REFRESH","scope":"`+centralScope+`"}`), nil
	})
	var accepts atomic.Int64
	result := make(chan error, 1)
	go func() {
		result <- f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error {
			accepts.Add(1)
			return errors.New("vault fixture refusal")
		})
	}()
	<-started
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error { accepts.Add(1); return nil }); err == nil {
		t.Fatal("parallel completion acquired same code")
	}
	close(release)
	if err := <-result; err == nil || accepts.Load() != 1 || f.calls.Load() != 1 {
		t.Fatal("vault failure or single-use contract lost", err)
	}
	if err := f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error { accepts.Add(1); return nil }); err == nil || f.calls.Load() != 1 {
		t.Fatal("failed vault callback caused a second exchange")
	}
}

func TestCentralCompletionRechecksInstallationAndRecipientAfterProviderIO(t *testing.T) {
	for _, change := range []string{"installation-removed", "recipient-changed"} {
		t.Run(change, func(t *testing.T) {
			f, _, installation := newCentralFixture(t)
			tx, _ := readyCentral(t, f, installation, centralRecipient)
			started, release := make(chan struct{}), make(chan struct{})
			f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
				close(started)
				<-release
				return fixtureResponse(200, `{"access_token":"LATE-ACCESS","refresh_token":"LATE-REFRESH","scope":"`+centralScope+`"}`), nil
			})
			var accepted atomic.Bool
			result := make(chan error, 1)
			go func() {
				result <- f.server.CompleteCentral(context.Background(), installation, tx.ID, centralRecipient, func(oauth.Token) error { accepted.Store(true); return nil })
			}()
			<-started
			if change == "installation-removed" {
				if err := f.server.Store.update(func(state *State) error { delete(state.Installations, installation.ID); return nil }); err != nil {
					t.Fatal(err)
				}
			} else {
				f.server.mu.Lock()
				f.server.transactions[tx.ID].recipient = "changed recipient"
				f.server.mu.Unlock()
			}
			close(release)
			if err := <-result; err == nil || accepted.Load() || len(f.server.Store.snapshot().TokenBindings) != 0 {
				t.Fatal("late exchange escaped current context fence", err)
			}
		})
	}
}

func TestCentralCompletionContextCancellationNeverCallsVault(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	tx, _ := readyCentral(t, f, installation, centralRecipient)
	started := make(chan struct{})
	f.server.Engine.Client = doerFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- f.server.CompleteCentral(ctx, installation, tx.ID, centralRecipient, func(oauth.Token) error { t.Error("cancelled exchange called vault"); return nil })
	}()
	<-started
	cancel()
	if err := <-result; err == nil {
		t.Fatal("cancelled exchange succeeded")
	}
	if len(f.server.Store.snapshot().TokenBindings) != 0 {
		t.Fatal("cancelled exchange persisted a binding")
	}
}

func TestCentralRefreshUsesBoundGrantAndPreservesNoTokenMetadata(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	tx, _ := readyCentral(t, f, installation, centralRecipient)
	token := acceptCentral(t, f, installation, tx)
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		f.calls.Add(1)
		return fixtureResponse(200, `{"access_token":"NEXT-ACCESS","refresh_token":"NEXT-REFRESH","expires_in":3600,"scope":"`+centralScope+`"}`), nil
	})
	for _, mutate := range []func(*oauth.Token){func(token *oauth.Token) { token.AppID = "wrong-app" },
		func(token *oauth.Token) { token.Scopes = []string{"unapproved"} },
		func(token *oauth.Token) { token.ExternalID = "forged-account" },
		func(token *oauth.Token) { token.RefreshToken = "unbound-refresh" }} {
		copy := token
		mutate(&copy)
		if _, err := f.server.RefreshCentral(context.Background(), installation, "gmail", copy); err == nil || f.calls.Load() != 1 {
			t.Fatal("forged refresh reached provider")
		}
	}
	refreshed, err := f.server.RefreshCentral(context.Background(), installation, "gmail", token)
	if err != nil || refreshed.AccessToken != "NEXT-ACCESS" || refreshed.AppID != token.AppID || f.calls.Load() != 2 {
		t.Fatal("valid central refresh unavailable", err)
	}
	metadata, _ := json.Marshal(f.server.Store.snapshot())
	if strings.Contains(string(metadata), "NEXT-ACCESS") || strings.Contains(string(metadata), "NEXT-REFRESH") {
		t.Fatal("auth State stored refreshed credential")
	}
}

func TestCentralRefreshCannotReturnAfterConcurrentGrantRevocation(t *testing.T) {
	f, _, installation := newCentralFixture(t)
	tx, _ := readyCentral(t, f, installation, centralRecipient)
	token := acceptCentral(t, f, installation, tx)
	started, release := make(chan struct{}), make(chan struct{})
	f.server.Engine.Client = doerFunc(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return fixtureResponse(200, `{"access_token":"REVOKED-LATE-ACCESS","refresh_token":"REVOKED-LATE-REFRESH","scope":"`+centralScope+`"}`), nil
	})
	result := make(chan error, 1)
	go func() {
		_, err := f.server.RefreshCentral(context.Background(), installation, "gmail", token)
		result <- err
	}()
	<-started
	if err := f.server.Store.update(func(state *State) error {
		for hash, binding := range state.TokenBindings {
			binding.Revoked = true
			state.TokenBindings[hash] = binding
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("revoked grant returned replacement credential")
	}
	if _, exists := f.server.Store.snapshot().TokenBindings[f.server.tokenHash(token.AppID, "gmail", "REVOKED-LATE-ACCESS")]; exists {
		t.Fatal("revocation tombstone was overwritten by late refresh")
	}
}
