package auth

import (
	"context"
	"html/template"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// CentralMode is an in-process custody mode, never a legacy token redemption.
const CentralMode = "central-v1"

// The legacy disclosure is deliberately unchanged. This page describes the
// different credential custodian and data-plane executor before provider consent.
var centralConsentPage = template.Must(template.New("central-consent").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Connect with OpenAgent</title><style>body{font:17px system-ui;max-width:560px;margin:12vh auto;padding:24px;color:#18212b}button{padding:12px 22px;border-radius:10px;font:inherit;border:0;background:#18212b;color:white}small{color:#566}code{overflow-wrap:anywhere}</style><h1>Connect {{.Provider}}</h1><p>You are authorizing <strong>{{.Name}}</strong> ({{.Product}}) to use the centrally managed OpenAgent connector.</p><p>OpenAgent stores your credentials encrypted in the central credential vault and executes provider API requests there. The destination host receives authorized results, not reusable provider tokens.</p><p>Destination host: <strong>{{.Name}}</strong> ({{.Product}})</p><p>Installation: <code>{{.Installation}}</code></p><p>Destination recipient (workspace and subject): <code>{{.Recipient}}</code></p><p>Permissions: {{if eq .Provider "postiz"}}Postiz app-wide read and write access (mcp:read and mcp:write). This app does not offer granular permission selection.{{else}}{{.Scopes}}{{end}}</p><p><small>The host name and recipient are supplied by its operator. They are not an endorsement by OpenAgent.</small></p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Continue to {{.Provider}}</button></form><p>You can close this window to cancel.</p></html>`))

// AuthenticateInstallation verifies the exact already-bounded request body once,
// consuming its signed nonce and applying the same rate and QA fences as the
// legacy HTTP router. Begin/Complete/Refresh do not re-authenticate that nonce.
func (s *Server) AuthenticateInstallation(r *http.Request, body []byte) (Installation, error) {
	if r == nil || len(body) > 2<<20 {
		return Installation{}, ErrDenied
	}
	installation, err := s.authenticate(r, body)
	if err != nil {
		return Installation{}, err
	}
	if s.limited(installation.ID, 120, time.Minute) || !s.admittedInstallation(installation.ID) {
		return Installation{}, ErrDenied
	}
	if !s.centralInstallation(s.Store.snapshot(), installation) {
		return Installation{}, ErrDenied
	}
	return installation, nil
}

func (s *Server) centralInstallation(state State, installation Installation) bool {
	current, exists := state.Installations[installation.ID]
	return installation.ID != "" && exists && current == installation && s.admittedInstallation(installation.ID)
}

// WithCentralInstallation fences credential-free durable admission and outcome
// publication against installation revocation after signature authentication.
// accept must not perform provider IO or re-enter this auth Store; a separate
// central vault update is allowed. A valid signature is not a permanent grant.
func (s *Server) WithCentralInstallation(installation Installation, accept func() error) error {
	if accept == nil {
		return ErrDenied
	}
	s.Store.mu.Lock()
	defer s.Store.mu.Unlock()
	if !s.centralInstallation(s.Store.state, installation) {
		return ErrDenied
	}
	return accept()
}

func validCentralRecipient(recipient string) bool {
	return recipient != "" && len(recipient) <= 1024 && strings.TrimSpace(recipient) == recipient &&
		utf8.ValidString(recipient) && !strings.ContainsAny(recipient, "\r\n\x00")
}

// BeginCentral binds one provider consent to one exact authenticated host and
// recipient. The returned transaction is a copy: changing it cannot change the
// mode, recipient or approved scopes held by the broker.
func (s *Server) BeginCentral(installation Installation, start Start, recipient string) (Transaction, error) {
	return s.beginCentral(installation, start, recipient, nil)
}

// BeginCentralWithAdmission adds a private, server-owned admission predicate to
// the normal central consent. It is never serialized or accepted from HTTP.
// admit must be synchronous, thread-safe, side-effect free, and perform no IO or
// auth Store/transaction lock reentry: it can run while either lock is held.
// The accepting vault must also enforce its own current rule before commit.
func (s *Server) BeginCentralWithAdmission(installation Installation, start Start, recipient string, admit func() bool) (Transaction, error) {
	if admit == nil {
		return Transaction{}, ErrDenied
	}
	return s.beginCentral(installation, start, recipient, admit)
}

func centralAdmissionAllowed(admit func() bool) (allowed bool) {
	if admit == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			allowed = false
		}
	}()
	return admit()
}

func (s *Server) beginCentral(installation Installation, start Start, recipient string, admit func() bool) (Transaction, error) {
	if start.Provider == "shopify" || !validCentralRecipient(recipient) || !centralAdmissionAllowed(admit) || !s.centralInstallation(s.Store.snapshot(), installation) {
		return Transaction{}, ErrDenied
	}
	return s.beginTransactionWithAdmission(installation, start, CentralMode, recipient, admit)
}

// CentralTransaction returns only public metadata for one central consent. It
// never returns code, state, PKCE, CSRF or recipient fields, nor consumes consent.
// Transaction and registration locks are acquired separately, so this read does
// not introduce an auth Store/transaction lock inversion.
func (s *Server) CentralTransaction(installation Installation, id, recipient string) (Transaction, error) {
	if !validCentralRecipient(recipient) {
		return Transaction{}, ErrDenied
	}
	s.mu.Lock()
	tx := s.transactions[id]
	if tx == nil || tx.Mode != CentralMode || tx.Installation != installation.ID || tx.recipient != recipient ||
		tx.Provider == "shopify" || !s.now().Before(tx.ExpiresAt) || !centralAdmissionAllowed(tx.centralAdmission) {
		s.mu.Unlock()
		return Transaction{}, ErrDenied
	}
	metadata := Transaction{Mode: tx.Mode, ID: tx.ID, Installation: tx.Installation, Provider: tx.Provider,
		AppID: tx.AppID, Shop: tx.Shop, Scopes: append([]string{}, tx.Scopes...), Status: tx.Status,
		ExpiresAt: tx.ExpiresAt, AuthorizationURL: tx.AuthorizationURL}
	admit := tx.centralAdmission
	s.mu.Unlock()
	p, err := s.centralProvider(installation, metadata.Provider)
	if err != nil || p.AppID != metadata.AppID || !scopeSubset(metadata.Scopes, p.Scopes) || !centralAdmissionAllowed(admit) {
		return Transaction{}, ErrDenied
	}
	return metadata, nil
}

func sameCentralProvider(a, b oauth.Provider) bool {
	return a.ID == b.ID && a.AppID == b.AppID && a.ClientID == b.ClientID && a.SecretFile == b.SecretFile &&
		a.AuthorizationURL == b.AuthorizationURL && a.TokenURL == b.TokenURL && a.RevocationURL == b.RevocationURL &&
		a.RedirectURI == b.RedirectURI && a.PKCE == b.PKCE && sameScopes(a.Scopes, b.Scopes)
}

func (s *Server) centralProvider(installation Installation, provider string) (oauth.Provider, error) {
	p, exists := s.Providers[provider]
	if !exists || provider == "shopify" || p.ID != provider || !s.admittedProviderInstallation(provider, installation.ID) ||
		!s.centralInstallation(s.Store.snapshot(), installation) {
		return oauth.Provider{}, ErrDenied
	}
	return p, nil
}

// CompleteCentral consumes the code atomically and exchanges it only in memory.
// accept must store the token in the separate encrypted vault and must not
// re-enter this auth Store. Its final invocation holds the Store's revocation
// fence, so an installation/grant revocation cannot win between check and save.
// A failed callback consumes the code too; it never authorizes a retry exchange.
func (s *Server) CompleteCentral(ctx context.Context, installation Installation, id, recipient string, accept func(oauth.Token) error) error {
	if ctx == nil || accept == nil || !validCentralRecipient(recipient) {
		return ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	tx := s.transactions[id]
	if tx == nil || tx.Mode != CentralMode || tx.recipient != recipient || tx.Installation != installation.ID ||
		tx.Provider == "shopify" || tx.Status != "ready" || tx.busy || !s.now().Before(tx.ExpiresAt) || !centralAdmissionAllowed(tx.centralAdmission) {
		s.mu.Unlock()
		return ErrDenied
	}
	copy := *tx
	copy.Scopes = append([]string{}, tx.Scopes...)
	p, err := s.centralProvider(installation, copy.Provider)
	if err != nil || p.AppID != copy.AppID || !scopeSubset(copy.Scopes, p.Scopes) {
		s.mu.Unlock()
		return ErrDenied
	}
	tx.busy, tx.Status, tx.code = true, "consumed", ""
	s.mu.Unlock()
	defer func() { s.mu.Lock(); tx.busy = false; tx.verifier = ""; s.mu.Unlock() }()
	ctx, cancel := bounded(ctx)
	defer cancel()
	if !centralAdmissionAllowed(copy.centralAdmission) {
		return ErrDenied
	}
	token, err := s.Engine.Exchange(ctx, p, copy.code, copy.verifier, copy.Shop, copy.Scopes)
	if err != nil {
		return err
	}
	current, err := s.centralProvider(installation, copy.Provider)
	if err != nil || !sameCentralProvider(p, current) || token.AppID != p.AppID ||
		token.AccessToken == "" || !scopeSubset(token.Scopes, copy.Scopes) || ctx.Err() != nil || !centralAdmissionAllowed(copy.centralAdmission) {
		return ErrDenied
	}
	s.mu.Lock()
	stillBound := s.transactions[id] == tx && tx.Mode == CentralMode && tx.recipient == recipient &&
		tx.Installation == installation.ID && tx.Provider == copy.Provider && tx.AppID == p.AppID &&
		tx.Status == "consumed" && tx.busy && sameScopes(tx.Scopes, copy.Scopes) && s.now().Before(tx.ExpiresAt) && centralAdmissionAllowed(tx.centralAdmission)
	s.mu.Unlock()
	if !stillBound {
		return ErrDenied
	}
	// Persist only the established HMAC metadata. State never receives a raw
	// access/refresh token or the authorization code.
	if err = s.Store.update(func(state *State) error {
		if !s.centralInstallation(*state, installation) || !s.admittedProviderInstallation(p.ID, installation.ID) || !centralAdmissionAllowed(copy.centralAdmission) {
			return ErrDenied
		}
		binding := TokenBinding{Installation: installation.ID, Provider: p.ID, AppID: token.AppID,
			ExternalID: token.ExternalID, Scopes: append([]string{}, token.Scopes...), GrantID: randomID()}
		return s.bindTokenInState(state, binding, token, true)
	}); err != nil {
		return err
	}
	return s.WithCentralToken(installation, p.ID, token, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !centralAdmissionAllowed(copy.centralAdmission) {
			return ErrDenied
		}
		return accept(token)
	})
}

// WithCentralToken revalidates a live central credential at durable admission
// and again before publishing an outcome. accept runs under the auth metadata
// revocation fence and must not perform provider IO or re-enter this auth Store;
// a separate vault update is allowed. No token or result is sent over HTTP here.
func (s *Server) WithCentralToken(installation Installation, provider string, token oauth.Token, accept func() error) error {
	if accept == nil || token.AccessToken == "" || token.ExpiresAt != nil && !s.now().Before(*token.ExpiresAt) {
		return ErrDenied
	}
	p, err := s.centralProvider(installation, provider)
	if err != nil || token.AppID != p.AppID || !scopeSubset(token.Scopes, p.Scopes) {
		return ErrDenied
	}
	s.Store.mu.Lock()
	defer s.Store.mu.Unlock()
	state := s.Store.state
	binding, exists := state.TokenBindings[s.tokenHash(p.AppID, provider, token.AccessToken)]
	if !exists || binding.Revoked || binding.Installation != installation.ID || binding.Provider != provider ||
		binding.AppID != p.AppID || binding.ExternalID != token.ExternalID || !sameScopes(binding.Scopes, token.Scopes) ||
		!s.centralInstallation(state, installation) || !s.admittedProviderInstallation(provider, installation.ID) {
		return ErrDenied
	}
	if token.RefreshToken != "" {
		refresh, found := state.TokenBindings[s.tokenHash(p.AppID, provider, token.RefreshToken)]
		if !found || refresh.Revoked || !sameGrant(refresh, binding) || !sameScopes(refresh.Scopes, token.Scopes) {
			return ErrDenied
		}
	}
	return accept()
}

// RefreshCentral is in-process only. It accepts solely a token from an existing
// bound grant, retains the existing account/scope checks and never writes token
// material to auth State or serializes it to an HTTP response.
func (s *Server) RefreshCentral(ctx context.Context, installation Installation, provider string, token oauth.Token) (oauth.Token, error) {
	if ctx == nil || ctx.Err() != nil {
		return oauth.Token{}, ErrDenied
	}
	p, err := s.centralProvider(installation, provider)
	if err != nil || token.AppID != p.AppID || token.RefreshToken == "" || !scopeSubset(token.Scopes, p.Scopes) ||
		token.RefreshExpiresAt != nil && !s.now().Before(*token.RefreshExpiresAt) {
		return oauth.Token{}, ErrDenied
	}
	binding, exists := s.Store.snapshot().TokenBindings[s.tokenHash(p.AppID, p.ID, token.RefreshToken)]
	if !exists || binding.Revoked || binding.Installation != installation.ID || binding.Provider != p.ID ||
		binding.AppID != token.AppID || binding.ExternalID != token.ExternalID || !sameScopes(binding.Scopes, token.Scopes) {
		return oauth.Token{}, ErrDenied
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	refreshed, err := s.Engine.Refresh(ctx, p, token.RefreshToken, token.ExternalID, token.Scopes)
	if err != nil {
		return oauth.Token{}, err
	}
	current, err := s.centralProvider(installation, provider)
	if err != nil || !sameCentralProvider(p, current) || refreshed.AppID != p.AppID ||
		refreshed.ExternalID != binding.ExternalID || refreshed.AccessToken == "" ||
		!scopeSubset(refreshed.Scopes, token.Scopes) || ctx.Err() != nil {
		return oauth.Token{}, ErrDenied
	}
	if err = s.bindRefreshedToken(installation.ID, provider, token.RefreshToken, binding, refreshed); err != nil {
		return oauth.Token{}, err
	}
	// Revalidate after persistence, including revocation concurrent with provider
	// IO. The central vault additionally serializes its own connection revision.
	err = s.WithCentralToken(installation, provider, refreshed, func() error { return ctx.Err() })
	if err != nil {
		return oauth.Token{}, err
	}
	return refreshed, nil
}
