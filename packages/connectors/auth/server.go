package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

type Transaction struct {
	Mode             string    `json:"mode,omitempty"`
	ID               string    `json:"id"`
	Installation     string    `json:"installation"`
	Provider         string    `json:"provider"`
	AppID            string    `json:"app_id"`
	Shop             string    `json:"shop,omitempty"`
	Scopes           []string  `json:"scopes"`
	Status           string    `json:"status"`
	ExpiresAt        time.Time `json:"expires_at"`
	AuthorizationURL string    `json:"authorization_url"`
	state            string
	verifier         string
	code             string
	csrf             string
	busy             bool
	approved         bool
}
type Start struct {
	Provider string   `json:"provider"`
	Shop     string   `json:"shop,omitempty"`
	Scopes   []string `json:"scopes"`
}
type Rotation struct {
	Token      oauth.Token    `json:"token"`
	Group      string         `json:"group,omitempty"`
	Recipients []Installation `json:"recipients,omitempty"`
}
type Server struct {
	Store        *Store
	Engine       oauth.Engine
	Providers    map[string]oauth.Provider
	Origin       string
	EventKey     []byte
	mu           sync.Mutex
	transactions map[string]*Transaction
	nonces       map[string]time.Time
	rates        map[string][]time.Time
	mail         map[string][]Envelope
	recoveries   map[string][]Recovery
	now          func() time.Time
}

func NewServer(store *Store, engine oauth.Engine, providers []oauth.Provider, origin string, eventKey []byte) (*Server, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Path != "" || u.Fragment != "" || (u.Scheme != "https" && !engine.AllowLoopback) || len(eventKey) != 32 {
		return nil, errors.New("invalid broker configuration")
	}
	s := &Server{Store: store, Engine: engine, Providers: map[string]oauth.Provider{}, Origin: origin, EventKey: append([]byte{}, eventKey...), transactions: map[string]*Transaction{}, nonces: map[string]time.Time{}, rates: map[string][]time.Time{}, mail: map[string][]Envelope{}, recoveries: map[string][]Recovery{}, now: func() time.Time { return time.Now().UTC() }}
	for _, p := range providers {
		if p.ID == "" || p.AppID == "" || p.ClientID == "" || p.SecretFile == "" || p.RedirectURI != origin+"/v1/oauth/"+p.ID+"/callback" || s.Providers[p.ID].ID != "" {
			return nil, errors.New("invalid provider configuration")
		}
		if err = s.Engine.ValidateConfiguration(p); err != nil {
			return nil, err
		}
		if _, err = s.Engine.Authorize(p, "configuration-check", randomID(), "configuration-check.myshopify.com", p.Scopes); err != nil {
			return nil, err
		}
		s.Providers[p.ID] = p
	}
	return s, nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
func decode(body []byte, value any) error {
	reader := json.NewDecoder(strings.NewReader(string(body)))
	reader.DisallowUnknownFields()
	if err := reader.Decode(value); err != nil {
		return ErrDenied
	}
	if reader.Decode(new(any)) != io.EOF {
		return ErrDenied
	}
	return nil
}
func (s *Server) limited(key string, maximum int, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	kept := []time.Time{}
	for _, t := range s.rates[key] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= maximum {
		s.rates[key] = kept
		return true
	}
	s.rates[key] = append(kept, now)
	return false
}
func (s *Server) authenticate(r *http.Request, body []byte) (Installation, error) {
	state := s.Store.snapshot()
	installation, ok := state.Installations[r.Header.Get("X-OpenAgent-Installation")]
	if !ok {
		return Installation{}, ErrDenied
	}
	if err := verifySignature(r, body, installation, s.now()); err != nil {
		return Installation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for n, t := range s.nonces {
		if !now.Before(t) {
			delete(s.nonces, n)
		}
	}
	key := installation.ID + ":" + r.Header.Get("X-OpenAgent-Nonce")
	if _, ok = s.nonces[key]; ok || len(s.nonces) > 100000 {
		return Installation{}, ErrDenied
	}
	s.nonces[key] = now.Add(3 * time.Minute)
	return installation, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		writeJSON(w, 200, map[string]any{"ok": true, "contract": "openagent-connectors/v1", "configured_providers": len(s.Providers)})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/oauth/") && strings.HasSuffix(r.URL.Path, "/callback") && r.Method == "GET" {
		s.callback(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/authorize/") {
		s.authorize(w, r)
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/webhooks/shopify" {
		s.webhook(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		fail(w, 413, "request_too_large")
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/installations" {
		s.register(w, r, body)
		return
	}
	installation, err := s.authenticate(r, body)
	if err != nil {
		fail(w, 401, "invalid_installation_signature")
		return
	}
	if s.limited(installation.ID, 120, time.Minute) {
		fail(w, 429, "rate_limited")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.Method == "POST" && r.URL.Path == "/v1/transactions" {
		s.start(w, installation, body)
		return
	}
	if len(parts) == 3 && parts[0] == "v1" && parts[1] == "transactions" && r.Method == "GET" {
		s.transaction(w, installation, parts[2])
		return
	}
	if len(parts) == 4 && parts[0] == "v1" && parts[1] == "transactions" && parts[3] == "redeem" && r.Method == "POST" {
		s.redeem(w, r, installation, parts[2])
		return
	}
	if r.URL.Path == "/v1/refresh" && r.Method == "POST" {
		s.refresh(w, r, installation, body)
		return
	}
	if r.URL.Path == "/v1/revoke" && r.Method == "POST" {
		s.revoke(w, r, installation, body)
		return
	}
	if len(parts) == 4 && parts[0] == "v1" && parts[1] == "groups" && r.Method == "POST" {
		s.groupAction(w, installation, parts[2], parts[3], body)
		return
	}
	if r.URL.Path == "/v1/mail" && r.Method == "GET" {
		s.receiveMail(w, installation)
		return
	}
	if r.URL.Path == "/v1/mail" && r.Method == "POST" {
		s.sendMail(w, installation, body)
		return
	}
	if r.URL.Path == "/v1/events" && r.Method == "GET" {
		s.events(w, installation)
		return
	}
	if len(parts) == 4 && parts[0] == "v1" && parts[1] == "events" && parts[3] == "ack" && r.Method == "POST" {
		s.ack(w, installation, parts[2])
		return
	}
	fail(w, 404, "not_found")
}
func (s *Server) register(w http.ResponseWriter, r *http.Request, body []byte) {
	var installation Installation
	if decode(body, &installation) != nil || len(installation.Product) < 1 || len(installation.Product) > 80 || len(installation.Name) < 1 || len(installation.Name) > 120 || strings.ContainsAny(installation.Name+installation.Product, "\x00\r\n") {
		fail(w, 400, "invalid_installation")
		return
	}
	key, err := encoding.DecodeString(installation.EncryptionKey)
	if err != nil || len(key) != 32 || verifySignature(r, body, installation, s.now()) != nil {
		fail(w, 401, "invalid_installation_signature")
		return
	}
	if old, exists := s.Store.snapshot().Installations[installation.ID]; exists && old == installation {
		writeJSON(w, 200, installation)
		return
	}
	if s.limited("register:"+strings.Split(r.RemoteAddr, ":")[0], 20, time.Hour) {
		fail(w, 429, "rate_limited")
		return
	}
	err = s.Store.update(func(state *State) error {
		if old, exists := state.Installations[installation.ID]; exists {
			if old != installation {
				return ErrConflict
			}
			return nil
		}
		if len(state.Installations) >= 10000 {
			return ErrConflict
		}
		state.Installations[installation.ID] = installation
		return nil
	})
	if err != nil {
		fail(w, 409, "installation_conflict")
		return
	}
	writeJSON(w, 201, installation)
}
func (s *Server) start(w http.ResponseWriter, installation Installation, body []byte) {
	if s.limited("start:"+installation.ID, 10, time.Minute) {
		fail(w, 429, "rate_limited")
		return
	}
	var start Start
	if decode(body, &start) != nil {
		fail(w, 400, "invalid_start")
		return
	}
	p, ok := s.Providers[start.Provider]
	if !ok {
		fail(w, 503, "provider_not_configured")
		return
	}
	if p.ID == "shopify" && start.Shop != "" && !oauth.ValidShop(start.Shop) || p.ID != "shopify" && start.Shop != "" {
		fail(w, 400, "invalid_provider_account")
		return
	}
	if start.Scopes == nil {
		start.Scopes = append([]string{}, p.Scopes...)
	}
	id, state, verifier := randomID(), randomID(), randomID()
	sum := sha256.Sum256([]byte(verifier))
	validationShop := start.Shop
	if p.ID == "shopify" && validationShop == "" {
		validationShop = "onboarding.myshopify.com"
	}
	if _, err := s.Engine.Authorize(p, state, encoding.EncodeToString(sum[:]), validationShop, start.Scopes); err != nil {
		fail(w, 400, "invalid_scopes")
		return
	}
	tx := &Transaction{ID: id, Installation: installation.ID, Provider: p.ID, AppID: p.AppID, Shop: start.Shop, Scopes: start.Scopes, Status: "pending", ExpiresAt: s.now().Add(10 * time.Minute), AuthorizationURL: s.Origin + "/authorize/" + id, state: state, verifier: verifier}
	s.mu.Lock()
	for key, old := range s.transactions {
		if !s.now().Before(old.ExpiresAt) && !old.busy {
			delete(s.transactions, key)
		}
	}
	if len(s.transactions) >= 10000 {
		s.mu.Unlock()
		fail(w, 503, "busy")
		return
	}
	s.transactions[id] = tx
	s.mu.Unlock()
	writeJSON(w, 201, tx)
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Connect with OpenAgent</title><style>body{font:17px system-ui;max-width:560px;margin:12vh auto;padding:24px;color:#18212b}button,input{padding:12px 22px;border-radius:10px;font:inherit}button{border:0;background:#18212b;color:white}small{color:#566}</style><h1>Connect {{.Provider}}</h1><p>You are authorizing <strong>{{.Name}}</strong> ({{.Product}}) to use the OpenAgent connector.</p><p>Credentials and API data are stored on that server. OpenAgent handles authorization and token renewal.</p>{{if eq .Provider "shopify"}}<p>This server will join your store's connector credential synchronization group.</p>{{end}}<p>Installation: <code>{{.Installation}}</code></p><p>Permissions: {{.Scopes}}</p><p><small>This installation name is supplied by its operator. It is not an endorsement by OpenAgent.</small></p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}">{{if eq .Provider "shopify"}}<p><label>Shopify store <input name="shop" type="text" value="{{.Shop}}" placeholder="your-store.myshopify.com" pattern="[a-z0-9-]+\.myshopify\.com" required></label></p>{{end}}<button>Continue to {{.Provider}}</button></form><p>You can close this window to cancel.</p></html>`))

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/authorize/")
	s.mu.Lock()
	tx := s.transactions[id]
	if tx == nil || !s.now().Before(tx.ExpiresAt) || tx.Status != "pending" {
		s.mu.Unlock()
		fail(w, 410, "authorization_expired")
		return
	}
	copy := *tx
	s.mu.Unlock()
	installation := s.Store.snapshot().Installations[copy.Installation]
	if r.Method == "GET" {
		csrf := randomID()
		s.mu.Lock()
		tx.csrf = csrf
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "oa_connector_consent", Value: csrf, Path: "/authorize/" + id, HttpOnly: true, Secure: !s.Engine.AllowLoopback, SameSite: http.SameSiteLaxMode, MaxAge: 600})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = consentPage.Execute(w, map[string]string{"Name": installation.Name, "Product": installation.Product, "Provider": copy.Provider, "Shop": copy.Shop, "CSRF": csrf, "Installation": installation.ID, "Scopes": strings.Join(copy.Scopes, ", ")})
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed")
		return
	}
	cookie, err := r.Cookie("oa_connector_consent")
	if err != nil || r.Header.Get("Origin") != s.Origin {
		fail(w, 403, "invalid_consent")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil {
		fail(w, 400, "invalid_consent")
		return
	}
	s.mu.Lock()
	csrf := tx.csrf
	tx.csrf = ""
	s.mu.Unlock()
	if csrf == "" || cookie.Value != csrf || r.PostForm.Get("csrf") != csrf {
		fail(w, 403, "invalid_consent")
		return
	}
	if copy.Provider == "shopify" {
		shop := r.PostForm.Get("shop")
		if !oauth.ValidShop(shop) || copy.Shop != "" && copy.Shop != shop {
			fail(w, 400, "invalid_shop")
			return
		}
		copy.Shop = shop
		s.mu.Lock()
		tx.Shop = shop
		s.mu.Unlock()
	}
	p := s.Providers[copy.Provider]
	sum := sha256.Sum256([]byte(copy.verifier))
	target, err := s.Engine.Authorize(p, copy.state, encoding.EncodeToString(sum[:]), copy.Shop, copy.Scopes)
	if err != nil {
		fail(w, 400, "invalid_authorization")
		return
	}
	s.mu.Lock()
	tx.approved = true
	s.mu.Unlock()
	http.Redirect(w, r, target, 303)
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/oauth/"), "/callback")
	q := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	var tx *Transaction
	for _, candidate := range s.transactions {
		if candidate.state == q.Get("state") {
			tx = candidate
			break
		}
	}
	if tx == nil || tx.Provider != provider || !tx.approved || !s.now().Before(tx.ExpiresAt) || tx.Status != "pending" {
		fail(w, 400, "invalid_oauth_state")
		return
	}
	if provider == "shopify" && (q.Get("shop") != tx.Shop || oauth.VerifyShopifyCallback(s.Providers[provider], q, s.now()) != nil) {
		fail(w, 401, "invalid_provider_signature")
		return
	}
	if q.Get("error") != "" {
		tx.Status = "cancelled"
	} else {
		if len(q["code"]) != 1 || q.Get("code") == "" || len(q.Get("code")) > 16384 {
			fail(w, 400, "invalid_authorization_code")
			return
		}
		tx.code = q.Get("code")
		tx.Status = "ready"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>OpenAgent connector</title><h1>Authorization received</h1><p>Return to your application. You can close this window.</p>`)
}
func (s *Server) transaction(w http.ResponseWriter, installation Installation, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx := s.transactions[id]
	if tx == nil || tx.Installation != installation.ID {
		fail(w, 404, "not_found")
		return
	}
	if !s.now().Before(tx.ExpiresAt) {
		fail(w, 410, "authorization_expired")
		return
	}
	writeJSON(w, 200, tx)
}
func groupID(app, shop string) string {
	h := sha256.Sum256([]byte(app + "\x00" + shop))
	return hex.EncodeToString(h[:])
}

// Expiry is persisted separately from a denied acquisition. A process crash
// during provider exchange must never make an older peer look current.
func (s *Server) expireRotation(id string) error {
	return s.Store.update(func(state *State) error {
		g := state.Groups[id]
		if g != nil && g.Pending != "" && !s.now().Before(g.PendingUntil) {
			g.Reconnect = true
			// Keep the checkpoint owner so a server that saved before the broker
			// went offline can commit its current generation after a restart.
			if _, checkpoint := state.Installations[g.Pending]; !checkpoint {
				g.Pending = ""
			}
		}
		return nil
	})
}
func (s *Server) beginRotation(p oauth.Provider, shop, installation, operation string, version uint64, authorize bool) (string, error) {
	id := groupID(p.AppID, shop)
	if err := s.expireRotation(id); err != nil {
		return id, err
	}
	err := s.Store.update(func(state *State) error {
		group := state.Groups[id]
		if group == nil {
			if !authorize {
				return ErrDenied
			}
			group = &Group{ID: id, AppID: p.AppID, Shop: shop, Members: map[string]uint64{}, PrivacyRecipients: map[string]bool{}}
			state.Groups[id] = group
		}
		if group.Pending != "" {
			if s.now().Before(group.PendingUntil) {
				return ErrConflict
			}
			group.Pending = ""
			group.Reconnect = true
		}
		if !authorize {
			if _, ok := group.Members[installation]; !ok || group.Revoked {
				return ErrDenied
			}
			if group.Reconnect {
				return ErrReconnect
			}
			if group.Version != version {
				return ErrConflict
			}
		}
		group.Pending = operation
		group.PendingAuthorization = authorize
		group.PendingUntil = s.now().Add(time.Minute)
		return nil
	})
	return id, err
}
func (s *Server) finishRotation(id, operation, installation string, token *oauth.Token) ([]Installation, error) {
	recipients := []Installation{}
	err := s.Store.update(func(state *State) error {
		group := state.Groups[id]
		if group == nil || group.Pending != operation || !s.now().Before(group.PendingUntil) {
			return ErrConflict
		}
		group.Version++
		group.RefreshHash = s.tokenHash(group.AppID, "shopify", token.RefreshToken)
		group.CredentialDigest = tokenDigest(*token)
		group.Scopes = append([]string{}, token.Scopes...)
		if group.PendingAuthorization {
			group.AuthorizedAt = s.now()
			group.PendingAuthorization = false
		}
		grantTime := group.AuthorizedAt
		token.AuthorizedAt = &grantTime
		token.Version = group.Version
		group.Pending = installation
		group.PendingUntil = s.now().Add(10 * time.Minute)
		group.Reconnect = false
		group.Revoked = false
		group.Members[installation] = 0
		if group.PrivacyRecipients == nil {
			group.PrivacyRecipients = map[string]bool{}
		}
		group.PrivacyRecipients[installation] = true
		for member := range group.Members {
			if member != installation {
				recipients = append(recipients, state.Installations[member])
			}
		}
		return nil
	})
	return recipients, err
}
func (s *Server) failedRotation(id, operation string) {
	_ = s.Store.update(func(state *State) error {
		group := state.Groups[id]
		if group != nil && group.Pending == operation {
			group.Pending = ""
			group.Reconnect = true
		}
		return nil
	})
}
func (s *Server) redeem(w http.ResponseWriter, r *http.Request, installation Installation, id string) {
	s.mu.Lock()
	tx := s.transactions[id]
	if tx == nil || tx.Installation != installation.ID || tx.Status != "ready" || tx.busy || !s.now().Before(tx.ExpiresAt) {
		s.mu.Unlock()
		fail(w, 409, "authorization_not_ready")
		return
	}
	tx.busy = true
	copy := *tx
	tx.code = ""
	tx.Status = "consumed"
	s.mu.Unlock()
	defer func() { s.mu.Lock(); tx.busy = false; tx.verifier = ""; s.mu.Unlock() }()
	p := s.Providers[copy.Provider]
	group := ""
	operation := randomID()
	if p.ID == "shopify" {
		var err error
		group, err = s.beginRotation(p, copy.Shop, installation.ID, operation, 0, true)
		if err != nil {
			fail(w, 409, "rotation_in_progress")
			return
		}
	}
	token, err := s.Engine.Exchange(r.Context(), p, copy.code, copy.verifier, copy.Shop, copy.Scopes)
	if err != nil {
		if group != "" {
			s.failedRotation(group, operation)
		}
		fail(w, 502, "provider_exchange_failed")
		return
	}
	result := Rotation{Token: token, Group: group}
	if group != "" {
		result.Recipients, err = s.finishRotation(group, operation, installation.ID, &result.Token)
		if err != nil {
			fail(w, 409, "rotation_conflict")
			return
		}
	}
	if group == "" {
		if err = s.bindToken(installation.ID, p.ID, token); err != nil {
			fail(w, 500, "token_binding_failed")
			return
		}
	}
	writeJSON(w, 200, result)
}

type Refresh struct {
	Provider     string   `json:"provider"`
	AppID        string   `json:"app_id"`
	RefreshToken string   `json:"refresh_token"`
	Shop         string   `json:"shop,omitempty"`
	Scopes       []string `json:"scopes"`
	Version      uint64   `json:"version,omitempty"`
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, installation Installation, body []byte) {
	var input Refresh
	if decode(body, &input) != nil {
		fail(w, 400, "invalid_refresh")
		return
	}
	p, ok := s.Providers[input.Provider]
	if !ok || input.AppID != p.AppID {
		fail(w, 409, "oauth_app_mismatch")
		return
	}
	id, operation := "", randomID()
	if p.ID == "shopify" {
		group := s.Store.snapshot().Groups[groupID(p.AppID, input.Shop)]
		if group == nil || group.RefreshHash != s.tokenHash(p.AppID, p.ID, input.RefreshToken) || !sameScopes(group.Scopes, input.Scopes) {
			fail(w, 409, "credential_recovery_required")
			return
		}

		var err error
		id, err = s.beginRotation(p, input.Shop, installation.ID, operation, input.Version, false)
		if err != nil {
			fail(w, 409, "credential_recovery_required")
			return
		}
	}
	if p.ID != "shopify" {
		binding, ok := s.Store.snapshot().TokenBindings[s.tokenHash(p.AppID, p.ID, input.RefreshToken)]
		if !ok || binding.Installation != installation.ID || binding.Provider != p.ID || !sameScopes(binding.Scopes, input.Scopes) {
			fail(w, 403, "invalid_token_binding")
			return
		}
	}
	token, err := s.Engine.Refresh(r.Context(), p, input.RefreshToken, input.Shop, input.Scopes)
	if err != nil {
		if id != "" {
			s.failedRotation(id, operation)
		}
		fail(w, 502, "provider_refresh_failed")
		return
	}
	result := Rotation{Token: token, Group: id}
	if id != "" {
		result.Recipients, err = s.finishRotation(id, operation, installation.ID, &result.Token)
		if err != nil {
			fail(w, 409, "rotation_conflict")
			return
		}
	}
	if id == "" {
		if err = s.bindToken(installation.ID, p.ID, token); err != nil {
			fail(w, 500, "token_binding_failed")
			return
		}
	}
	writeJSON(w, 200, result)
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request, installation Installation, body []byte) {
	var input struct {
		Provider string `json:"provider"`
		AppID    string `json:"app_id"`
		Token    string `json:"token"`
		Global   bool   `json:"global"`
	}
	if decode(body, &input) != nil || !input.Global {
		fail(w, 400, "explicit_global_revocation_required")
		return
	}
	p, ok := s.Providers[input.Provider]
	if !ok || p.AppID != input.AppID {
		fail(w, 409, "oauth_app_mismatch")
		return
	}
	binding, ok := s.Store.snapshot().TokenBindings[s.tokenHash(p.AppID, p.ID, input.Token)]
	if !ok || binding.Installation != installation.ID || binding.Provider != p.ID {
		fail(w, 403, "invalid_token_binding")
		return
	}
	if s.Engine.Revoke(r.Context(), p, input.Token, "") != nil {
		fail(w, 502, "provider_revocation_failed")
		return
	}
	writeJSON(w, 200, map[string]bool{"revoked": true})
}
func (s *Server) groupAction(w http.ResponseWriter, installation Installation, id, action string, body []byte) {
	var input struct {
		Version uint64 `json:"version"`
	}
	if decode(body, &input) != nil {
		fail(w, 400, "invalid_group_action")
		return
	}
	if action == "recover" {
		if err := s.expireRotation(id); err != nil {
			fail(w, 500, "metadata_unavailable")
			return
		}
		state := s.Store.snapshot()
		group := state.Groups[id]
		if group == nil || group.Revoked {
			fail(w, 404, "not_found")
			return
		}
		if _, ok := group.Members[installation.ID]; !ok {
			fail(w, 403, "not_a_group_member")
			return
		}
		members := []Installation{}
		for member, v := range group.Members {
			if v == group.Version && member != installation.ID {
				members = append(members, state.Installations[member])
			}
		}
		s.mu.Lock()
		for _, member := range members {
			queue := s.recoveries[member.ID]
			if len(queue) < 1000 {
				s.recoveries[member.ID] = append(queue, Recovery{Group: id, Version: group.Version, Recipient: installation})
			}
		}
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"group": id, "version": group.Version, "reconnect": group.Reconnect || len(members) == 0, "members": members})
		return
	}
	err := s.Store.update(func(state *State) error {
		group := state.Groups[id]
		if group == nil {
			return ErrDenied
		}
		if _, ok := group.Members[installation.ID]; !ok {
			return ErrDenied
		}
		switch action {
		case "commit":
			if input.Version != group.Version || group.Revoked {
				return ErrConflict
			}
			if group.Pending != "" && group.Pending != installation.ID {
				return ErrConflict
			}
			group.Members[installation.ID] = input.Version
			if group.Pending == installation.ID {
				group.Pending = ""
				group.Reconnect = false
			}
		case "disconnect":
			delete(group.Members, installation.ID)
		default:
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		fail(w, 409, "group_conflict")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) sendMail(w http.ResponseWriter, installation Installation, body []byte) {
	var e Envelope
	if decode(body, &e) != nil || e.Sender != installation.ID || !s.now().Before(e.ExpiresAt) || e.ExpiresAt.After(s.now().Add(10*time.Minute)) || len(e.Ciphertext) > 180000 {
		fail(w, 400, "invalid_envelope")
		return
	}
	state := s.Store.snapshot()
	group := state.Groups[e.Group]
	if group == nil || group.Revoked || group.Version != e.Version || group.Members[e.Sender] != e.Version {
		fail(w, 403, "invalid_group_generation")
		return
	}
	if _, ok := group.Members[e.Recipient]; !ok {
		fail(w, 403, "invalid_recipient")
		return
	}
	signature, err := encoding.DecodeString(e.Signature)
	public, _ := encoding.DecodeString(installation.PublicKey)
	if err != nil || !ed25519.Verify(public, e.signed(), signature) {
		fail(w, 403, "invalid_envelope_signature")
		return
	}
	s.mu.Lock()
	queue := []Envelope{}
	for _, old := range s.mail[e.Recipient] {
		if s.now().Before(old.ExpiresAt) && !(old.Group == e.Group && old.Sender == e.Sender) {
			queue = append(queue, old)
		}
	}
	if len(queue) > 1000 {
		s.mu.Unlock()
		fail(w, 429, "mailbox_full")
		return
	}
	s.mail[e.Recipient] = append(queue, e)
	s.mu.Unlock()
	writeJSON(w, 202, map[string]bool{"queued": true})
}
func (s *Server) receiveMail(w http.ResponseWriter, installation Installation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []Envelope{}
	state := s.Store.snapshot()
	publicKeys := map[string]Installation{}
	groups := map[string]GroupInfo{}
	for _, e := range s.mail[installation.ID] {
		group := state.Groups[e.Group]
		if group != nil && !group.Revoked && s.now().Before(e.ExpiresAt) && group.Version == e.Version {
			if _, ok := group.Members[installation.ID]; ok {
				result = append(result, e)
				publicKeys[e.Sender] = state.Installations[e.Sender]
				groups[group.ID] = GroupInfo{ID: group.ID, AppID: group.AppID, Shop: group.Shop, Version: group.Version, Scopes: group.Scopes, AuthorizedAt: group.AuthorizedAt, CredentialDigest: group.CredentialDigest}
			}
		}
	}
	s.mail[installation.ID] = nil
	recoveries := []Recovery{}
	for _, request := range s.recoveries[installation.ID] {
		group := state.Groups[request.Group]
		if group != nil && !group.Revoked && group.Version == request.Version && group.Members[installation.ID] == request.Version {
			if _, ok := group.Members[request.Recipient.ID]; ok {
				recoveries = append(recoveries, request)
			}
		}
	}
	s.recoveries[installation.ID] = nil
	writeJSON(w, 200, Mail{Envelopes: result, Installations: publicKeys, Recoveries: recoveries, Groups: groups})
}
func (s *Server) encryptEvent(body []byte) (string, string, error) {
	block, err := aes.NewCipher(s.EventKey)
	if err != nil {
		return "", "", err
	}
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", "", err
	}
	return encoding.EncodeToString(gcm.Seal(nil, nonce, body, []byte("shopify-webhook-v1"))), encoding.EncodeToString(nonce), nil
}
func (s *Server) decryptEvent(event *Event) (json.RawMessage, error) {
	block, _ := aes.NewCipher(s.EventKey)
	gcm, _ := cipher.NewGCM(block)
	nonce, err := encoding.DecodeString(event.Nonce)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, ErrDenied
	}
	body, err := encoding.DecodeString(event.Ciphertext)
	if err != nil {
		return nil, ErrDenied
	}
	return gcm.Open(nil, nonce, body, []byte("shopify-webhook-v1"))
}
func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Providers["shopify"]
	if !ok {
		fail(w, 503, "provider_not_configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		fail(w, 413, "webhook_too_large")
		return
	}
	if oauth.VerifyShopifyWebhook(p, body, r.Header.Get("X-Shopify-Hmac-Sha256")) != nil {
		fail(w, 401, "invalid_provider_signature")
		return
	}
	topic := r.Header.Get("X-Shopify-Topic")
	if topic != "app/uninstalled" && topic != "customers/data_request" && topic != "customers/redact" && topic != "shop/redact" {
		fail(w, 400, "unsupported_topic")
		return
	}
	shop := r.Header.Get("X-Shopify-Shop-Domain")
	if !oauth.ValidShop(shop) || !json.Valid(body) {
		fail(w, 400, "invalid_webhook")
		return
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil {
		fail(w, 400, "invalid_webhook")
		return
	}
	minimal := map[string]json.RawMessage{}
	for _, key := range []string{"id", "shop_id", "shop_domain", "customer", "orders_requested", "orders_to_redact", "data_request"} {
		if v, ok := payload[key]; ok {
			minimal[key] = v
		}
	}
	for _, key := range []string{"customer", "data_request"} {
		if raw, ok := minimal[key]; ok {
			var nested map[string]json.RawMessage
			if json.Unmarshal(raw, &nested) != nil {
				fail(w, 400, "invalid_webhook")
				return
			}
			reduced := map[string]json.RawMessage{}
			for _, field := range []string{"id", "email"} {
				if key == "data_request" && field == "email" {
					continue
				}
				if value, ok := nested[field]; ok {
					reduced[field] = value
				}
			}
			minimal[key], _ = json.Marshal(reduced)
		}
	}
	data, _ := json.Marshal(minimal)
	minimal["shop_domain"], _ = json.Marshal(shop)
	data, _ = json.Marshal(minimal)
	group := groupID(p.AppID, shop)
	deliveryID := r.Header.Get("X-Shopify-Webhook-Id")
	if deliveryID == "" {
		if !s.Engine.AllowLoopback {
			fail(w, 400, "missing_webhook_id")
			return
		}
		fallback := sha256.Sum256(body)
		deliveryID = hex.EncodeToString(fallback[:])
	}
	if len(deliveryID) > 128 || strings.ContainsAny(deliveryID, "\r\n\x00") {
		fail(w, 400, "invalid_webhook_id")
		return
	}
	occurredAt, parseErr := time.Parse(time.RFC3339Nano, r.Header.Get("X-Shopify-Triggered-At"))
	if parseErr != nil {
		if !s.Engine.AllowLoopback {
			fail(w, 400, "missing_webhook_time")
			return
		}
		occurredAt = s.now()
	}
	if occurredAt.After(s.now().Add(5 * time.Minute)) {
		fail(w, 400, "invalid_webhook_time")
		return
	}
	bodyHash := sha256.Sum256(body)
	hash := sha256.Sum256([]byte(group + "/" + topic + "/" + deliveryID))
	eventID := hex.EncodeToString(hash[:])
	encrypted, nonce, err := s.encryptEvent(data)
	if err != nil {
		fail(w, 500, "event_storage_failed")
		return
	}
	err = s.Store.update(func(state *State) error {
		if previous, exists := state.Events[eventID]; exists {
			if previous.BodySHA256 != hex.EncodeToString(bodyHash[:]) {
				return ErrConflict
			}
			return nil
		}
		g := state.Groups[group]
		if g == nil {
			return nil
		}
		acks := map[string]bool{}
		for member := range g.PrivacyRecipients {
			acks[member] = false
		}
		state.Events[eventID] = &Event{ID: eventID, Group: group, Topic: topic, Ciphertext: encrypted, Nonce: nonce, CreatedAt: s.now(), OccurredAt: occurredAt, BodySHA256: hex.EncodeToString(bodyHash[:]), Acknowledged: acks}
		if (topic == "app/uninstalled" || topic == "shop/redact") && !occurredAt.Before(g.AuthorizedAt) {
			g.Revoked = true
			g.Pending = ""
			g.Reconnect = true
		}
		return nil
	})
	if err != nil {
		fail(w, 500, "event_storage_failed")
		return
	}
	writeJSON(w, 200, map[string]bool{"accepted": true})
}
func (s *Server) events(w http.ResponseWriter, installation Installation) {
	state := s.Store.snapshot()
	result := []map[string]any{}
	for _, event := range state.Events {
		ack, ok := event.Acknowledged[installation.ID]
		if ok && !ack {
			body, err := s.decryptEvent(event)
			if err != nil {
				fail(w, 500, "event_decode_failed")
				return
			}
			result = append(result, map[string]any{"id": event.ID, "group": event.Group, "topic": event.Topic, "payload": body, "created_at": event.CreatedAt, "occurred_at": event.OccurredAt})
			if len(result) >= 100 {
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{"events": result})
}
func (s *Server) ack(w http.ResponseWriter, installation Installation, id string) {
	err := s.Store.update(func(state *State) error {
		event := state.Events[id]
		if event == nil {
			return ErrDenied
		}
		if _, ok := event.Acknowledged[installation.ID]; !ok {
			return ErrDenied
		}
		event.Acknowledged[installation.ID] = true
		all := true
		for _, ack := range event.Acknowledged {
			all = all && ack
		}
		if all {
			event.Ciphertext = ""
			event.Nonce = ""
		}
		return nil
	})
	if err != nil {
		fail(w, 404, "not_found")
		return
	}
	writeJSON(w, 200, map[string]bool{"acknowledged": true})
}

// HTTP requests must have a bounded deadline even when a host supplies a custom client.
func bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 25*time.Second)
}

func (s *Server) tokenHash(app, provider, token string) string {
	mac := hmac.New(sha256.New, s.EventKey)
	mac.Write([]byte(app + "\x00" + provider + "\x00" + token))
	return hex.EncodeToString(mac.Sum(nil))
}
func (s *Server) bindToken(installation, provider string, token oauth.Token) error {
	return s.Store.update(func(state *State) error {
		binding := TokenBinding{Installation: installation, Provider: provider, AppID: token.AppID, Scopes: token.Scopes}
		state.TokenBindings[s.tokenHash(token.AppID, provider, token.AccessToken)] = binding
		if token.RefreshToken != "" {
			state.TokenBindings[s.tokenHash(token.AppID, provider, token.RefreshToken)] = binding
		}
		return nil
	})
}
func sameScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	allowed := map[string]bool{}
	for _, v := range a {
		allowed[v] = true
	}
	for _, v := range b {
		if !allowed[v] {
			return false
		}
		delete(allowed, v)
	}
	return len(allowed) == 0
}
