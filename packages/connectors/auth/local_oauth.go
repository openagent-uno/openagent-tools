package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// LocalOAuth is an optional own-app flow for a trusted desktop server. It binds
// callbacks to loopback only. Shopify own-app multi-server coordination uses a
// separately configured broker; it must never bypass its group lock.
type LocalOAuth struct {
	mu           sync.Mutex
	providers    map[string]oauth.Provider
	transactions map[string]*Transaction
	listeners    []net.Listener
	engine       oauth.Engine
}

func NewLocalOAuth(path string) (*LocalOAuth, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrDenied
	}
	var providers []oauth.Provider
	if json.Unmarshal(data, &providers) != nil || len(providers) == 0 || len(providers) > 16 {
		return nil, ErrDenied
	}
	flow := &LocalOAuth{providers: map[string]oauth.Provider{}, transactions: map[string]*Transaction{}, engine: oauth.Engine{}}
	muxes := map[string]*http.ServeMux{}
	for _, p := range providers {
		u, err := url.Parse(p.RedirectURI)
		if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || p.AppID == "" || p.ClientID == "" || p.ID == "shopify" || flow.providers[p.ID].ID != "" {
			flow.Close()
			return nil, ErrDenied
		}
		switch p.ID {
		case "gmail", "google_drive", "google_analytics", "google_calendar", "outlook_mail", "outlook_calendar", "onedrive", "sharepoint", "clickup", "postiz":
		default:
			flow.Close()
			return nil, ErrDenied
		}
		if _, err = flow.engine.Authorize(p, "validation", randomID(), "", p.Scopes); err != nil {
			flow.Close()
			return nil, err
		}
		if muxes[u.Host] == nil {
			muxes[u.Host] = http.NewServeMux()
		}
		callback := p.ID
		// Duplicate redirect paths in a provider set are rejected instead of panicking.
		if handler, pattern := muxes[u.Host].Handler(&http.Request{URL: u}); pattern != "" && handler != nil {
			flow.Close()
			return nil, ErrDenied
		}
		muxes[u.Host].HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) { flow.callback(w, r, callback) })
		flow.providers[p.ID] = p
	}
	for address, mux := range muxes {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			flow.Close()
			return nil, ErrDenied
		}
		flow.listeners = append(flow.listeners, listener)
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
		go func() { _ = server.Serve(listener) }()
	}
	return flow, nil
}
func (f *LocalOAuth) Close() {
	if f != nil {
		for _, listener := range f.listeners {
			_ = listener.Close()
		}
	}
}
func (f *LocalOAuth) HasProvider(provider string) bool {
	if f == nil {
		return false
	}
	_, ok := f.providers[provider]
	return ok
}
func (f *LocalOAuth) Owns(id string) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.transactions[id] != nil
}
func (f *LocalOAuth) Start(start Start) (Transaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.providers[start.Provider]
	if !ok || start.Shop != "" {
		return Transaction{}, ErrDenied
	}
	now := time.Now().UTC()
	for id, tx := range f.transactions {
		if !now.Before(tx.ExpiresAt) {
			delete(f.transactions, id)
		}
	}
	if len(f.transactions) >= 100 {
		return Transaction{}, ErrConflict
	}
	scopes := start.Scopes
	if scopes == nil {
		scopes = append([]string{}, p.Scopes...)
	}
	id, state, verifier := randomID(), randomID(), randomID()
	challenge := sha256.Sum256([]byte(verifier))
	target, err := f.engine.Authorize(p, state, encoding.EncodeToString(challenge[:]), "", scopes)
	if err != nil {
		return Transaction{}, err
	}
	tx := &Transaction{ID: id, Provider: p.ID, AppID: p.AppID, Scopes: scopes, Status: "pending", ExpiresAt: now.Add(10 * time.Minute), AuthorizationURL: target, Mode: "own-app", state: state, verifier: verifier}
	f.transactions[id] = tx
	return *tx, nil
}
func (f *LocalOAuth) Transaction(id string) (Transaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tx := f.transactions[id]
	if tx == nil || !time.Now().Before(tx.ExpiresAt) {
		return Transaction{}, ErrDenied
	}
	return *tx, nil
}
func (f *LocalOAuth) callback(w http.ResponseWriter, r *http.Request, provider string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method != "GET" {
		http.Error(w, "Invalid callback", 405)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	for _, v := range q {
		if len(v) != 1 {
			http.Error(w, "Invalid callback", 400)
			return
		}
	}
	for _, tx := range f.transactions {
		if tx.Provider != provider || tx.state != q.Get("state") || tx.Status != "pending" || !time.Now().Before(tx.ExpiresAt) {
			continue
		}
		if q.Get("error") != "" {
			tx.Status = "cancelled"
		} else if q.Get("code") != "" && len(q.Get("code")) <= 16384 {
			tx.Status = "ready"
			tx.code = q.Get("code")
		} else {
			http.Error(w, "Invalid callback", 400)
			return
		}
		_, _ = w.Write([]byte("Return to OpenAgent. You can close this window."))
		return
	}
	http.Error(w, "Invalid callback", 400)
}
func (f *LocalOAuth) Redeem(ctx context.Context, id string) (Rotation, error) {
	f.mu.Lock()
	tx := f.transactions[id]
	if tx == nil || tx.Status != "ready" || !time.Now().Before(tx.ExpiresAt) {
		f.mu.Unlock()
		return Rotation{}, ErrDenied
	}
	copy := *tx
	tx.Status = "consumed"
	tx.code = ""
	tx.verifier = ""
	f.mu.Unlock()
	token, err := f.engine.Exchange(ctx, f.providers[copy.Provider], copy.code, copy.verifier, "", copy.Scopes)
	return Rotation{Token: token}, err
}
func (f *LocalOAuth) Refresh(ctx context.Context, provider string, token oauth.Token) (Rotation, error) {
	p, ok := f.providers[provider]
	if !ok || token.AppID != p.AppID {
		return Rotation{}, ErrDenied
	}
	next, err := f.engine.Refresh(ctx, p, token.RefreshToken, token.ExternalID, token.Scopes)
	return Rotation{Token: next}, err
}
func (f *LocalOAuth) Issued(provider, app string) bool {
	if f == nil {
		return false
	}
	p, ok := f.providers[provider]
	return ok && p.AppID == app
}
