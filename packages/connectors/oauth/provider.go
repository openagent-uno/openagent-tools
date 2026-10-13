// Package oauth implements provider authentication without owning host identities or storage.
package oauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrAuthentication = errors.New("provider authentication failed")

type Provider struct {
	ID               string   `json:"id"`
	AppID            string   `json:"app_id"`
	ClientID         string   `json:"client_id"`
	SecretFile       string   `json:"secret_file"`
	AuthorizationURL string   `json:"authorization_url"`
	TokenURL         string   `json:"token_url"`
	RevocationURL    string   `json:"revocation_url,omitempty"`
	RedirectURI      string   `json:"redirect_uri"`
	Scopes           []string `json:"scopes"`
	PKCE             bool     `json:"pkce"`
}

// Token is only a transient wire value. Persist it exclusively in the consuming host.
type Token struct {
	AccessToken      string     `json:"access_token"`
	RefreshToken     string     `json:"refresh_token,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RefreshExpiresAt *time.Time `json:"refresh_expires_at,omitempty"`
	Scopes           []string   `json:"scopes"`
	AppID            string     `json:"app_id"`
	ExternalID       string     `json:"external_id,omitempty"`
	ShopID           uint64     `json:"shop_id,omitempty"`
	Version          uint64     `json:"version,omitempty"`
	AuthorizedAt     *time.Time `json:"authorized_at,omitempty"`
}

func (Token) String() string   { return "[redacted OAuth token]" }
func (Token) GoString() string { return "[redacted OAuth token]" }

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type Engine struct {
	Client        HTTPDoer
	AllowLoopback bool
}

func (e Engine) target(p Provider, raw, shop string) (*url.URL, error) {
	if strings.Contains(raw, "{shop}") {
		if p.ID != "shopify" || !ValidShop(shop) {
			return nil, ErrAuthentication
		}
		raw = strings.ReplaceAll(raw, "{shop}", shop)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(e.AllowLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))) {
		return nil, ErrAuthentication
	}
	return u, nil
}

// ValidateConfiguration checks local configuration without any provider call.
func (e Engine) ValidateConfiguration(p Provider) error {
	if p.ID == "" || p.AppID == "" || p.ClientID == "" || !approvedScopes(p, p.Scopes) {
		return ErrAuthentication
	}
	if _, err := secret(p); err != nil {
		return err
	}
	for _, target := range []string{p.AuthorizationURL, p.TokenURL} {
		if _, err := e.target(p, target, "validation.myshopify.com"); err != nil {
			return err
		}
	}
	if p.RevocationURL != "" {
		if _, err := e.target(p, p.RevocationURL, "validation.myshopify.com"); err != nil {
			return err
		}
	}
	return nil
}
func ValidShop(shop string) bool {
	if !strings.HasSuffix(shop, ".myshopify.com") {
		return false
	}
	label := strings.TrimSuffix(shop, ".myshopify.com")
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func approvedScopes(p Provider, scopes []string) bool {
	allowed := map[string]bool{}
	for _, s := range p.Scopes {
		allowed[s] = true
	}
	seen := map[string]bool{}
	for _, s := range scopes {
		if !allowed[s] || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func (e Engine) Authorize(p Provider, state, challenge, shop string, scopes []string) (string, error) {
	if state == "" || p.AppID == "" || p.ClientID == "" || !approvedScopes(p, scopes) {
		return "", ErrAuthentication
	}
	u, err := e.target(p, p.AuthorizationURL, shop)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", p.ClientID)
	q.Set("state", state)
	// Postiz uses the callback stored in the registered app, without a request override.
	if p.ID != "postiz" {
		q.Set("redirect_uri", p.RedirectURI)
	}
	if p.ID != "clickup" {
		q.Set("response_type", "code")
	}
	if len(scopes) > 0 && p.ID != "shopify" {
		q.Set("scope", strings.Join(scopes, " "))
	}
	if p.PKCE {
		if challenge == "" {
			return "", ErrAuthentication
		}
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	if strings.HasPrefix(p.ID, "google_") || p.ID == "gmail" {
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func secret(p Provider) (string, error) {
	f, err := os.Open(p.SecretFile)
	if err != nil {
		return "", ErrAuthentication
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return "", ErrAuthentication
	}
	s := strings.TrimSpace(string(b))
	if s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return "", ErrAuthentication
	}
	return s, nil
}
func (e Engine) Exchange(ctx context.Context, p Provider, code, verifier, shop string, scopes []string) (Token, error) {
	if code == "" || len(code) > 16384 || !approvedScopes(p, scopes) {
		return Token{}, ErrAuthentication
	}
	fields := url.Values{"code": {code}, "redirect_uri": {p.RedirectURI}, "grant_type": {"authorization_code"}}
	if p.ID == "clickup" {
		fields.Del("redirect_uri")
		fields.Del("grant_type")
	} else if p.ID == "postiz" {
		fields.Del("redirect_uri")
	}
	if p.PKCE {
		if verifier == "" {
			return Token{}, ErrAuthentication
		}
		fields.Set("code_verifier", verifier)
	}
	if p.ID == "shopify" {
		fields.Set("expiring", "1")
	}
	token, err := e.request(ctx, p, shop, fields, scopes, "")
	if err == nil && p.ID == "shopify" {
		token.ShopID, err = e.shopIdentity(ctx, p, shop, token.AccessToken)
	}
	if err != nil {
		return Token{}, ErrAuthentication
	}
	return token, nil
}

// shopIdentity binds privacy webhooks to a provider-verified numeric shop ID.
// This is an authentication-only identity check, never a general API proxy.
func (e Engine) shopIdentity(ctx context.Context, p Provider, shop, access string) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	target, err := e.target(p, p.TokenURL, shop)
	if err != nil {
		return 0, ErrAuthentication
	}
	target.Path, target.RawQuery = "/admin/api/2026-07/graphql.json", ""
	body := `{"query":"query OpenAgentConsentIdentity { shop { id myshopifyDomain } }"}`
	req, err := http.NewRequestWithContext(ctx, "POST", target.String(), strings.NewReader(body))
	if err != nil {
		return 0, ErrAuthentication
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shopify-Access-Token", access)
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, ErrAuthentication
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	if err != nil || res.StatusCode != 200 || len(data) > 64<<10 {
		return 0, ErrAuthentication
	}
	var result struct {
		Data struct {
			Shop struct {
				ID     string `json:"id"`
				Domain string `json:"myshopifyDomain"`
			} `json:"shop"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(data, &result) != nil || len(result.Errors) != 0 || result.Data.Shop.Domain != shop || !strings.HasPrefix(result.Data.Shop.ID, "gid://shopify/Shop/") {
		return 0, ErrAuthentication
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(result.Data.Shop.ID, "gid://shopify/Shop/"), 10, 64)
	if err != nil || id == 0 {
		return 0, ErrAuthentication
	}
	return id, nil
}
func (e Engine) Refresh(ctx context.Context, p Provider, refresh, shop string, scopes []string) (Token, error) {
	if refresh == "" || len(refresh) > 65536 || !approvedScopes(p, scopes) {
		return Token{}, ErrAuthentication
	}
	return e.request(ctx, p, shop, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, scopes, refresh)
}
func (e Engine) request(ctx context.Context, p Provider, shop string, fields url.Values, scopes []string, previous string) (Token, error) {
	u, err := e.target(p, p.TokenURL, shop)
	if err != nil {
		return Token{}, err
	}
	s, err := secret(p)
	if err != nil {
		return Token{}, err
	}
	fields.Set("client_id", p.ClientID)
	fields.Set("client_secret", s)
	var body io.Reader
	contentType := "application/x-www-form-urlencoded"
	if p.ID == "clickup" || p.ID == "postiz" {
		m := map[string]string{}
		for k, v := range fields {
			m[k] = v[0]
		}
		b, _ := json.Marshal(m)
		body = bytes.NewReader(b)
		contentType = "application/json"
	} else {
		body = strings.NewReader(fields.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return Token{}, ErrAuthentication
	}
	req.Header.Set("Content-Type", contentType)
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	res, err := client.Do(req)
	if err != nil {
		return Token{}, ErrAuthentication
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil || res.StatusCode != 200 {
		return Token{}, ErrAuthentication
	}
	var wire struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int64  `json:"expires_in"`
		RefreshExpiresIn int64  `json:"refresh_token_expires_in"`
		Scope            string `json:"scope"`
		TokenType        string `json:"token_type"`
	}
	if json.Unmarshal(b, &wire) != nil || wire.AccessToken == "" || len(wire.AccessToken) > 65536 || strings.ContainsAny(wire.AccessToken, "\r\n\x00") || len(wire.RefreshToken) > 65536 || strings.ContainsAny(wire.RefreshToken, "\r\n\x00") || wire.ExpiresIn < 0 || wire.ExpiresIn > 315360000 || wire.RefreshExpiresIn < 0 || wire.RefreshExpiresIn > 315360000 {
		return Token{}, ErrAuthentication
	}
	if wire.TokenType != "" && !strings.EqualFold(wire.TokenType, "bearer") {
		return Token{}, ErrAuthentication
	}
	granted := append([]string{}, scopes...)
	if wire.Scope != "" {
		granted = strings.Fields(strings.ReplaceAll(wire.Scope, ",", " "))
	}
	if !approvedScopes(p, granted) || !approvedScopes(Provider{Scopes: scopes}, granted) {
		return Token{}, ErrAuthentication
	}
	if p.ID == "shopify" && (wire.ExpiresIn <= 0 || wire.RefreshToken == "" || wire.RefreshExpiresIn <= 0) {
		return Token{}, ErrAuthentication
	}
	if wire.RefreshToken == "" {
		wire.RefreshToken = previous
	}
	sort.Strings(granted)
	token := Token{AccessToken: wire.AccessToken, RefreshToken: wire.RefreshToken, Scopes: granted, AppID: p.AppID, ExternalID: shop}
	now := time.Now().UTC()
	if wire.ExpiresIn > 0 {
		expiry := now.Add(time.Duration(wire.ExpiresIn) * time.Second)
		token.ExpiresAt = &expiry
	}
	if wire.RefreshExpiresIn > 0 {
		expiry := now.Add(time.Duration(wire.RefreshExpiresIn) * time.Second)
		token.RefreshExpiresAt = &expiry
	}
	return token, nil
}
func (e Engine) Revoke(ctx context.Context, p Provider, token, shop string) error {
	if p.RevocationURL == "" {
		return ErrAuthentication
	}
	u, err := e.target(p, p.RevocationURL, shop)
	if err != nil {
		return err
	}
	fields := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(fields.Encode()))
	if err != nil {
		return ErrAuthentication
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	res, err := client.Do(req)
	if err != nil {
		return ErrAuthentication
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return ErrAuthentication
	}
	return nil
}
func VerifyShopifyCallback(p Provider, q url.Values, now time.Time) error {
	s, err := secret(p)
	if err != nil {
		return err
	}
	given, err := hex.DecodeString(q.Get("hmac"))
	if err != nil || len(given) != 32 {
		return ErrAuthentication
	}
	copy := url.Values{}
	for k, v := range q {
		if len(v) != 1 {
			return ErrAuthentication
		}
		if k != "hmac" && k != "signature" {
			copy[k] = v
		}
	}
	// Shopify supplies Unix seconds, not an RFC3339 date.
	var seconds int64
	if json.Unmarshal([]byte(q.Get("timestamp")), &seconds) != nil || seconds <= 0 || now.Sub(time.Unix(seconds, 0)) > 10*time.Minute || time.Unix(seconds, 0).Sub(now) > time.Minute {
		return ErrAuthentication
	}
	mac := hmac.New(sha256.New, []byte(s))
	mac.Write([]byte(copy.Encode()))
	if !hmac.Equal(given, mac.Sum(nil)) {
		return ErrAuthentication
	}
	return nil
}
func VerifyShopifyWebhook(p Provider, body []byte, signature string) error {
	s, err := secret(p)
	if err != nil {
		return err
	}
	given, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return ErrAuthentication
	}
	mac := hmac.New(sha256.New, []byte(s))
	mac.Write(body)
	if !hmac.Equal(given, mac.Sum(nil)) {
		return ErrAuthentication
	}
	return nil
}
