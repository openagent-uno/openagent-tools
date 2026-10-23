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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrAuthentication = errors.New("provider authentication failed")

const GoogleCalendarListScope = "https://www.googleapis.com/auth/calendar.calendarlist.readonly"
const GoogleCalendarEventsScope = "https://www.googleapis.com/auth/calendar.events"
const MicrosoftGraphScopePrefix = "https://graph.microsoft.com/"

func microsoftProvider(id string) bool {
	return id == "outlook_mail" || id == "outlook_calendar" || id == "onedrive" || id == "sharepoint"
}
func calendarOrMicrosoft(id string) bool { return id == "google_calendar" || microsoftProvider(id) }

// Only Microsoft Graph's documented resource-prefix form and exact short names
// are equivalent. Other providers retain exact scope matching unchanged.
func microsoftScopes(scopes []string) ([]string, bool) {
	allowed := map[string]bool{"offline_access": true, "User.Read": true, "Mail.ReadBasic": true, "Mail.Read": true, "Mail.ReadWrite": true, "Mail.Send": true, "Calendars.ReadBasic": true, "Calendars.Read": true, "Calendars.ReadWrite": true, "Files.Read": true, "Files.Read.All": true, "Files.ReadWrite": true, "Files.ReadWrite.All": true, "Sites.Read.All": true, "Sites.ReadWrite.All": true}
	seen := map[string]bool{}
	result := make([]string, 0, len(scopes))
	if len(scopes) > 16 {
		return nil, false
	}
	for _, raw := range scopes {
		scope := strings.TrimPrefix(raw, MicrosoftGraphScopePrefix)
		if !allowed[scope] || seen[scope] || (scope == "offline_access" && raw != scope) {
			return nil, false
		}
		seen[scope] = true
		result = append(result, scope)
	}
	return result, true
}

func microsoftRequestScopes(scopes []string) (string, bool) {
	canonical, ok := microsoftScopes(scopes)
	if !ok {
		return "", false
	}
	for i, scope := range canonical {
		if scope != "offline_access" {
			canonical[i] = MicrosoftGraphScopePrefix + scope
		}
	}
	return strings.Join(canonical, " "), true
}

func hasOAuthScope(scopes []string, wanted string) bool {
	for _, scope := range scopes {
		if scope == wanted {
			return true
		}
	}
	return false
}

// API-only flows use fixed global-cloud endpoints. Loopback remains exclusively
// an explicit fixture option, never a caller-supplied production authority.
func (e Engine) calendarMicrosoftTargets(p Provider) bool {
	if !calendarOrMicrosoft(p.ID) {
		return true
	}
	authorize, token := "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token"
	if microsoftProvider(p.ID) {
		authorize, token = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	}
	for _, pair := range [][2]string{{p.AuthorizationURL, authorize}, {p.TokenURL, token}} {
		raw, expected := pair[0], pair[1]
		u, err := e.target(p, raw, "")
		if err != nil || u.RawQuery != "" || u.Opaque != "" {
			return false
		}
		fixture := e.AllowLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")
		if !fixture && raw != expected {
			return false
		}
	}
	if microsoftProvider(p.ID) {
		return p.RevocationURL == ""
	}
	return p.RevocationURL == "" || p.RevocationURL == "https://oauth2.googleapis.com/revoke"
}

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
	// Notion capabilities are configured on the registered connection and the
	// user selects pages during consent; they are not OAuth scope strings.
	if !validWorkspaceProtocol(p, p.Scopes) || !e.calendarMicrosoftTargets(p) {
		return ErrAuthentication
	}
	if microsoftProvider(p.ID) {
		scopes, _ := microsoftScopes(p.Scopes)
		if !hasOAuthScope(scopes, "offline_access") {
			return ErrAuthentication
		}
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
	if microsoftProvider(p.ID) {
		configured, ok := microsoftScopes(p.Scopes)
		if !ok {
			return false
		}
		requested, ok := microsoftScopes(scopes)
		if !ok {
			return false
		}
		return approvedScopes(Provider{Scopes: configured}, requested)
	}
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
	if calendarOrMicrosoft(p.ID) && shop != "" {
		return "", ErrAuthentication
	}
	if state == "" || p.AppID == "" || p.ClientID == "" || !approvedScopes(p, scopes) {
		return "", ErrAuthentication
	}
	if !validWorkspaceProtocol(p, scopes) || !e.calendarMicrosoftTargets(p) {
		return "", ErrAuthentication
	}
	u, err := e.target(p, p.AuthorizationURL, shop)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if microsoftProvider(p.ID) {
		canonical, _ := microsoftScopes(scopes)
		if !hasOAuthScope(canonical, "offline_access") {
			return "", ErrAuthentication
		}
	}
	q.Set("client_id", p.ClientID)
	q.Set("state", state)
	// Postiz uses the callback stored in the registered app, without a request override.
	if p.ID != "postiz" {
		q.Set("redirect_uri", p.RedirectURI)
	}
	if p.ID != "clickup" && p.ID != "slack_import" {
		q.Set("response_type", "code")
	}
	if p.ID == "notion" {
		q.Set("owner", "user")
	}
	if p.ID == "atlassian" {
		q.Set("audience", "api.atlassian.com")
		q.Set("prompt", "consent")
	}
	if p.ID == "slack_import" {
		// This connector acts only as the consenting user, never as a bot.
		q.Del("scope")
		q.Del("response_type")
		q.Del("code_challenge")
		q.Del("code_challenge_method")
		q.Set("user_scope", strings.Join(scopes, ","))
	}
	if len(scopes) > 0 && p.ID != "shopify" && p.ID != "slack_import" {
		q.Set("scope", strings.Join(scopes, " "))
	}
	if microsoftProvider(p.ID) {
		wire, ok := microsoftRequestScopes(scopes)
		if !ok {
			return "", ErrAuthentication
		}
		q.Set("scope", wire)
		q.Set("response_mode", "query")
	}
	if p.PKCE {
		if challenge == "" {
			return "", ErrAuthentication
		}
		if calendarOrMicrosoft(p.ID) {
			raw, err := base64.RawURLEncoding.DecodeString(challenge)
			if err != nil || len(raw) != 32 || len(challenge) != 43 {
				return "", ErrAuthentication
			}
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
	failure := func(reason string) error {
		if microsoftProvider(p.ID) {
			return microsoftExchangeFailure("preflight", reason, "none")
		}
		if p.ID == "postiz" {
			return postizExchangeFailure("preflight", reason, "none", 0)
		}
		return ErrAuthentication
	}
	if code == "" || len(code) > 16384 || !approvedScopes(p, scopes) {
		return Token{}, failure("code_or_scopes")
	}
	fields := url.Values{"code": {code}, "redirect_uri": {p.RedirectURI}, "grant_type": {"authorization_code"}}
	if calendarOrMicrosoft(p.ID) && (shop != "" || !validPKCEVerifier(verifier)) {
		return Token{}, failure("request_context")
	}
	if microsoftProvider(p.ID) {
		canonical, ok := microsoftScopes(scopes)
		wire, wireOK := microsoftRequestScopes(scopes)
		if !ok || !wireOK || !hasOAuthScope(canonical, "offline_access") {
			return Token{}, failure("requested_scopes")
		}
		fields.Set("scope", wire)
	}
	if p.ID == "clickup" {
		fields.Del("redirect_uri")
		fields.Del("grant_type")
	} else if p.ID == "postiz" {
		fields.Del("redirect_uri")
	} else if p.ID == "github" || p.ID == "slack_import" {
		fields.Del("grant_type")
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
		var rejection *MicrosoftExchangeError
		if microsoftProvider(p.ID) && errors.As(err, &rejection) {
			return Token{}, rejection
		}
		var postizRejection *PostizExchangeError
		if p.ID == "postiz" && errors.As(err, &postizRejection) {
			return Token{}, postizRejection
		}
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
	if calendarOrMicrosoft(p.ID) && !validAPIOnlyToken(refresh) {
		return Token{}, ErrAuthentication
	}
	if refresh == "" || len(refresh) > 65536 {
		if p.ID == "slack_import" {
			return Token{}, slackRefreshFailure("preflight", "refresh_invalid", "none")
		}
		return Token{}, ErrAuthentication
	}
	// Old host-held Gmail grants retain their original registration and exact
	// bound scopes. This exception applies only to refresh, never new consent or
	// code exchange; request still rejects any provider-returned scope expansion.
	if p.ID == "gmail" && !approvedScopes(p, scopes) && len(scopes) > 0 && len(p.Scopes) == 2 &&
		approvedScopes(Provider{Scopes: []string{"https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.compose"}}, p.Scopes) &&
		approvedScopes(Provider{Scopes: []string{"https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.send"}}, scopes) {
		p.Scopes = append(append([]string{}, p.Scopes...), scopes...)
	}
	if !approvedScopes(p, scopes) {
		if p.ID == "slack_import" {
			return Token{}, slackRefreshFailure("preflight", "scope_config", "none")
		}
		return Token{}, ErrAuthentication
	}
	// Slack's refresh response may omit team. Only the host-held original
	// provider team binding may supply it; never adopt a refresh caller's hint.
	if p.ID == "slack_import" && !validSlackTeam(shop) {
		return Token{}, slackRefreshFailure("preflight", "team_invalid", "none")
	}
	if microsoftProvider(p.ID) && !validMicrosoftAccountID(shop) {
		return Token{}, ErrAuthentication
	}
	return e.request(ctx, p, shop, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, scopes, refresh)
}
func (e Engine) request(ctx context.Context, p Provider, shop string, fields url.Values, scopes []string, previous string) (Token, error) {
	postizStatus, postizCode := 0, "none"
	failure := func(stage, reason string) error {
		if p.ID == "slack_import" && fields.Get("grant_type") == "refresh_token" {
			return slackRefreshFailure(stage, reason, "none")
		}
		if microsoftProvider(p.ID) && fields.Get("grant_type") == "authorization_code" {
			return microsoftExchangeFailure(stage, reason, "none")
		}
		if p.ID == "postiz" && fields.Get("grant_type") == "authorization_code" {
			return postizExchangeFailure(stage, reason, postizCode, postizStatus)
		}
		return ErrAuthentication
	}
	if !validWorkspaceProtocol(p, scopes) || !e.calendarMicrosoftTargets(p) {
		return Token{}, failure("preflight", "protocol")
	}
	if calendarOrMicrosoft(p.ID) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	if microsoftProvider(p.ID) && fields.Get("grant_type") == "refresh_token" {
		wire, ok := microsoftRequestScopes(scopes)
		if !ok {
			return Token{}, ErrAuthentication
		}
		fields.Set("scope", wire)
	}
	u, err := e.target(p, p.TokenURL, shop)
	if err != nil {
		if (p.ID == "slack_import" && previous != "") || (microsoftProvider(p.ID) && previous == "") || (p.ID == "postiz" && fields.Get("grant_type") == "authorization_code") {
			return Token{}, failure("request", "target")
		}
		return Token{}, err
	}
	s, err := secret(p)
	if err != nil {
		if (p.ID == "slack_import" && previous != "") || (microsoftProvider(p.ID) && previous == "") || (p.ID == "postiz" && fields.Get("grant_type") == "authorization_code") {
			return Token{}, failure("request", "secret")
		}
		return Token{}, err
	}
	fields.Set("client_id", p.ClientID)
	fields.Set("client_secret", s)
	if p.ID == "notion" {
		fields.Del("client_id")
		fields.Del("client_secret")
	}
	var body io.Reader
	contentType := "application/x-www-form-urlencoded"
	if p.ID == "clickup" || p.ID == "postiz" || p.ID == "notion" || p.ID == "atlassian" {
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
		return Token{}, failure("request", "request_invalid")
	}
	req.Header.Set("Content-Type", contentType)
	// GitHub defaults to a form-encoded response unless JSON is requested.
	req.Header.Set("Accept", "application/json")
	if p.ID == "notion" {
		req.SetBasicAuth(p.ClientID, s)
		req.Header.Set("Notion-Version", "2026-03-11")
	}
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if calendarOrMicrosoft(p.ID) {
		client = noRedirectOAuthClient(client)
	}
	res, err := client.Do(req)
	if err != nil || res == nil || res.Body == nil {
		if res != nil && res.Body != nil {
			_ = res.Body.Close()
		}
		return Token{}, failure("request", "network")
	}
	defer res.Body.Close()
	postizStatus = res.StatusCode
	b, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil {
		return Token{}, failure("response", "response_read")
	}
	if p.ID == "postiz" && fields.Get("grant_type") == "authorization_code" {
		postizCode = postizExchangeProviderCode(b)
	}
	if res.StatusCode != 200 {
		if microsoftProvider(p.ID) && fields.Get("grant_type") == "authorization_code" {
			return Token{}, microsoftExchangeFailure("response", "http_status", microsoftExchangeProviderCode(b))
		}
		return Token{}, failure("response", "http_status")
	}
	if len(b) > 1<<20 {
		return Token{}, failure("response", "response_size")
	}
	if calendarOrMicrosoft(p.ID) && !validAPIOnlyOAuthJSON(b) {
		return Token{}, failure("response", "json")
	}
	type tokenFields struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int64  `json:"expires_in"`
		RefreshExpiresIn int64  `json:"refresh_token_expires_in"`
		Scope            string `json:"scope"`
		TokenType        string `json:"token_type"`
	}
	var response struct {
		tokenFields
		OK         *bool           `json:"ok"`
		Error      json.RawMessage `json:"error"`
		AuthedUser *tokenFields    `json:"authed_user"`
		Team       *struct {
			ID string `json:"id"`
		} `json:"team"`
		IsEnterpriseInstall bool `json:"is_enterprise_install"`
	}
	if json.Unmarshal(b, &response) != nil {
		return Token{}, failure("response", "json")
	}
	if calendarOrMicrosoft(p.ID) && len(response.Error) != 0 {
		if microsoftProvider(p.ID) && fields.Get("grant_type") == "authorization_code" {
			return Token{}, microsoftExchangeFailure("response", "provider_error", microsoftExchangeProviderCode(b))
		}
		return Token{}, ErrAuthentication
	}
	wire := response.tokenFields
	externalID := shop
	if p.ID == "slack_import" {
		if response.OK == nil {
			return Token{}, failure("response", "ok_missing")
		}
		if !*response.OK {
			if previous != "" {
				var code string
				_ = json.Unmarshal(response.Error, &code)
				return Token{}, slackRefreshFailure("response", "ok_false", code)
			}
			return Token{}, ErrAuthentication
		}
		if response.IsEnterpriseInstall {
			return Token{}, failure("token", "enterprise")
		}
		if previous == "" {
			if response.AuthedUser == nil || response.Team == nil || !validSlackTeam(response.Team.ID) {
				return Token{}, ErrAuthentication
			}
			wire = *response.AuthedUser
			externalID = response.Team.ID
			if shop != "" && shop != externalID {
				return Token{}, ErrAuthentication
			}
		} else {
			if response.AuthedUser != nil {
				return Token{}, failure("token", "unexpected_nested")
			}
			if wire.RefreshToken == "" {
				return Token{}, failure("token", "refresh_missing")
			}
			if wire.ExpiresIn <= 0 {
				return Token{}, failure("token", "expiry_invalid")
			}
			if response.Team != nil && !validSlackTeam(response.Team.ID) {
				return Token{}, failure("token", "team_invalid")
			}
			if response.Team != nil && response.Team.ID != shop {
				return Token{}, failure("token", "team_mismatch")
			}
		}
		if wire.TokenType != "user" {
			return Token{}, failure("token", "token_type")
		}
		// Slack rotation may omit scope; only refresh can retain the previously
		// approved scopes supplied by the host (and verified by broker binding).
		if wire.Scope == "" && previous == "" {
			return Token{}, failure("token", "scope_missing")
		}
		if !strings.HasPrefix(wire.AccessToken, "xoxp-") && !strings.HasPrefix(wire.AccessToken, "xoxe.xoxp-") {
			return Token{}, failure("token", "token_prefix")
		}
		if (wire.ExpiresIn > 0) != (wire.RefreshToken != "") {
			return Token{}, failure("token", "rotation_shape")
		}
	}
	if wire.AccessToken == "" || len(wire.AccessToken) > 65536 || strings.ContainsAny(wire.AccessToken, "\r\n\x00") || len(wire.RefreshToken) > 65536 || strings.ContainsAny(wire.RefreshToken, "\r\n\x00") || wire.ExpiresIn < 0 || wire.ExpiresIn > 315360000 || wire.RefreshExpiresIn < 0 || wire.RefreshExpiresIn > 315360000 {
		return Token{}, failure("token", "token_bounds")
	}
	if calendarOrMicrosoft(p.ID) && (!validAPIOnlyToken(wire.AccessToken) || (wire.RefreshToken != "" && !validAPIOnlyToken(wire.RefreshToken))) {
		return Token{}, failure("token", "token_bounds")
	}
	if p.ID != "slack_import" && wire.TokenType != "" && !strings.EqualFold(wire.TokenType, "bearer") {
		return Token{}, failure("token", "token_type")
	}
	if microsoftProvider(p.ID) {
		if !strings.EqualFold(wire.TokenType, "bearer") {
			return Token{}, failure("token", "token_type")
		}
		if wire.ExpiresIn <= 0 {
			return Token{}, failure("token", "expiry_invalid")
		}
		if previous == "" && wire.RefreshToken == "" {
			return Token{}, failure("token", "refresh_missing")
		}
		if previous == "" && wire.Scope == "" {
			return Token{}, failure("token", "scope_missing")
		}
	}
	granted := append([]string{}, scopes...)
	if wire.Scope != "" {
		granted = strings.Fields(strings.ReplaceAll(wire.Scope, ",", " "))
	}
	if p.ID == "postiz" && wire.Scope != "" {
		// Static Postiz apps grant the fixed app-wide MCP bundle. They have no
		// granular request scopes; preserve that existing host token contract.
		if len(scopes) != 0 || len(p.Scopes) != 0 || strings.Contains(wire.Scope, ",") || len(granted) != 2 ||
			!(granted[0] == "mcp:read" && granted[1] == "mcp:write" || granted[0] == "mcp:write" && granted[1] == "mcp:read") {
			return Token{}, failure("scopes", "scope_config")
		}
		granted = []string{}
	}
	if microsoftProvider(p.ID) {
		if strings.Contains(wire.Scope, ",") {
			return Token{}, failure("scopes", "scope_format")
		}
		var ok bool
		granted, ok = microsoftScopes(granted)
		requested, requestedOK := microsoftScopes(scopes)
		if !ok || !requestedOK {
			return Token{}, failure("scopes", "scope_format")
		}
		if !hasOAuthScope(granted, "User.Read") {
			return Token{}, failure("scopes", "scope_identity")
		}
		// offline_access grants renewal rather than a Graph API operation and is
		// commonly absent from response.scope. Retain it only from the bound
		// request, with a returned or previously-held refresh credential.
		if hasOAuthScope(requested, "offline_access") && !hasOAuthScope(granted, "offline_access") && (wire.RefreshToken != "" || previous != "") {
			granted = append(granted, "offline_access")
		}
	}
	if p.ID == "slack_import" && previous != "" {
		// Slack may report its implicit identify permission during rotation.
		// Keep the effective grant bounded to the previously approved scopes.
		seen := map[string]bool{}
		for _, scope := range granted {
			if seen[scope] {
				return Token{}, failure("scopes", "scope_config")
			}
			seen[scope] = true
		}
		requestedIdentify := false
		for _, scope := range scopes {
			requestedIdentify = requestedIdentify || scope == "identify"
		}
		if !requestedIdentify {
			filtered := make([]string, 0, len(granted))
			for _, scope := range granted {
				if scope != "identify" {
					filtered = append(filtered, scope)
				}
			}
			granted = filtered
		}
	}
	if !approvedScopes(p, granted) {
		return Token{}, failure("scopes", "scope_config")
	}
	if !approvedScopes(Provider{ID: p.ID, Scopes: scopes}, granted) {
		return Token{}, failure("scopes", "scope_subset")
	}
	if p.ID == "shopify" && (wire.ExpiresIn <= 0 || wire.RefreshToken == "" || wire.RefreshExpiresIn <= 0) {
		return Token{}, ErrAuthentication
	}
	if wire.RefreshToken == "" {
		wire.RefreshToken = previous
	}
	if microsoftProvider(p.ID) {
		verified, err := e.microsoftAccountIdentity(ctx, wire.AccessToken)
		if err != nil || (shop != "" && verified != shop) {
			return Token{}, failure("identity", "account_verification")
		}
		externalID = verified
	}
	sort.Strings(granted)
	token := Token{AccessToken: wire.AccessToken, RefreshToken: wire.RefreshToken, Scopes: granted, AppID: p.AppID, ExternalID: externalID}
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
	if p.RevocationURL == "" || token == "" || len(token) > 65536 || strings.ContainsAny(token, "\r\n\x00") {
		return ErrAuthentication
	}
	u, err := e.target(p, p.RevocationURL, shop)
	if err != nil {
		return err
	}
	method, contentType := http.MethodPost, "application/x-www-form-urlencoded"
	var body io.Reader = strings.NewReader(url.Values{"token": {token}}.Encode())
	clientSecret := ""
	if p.ID == "notion" || p.ID == "github" {
		// Provider-specific endpoints, not an arbitrary authenticated REST call.
		expectedHost, expectedPath := "api.notion.com", "/v1/oauth/revoke"
		field := "token"
		if p.ID == "github" {
			if p.ClientID == "" || len(p.ClientID) > 128 || strings.ContainsAny(p.ClientID, "/?#%\\\r\n\x00") {
				return ErrAuthentication
			}
			expectedHost, expectedPath = "api.github.com", "/applications/"+p.ClientID+"/token"
			method, field = http.MethodDelete, "access_token"
		}
		loopback := e.AllowLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")
		if (!loopback && u.Host != expectedHost) || u.EscapedPath() != expectedPath || u.RawQuery != "" {
			return ErrAuthentication
		}
		clientSecret, err = secret(p)
		if err != nil {
			return err
		}
		encoded, _ := json.Marshal(map[string]string{field: token})
		body, contentType = bytes.NewReader(encoded), "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return ErrAuthentication
	}
	req.Header.Set("Content-Type", contentType)
	if clientSecret != "" {
		req.SetBasicAuth(p.ClientID, clientSecret)
		req.Header.Set("Accept", "application/json")
		if p.ID == "notion" {
			req.Header.Set("Notion-Version", "2026-03-11")
		} else {
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
		}
	}
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	res, err := client.Do(req)
	if err != nil {
		return ErrAuthentication
	}
	defer res.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	expectedStatus := http.StatusOK
	if p.ID == "github" {
		expectedStatus = http.StatusNoContent
	}
	if readErr != nil || len(data) > 1<<20 || res.StatusCode != expectedStatus {
		return ErrAuthentication
	}
	return nil
}

// These branches implement the documented confidential flow only. Enabling
// Slack PKCE requires app-side configuration and is deliberately not guessed.
func validWorkspaceProtocol(p Provider, scopes []string) bool {
	if p.ID == "google_calendar" {
		return p.PKCE && len(scopes) > 0 && approvedScopes(Provider{Scopes: []string{GoogleCalendarListScope, GoogleCalendarEventsScope}}, scopes)
	}
	if microsoftProvider(p.ID) {
		canonical, ok := microsoftScopes(scopes)
		if !ok || !p.PKCE || !hasOAuthScope(canonical, "User.Read") {
			return false
		}
		found := false
		for _, scope := range canonical {
			if scope == "offline_access" || scope == "User.Read" {
				continue
			}
			prefix := "Mail."
			if p.ID == "outlook_calendar" {
				prefix = "Calendars."
			}
			if p.ID == "onedrive" || p.ID == "sharepoint" {
				allowed := map[string]bool{"Files.Read": true, "Files.Read.All": true, "Files.ReadWrite": true, "Files.ReadWrite.All": true, "Sites.Read.All": true, "Sites.ReadWrite.All": true}
				if p.ID == "sharepoint" {
					allowed = map[string]bool{"Sites.Read.All": true, "Sites.ReadWrite.All": true}
				}
				if !allowed[scope] {
					return false
				}
			} else if !strings.HasPrefix(scope, prefix) {
				return false
			}
			found = true
		}
		return found
	}
	if p.ID == "notion" {
		return len(scopes) == 0 && !p.PKCE
	}
	if p.ID == "atlassian" || p.ID == "slack_import" {
		return !p.PKCE && len(scopes) > 0
	}
	return true
}

func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}

func validAPIOnlyToken(value string) bool {
	if len(value) == 0 || len(value) > 65536 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func noRedirectOAuthClient(client HTTPDoer) HTTPDoer {
	if c, ok := client.(*http.Client); ok {
		copy := *c
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		copy.Jar = nil
		return &copy
	}
	return client
}

// The new API-only flows reject duplicate keys, invalid UTF8 and excessive
// structure before interpreting authentication fields. Existing providers are
// unchanged; arbitrary provider error messages never leave the engine.
func validAPIOnlyOAuthJSON(raw []byte) bool {
	if !utf8.Valid(raw) || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var visit func(int) bool
	visit = func(depth int) bool {
		nodes++
		if depth > 16 || nodes > 8192 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		if t == json.Delim('{') {
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				key, ok := k.(string)
				if err != nil || !ok || seen[key] {
					return false
				}
				seen[key] = true
				if !visit(depth + 1) {
					return false
				}
			}
			t, err = d.Token()
			return err == nil && t == json.Delim('}')
		}
		if t == json.Delim('[') {
			for d.More() {
				if !visit(depth + 1) {
					return false
				}
			}
			t, err = d.Token()
			return err == nil && t == json.Delim(']')
		}
		_, delimiter := t.(json.Delim)
		return !delimiter
	}
	if !visit(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

var microsoftAccountIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func validMicrosoftAccountID(id string) bool { return microsoftAccountIDPattern.MatchString(id) }

// Graph itself verifies the delegated access token. /me is never derived from a
// callback hint, JWT body, connection configuration or caller-selected tenant.
// User.Read is required. An account switch on refresh is rejected before the
// consuming product can persist the replacement credentials.
func (e Engine) microsoftAccountIdentity(ctx context.Context, access string) (string, error) {
	if !validAPIOnlyToken(access) {
		return "", ErrAuthentication
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me?$select=id", nil)
	if err != nil {
		return "", ErrAuthentication
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	res, err := noRedirectOAuthClient(client).Do(req)
	if err != nil || res == nil || res.Body == nil {
		if res != nil && res.Body != nil {
			_ = res.Body.Close()
		}
		return "", ErrAuthentication
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	if err != nil || res.StatusCode != http.StatusOK || len(raw) > 64<<10 || !validAPIOnlyOAuthJSON(raw) {
		return "", ErrAuthentication
	}
	var identity struct {
		ID    string          `json:"id"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &identity) != nil || !validMicrosoftAccountID(identity.ID) || len(identity.Error) != 0 {
		return "", ErrAuthentication
	}
	return identity.ID, nil
}

func validSlackTeam(value string) bool {
	if len(value) < 9 || len(value) > 64 || value[0] != 'T' {
		return false
	}
	for _, c := range value[1:] {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
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
