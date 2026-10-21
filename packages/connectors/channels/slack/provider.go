package slackchannel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const slackAuthorizeURL = "https://slack.com/oauth/v2/authorize"
const slackAPIOrigin = "https://slack.com/api/"
const slackResponseLimit = 2 << 20

var errSlackProvider = errors.New("slack_channel_provider_failed")
var errSlackConfig = errors.New("slack_channel_provider_configuration_invalid")
var slackID = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,127}$`)

// SlackProvider owns only the fixed Slack bot OAuth/API boundary. It never
// returns provider error bodies or logs grants. HTTP transports are injectable;
// endpoint origins and redirect policy are not.
type SlackProvider struct {
	clientID string
	appID    string
	secret   string
	callback string
	client   *http.Client
	scopes   []string
}

func (SlackProvider) String() string   { return "[redacted Slack bot provider]" }
func (SlackProvider) GoString() string { return "[redacted Slack bot provider]" }

func NewProvider(clientID, appID, secret, origin string, httpClient *http.Client) (*SlackProvider, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, errSlackConfig
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host == "" || strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") || (ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())) || (ip == nil && !strings.Contains(host, ".")) {
		return nil, errSlackConfig
	}
	if !providerSecret(clientID) || len(clientID) > 256 || !providerID(appID, "A") || !providerSecret(secret) {
		return nil, errSlackConfig
	}
	c := http.Client{Timeout: 20 * time.Second}
	if httpClient != nil {
		c = *httpClient
	}
	if c.Timeout <= 0 || c.Timeout > 20*time.Second {
		c.Timeout = 20 * time.Second
	}
	c.Jar = nil
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &SlackProvider{clientID: clientID, appID: appID, secret: secret,
		callback: strings.TrimSuffix(origin, "/") + Prefix + "/oauth/callback", client: &c,
		scopes: append([]string(nil), BotScopes...)}, nil
}

func providerSecret(value string) bool {
	if len(value) == 0 || len(value) > 8192 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
func providerID(value, prefixes string) bool {
	return slackID.MatchString(value) && strings.ContainsRune(prefixes, rune(value[0]))
}

func (p *SlackProvider) AuthorizationURL(state string) (string, error) {
	if !providerSecret(state) || len(state) > 1024 {
		return "", errSlackProvider
	}
	q := url.Values{"client_id": {p.clientID}, "redirect_uri": {p.callback}, "scope": {strings.Join(p.scopes, ",")}, "state": {state}}
	return slackAuthorizeURL + "?" + q.Encode(), nil
}

type slackOAuthResponse struct {
	OK           bool   `json:"ok"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	AppID        string `json:"app_id"`
	BotUserID    string `json:"bot_user_id"`
	ExpiresIn    int64  `json:"expires_in"`
	Team         struct {
		ID string `json:"id"`
	} `json:"team"`
	Enterprise        json.RawMessage `json:"enterprise"`
	EnterpriseInstall bool            `json:"is_enterprise_install"`
	AuthedUser        struct {
		ID           string `json:"id"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	} `json:"authed_user"`
}

func (p *SlackProvider) Exchange(ctx context.Context, code string, now time.Time) (BotGrant, error) {
	if !providerSecret(code) || now.IsZero() {
		return BotGrant{}, errSlackProvider
	}
	raw, err := p.oauth(ctx, url.Values{"code": {code}, "redirect_uri": {p.callback}})
	if err != nil {
		return BotGrant{}, errSlackProvider
	}
	grant, err := p.decodeGrant(raw, nil, now)
	if err != nil {
		return BotGrant{}, errSlackProvider
	}
	if err = p.verifyIdentity(ctx, grant); err != nil {
		return BotGrant{}, errSlackProvider
	}
	return grant, nil
}

func (p *SlackProvider) Refresh(ctx context.Context, old BotGrant, now time.Time) (BotGrant, error) {
	if !p.validGrant(old) || now.IsZero() || old.Version == ^uint64(0) {
		return BotGrant{}, errSlackProvider
	}
	raw, err := p.oauth(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {old.RefreshToken}})
	if err != nil {
		return BotGrant{}, errSlackProvider
	}
	grant, err := p.decodeGrant(raw, &old, now)
	if err != nil || grant.AccessToken == old.AccessToken || grant.RefreshToken == old.RefreshToken {
		return BotGrant{}, errSlackProvider
	}
	if err = p.verifyIdentity(ctx, grant); err != nil {
		return BotGrant{}, errSlackProvider
	}
	return grant, nil
}

func (p *SlackProvider) oauth(ctx context.Context, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, slackAPIOrigin+"oauth.v2.access", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errSlackProvider
	}
	req.SetBasicAuth(p.clientID, p.secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return p.request(req)
}

func (p *SlackProvider) decodeGrant(raw []byte, old *BotGrant, now time.Time) (BotGrant, error) {
	var response slackOAuthResponse
	if !providerJSON(raw) || json.Unmarshal(raw, &response) != nil || !response.OK || response.TokenType != "bot" || response.EnterpriseInstall || (len(response.Enterprise) != 0 && string(bytes.TrimSpace(response.Enterprise)) != "null") || !strings.HasPrefix(response.AccessToken, "xoxe.xoxb-") || !providerSecret(response.AccessToken) || !strings.HasPrefix(response.RefreshToken, "xoxe-") || !providerSecret(response.RefreshToken) || response.ExpiresIn <= 0 || response.ExpiresIn > 43200 {
		return BotGrant{}, errSlackProvider
	}
	// No user_scope was requested. Never accept a second user credential or a
	// silently broader cumulative bot grant.
	if response.AuthedUser.AccessToken != "" || response.AuthedUser.RefreshToken != "" || response.AuthedUser.Scope != "" || response.AuthedUser.TokenType != "" {
		return BotGrant{}, errSlackProvider
	}
	appID, teamID, botUserID, userID := response.AppID, response.Team.ID, response.BotUserID, response.AuthedUser.ID
	if old != nil {
		if appID == "" {
			appID = old.AppID
		}
		if teamID == "" {
			teamID = old.TeamID
		}
		if botUserID == "" {
			botUserID = old.BotUserID
		}
		if userID == "" {
			userID = old.AuthorizedUserID
		}
		if appID != old.AppID || teamID != old.TeamID || botUserID != old.BotUserID || userID != old.AuthorizedUserID {
			return BotGrant{}, errSlackProvider
		}
	}
	scopes := strings.Split(response.Scope, ",")
	if appID != p.appID || !providerID(teamID, "T") || !providerID(botUserID, "UW") || !providerID(userID, "UW") || !sameProviderScopes(scopes, p.scopes) {
		return BotGrant{}, errSlackProvider
	}
	grant := BotGrant{AppID: appID, TeamID: teamID, BotUserID: botUserID, AuthorizedUserID: userID,
		AccessToken: response.AccessToken, RefreshToken: response.RefreshToken,
		ExpiresAt: now.UTC().Add(time.Duration(response.ExpiresIn) * time.Second), Scopes: append([]string(nil), p.scopes...),
		Status: "active", Version: 1, AuthorizedAt: now.UTC()}
	if old != nil {
		grant.Version = old.Version + 1
		grant.AuthorizedAt = old.AuthorizedAt
	}
	return grant, nil
}

func sameProviderScopes(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] == "" || a[i] != b[i] || (i > 0 && a[i] == a[i-1]) {
			return false
		}
	}
	return true
}

func (p *SlackProvider) validGrant(grant BotGrant) bool {
	return grant.AppID == p.appID && providerID(grant.TeamID, "T") && providerID(grant.BotUserID, "UW") && providerID(grant.AuthorizedUserID, "UW") && strings.HasPrefix(grant.AccessToken, "xoxe.xoxb-") && providerSecret(grant.AccessToken) && strings.HasPrefix(grant.RefreshToken, "xoxe-") && providerSecret(grant.RefreshToken) && sameProviderScopes(grant.Scopes, p.scopes) && grant.Status == "active" && grant.Version > 0 && !grant.AuthorizedAt.IsZero() && !grant.ExpiresAt.IsZero()
}

func (p *SlackProvider) verifyIdentity(ctx context.Context, grant BotGrant) error {
	raw, err := p.api(ctx, grant.AccessToken, "auth.test", map[string]any{})
	if err != nil {
		return errSlackProvider
	}
	var identity struct {
		OK                bool   `json:"ok"`
		TeamID            string `json:"team_id"`
		UserID            string `json:"user_id"`
		BotID             string `json:"bot_id"`
		EnterpriseID      string `json:"enterprise_id"`
		EnterpriseInstall bool   `json:"is_enterprise_install"`
	}
	if json.Unmarshal(raw, &identity) != nil || !identity.OK || identity.TeamID != grant.TeamID || identity.UserID != grant.BotUserID || !providerID(identity.BotID, "B") || identity.EnterpriseID != "" || identity.EnterpriseInstall {
		return errSlackProvider
	}
	return nil
}

// Call supports only these channel methods. The service owns channel binding,
// actor admission and write deduplication; arguments can never choose a host,
// bearer credential, headers or another Slack method.
func (p *SlackProvider) Call(ctx context.Context, grant BotGrant, method string, args map[string]any) (json.RawMessage, error) {
	if !p.validGrant(grant) || !grant.ExpiresAt.After(time.Now()) {
		return nil, errSlackProvider
	}
	if !slackMethod(method) {
		return nil, errSlackProvider
	}
	for key := range args {
		switch strings.ToLower(key) {
		case "token", "access_token", "refresh_token", "client_secret", "client_id", "url", "endpoint", "headers", "method":
			return nil, errSlackProvider
		}
	}
	raw, err := p.api(ctx, grant.AccessToken, method, args)
	if err != nil {
		return nil, errSlackProvider
	}
	return json.RawMessage(raw), nil
}

func slackMethod(method string) bool {
	switch method {
	case "auth.test", "conversations.info", "conversations.members", "conversations.history", "conversations.replies", "chat.postMessage":
		return true
	}
	return false
}
func (p *SlackProvider) api(ctx context.Context, access, method string, args map[string]any) ([]byte, error) {
	if !slackMethod(method) {
		return nil, errSlackProvider
	}
	if args == nil {
		args = map[string]any{}
	}
	body, err := json.Marshal(args)
	if err != nil || len(body) > 65536 {
		return nil, errSlackProvider
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, slackAPIOrigin+method, bytes.NewReader(body))
	if err != nil {
		return nil, errSlackProvider
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	raw, err := p.request(req)
	if err != nil {
		return nil, errSlackProvider
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(raw, &response) != nil || !response.OK {
		return nil, errSlackProvider
	}
	return raw, nil
}
func (p *SlackProvider) request(req *http.Request) ([]byte, error) {
	response, err := p.client.Do(req)
	if err != nil {
		return nil, errSlackProvider
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errSlackProvider
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, slackResponseLimit+1))
	if err != nil || len(raw) > slackResponseLimit || !providerJSON(raw) {
		return nil, errSlackProvider
	}
	return raw, nil
}

// Reject ambiguous duplicate keys as well as unbounded JSON structure before
// interpreting authentication fields; no decoder errors escape this boundary.
func providerJSON(raw []byte) bool {
	if !utf8.Valid(raw) || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var value func(int) bool
	value = func(depth int) bool {
		nodes++
		if depth > 16 || nodes > 32768 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				k, ok := key.(string)
				if err != nil || !ok || seen[k] {
					return false
				}
				seen[k] = true
				if !value(depth + 1) {
					return false
				}
			}
			t, err = d.Token()
			return err == nil && t == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			t, err = d.Token()
			return err == nil && t == json.Delim(']')
		}
		_, delimiter := t.(json.Delim)
		return !delimiter
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

var _ Provider = (*SlackProvider)(nil)
