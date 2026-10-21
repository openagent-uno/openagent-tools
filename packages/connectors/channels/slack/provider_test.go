package slackchannel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type providerRoundTrip func(*http.Request) (*http.Response, error)

func (f providerRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func providerFixtureJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func providerFixtureResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func providerFixtureGrant() map[string]any {
	return map[string]any{"ok": true, "access_token": "xoxe.xoxb-fixture-new-access", "refresh_token": "xoxe-fixture-new-refresh", "token_type": "bot",
		"scope": strings.Join(BotScopes, ","), "app_id": "AAPP42", "bot_user_id": "UBOT42", "expires_in": 43200,
		"team": map[string]any{"id": "TFIX42"}, "authed_user": map[string]any{"id": "UOWNER42"}, "enterprise": nil, "is_enterprise_install": false}
}
func providerFixtureIdentity() map[string]any {
	return map[string]any{"ok": true, "team_id": "TFIX42", "user_id": "UBOT42", "bot_id": "BBOT42"}
}
func providerFixture(t *testing.T, transport providerRoundTrip) *SlackProvider {
	t.Helper()
	p, err := NewProvider("123.456", "AAPP42", "fixture-client-secret", "https://channels.example.org", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func providerFixtureOld(t *testing.T, p *SlackProvider) BotGrant {
	t.Helper()
	grant, err := p.decodeGrant([]byte(providerFixtureJSON(t, providerFixtureGrant())), nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	grant.AccessToken = "xoxe.xoxb-fixture-old-access"
	grant.RefreshToken = "xoxe-fixture-old-refresh"
	grant.Version = 4
	grant.AuthorizedAt = time.Now().UTC().Add(-time.Hour)
	return grant
}

func TestProviderAuthorizationIsFixedBotOnly(t *testing.T) {
	p := providerFixture(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("authorization must not make HTTP calls")
		return nil, nil
	})
	value, err := p.AuthorizationURL("csrf-fixture+reserved&value")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "slack.com" || u.Path != "/oauth/v2/authorize" {
		t.Fatal("authorization endpoint changed")
	}
	q := u.Query()
	if q.Get("state") != "csrf-fixture+reserved&value" || q.Get("client_id") != "123.456" || q.Get("redirect_uri") != "https://channels.example.org"+Prefix+"/oauth/callback" || q.Get("scope") != strings.Join(BotScopes, ",") {
		t.Fatal("authorization fields changed")
	}
	if _, ok := q["user_scope"]; ok {
		t.Fatal("user scope must be absent")
	}
	if len(q) != 4 {
		t.Fatal("unexpected authorization parameter")
	}
	if _, err = p.AuthorizationURL(""); err == nil {
		t.Fatal("empty state accepted")
	}
}

func TestProviderRejectsInvalidOriginAndConfiguration(t *testing.T) {
	for _, origin := range []string{"http://channels.example.org", "https://localhost", "https://127.0.0.1", "https://10.0.0.1", "https://[::1]", "https://user:password@channels.example.org", "https://channels.example.org/path", "https://channels.example.org?query=value", "https://channels.example.org#fragment"} {
		t.Run(origin, func(t *testing.T) {
			if _, err := NewProvider("123.456", "AAPP42", "fixture-secret", origin, nil); err == nil {
				t.Fatal("invalid origin accepted")
			}
		})
	}
	if _, err := NewProvider("123.456", "not-app", "fixture-secret", "https://channels.example.org", nil); err == nil {
		t.Fatal("invalid app accepted")
	}
	if _, err := NewProvider("123.456", "AAPP42", "secret\nheader", "https://channels.example.org", nil); err == nil {
		t.Fatal("invalid credential accepted")
	}
}

func TestProviderExchangeEncodesCodeAndValidatesBotIdentity(t *testing.T) {
	calls := 0
	now := time.Now().UTC()
	p := providerFixture(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.URL.Host != "slack.com" || r.Method != http.MethodPost {
			t.Fatal("request escaped fixed API")
		}
		if calls == 1 {
			if r.URL.Path != "/api/oauth.v2.access" {
				t.Fatal("wrong token endpoint")
			}
			user, secret, ok := r.BasicAuth()
			if !ok || user != "123.456" || secret != "fixture-client-secret" {
				t.Fatal("missing client authentication")
			}
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Fatal("wrong token encoding")
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.PostForm.Get("code") != "temporary+code&data" || r.PostForm.Get("redirect_uri") != "https://channels.example.org"+Prefix+"/oauth/callback" || len(r.PostForm) != 2 {
				t.Fatal("token fields differ")
			}
			if _, ok := r.PostForm["user_scope"]; ok {
				t.Fatal("user scope was sent")
			}
			return providerFixtureResponse(200, providerFixtureJSON(t, providerFixtureGrant())), nil
		}
		if r.URL.Path != "/api/auth.test" || r.Header.Get("Authorization") != "Bearer xoxe.xoxb-fixture-new-access" {
			t.Fatal("identity request not bound to returned bot token")
		}
		return providerFixtureResponse(200, providerFixtureJSON(t, providerFixtureIdentity())), nil
	})
	grant, err := p.Exchange(context.Background(), "temporary+code&data", now)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || grant.AppID != "AAPP42" || grant.TeamID != "TFIX42" || grant.BotUserID != "UBOT42" || grant.AuthorizedUserID != "UOWNER42" || grant.Version != 1 || grant.Status != "active" || !grant.ExpiresAt.Equal(now.Add(12*time.Hour)) || !grant.AuthorizedAt.Equal(now) || !reflect.DeepEqual(grant.Scopes, BotScopes) {
		t.Fatal("bot grant differs")
	}
}

func TestProviderRejectsUnsafeGrantWithoutFurtherIO(t *testing.T) {
	cases := map[string]func(map[string]any){
		"user-token":    func(v map[string]any) { v["token_type"] = "user" },
		"user-prefix":   func(v map[string]any) { v["access_token"] = "xoxe.xoxp-fixture-access" },
		"extra-scope":   func(v map[string]any) { v["scope"] = v["scope"].(string) + ",users:read" },
		"missing-scope": func(v map[string]any) { v["scope"] = strings.Join(BotScopes[1:], ",") },
		"duplicate-scope": func(v map[string]any) {
			v["scope"] = strings.Join(BotScopes[:len(BotScopes)-1], ",") + "," + BotScopes[0]
		},
		"no-expiry":        func(v map[string]any) { delete(v, "expires_in") },
		"unbounded-expiry": func(v map[string]any) { v["expires_in"] = 43201 },
		"no-refresh":       func(v map[string]any) { delete(v, "refresh_token") },
		"wrong-app":        func(v map[string]any) { v["app_id"] = "AOTHER42" },
		"missing-owner":    func(v map[string]any) { delete(v, "authed_user") },
		"user-credential": func(v map[string]any) {
			v["authed_user"] = map[string]any{"id": "UOWNER42", "access_token": "xoxp-fixture"}
		},
		"enterprise": func(v map[string]any) { v["enterprise"] = map[string]any{"id": "E42"} },
		"org-wide":   func(v map[string]any) { v["is_enterprise_install"] = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			v := providerFixtureGrant()
			change(v)
			p := providerFixture(t, func(*http.Request) (*http.Response, error) {
				calls++
				return providerFixtureResponse(200, providerFixtureJSON(t, v)), nil
			})
			got, err := p.Exchange(context.Background(), "fixture-code", time.Now())
			if err == nil || got.AccessToken != "" || calls != 1 {
				t.Fatal("unsafe grant escaped or caused extra IO")
			}
		})
	}
}

func TestProviderRejectsWrongIdentity(t *testing.T) {
	for _, field := range []string{"team_id", "user_id", "bot_id", "enterprise_id"} {
		t.Run(field, func(t *testing.T) {
			calls := 0
			p := providerFixture(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path == "/api/oauth.v2.access" {
					return providerFixtureResponse(200, providerFixtureJSON(t, providerFixtureGrant())), nil
				}
				v := providerFixtureIdentity()
				v[field] = "OTHER42"
				return providerFixtureResponse(200, providerFixtureJSON(t, v)), nil
			})
			grant, err := p.Exchange(context.Background(), "fixture-code", time.Now())
			if err == nil || grant.AccessToken != "" || calls != 2 {
				t.Fatal("wrong Slack identity accepted")
			}
		})
	}
}

func TestProviderRefreshRotatesAndPreservesAuthorizerMetadata(t *testing.T) {
	calls := 0
	now := time.Now().UTC()
	var old BotGrant
	p := providerFixture(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/api/oauth.v2.access" {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != old.RefreshToken || len(r.PostForm) != 2 {
				t.Fatal("refresh form differs")
			}
			v := providerFixtureGrant()
			delete(v, "authed_user")
			delete(v, "team")
			delete(v, "bot_user_id")
			delete(v, "app_id")
			return providerFixtureResponse(200, providerFixtureJSON(t, v)), nil
		}
		return providerFixtureResponse(200, providerFixtureJSON(t, providerFixtureIdentity())), nil
	})
	old = providerFixtureOld(t, p)
	grant, err := p.Refresh(context.Background(), old, now)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || grant.AccessToken == old.AccessToken || grant.RefreshToken == old.RefreshToken || grant.Version != 5 || grant.AuthorizedUserID != old.AuthorizedUserID || !grant.AuthorizedAt.Equal(old.AuthorizedAt) || grant.TeamID != old.TeamID || grant.BotUserID != old.BotUserID {
		t.Fatal("rotated grant lost binding")
	}
	if old.AccessToken != "xoxe.xoxb-fixture-old-access" || old.RefreshToken != "xoxe-fixture-old-refresh" {
		t.Fatal("input grant mutated")
	}
}

func TestProviderRefreshRejectsChangedOrUnrotatedGrant(t *testing.T) {
	for _, field := range []string{"app_id", "team", "bot_user_id", "authed_user", "access_token", "refresh_token"} {
		t.Run(field, func(t *testing.T) {
			var old BotGrant
			calls := 0
			p := providerFixture(t, func(*http.Request) (*http.Response, error) {
				calls++
				v := providerFixtureGrant()
				switch field {
				case "app_id":
					v[field] = "AOTHER42"
				case "team":
					v[field] = map[string]any{"id": "TOTHER42"}
				case "bot_user_id":
					v[field] = "UOTHER42"
				case "authed_user":
					v[field] = map[string]any{"id": "UOTHER42"}
				case "access_token":
					v[field] = old.AccessToken
				case "refresh_token":
					v[field] = old.RefreshToken
				}
				return providerFixtureResponse(200, providerFixtureJSON(t, v)), nil
			})
			old = providerFixtureOld(t, p)
			if _, err := p.Refresh(context.Background(), old, time.Now()); err == nil || calls != 1 {
				t.Fatal("unsafe refresh accepted or retried")
			}
		})
	}
}

func TestProviderCallUsesFixedMethodsAndBearerOnly(t *testing.T) {
	calls := 0
	p := providerFixture(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Scheme != "https" || r.URL.Host != "slack.com" || !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.RawQuery != "" {
			t.Fatal("call escaped fixed endpoint")
		}
		if r.Header.Get("Authorization") != "Bearer xoxe.xoxb-fixture-old-access" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			t.Fatal("bad call encoding")
		}
		var args map[string]any
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			t.Fatal(err)
		}
		if args["channel"] != "C42" {
			t.Fatal("channel arg lost")
		}
		return providerFixtureResponse(200, `{"ok":true,"fixture":"result"}`), nil
	})
	grant := providerFixtureOld(t, p)
	for _, method := range []string{"auth.test", "conversations.info", "conversations.members", "conversations.history", "conversations.replies", "chat.postMessage"} {
		raw, err := p.Call(context.Background(), grant, method, map[string]any{"channel": "C42"})
		if err != nil || !strings.Contains(string(raw), "result") {
			t.Fatal("allowed method failed")
		}
	}
	if calls != 6 {
		t.Fatal("unexpected call count")
	}
	for _, method := range []string{"users.list", "files.upload", "oauth.v2.access", "https://example.org/steal", "../auth.test", "auth.test?token=fixture"} {
		if _, err := p.Call(context.Background(), grant, method, nil); err == nil {
			t.Fatal("arbitrary method accepted")
		}
	}
	for _, key := range []string{"token", "access_token", "refresh_token", "client_secret", "url", "endpoint", "headers", "method"} {
		if _, err := p.Call(context.Background(), grant, "chat.postMessage", map[string]any{key: "fixture"}); err == nil {
			t.Fatal("credential/URL override accepted")
		}
	}
	if calls != 6 {
		t.Fatal("rejected call made IO")
	}
}

func TestProviderErrorsAreRedactedWithoutRetries(t *testing.T) {
	const private = "fixture-private-provider-body-and-token"
	for _, mode := range []string{"error-body", "http-error", "transport-error", "invalid-json", "duplicate-json", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			var logs strings.Builder
			oldWriter := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(oldWriter)
			calls := 0
			p := providerFixture(t, func(*http.Request) (*http.Response, error) {
				calls++
				switch mode {
				case "transport-error":
					return nil, errors.New(private)
				case "http-error":
					return providerFixtureResponse(502, private), nil
				case "invalid-json":
					return providerFixtureResponse(200, private), nil
				case "duplicate-json":
					return providerFixtureResponse(200, `{"ok":false,"ok":true,"access_token":"`+private+`"}`), nil
				case "oversize":
					return providerFixtureResponse(200, strings.Repeat("x", slackResponseLimit+1)), nil
				}
				return providerFixtureResponse(200, `{"ok":false,"error":"`+private+`"}`), nil
			})
			_, err := p.Exchange(context.Background(), "fixture-code", time.Now())
			if err == nil || calls != 1 || strings.Contains(fmt.Sprintf("%v %#v %v", err, err, errors.Unwrap(err)), private) || strings.Contains(logs.String(), private) {
				t.Fatal("unsafe provider failure escaped or retried")
			}
		})
	}
}

func TestProviderRefusesRedirectsEvenInjectedClientPolicy(t *testing.T) {
	calls := 0
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }, Transport: providerRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		response := providerFixtureResponse(302, "")
		response.Header.Set("Location", "https://other.example.org/token")
		return response, nil
	})}
	p, err := NewProvider("123.456", "AAPP42", "fixture-secret", "https://channels.example.org", client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exchange(context.Background(), "fixture-code", time.Now()); err == nil || calls != 1 {
		t.Fatal("provider redirect followed")
	}
	if client.CheckRedirect(nil, nil) != nil {
		t.Fatal("caller client mutated")
	}
}

func TestProviderCancelledContextAndExpiredCallDoNotDeliver(t *testing.T) {
	calls := 0
	p := providerFixture(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Context().Err() == nil {
			t.Fatal("request context not propagated")
		}
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Exchange(ctx, "fixture-code", time.Now()); err == nil {
		t.Fatal("cancelled exchange succeeded")
	}
	grant := providerFixtureOld(t, p)
	grant.ExpiresAt = time.Now().Add(-time.Minute)
	before := calls
	if _, err := p.Call(context.Background(), grant, "chat.postMessage", map[string]any{"channel": "C42"}); err == nil || calls != before {
		t.Fatal("expired grant made API call")
	}
}

func TestProviderFormattingDoesNotExposeCredentials(t *testing.T) {
	p := providerFixture(t, func(*http.Request) (*http.Response, error) { t.Fatal("no HTTP expected"); return nil, nil })
	grant := providerFixtureOld(t, p)
	for _, value := range []any{p, *p, grant, &grant} {
		formatted := fmt.Sprintf("%v %+v %#v", value, value, value)
		for _, secret := range []string{p.secret, grant.AccessToken, grant.RefreshToken} {
			if strings.Contains(formatted, secret) {
				t.Fatal("debug formatting exposed credentials")
			}
		}
	}
}
