package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const slackTestChannel = "C012ABCDE9"
const slackTestTS = "1482960137.003543"
const slackTestCursor = "opaque:next/page=+"

func TestSlackPreservesProviderIdentityFixedTypedCatalog(t *testing.T) {
	manifest := slackManifest()
	if err := manifest.validate(); err != nil {
		t.Fatal(err)
	}
	if manifest.Provider != "slack_import" || manifest.Capability != domain.Social || manifest.OriginKind != OriginFixed || manifest.Origin != "https://slack.com" ||
		manifest.APIVersion != "web-api" || !manifest.TypedOnly || manifest.ReadOnly || manifest.CredentialHeader != "Authorization" || manifest.CredentialScheme != "Bearer" || manifest.MaxRequestBytes != 1<<20 {
		t.Fatalf("invalid manifest: %+v", manifest)
	}
	wanted := map[string]domain.Risk{"auth.test": domain.RiskRead, "conversations.list": domain.RiskRead, "conversations.info": domain.RiskRead,
		"conversations.history": domain.RiskRead, "conversations.replies": domain.RiskRead, "users.info": domain.RiskRead,
		"chat.post_message": domain.RiskPublish, "chat.update": domain.RiskWrite, "chat.delete": domain.RiskDestructive}
	if len(manifest.Operations) != len(wanted) {
		t.Fatalf("operations=%d", len(manifest.Operations))
	}
	for _, operation := range manifest.Operations {
		method := strings.TrimPrefix(operation.Name, "social.slack_import.")
		endpointMethod := strings.ReplaceAll(method, "post_message", "postMessage")
		if operation.Risk != wanted[method] || operation.Path != "/api/"+endpointMethod || operation.Raw != nil || operation.Retry.MaxAttempts != 1 || operation.Retry.RetryableWrite || operation.IdempotencyHeader != "" {
			t.Fatalf("unsafe operation: %+v", operation)
		}
		if operation.Risk != domain.RiskRead && (len(operation.RequiredScopes) != 1 || operation.RequiredScopes[0] != "chat:write") {
			t.Fatalf("missing Slack write scope: %+v", operation)
		}
		delete(wanted, method)
		var schema map[string]any
		if json.Unmarshal(operation.InputSchema, &schema) != nil || schema["additionalProperties"] != false {
			t.Fatalf("non-strict schema: %s", operation.InputSchema)
		}
	}
}

func TestSlackFixedMethodsBearerBodiesAndPagination(t *testing.T) {
	for _, test := range []struct{ name, args, method, query, body string }{
		{"auth.test", `{}`, "POST", "", `{}`},
		{"conversations.list", `{"cursor":"` + slackTestCursor + `","limit":100,"types":"public_channel,private_channel","exclude_archived":true}`, "GET", "cursor=" + url.QueryEscape(slackTestCursor) + "&exclude_archived=true&limit=100&types=public_channel%2Cprivate_channel", ""},
		{"conversations.info", `{"channel":"` + slackTestChannel + `","include_num_members":true}`, "GET", "channel=" + slackTestChannel + "&include_num_members=true", ""},
		{"conversations.history", `{"channel":"` + slackTestChannel + `","oldest":"0000000001.000001","latest":"` + slackTestTS + `","inclusive":true}`, "GET", "channel=" + slackTestChannel + "&inclusive=true&latest=" + slackTestTS + "&limit=15&oldest=0000000001.000001", ""},
		{"conversations.replies", `{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `","cursor":"` + slackTestCursor + `","limit":1}`, "GET", "channel=" + slackTestChannel + "&cursor=" + url.QueryEscape(slackTestCursor) + "&limit=1&ts=" + slackTestTS, ""},
		{"users.info", `{"user":"W012ABCDE9"}`, "GET", "user=W012ABCDE9", ""},
		{"chat.postMessage", `{"body":{"channel":"` + slackTestChannel + `","text":"Hello — 世界\nline 2","thread_ts":"` + slackTestTS + `","mrkdwn":false,"unfurl_links":false,"unfurl_media":false}}`, "POST", "", `{"channel":"` + slackTestChannel + `","text":"Hello — 世界\nline 2","thread_ts":"` + slackTestTS + `","mrkdwn":false,"unfurl_links":false,"unfurl_media":false}`},
		{"chat.update", `{"body":{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `","text":"Updated"}}`, "POST", "", `{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `","text":"Updated"}`},
		{"chat.delete", `{"body":{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `"}}`, "POST", "", `{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			manifest := slackManifest()
			response := `{"ok":true,"ts":"` + slackTestTS + `","message":{"text":"slack-provider-secret"},"has_more":true,"response_metadata":{"next_cursor":"` + slackTestCursor + `"}}`
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != test.method || request.URL.Scheme != "https" || request.URL.Host != "slack.com" || request.URL.Path != "/api/"+test.name || request.URL.RawQuery != test.query {
					t.Fatalf("unexpected target: %s %s", request.Method, request.URL)
				}
				if request.Header.Get("Authorization") != "Bearer slack-provider-secret" || request.Header.Get("Idempotency-Key") != "" {
					t.Fatal("credential or unsupported idempotency header")
				}
				body, _ := io.ReadAll(request.Body)
				if string(body) != test.body {
					t.Fatalf("body=%s want=%s", body, test.body)
				}
				if test.method == "POST" && request.Header.Get("Content-Type") != "application/json" {
					t.Fatal("POST body must be JSON")
				}
				return jsonResponse(200, response, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			inv := testInvocation(t, manifest, findOperation(t, adapter, slackToolName(test.name)), json.RawMessage(test.args))
			inv.Connection.Scopes = []string{"chat:write", "users:read"}
			inv.Credential = credentialWithSecret(t, "slack-provider-secret", "Authorization", "Bearer")
			result, err := adapter.Invoke(context.Background(), inv)
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			serialized, _ := json.Marshal(result.Data)
			var expected any
			_ = json.Unmarshal([]byte(strings.ReplaceAll(response, "slack-provider-secret", "[REDACTED]")), &expected)
			expectedJSON, _ := json.Marshal(expected)
			if string(serialized) != string(expectedJSON) {
				t.Fatalf("response lost exact ts/cursor or leaked credential: %s", serialized)
			}
		})
	}
}

func TestSlackRejectsUnsafeArgumentsBeforeProviderIO(t *testing.T) {
	manifest := slackManifest()
	calls := 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(200, `{"ok":true}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, args string }{
		{"auth.test", `{"token":"caller-secret"}`},
		{"auth.test", `{"body":{"token":"caller-secret"}}`},
		{"auth.test", `{"provider":"slack"}`},
		{"auth.test", `{"headers":{"Authorization":"evil"}}`},
		{"auth.test", `{"origin":"https://attacker.invalid"}`},
		{"conversations.info", `{"channel":"../chat.delete"}`},
		{"conversations.info", `{"channel":"#general"}`},
		{"conversations.info", `{"channel":"U012ABCDE9"}`},
		{"conversations.info", `{"channel":"C012ABCDE9?token=x"}`},
		{"conversations.info", `{"channel":null}`},
		{"conversations.info", `{"channel":"` + slackTestChannel + `","include_num_members":"true"}`},
		{"conversations.list", `{"cursor":"next\u0000"}`},
		{"conversations.list", `{"cursor":""}`},
		{"conversations.list", `{"limit":201}`},
		{"conversations.list", `{"types":"public_channel,public_channel"}`},
		{"conversations.list", `{"types":"public_channel,other"}`},
		{"conversations.history", `{"channel":"` + slackTestChannel + `","limit":16}`},
		{"conversations.history", `{"channel":"` + slackTestChannel + `","limit":1.5}`},
		{"conversations.history", `{"channel":"` + slackTestChannel + `","oldest":1482960137.003543}`},
		{"conversations.replies", `{"channel":"` + slackTestChannel + `"}`},
		{"conversations.replies", `{"channel":"` + slackTestChannel + `","ts":"1482960137.003543\n"}`},
		{"users.info", `{"user":"C012ABCDE9"}`},
		{"chat.postMessage", `{"body":{"channel":"` + slackTestChannel + `","text":""}}`},
		{"chat.postMessage", `{"body":{"channel":"` + slackTestChannel + `","text":"x","thread_ts":1482960137.003543}}`},
		{"chat.postMessage", `{"body":{"channel":"` + slackTestChannel + `","text":"x","as_user":true}}`},
		{"chat.postMessage", `{"body":{"channel":"` + slackTestChannel + `","text":"x","blocks":[]}}`},
		{"chat.postMessage", `{"body":{"channel":"` + slackTestChannel + `","text":"x","unfurl_links":null}}`},
		{"chat.postMessage", `{"body":{"channel":"` + slackTestChannel + `","channel":"D012ABCDE9","text":"x"}}`},
		{"chat.update", `{"body":{"channel":"` + slackTestChannel + `","text":"x"}}`},
		{"chat.update", `{"body":{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `","text":null}}`},
		{"chat.update", `{"body":{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `","text":"x","thread_ts":"` + slackTestTS + `"}}`},
		{"chat.delete", `{"body":{"channel":"` + slackTestChannel + `","ts":1482960137.003543}}`},
		{"chat.delete", `{"body":{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `","text":"hidden"}}`},
	} {
		inv := testInvocation(t, manifest, findOperation(t, adapter, slackToolName(test.name)), json.RawMessage(test.args))
		inv.Connection.Scopes = []string{"chat:write"}
		if _, err := adapter.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("accepted %s %s: %v", test.name, test.args, err)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid arguments reached provider: %d", calls)
	}
}

func TestSlackNeverRetriesRateLimitedOrAmbiguousRequests(t *testing.T) {
	for _, test := range []struct{ name, args string }{
		{"auth.test", `{}`},
		{"conversations.history", `{"channel":"` + slackTestChannel + `"}`},
		{"conversations.replies", `{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `"}`},
		{"chat.postMessage", `{"body":{"channel":"` + slackTestChannel + `","text":"once"}}`},
		{"chat.update", `{"body":{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `","text":"once"}}`},
		{"chat.delete", `{"body":{"channel":"` + slackTestChannel + `","ts":"` + slackTestTS + `"}}`},
	} {
		for _, failure := range []string{"rate_limit", "network", "protocol"} {
			t.Run(test.name+failure, func(t *testing.T) {
				manifest := slackManifest()
				calls := 0
				adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
					calls++
					if failure == "network" {
						return nil, errors.New("connection reset after dispatch")
					}
					if failure == "protocol" {
						return jsonResponse(200, `{"ok":false,"error":"ratelimited"}`, nil), nil
					}
					return jsonResponse(429, `{"ok":false,"error":"ratelimited"}`, map[string]string{"Retry-After": "60"}), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				adapter.sleep = func(context.Context, time.Duration) error {
					t.Fatal("Slack Retry-After was retried internally")
					return nil
				}
				inv := testInvocation(t, manifest, findOperation(t, adapter, slackToolName(test.name)), json.RawMessage(test.args))
				inv.Connection.Scopes = []string{"chat:write"}
				inv.Idempotency = "not-a-Slack-idempotency-guarantee"
				_, err = adapter.Invoke(context.Background(), inv)
				var providerErr *domain.ProviderError
				if calls != 1 || err == nil || !errors.As(err, &providerErr) {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
				if failure != "network" && providerErr.Kind != "rate_limited" {
					t.Fatalf("kind=%s", providerErr.Kind)
				}
			})
		}
	}
}

func TestSlackProtocolFailureCannotLookLikeSuccessfulHTTP200(t *testing.T) {
	for _, test := range []struct {
		body, kind string
		permission bool
	}{
		{`{"ok":true,"response_metadata":{"next_cursor":"opaque:next=+"}}`, "", false},
		{`{"ok":false,"error":"missing_scope","needed":"chat:write"}`, "provider_permission", true},
		{`{"ok":false,"error":"token_revoked"}`, "provider_permission", true},
		{`{"ok":false,"error":"ratelimited"}`, "rate_limited", false},
		{`{"ok":false,"error":"channel_not_found"}`, "provider_error", false},
		{`{"ok":false,"error":"secret-arbitrary-provider-message"}`, "provider_error", false},
		{`{"ok":"true"}`, "invalid_response", false},
		{`{"ok":null}`, "invalid_response", false},
		{`{"error":"missing_scope"}`, "invalid_response", false},
		{`{"ok":false,"ok":true}`, "invalid_response", false},
		{`{"ok":true,"error":"missing_scope"}`, "invalid_response", false},
		{`{"ok":false}`, "invalid_response", false},
		{`{"ok":true} {"ok":false}`, "invalid_response", false},
		{`[]`, "invalid_response", false},
	} {
		kind, permission := slackResponseFailure(json.RawMessage(test.body))
		if kind != test.kind || permission != test.permission {
			t.Fatalf("body=%s kind=%s permission=%v", test.body, kind, permission)
		}
	}
}

func TestSlackHTTP200FailureCarriesRealAccountingAndPermission(t *testing.T) {
	manifest := slackManifest()
	body := `{"ok":false,"error":"missing_scope","needed":"chat:write"}`
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, body, map[string]string{"X-Slack-Req-Id": "slack-request-1"}), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	inv := testInvocation(t, manifest, findOperation(t, adapter, "social.slack_import.auth.test"), json.RawMessage(`{}`))
	result, err := adapter.Invoke(context.Background(), inv)
	var providerErr *domain.ProviderError
	if !errors.Is(err, domain.ErrProviderPermission) || !errors.As(err, &providerErr) || result.Data != nil {
		t.Fatalf("Slack error published as success: result=%+v error=%v", result, err)
	}
	if providerErr.Kind != "provider_permission" || providerErr.StatusCode != 200 || providerErr.Attempts != 1 || providerErr.RequestBytes != 2 || providerErr.ResponseBytes != int64(len(body)) || providerErr.ProviderID != "slack-request-1" {
		t.Fatalf("inaccurate accounting: %+v", providerErr)
	}
	if strings.Contains(err.Error(), "missing_scope") || strings.Contains(err.Error(), "chat:write") {
		t.Fatal("raw provider failure escaped in error text")
	}
}

func TestSlackInputBoundsAndTimestampStrings(t *testing.T) {
	if !slackTimestamp.MatchString("0000000001.000001") || slackTimestamp.MatchString("1e9") || slackTimestamp.MatchString("1482960137.00354") {
		t.Fatal("timestamps must remain exact documented strings")
	}
	for _, length := range []int{4000, 4001} {
		body, _ := json.Marshal(map[string]any{"channel": slackTestChannel, "text": strings.Repeat("界", length)})
		if slackWriteBody("social.slack_import.chat.post_message", body) != (length == 4000) {
			t.Fatalf("text bound=%d", length)
		}
	}
	if slackWriteBody("social.slack_import.chat.post_message", json.RawMessage(`{"channel":"`+slackTestChannel+`","text":"a\u0000b"}`)) {
		t.Fatal("NUL text accepted")
	}
}
