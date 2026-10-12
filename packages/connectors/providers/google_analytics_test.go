package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestGoogleAnalyticsCatalogIsReadOnlyAndScopeBound(t *testing.T) {
	adapters, err := CatalogWithDoer(successDoer())
	if err != nil {
		t.Fatal(err)
	}
	var operations []domain.Operation
	for _, adapter := range adapters {
		if adapter.Provider() == "google_analytics" {
			if adapter.Capability() != domain.Ads {
				t.Fatal("wrong Analytics capability")
			}
			operations = adapter.Operations()
		}
	}
	if len(operations) != 4 {
		t.Fatalf("Analytics catalog has %d tools", len(operations))
	}
	for _, op := range operations {
		if op.Risk != domain.RiskRead || op.Mode != domain.OperationTyped ||
			len(op.RequiredScopes) != 1 || op.RequiredScopes[0] != GoogleAnalyticsReadScope {
			t.Fatalf("unsafe Analytics operation: %+v", op)
		}
		if domain.GrantsScopes(nil, op.RequiredScopes) {
			t.Fatal("missing OAuth scope granted")
		}
	}
	manifest := googleAnalyticsManifest()
	if !manifest.ReadOnly || manifest.MaxRequestBytes != 64<<10 || manifest.MaxResponseBytes != 8<<20 {
		t.Fatalf("unexpected Analytics bounds: %+v", manifest)
	}
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.Operations[0].Risk = domain.RiskWrite },
		func(m *Manifest) { m.Operations[0].Sync = &SyncSpec{Strategy: "poll"} },
		func(m *Manifest) {
			m.Operations = append(m.Operations, driveManifest().Operations[len(driveManifest().Operations)-1])
		},
	} {
		mutated := cloneManifest(manifest)
		change(&mutated)
		if mutated.validate() == nil {
			t.Fatal("read-only manifest accepted mutation, raw or sync")
		}
	}
}

func TestGoogleAnalyticsCallsFixedDocumentedEndpoints(t *testing.T) {
	cases := []struct{ name, args, method, host, path, response string }{
		{"ads.google_analytics.account_summaries.list", `{"page_size":100,"page_token":"opaque+next/page"}`, "GET", "analyticsadmin.googleapis.com", "/v1beta/accountSummaries", `{"accountSummaries":[{"account":"accounts/1","propertySummaries":[{"property":"properties/1234"}]}],"nextPageToken":"next-page"}`},
		{"ads.google_analytics.reports.run", `{"property_id":"1234","body":{"dimensions":[{"name":"country"}],"metrics":[{"name":"activeUsers"}],"dateRanges":[{"startDate":"7daysAgo","endDate":"today"}],"offset":"2000","limit":"1000","returnPropertyQuota":true}}`, "POST", "analyticsdata.googleapis.com", "/v1beta/properties/1234:runReport", `{"dimensionHeaders":[{"name":"country"}],"metricHeaders":[{"name":"activeUsers","type":"TYPE_INTEGER"}],"rows":[{"dimensionValues":[{"value":"Italy"}],"metricValues":[{"value":"42"}]}],"rowCount":2200,"propertyQuota":{}}`},
		{"ads.google_analytics.realtime.run", `{"property_id":"1234","body":{"metrics":[{"name":"activeUsers"}]}}`, "POST", "analyticsdata.googleapis.com", "/v1beta/properties/1234:runRealtimeReport", `{"metricHeaders":[{"name":"activeUsers"}],"rows":[{"metricValues":[{"value":"4"}]}],"rowCount":1}`},
		{"ads.google_analytics.metadata.get", `{"property_id":"0"}`, "GET", "analyticsdata.googleapis.com", "/v1beta/properties/0/metadata", `{"name":"properties/0/metadata","dimensions":[{"apiName":"country"}],"metrics":[{"apiName":"activeUsers"}],"echo":"analytics-test-secret"}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			manifest := googleAnalyticsManifest()
			var body []byte
			calls := 0
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != test.method || req.URL.Host != test.host || req.URL.Path != test.path || req.URL.Scheme != "https" {
					t.Fatalf("wrong provider route: %s %s", req.Method, req.URL)
				}
				if req.Header.Get("Authorization") != "Bearer analytics-test-secret" || req.Header.Get("Idempotency-Key") != "" {
					t.Fatal("incorrect fixed credential/idempotency header")
				}
				if test.name == "ads.google_analytics.account_summaries.list" && (req.URL.Query().Get("pageSize") != "100" || req.URL.Query().Get("pageToken") != "opaque+next/page") {
					t.Fatalf("wrong pagination mapping: %s", req.URL.RawQuery)
				}
				body, _ = io.ReadAll(req.Body)
				return jsonResponse(http.StatusOK, test.response, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			inv := testInvocation(t, manifest, findOperation(t, adapter, test.name), json.RawMessage(test.args))
			inv.Credential = credentialWithSecret(t, "analytics-test-secret", "Authorization", "Bearer")
			// Even a secret-free config containing URL-like values cannot reroute
			// an immutable built-in origin.
			inv.Connection.Config = json.RawMessage(`{"origin":"https://attacker.invalid","property_id":"other"}`)
			preview, err := adapter.Preview(inv)
			if err != nil || !strings.HasPrefix(preview.Path, test.path) {
				t.Fatalf("preview=%+v err=%v", preview, err)
			}
			result, err := adapter.Invoke(context.Background(), inv)
			if err != nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if test.method == http.MethodGet && len(body) != 0 {
				t.Fatalf("GET body=%s", body)
			}
			if test.method == http.MethodPost {
				var payload map[string]json.RawMessage
				if json.Unmarshal(body, &payload) != nil || len(payload["metrics"]) == 0 || string(payload["limit"]) != `"1000"` {
					t.Fatalf("body=%s", body)
				}
				if _, exists := payload["property_id"]; exists {
					t.Fatalf("property id escaped into body: %s", body)
				}
			}
			serialized, _ := json.Marshal(result.Data)
			if strings.Contains(string(serialized), "analytics-test-secret") {
				t.Fatal("secret reflected into result")
			}
			var expected any
			_ = json.Unmarshal([]byte(strings.ReplaceAll(test.response, "analytics-test-secret", "[REDACTED]")), &expected)
			expectedJSON, _ := json.Marshal(expected)
			if string(serialized) != string(expectedJSON) {
				t.Fatalf("response lost data: %s want=%s", serialized, expectedJSON)
			}
		})
	}
}

func TestGoogleAnalyticsRejectsUnsafeAndUnboundedArgumentsBeforeHTTP(t *testing.T) {
	manifest := googleAnalyticsManifest()
	calls := 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) { calls++; return jsonResponse(200, `{}`, nil), nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []any{"../1", "1234:runPivotReport", "1234/metadata", "https://attacker.invalid", "%2e%2e", "1?key=x", "1#fragment", "0001", "0", "-1", " 1234", "1\n", strings.Repeat("1", 21), 1234, nil} {
		body := map[string]any{"property_id": id, "body": map[string]any{"metrics": []any{map[string]any{"name": "activeUsers"}}}}
		args, _ := json.Marshal(body)
		inv := testInvocation(t, manifest, findOperation(t, adapter, "ads.google_analytics.realtime.run"), args)
		if _, err := adapter.Preview(inv); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("property=%v error=%v", id, err)
		}
	}
	cases := []struct{ operation, args string }{
		{"account_summaries.list", `{"page_size":201}`},
		{"account_summaries.list", `{"page_size":0}`},
		{"account_summaries.list", `{"page_size":null}`},
		{"account_summaries.list", `{"page_token":""}`},
		{"account_summaries.list", `{"page_token":"x\n"}`},
		{"account_summaries.list", `{"origin":"https://attacker.invalid"}`},
		{"metadata.get", `{"property_id":"1","headers":{"Authorization":"evil"}}`},
		{"metadata.get", `{"property_id":"1","provider":"google_drive"}`},
		{"metadata.get", `{"property_id":"1","method":"DELETE"}`},
		{"metadata.get", `{"property_id":"1","body":{}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[]}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers","expression":"1+1"}]}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"dateRanges":[]}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"offset":"0"}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"limit":"10001"}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"limit":100}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"limit":"0"}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"returnPropertyQuota":null}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"},{"name":"activeUsers"}]}}`},
		{"realtime.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"metricFilter":{"raw":"unsupported"}}}`},
		{"reports.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}]}}`},
		{"reports.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"dateRanges":[{"startDate":"2026-02-30","endDate":"today"}]}}`},
		{"reports.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"dateRanges":[{"startDate":"9999daysAgo","endDate":"today"}]}}`},
		{"reports.run", `{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}],"dateRanges":[{"startDate":"2026-09-04","endDate":"2026-09-01"}]}}`},
	}
	for _, test := range cases {
		inv := testInvocation(t, manifest, findOperation(t, adapter, "ads.google_analytics."+test.operation), json.RawMessage(test.args))
		if _, err := adapter.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("accepted %s %s: %v", test.operation, test.args, err)
		}
	}
	for _, field := range []string{"metrics", "dimensions", "dateRanges"} {
		body := map[string]any{"metrics": []any{map[string]any{"name": "activeUsers"}}, "dateRanges": []any{map[string]any{"startDate": "7daysAgo", "endDate": "today"}}}
		values := []any{}
		for n := 0; n < 11; n++ {
			values = append(values, map[string]any{"name": "field" + strconv.Itoa(n)})
		}
		body[field] = values
		args, _ := json.Marshal(map[string]any{"property_id": "1", "body": body})
		inv := testInvocation(t, manifest, findOperation(t, adapter, "ads.google_analytics.reports.run"), args)
		if _, err := adapter.Invoke(context.Background(), inv); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("accepted unbounded %s: %v", field, err)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid arguments reached HTTP %d times", calls)
	}
}

func TestGoogleAnalyticsReadPOSTRetriesWithoutIdempotencyAndDeniesRedirects(t *testing.T) {
	manifest := googleAnalyticsManifest()
	calls := 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(http.StatusTooManyRequests, `{}`, nil), nil
		}
		return jsonResponse(http.StatusOK, `{"rows":[]}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error { return nil }
	inv := testInvocation(t, manifest, findOperation(t, adapter, "ads.google_analytics.realtime.run"), json.RawMessage(`{"property_id":"1","body":{"metrics":[{"name":"activeUsers"}]}}`))
	inv.Idempotency = ""
	if _, err := adapter.Invoke(context.Background(), inv); err != nil || calls != 2 {
		t.Fatalf("read retry calls=%d err=%v", calls, err)
	}
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusUnauthorized, http.StatusForbidden} {
		adapter.doer = doerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(status, `{"token":"secret"}`, map[string]string{"Location": "https://attacker.invalid"}), nil
		})
		_, err := adapter.Invoke(context.Background(), inv)
		var providerError *domain.ProviderError
		if !errors.As(err, &providerError) || providerError.StatusCode != status || strings.Contains(err.Error(), "secret") {
			t.Fatalf("status=%d err=%v", status, err)
		}
	}
}

func TestTypedOperationOriginsRejectUnsafeOverrides(t *testing.T) {
	for _, origin := range []string{"http://analyticsadmin.googleapis.com", "https://localhost", "https://127.0.0.1", "https://analyticsadmin.googleapis.com/path", "https://user@analyticsadmin.googleapis.com", "https://analyticsadmin.googleapis.com:443"} {
		manifest := googleAnalyticsManifest()
		manifest.Operations[0].Origin = origin
		if _, err := NewHTTPAdapter(manifest, successDoer()); err == nil {
			t.Fatalf("unsafe operation origin %s accepted", origin)
		}
	}
	manifest := pipeboardManifest()
	manifest.Operations[0].Origin = googleAnalyticsDataOrigin
	if manifest.validate() == nil {
		t.Fatal("dynamic-origin manifest accepted operation origin override")
	}
}
