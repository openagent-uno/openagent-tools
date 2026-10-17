package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// Source-derived contract examples, not real market-data responses. Actual
// execute calls and free-subset acceptance are deliberately separate QA gates.
func coinGeckoOutput(global bool) map[string]any {
	if !global {
		return map[string]any{"schema": "openagent-coingecko-prices-v1", "data": map[string]any{
			"bitcoin": map[string]any{"usd": 100.25, "last_updated_at": 1700000000},
		}}
	}
	return map[string]any{"schema": "openagent-coingecko-global-v1", "data": map[string]any{"data": map[string]any{
		"active_cryptocurrencies": 10, "ended_icos": 0, "markets": 4, "ongoing_icos": 0, "upcoming_icos": 0,
		"total_market_cap": map[string]any{"usd": 1000.5}, "total_volume": map[string]any{"usd": 100.5},
		"market_cap_percentage": map[string]any{"btc": 50.0, "eth": 25.0}, "updated_at": 1700000000,
		"market_cap_change_percentage_24h_usd": -1.2,
	}}}
}

func coinGeckoResultJSON(t *testing.T, value any) string {
	t.Helper()
	text, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return coinGeckoTextResult(t, string(text))
}

func coinGeckoTextResult(t *testing.T, text string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestCoinGeckoFixedTemplatesSessionDeadlineAndNormalizedOutput(t *testing.T) {
	for index, global := range []bool{false, true} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("global=%v/wrapped=%v", global, wrapped), func(t *testing.T) {
				var payload any = coinGeckoOutput(global)
				if wrapped {
					payload = map[string]any{"result": payload, "log_lines": []any{}, "err_lines": []any{}}
				}
				base := &keylessDoer{t: t, sse: wrapped, result: coinGeckoResultJSON(t, payload)}
				doer := keylessResponseDoer(func(request *http.Request) (*http.Response, error) {
					deadline, ok := request.Context().Deadline()
					if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
						t.Fatal("CoinGecko lacks bounded total deadline")
					}
					return base.Do(request)
				})
				adapter, err := NewKeylessMCPAdapter("coingecko", doer)
				if err != nil {
					t.Fatal(err)
				}
				args := `{"ids":["bitcoin"],"currencies":["usd"]}`
				if global {
					args = `{}`
				}
				inv := keylessInvocation(t, adapter, index, args)
				result, err := adapter.Invoke(context.Background(), inv)
				if err != nil || result.Attempts != 1 || result.ProviderStatus != 200 || len(base.requests) != 3 {
					t.Fatalf("compiled read: %v", err)
				}
				params := base.calls[2]["params"].(map[string]any)
				remote := params["arguments"].(map[string]any)
				code, _ := remote["code"].(string)
				expected := `async function run(client) { return {schema:"openagent-coingecko-prices-v1",data:await client.simple.price.get({"ids":"bitcoin","include_last_updated_at":true,"vs_currencies":"usd"},{maxRetries:0,timeout:10000})}; }`
				if global {
					expected = `async function run(client) { return {schema:"openagent-coingecko-global-v1",data:await client.global.get({maxRetries:0,timeout:10000})}; }`
				}
				if params["name"] != "execute" || len(remote) != 1 || code != expected || strings.Count(code, ".get(") != 1 {
					t.Fatal("template, SDK method or fixed options changed")
				}
				data, ok := result.Data.(map[string]any)
				if !ok || len(data) != 2 || data["schema"] != coinGeckoOutput(global)["schema"] || data["data"] == nil {
					t.Fatal("remote wrapper or raw execute surface leaked")
				}
				for _, op := range adapter.Operations() {
					if op.Validate() != nil || op.Risk != domain.RiskRead || op.Mode != domain.OperationTyped || op.Retry.MaxAttempts != 1 || strings.Contains(op.Name, "execute") || strings.Contains(op.Name, "search_docs") {
						t.Fatal("raw or retryable tool exposed")
					}
					var schema map[string]any
					if json.Unmarshal(op.InputSchema, &schema) != nil || schema["additionalProperties"] != false {
						t.Fatal("non-strict public schema")
					}
					properties := schema["properties"].(map[string]any)
					for _, field := range []string{"code", "intent", "url", "method", "session_id", "headers", "client_opts"} {
						if properties[field] != nil {
							t.Fatal("compiler control exposed")
						}
					}
				}
			})
		}
	}
}

func TestCoinGeckoRejectsCodeOptionsIdentityAndTypedInputEscapesBeforeIO(t *testing.T) {
	for _, mutate := range []func(*domain.Invocation){
		func(i *domain.Invocation) { i.Credential = domain.Credential{} },
		func(i *domain.Invocation) {
			i.Credential, _ = domain.NewCredential(domain.CredentialAPIToken, "secret", "", "", "", nil)
		},
		func(i *domain.Invocation) { i.Connection.WorkspaceID = "another-workspace" },
		func(i *domain.Invocation) { i.Connection.Provider = "exa" },
		func(i *domain.Invocation) { i.Connection.Enabled = false },
		func(i *domain.Invocation) { i.Operation.Name = "execute" },
		func(i *domain.Invocation) { i.Operation.Name = "files.coingecko.search_docs" },
		func(i *domain.Invocation) { i.Operation.Risk = domain.RiskWrite },
		func(i *domain.Invocation) {
			i.Connection.Config = json.RawMessage(`{"endpoint":"https://pro-api.coingecko.com"}`)
		},
		func(i *domain.Invocation) { i.Connection.Config = json.RawMessage(`{"api_key":"secret"}`) },
	} {
		base := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		inv := keylessInvocation(t, adapter, 0, `{"ids":["bitcoin"],"currencies":["usd"]}`)
		mutate(&inv)
		if _, err := adapter.Invoke(context.Background(), inv); err == nil || len(base.requests) != 0 {
			t.Fatal("escape reached CoinGecko")
		}
	}
	invalid := []string{`{}`, `{"ids":["ethereum"],"ids":["bitcoin"],"currencies":["usd"]}`, `{"ids":[],"currencies":["usd"]}`, `{"ids":["bitcoin","bitcoin"],"currencies":["usd"]}`,
		`{"ids":["Bitcoin"],"currencies":["usd"]}`, `{"ids":["bitcoin');evil()//"],"currencies":["usd"]}`, `{"ids":["bitcoin-usd"],"currencies":["btc"]}`,
		`{"ids":["bitcoin"],"currencies":["usd","usd"]}`, `{"ids":["bitcoin"],"currencies":["usd","eur","gbp","jpy"]}`,
		`{"ids":[{"code":"x"}],"currencies":["usd"]}`, `{"ids":["bitcoin\");evil()//"],"currencies":["usd"]}`,
		fmt.Sprintf(`{"ids":[%q],"currencies":["usd"]}`, strings.Repeat("a", 65)),
		`{"ids":["a","b","c","d","e","f","g","h","i","j","k"],"currencies":["usd"]}`,
		`{"ids":["bitcoin"],"currencies":["usd"],"connection_id":"another"}`,
		`{"ids":["bitcoin"],"currencies":["usd"],"provider":"exa"}`,
	}
	for _, field := range []string{"code", "intent", "method", "url", "path", "headers", "auth", "client_opts", "imports", "session_id", "maxRetries", "timeout"} {
		invalid = append(invalid, fmt.Sprintf(`{"ids":["bitcoin"],"currencies":["usd"],%q:"caller-controlled"}`, field))
	}
	for _, raw := range invalid {
		base := &keylessDoer{t: t}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, raw)); err == nil || len(base.requests) != 0 {
			t.Fatal("invalid typed input reached execute")
		}
	}
	base := &keylessDoer{t: t}
	adapter, _ := NewKeylessMCPAdapter("coingecko", base)
	if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{"code":"caller"}`)); err == nil || len(base.requests) != 0 {
		t.Fatal("global operation accepted arbitrary input")
	}
}

func TestCoinGeckoRejectsMalformedWrapperAndJSONWithoutTraversal(t *testing.T) {
	valid, _ := json.Marshal(coinGeckoOutput(false))
	texts := []string{
		`{"result":{"result":` + string(valid) + `}}`,
		`{"result":` + string(valid) + `,"log_lines":["private-provider-diagnostic"]}`,
		`{"result":` + string(valid) + `,"err_lines":["private-provider-diagnostic"]}`,
		`{"result":` + string(valid) + `,"extra":true}`,
		`{"schema":"wrong","data":{}}`,
		`{"schema":"openagent-coingecko-prices-v1","schema":"wrong","data":{}}`,
		`{"schema":"openagent-coingecko-prices-v1","data":{"bitcoin":{"usd":1,"usd":2,"last_updated_at":1700000000}}}`,
		`{"schema":"openagent-coingecko-prices-v1","data":{"bitcoin":{"usd":1e999,"last_updated_at":1700000000}}}`,
		string(valid) + string(valid), strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18),
		"[" + strings.Repeat("0,", 10000) + "0]",
	}
	var fields []string
	for i := 0; i < 1025; i++ {
		fields = append(fields, fmt.Sprintf(`"key%d":0`, i))
	}
	texts = append(texts, "{"+strings.Join(fields, ",")+"}")
	for _, text := range texts {
		base := &keylessDoer{t: t, result: coinGeckoTextResult(t, text)}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"ids":["bitcoin"],"currencies":["usd"]}`))
		var failure *domain.ProviderError
		if !errors.As(err, &failure) || failure.Attempts != 1 || len(base.requests) != 3 || strings.Contains(err.Error(), "private-provider-diagnostic") {
			t.Fatalf("malicious output accepted/leaked/retried: %v", err)
		}
	}
	for _, result := range []string{`{"isError":true,"content":[{"type":"text","text":"private-provider-diagnostic"}]}`, `{"content":[]}`, `{"content":[{"type":"image","data":"private"}]}`, `{"content":[{"type":"text","text":"{}"},{"type":"text","text":"{}"}]}`} {
		base := &keylessDoer{t: t, result: result}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"ids":["bitcoin"],"currencies":["usd"]}`)); err == nil || len(base.requests) != 3 {
			t.Fatal("invalid MCP output accepted")
		}
	}
}

func TestCoinGeckoValidatesPricesAndGlobalDataNotHTTP200(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["data"] = map[string]any{} },
		func(p map[string]any) { p["data"].(map[string]any)["ethereum"] = map[string]any{"usd": 1} },
		func(p map[string]any) { delete(p["data"].(map[string]any)["bitcoin"].(map[string]any), "usd") },
		func(p map[string]any) { p["data"].(map[string]any)["bitcoin"].(map[string]any)["usd"] = -1 },
		func(p map[string]any) { p["data"].(map[string]any)["bitcoin"].(map[string]any)["usd"] = "1" },
		func(p map[string]any) {
			delete(p["data"].(map[string]any)["bitcoin"].(map[string]any), "last_updated_at")
		},
		func(p map[string]any) {
			p["data"].(map[string]any)["bitcoin"].(map[string]any)["last_updated_at"] = 1.5
		},
	} {
		payload := coinGeckoOutput(false)
		mutate(payload)
		base := &keylessDoer{t: t, result: coinGeckoResultJSON(t, payload)}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, `{"ids":["bitcoin"],"currencies":["usd"]}`)); err == nil || len(base.requests) != 3 {
			t.Fatal("missing/invalid price succeeded")
		}
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { delete(d, "updated_at") }, func(d map[string]any) { d["updated_at"] = -1 },
		func(d map[string]any) { d["markets"] = -1 }, func(d map[string]any) { d["markets"] = 1.5 },
		func(d map[string]any) { d["total_market_cap"] = map[string]any{} }, func(d map[string]any) { d["total_volume"] = map[string]any{"usd": "1"} },
		func(d map[string]any) { d["market_cap_percentage"] = map[string]any{"btc": -1} }, func(d map[string]any) { d["unexpected"] = true },
	} {
		payload := coinGeckoOutput(true)
		mutate(payload["data"].(map[string]any)["data"].(map[string]any))
		base := &keylessDoer{t: t, result: coinGeckoResultJSON(t, payload)}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{}`)); err == nil || len(base.requests) != 3 {
			t.Fatal("invalid global data succeeded")
		}
	}
}

// Regression for an actual global-response ticker rejected by the initial
// candidate. It must not broaden request identifiers or currency-map keys.
func TestCoinGeckoGlobalTickerUnderscoresRemainOutputOnly(t *testing.T) {
	for _, ticker := range []string{"figr_heloc", "figr-heloc"} {
		payload := coinGeckoOutput(true)
		payload["data"].(map[string]any)["data"].(map[string]any)["market_cap_percentage"] = map[string]any{ticker: 1.25}
		base := &keylessDoer{t: t, result: coinGeckoResultJSON(t, payload)}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{}`)); err != nil || len(base.requests) != 3 {
			t.Fatal("valid provider ticker rejected")
		}
	}
	if coinGeckoList([]any{"figr_heloc"}, false) {
		t.Fatal("output ticker broadened request coin identifiers")
	}
	for _, field := range []string{"total_market_cap", "total_volume", "market_cap_percentage"} {
		for _, key := range []string{"btc/path", "btc\nheader", "_btc", "btc_", strings.Repeat("a", 65)} {
			payload := coinGeckoOutput(true)
			payload["data"].(map[string]any)["data"].(map[string]any)[field] = map[string]any{key: 1.25}
			base := &keylessDoer{t: t, result: coinGeckoResultJSON(t, payload)}
			adapter, _ := NewKeylessMCPAdapter("coingecko", base)
			if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{}`)); err == nil {
				t.Fatal("invalid output key accepted")
			}
		}
		if field == "market_cap_percentage" {
			continue
		}
		payload := coinGeckoOutput(true)
		payload["data"].(map[string]any)["data"].(map[string]any)[field] = map[string]any{"figr_heloc": 1.25}
		base := &keylessDoer{t: t, result: coinGeckoResultJSON(t, payload)}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{}`)); err == nil {
			t.Fatal("ticker rule broadened output currency keys")
		}
	}
}

func TestCoinGeckoTransportBoundsDuplicateEnvelopeAndQuotaNoReplay(t *testing.T) {
	for _, mutate := range []func(*http.Response){
		func(r *http.Response) { r.Header.Set("MCP-Session-Id", strings.Repeat("x", 257)) },
		func(r *http.Response) { r.Header.Set("MCP-Session-Id", "session\r\nAuthorization: secret") },
		func(r *http.Response) {
			r.StatusCode = 307
			r.Header.Set("Location", "https://pro-api.coingecko.com/mcp")
		},
		func(r *http.Response) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", coinGeckoMaxResponse+1)))
		},
		func(r *http.Response) {
			r.Body = io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":"wrong","id":"invocation-one:initialize","result":{"protocolVersion":"2025-06-18"}}`))
		},
	} {
		base := &keylessDoer{t: t}
		doer := keylessResponseDoer(func(req *http.Request) (*http.Response, error) {
			response, err := base.Do(req)
			mutate(response)
			return response, err
		})
		adapter, _ := NewKeylessMCPAdapter("coingecko", doer)
		if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{}`)); err == nil || len(base.requests) != 1 {
			t.Fatal("unsafe transport retried or accepted")
		}
	}
	for _, method := range []string{"initialize", "tools/call"} {
		base := &keylessDoer{t: t, quota: true, quotaMethod: method}
		adapter, _ := NewKeylessMCPAdapter("coingecko", base)
		_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{}`))
		var failure *domain.ProviderError
		count := 1
		if method == "tools/call" {
			count = 3
		}
		if !errors.As(err, &failure) || failure.StatusCode != 429 || failure.Attempts != 1 || len(base.requests) != count {
			t.Fatalf("quota was retried or upgraded: %v", err)
		}
	}
}

func TestCoinGeckoPaymentRequiredCannotTriggerFallback(t *testing.T) {
	base := &keylessDoer{t: t, quota: true}
	doer := keylessResponseDoer(func(request *http.Request) (*http.Response, error) {
		response, err := base.Do(request)
		response.StatusCode = http.StatusPaymentRequired
		return response, err
	})
	adapter, _ := NewKeylessMCPAdapter("coingecko", doer)
	_, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 1, `{}`))
	var failure *domain.ProviderError
	if !errors.As(err, &failure) || failure.StatusCode != 402 || failure.Attempts != 1 || len(base.requests) != 1 {
		t.Fatal("payment-required response was retried or replaced")
	}
}

func TestCoinGeckoMaximumTypedBatchRemainsOneCompiledRead(t *testing.T) {
	ids := []any{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	currencies := []any{"usd", "eur", "gbp"}
	data := map[string]any{}
	for _, id := range ids {
		data[id.(string)] = map[string]any{"usd": 1, "eur": 2, "gbp": 3, "last_updated_at": 1700000000}
	}
	base := &keylessDoer{t: t, result: coinGeckoResultJSON(t, map[string]any{"schema": "openagent-coingecko-prices-v1", "data": data})}
	adapter, _ := NewKeylessMCPAdapter("coingecko", base)
	raw, err := json.Marshal(map[string]any{"ids": ids, "currencies": currencies})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Invoke(context.Background(), keylessInvocation(t, adapter, 0, string(raw))); err != nil || len(base.requests) != 3 {
		t.Fatalf("maximum typed batch: %v", err)
	}
	params := base.calls[2]["params"].(map[string]any)
	code := params["arguments"].(map[string]any)["code"].(string)
	if strings.Count(code, ".get(") != 1 || !strings.Contains(code, `"ids":"a,b,c,d,e,f,g,h,i,j"`) || !strings.Contains(code, `"vs_currencies":"usd,eur,gbp"`) {
		t.Fatal("typed batch introduced a second SDK call or non-JSON interpolation")
	}
}
