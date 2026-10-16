package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) { return function(request) }

func TestBuiltInManifestConformance(t *testing.T) {
	t.Parallel()
	seenProviders := make(map[string]bool)
	for _, manifest := range Manifests() {
		if seenProviders[manifest.Provider] {
			t.Fatalf("duplicate provider %q", manifest.Provider)
		}
		seenProviders[manifest.Provider] = true
		manifest := manifest
		t.Run(manifest.Provider, func(t *testing.T) {
			t.Parallel()
			if err := manifest.validate(); err != nil {
				t.Fatalf("manifest validation failed: %v", err)
			}
			adapter, err := NewHTTPAdapterWithOptions(manifest, successDoer(), AdapterOptions{ShopifyThemeWritesEnabled: true})
			if err != nil {
				t.Fatalf("NewHTTPAdapter: %v", err)
			}
			if _, ok := any(adapter).(domain.ActionPreviewer); !ok {
				t.Fatal("adapter must provide pre-approval action previews")
			}
			operations := adapter.Operations()
			if len(operations) != len(manifest.Operations) {
				t.Fatalf("manifest has %d operations, adapter exposes %d", len(manifest.Operations), len(operations))
			}
			exposed := make(map[string]domain.Operation, len(operations))
			for _, operation := range operations {
				if err := operation.Validate(); err != nil {
					t.Errorf("operation %s is not domain-valid: %v", operation.Name, err)
				}
				exposed[operation.Name] = operation
			}

			rawCount := 0
			for _, specification := range manifest.Operations {
				operation, exists := exposed[specification.Name]
				if !exists {
					t.Errorf("manifest operation %q is unreachable", specification.Name)
					continue
				}
				arguments := conformanceArguments(specification)
				invocation := testInvocation(t, manifest, operation, arguments)
				preview, previewErr := adapter.Preview(invocation)
				if previewErr != nil {
					t.Errorf("operation %q cannot build a validated request: %v", specification.Name, previewErr)
				}
				if preview.Method == "" || preview.Path == "" {
					t.Errorf("operation %q produced an empty preview", specification.Name)
				}
				if specification.Raw != nil {
					rawCount++
					if operation.Mode != domain.OperationRaw {
						t.Errorf("raw operation %q is not marked raw", specification.Name)
					}
				} else if operation.Mode != domain.OperationTyped {
					t.Errorf("typed operation %q is not marked typed", specification.Name)
				}
			}
			wantRaw := 1
			if manifest.ReadOnly || manifest.TypedOnly {
				wantRaw = 0
			}
			if rawCount != wantRaw {
				t.Fatalf("provider has %d raw escape operations; want %d", rawCount, wantRaw)
			}
		})
	}
}

func TestProviderSetupAndUploadCopyIsNeutralAndExact(t *testing.T) {
	t.Parallel()
	const uploadDescription = "One in-memory payload, at most 16 MiB before base64 encoding"
	var uploadSchema struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(driveUploadSchema(false), &uploadSchema); err != nil {
		t.Fatalf("decode Drive upload schema: %v", err)
	}
	if got := uploadSchema.Properties["content_base64"].Description; got != uploadDescription {
		t.Fatalf("content_base64 description = %q, want %q", got, uploadDescription)
	}

	flags := DirectAdsFeatureFlags()
	if len(flags) != 2 {
		t.Fatalf("direct Ads flags = %d, want 2", len(flags))
	}
	var metaDescription string
	for _, flag := range flags {
		if flag.Key == FeatureDirectMetaAds {
			metaDescription = flag.Description
		}
		for _, forbidden := range []string{
			"beta", "experimental", "incomplete", "test access", "coming soon",
			"under review", "app review", "provider review",
			"production review", "reviewed provider",
		} {
			if strings.Contains(strings.ToLower(flag.Description), forbidden) {
				t.Fatalf("feature %s exposes misleading copy %q", flag.Key, flag.Description)
			}
		}
	}
	if metaDescription != "Direct Meta Marketing API adapter (provider setup required)" {
		t.Fatalf("Meta feature description = %q", metaDescription)
	}
}

func TestRawEscapesRejectURLOriginVersionMethodAndCredentialOverrides(t *testing.T) {
	t.Parallel()
	for _, manifest := range Manifests() {
		if manifest.ReadOnly || manifest.TypedOnly {
			continue // Read-only providers intentionally offer no raw operation.
		}
		manifest := manifest
		t.Run(manifest.Provider, func(t *testing.T) {
			t.Parallel()
			adapter, err := NewHTTPAdapter(manifest, successDoer())
			if err != nil {
				t.Fatal(err)
			}
			var rawOperation domain.Operation
			var rawSpec OperationManifest
			for _, specification := range manifest.Operations {
				if specification.Raw != nil {
					rawSpec = specification
				}
			}
			for _, operation := range adapter.Operations() {
				if operation.Name == rawSpec.Name {
					rawOperation = operation
				}
			}
			validPath := rawSpec.Raw.PathPrefixes[0]
			if strings.HasSuffix(validPath, "/") {
				validPath += "resource"
			}
			validMethod := rawSpec.Raw.Methods[0]
			cases := map[string]map[string]any{
				"arbitrary URL field": {"method": validMethod, "path": validPath, "url": "https://attacker.invalid"},
				"absolute URL path":   {"method": validMethod, "path": "https://attacker.invalid/steal"},
				"network path":        {"method": validMethod, "path": "//attacker.invalid/steal"},
				"traversal":           {"method": validMethod, "path": validPath + "/../steal"},
				"encoded traversal":   {"method": validMethod, "path": validPath + "/%2e%2e/steal"},
				"wrong API version":   {"method": validMethod, "path": "/v0/steal"},
				"unsafe method":       {"method": "CONNECT", "path": validPath},
				"credential query":    {"method": validMethod, "path": validPath, "query": map[string]any{"access_token": "stolen"}},
				"arbitrary headers":   {"method": validMethod, "path": validPath, "headers": map[string]string{"Authorization": "stolen"}},
			}
			for name, arguments := range cases {
				t.Run(name, func(t *testing.T) {
					encoded, _ := json.Marshal(arguments)
					invocation := testInvocation(t, manifest, rawOperation, encoded)
					if _, previewErr := adapter.Preview(invocation); !errors.Is(previewErr, domain.ErrInvalidArguments) {
						t.Fatalf("Preview error = %v, want ErrInvalidArguments", previewErr)
					}
				})
			}
		})
	}
}

func TestFixedOriginCredentialAndReservedArguments(t *testing.T) {
	t.Parallel()
	manifest := driveManifest()
	var captured *http.Request
	doer := doerFunc(func(request *http.Request) (*http.Response, error) {
		captured = request.Clone(context.Background())
		return jsonResponse(http.StatusOK, `{"files":[]}`, map[string]string{"X-Request-ID": "provider-1"}), nil
	})
	adapter, err := NewHTTPAdapter(manifest, doer)
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "files.drive.search")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"connection_id":"conn-1","provider":"google_drive","query":"name contains 'report'","page_size":50,"headers":{"Authorization":"evil"}}`))
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if captured.URL.Scheme != "https" || captured.URL.Host != "www.googleapis.com" || captured.URL.Path != "/drive/v3/files" {
		t.Fatalf("unexpected fixed target: %s", captured.URL)
	}
	if got := captured.Header.Get("Authorization"); got != "Bearer provider-secret" {
		t.Fatalf("Authorization = %q", got)
	}
	if captured.Header.Get("X-OpenAgent-Workspace-ID") != "" || captured.Header.Get("Cookie") != "" {
		t.Fatal("identity or ambient credential header reached provider")
	}
	if got := captured.URL.Query().Get("q"); got != "name contains 'report'" {
		t.Fatalf("q = %q", got)
	}
	if captured.URL.Query().Get("connection_id") != "" || captured.URL.Query().Get("provider") != "" {
		t.Fatal("OpenAgent routing arguments reached provider")
	}
	if result.ProviderID != "provider-1" || result.Attempts != 1 || result.ProviderStatus != http.StatusOK {
		t.Fatalf("unexpected result metadata: %+v", result)
	}
}

func TestShopifyDomainIsStrictAndCredentialUsesFixedHeader(t *testing.T) {
	t.Parallel()
	manifest := shopifyManifest()
	var calls int
	doer := doerFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host != "snow-globe.myshopify.com" {
			t.Fatalf("unexpected Shopify host %q", request.URL.Host)
		}
		if got := request.Header.Get("X-Shopify-Access-Token"); got != "provider-secret" {
			t.Fatalf("Shopify token header = %q", got)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("Shopify credential was copied to Authorization")
		}
		return jsonResponse(http.StatusOK, `{"data":{"products":{"nodes":[]}}}`, nil), nil
	})
	adapter, err := NewHTTPAdapter(manifest, doer)
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "commerce.shopify.products.list")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"first":10}`))
	invocation.Connection.ExternalID = "snow-globe.myshopify.com"
	invocation.Connection.Config = json.RawMessage(`{}`)
	invocation.Credential = credential(t, "X-Shopify-Access-Token", "")
	if _, err := adapter.Invoke(context.Background(), invocation); err != nil {
		t.Fatalf("valid Shopify call: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	matchingLegacy := invocation
	matchingLegacy.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com"}`)
	if _, previewErr := adapter.Preview(matchingLegacy); previewErr != nil {
		t.Fatalf("matching legacy shop_domain: %v", previewErr)
	}
	mismatchedLegacy := invocation
	mismatchedLegacy.Connection.Config = json.RawMessage(`{"shop_domain":"other.myshopify.com"}`)
	if _, previewErr := adapter.Preview(mismatchedLegacy); !errors.Is(previewErr, domain.ErrInvalidArguments) {
		t.Fatalf("mismatched legacy shop_domain error = %v", previewErr)
	}

	invalid := []string{
		"myshopify.com", "HTTPS://snow.myshopify.com", "snow.myshopify.com.evil.test",
		"snow.myshopify.com:443", "https://snow.myshopify.com", "SNOW.myshopify.com",
		"snow..myshopify.com", "-snow.myshopify.com", "snow.myshopify.com.", "127.0.0.1",
	}
	for _, host := range invalid {
		t.Run(host, func(t *testing.T) {
			candidate := invocation
			candidate.Connection.ExternalID = host
			if _, previewErr := adapter.Preview(candidate); !errors.Is(previewErr, domain.ErrInvalidArguments) {
				t.Fatalf("Preview error = %v", previewErr)
			}
		})
	}
}

func TestPostizUsesRawAPIKeyWithoutBearerScheme(t *testing.T) {
	t.Parallel()
	manifest := postizManifest()
	var authorization string
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		authorization = request.Header.Get("Authorization")
		return jsonResponse(http.StatusOK, `{"posts":[],"echo":"pos_live_secret"}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "social.postiz.posts.list")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"start_date":"2026-06-01T00:00:00Z","end_date":"2026-07-01T00:00:00Z"}`))
	invocation.Credential = credentialWithSecret(t, "pos_live_secret", "Authorization", "")
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "pos_live_secret" || strings.HasPrefix(authorization, "Bearer ") {
		t.Fatalf("Postiz Authorization header = %q", authorization)
	}
	encoded, _ := json.Marshal(result.Data)
	if strings.Contains(string(encoded), "pos_live_secret") || !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("Postiz response leaked API key: %s", encoded)
	}
}

func TestPipeboardUsesOnlyConfiguredEndpointAndStandardMCP(t *testing.T) {
	t.Parallel()
	manifest := pipeboardManifest()
	var hosts []string
	var methods []string
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		hosts = append(hosts, request.URL.Host)
		var rpcRequest struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		_ = json.NewDecoder(request.Body).Decode(&rpcRequest)
		methods = append(methods, rpcRequest.Method)
		response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": rpcRequest.ID, "result": map[string]any{"content": []any{}}})
		return jsonResponse(http.StatusOK, string(response), nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "ads.pipeboard.accounts.list")
	for endpoint, expectedHost := range map[string]string{
		"meta_ads": "meta-ads.mcp.pipeboard.co", "google_ads": "google-ads.mcp.pipeboard.co",
	} {
		invocation := testInvocation(t, manifest, operation, json.RawMessage(`{}`))
		invocation.Connection.Config, _ = json.Marshal(map[string]string{"ads_provider": endpoint})
		if _, err := adapter.Invoke(context.Background(), invocation); err != nil {
			t.Fatalf("%s invoke: %v", endpoint, err)
		}
		if hosts[len(hosts)-1] != expectedHost || methods[len(methods)-1] != "tools/call" {
			t.Fatalf("endpoint=%s host=%s rpc=%s", endpoint, hosts[len(hosts)-1], methods[len(methods)-1])
		}
	}
	before := len(hosts)
	for _, configuration := range []json.RawMessage{
		json.RawMessage(`{"ads_provider":"https://attacker.invalid"}`),
		json.RawMessage(`{"ads_provider":"unknown_ads"}`),
		json.RawMessage(`{"ads_provider":"meta_ads","url":"https://attacker.invalid"}`),
	} {
		invocation := testInvocation(t, manifest, operation, json.RawMessage(`{}`))
		invocation.Connection.Config = configuration
		if strings.Contains(string(configuration), `"url"`) {
			// Extra config is harmless: the adapter still uses the hardcoded enum
			// endpoint and never reads the URL field.
			if _, err := adapter.Invoke(context.Background(), invocation); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("unsafe Pipeboard config accepted: %s err=%v", configuration, err)
		}
	}
	if len(hosts) != before+1 || hosts[len(hosts)-1] != "meta-ads.mcp.pipeboard.co" {
		t.Fatalf("untrusted config controlled endpoint: %v", hosts)
	}

	raw := findOperation(t, adapter, "ads.pipeboard.raw")
	validRaw := testInvocation(t, manifest, raw, json.RawMessage(`{"method":"POST","path":"/","body":{"jsonrpc":"2.0","id":"raw-1","method":"tools/list","params":{}}}`))
	validRaw.Connection.Config = json.RawMessage(`{"ads_provider":"meta_ads"}`)
	if _, err := adapter.Preview(validRaw); err != nil {
		t.Fatalf("standard MCP raw rejected: %v", err)
	}
	for _, arguments := range []json.RawMessage{
		json.RawMessage(`{"method":"POST","path":"/mcp","body":{"jsonrpc":"2.0","id":1,"method":"tools/list"}}`),
		json.RawMessage(`{"method":"POST","path":"/","body":{"jsonrpc":"2.0","id":1,"method":"resources/list"}}`),
		json.RawMessage(`{"method":"POST","path":"/","body":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bad tool","arguments":{}}}}`),
	} {
		candidate := validRaw
		candidate.Arguments = arguments
		if _, err := adapter.Preview(candidate); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("unsafe raw MCP accepted: %s err=%v", arguments, err)
		}
	}
}

func TestShopifyThemeWritesRequirePlatformAndConnectionFlags(t *testing.T) {
	t.Parallel()
	manifest := shopifyManifest()
	var calls int
	doer := doerFunc(func(_ *http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(http.StatusOK, `{"data":{}}`, nil), nil
	})
	adapter, err := NewHTTPAdapter(manifest, doer)
	if err != nil {
		t.Fatal(err)
	}
	graphqlPath := "/admin/api/" + ShopifyAPIVersion + "/graphql.json"

	read := findOperation(t, adapter, "commerce.shopify.theme_files.get")
	readInvocation := testInvocation(t, manifest, read, json.RawMessage(`{"theme_id":"gid://shopify/OnlineStoreTheme/123","asset_key":"templates/index.json"}`))
	readInvocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com"}`)
	if preview, previewErr := adapter.Preview(readInvocation); previewErr != nil {
		t.Fatalf("theme reads must remain enabled: %v", previewErr)
	} else if preview.Method != http.MethodPost || preview.Path != graphqlPath {
		t.Fatalf("theme read used non-GraphQL transport: %#v", preview)
	}

	writeNames := []string{"commerce.shopify.themes.publish", "commerce.shopify.theme_files.write", "commerce.shopify.theme_files.delete"}
	writeArguments := map[string]json.RawMessage{
		"commerce.shopify.themes.publish":     json.RawMessage(`{"theme_id":"gid://shopify/OnlineStoreTheme/123"}`),
		"commerce.shopify.theme_files.write":  json.RawMessage(`{"theme_id":"gid://shopify/OnlineStoreTheme/123","files":[{"filename":"templates/index.json","body":{"type":"TEXT","value":"safe"}}]}`),
		"commerce.shopify.theme_files.delete": json.RawMessage(`{"theme_id":"gid://shopify/OnlineStoreTheme/123","files":["templates/index.json"]}`),
	}
	for _, name := range writeNames {
		t.Run(name, func(t *testing.T) {
			operation := findOperation(t, adapter, name)
			invocation := testInvocation(t, manifest, operation, writeArguments[name])
			invocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com"}`)
			if _, previewErr := adapter.Preview(invocation); !errors.Is(previewErr, domain.ErrUnsupported) {
				t.Fatalf("disabled Preview error = %v", previewErr)
			}
			if _, invokeErr := adapter.Invoke(context.Background(), invocation); !errors.Is(invokeErr, domain.ErrUnsupported) {
				t.Fatalf("disabled Invoke error = %v", invokeErr)
			}

			invocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com","theme_writes_enabled":true}`)
			if _, previewErr := adapter.Preview(invocation); !errors.Is(previewErr, domain.ErrUnsupported) {
				t.Fatalf("tenant flag bypassed disabled platform gate: %v", previewErr)
			}
			if _, invokeErr := adapter.Invoke(context.Background(), invocation); !errors.Is(invokeErr, domain.ErrUnsupported) {
				t.Fatalf("tenant flag bypassed disabled platform gate during invoke: %v", invokeErr)
			}
		})
	}

	raw := findOperation(t, adapter, "commerce.shopify.raw")
	rawInvocation := testInvocation(t, manifest, raw, json.RawMessage(`{"method":"POST","path":"/admin/api/2026-07/graphql.json","body":{"query":"mutation ThemePublish($id: ID!) { themePublish(id: $id) { theme { id } } }","variables":{"id":"gid://shopify/OnlineStoreTheme/123"}}}`))
	rawInvocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com"}`)
	if _, previewErr := adapter.Preview(rawInvocation); !errors.Is(previewErr, domain.ErrUnsupported) {
		t.Fatalf("raw GraphQL theme write bypassed gate: %v", previewErr)
	}
	rawInvocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com","theme_writes_enabled":true}`)
	if _, previewErr := adapter.Preview(rawInvocation); !errors.Is(previewErr, domain.ErrUnsupported) {
		t.Fatalf("raw GraphQL theme write bypassed disabled platform gate with tenant flag: %v", previewErr)
	}
	graphql := findOperation(t, adapter, "commerce.shopify.graphql")
	graphqlInvocation := testInvocation(t, manifest, graphql, json.RawMessage(`{"body":{"query":"mutation ThemePublish($id: ID!) { themePublish(id: $id) { theme { id } } }","variables":{"id":"gid://shopify/OnlineStoreTheme/123"}}}`))
	graphqlInvocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com","theme_writes_enabled":true}`)
	if _, previewErr := adapter.Preview(graphqlInvocation); !errors.Is(previewErr, domain.ErrUnsupported) {
		t.Fatalf("arbitrary GraphQL theme mutation bypassed disabled platform gate: %v", previewErr)
	}

	enabledAdapter, err := NewHTTPAdapterWithOptions(manifest, doer, AdapterOptions{ShopifyThemeWritesEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range writeNames {
		operation := findOperation(t, enabledAdapter, name)
		invocation := testInvocation(t, manifest, operation, writeArguments[name])
		invocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com"}`)
		if _, previewErr := enabledAdapter.Preview(invocation); !errors.Is(previewErr, domain.ErrUnsupported) {
			t.Fatalf("%s bypassed disabled tenant gate: %v", name, previewErr)
		}
		invocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com","theme_writes_enabled":true}`)
		if _, previewErr := enabledAdapter.Preview(invocation); previewErr != nil {
			t.Fatalf("%s with both gates enabled Preview: %v", name, previewErr)
		}
		if _, invokeErr := enabledAdapter.Invoke(context.Background(), invocation); invokeErr != nil {
			t.Fatalf("%s with both gates enabled Invoke: %v", name, invokeErr)
		}
	}
	rawInvocation = testInvocation(t, manifest, findOperation(t, enabledAdapter, "commerce.shopify.raw"), json.RawMessage(`{"method":"POST","path":"/admin/api/2026-07/graphql.json","body":{"query":"mutation ThemePublish($id: ID!) { themePublish(id: $id) { theme { id } } }","variables":{"id":"gid://shopify/OnlineStoreTheme/123"}}}`))
	rawInvocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com"}`)
	if _, previewErr := enabledAdapter.Preview(rawInvocation); !errors.Is(previewErr, domain.ErrUnsupported) {
		t.Fatalf("globally enabled raw GraphQL write bypassed tenant gate: %v", previewErr)
	}
	rawInvocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com","theme_writes_enabled":true}`)
	if _, previewErr := enabledAdapter.Preview(rawInvocation); previewErr != nil {
		t.Fatalf("raw GraphQL theme write with both gates enabled Preview: %v", previewErr)
	}
	if _, invokeErr := enabledAdapter.Invoke(context.Background(), rawInvocation); invokeErr != nil {
		t.Fatalf("raw GraphQL theme write with both gates enabled Invoke: %v", invokeErr)
	}
	graphqlInvocation = testInvocation(t, manifest, findOperation(t, enabledAdapter, "commerce.shopify.graphql"), json.RawMessage(`{"body":{"query":"mutation ThemePublish($id: ID!) { themePublish(id: $id) { theme { id } } }","variables":{"id":"gid://shopify/OnlineStoreTheme/123"}}}`))
	graphqlInvocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com"}`)
	if _, previewErr := enabledAdapter.Preview(graphqlInvocation); !errors.Is(previewErr, domain.ErrUnsupported) {
		t.Fatalf("globally enabled GraphQL theme mutation bypassed tenant gate: %v", previewErr)
	}
	graphqlInvocation.Connection.Config = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com","theme_writes_enabled":true}`)
	if _, previewErr := enabledAdapter.Preview(graphqlInvocation); previewErr != nil {
		t.Fatalf("GraphQL theme mutation with both gates enabled Preview: %v", previewErr)
	}
	if calls != 4 {
		t.Fatalf("provider calls = %d, want only the four writes with both gates enabled", calls)
	}
}

func TestWritesRetryOnlyWithIdempotencyAndOmitRetiredSyncMetadata(t *testing.T) {
	t.Parallel()
	manifest := postizManifest()
	var mu sync.Mutex
	calls := 0
	seenKeys := []string{}
	doer := doerFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		seenKeys = append(seenKeys, request.Header.Get("Idempotency-Key"))
		if calls == 1 {
			return jsonResponse(http.StatusServiceUnavailable, `{"error":"temporary"}`, nil), nil
		}
		return jsonResponse(http.StatusOK, `{"id":"post-1"}`, nil), nil
	})
	adapter, err := NewHTTPAdapter(manifest, doer)
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error { return nil }
	operation := findOperation(t, adapter, "social.postiz.posts.create")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"type":"schedule","date":"2026-07-23T12:00:00Z","shortLink":false,"tags":[],"posts":[{"integration":{"id":"integration-1"},"value":[{"content":"hello","image":[]}],"settings":{"__type":"bluesky"}}]}`))
	invocation.Idempotency = "gp-stable-key"
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls != 2 || result.Attempts != 2 || len(seenKeys) != 2 || seenKeys[0] != "gp-stable-key" || seenKeys[1] != "gp-stable-key" {
		t.Fatalf("retry observations: calls=%d attempts=%d keys=%v", calls, result.Attempts, seenKeys)
	}
	if result.Metadata["idempotency_applied"] != "true" {
		t.Fatalf("missing retry metadata: %+v", result.Metadata)
	}
	for _, retired := range []string{"sync_strategy", "sync_resource", "sync_cursor_field", "webhook_capable"} {
		if _, found := result.Metadata[retired]; found {
			t.Fatalf("retired sync metadata %q remains: %+v", retired, result.Metadata)
		}
	}

	calls = 0
	seenKeys = nil
	invocation.Idempotency = ""
	_, err = adapter.Invoke(context.Background(), invocation)
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Attempts != 1 || calls != 1 {
		t.Fatalf("non-idempotent write retried or returned wrong error: calls=%d err=%v", calls, err)
	}
}

func TestReadOperationUsingPOSTRetriesWithoutIdempotency(t *testing.T) {
	t.Parallel()
	manifest := shopifyManifest()
	var calls int
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(_ *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(http.StatusServiceUnavailable, `{}`, nil), nil
		}
		return jsonResponse(http.StatusOK, `{"data":{"products":{"nodes":[]}}}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error { return nil }
	operation := findOperation(t, adapter, "commerce.shopify.products.list")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"first":10}`))
	invocation.Idempotency = ""
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls != 2 || result.Attempts != 2 || result.Metadata["idempotency_applied"] != "false" {
		t.Fatalf("calls=%d result=%+v", calls, result)
	}
}

func TestCredentialBindingFailsClosedAndProviderBodyIsRedacted(t *testing.T) {
	t.Parallel()
	manifest := driveManifest()
	var calls int
	doer := doerFunc(func(_ *http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(http.StatusOK, `{"echo":"provider-secret"}`, nil), nil
	})
	adapter, err := NewHTTPAdapter(manifest, doer)
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "files.drive.search")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{}`))
	wrongCredential, credentialErr := domain.NewCredential(domain.CredentialOAuth2Bearer, "provider-secret", "X-Evil", "Bearer", "v1", nil)
	if credentialErr != nil {
		t.Fatal(credentialErr)
	}
	invocation.Credential = wrongCredential
	_, err = adapter.Invoke(context.Background(), invocation)
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "credential_error" || calls != 0 || strings.Contains(err.Error(), "provider-secret") {
		t.Fatalf("credential mismatch did not fail closed: calls=%d err=%v", calls, err)
	}

	invocation.Credential = credential(t, "Authorization", "Bearer")
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result.Data)
	if strings.Contains(string(encoded), "provider-secret") || !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("credential was not redacted from provider response: %s", encoded)
	}
}

func TestResponseBodyBoundAndPermissionClassification(t *testing.T) {
	t.Parallel()
	manifest := driveManifest()
	manifest.MaxResponseBytes = 4
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, "12345", nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "files.drive.search")
	_, err = adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, json.RawMessage(`{}`)))
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "response_too_large" {
		t.Fatalf("error = %v", err)
	}

	manifest.MaxResponseBytes = defaultMaxResponseBytes
	adapter, err = NewHTTPAdapter(manifest, doerFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusForbidden, `{"error":"scope"}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation = findOperation(t, adapter, "files.drive.search")
	_, err = adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, json.RawMessage(`{}`)))
	if !errors.Is(err, domain.ErrProviderPermission) || !errors.As(err, &providerErr) || providerErr.StatusCode != http.StatusForbidden {
		t.Fatalf("permission error = %v", err)
	}
}

func TestDirectAdsFlagsAreOffByDefault(t *testing.T) {
	t.Parallel()
	flags := DirectAdsFeatureFlags()
	if len(flags) != 2 {
		t.Fatalf("flags = %d", len(flags))
	}
	seen := map[string]bool{}
	for _, flag := range flags {
		if flag.DefaultEnabled || flag.Capability != domain.Ads || flag.Key == "" || seen[flag.Key] {
			t.Fatalf("invalid direct ads feature flag: %+v", flag)
		}
		seen[flag.Key] = true
	}
}

func TestProductionTransportDisablesEnvironmentProxyAndRedirects(t *testing.T) {
	t.Parallel()
	client, ok := secureHTTPDoer().(*http.Client)
	if !ok {
		t.Fatal("production doer is not an http.Client")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("production transport must not consult environment proxies")
	}
	if redirectErr := client.CheckRedirect(&http.Request{}, nil); !errors.Is(redirectErr, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v", redirectErr)
	}
}

func TestFixedOriginsRejectInternalAndAmbiguousHosts(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{
		"https://127.0.0.1", "https://[::1]", "https://localhost", "https://control-plane.svc",
		"https://metadata.google.internal", "https://user@example.com", "https://example.com:443",
		"http://example.com", "https://example.com/path", "https://EXAMPLE.com",
	} {
		t.Run(origin, func(t *testing.T) {
			manifest := driveManifest()
			manifest.Origin = origin
			if _, err := NewHTTPAdapter(manifest, successDoer()); err == nil {
				t.Fatalf("unsafe origin %q was accepted", origin)
			}
		})
	}
}

func conformanceArguments(specification OperationManifest) json.RawMessage {
	if strings.HasPrefix(specification.Name, "social.slack_import.") {
		arguments := map[string]any{}
		for _, required := range specification.Required {
			switch required {
			case "channel":
				arguments[required] = "C012ABCDE9"
			case "user":
				arguments[required] = "U012ABCDE9"
			case "ts":
				arguments[required] = "1482960137.003543"
			case "body":
				body := map[string]any{"channel": "C012ABCDE9"}
				if specification.Name != "social.slack_import.chat.post_message" {
					body["ts"] = "1482960137.003543"
				}
				if specification.Name != "social.slack_import.chat.delete" {
					body["text"] = "Conformance message"
				}
				arguments[required] = body
			}
		}
		data, _ := json.Marshal(arguments)
		return data
	}
	if strings.HasPrefix(specification.Name, "files.atlassian.") {
		arguments := map[string]any{}
		for _, required := range specification.Required {
			switch required {
			case "project_id_or_key":
				arguments[required] = "ALPHA"
			case "issue_id_or_key":
				arguments[required] = "ALPHA-12"
			case "jql":
				arguments[required] = "project = ALPHA"
			}
		}
		switch specification.Name {
		case "files.atlassian.issues.create":
			arguments["body"] = map[string]any{"fields": map[string]any{"project": map[string]any{"key": "ALPHA"}, "issuetype": map[string]any{"id": "10001"}, "summary": "Conformance issue"}}
		case "files.atlassian.issues.update":
			arguments["body"] = map[string]any{"fields": map[string]any{"summary": "Conformance update"}}
		case "files.atlassian.issue_comments.create":
			arguments["body"] = map[string]any{"body": map[string]any{"version": 1, "type": "doc", "content": []any{map[string]any{"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": "Conformance comment"}}}}}}
		}
		data, _ := json.Marshal(arguments)
		return data
	}
	if strings.HasPrefix(specification.Name, "files.notion.") {
		id := "b55c9c91-384d-452b-81db-d1ef79372b75"
		arguments := map[string]any{}
		for _, match := range pathTemplatePattern.FindAllStringSubmatch(specification.Path, -1) {
			arguments[match[1]] = id
		}
		switch specification.Name {
		case "files.notion.search":
			arguments["body"] = map[string]any{}
		case "files.notion.pages.create":
			arguments["body"] = map[string]any{"parent": map[string]any{"page_id": id}, "properties": map[string]any{"title": map[string]any{"title": []any{map[string]any{"type": "text", "text": map[string]any{"content": "Conformance"}}}}}}
		case "files.notion.pages.update":
			arguments["body"] = map[string]any{"properties": map[string]any{"title": map[string]any{"title": []any{map[string]any{"type": "text", "text": map[string]any{"content": "Conformance"}}}}}}
		case "files.notion.blocks.children.append":
			arguments["body"] = map[string]any{"children": []any{map[string]any{"type": "paragraph", "paragraph": map[string]any{"rich_text": []any{map[string]any{"type": "text", "text": map[string]any{"content": "Conformance"}}}}}}}
		}
		data, _ := json.Marshal(arguments)
		return data
	}
	arguments := map[string]any{}
	if specification.Raw != nil {
		path := specification.Raw.PathPrefixes[0]
		if path != "/" && strings.HasSuffix(path, "/") {
			path += "resource"
		}
		arguments["method"] = specification.Raw.Methods[0]
		arguments["path"] = path
		if path == "/" {
			arguments["body"] = map[string]any{"jsonrpc": "2.0", "id": "conformance", "method": "tools/list", "params": map[string]any{}}
		} else {
			arguments["body"] = map[string]any{}
		}
	} else {
		for _, match := range pathTemplatePattern.FindAllStringSubmatch(specification.Path, -1) {
			arguments[match[1]] = "resource-1"
		}
		for _, required := range specification.Required {
			if required == "content_base64" {
				arguments[required] = "eA=="
			} else if required == "mime_type" {
				arguments[required] = "image/png"
			} else if required == "body" {
				arguments[required] = map[string]any{}
			} else {
				arguments[required] = "resource-1"
			}
		}
		if strings.HasPrefix(specification.Name, "files.github.") {
			for _, name := range []string{"owner", "username"} {
				if _, exists := arguments[name]; exists {
					arguments[name] = "octocat"
				}
			}
			if _, exists := arguments["repo"]; exists {
				arguments["repo"] = "hello-world"
			}
			for _, name := range []string{"issue_number", "pull_number"} {
				if _, exists := arguments[name]; exists {
					arguments[name] = 1
				}
			}
			for _, name := range []string{"tree_sha", "file_sha", "commit_sha"} {
				if _, exists := arguments[name]; exists {
					arguments[name] = strings.Repeat("a", 40)
				}
			}
			if specification.Body == BodyJSON {
				if specification.Name == "files.github.issue_comments.create" {
					arguments["body"] = map[string]any{"body": "Conformance comment"}
				} else {
					arguments["body"] = map[string]any{"title": "Conformance issue"}
				}
			}
		}
		switch specification.Name {
		case "outreach.replio.apps.list", "outreach.replio.threads.list", "outreach.replio.threads.get", "outreach.replio.stats.overview":
			delete(arguments, "organization_id")
			if specification.Name == "outreach.replio.threads.get" {
				arguments["thread_id"] = "11111111-1111-4111-8111-111111111111"
			}
		case "commerce.billingbear.project.stats", "commerce.billingbear.customers.stats", "commerce.billingbear.customers.history":
			delete(arguments, "project_id")
			if specification.Name != "commerce.billingbear.project.stats" {
				arguments["app_user_id"] = "customer-test"
			}
		case "files.clickup.dependencies.remove":
			arguments["depends_on"] = "resource-2"
		case "ads.google_analytics.metadata.get":
			arguments["property_id"] = "1234"
		case "ads.google_analytics.reports.run":
			arguments["property_id"] = "1234"
			arguments["body"] = map[string]any{
				"metrics":    []any{map[string]any{"name": "activeUsers"}},
				"dateRanges": []any{map[string]any{"startDate": "7daysAgo", "endDate": "today"}},
			}
		case "ads.google_analytics.realtime.run":
			arguments["property_id"] = "1234"
			arguments["body"] = map[string]any{"metrics": []any{map[string]any{"name": "activeUsers"}}}
		case "outreach.gmail.history.list":
			arguments["start_history_id"] = "1"
		case "outreach.gmail.watch":
			arguments["body"] = map[string]any{
				"topicName": "projects/openagent-test/topics/gmail-events",
				"labelIds":  []string{"INBOX"},
			}
		case "outreach.gmail.drafts.create":
			arguments["body"] = map[string]any{
				"message": map[string]any{"raw": "VG86IHVzZXJAZXhhbXBsZS5jb20NClN1YmplY3Q6IFRlc3QNCg0KSGVsbG8"},
			}
		case "outreach.gmail.drafts.send":
			arguments["body"] = map[string]any{"id": "draft-1"}
		case "outreach.gmail.messages.send":
			arguments["body"] = map[string]any{
				"raw": "VG86IHVzZXJAZXhhbXBsZS5jb20NClN1YmplY3Q6IFRlc3QNCg0KSGVsbG8",
			}
		case "commerce.shopify.webhook_subscriptions.list":
			arguments["variables"] = map[string]any{"first": 250}
		case "commerce.shopify.webhook_subscriptions.create":
			arguments["variables"] = map[string]any{
				"topic":               "PRODUCTS_CREATE",
				"webhookSubscription": map[string]any{"uri": "https://api.example.com/webhooks/shopify/hook_conformance"},
			}
		case "commerce.shopify.webhook_subscriptions.delete":
			arguments["variables"] = map[string]any{"id": "gid://shopify/WebhookSubscription/1"}
		case "commerce.shopify.products.variants.list":
			arguments["product_id"] = "gid://shopify/Product/1"
		case "social.postiz.posts.list":
			arguments["start_date"] = "2026-07-01T00:00:00Z"
			arguments["end_date"] = "2026-07-23T00:00:00Z"
		case "social.postiz.posts.create":
			arguments["type"] = "schedule"
			arguments["date"] = "2026-07-23T12:00:00Z"
			arguments["shortLink"] = false
			arguments["tags"] = []any{}
			arguments["posts"] = []any{map[string]any{"integration": map[string]any{"id": "integration-1"}}}
		case "social.postiz.drafts.create":
			arguments["type"] = "draft"
			arguments["date"] = "2026-07-23T12:00:00Z"
			arguments["shortLink"] = false
			arguments["tags"] = []any{}
		case "social.postiz.posts.status.update":
			arguments["status"] = "draft"
		case "social.postiz.posts.release_id.update":
			arguments["releaseId"] = "provider-release-1"
		}
	}
	encoded, _ := json.Marshal(arguments)
	return encoded
}

func testInvocation(t *testing.T, manifest Manifest, operation domain.Operation, arguments json.RawMessage) domain.Invocation {
	t.Helper()
	configuration := json.RawMessage(`{}`)
	externalID := ""
	var scopes []string
	if manifest.Provider == "atlassian" || manifest.Provider == "slack_import" {
		scopes = append([]string(nil), operation.RequiredScopes...)
	}
	credentialValue := credential(t, manifest.CredentialHeader, manifest.CredentialScheme)
	if manifest.Provider == "shopify" {
		externalID = "snow-globe.myshopify.com"
		configuration = json.RawMessage(`{"shop_domain":"snow-globe.myshopify.com","theme_writes_enabled":true}`)
	} else if manifest.Provider == "gmail" {
		configuration = json.RawMessage(`{"gmail_topic_name":"projects/openagent-test/topics/gmail-events"}`)
	} else if manifest.Provider == "replio" {
		configuration = json.RawMessage(`{"organization_id":"11111111-1111-4111-8111-111111111111"}`)
		credentialValue = credentialWithSecret(t, "rpl_"+strings.Repeat("a", 48), "Authorization", "Bearer")
	} else if manifest.Provider == "billingbear" {
		configuration = json.RawMessage(`{"project_id":"project-test"}`)
		credentialValue = credentialWithSecret(t, "sk_live_"+strings.Repeat("b", 32), "Authorization", "Bearer")
	} else if manifest.Provider == "atlassian" {
		configuration = json.RawMessage(`{"cloud_id":"11111111-1111-4111-8111-111111111111"}`)
	} else if manifest.Provider == "pipeboard" {
		endpoint := "meta_ads"
		if strings.Contains(operation.Name, ".keywords.") || strings.Contains(operation.Name, ".google.") {
			endpoint = "google_ads"
		}
		configuration, _ = json.Marshal(map[string]string{"ads_provider": endpoint})
	}
	return domain.Invocation{
		ID: "inv-1", Principal: domain.Principal{WorkspaceID: "ws-1", ActorID: "workspace-agent", Role: "agent"},
		Connection: domain.Connection{ID: "conn-1", WorkspaceID: "ws-1", Capability: manifest.Capability, Provider: manifest.Provider, ExternalID: externalID, Config: configuration, Enabled: true, Scopes: scopes},
		Credential: credentialValue, Operation: operation, Arguments: arguments, RequestedAt: time.Now().UTC(), Idempotency: "gp-test-idempotency",
	}
}

func credential(t *testing.T, header, scheme string) domain.Credential {
	t.Helper()
	kind := domain.CredentialOAuth2Bearer
	if scheme == "" {
		kind = domain.CredentialAPIToken
	}
	value, err := domain.NewCredential(kind, "provider-secret", header, scheme, "test-v1", nil)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return value
}

func credentialWithSecret(t *testing.T, secret, header, scheme string) domain.Credential {
	t.Helper()
	kind := domain.CredentialOAuth2Bearer
	if scheme == "" {
		kind = domain.CredentialAPIToken
	}
	value, err := domain.NewCredential(kind, secret, header, scheme, "test-v1", nil)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return value
}

func findOperation(t *testing.T, adapter *HTTPAdapter, name string) domain.Operation {
	t.Helper()
	for _, operation := range adapter.Operations() {
		if operation.Name == name {
			return operation
		}
	}
	t.Fatalf("operation %q not found", name)
	return domain.Operation{}
}

func successDoer() HTTPDoer {
	return doerFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{}`, nil), nil
	})
}

func jsonResponse(status int, body string, headers map[string]string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	for name, value := range headers {
		header.Set(name, value)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}
