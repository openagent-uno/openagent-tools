package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestRawEscapesAndArbitraryShopifyGraphQLUseNonBypassableRisk(t *testing.T) {
	for _, manifest := range Manifests() {
		for _, operation := range manifest.Operations {
			if operation.Raw != nil && operation.Risk != domain.RiskRaw {
				t.Errorf("%s raw risk = %q", operation.Name, operation.Risk)
			}
			if operation.Name == "commerce.shopify.graphql" && operation.Risk != domain.RiskRaw {
				t.Errorf("arbitrary Shopify GraphQL risk = %q", operation.Risk)
			}
		}
	}
	manifest := driveManifest()
	manifest.Operations[len(manifest.Operations)-1].Risk = domain.RiskWrite
	if err := manifest.validate(); err == nil {
		t.Fatal("manifest accepted a raw escape hatch classified as an ordinary write")
	}
}

func TestShopifyGraphQLApplicationErrorsAndMalformedEnvelopesFail(t *testing.T) {
	responses := map[string]string{
		"top-level errors":       `{"errors":[{"message":"denied"}]}`,
		"user errors":            `{"data":{"productCreate":{"product":null,"userErrors":[{"message":"invalid"}]}}}`,
		"named user errors":      `{"data":{"orderCancel":{"orderCancelUserErrors":[{"message":"invalid"}]}}}`,
		"shopifyql parse errors": `{"data":{"shopifyqlQuery":{"tableData":null,"parseErrors":[{"message":"invalid query"}]}}}`,
		"empty object":           `{}`,
		"scalar":                 `"unexpected"`,
		"array":                  `[]`,
	}
	for name, responseBody := range responses {
		t.Run(name, func(t *testing.T) {
			manifest := shopifyManifest()
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, responseBody, nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			operation := findOperation(t, adapter, "commerce.shopify.products.list")
			invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"variables":{"first":1}}`))
			_, invokeErr := adapter.Invoke(context.Background(), invocation)
			var providerErr *domain.ProviderError
			if !errors.As(invokeErr, &providerErr) || providerErr.Kind != "provider_operation_error" || providerErr.StatusCode != http.StatusOK {
				t.Fatalf("Invoke error = %v", invokeErr)
			}
			if errors.Is(invokeErr, domain.ErrProviderPermission) {
				t.Fatalf("non-permission GraphQL error was classified as permission denied: %v", invokeErr)
			}
		})
	}
}

func TestShopifyGraphQLAccessDeniedIsProviderPermission(t *testing.T) {
	manifest := shopifyManifest()
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(
			http.StatusOK,
			`{"errors":[{"message":"This app is not approved for the requested protected customer data.","extensions":{"code":"ACCESS_DENIED"}}]}`,
			nil,
		), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "commerce.shopify.analytics.shopifyql")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"variables":{"query":"FROM sales SHOW total_sales"}}`))
	_, invokeErr := adapter.Invoke(context.Background(), invocation)
	var providerErr *domain.ProviderError
	if !errors.Is(invokeErr, domain.ErrProviderPermission) ||
		!errors.As(invokeErr, &providerErr) ||
		providerErr.Kind != "provider_permission" ||
		providerErr.StatusCode != http.StatusOK {
		t.Fatalf("Invoke error = %v", invokeErr)
	}
}

func TestShopifyInventoryLevelsListIsExecutableWithoutAnItemID(t *testing.T) {
	manifest := shopifyManifest()
	var requestBody map[string]any
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		if decodeErr := json.NewDecoder(request.Body).Decode(&requestBody); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		return jsonResponse(
			http.StatusOK,
			`{"data":{"inventoryItems":{"nodes":[{"id":"gid://shopify/InventoryItem/1","sku":"snow-1","tracked":true,"inventoryLevels":{"nodes":[{"id":"gid://shopify/InventoryLevel/1?inventory_item_id=1","quantities":[{"name":"available","quantity":3}]}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`,
			nil,
		), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	var manifestOperation OperationManifest
	for _, candidate := range manifest.Operations {
		if candidate.Name == "commerce.shopify.inventory.levels.list" {
			manifestOperation = candidate
			break
		}
	}
	if manifestOperation.Name == "" ||
		len(manifestOperation.Required) != 0 ||
		len(manifestOperation.RequiredScopes) != 1 ||
		manifestOperation.RequiredScopes[0] != "read_inventory" {
		t.Fatalf("inventory list manifest=%#v", manifestOperation)
	}
	operation := findOperation(t, adapter, "commerce.shopify.inventory.levels.list")
	if len(operation.RequiredScopes) != 1 || operation.RequiredScopes[0] != "read_inventory" {
		t.Fatalf("inventory list contract=%#v", operation)
	}
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{}`))
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	query, _ := requestBody["query"].(string)
	variables, _ := requestBody["variables"].(map[string]any)
	if !strings.Contains(query, "inventoryItems(first:$first,after:$after,query:$query)") ||
		!strings.Contains(query, `quantities(names:["available"])`) ||
		strings.Contains(query, "inventoryItem(id:$id)") ||
		strings.Contains(query, "location{") ||
		strings.Contains(query, `"committed"`) ||
		strings.Contains(query, `"incoming"`) ||
		len(variables) != 0 {
		t.Fatalf("inventory list query=%q variables=%#v", query, variables)
	}
	data, ok := result.Data.(map[string]any)
	envelope, _ := data["data"].(map[string]any)
	items, _ := envelope["inventoryItems"].(map[string]any)
	nodes, _ := items["nodes"].([]any)
	if !ok || len(nodes) != 1 {
		t.Fatalf("inventory list result=%#v", result.Data)
	}
	item, _ := nodes[0].(map[string]any)
	levels, _ := item["inventoryLevels"].(map[string]any)
	levelNodes, _ := levels["nodes"].([]any)
	if len(levelNodes) != 1 {
		t.Fatalf("inventory list result=%#v", result.Data)
	}
	level, _ := levelNodes[0].(map[string]any)
	quantities, _ := level["quantities"].([]any)
	pageInfo, _ := items["pageInfo"].(map[string]any)
	levelPageInfo, _ := levels["pageInfo"].(map[string]any)
	if len(quantities) != 1 ||
		pageInfo["hasNextPage"] != false ||
		levelPageInfo["hasNextPage"] != false {
		t.Fatalf("inventory list result=%#v", result.Data)
	}
}

func TestPipeboardJSONRPCErrorAndMalformedEnvelopesFail(t *testing.T) {
	responses := map[string]func(any) any{
		"rpc error": func(id any) any {
			return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000}}
		},
		"missing result": func(id any) any { return map[string]any{"jsonrpc": "2.0", "id": id} },
		"wrong version":  func(id any) any { return map[string]any{"jsonrpc": "1.0", "id": id, "result": map[string]any{}} },
		"wrong id":       func(any) any { return map[string]any{"jsonrpc": "2.0", "id": "other", "result": map[string]any{}} },
		"scalar":         func(any) any { return "unexpected" },
		"array":          func(any) any { return []any{} },
	}
	for name, responseFor := range responses {
		t.Run(name, func(t *testing.T) {
			manifest := pipeboardManifest()
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
				var envelope map[string]any
				_ = json.NewDecoder(request.Body).Decode(&envelope)
				encoded, _ := json.Marshal(responseFor(envelope["id"]))
				return jsonResponse(http.StatusOK, string(encoded), nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			operation := findOperation(t, adapter, "ads.pipeboard.accounts.list")
			invocation := testInvocation(t, manifest, operation, json.RawMessage(`{}`))
			invocation.Connection.Config = json.RawMessage(`{"ads_provider":"meta_ads"}`)
			_, invokeErr := adapter.Invoke(context.Background(), invocation)
			var providerErr *domain.ProviderError
			if !errors.As(invokeErr, &providerErr) || providerErr.Kind != "provider_operation_error" {
				t.Fatalf("Invoke error = %v", invokeErr)
			}
		})
	}

	t.Run("invalid json", func(t *testing.T) {
		manifest := pipeboardManifest()
		adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{not-json`, nil), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		operation := findOperation(t, adapter, "ads.pipeboard.accounts.list")
		invocation := testInvocation(t, manifest, operation, json.RawMessage(`{}`))
		invocation.Connection.Config = json.RawMessage(`{"ads_provider":"meta_ads"}`)
		_, invokeErr := adapter.Invoke(context.Background(), invocation)
		var providerErr *domain.ProviderError
		if !errors.As(invokeErr, &providerErr) || providerErr.Kind != "provider_operation_error" {
			t.Fatalf("Invoke error = %v", invokeErr)
		}
	})
}

func TestPipeboardMCPToolErrorsInsideSuccessfulJSONRPCFail(t *testing.T) {
	responses := map[string]func(any) any{
		"fastmcp isError": func(id any) any {
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
				"isError": true, "content": []any{map[string]any{"type": "text", "text": "tool failed"}},
			}}
		},
		"json error text": func(id any) any {
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
				"content": []any{map[string]any{"type": "text", "text": `{"error":"No account ID specified"}`}},
			}}
		},
		"structured error": func(id any) any {
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
				"structuredContent": map[string]any{"errors": []any{map[string]any{"message": "denied"}}},
			}}
		},
	}
	for name, responseFor := range responses {
		t.Run(name, func(t *testing.T) {
			manifest := pipeboardManifest()
			adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
				var envelope map[string]any
				_ = json.NewDecoder(request.Body).Decode(&envelope)
				encoded, _ := json.Marshal(responseFor(envelope["id"]))
				return jsonResponse(http.StatusOK, string(encoded), nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			operation := findOperation(t, adapter, "ads.pipeboard.accounts.list")
			invocation := testInvocation(t, manifest, operation, json.RawMessage(`{}`))
			invocation.Connection.Config = json.RawMessage(`{"ads_provider":"meta_ads"}`)
			_, invokeErr := adapter.Invoke(context.Background(), invocation)
			var providerErr *domain.ProviderError
			if !errors.As(invokeErr, &providerErr) || providerErr.Kind != "provider_operation_error" {
				t.Fatalf("Invoke error = %v", invokeErr)
			}
		})
	}
}

func TestPostizUploadUsesMultipartFilePart(t *testing.T) {
	manifest := postizManifest()
	var received []byte
	var fileName, mediaType string
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		parsedType, parameters, parseErr := mimeParse(request.Header.Get("Content-Type"))
		if parseErr != nil || parsedType != "multipart/form-data" {
			t.Fatalf("Content-Type = %q err=%v", request.Header.Get("Content-Type"), parseErr)
		}
		reader := multipart.NewReader(request.Body, parameters["boundary"])
		part, partErr := reader.NextPart()
		if partErr != nil {
			t.Fatal(partErr)
		}
		fileName, mediaType = part.FileName(), part.Header.Get("Content-Type")
		received, partErr = io.ReadAll(part)
		if partErr != nil {
			t.Fatal(partErr)
		}
		if _, partErr = reader.NextPart(); !errors.Is(partErr, io.EOF) {
			t.Fatalf("unexpected extra multipart part: %v", partErr)
		}
		return jsonResponse(http.StatusOK, `{"id":"upload-1"}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "social.postiz.media.upload")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"content_base64":"aGVsbG8=","mime_type":"image/png","file_name":"creative.png"}`))
	if _, err = adapter.Invoke(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	if string(received) != "hello" || fileName != "creative.png" || mediaType != "image/png" {
		t.Fatalf("multipart file=%q name=%q type=%q", received, fileName, mediaType)
	}
}

func TestShopifyIdempotentDirectiveUsesTrustedInvocationKey(t *testing.T) {
	manifest := shopifyManifest()
	var requestBody map[string]any
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		if decodeErr := json.NewDecoder(request.Body).Decode(&requestBody); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		return jsonResponse(http.StatusOK, `{"data":{"inventoryAdjustQuantities":{"userErrors":[]}}}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "commerce.shopify.inventory.adjust")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{"variables":{"input":{"reason":"correction","changes":[]},"idempotencyKey":"caller-controlled"}}`))
	invocation.Idempotency = "trusted-gateway-key"
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	query, _ := requestBody["query"].(string)
	variables, _ := requestBody["variables"].(map[string]any)
	if !strings.Contains(query, "inventoryAdjustQuantities(input:$input) @idempotent(key:$idempotencyKey)") ||
		strings.Contains(query, ") @idempotent(key:$idempotencyKey){inventoryAdjustQuantities") || variables["idempotencyKey"] != "trusted-gateway-key" {
		t.Fatalf("query=%q variables=%#v", query, variables)
	}
	if result.Metadata["idempotency_applied"] != "true" {
		t.Fatalf("metadata = %#v", result.Metadata)
	}
}

func TestShopifyRefundIdempotentDirectiveIsOnMutationField(t *testing.T) {
	manifest := shopifyManifest()
	var operation OperationManifest
	for _, candidate := range manifest.Operations {
		if candidate.Name == "commerce.shopify.refunds.create" {
			operation = candidate
			break
		}
	}
	if operation.Name == "" {
		t.Fatal("refund operation not found")
	}
	want := "refundCreate(input:$input) @idempotent(key:$idempotencyKey)"
	if !strings.Contains(operation.GraphQLDocument, want) {
		t.Fatalf("refund mutation = %q; want field directive %q", operation.GraphQLDocument, want)
	}
}

func TestShopifyWebhookSubscriptionsUseTypedGraphQLOnly(t *testing.T) {
	manifest := shopifyManifest()
	graphqlPath := "/admin/api/" + ShopifyAPIVersion + "/graphql.json"
	wantedDocuments := map[string]string{
		"commerce.shopify.webhook_subscriptions.list":   `webhookSubscriptions(first:$first,after:$after){nodes{id topic uri}pageInfo{hasNextPage endCursor}}`,
		"commerce.shopify.webhook_subscriptions.create": `webhookSubscriptionCreate(topic:$topic,webhookSubscription:$webhookSubscription){webhookSubscription{id topic uri}userErrors{field message}}`,
		"commerce.shopify.webhook_subscriptions.delete": `webhookSubscriptionDelete(id:$id){deletedWebhookSubscriptionId userErrors{field message}}`,
	}
	specifications := make(map[string]OperationManifest, len(wantedDocuments))
	for _, operation := range manifest.Operations {
		if operation.Name == "commerce.shopify.webhooks.list" || operation.Name == "commerce.shopify.webhooks.create" || operation.Name == "commerce.shopify.webhooks.delete" ||
			strings.Contains(operation.Path, "/webhooks.json") {
			t.Errorf("legacy Shopify REST webhook operation remains: %#v", operation)
		}
		if document, wanted := wantedDocuments[operation.Name]; wanted {
			specifications[operation.Name] = operation
			if operation.Method != http.MethodPost || operation.Path != graphqlPath || operation.Body != BodyGraphQL || !strings.Contains(operation.GraphQLDocument, document) {
				t.Errorf("%s is not the fixed typed GraphQL contract: %#v", operation.Name, operation)
			}
		}
	}
	if len(specifications) != len(wantedDocuments) {
		t.Fatalf("Shopify webhook GraphQL operations=%d want=%d", len(specifications), len(wantedDocuments))
	}
	if create := specifications["commerce.shopify.webhook_subscriptions.create"]; create.Retry.MaxAttempts != 1 || create.Retry.RetryableWrite {
		t.Fatalf("non-idempotent create has unsafe transport retry: %#v", create.Retry)
	}
	if remove := specifications["commerce.shopify.webhook_subscriptions.delete"]; remove.Retry.MaxAttempts != 1 || remove.Retry.RetryableWrite {
		t.Fatalf("delete has unexpected transport retry: %#v", remove.Retry)
	}

	type capturedRequest struct {
		Method string
		Path   string
		Body   map[string]any
	}
	requests := make([]capturedRequest, 0, 3)
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		requests = append(requests, capturedRequest{Method: request.Method, Path: request.URL.Path, Body: body})
		query, _ := body["query"].(string)
		switch {
		case strings.Contains(query, "query WebhookSubscriptions"):
			return jsonResponse(http.StatusOK, `{"data":{"webhookSubscriptions":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`, nil), nil
		case strings.Contains(query, "mutation WebhookSubscriptionCreate"):
			return jsonResponse(http.StatusOK, `{"data":{"webhookSubscriptionCreate":{"webhookSubscription":{"id":"gid://shopify/WebhookSubscription/1","topic":"PRODUCTS_CREATE","uri":"https://api.example.com/webhooks/shopify/hook_test"},"userErrors":[]}}}`, nil), nil
		case strings.Contains(query, "mutation WebhookSubscriptionDelete"):
			return jsonResponse(http.StatusOK, `{"data":{"webhookSubscriptionDelete":{"deletedWebhookSubscriptionId":"gid://shopify/WebhookSubscription/1","userErrors":[]}}}`, nil), nil
		default:
			t.Fatalf("unexpected GraphQL document %q", query)
			return nil, nil
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	callback := "https://api.example.com/webhooks/shopify/hook_test"
	invocations := []struct {
		name      string
		arguments json.RawMessage
		variables string
	}{
		{name: "commerce.shopify.webhook_subscriptions.list", arguments: json.RawMessage(`{"variables":{"first":250}}`), variables: `{"first":250}`},
		{name: "commerce.shopify.webhook_subscriptions.create", arguments: json.RawMessage(`{"variables":{"topic":"PRODUCTS_CREATE","webhookSubscription":{"uri":"` + callback + `"}}}`), variables: `{"topic":"PRODUCTS_CREATE","webhookSubscription":{"uri":"` + callback + `"}}`},
		{name: "commerce.shopify.webhook_subscriptions.delete", arguments: json.RawMessage(`{"variables":{"id":"gid://shopify/WebhookSubscription/1"}}`), variables: `{"id":"gid://shopify/WebhookSubscription/1"}`},
	}
	for _, request := range invocations {
		operation := findOperation(t, adapter, request.name)
		invocation := testInvocation(t, manifest, operation, request.arguments)
		if _, invokeErr := adapter.Invoke(context.Background(), invocation); invokeErr != nil {
			t.Fatalf("%s Invoke: %v", request.name, invokeErr)
		}
		captured := requests[len(requests)-1]
		variables, _ := json.Marshal(captured.Body["variables"])
		if captured.Method != http.MethodPost || captured.Path != graphqlPath || string(variables) != request.variables {
			t.Errorf("%s request=%#v variables=%s", request.name, captured, variables)
		}
	}
}

func TestShopifyCurrentAccessScopesUsesTypedGraphQL(t *testing.T) {
	var operation OperationManifest
	for _, candidate := range shopifyManifest().Operations {
		if candidate.Name == "commerce.shopify.app.access_scopes" {
			operation = candidate
			break
		}
	}
	if operation.Name == "" {
		t.Fatal("current access-scope operation is missing")
	}
	if operation.Method != http.MethodPost ||
		operation.Path != "/admin/api/"+ShopifyAPIVersion+"/graphql.json" ||
		operation.Body != BodyGraphQL ||
		operation.Risk != domain.RiskRead ||
		!strings.Contains(operation.GraphQLDocument, "currentAppInstallation{accessScopes{handle}}") {
		t.Fatalf("current access-scope operation is not a fixed typed query: %#v", operation)
	}
}

func TestShopifyAdminAndThemeContractsUseGraphQLOnly(t *testing.T) {
	manifest := shopifyManifest()
	graphqlPath := "/admin/api/" + ShopifyAPIVersion + "/graphql.json"
	themeDocuments := map[string]string{
		"commerce.shopify.themes.list":        "query Themes",
		"commerce.shopify.themes.publish":     "mutation ThemePublish",
		"commerce.shopify.theme_files.list":   "query ThemeFiles",
		"commerce.shopify.theme_files.get":    "query ThemeFile",
		"commerce.shopify.theme_files.write":  "mutation ThemeFilesUpsert",
		"commerce.shopify.theme_files.delete": "mutation ThemeFilesDelete",
	}
	seenThemes := make(map[string]bool, len(themeDocuments))
	var rawSpec OperationManifest
	for _, operation := range manifest.Operations {
		if operation.Raw != nil {
			rawSpec = operation
			continue
		}
		if operation.Path != graphqlPath || operation.Method != http.MethodPost {
			t.Errorf("Shopify Admin operation %s uses non-GraphQL transport %s %s", operation.Name, operation.Method, operation.Path)
		}
		if strings.Contains(operation.Path, "/themes") || strings.Contains(operation.Path, "/assets") {
			t.Errorf("legacy Shopify theme REST path remains: %s", operation.Path)
		}
		if marker, ok := themeDocuments[operation.Name]; ok {
			seenThemes[operation.Name] = true
			if operation.Body != BodyGraphQL || !strings.Contains(operation.GraphQLDocument, marker) {
				t.Errorf("%s is not a fixed GraphQL theme contract: %#v", operation.Name, operation)
			}
		}
	}
	if len(seenThemes) != len(themeDocuments) {
		t.Fatalf("Shopify GraphQL theme operations=%d want=%d", len(seenThemes), len(themeDocuments))
	}
	if rawSpec.Name != "commerce.shopify.raw" ||
		len(rawSpec.Raw.Methods) != 1 || rawSpec.Raw.Methods[0] != http.MethodPost ||
		len(rawSpec.Raw.PathPrefixes) != 1 || rawSpec.Raw.PathPrefixes[0] != graphqlPath {
		t.Fatalf("Shopify raw fallback is not GraphQL-only: %#v", rawSpec)
	}

	adapter, err := NewHTTPAdapter(manifest, successDoer())
	if err != nil {
		t.Fatal(err)
	}
	raw := findOperation(t, adapter, rawSpec.Name)
	for _, request := range []json.RawMessage{
		json.RawMessage(`{"method":"GET","path":"/admin/api/2026-07/products.json"}`),
		json.RawMessage(`{"method":"GET","path":"/admin/api/2026-07/themes.json"}`),
		json.RawMessage(`{"method":"PUT","path":"/admin/api/2026-07/themes/123/assets.json","body":{}}`),
		json.RawMessage(`{"method":"POST","path":"/admin/api/2026-07/graphql.json/legacy","body":{"query":"query { shop { id } }"}}`),
	} {
		invocation := testInvocation(t, manifest, raw, request)
		if _, previewErr := adapter.Preview(invocation); !errors.Is(previewErr, domain.ErrInvalidArguments) {
			t.Errorf("legacy Shopify REST/raw path was accepted: %s error=%v", request, previewErr)
		}
	}
}

func TestPostizDocumentedAnalyticsAndPostsArguments(t *testing.T) {
	manifest := postizManifest()
	var analytics, posts OperationManifest
	documented := map[string]struct {
		method string
		path   string
	}{
		"social.postiz.posts.create":            {http.MethodPost, "/public/v1/posts"},
		"social.postiz.drafts.create":           {http.MethodPost, "/public/v1/posts"},
		"social.postiz.posts.delete":            {http.MethodDelete, "/public/v1/posts/{post_id}"},
		"social.postiz.posts.status.update":     {http.MethodPut, "/public/v1/posts/{post_id}/status"},
		"social.postiz.posts.release_id.update": {http.MethodPut, "/public/v1/posts/{post_id}/release-id"},
		"social.postiz.posts.missing":           {http.MethodGet, "/public/v1/posts/{post_id}/missing"},
	}
	seen := make(map[string]bool, len(documented))
	for _, operation := range manifest.Operations {
		switch operation.Name {
		case "social.postiz.analytics.posts":
			analytics = operation
		case "social.postiz.posts.list":
			posts = operation
		case "social.postiz.posts.get", "social.postiz.posts.update", "social.postiz.posts.publish":
			t.Errorf("undocumented Postiz operation remains in manifest: %s", operation.Name)
		}
		if contract, ok := documented[operation.Name]; ok {
			seen[operation.Name] = true
			if operation.Method != contract.method || operation.Path != contract.path {
				t.Errorf("%s = %s %s; want %s %s", operation.Name, operation.Method, operation.Path, contract.method, contract.path)
			}
			switch operation.Name {
			case "social.postiz.posts.status.update":
				if !containsString(operation.Required, "status") {
					t.Error("Postiz status operation does not require status")
				}
			case "social.postiz.posts.release_id.update":
				if !containsString(operation.Required, "releaseId") {
					t.Error("Postiz release ID operation does not require exact releaseId body field")
				}
			}
		}
	}
	for name := range documented {
		if !seen[name] {
			t.Errorf("documented Postiz operation missing: %s", name)
		}
	}
	if analytics.Path != "/public/v1/analytics/post/{post_id}" || analytics.Query["date"] != "date" ||
		!containsString(analytics.Required, "post_id") || !containsString(analytics.Required, "date") {
		t.Fatalf("analytics manifest = %#v", analytics)
	}
	if posts.Query["start_date"] != "startDate" || posts.Query["end_date"] != "endDate" ||
		!containsString(posts.Required, "start_date") || !containsString(posts.Required, "end_date") {
		t.Fatalf("posts list manifest = %#v", posts)
	}
}

func TestPostizTypedContractsRejectClassificationAndPayloadBypasses(t *testing.T) {
	manifest := postizManifest()
	doerCalls := 0
	var receivedPath string
	var receivedBody map[string]any
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		doerCalls++
		receivedPath = request.URL.Path
		if request.Body != nil {
			_ = json.NewDecoder(request.Body).Decode(&receivedBody)
		}
		return jsonResponse(http.StatusOK, `{"ok":true}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	draft := findOperation(t, adapter, "social.postiz.drafts.create")
	for name, arguments := range map[string]string{
		"publish through draft tool": `{"type":"now","date":"2026-07-23T12:00:00Z","shortLink":false,"tags":[],"posts":[{}]}`,
		"explicit body mismatch":     `{"type":"draft","date":"2026-07-23T12:00:00Z","shortLink":false,"tags":[],"body":{"type":"now"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, invokeErr := adapter.Invoke(context.Background(), testInvocation(t, manifest, draft, json.RawMessage(arguments))); !errors.Is(invokeErr, domain.ErrInvalidArguments) {
				t.Fatalf("Invoke error = %v", invokeErr)
			}
		})
	}

	list := findOperation(t, adapter, "social.postiz.posts.list")
	if _, invokeErr := adapter.Invoke(context.Background(), testInvocation(t, manifest, list, json.RawMessage(`{"start_date":"not-a-date","end_date":"2026-07-23T12:00:00Z"}`))); !errors.Is(invokeErr, domain.ErrInvalidArguments) {
		t.Fatalf("invalid date Invoke error = %v", invokeErr)
	}

	release := findOperation(t, adapter, "social.postiz.posts.release_id.update")
	invocation := testInvocation(t, manifest, release, json.RawMessage(`{"post_id":"post-1","releaseId":"7321456789012345678"}`))
	if _, err = adapter.Invoke(context.Background(), invocation); err != nil {
		t.Fatal(err)
	}
	if doerCalls != 1 || receivedPath != "/public/v1/posts/post-1/release-id" || receivedBody["releaseId"] != "7321456789012345678" {
		t.Fatalf("calls=%d path=%q body=%#v", doerCalls, receivedPath, receivedBody)
	}
}

func TestPostizStructuredInputSchemasMatchWireTypes(t *testing.T) {
	manifest := postizManifest()
	want := map[string]map[string]string{
		"social.postiz.posts.create": {
			"type": "string", "date": "string", "shortLink": "boolean", "tags": "array", "posts": "array",
		},
		"social.postiz.drafts.create": {
			"type": "string", "date": "string", "shortLink": "boolean", "tags": "array",
		},
		"social.postiz.posts.status.update":     {"status": "string"},
		"social.postiz.posts.release_id.update": {"releaseId": "string"},
	}
	seen := make(map[string]bool, len(want))
	for _, operation := range manifest.Operations {
		fields, ok := want[operation.Name]
		if !ok {
			continue
		}
		seen[operation.Name] = true
		var schema struct {
			Properties map[string]map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(operation.InputSchema, &schema); err != nil {
			t.Fatalf("%s schema: %v", operation.Name, err)
		}
		for field, expectedType := range fields {
			if actualType, _ := schema.Properties[field]["type"].(string); actualType != expectedType {
				t.Errorf("%s field %s type = %q; want %q", operation.Name, field, actualType, expectedType)
			}
		}
	}
	for operation := range want {
		if !seen[operation] {
			t.Errorf("missing schema assertion target %s", operation)
		}
	}
}

// Kept local to this test file so the production adapter continues to use its
// strict mime.ParseMediaType call without exporting an implementation detail.
func mimeParse(value string) (string, map[string]string, error) {
	return mime.ParseMediaType(value)
}
