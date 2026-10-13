package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestShopifyCatalogQueriesExposeExactAggregatesAndPagination(t *testing.T) {
	operations := make(map[string]OperationManifest)
	for _, operation := range shopifyManifest().Operations {
		operations[operation.Name] = operation
	}
	list := operations["commerce.shopify.products.list"]
	get := operations["commerce.shopify.products.get"]
	variants := operations["commerce.shopify.products.variants.list"]
	for name, operation := range map[string]OperationManifest{"list": list, "get": get} {
		for _, field := range []string{"totalInventory", "tracksInventory", "variantsCount{count precision}", "pageInfo{hasNextPage endCursor}"} {
			if !strings.Contains(operation.GraphQLDocument, field) {
				t.Errorf("products %s query is missing %s: %s", name, field, operation.GraphQLDocument)
			}
		}
	}
	if !strings.Contains(list.GraphQLDocument, "productsCount(query:$query,limit:null){count precision}") {
		t.Fatalf("products list lacks an unbounded precision-aware root count: %s", list.GraphQLDocument)
	}
	if !strings.Contains(list.GraphQLDocument, "status tags updatedAt totalInventory tracksInventory") {
		t.Fatalf("products list does not preserve Shopify tags for webhook reconciliation: %s", list.GraphQLDocument)
	}
	if !strings.Contains(list.GraphQLDocument, "variants(first:100)") ||
		!strings.Contains(get.GraphQLDocument, "variants(first:250)") {
		t.Fatalf("product variant page bounds drifted: list=%s get=%s", list.GraphQLDocument, get.GraphQLDocument)
	}
	if variants.Name == "" || variants.GraphQLIDSearchFilter == nil ||
		!strings.Contains(variants.GraphQLDocument, "productVariants(first:$first,after:$after,query:$productFilter)") ||
		!strings.Contains(variants.GraphQLDocument, "pageInfo{hasNextPage endCursor}") ||
		len(variants.RequiredScopes) != 2 || variants.RequiredScopes[0] != "read_products" || variants.RequiredScopes[1] != "read_inventory" {
		t.Fatalf("paginated product variant operation=%#v", variants)
	}
	var schema struct {
		Properties map[string]struct {
			Minimum float64 `json:"minimum"`
			Maximum float64 `json:"maximum"`
			Pattern string  `json:"pattern"`
		} `json:"properties"`
		Required             []string `json:"required"`
		AdditionalProperties bool     `json:"additionalProperties"`
	}
	if json.Unmarshal(variants.InputSchema, &schema) != nil || len(schema.Required) != 1 || schema.Required[0] != "product_id" ||
		schema.AdditionalProperties || schema.Properties["first"].Minimum != 1 || schema.Properties["first"].Maximum != 250 ||
		schema.Properties["product_id"].Pattern == "" {
		t.Fatalf("variant list schema=%s", variants.InputSchema)
	}
}

func TestShopifyProductListAdapterPreservesTags(t *testing.T) {
	manifest := shopifyManifest()
	var query string
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query = body.Query
		return jsonResponse(http.StatusOK, `{"data":{"productsCount":{"count":1,"precision":"EXACT"},"products":{"nodes":[{"id":"gid://shopify/Product/1","title":"Gift Card","tags":["connector-webhook-probe","featured"],"totalInventory":0,"tracksInventory":false}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "commerce.shopify.products.list")
	result, err := adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, json.RawMessage(`{"first":50}`)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, "status tags updatedAt totalInventory tracksInventory") {
		t.Fatalf("Shopify product list query=%q", query)
	}
	data := result.Data.(map[string]any)["data"].(map[string]any)
	products := data["products"].(map[string]any)
	product := products["nodes"].([]any)[0].(map[string]any)
	tags, ok := product["tags"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "connector-webhook-probe" || tags[1] != "featured" {
		t.Fatalf("adapter product tags=%#v", product["tags"])
	}
	if tracked, ok := product["tracksInventory"].(bool); !ok || tracked {
		t.Fatalf("adapter product tracksInventory=%#v", product["tracksInventory"])
	}
}

func TestShopifyCatalogAndVariantCursorsCoverMoreThanOnePage(t *testing.T) {
	manifest := shopifyManifest()
	var productCalls, variantCalls int
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil {
			t.Fatal("could not decode Shopify GraphQL request")
		}
		var root string
		var nodes []map[string]any
		pageInfo := map[string]any{"hasNextPage": false, "endCursor": nil}
		switch {
		case strings.Contains(body.Query, "query Products("):
			root = "products"
			productCalls++
			count := 50
			if productCalls == 1 {
				if body.Variables["first"] != float64(50) || body.Variables["after"] != nil {
					t.Fatalf("first product variables=%#v", body.Variables)
				}
				pageInfo = map[string]any{"hasNextPage": true, "endCursor": "product-50"}
			} else {
				if body.Variables["after"] != "product-50" {
					t.Fatalf("second product variables=%#v", body.Variables)
				}
				count = 1
			}
			for index := 0; index < count; index++ {
				nodes = append(nodes, map[string]any{"id": "gid://shopify/Product/" + strconv.Itoa(index+1)})
			}
		case strings.Contains(body.Query, "query ProductVariants("):
			root = "productVariants"
			variantCalls++
			if body.Variables["productFilter"] != "product_id:8474977763649" || body.Variables["product_id"] != nil {
				t.Fatalf("trusted product filter variables=%#v", body.Variables)
			}
			count := 100
			if variantCalls == 1 {
				if body.Variables["first"] != float64(100) || body.Variables["after"] != nil {
					t.Fatalf("first variant variables=%#v", body.Variables)
				}
				pageInfo = map[string]any{"hasNextPage": true, "endCursor": "variant-100"}
			} else {
				if body.Variables["after"] != "variant-100" {
					t.Fatalf("second variant variables=%#v", body.Variables)
				}
				count = 37
			}
			for index := 0; index < count; index++ {
				nodes = append(nodes, map[string]any{"id": "gid://shopify/ProductVariant/" + strconv.Itoa(index+1)})
			}
		default:
			t.Fatalf("unexpected GraphQL query: %s", body.Query)
		}
		data := map[string]any{root: map[string]any{"nodes": nodes, "pageInfo": pageInfo}}
		if root == "products" {
			// A count and a page are independent evidence: AT_LEAST must never
			// turn a page into a complete catalog claim.
			data["productsCount"] = map[string]any{"count": 51, "precision": "AT_LEAST"}
		}
		encoded, _ := json.Marshal(map[string]any{"data": data})
		return jsonResponse(http.StatusOK, string(encoded), nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	page := func(operation domain.Operation, arguments string, root string) (int, bool, string, string) {
		result, invokeErr := adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, json.RawMessage(arguments)))
		if invokeErr != nil {
			t.Fatal(invokeErr)
		}
		data := result.Data.(map[string]any)["data"].(map[string]any)
		envelope := data[root].(map[string]any)
		nodes := envelope["nodes"].([]any)
		pageInfo := envelope["pageInfo"].(map[string]any)
		cursor, _ := pageInfo["endCursor"].(string)
		precision := ""
		if count, exists := data["productsCount"].(map[string]any); exists {
			precision, _ = count["precision"].(string)
		}
		return len(nodes), pageInfo["hasNextPage"].(bool), cursor, precision
	}
	products := findOperation(t, adapter, "commerce.shopify.products.list")
	count, more, cursor, precision := page(products, `{"first":50}`, "products")
	if count != 50 || !more || cursor != "product-50" || precision != "AT_LEAST" {
		t.Fatalf("first products page count=%d more=%t cursor=%q precision=%q", count, more, cursor, precision)
	}
	last, more, _, _ := page(products, `{"first":50,"after":"product-50"}`, "products")
	if count+last != 51 || more {
		t.Fatalf("product pagination total=%d more=%t", count+last, more)
	}
	productVariants := findOperation(t, adapter, "commerce.shopify.products.variants.list")
	count, more, cursor, _ = page(productVariants, `{"product_id":"gid://shopify/Product/8474977763649","first":100}`, "productVariants")
	if count != 100 || !more || cursor != "variant-100" {
		t.Fatalf("first variants page count=%d more=%t cursor=%q", count, more, cursor)
	}
	last, more, _, _ = page(productVariants, `{"product_id":"8474977763649","first":100,"after":"variant-100"}`, "productVariants")
	if count+last != 137 || more {
		t.Fatalf("variant pagination total=%d more=%t", count+last, more)
	}
}

func TestShopifyProductVariantFilterRejectsUntrustedOrOutOfRangeInputs(t *testing.T) {
	manifest := shopifyManifest()
	var calls int
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(http.StatusOK, `{"data":{"productVariants":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "commerce.shopify.products.variants.list")
	for _, arguments := range []string{
		`{"product_id":"0"}`,
		`{"product_id":"gid://shopify/Order/1"}`,
		`{"product_id":"1 OR inventory_quantity:0"}`,
		`{"product_id":"1","first":0}`,
		`{"product_id":"1","first":251}`,
		`{"product_id":"1","first":1.5}`,
		`{"product_id":"1","after":""}`,
		`{"product_id":"1","query":"inventory_quantity:0"}`,
	} {
		invocation := testInvocation(t, manifest, operation, json.RawMessage(arguments))
		if _, previewErr := adapter.Preview(invocation); !errors.Is(previewErr, domain.ErrInvalidArguments) {
			t.Errorf("arguments %s error=%v", arguments, previewErr)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid variant filters reached Shopify %d times", calls)
	}
}
