package providers

import (
	"slices"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestShopifyManifestDeclaresOperationScopes(t *testing.T) {
	operations := make(map[string]OperationManifest)
	for _, operation := range shopifyManifest().Operations {
		operations[operation.Name] = operation
		if !operation.InternalOnly && operation.Risk != domain.RiskRead && len(operation.RequiredScopes) == 0 {
			t.Errorf("%s is mutating but has no required scopes", operation.Name)
		}
		if (strings.HasPrefix(operation.Name, "commerce.shopify.themes.") ||
			strings.HasPrefix(operation.Name, "commerce.shopify.theme_files.")) &&
			len(operation.RequiredScopes) == 0 {
			t.Errorf("%s is a theme operation but has no required scopes", operation.Name)
		}
	}
	for _, name := range []string{
		"commerce.shopify.webhook_subscriptions.list",
		"commerce.shopify.webhook_subscriptions.create",
		"commerce.shopify.webhook_subscriptions.delete",
	} {
		operation := operations[name]
		if !operation.InternalOnly || len(operation.RequiredScopes) != 0 {
			t.Errorf("%s internal=%t required scopes=%v", name, operation.InternalOnly, operation.RequiredScopes)
		}
	}

	expected := map[string][]string{
		"commerce.shopify.products.list":         {"read_products", "read_inventory"},
		"commerce.shopify.products.update":       {"write_products"},
		"commerce.shopify.collections.list":      {"read_products"},
		"commerce.shopify.orders.list":           {"read_orders", "read_inventory"},
		"commerce.shopify.orders.cancel":         {"write_orders"},
		"commerce.shopify.customers.list":        {"read_customers"},
		"commerce.shopify.customers.update":      {"write_customers"},
		"commerce.shopify.inventory.levels.list": {"read_inventory"},
		"commerce.shopify.inventory.adjust":      {"write_inventory"},
		"commerce.shopify.fulfillments.create":   {"write_merchant_managed_fulfillment_orders"},
		"commerce.shopify.refunds.create":        {"write_orders"},
		"commerce.shopify.themes.list":           {"read_themes"},
		"commerce.shopify.themes.publish":        {"write_themes"},
		"commerce.shopify.theme_files.get":       {"read_themes"},
		"commerce.shopify.theme_files.write":     {"write_themes"},
	}
	for name, requiredScopes := range expected {
		operation, ok := operations[name]
		if !ok {
			t.Errorf("missing Shopify operation %s", name)
			continue
		}
		if !slices.Equal(operation.RequiredScopes, requiredScopes) {
			t.Errorf("%s required scopes=%v want=%v", name, operation.RequiredScopes, requiredScopes)
		}
	}
}

func TestShopifyOrderQueriesExcludeDirectCustomerIdentifiers(t *testing.T) {
	for _, operation := range shopifyManifest().Operations {
		if operation.Name != "commerce.shopify.orders.list" && operation.Name != "commerce.shopify.orders.get" {
			continue
		}
		lower := strings.ToLower(operation.GraphQLDocument)
		for _, forbidden := range []string{"customer{", "email", "phone", "billingaddress", "shippingaddress", "displayaddress"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s requests direct customer identity field %q: %s", operation.Name, forbidden, operation.GraphQLDocument)
			}
		}
		for _, required := range []string{"currentSubtotalPriceSet", "currentTotalPriceSet", "priceAfterAllDiscountsBeforeTaxesSet", "lineItems", "unitCost"} {
			if !strings.Contains(operation.GraphQLDocument, required) {
				t.Errorf("%s omits financial field %q", operation.Name, required)
			}
		}
	}
}

func TestShopifyCustomerQueriesRequestOnlyApprovedIdentityFields(t *testing.T) {
	documents := make(map[string]string)
	for _, operation := range shopifyManifest().Operations {
		switch operation.Name {
		case "commerce.shopify.customers.list", "commerce.shopify.customers.get":
			documents[operation.Name] = operation.GraphQLDocument
		}
	}
	for _, name := range []string{"commerce.shopify.customers.list", "commerce.shopify.customers.get"} {
		document, exists := documents[name]
		if !exists {
			t.Fatalf("missing Shopify customer operation %s", name)
		}
		lower := strings.ToLower(document)
		if strings.Contains(lower, "phone") || strings.Contains(lower, "address") || strings.Contains(lower, "tags") {
			t.Errorf("%s requests PCD outside the approved Name and Email fields: %s", name, document)
		}
		if !strings.Contains(document, "displayName") || !strings.Contains(document, "email") {
			t.Errorf("%s does not request the approved Name and Email fields: %s", name, document)
		}
	}
}
