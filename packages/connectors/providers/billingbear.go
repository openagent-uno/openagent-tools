package providers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

var (
	billingBearProjectID  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	billingBearCustomerID = regexp.MustCompile(`^[A-Za-z0-9_:@+~-][A-Za-z0-9._:@+~-]{0,255}$`)
	billingBearSecretKey  = regexp.MustCompile(`^sk_[A-Za-z0-9_-]{16,256}$`)
)

// Official API: https://billingbear.io/docs#events-analytics. BillingBear is
// not BillaBear. Only project-scoped secret keys are accepted by this adapter;
// the fixed customer endpoints derive project authority from that key.
func billingbearManifest() Manifest {
	operations := []OperationManifest{
		getOp("commerce.billingbear.project.stats", "Read subscription and revenue metrics for the connected BillingBear project", "/v1/projects/{project_id}/stats", nil, nil),
		getOp("commerce.billingbear.customers.stats", "Read billing statistics for a customer under the connected BillingBear project's secret key", "/v1/customers/{app_user_id}/stats", nil, nil, "app_user_id"),
		getOp("commerce.billingbear.customers.history", "Read a customer's billing event history under the connected BillingBear project's secret key", "/v1/customers/{app_user_id}/history", nil, nil, "app_user_id"),
	}
	for index := range operations {
		properties := map[string]any{}
		if len(operations[index].Required) > 0 {
			properties["app_user_id"] = stringProperty(billingBearCustomerID.String())
		}
		operations[index].InputSchema = platformReadSchema("billingbear", properties, operations[index].Required)
	}
	return Manifest{
		Provider: "billingbear", Capability: domain.Commerce, APIVersion: "v1", OriginKind: OriginFixed, Origin: "https://api.billingbear.io",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer", ReadOnly: true,
		MaxRequestBytes: 16 << 10, MaxResponseBytes: 4 << 20, Operations: operations,
	}
}

func platformReadSchema(provider string, properties map[string]any, required []string) json.RawMessage {
	properties["connection_id"] = boundedStringProperty(128)
	properties["provider"] = map[string]any{"type": "string", "const": provider}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	encoded, _ := json.Marshal(schema)
	return encoded
}

// Project scope is injected from the server-owned connection before approval
// and credential resolution. Tool arguments can never override it.
func validateBillingBearArguments(operation OperationManifest, arguments map[string]json.RawMessage, connectionConfig json.RawMessage) error {
	if operation.Method != http.MethodGet || operation.Body != BodyNone || operation.Raw != nil {
		return domain.ErrInvalidArguments
	}
	allowed := map[string]bool{"connection_id": true, "provider": true}
	if value, exists := arguments["provider"]; exists && jsonString(value) != "billingbear" {
		return domain.ErrInvalidArguments
	}
	if !optionalBoundedString(arguments["connection_id"], 128) {
		return domain.ErrInvalidArguments
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(connectionConfig, &config) != nil || len(config) != 1 {
		return domain.ErrInvalidArguments
	}
	scopeID := jsonString(config["project_id"])
	if !billingBearProjectID.MatchString(scopeID) {
		return domain.ErrInvalidArguments
	}
	switch operation.Name {
	case "commerce.billingbear.project.stats":
	case "commerce.billingbear.customers.stats", "commerce.billingbear.customers.history":
		allowed["app_user_id"] = true
		if !billingBearCustomerID.MatchString(jsonString(arguments["app_user_id"])) {
			return domain.ErrInvalidArguments
		}
	default:
		return domain.ErrUnsupported
	}
	for key := range arguments {
		if !allowed[key] {
			return domain.ErrInvalidArguments
		}
	}
	if strings.Contains(operation.Path, "{project_id}") {
		arguments["project_id"], _ = json.Marshal(scopeID)
	}
	return nil
}

// Reject public and cross-project administrative keys before provider I/O.
func validateBillingBearCredential(authorization string) error {
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || !billingBearSecretKey.MatchString(token) || strings.HasPrefix(strings.ToLower(token), "sk_admin_") {
		return domain.ErrProviderPermission
	}
	return nil
}
