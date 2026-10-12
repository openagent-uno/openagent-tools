package providers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

var (
	platformUUIDPattern       = regexp.MustCompile(`^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$`)
	platformProjectIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	platformCustomerIDPattern = regexp.MustCompile(`^[A-Za-z0-9_:@+~-][A-Za-z0-9._:@+~-]{0,255}$`)
	platformReplioKeyPattern  = regexp.MustCompile(`^rpl_[A-Za-z0-9_-]{32,128}$`)
	platformBillingKeyPattern = regexp.MustCompile(`^sk_[A-Za-z0-9_-]{16,256}$`)
)

// validatePlatformArguments validates before approval and before credential
// resolution. Provider tenant path fields are injected from the server-owned
// connection, never accepted as tool arguments (even if their value matches).
func validatePlatformArguments(operation OperationManifest, arguments map[string]json.RawMessage, connectionConfig json.RawMessage) error {
	provider := ""
	switch {
	case strings.HasPrefix(operation.Name, "outreach.replio."):
		provider = "replio"
	case strings.HasPrefix(operation.Name, "commerce.billingbear."):
		provider = "billingbear"
	default:
		return domain.ErrUnsupported
	}
	if operation.Method != http.MethodGet || operation.Body != BodyNone || operation.Raw != nil {
		return domain.ErrInvalidArguments
	}
	allowed := map[string]bool{"connection_id": true, "provider": true}
	if value, exists := arguments["provider"]; exists && jsonString(value) != provider {
		return domain.ErrInvalidArguments
	}
	if !optionalBoundedString(arguments["connection_id"], 128) {
		return domain.ErrInvalidArguments
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(connectionConfig, &config) != nil || len(config) != 1 {
		return domain.ErrInvalidArguments
	}
	scopeKey := "organization_id"
	scopePattern := platformUUIDPattern
	if provider == "billingbear" {
		scopeKey, scopePattern = "project_id", platformProjectIDPattern
	}
	scopeID := jsonString(config[scopeKey])
	if !scopePattern.MatchString(scopeID) {
		return domain.ErrInvalidArguments
	}
	switch operation.Name {
	case "outreach.replio.apps.list", "outreach.replio.stats.overview", "commerce.billingbear.project.stats":
	case "outreach.replio.threads.list":
		addAllowed(allowed, "app_id", "query", "status", "limit", "cursor", "waiting_for_team")
		if value, exists := arguments["app_id"]; exists && !platformUUIDPattern.MatchString(jsonString(value)) {
			return domain.ErrInvalidArguments
		}
		if value, exists := arguments["status"]; exists {
			status := jsonString(value)
			if status != "open" && status != "closed" && status != "archived" {
				return domain.ErrInvalidArguments
			}
		}
		if !optionalBoundedString(arguments["query"], 1024) || !optionalBoundedString(arguments["cursor"], 2048) ||
			!optionalInteger(arguments["limit"], 1, 200) || !optionalBoolean(arguments["waiting_for_team"]) {
			return domain.ErrInvalidArguments
		}
		if value, exists := arguments["waiting_for_team"]; exists && string(value) != "true" && string(value) != "false" {
			return domain.ErrInvalidArguments
		}
	case "outreach.replio.threads.get":
		addAllowed(allowed, "thread_id")
		if !platformUUIDPattern.MatchString(jsonString(arguments["thread_id"])) {
			return domain.ErrInvalidArguments
		}
	case "commerce.billingbear.customers.stats", "commerce.billingbear.customers.history":
		addAllowed(allowed, "app_user_id")
		if !platformCustomerIDPattern.MatchString(jsonString(arguments["app_user_id"])) {
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
	if strings.Contains(operation.Path, "{"+scopeKey+"}") {
		arguments[scopeKey], _ = json.Marshal(scopeID)
	}
	return nil
}

// This runs only after the ephemeral credential has been applied to a fresh
// request, and before any network I/O. Public SDK keys and cross-project admin
// keys must never reach BillingBear's customer endpoints through this adapter.
func validatePlatformCredential(provider, authorization string) error {
	if provider != "replio" && provider != "billingbear" {
		return nil
	}
	if !strings.HasPrefix(authorization, "Bearer ") {
		return domain.ErrProviderPermission
	}
	token := strings.TrimPrefix(authorization, "Bearer ")
	if provider == "replio" && platformReplioKeyPattern.MatchString(token) {
		return nil
	}
	if provider == "billingbear" && platformBillingKeyPattern.MatchString(token) && !strings.HasPrefix(strings.ToLower(token), "sk_admin_") {
		return nil
	}
	return domain.ErrProviderPermission
}
