package providers

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const buddyBooksPrefix = "commerce.buddybooks."

var buddyBooksKey = regexp.MustCompile(`^sps_live_[a-zA-Z0-9_-]{32,128}$`)

func buddyBooksManifest() Manifest {
	list := func(resource, description, filter string, values ...string) OperationManifest {
		op := getOp(buddyBooksPrefix+resource+".list", description, "/public/v1/"+resource,
			map[string]string{"page": "page", "page_size": "pageSize", filter: filter}, nil)
		op.InputSchema, _ = json.Marshal(map[string]any{
			"type": "object", "additionalProperties": false,
			"properties": map[string]any{
				"page":      integerProperty(1, 100000),
				"page_size": integerProperty(1, 200),
				filter:      map[string]any{"type": "string", "enum": values},
			},
		})
		return op
	}
	return Manifest{
		Provider: "buddybooks", Capability: domain.Commerce, APIVersion: "public/v1",
		OriginKind: OriginFixed, Origin: "https://os.spicysparks.com",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer", ReadOnly: true,
		MaxRequestBytes: 16 << 10, MaxResponseBytes: 2 << 20,
		Operations: []OperationManifest{
			list("documents", "List one page of accounting documents for the connected company. Use incoming for purchases. A document's status alone does not confirm payment.", "direction", "incoming", "outgoing"),
			list("invoices", "List one page of electronic invoices for the connected company, with SdI identifiers and transmission states. Use incoming for received invoices.", "direction", "incoming", "outgoing"),
			list("parties", "List one page of customer or supplier records for the connected company. Use supplier for payee records and handle returned tax identifiers as confidential.", "role", "customer", "supplier"),
		},
	}
}

func validateBuddyBooksArguments(operation OperationManifest, arguments map[string]json.RawMessage) error {
	for key, value := range arguments {
		switch key {
		case "connection_id":
			if optionalBoundedString(value, 128) {
				continue
			}
		case "provider":
			if jsonString(value) == "buddybooks" {
				continue
			}
		case "page":
			if optionalInteger(value, 1, 100000) {
				continue
			}
		case "page_size":
			if optionalInteger(value, 1, 200) {
				continue
			}
		case "role":
			if operation.Name == buddyBooksPrefix+"parties.list" && (jsonString(value) == "customer" || jsonString(value) == "supplier") {
				continue
			}
		case "direction":
			if operation.Name != buddyBooksPrefix+"parties.list" && (jsonString(value) == "incoming" || jsonString(value) == "outgoing") {
				continue
			}
		}
		return domain.ErrInvalidArguments
	}
	return nil
}

func validBuddyBooksAuthorization(value string) bool {
	return strings.HasPrefix(value, "Bearer ") && buddyBooksKey.MatchString(strings.TrimPrefix(value, "Bearer "))
}
