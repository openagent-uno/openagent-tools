package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const buddyBooksPrefix = "commerce.buddybooks."

var (
	buddyBooksKey      = regexp.MustCompile(`^sps_live_[a-zA-Z0-9_-]{32,128}$`)
	buddyBooksID       = regexp.MustCompile(`^[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$`)
	buddyBooksCountry  = regexp.MustCompile(`^[A-Z]{2}$`)
	buddyBooksCurrency = regexp.MustCompile(`^[A-Z]{3}$`)
	buddyBooksMoney    = regexp.MustCompile(`^[0-9]{1,8}(\.[0-9]{1,2})?$`)
)

const buddyBooksMaxPDF = 5 << 20

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
	receipt := func(action, description string, risk domain.Risk, confirm string) OperationManifest {
		op := buddyBooksPost("receipts."+action, description, risk, "/api/receipts", []string{
			"partyId", "number", "date", "gross", "subject", "workFrom", "workTo",
		}, map[string]any{
			"partyId": buddyBooksString(36), "number": buddyBooksString(64), "date": buddyBooksString(10),
			"gross":   map[string]any{"type": "number", "exclusiveMinimum": 0, "maximum": 99999999.99},
			"subject": buddyBooksString(512), "workFrom": buddyBooksString(10), "workTo": buddyBooksString(10),
			"taxCodeRef":       buddyBooksString(64),
			"stampDutyBorneBy": map[string]any{"type": "string", "enum": []string{"payee", "company"}},
		})
		op.FixedQuery = map[string]string{"confirm": confirm}
		return op
	}
	attachmentFields := map[string]any{"documentId": buddyBooksString(36), "contentBase64": buddyBooksString(base64.StdEncoding.EncodedLen(buddyBooksMaxPDF))}
	purchase := func(action, description string, risk domain.Risk, confirm string, us bool) OperationManifest {
		fields := map[string]any{"partyId": buddyBooksString(36), "date": buddyBooksString(10), "number": buddyBooksString(64), "dueDate": buddyBooksString(10)}
		required := []string{"partyId", "date", "number"}
		path := "/api/entry/save"
		if us {
			path = "/api/us/purchases"
			fields["description"] = buddyBooksString(512)
			fields["currency"] = buddyBooksString(3)
			fields["total"] = map[string]any{"type": "number", "exclusiveMinimum": 0, "maximum": 99999999.99}
			fields["salesTax"] = map[string]any{"type": "number", "minimum": 0, "maximum": 99999999.99}
			required = append(required, "total", "currency", "description")
		} else {
			fields["lines"] = map[string]any{
				"type": "array", "minItems": 1, "maxItems": 50,
				"items": map[string]any{
					"type": "object", "additionalProperties": false,
					"required": []string{"description", "quantity", "unitPrice", "taxCode"},
					"properties": map[string]any{
						"description": buddyBooksString(512), "taxCode": buddyBooksString(64),
						"quantity":  map[string]any{"type": "number", "exclusiveMinimum": 0},
						"unitPrice": map[string]any{"type": "number", "minimum": 0},
					},
				},
			}
			required = append(required, "lines")
		}
		op := buddyBooksPost(action, description, risk, path, required, fields)
		op.FixedQuery = map[string]string{"confirm": confirm}
		return op
	}
	return Manifest{
		Provider: "buddybooks", Capability: domain.Commerce, APIVersion: "public/v1",
		OriginKind: OriginFixed, Origin: "https://api.spicysparks.com",
		CredentialHeader: "X-API-Key", TypedOnly: true,
		MaxRequestBytes: int64(base64.StdEncoding.EncodedLen(buddyBooksMaxPDF)) + 4096, MaxResponseBytes: 2 << 20,
		Operations: []OperationManifest{
			list("documents", "List one page of accounting documents for the connected company. Use incoming for purchases. A document's status alone does not confirm payment.", "direction", "incoming", "outgoing"),
			list("invoices", "List one page of electronic invoices for the connected company, with SdI identifiers and transmission states. Use incoming for received invoices.", "direction", "incoming", "outgoing"),
			list("parties", "List one page of customer or supplier records for the connected company. Use supplier for payee records and handle returned tax identifiers as confidential.", "role", "customer", "supplier"),
			buddyBooksPost("suppliers.upsert", "Register or update a supplier in the approved company using its tax ID or VAT number. Use reviewed legal and address details. Requires approval and does not accept bank details.", domain.RiskWrite, "/api/parties",
				[]string{"name", "country", "address", "postalCode", "city"},
				map[string]any{"name": buddyBooksString(200), "country": buddyBooksString(2), "address": buddyBooksString(240), "postalCode": buddyBooksString(24), "city": buddyBooksString(120), "province": buddyBooksString(24), "taxCode": buddyBooksString(40), "vatNumber": buddyBooksString(40), "email": buddyBooksString(254), "certifiedEmail": buddyBooksString(254), "eInvoiceCode": buddyBooksString(16)}),
			receipt("preview", "Calculate an occasional-work receipt for a supplier in the connected company. Return the provider's preview without recording a document. Enter the reviewed gross amount and work dates.", domain.RiskRead, "false"),
			receipt("register", "Record an approved occasional-work receipt and its open purchase liability. Enter the same reviewed inputs as the preview. Requires a separate approval. Does not send the receipt or record payment.", domain.RiskWrite, "true"),
			buddyBooksPost("receipts.signed.attach", "Archive the reviewed signed PDF on the exact registered receipt. Requires approval. The provider's archive acknowledgement is not independent proof of signature or stamp duty.", domain.RiskWrite, "/api/receipts/{documentId}/signed",
				[]string{"documentId", "contentBase64"}, attachmentFields),
			purchase("purchases.preview", "Preview an incoming EUR supplier invoice using the accountant's explicit tax code on every line. Use the original document number and date. Does not record the purchase.", domain.RiskRead, "false", false),
			purchase("purchases.register", "Record an approved incoming EUR supplier invoice as an open purchase liability. Use exactly the reviewed lines and provider tax codes. Requires approval. Does not send to SdI or record payment.", domain.RiskWrite, "true", false),
			purchase("us_purchases.preview", "Preview the amount of an invoice received by a US company. Supply the approved currency, total, supplier and date. Does not record the purchase.", domain.RiskRead, "false", true),
			purchase("us_purchases.register", "Record an approved invoice received by a US company as an open purchase liability. Requires approval. If the provider reports a duplicate, reconcile the original instead of retrying with a new number.", domain.RiskWrite, "true", true),
			buddyBooksPost("purchases.pdf.attach", "Archive the reviewed original PDF on the exact accounting document. Requires approval. Do not substitute a generated copy for an original.", domain.RiskWrite, "/api/documents/{documentId}/attachments",
				[]string{"documentId", "contentBase64"}, attachmentFields),
		},
	}
}

func buddyBooksString(maximum int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
}

func buddyBooksPost(action, description string, risk domain.Risk, path string, required []string, fields map[string]any) OperationManifest {
	schema, _ := json.Marshal(map[string]any{"type": "object", "additionalProperties": false, "properties": fields, "required": required})
	return OperationManifest{
		Name: buddyBooksPrefix + action, Description: description, Risk: risk,
		Method: http.MethodPost, Path: path, Required: required, Body: BodyJSON,
		RequiredScopes: []string{"api", "write"}, InputSchema: schema,
		Retry: RetrySpec{MaxAttempts: 1},
	}
}

func validateBuddyBooksArguments(operation OperationManifest, arguments map[string]json.RawMessage, invocation domain.Invocation) error {
	if operation.Method == http.MethodPost {
		return prepareBuddyBooksAccounting(operation, arguments, invocation)
	}
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

func prepareBuddyBooksAccounting(operation OperationManifest, arguments map[string]json.RawMessage, invocation domain.Invocation) error {
	company := invocation.Connection.ExternalID
	if !validBuddyBooksID(company) {
		return domain.ErrInvalidArguments
	}
	var schema struct {
		Properties map[string]struct {
			Type      string   `json:"type"`
			MaxLength int      `json:"maxLength"`
			Enum      []string `json:"enum"`
		} `json:"properties"`
	}
	if json.Unmarshal(operation.InputSchema, &schema) != nil {
		return domain.ErrInvalidArguments
	}
	for key, raw := range arguments {
		if key == "connection_id" && jsonString(raw) == invocation.Connection.ID {
			continue
		}
		field, ok := schema.Properties[key]
		if !ok {
			return domain.ErrInvalidArguments
		}
		if field.Type == "number" {
			if !validBuddyBooksAmount(raw, key == "gross" || key == "total") {
				return domain.ErrInvalidArguments
			}
			continue
		}
		if field.Type == "array" {
			if !validBuddyBooksPurchaseLines(raw) {
				return domain.ErrInvalidArguments
			}
			continue
		}
		if len(field.Enum) > 0 {
			if !slices.Contains(field.Enum, jsonString(raw)) {
				return domain.ErrInvalidArguments
			}
			continue
		}
		value, err := strictJSONString(raw, field.MaxLength)
		if err != nil || strings.TrimSpace(value) != value {
			return domain.ErrInvalidArguments
		}
		switch key {
		case "partyId", "documentId":
			if !validBuddyBooksID(value) {
				return domain.ErrInvalidArguments
			}
		case "date", "workFrom", "workTo", "dueDate":
			if _, err := time.Parse(time.DateOnly, value); err != nil {
				return domain.ErrInvalidArguments
			}
		case "country":
			if !buddyBooksCountry.MatchString(value) {
				return domain.ErrInvalidArguments
			}
		case "currency":
			if !buddyBooksCurrency.MatchString(value) {
				return domain.ErrInvalidArguments
			}
		case "contentBase64":
			file, err := base64.StdEncoding.Strict().DecodeString(value)
			if err != nil || len(file) > buddyBooksMaxPDF || !bytes.HasPrefix(file, []byte("%PDF-")) {
				return domain.ErrInvalidArguments
			}
		}
	}
	// The provider checks the bound company independently against its company key.
	arguments["tenantId"], _ = json.Marshal(company)
	switch operation.Name {
	case buddyBooksPrefix + "suppliers.upsert":
		if jsonString(arguments["taxCode"]) == "" && jsonString(arguments["vatNumber"]) == "" {
			return domain.ErrInvalidArguments
		}
		arguments["role"] = json.RawMessage(`"Supplier"`)
	case buddyBooksPrefix + "receipts.preview", buddyBooksPrefix + "receipts.register":
		if jsonString(arguments["workFrom"]) > jsonString(arguments["workTo"]) {
			return domain.ErrInvalidArguments
		}
		if operation.Risk == domain.RiskWrite {
			if !validBuddyBooksID(invocation.Idempotency) {
				return domain.ErrInvalidArguments
			}
			arguments["requestId"], _ = json.Marshal(invocation.Idempotency)
		}
		arguments["kind"] = json.RawMessage(`"occasionalWork"`)
	case buddyBooksPrefix + "purchases.preview", buddyBooksPrefix + "purchases.register":
		if !validBuddyBooksID(invocation.Idempotency) {
			return domain.ErrInvalidArguments
		}
		arguments["requestId"], _ = json.Marshal(invocation.Idempotency)
		arguments["direction"] = json.RawMessage(`"Incoming"`)
		arguments["currency"] = json.RawMessage(`"EUR"`)
		arguments["documentType"] = json.RawMessage(`"TD01"`)
		arguments["series"] = json.RawMessage(`""`)
	case buddyBooksPrefix + "us_purchases.preview", buddyBooksPrefix + "us_purchases.register":
		// The provider accepts only its US jurisdiction for these operations.
	case buddyBooksPrefix + "receipts.signed.attach", buddyBooksPrefix + "purchases.pdf.attach":
		arguments["kind"] = json.RawMessage(`"pdf"`)
	default:
		return domain.ErrUnsupported
	}
	return nil
}

func validBuddyBooksAmount(raw json.RawMessage, positive bool) bool {
	return buddyBooksMoney.Match(raw) && (!positive || strings.Trim(string(raw), "0.") != "")
}

func validBuddyBooksPurchaseLines(raw json.RawMessage) bool {
	var lines []json.RawMessage
	if json.Unmarshal(raw, &lines) != nil || len(lines) == 0 || len(lines) > 50 {
		return false
	}
	for _, line := range lines {
		fields, err := decodeArguments(line, 2048)
		if err != nil || len(fields) != 4 {
			return false
		}
		description, descriptionErr := strictJSONString(fields["description"], 512)
		taxCode, taxCodeErr := strictJSONString(fields["taxCode"], 64)
		if descriptionErr != nil || taxCodeErr != nil || strings.TrimSpace(description) != description ||
			strings.TrimSpace(taxCode) != taxCode || !validBuddyBooksAmount(fields["quantity"], true) ||
			!validBuddyBooksAmount(fields["unitPrice"], false) {
			return false
		}
	}
	return true
}

func validBuddyBooksID(value string) bool {
	return buddyBooksID.MatchString(value) && strings.Trim(value, "0-") != ""
}
