package providers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const (
	GoogleAnalyticsReadScope       = "https://www.googleapis.com/auth/analytics.readonly"
	googleAnalyticsDataOrigin      = "https://analyticsdata.googleapis.com"
	googleAnalyticsAdminOrigin     = "https://analyticsadmin.googleapis.com"
	googleAnalyticsNamePattern     = `^[A-Za-z][A-Za-z0-9_:]{0,127}$`
	googleAnalyticsPropertyPattern = `^[1-9][0-9]{0,19}$`
	googleAnalyticsDatePattern     = `^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{1,4}daysAgo|today|yesterday)$`
)

var (
	analyticsPropertyID   = regexp.MustCompile(googleAnalyticsPropertyPattern)
	analyticsFieldName    = regexp.MustCompile(googleAnalyticsNamePattern)
	analyticsDecimal      = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,9})$`)
	analyticsRelativeDate = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})daysAgo$`)
)

// Both origins and all methods are static manifest data. The numeric property
// identifier never determines a host, API version, method or arbitrary path.
func googleAnalyticsManifest() Manifest {
	return Manifest{
		Provider: "google_analytics", Capability: domain.Ads, APIVersion: "v1beta",
		OriginKind: OriginFixed, Origin: googleAnalyticsDataOrigin,
		CredentialHeader: "Authorization", CredentialScheme: "Bearer", ReadOnly: true,
		MaxRequestBytes: 64 << 10, MaxResponseBytes: 8 << 20,
		Operations: []OperationManifest{
			{
				Name:        "ads.google_analytics.account_summaries.list",
				Description: "List accessible Analytics accounts and their GA4 property summaries; follow nextPageToken for subsequent pages",
				Risk:        domain.RiskRead, Method: http.MethodGet, Path: "/v1beta/accountSummaries", Origin: googleAnalyticsAdminOrigin,
				Query: map[string]string{"page_size": "pageSize", "page_token": "pageToken"}, Body: BodyNone,
				InputSchema:    analyticsSchema(map[string]any{"page_size": integerProperty(1, 200), "page_token": boundedStringProperty(2048)}),
				RequiredScopes: []string{GoogleAnalyticsReadScope}, Retry: readRetry,
			},
			{
				Name:        "ads.google_analytics.reports.run",
				Description: "Read a bounded GA4 report with named metrics, dimensions and date ranges; default 1000 and maximum 10000 rows, paginate using body.offset and the returned rowCount",
				Risk:        domain.RiskRead, Method: http.MethodPost, Path: "/v1beta/properties/{property_id}:runReport", Body: BodyJSON,
				Required: []string{"property_id", "body"}, InputSchema: analyticsReportSchema(false),
				RequiredScopes: []string{GoogleAnalyticsReadScope}, Retry: readRetry,
			},
			{
				Name:        "ads.google_analytics.realtime.run",
				Description: "Read a bounded GA4 realtime report for the provider default last 30 minutes; default 1000 and maximum 10000 rows",
				Risk:        domain.RiskRead, Method: http.MethodPost, Path: "/v1beta/properties/{property_id}:runRealtimeReport", Body: BodyJSON,
				Required: []string{"property_id", "body"}, InputSchema: analyticsReportSchema(true),
				RequiredScopes: []string{GoogleAnalyticsReadScope}, Retry: readRetry,
			},
			{
				Name:        "ads.google_analytics.metadata.get",
				Description: "Read available GA4 dimensions and metrics, including property-specific custom fields; property_id 0 returns universal metadata",
				Risk:        domain.RiskRead, Method: http.MethodGet, Path: "/v1beta/properties/{property_id}/metadata", Body: BodyNone,
				Required: []string{"property_id"}, InputSchema: analyticsSchema(map[string]any{"property_id": stringProperty(`^(?:0|[1-9][0-9]{0,19})$`)}, "property_id"),
				RequiredScopes: []string{GoogleAnalyticsReadScope}, Retry: readRetry,
			},
		},
	}
}

func analyticsSchema(properties map[string]any, required ...string) json.RawMessage {
	properties["connection_id"] = boundedStringProperty(128)
	properties["provider"] = map[string]any{"type": "string", "const": "google_analytics"}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	encoded, _ := json.Marshal(schema)
	return encoded
}

func analyticsReportSchema(realtime bool) json.RawMessage {
	namedField := map[string]any{
		"type": "object", "properties": map[string]any{"name": stringProperty(googleAnalyticsNamePattern)},
		"required": []string{"name"}, "additionalProperties": false,
	}
	metrics := arrayProperty(namedField, 10)
	metrics["minItems"] = 1
	properties := map[string]any{
		"metrics": metrics, "dimensions": arrayProperty(namedField, 9),
		"limit":               map[string]any{"type": "string", "pattern": `^(?:[1-9][0-9]{0,3}|10000)$`, "default": "1000"},
		"returnPropertyQuota": map[string]any{"type": "boolean"},
	}
	required := []string{"metrics"}
	if !realtime {
		ranges := arrayProperty(map[string]any{
			"type": "object", "properties": map[string]any{
				"startDate": stringProperty(googleAnalyticsDatePattern), "endDate": stringProperty(googleAnalyticsDatePattern),
			}, "required": []string{"startDate", "endDate"}, "additionalProperties": false,
		}, 4)
		ranges["minItems"] = 1
		properties["dateRanges"] = ranges
		properties["offset"] = map[string]any{"type": "string", "pattern": `^(?:0|[1-9][0-9]{0,8}|1000000000)$`}
		properties["keepEmptyRows"] = map[string]any{"type": "boolean"}
		required = append(required, "dateRanges")
	}
	return analyticsSchema(map[string]any{
		"property_id": stringProperty(googleAnalyticsPropertyPattern),
		"body":        map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false},
	}, "property_id", "body")
}

func validateGoogleAnalyticsArguments(operation OperationManifest, arguments map[string]json.RawMessage) error {
	allowed := map[string]bool{"connection_id": true, "provider": true}
	for _, raw := range arguments {
		if !analyticsNonNullJSON(raw) {
			return domain.ErrInvalidArguments
		}
	}
	if raw, exists := arguments["provider"]; exists && jsonString(raw) != "google_analytics" {
		return domain.ErrInvalidArguments
	}
	if raw, exists := arguments["connection_id"]; exists && !domain.ValidResourceID(jsonString(raw)) {
		return domain.ErrInvalidArguments
	}
	switch operation.Name {
	case "ads.google_analytics.account_summaries.list":
		addAllowed(allowed, "page_size", "page_token")
		if !optionalInteger(arguments["page_size"], 1, 200) || !optionalBoundedString(arguments["page_token"], 2048) {
			return domain.ErrInvalidArguments
		}
	case "ads.google_analytics.metadata.get":
		addAllowed(allowed, "property_id")
		id := jsonString(arguments["property_id"])
		if id != "0" && !analyticsPropertyID.MatchString(id) {
			return domain.ErrInvalidArguments
		}
	case "ads.google_analytics.reports.run", "ads.google_analytics.realtime.run":
		addAllowed(allowed, "property_id", "body")
		if !analyticsPropertyID.MatchString(jsonString(arguments["property_id"])) {
			return domain.ErrInvalidArguments
		}
		body, err := normalizeAnalyticsReport(arguments["body"], operation.Name == "ads.google_analytics.realtime.run")
		if err != nil {
			return err
		}
		arguments["body"] = body
	default:
		return domain.ErrUnsupported
	}
	for key := range arguments {
		if !allowed[key] {
			return domain.ErrInvalidArguments
		}
	}
	return nil
}

type analyticsNamedField struct {
	Name string `json:"name"`
}
type analyticsDateRange struct {
	StartDate string `json:"startDate"`
	EndDate   string `json:"endDate"`
}
type analyticsReport struct {
	Dimensions          []analyticsNamedField `json:"dimensions,omitempty"`
	Metrics             []analyticsNamedField `json:"metrics"`
	DateRanges          []analyticsDateRange  `json:"dateRanges,omitempty"`
	Limit               string                `json:"limit"`
	Offset              string                `json:"offset,omitempty"`
	KeepEmptyRows       *bool                 `json:"keepEmptyRows,omitempty"`
	ReturnPropertyQuota *bool                 `json:"returnPropertyQuota,omitempty"`
}

func normalizeAnalyticsReport(raw json.RawMessage, realtime bool) (json.RawMessage, error) {
	var report analyticsReport
	var fields map[string]json.RawMessage
	if !analyticsNonNullJSON(raw) || strictJSON(raw, &report) != nil || json.Unmarshal(raw, &fields) != nil || fields == nil ||
		len(report.Metrics) < 1 || len(report.Metrics) > 10 || len(report.Dimensions) > 9 {
		return nil, domain.ErrInvalidArguments
	}
	for _, collection := range [][]analyticsNamedField{report.Metrics, report.Dimensions} {
		seen := map[string]bool{}
		for _, field := range collection {
			if !analyticsFieldName.MatchString(field.Name) || seen[field.Name] {
				return nil, domain.ErrInvalidArguments
			}
			seen[field.Name] = true
		}
	}
	if _, exists := fields["limit"]; !exists {
		report.Limit = "1000"
	}
	if !analyticsBoundedDecimal(report.Limit, 1, 10000) {
		return nil, domain.ErrInvalidArguments
	}
	if realtime {
		for _, key := range []string{"dateRanges", "offset", "keepEmptyRows"} {
			if _, exists := fields[key]; exists {
				return nil, domain.ErrInvalidArguments
			}
		}
	} else {
		if len(report.DateRanges) < 1 || len(report.DateRanges) > 4 {
			return nil, domain.ErrInvalidArguments
		}
		if _, exists := fields["offset"]; exists && !analyticsBoundedDecimal(report.Offset, 0, 1000000000) {
			return nil, domain.ErrInvalidArguments
		}
		for _, dates := range report.DateRanges {
			if !analyticsDateValid(dates.StartDate) || !analyticsDateValid(dates.EndDate) {
				return nil, domain.ErrInvalidArguments
			}
			start, startErr := time.Parse("2006-01-02", dates.StartDate)
			end, endErr := time.Parse("2006-01-02", dates.EndDate)
			if startErr == nil && endErr == nil && start.After(end) {
				return nil, domain.ErrInvalidArguments
			}
		}
	}
	return json.Marshal(report)
}

func analyticsBoundedDecimal(value string, minimum, maximum int64) bool {
	if !analyticsDecimal.MatchString(value) {
		return false
	}
	number, err := strconv.ParseInt(value, 10, 64)
	return err == nil && number >= minimum && number <= maximum
}

func analyticsDateValid(value string) bool {
	if value == "today" || value == "yesterday" {
		return true
	}
	if analyticsRelativeDate.MatchString(value) {
		number, _ := strconv.Atoi(strings.TrimSuffix(value, "daysAgo"))
		return number <= 3650
	}
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Format("2006-01-02") == value && parsed.Year() >= 2000
}

// Reject null instead of allowing Go's zero-value decoding to accept invalid
// optional fields. The request size bounds also bound this traversal.
func analyticsNonNullJSON(raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	var valid func(any) bool
	valid = func(item any) bool {
		switch item := item.(type) {
		case nil:
			return false
		case []any:
			for _, child := range item {
				if !valid(child) {
					return false
				}
			}
		case map[string]any:
			for _, child := range item {
				if !valid(child) {
					return false
				}
			}
		}
		return true
	}
	return valid(value)
}
