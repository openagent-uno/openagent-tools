package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// time.Parse also accepts comma fractions and out-of-range numeric offsets.
// This local RFC3339 subset bounds fractions to nanoseconds before parsing the
// calendar date itself. It intentionally preserves the existing uppercase T/Z.
var calendarRFC3339Pattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

func calendarRFC3339(value string) (time.Time, error) {
	if !calendarRFC3339Pattern.MatchString(value) {
		return time.Time{}, domain.ErrInvalidArguments
	}
	return time.Parse(time.RFC3339Nano, value)
}

const (
	GoogleCalendarListScope         = "https://www.googleapis.com/auth/calendar.calendarlist.readonly"
	GoogleCalendarEventsScope       = "https://www.googleapis.com/auth/calendar.events"
	googleCalendarOrigin            = "https://www.googleapis.com/calendar/v3"
	googleCalendarMaxRequest        = 64 << 10
	googleCalendarMaxResponse int64 = 4 << 20
)

// GoogleCalendarAdapter is a connection-bound Calendar v3 subset. It owns no
// sync state: hosts persist each query profile, page cursor and final sync token
// atomically with their projection. A 410 requires an explicit host reset decision.
// Sources: developers.google.com/workspace/calendar/api/v3/reference/{calendarList,events}
// and /api/guides/{sync,version-resources}. Local bounds below are not API maxima.
type GoogleCalendarAdapter struct{ doer HTTPDoer }

// NewGoogleCalendarAdapter uses the runner's bounded, no-redirect HTTP transport.
// No endpoint, credential header or remote operation is supplied by a caller.
func NewGoogleCalendarAdapter(doer HTTPDoer) (*GoogleCalendarAdapter, error) {
	if doer == nil {
		return nil, errors.New("Google Calendar transport is required")
	}
	if client, ok := doer.(*http.Client); ok {
		copy := *client
		copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		doer = &copy
	}
	return &GoogleCalendarAdapter{doer: doer}, nil
}

func (a *GoogleCalendarAdapter) Provider() string              { return "google_calendar" }
func (a *GoogleCalendarAdapter) Capability() domain.Capability { return domain.Files }

// OperationScopesGranted recognizes only scope alternatives listed by Google's
// seven compiled API methods. RequiredScopes continues to advertise the minimal
// default consent. In particular, an events.readonly token never grants writes.
func (a *GoogleCalendarAdapter) OperationScopesGranted(granted []string, operationName string) bool {
	if !domain.ValidProviderScopes(granted) {
		return false
	}
	allowed := []string{}
	switch operationName {
	case "files.google_calendar.calendars.list", "files.google_calendar.calendars.get":
		allowed = []string{GoogleCalendarListScope, "https://www.googleapis.com/auth/calendar.calendarlist", "https://www.googleapis.com/auth/calendar.readonly", "https://www.googleapis.com/auth/calendar"}
	case "files.google_calendar.events.list", "files.google_calendar.events.get":
		allowed = []string{GoogleCalendarEventsScope, "https://www.googleapis.com/auth/calendar.events.readonly", "https://www.googleapis.com/auth/calendar.readonly", "https://www.googleapis.com/auth/calendar"}
	case "files.google_calendar.events.create", "files.google_calendar.events.update", "files.google_calendar.events.delete":
		allowed = []string{GoogleCalendarEventsScope, "https://www.googleapis.com/auth/calendar"}
	default:
		return false
	}
	for _, scope := range allowed {
		if domain.GrantsScopes(granted, []string{scope}) {
			return true
		}
	}
	return false
}

func calendarObjectSchema(properties map[string]any, required ...string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}

func calendarStringSchema(maximum int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
}

func calendarEventSchema(create bool) map[string]any {
	when := calendarObjectSchema(map[string]any{
		"date":     map[string]any{"type": "string", "format": "date"},
		"dateTime": map[string]any{"type": "string", "format": "date-time", "description": "RFC3339 with an explicit UTC offset."},
		"timeZone": calendarStringSchema(128),
	})
	when["oneOf"] = []any{map[string]any{"required": []string{"date"}, "not": map[string]any{"required": []string{"dateTime"}}}, map[string]any{"required": []string{"dateTime"}, "not": map[string]any{"required": []string{"date"}}}}
	properties := map[string]any{
		"summary":     map[string]any{"type": "string", "maxLength": 1024},
		"description": map[string]any{"type": "string", "maxLength": 16384},
		"location":    map[string]any{"type": "string", "maxLength": 2048},
		"start":       when, "end": when,
		"recurrence":   map[string]any{"type": "array", "maxItems": 16, "uniqueItems": true, "items": calendarStringSchema(1024), "description": "RRULE/EXRULE/RDATE/EXDATE only; arrays replace the previous array. Recurring writes require start/end with IANA time zones."},
		"status":       map[string]any{"type": "string", "enum": []string{"confirmed", "tentative"}},
		"visibility":   map[string]any{"type": "string", "enum": []string{"default", "public", "private", "confidential"}},
		"transparency": map[string]any{"type": "string", "enum": []string{"opaque", "transparent"}},
	}
	if create {
		return calendarObjectSchema(properties, "start", "end")
	}
	schema := calendarObjectSchema(properties)
	schema["minProperties"] = 1
	schema["dependentRequired"] = map[string]any{"start": []string{"end"}, "end": []string{"start"}}
	return schema
}

// Operations returns the canonical seven typed definitions for central wiring.
// Both event reads and writes require calendar.events; the OAuth registration
// does not request a redundant events.readonly scope. The optional provider-only
// scope policy recognizes documented read-only and broader Calendar consents.
func (a *GoogleCalendarAdapter) Operations() []domain.Operation {
	operations := []domain.Operation{}
	add := func(name, description, method, path string, risk domain.Risk, properties map[string]any, required ...string) {
		properties["connection_id"] = calendarStringSchema(128)
		properties["provider"] = map[string]any{"type": "string", "enum": []string{a.Provider()}}
		schema, _ := json.Marshal(calendarObjectSchema(properties, required...))
		scope := GoogleCalendarEventsScope
		if strings.HasPrefix(name, "calendars.") {
			scope = GoogleCalendarListScope
		}
		operations = append(operations, domain.Operation{Name: "files.google_calendar." + name, Description: description, Provider: a.Provider(), Capability: domain.Files, Risk: risk, Mode: domain.OperationTyped, InputSchema: schema, RequiredScopes: []string{scope}, Retry: domain.RetryPolicy{MaxAttempts: 1}, Preview: domain.ActionPreview{Method: method, Path: "/calendar/v3" + path, Summary: description}})
	}
	cursors := func() map[string]any {
		return map[string]any{"max_results": map[string]any{"type": "integer", "minimum": 1, "maximum": 250}, "page_token": calendarStringSchema(4096), "sync_token": calendarStringSchema(4096)}
	}
	add("calendars.list", "List CalendarList entries including hidden/deleted entries. Persist identical query parameters with page and sync cursors; 410 requires a host-authorized reset.", "GET", "/users/me/calendarList", domain.RiskRead, cursors())
	add("calendars.get", "Read an entry on this account's CalendarList.", "GET", "/users/me/calendarList/{calendar_id}", domain.RiskRead, map[string]any{"calendar_id": calendarStringSchema(1024)}, "calendar_id")
	list := cursors()
	list["calendar_id"] = calendarStringSchema(1024)
	list["time_min"] = map[string]any{"type": "string", "format": "date-time", "maxLength": 64}
	list["time_max"] = map[string]any{"type": "string", "format": "date-time", "maxLength": 64}
	list["query"] = calendarStringSchema(1024)
	list["single_events"] = map[string]any{"type": "boolean", "description": "Expand recurring events; preserve this setting and the whole query profile across pagination/incremental sync."}
	add("events.list", "List one event page including cancellation tombstones. time_min/time_max/query cannot accompany sync_token. Persist query profile and final nextSyncToken locally.", "GET", "/calendars/{calendar_id}/events", domain.RiskRead, list, "calendar_id")
	ids := func() map[string]any {
		return map[string]any{"calendar_id": calendarStringSchema(1024), "event_id": calendarStringSchema(1024)}
	}
	add("events.get", "Read an event and its ETag, including cancelled instances.", "GET", "/calendars/{calendar_id}/events/{event_id}", domain.RiskRead, ids(), "calendar_id", "event_id")
	add("events.create", "Create a normal event once. No attendees, conferencing or arbitrary event properties are accepted.", "POST", "/calendars/{calendar_id}/events", domain.RiskWrite, map[string]any{"calendar_id": calendarStringSchema(1024), "body": calendarEventSchema(true)}, "calendar_id", "body")
	update := ids()
	update["etag"] = calendarStringSchema(512)
	update["body"] = calendarEventSchema(false)
	add("events.update", "PATCH supplied event fields once using the exact strong ETag from a read. Arrays replace previous arrays; 412 is a conflict requiring a new host decision. Google charges three quota units for PATCH and may notify existing guests.", "PATCH", "/calendars/{calendar_id}/events/{event_id}", domain.RiskWrite, update, "calendar_id", "event_id", "etag", "body")
	remove := ids()
	remove["etag"] = calendarStringSchema(512)
	add("events.delete", "Delete once using the exact strong ETag from a read. A conflict never causes a retry or overwrite. Google may notify existing guests.", "DELETE", "/calendars/{calendar_id}/events/{event_id}", domain.RiskDestructive, remove, "calendar_id", "event_id", "etag")
	return operations
}

type calendarPlan struct {
	operation domain.Operation
	url       string
	body      []byte
	etag      string
	limit     int
}

func (a *GoogleCalendarAdapter) plan(inv domain.Invocation) (calendarPlan, error) {
	var p calendarPlan
	for _, op := range a.Operations() {
		if op.Name == inv.Operation.Name {
			p.operation = op
			break
		}
	}
	op := p.operation
	if inv.ID == "" || len(inv.ID) > 256 {
		return p, domain.ErrDenied
	}
	if op.Name == "" || inv.Operation.Provider != a.Provider() || inv.Operation.Capability != domain.Files || inv.Operation.Risk != op.Risk || inv.Operation.Mode != domain.OperationTyped || inv.Connection.Provider != a.Provider() || inv.Connection.Validate(inv.Principal.WorkspaceID, domain.Files) != nil || !a.OperationScopesGranted(inv.Connection.Scopes, op.Name) {
		return p, domain.ErrDenied
	}
	if inv.Principal.BoundConnectionID != "" && inv.Principal.BoundConnectionID != inv.Connection.ID {
		return p, domain.ErrDenied
	}
	// Configuration is deliberately empty; neither account binding nor endpoint
	// can be redirected through a provider config object.
	if len(inv.Connection.Config) > 0 {
		config, err := calendarJSON(inv.Connection.Config, googleCalendarMaxRequest)
		if err != nil || len(config) != 0 {
			return p, domain.ErrInvalidArguments
		}
	}
	args, err := calendarJSON(inv.Arguments, googleCalendarMaxRequest)
	if err != nil {
		return p, domain.ErrInvalidArguments
	}
	var schema struct {
		Properties map[string]json.RawMessage
		Required   []string
	}
	if json.Unmarshal(op.InputSchema, &schema) != nil {
		return p, domain.ErrInvalidArguments
	}
	for key := range args {
		if _, ok := schema.Properties[key]; !ok {
			return p, domain.ErrInvalidArguments
		}
	}
	for _, key := range schema.Required {
		if _, ok := args[key]; !ok {
			return p, domain.ErrInvalidArguments
		}
	}
	if value, exists := args["connection_id"]; exists && value != inv.Connection.ID {
		return p, domain.ErrDenied
	}
	if value, exists := args["provider"]; exists && value != a.Provider() {
		return p, domain.ErrDenied
	}
	path := op.Preview.Path
	for _, key := range []string{"calendar_id", "event_id"} {
		if value, present := args[key]; present {
			text, ok := value.(string)
			if !ok || !calendarOpaque(text, 1024) || text == "." || text == ".." {
				return p, domain.ErrInvalidArguments
			}
			path = strings.ReplaceAll(path, "{"+key+"}", url.PathEscape(text))
		}
	}
	query := url.Values{}
	p.limit = 100
	if strings.HasSuffix(op.Name, ".list") {
		if value, present := args["max_results"]; present {
			number, ok := value.(json.Number)
			if !ok {
				return p, domain.ErrInvalidArguments
			}
			parsed, err := strconv.Atoi(string(number))
			if err != nil || parsed < 1 || parsed > 250 {
				return p, domain.ErrInvalidArguments
			}
			p.limit = parsed
		}
		query.Set("maxResults", strconv.Itoa(p.limit))
		query.Set("showDeleted", "true")
		if strings.Contains(op.Name, ".calendars.") {
			query.Set("showHidden", "true")
		} else {
			query.Set("singleEvents", "false")
		}
	}
	for local, remote := range map[string]string{"page_token": "pageToken", "sync_token": "syncToken"} {
		if value, present := args[local]; present {
			text, ok := value.(string)
			if !ok || !calendarOpaque(text, 4096) {
				return p, domain.ErrInvalidArguments
			}
			query.Set(remote, text)
		}
	}
	if strings.HasSuffix(op.Name, "events.list") {
		if value, present := args["single_events"]; present {
			boolean, ok := value.(bool)
			if !ok {
				return p, domain.ErrInvalidArguments
			}
			query.Set("singleEvents", strconv.FormatBool(boolean))
		}
		for local, remote := range map[string]string{"time_min": "timeMin", "time_max": "timeMax", "query": "q"} {
			if value, present := args[local]; present {
				text, ok := value.(string)
				if !ok || !calendarText(text, 1024, false) || text == "" || query.Get("syncToken") != "" {
					return p, domain.ErrInvalidArguments
				}
				if local != "query" {
					if len(text) > 64 {
						return p, domain.ErrInvalidArguments
					}
					if _, err := calendarRFC3339(text); err != nil {
						return p, domain.ErrInvalidArguments
					}
				}
				query.Set(remote, text)
			}
		}
		if query.Get("timeMin") != "" && query.Get("timeMax") != "" {
			start, _ := calendarRFC3339(query.Get("timeMin"))
			end, _ := calendarRFC3339(query.Get("timeMax"))
			if !end.After(start) {
				return p, domain.ErrInvalidArguments
			}
		}
	}
	if value, present := args["etag"]; present {
		text, ok := value.(string)
		if !ok || !calendarETag(text) {
			return p, domain.ErrInvalidArguments
		}
		p.etag = text
	}
	if raw, present := args["body"]; present {
		body, ok := raw.(map[string]any)
		if !ok || !calendarValidEvent(body, op.Preview.Method == http.MethodPost) {
			return p, domain.ErrInvalidArguments
		}
		p.body, err = json.Marshal(body)
		if err != nil || len(p.body) > googleCalendarMaxRequest {
			return p, domain.ErrInvalidArguments
		}
	}
	// Notifications use Google's documented default. This subset cannot add
	// guests, but existing guests may receive provider-defined notifications.
	// No misleading promise of zero emails or hidden sendUpdates=none is made.
	p.url = googleCalendarOrigin + strings.TrimPrefix(path, "/calendar/v3")
	if len(query) > 0 {
		p.url += "?" + query.Encode()
	}
	return p, nil
}

func (a *GoogleCalendarAdapter) Preview(inv domain.Invocation) (domain.ActionPreview, error) {
	p, err := a.plan(inv)
	if err != nil {
		return domain.ActionPreview{}, err
	}
	u, _ := url.Parse(p.url)
	return domain.ActionPreview{Method: p.operation.Preview.Method, Path: u.EscapedPath(), Summary: p.operation.Description}, nil
}

func (a *GoogleCalendarAdapter) Invoke(ctx context.Context, inv domain.Invocation) (domain.Result, error) {
	p, err := a.plan(inv)
	if err != nil {
		return domain.Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, p.operation.Preview.Method, p.url, bytes.NewReader(p.body))
	if err != nil {
		return domain.Result{}, domain.ErrInvalidArguments
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "OpenAgent-Connectors/google-calendar-v3")
	if len(p.body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.etag != "" {
		req.Header.Set("If-Match", p.etag)
	}
	if err := inv.Credential.Apply(req.Header, "Authorization", "Bearer", time.Now().UTC()); err != nil {
		return domain.Result{}, domain.ErrDenied
	}
	response, err := a.doer.Do(req)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return domain.Result{}, &domain.ProviderError{Kind: "network_error", Attempts: 1, RequestBytes: int64(len(p.body))}
	}
	if response == nil || response.Body == nil {
		return domain.Result{}, &domain.ProviderError{Kind: "invalid_response", Attempts: 1}
	}
	data, tooLarge, readErr := readBounded(response.Body, googleCalendarMaxResponse)
	_ = response.Body.Close()
	result := domain.Result{ProviderStatus: response.StatusCode, Attempts: 1, RequestBytes: int64(len(p.body)), ResponseBytes: int64(len(data)), Metadata: map[string]string{"api_version": "v3", "operation": p.operation.Name}}
	fail := func(kind string) (domain.Result, error) {
		return result, &domain.ProviderError{Kind: kind, StatusCode: response.StatusCode, Attempts: 1, RequestBytes: result.RequestBytes, ResponseBytes: result.ResponseBytes}
	}
	if readErr != nil || tooLarge {
		return fail("invalid_response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		switch response.StatusCode {
		case 410:
			if strings.HasSuffix(p.operation.Name, ".list") {
				return fail("sync_reset_required")
			}
			return fail("resource_gone")
		case 412:
			return fail("version_conflict")
		case 429:
			return fail("rate_limited")
		case 401, 403:
			_, providerErr := fail("provider_permission")
			return result, errors.Join(domain.ErrProviderPermission, providerErr)
		default:
			return fail("provider_error")
		}
	}
	if p.operation.Preview.Method == http.MethodDelete {
		if response.StatusCode != http.StatusNoContent || len(bytes.TrimSpace(data)) != 0 {
			return fail("invalid_response")
		}
		result.Data = map[string]any{"deleted": true}
		return result, nil
	}
	object, err := calendarJSON(inv.Credential.Redact(data), int(googleCalendarMaxResponse))
	if err != nil || !calendarValidResponse(object, p) {
		return fail("invalid_response")
	}
	result.Data = object
	return result, nil
}

func calendarOpaque(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func calendarText(value string, maximum int, multiline bool) bool {
	if !utf8.ValidString(value) || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if r == 0x7f || (r < 0x20 && !(multiline && (r == '\n' || r == '\r' || r == '\t'))) {
			return false
		}
	}
	return true
}

func calendarETag(value string) bool {
	if len(value) < 3 || len(value) > 512 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for _, r := range value[1 : len(value)-1] {
		if r < 0x21 || r > 0x7e || r == '"' {
			return false
		}
	}
	return true
}

func calendarValidEvent(body map[string]any, create bool) bool {
	if len(body) == 0 {
		return false
	}
	for key, value := range body {
		switch key {
		case "summary", "description", "location":
			text, ok := value.(string)
			maximum := 1024
			if key == "description" {
				maximum = 16384
			} else if key == "location" {
				maximum = 2048
			}
			if !ok || !calendarText(text, maximum, key == "description") {
				return false
			}
		case "start", "end": // Checked together below.
		case "recurrence":
			lines, ok := value.([]any)
			if !ok || len(lines) > 16 {
				return false
			}
			seen := map[string]bool{}
			for _, line := range lines {
				text, ok := line.(string)
				if !ok || seen[text] || !calendarRecurrence(text) {
					return false
				}
				seen[text] = true
			}
		case "status", "visibility", "transparency":
			text, ok := value.(string)
			allowed := []string{"confirmed", "tentative"}
			if key == "visibility" {
				allowed = []string{"default", "public", "private", "confidential"}
			} else if key == "transparency" {
				allowed = []string{"opaque", "transparent"}
			}
			if !ok || !calendarMember(text, allowed...) {
				return false
			}
		default:
			return false
		}
	}
	start, startPresent := body["start"]
	end, endPresent := body["end"]
	if startPresent != endPresent || (create && !startPresent) {
		return false
	}
	recurring := false
	if lines, ok := body["recurrence"].([]any); ok && len(lines) > 0 {
		recurring = true
		if !startPresent {
			return false
		}
	}
	if startPresent {
		s, sd, sz, ok := calendarWhen(start)
		if !ok {
			return false
		}
		e, ed, ez, ok := calendarWhen(end)
		if !ok || sd != ed || !e.After(s) || (recurring && (sz == "" || ez == "" || sz != ez)) {
			return false
		}
		if recurring {
			for _, line := range body["recurrence"].([]any) {
				if !calendarRecurrenceContext(line.(string), sd) {
					return false
				}
			}
		}
	}
	return true
}

func calendarWhen(value any) (time.Time, bool, string, bool) {
	var zero time.Time
	object, ok := value.(map[string]any)
	if !ok || len(object) < 1 || len(object) > 2 {
		return zero, false, "", false
	}
	for key := range object {
		if key != "date" && key != "dateTime" && key != "timeZone" {
			return zero, false, "", false
		}
	}
	zone := ""
	var location *time.Location
	if raw, present := object["timeZone"]; present {
		var ok bool
		zone, ok = raw.(string)
		if !ok || !calendarOpaque(zone, 128) {
			return zero, false, "", false
		}
		var err error
		location, err = time.LoadLocation(zone)
		if err != nil || zone == "Local" {
			return zero, false, "", false
		}
	}
	date, datePresent := object["date"]
	datetime, timePresent := object["dateTime"]
	if datePresent == timePresent {
		return zero, false, "", false
	}
	if datePresent {
		text, ok := date.(string)
		if !ok || len(text) != 10 {
			return zero, false, "", false
		}
		parsed, err := time.Parse("2006-01-02", text)
		return parsed, true, zone, err == nil
	}
	text, ok := datetime.(string)
	if !ok || len(text) > 64 {
		return zero, false, "", false
	}
	parsed, err := calendarRFC3339(text)
	if err != nil {
		return zero, false, "", false
	}
	if location != nil {
		_, supplied := parsed.Zone()
		_, actual := parsed.In(location).Zone()
		if supplied != actual {
			return zero, false, "", false
		}
	}
	return parsed, false, zone, true
}

// RFC5545's supported recurrence lines are locally bounded and never contain
// DTSTART/DTEND, line folding, arbitrary parameters, URLs or embedded newlines.
func calendarRecurrence(line string) bool {
	if !calendarOpaque(line, 1024) {
		return false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return false
	}
	header := strings.Split(parts[0], ";")
	kind := header[0]
	if kind == "RRULE" || kind == "EXRULE" {
		if len(header) != 1 {
			return false
		}
		seen := map[string]bool{}
		for _, field := range strings.Split(parts[1], ";") {
			pair := strings.SplitN(field, "=", 2)
			if len(pair) != 2 || pair[1] == "" || seen[pair[0]] {
				return false
			}
			seen[pair[0]] = true
			switch pair[0] {
			case "FREQ":
				if !calendarMember(pair[1], "SECONDLY", "MINUTELY", "HOURLY", "DAILY", "WEEKLY", "MONTHLY", "YEARLY") {
					return false
				}
			case "COUNT", "INTERVAL":
				n, err := strconv.Atoi(pair[1])
				if err != nil || n < 1 || n > 10000 {
					return false
				}
			case "UNTIL":
				if !calendarRecurrenceDate(pair[1], true) {
					return false
				}
			case "WKST":
				if !calendarMember(pair[1], "MO", "TU", "WE", "TH", "FR", "SA", "SU") {
					return false
				}
			case "BYDAY":
				for _, day := range strings.Split(pair[1], ",") {
					if len(day) < 2 || !calendarMember(day[len(day)-2:], "MO", "TU", "WE", "TH", "FR", "SA", "SU") {
						return false
					}
					if len(day) > 2 {
						n, err := strconv.Atoi(day[:len(day)-2])
						if err != nil || n == 0 || n < -53 || n > 53 {
							return false
						}
					}
				}
			case "BYSECOND", "BYMINUTE", "BYHOUR", "BYMONTHDAY", "BYYEARDAY", "BYWEEKNO", "BYMONTH", "BYSETPOS":
				maximum, minimum := 366, -366
				switch pair[0] {
				case "BYSECOND":
					minimum, maximum = 0, 60
				case "BYMINUTE":
					minimum, maximum = 0, 59
				case "BYHOUR":
					minimum, maximum = 0, 23
				case "BYMONTH":
					minimum, maximum = 1, 12
				case "BYMONTHDAY":
					minimum, maximum = -31, 31
				case "BYWEEKNO":
					minimum, maximum = -53, 53
				}
				for _, entry := range strings.Split(pair[1], ",") {
					n, err := strconv.Atoi(entry)
					if err != nil || n < minimum || n > maximum || (minimum < 0 && n == 0) {
						return false
					}
				}
			default:
				return false
			}
		}
		return seen["FREQ"] && !(seen["COUNT"] && seen["UNTIL"])
	}
	if kind != "RDATE" && kind != "EXDATE" {
		return false
	}
	dateOnly, hasZone := false, false
	for _, parameter := range header[1:] {
		if parameter == "VALUE=DATE" && !dateOnly {
			dateOnly = true
		} else if strings.HasPrefix(parameter, "TZID=") && !hasZone {
			zone := strings.TrimPrefix(parameter, "TZID=")
			if !calendarOpaque(zone, 128) || zone == "Local" {
				return false
			}
			if _, err := time.LoadLocation(zone); err != nil {
				return false
			}
			hasZone = true
		} else {
			return false
		}
	}
	if dateOnly && hasZone {
		return false
	}
	for _, date := range strings.Split(parts[1], ",") {
		if dateOnly {
			if len(date) != 8 {
				return false
			}
			if _, err := time.Parse("20060102", date); err != nil {
				return false
			}
		} else if hasZone {
			if _, err := time.Parse("20060102T150405", date); err != nil {
				return false
			}
		} else {
			if _, err := time.Parse("20060102T150405Z", date); err != nil {
				return false
			}
		}
	}
	return true
}

func calendarRecurrenceDate(value string, allowDate bool) bool {
	if allowDate && len(value) == 8 {
		_, err := time.Parse("20060102", value)
		return err == nil
	}
	_, err := time.Parse("20060102T150405Z", value)
	return err == nil
}

// RFC5545 section 3.3.10 binds UNTIL's type to DTSTART. Our timed recurring
// subset always has an IANA zone, so its UNTIL must be a UTC DATE-TIME. RDATE
// and EXDATE likewise cannot mix DATE and DATE-TIME within that event.
// Syntax/bounds have already been checked by calendarRecurrence; this adds no
// expansion engine or synchronization state.
func calendarRecurrenceContext(line string, dateOnly bool) bool {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return false
	}
	header := strings.Split(parts[0], ";")
	if header[0] == "RRULE" || header[0] == "EXRULE" {
		for _, field := range strings.Split(parts[1], ";") {
			if strings.HasPrefix(field, "UNTIL=") {
				until := strings.TrimPrefix(field, "UNTIL=")
				return (dateOnly && len(until) == 8) || (!dateOnly && len(until) == 16 && strings.HasSuffix(until, "Z"))
			}
		}
		return true
	}
	lineDateOnly := false
	for _, parameter := range header[1:] {
		lineDateOnly = lineDateOnly || parameter == "VALUE=DATE"
	}
	return lineDateOnly == dateOnly
}

func calendarMember(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func calendarValidResponse(object map[string]any, p calendarPlan) bool {
	if object == nil {
		return false
	}
	if _, exists := object["error"]; exists {
		return false
	}
	if strings.HasSuffix(p.operation.Name, ".list") {
		kind := "calendar#events"
		itemKind := "calendar#event"
		if strings.Contains(p.operation.Name, ".calendars.") {
			kind = "calendar#calendarList"
			itemKind = "calendar#calendarListEntry"
		}
		if object["kind"] != kind {
			return false
		}
		items, present := object["items"]
		if present {
			list, ok := items.([]any)
			if !ok || len(list) > p.limit {
				return false
			}
			for _, item := range list {
				entry, ok := item.(map[string]any)
				if !ok || !calendarResponseItem(entry, itemKind) {
					return false
				}
			}
		}
		page, pagePresent := object["nextPageToken"]
		sync, syncPresent := object["nextSyncToken"]
		if pagePresent && syncPresent {
			return false
		}
		if pagePresent {
			text, ok := page.(string)
			if !ok || !calendarOpaque(text, 4096) {
				return false
			}
		}
		if syncPresent {
			text, ok := sync.(string)
			if !ok || !calendarOpaque(text, 4096) {
				return false
			}
		}
		return true
	}
	kind := "calendar#event"
	if strings.Contains(p.operation.Name, ".calendars.") {
		kind = "calendar#calendarListEntry"
	}
	return calendarResponseItem(object, kind)
}

func calendarResponseItem(object map[string]any, kind string) bool {
	if _, exists := object["error"]; exists {
		return false
	}
	id, ok := object["id"].(string)
	if !ok || !calendarOpaque(id, 1024) {
		return false
	}
	// Google guarantees only identifying fields on cancellation tombstones.
	if kind == "calendar#event" && object["status"] == "cancelled" {
		return true
	}
	if kind == "calendar#calendarListEntry" && object["deleted"] == true {
		return true
	}
	etag, ok := object["etag"].(string)
	return object["kind"] == kind && ok && calendarETag(etag)
}

// Reject duplicate keys, malformed UTF-8, trailing values and excessive nesting
// before authorization-sensitive arguments or untrusted provider JSON are used.
func calendarJSON(raw []byte, maximum int) (map[string]any, error) {
	invalid := domain.ErrInvalidArguments
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) {
		return nil, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	budget := 100000
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		budget--
		if depth > 32 || budget < 0 {
			return nil, invalid
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, invalid
		}
		delimiter, nested := token.(json.Delim)
		if !nested {
			return token, nil
		}
		switch delimiter {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, invalid
				}
				key, ok := keyToken.(string)
				if !ok || len(key) > 2048 || len(object) >= 1024 {
					return nil, invalid
				}
				if _, present := object[key]; present {
					return nil, invalid
				}
				value, err := read(depth + 1)
				if err != nil {
					return nil, invalid
				}
				object[key] = value
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, invalid
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				value, err := read(depth + 1)
				if err != nil {
					return nil, invalid
				}
				array = append(array, value)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, invalid
			}
			return array, nil
		default:
			return nil, invalid
		}
	}
	value, err := read(0)
	if err != nil {
		return nil, invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid
	}
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return nil, invalid
	}
	return object, nil
}
