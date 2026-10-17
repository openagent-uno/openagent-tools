package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const microsoftGraphOrigin = "https://graph.microsoft.com"
const microsoftGraphMaxResponse = 4 << 20

var microsoftGraphID = regexp.MustCompile(`^[A-Za-z0-9_+=!/-]{1,1024}$`)
var microsoftGraphETag = regexp.MustCompile(`^(W/)?"[\x21\x23-\x7e]{1,512}"$`)

// MicrosoftGraphAdapter exposes the signed-in mailbox/calendar only. Host OAuth
// verifies /me with User.Read and binds its id to Connection.ExternalID; this
// adapter never parses JWTs or authenticates an OpenAgent user. No OIDC token is
// needed for delegated Graph API access (learn.microsoft.com/graph/auth-v2-user).
// Injected transports must enforce the package's no-redirect HTTPS policy.
type MicrosoftGraphAdapter struct {
	manifest Manifest
	doer     HTTPDoer
}

// NewMicrosoftGraphAdapter supports only these two compiled global-cloud APIs.
// No caller/connection origin, tenant, user id or arbitrary OData is accepted.
func NewMicrosoftGraphAdapter(provider string, doer HTTPDoer) (*MicrosoftGraphAdapter, error) {
	if doer == nil {
		return nil, errors.New("Microsoft Graph transport is required")
	}
	m, err := microsoftGraphManifest(provider)
	if err != nil {
		return nil, err
	}
	// Preserve redirect rejection even when a caller supplies a plain http.Client.
	if client, ok := doer.(*http.Client); ok {
		copy := *client
		copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		doer = &copy
	}
	return &MicrosoftGraphAdapter{manifest: m, doer: doer}, nil
}

func (a *MicrosoftGraphAdapter) Provider() string              { return a.manifest.Provider }
func (a *MicrosoftGraphAdapter) Capability() domain.Capability { return a.manifest.Capability }

// These implications are Microsoft-only and documented in each endpoint's
// permission table. Mail.ReadWrite explicitly does NOT include Mail.Send.
func (a *MicrosoftGraphAdapter) OperationScopesGranted(granted []string, name string) bool {
	if !domain.ValidProviderScopes(granted) {
		return false
	}
	for _, op := range a.manifest.Operations {
		if op.Name != name {
			continue
		}
		for _, required := range op.RequiredScopes {
			accepted := []string{required}
			switch required {
			case "Mail.ReadBasic":
				accepted = append(accepted, "Mail.Read", "Mail.ReadWrite")
			case "Mail.Read":
				accepted = append(accepted, "Mail.ReadWrite")
			case "Calendars.ReadBasic":
				accepted = append(accepted, "Calendars.Read", "Calendars.ReadWrite")
			case "Calendars.Read":
				accepted = append(accepted, "Calendars.ReadWrite")
			}
			found := false
			for _, candidate := range accepted {
				if domain.GrantsScopes(granted, []string{candidate}) {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	return false
}
func (a *MicrosoftGraphAdapter) Operations() []domain.Operation {
	result := make([]domain.Operation, 0, len(a.manifest.Operations))
	for _, op := range a.manifest.Operations {
		result = append(result, domain.Operation{Name: op.Name, Description: op.Description,
			Capability: a.Capability(), Provider: a.Provider(), Risk: op.Risk,
			Mode: domain.OperationTyped, InputSchema: cloneBytes(op.InputSchema),
			RequiredScopes: append([]string(nil), op.RequiredScopes...), Retry: domain.RetryPolicy{MaxAttempts: 1},
			Preview: domain.ActionPreview{Method: op.Method, Path: op.Path, Summary: op.Description}})
	}
	return result
}

func microsoftGraphObject(properties map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func microsoftGraphTextSchema(maximum int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": maximum}
}

func microsoftGraphItemBodySchema() map[string]any {
	return microsoftGraphObject(map[string]any{"contentType": map[string]any{"type": "string", "const": "Text"}, "content": microsoftGraphTextSchema(65536)}, "contentType", "content")
}

func microsoftGraphRecipientSchema() map[string]any {
	return microsoftGraphObject(map[string]any{"emailAddress": microsoftGraphObject(map[string]any{"address": microsoftGraphTextSchema(254), "name": microsoftGraphTextSchema(128)}, "address")}, "emailAddress")
}

func microsoftGraphBodySchema(calendar, create bool) map[string]any {
	p := map[string]any{"subject": microsoftGraphTextSchema(255), "body": microsoftGraphItemBodySchema()}
	required := []string{}
	if calendar {
		if !create {
			delete(p, "body")
		}
		dt := microsoftGraphObject(map[string]any{"dateTime": microsoftGraphTextSchema(32), "timeZone": map[string]any{"type": "string", "const": "UTC"}}, "dateTime", "timeZone")
		p["start"], p["end"] = dt, dt
		p["location"] = microsoftGraphObject(map[string]any{"displayName": microsoftGraphTextSchema(255)}, "displayName")
		// Recurrence, attendees, online meetings, extensions and sender overrides
		// are intentionally outside this finite first-phase request subset.
		if create {
			required = []string{"subject", "start", "end"}
		}
	} else {
		for _, k := range []string{"toRecipients", "ccRecipients", "bccRecipients"} {
			p[k] = map[string]any{"type": "array", "maxItems": 50, "items": microsoftGraphRecipientSchema()}
		}
		if create {
			required = []string{"subject", "body", "toRecipients"}
		}
	}
	s := microsoftGraphObject(p, required...)
	s["minProperties"] = 1
	return s
}

// Primary v1.0 contracts: user-list-messages, message-get, user-list-mailfolders,
// mailfolder-get, message-list-attachments, attachment-get, user-post-messages,
// message-update, message-send; user-list-calendars, calendar-get,
// calendar-list-events, event-get, calendar-post-events, event-update/event-delete.
// All pages are bounded; attachment JSON content shares the 4MiB response bound.
func microsoftGraphManifest(provider string) (Manifest, error) {
	capability, prefix := domain.Outreach, "outreach.outlook_mail."
	calendar := provider == "outlook_calendar"
	if calendar {
		capability, prefix = domain.Files, "files.outlook_calendar."
	} else if provider != "outlook_mail" {
		return Manifest{}, domain.ErrUnsupported
	}
	m := Manifest{Provider: provider, Capability: capability, APIVersion: "v1.0", OriginKind: OriginFixed,
		Origin: microsoftGraphOrigin, CredentialHeader: "Authorization", CredentialScheme: "Bearer",
		MaxRequestBytes: 256 << 10, MaxResponseBytes: microsoftGraphMaxResponse, TypedOnly: true}
	add := func(name, method, path, scope, description string, risk domain.Risk, required ...string) {
		p := map[string]any{"connection_id": boundedStringProperty(128), "provider": map[string]any{"type": "string", "const": provider}, "expected_external_id": boundedStringProperty(1024)}
		for _, key := range required {
			switch key {
			case "body":
				p[key] = microsoftGraphBodySchema(calendar, strings.HasSuffix(name, ".create"))
			case "etag":
				p[key] = map[string]any{"type": "string", "maxLength": 518, "pattern": microsoftGraphETag.String()}
			default:
				p[key] = map[string]any{"type": "string", "pattern": microsoftGraphID.String(), "maxLength": 1024}
			}
		}
		if strings.HasSuffix(name, ".list") {
			p["top"] = integerProperty(1, 100)
			p["page_token"] = microsoftGraphTextSchema(16384)
		}
		schema, _ := json.Marshal(microsoftGraphObject(p, required...))
		bodyMode := BodyNone
		for _, key := range required {
			if key == "body" {
				bodyMode = BodyJSON
			}
		}
		m.Operations = append(m.Operations, OperationManifest{Name: prefix + name, Method: method, Path: "/v1.0/me" + path,
			Description: description, Risk: risk, Required: required, RequiredScopes: []string{scope},
			Body: bodyMode, Retry: noRetry, InputSchema: schema})
	}
	if calendar {
		add("calendars.list", "GET", "/calendars", "Calendars.ReadBasic", "List one page of the signed-in account's calendars.", domain.RiskRead)
		add("calendars.get", "GET", "/calendars/{calendar_id}", "Calendars.ReadBasic", "Read a calendar in the signed-in account.", domain.RiskRead, "calendar_id")
		add("events.list", "GET", "/calendars/{calendar_id}/events", "Calendars.Read", "List one page of events and recurring masters; occurrences are not expanded.", domain.RiskRead, "calendar_id")
		add("events.get", "GET", "/calendars/{calendar_id}/events/{event_id}", "Calendars.Read", "Read an event, including its version ETag.", domain.RiskRead, "calendar_id", "event_id")
		add("events.create", "POST", "/calendars/{calendar_id}/events", "Calendars.ReadWrite", "Create a UTC event; no attendees or recurrence in this subset. Never retried.", domain.RiskWrite, "calendar_id", "body")
		add("events.update", "PATCH", "/calendars/{calendar_id}/events/{event_id}", "Calendars.ReadWrite", "Update subject/location or paired UTC start/end with If-Match. Existing meeting updates may notify attendees; body updates are excluded to preserve meeting details.", domain.RiskWrite, "calendar_id", "event_id", "etag", "body")
		add("events.delete", "DELETE", "/calendars/{calendar_id}/events/{event_id}", "Calendars.ReadWrite", "Delete an event with If-Match; deleting an organizer's meeting may notify attendees. Never retried.", domain.RiskDestructive, "calendar_id", "event_id", "etag")
	} else {
		add("folders.list", "GET", "/mailFolders", "Mail.ReadBasic", "List one page of top-level mail folders only.", domain.RiskRead)
		add("folders.get", "GET", "/mailFolders/{folder_id}", "Mail.ReadBasic", "Read mail folder metadata.", domain.RiskRead, "folder_id")
		add("messages.list", "GET", "/messages", "Mail.Read", "List one bounded page of messages; no arbitrary filter, search or expansion.", domain.RiskRead)
		add("messages.get", "GET", "/messages/{message_id}", "Mail.Read", "Read a message as text with its version ETag; HTML is provider data, never executable.", domain.RiskRead, "message_id")
		add("attachments.list", "GET", "/messages/{message_id}/attachments", "Mail.Read", "List one page of attachment metadata without file contents.", domain.RiskRead, "message_id")
		add("attachments.get", "GET", "/messages/{message_id}/attachments/{attachment_id}", "Mail.Read", "Read bounded attachment JSON/base64, max4MiB total response; no raw value, expansion, redirects or upload.", domain.RiskRead, "message_id", "attachment_id")
		add("drafts.create", "POST", "/messages", "Mail.ReadWrite", "Create a text-only draft with up to50 total recipients. Does not send it; never retried.", domain.RiskDraft, "body")
		add("drafts.update", "PATCH", "/messages/{message_id}", "Mail.ReadWrite", "Edit only draft subject/body/recipients with If-Match. Graph rejects draft-only fields on sent mail; never retried.", domain.RiskDraft, "message_id", "etag", "body")
		add("messages.send", "POST", "/messages/{message_id}/send", "Mail.Send", "Send an existing draft once. HTTP202 means accepted, not delivered. Sending requires separate publish authorization.", domain.RiskPublish, "message_id")
	}
	return m, nil
}

type microsoftGraphPlan struct {
	op   OperationManifest
	url  *url.URL
	body []byte
	etag string
}

// Reject duplicate JSON object keys recursively as well as unknown fields.
func microsoftGraphJSON(raw []byte) (any, error) {
	return microsoftGraphJSONBudget(raw, 4096, 12)
}

func microsoftGraphJSONBudget(raw []byte, maximumNodes, maximumDepth int) (any, error) {
	if !utf8.Valid(raw) {
		return nil, domain.ErrInvalidArguments
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		nodes++
		if depth > maximumDepth || nodes > maximumNodes {
			return nil, domain.ErrInvalidArguments
		}
		t, err := d.Token()
		if err != nil {
			return nil, domain.ErrInvalidArguments
		}
		switch t {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				key, ok := k.(string)
				if err != nil || !ok {
					return nil, domain.ErrInvalidArguments
				}
				if _, exists := m[key]; exists {
					return nil, domain.ErrInvalidArguments
				}
				v, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, domain.ErrInvalidArguments
			}
			return m, nil
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, domain.ErrInvalidArguments
			}
			return a, nil
		default:
			if _, ok := t.(json.Delim); ok {
				return nil, domain.ErrInvalidArguments
			}
			return t, nil
		}
	}
	v, err := value(0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, domain.ErrInvalidArguments
	}
	return v, nil
}

func microsoftGraphText(v any, max int, multiline bool) bool {
	s, ok := v.(string)
	if !ok || len(s) == 0 || !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if r == 0 || r == 0x7f || (r < 0x20 && !(multiline && (r == '\n' || r == '\r' || r == '\t'))) {
			return false
		}
	}
	return true
}

func microsoftGraphClosed(v any, keys ...string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	for k := range m {
		found := false
		for _, allowed := range keys {
			if k == allowed {
				found = true
			}
		}
		if !found {
			return nil, false
		}
	}
	return m, true
}

func microsoftGraphBody(v any, calendar, create bool) bool {
	allowed := []string{"subject", "body", "toRecipients", "ccRecipients", "bccRecipients"}
	if calendar {
		allowed = []string{"subject", "start", "end", "location"}
		if create {
			allowed = append(allowed, "body")
		}
	}
	m, ok := microsoftGraphClosed(v, allowed...)
	if !ok || len(m) == 0 {
		return false
	}
	if create && (!microsoftGraphText(m["subject"], 255, false) || (calendar && (m["start"] == nil || m["end"] == nil)) || (!calendar && (m["body"] == nil || m["toRecipients"] == nil))) {
		return false
	}
	recipients := 0
	for k, v := range m {
		switch k {
		case "subject":
			if !microsoftGraphText(v, 255, false) {
				return false
			}
		case "body":
			body, ok := microsoftGraphClosed(v, "contentType", "content")
			if !ok || len(body) != 2 || body["contentType"] != "Text" || !microsoftGraphText(body["content"], 65536, true) {
				return false
			}
		case "location":
			loc, ok := microsoftGraphClosed(v, "displayName")
			if !ok || len(loc) != 1 || !microsoftGraphText(loc["displayName"], 255, false) {
				return false
			}
		case "start", "end":
			dt, ok := microsoftGraphClosed(v, "dateTime", "timeZone")
			if !ok || len(dt) != 2 || dt["timeZone"] != "UTC" {
				return false
			}
			s, ok := dt["dateTime"].(string)
			if !ok {
				return false
			}
			if _, err := time.Parse("2006-01-02T15:04:05", s); err != nil {
				return false
			}
		default:
			list, ok := v.([]any)
			if !ok || len(list) > 50 {
				return false
			}
			recipients += len(list)
			for _, item := range list {
				r, ok := microsoftGraphClosed(item, "emailAddress")
				if !ok || len(r) != 1 {
					return false
				}
				e, ok := microsoftGraphClosed(r["emailAddress"], "address", "name")
				if !ok || !microsoftGraphText(e["address"], 254, false) {
					return false
				}
				s := e["address"].(string)
				parsed, err := mail.ParseAddress(s)
				if err != nil || parsed.Address != s || !strings.Contains(s, "@") {
					return false
				}
				if name, exists := e["name"]; exists && !microsoftGraphText(name, 128, false) {
					return false
				}
			}
		}
	}
	if calendar {
		if (m["start"] == nil) != (m["end"] == nil) {
			return false
		}
		if m["start"] != nil {
			start, _ := time.Parse("2006-01-02T15:04:05", m["start"].(map[string]any)["dateTime"].(string))
			end, _ := time.Parse("2006-01-02T15:04:05", m["end"].(map[string]any)["dateTime"].(string))
			if !end.After(start) {
				return false
			}
		}
	}
	return recipients <= 50
}

func microsoftGraphSelect(name string) string {
	switch {
	case strings.Contains(name, ".folders."):
		return "id,displayName,parentFolderId,childFolderCount,totalItemCount,unreadItemCount"
	case strings.Contains(name, ".attachments.list"):
		return "id,name,contentType,size,isInline"
	case strings.Contains(name, ".calendars."):
		return "id,name,color,canEdit,owner"
	case strings.Contains(name, ".events."):
		return "id,subject,body,bodyPreview,start,end,location,attendees,organizer,isCancelled,changeKey"
	default:
		return "id,subject,body,bodyPreview,from,toRecipients,ccRecipients,bccRecipients,receivedDateTime,isDraft,hasAttachments,changeKey"
	}
}

type microsoftGraphCursor struct {
	Connection string `json:"connection"`
	ExternalID string `json:"external_id"`
	Operation  string `json:"operation"`
	URL        string `json:"url"`
}

func microsoftGraphNext(raw, path, selectFields string) (*url.URL, error) {
	if len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\x00\\") {
		return nil, domain.ErrInvalidArguments
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "graph.microsoft.com" || u.User != nil || u.Fragment != "" || u.EscapedPath() != path || u.Opaque != "" {
		return nil, domain.ErrInvalidArguments
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, domain.ErrInvalidArguments
	}
	for k, values := range q {
		if len(values) != 1 {
			return nil, domain.ErrInvalidArguments
		}
		switch k {
		case "$select":
			if values[0] != selectFields {
				return nil, domain.ErrInvalidArguments
			}
		case "$top":
			n, err := strconv.Atoi(values[0])
			if err != nil || n < 1 || n > 100 {
				return nil, domain.ErrInvalidArguments
			}
		case "$skip", "$skiptoken":
			if !microsoftGraphText(values[0], 4096, false) {
				return nil, domain.ErrInvalidArguments
			}
		default:
			return nil, domain.ErrInvalidArguments
		}
	}
	if q.Get("$select") != selectFields || q.Get("$top") == "" || (q.Get("$skip") == "" && q.Get("$skiptoken") == "") {
		return nil, domain.ErrInvalidArguments
	}
	return u, nil
}

func (a *MicrosoftGraphAdapter) plan(inv domain.Invocation) (microsoftGraphPlan, error) {
	p := microsoftGraphPlan{}
	for _, op := range a.manifest.Operations {
		if op.Name == inv.Operation.Name {
			p.op = op
			break
		}
	}
	if p.op.Name == "" {
		return p, domain.ErrUnsupported
	}
	if inv.ID == "" || len(inv.ID) > 256 || inv.Operation.Provider != a.Provider() || inv.Operation.Capability != a.Capability() || inv.Operation.Risk != p.op.Risk || inv.Operation.Mode != domain.OperationTyped || inv.Connection.Provider != a.Provider() || inv.Connection.Validate(inv.Principal.WorkspaceID, a.Capability()) != nil || inv.Connection.ExternalID == "" || inv.Credential.IsNone() {
		return p, domain.ErrDenied
	}
	if inv.Principal.BoundConnectionID != "" && inv.Principal.BoundConnectionID != inv.Connection.ID {
		return p, domain.ErrDenied
	}
	if len(inv.Connection.Config) > 0 {
		config, err := microsoftGraphJSON(inv.Connection.Config)
		object, ok := config.(map[string]any)
		if err != nil || !ok || len(object) != 0 {
			return p, domain.ErrInvalidArguments
		}
	}
	if !a.OperationScopesGranted(inv.Connection.Scopes, p.op.Name) {
		return p, domain.ErrProviderPermission
	}
	if len(inv.Arguments) == 0 || len(inv.Arguments) > int(a.manifest.MaxRequestBytes) {
		return p, domain.ErrInvalidArguments
	}
	v, err := microsoftGraphJSON(inv.Arguments)
	if err != nil {
		return p, err
	}
	args, ok := v.(map[string]any)
	if !ok {
		return p, domain.ErrInvalidArguments
	}
	allowed := map[string]bool{"connection_id": true, "provider": true, "expected_external_id": true}
	for _, k := range p.op.Required {
		allowed[k] = true
		if args[k] == nil {
			return p, domain.ErrInvalidArguments
		}
	}
	listing := strings.HasSuffix(p.op.Name, ".list")
	if listing {
		allowed["top"], allowed["page_token"] = true, true
	}
	for k := range args {
		if !allowed[k] {
			return p, domain.ErrInvalidArguments
		}
	}
	for k, expected := range map[string]string{"connection_id": inv.Connection.ID, "provider": a.Provider(), "expected_external_id": inv.Connection.ExternalID} {
		if actual, exists := args[k]; exists && actual != expected {
			return p, domain.ErrDenied
		}
	}
	path := p.op.Path
	for _, k := range p.op.Required {
		if strings.HasSuffix(k, "_id") {
			id, ok := args[k].(string)
			if !ok || !microsoftGraphID.MatchString(id) {
				return p, domain.ErrInvalidArguments
			}
			path = strings.ReplaceAll(path, "{"+k+"}", url.PathEscape(id))
		}
	}
	p.url, _ = url.Parse(microsoftGraphOrigin + path)
	if etag, exists := args["etag"]; exists {
		s, ok := etag.(string)
		if !ok || !microsoftGraphETag.MatchString(s) {
			return p, domain.ErrInvalidArguments
		}
		p.etag = s
	}
	if body, exists := args["body"]; exists {
		if !microsoftGraphBody(body, a.Provider() == "outlook_calendar", strings.HasSuffix(p.op.Name, ".create")) {
			return p, domain.ErrInvalidArguments
		}
		p.body, _ = json.Marshal(body)
	}
	if p.op.Method == "GET" && !strings.HasSuffix(p.op.Name, ".attachments.get") {
		q := url.Values{"$select": {microsoftGraphSelect(p.op.Name)}}
		if listing {
			top := 25
			if raw, exists := args["top"]; exists {
				n, ok := raw.(json.Number)
				if !ok {
					return p, domain.ErrInvalidArguments
				}
				parsed, err := strconv.Atoi(n.String())
				if err != nil || parsed < 1 || parsed > 100 {
					return p, domain.ErrInvalidArguments
				}
				top = parsed
			}
			q.Set("$top", strconv.Itoa(top))
			if raw, exists := args["page_token"]; exists {
				if _, exists := args["top"]; exists {
					return p, domain.ErrInvalidArguments
				}
				s, ok := raw.(string)
				if !ok || len(s) > 16384 {
					return p, domain.ErrInvalidArguments
				}
				b, err := base64.RawURLEncoding.DecodeString(s)
				if err != nil {
					return p, domain.ErrInvalidArguments
				}
				decoded, err := microsoftGraphJSON(b)
				c, ok := microsoftGraphClosed(decoded, "connection", "external_id", "operation", "url")
				if err != nil || !ok || len(c) != 4 || c["connection"] != inv.Connection.ID || c["external_id"] != inv.Connection.ExternalID || c["operation"] != p.op.Name {
					return p, domain.ErrInvalidArguments
				}
				link, ok := c["url"].(string)
				if !ok {
					return p, domain.ErrInvalidArguments
				}
				u, err := microsoftGraphNext(link, p.url.EscapedPath(), q.Get("$select"))
				if err != nil {
					return p, err
				}
				p.url = u
				return p, nil
			}
		}
		p.url.RawQuery = q.Encode()
	}
	return p, nil
}

func (a *MicrosoftGraphAdapter) Preview(inv domain.Invocation) (domain.ActionPreview, error) {
	p, err := a.plan(inv)
	if err != nil {
		return domain.ActionPreview{}, err
	}
	// Opaque continuation contents and credentials are not preview text.
	return domain.ActionPreview{Method: p.op.Method, Path: p.url.EscapedPath(), Summary: p.op.Description}, nil
}

func (a *MicrosoftGraphAdapter) Invoke(ctx context.Context, inv domain.Invocation) (domain.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p, err := a.plan(inv)
	if err != nil {
		return domain.Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, p.op.Method, p.url.String(), bytes.NewReader(p.body))
	if err != nil {
		return domain.Result{}, domain.ErrInvalidArguments
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Prefer", `IdType="ImmutableId", outlook.body-content-type="text"`)
	if len(p.body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.etag != "" {
		req.Header.Set("If-Match", p.etag)
	}
	if inv.Credential.Apply(req.Header, "Authorization", "Bearer", time.Now()) != nil {
		return domain.Result{}, domain.ErrProviderPermission
	}
	res, err := a.doer.Do(req)
	if err != nil {
		if res != nil && res.Body != nil {
			_ = res.Body.Close()
		}
		return domain.Result{}, &domain.ProviderError{Kind: "network_error", Attempts: 1, RequestBytes: int64(len(p.body))}
	}
	if res == nil || res.Body == nil {
		return domain.Result{}, &domain.ProviderError{Kind: "response_error", Attempts: 1}
	}
	data, large, readErr := readBounded(res.Body, microsoftGraphMaxResponse)
	_ = res.Body.Close()
	failure := func(kind string) error {
		return &domain.ProviderError{Kind: kind, StatusCode: res.StatusCode, Attempts: 1, RequestBytes: int64(len(p.body)), ResponseBytes: int64(len(data))}
	}
	if readErr != nil {
		return domain.Result{}, failure("response_error")
	}
	if large {
		return domain.Result{}, failure("response_too_large")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		kind := "provider_error"
		if res.StatusCode == 429 {
			kind = "rate_limited"
		}
		if res.StatusCode == 412 {
			kind = "version_conflict"
		}
		if res.StatusCode == 401 || res.StatusCode == 403 {
			return domain.Result{}, errors.Join(domain.ErrProviderPermission, failure(kind))
		}
		return domain.Result{}, failure(kind)
	}
	expectedStatus := http.StatusOK
	if p.op.Method == "DELETE" {
		expectedStatus = http.StatusNoContent
	} else if strings.HasSuffix(p.op.Name, ".send") {
		expectedStatus = http.StatusAccepted
	} else if p.op.Method == "POST" {
		expectedStatus = http.StatusCreated
	}
	if res.StatusCode != expectedStatus {
		return domain.Result{}, failure("unexpected_status")
	}
	metadata := map[string]string{"provider": a.Provider(), "operation": p.op.Name, "api_version": "v1.0"}
	if expectedStatus == http.StatusAccepted || expectedStatus == http.StatusNoContent {
		if len(data) != 0 {
			return domain.Result{}, failure("invalid_response")
		}
		if expectedStatus == http.StatusAccepted {
			metadata["accepted"] = "true"
		} else {
			metadata["completed"] = "true"
		}
		return domain.Result{ProviderStatus: res.StatusCode, Attempts: 1, RequestBytes: int64(len(p.body)), Metadata: metadata}, nil
	}
	data = inv.Credential.Redact(data)
	var decoded map[string]any
	if len(bytes.TrimSpace(data)) > 0 {
		v, err := microsoftGraphJSONBudget(data, 100000, 32)
		var ok bool
		decoded, ok = v.(map[string]any)
		if err != nil || !ok || len(decoded) == 0 {
			return domain.Result{}, failure("invalid_response")
		}
		if _, exists := decoded["error"]; exists {
			return domain.Result{}, failure("provider_operation_error")
		}
	}
	if expectedStatus == http.StatusOK || expectedStatus == http.StatusCreated {
		if decoded == nil {
			return domain.Result{}, failure("invalid_response")
		}
	}
	if strings.HasSuffix(p.op.Name, ".list") {
		items, ok := decoded["value"].([]any)
		top, err := strconv.Atoi(p.url.Query().Get("$top"))
		if !ok || err != nil || top < 1 || top > 100 || len(items) > top {
			return domain.Result{}, failure("invalid_response")
		}
		for _, item := range items {
			object, ok := item.(map[string]any)
			id, stringID := object["id"].(string)
			if !ok || !stringID || !microsoftGraphID.MatchString(id) {
				return domain.Result{}, failure("invalid_response")
			}
		}
	} else {
		id, ok := decoded["id"].(string)
		if !ok || !microsoftGraphID.MatchString(id) {
			return domain.Result{}, failure("invalid_response")
		}
	}
	if tag, exists := decoded["@odata.etag"]; exists {
		s, ok := tag.(string)
		if !ok || !microsoftGraphETag.MatchString(s) {
			return domain.Result{}, failure("invalid_response")
		}
	}
	if tag := res.Header.Get("ETag"); tag != "" {
		if !microsoftGraphETag.MatchString(tag) {
			return domain.Result{}, failure("invalid_response")
		}
		if old, exists := decoded["@odata.etag"]; exists && old != tag {
			return domain.Result{}, failure("invalid_response")
		}
		if decoded != nil {
			decoded["@odata.etag"] = tag
		}
	}
	if raw, exists := decoded["@odata.nextLink"]; exists {
		next, ok := raw.(string)
		if !ok || !strings.HasSuffix(p.op.Name, ".list") {
			return domain.Result{}, failure("invalid_continuation")
		}
		if _, err = microsoftGraphNext(next, p.url.EscapedPath(), microsoftGraphSelect(p.op.Name)); err != nil {
			return domain.Result{}, failure("invalid_continuation")
		}
		cursor, _ := json.Marshal(microsoftGraphCursor{Connection: inv.Connection.ID, ExternalID: inv.Connection.ExternalID, Operation: p.op.Name, URL: next})
		delete(decoded, "@odata.nextLink")
		decoded["next_page_token"] = base64.RawURLEncoding.EncodeToString(cursor)
	}
	return domain.Result{Data: decoded, ProviderStatus: res.StatusCode, Attempts: 1, RequestBytes: int64(len(p.body)), ResponseBytes: int64(len(data)), Metadata: metadata}, nil
}
