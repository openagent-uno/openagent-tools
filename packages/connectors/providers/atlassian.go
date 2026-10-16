package providers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const atlassianAPIVersion = "v3"

var (
	atlassianCloudIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	atlassianNumberPattern  = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	atlassianProjectPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
	atlassianIssuePattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}-[1-9][0-9]{0,18}$`)
	atlassianFieldPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	atlassianAccountPattern = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)
)

// The host selects a Jira site from accessible-resources and stores its cloud_id
// in this connection's trusted configuration. Tools cannot select a site or URL.
// The API's classic scopes are recommended by Atlassian; Jira permissions and
// app access rules still apply independently of these scopes.
func atlassianManifest() Manifest {
	base := "/ex/jira/{cloud_id}/rest/api/3"
	op := func(name, description, method, path string, required []string, query map[string]string, properties map[string]any) OperationManifest {
		result := OperationManifest{Name: "files.atlassian." + name, Description: description, Method: method,
			Path: path, Required: required, Query: query, Body: BodyNone, Risk: domain.RiskRead, Retry: readRetry}
		if name != "resources.list" {
			result.RequiredScopes = []string{"read:jira-work"}
		}
		if method != http.MethodGet {
			result.Risk, result.Retry, result.Body = domain.RiskWrite, noRetry, BodyJSON
			result.RequiredScopes = []string{"write:jira-work"}
		}
		result.InputSchema = atlassianToolSchema(properties, required)
		return result
	}
	issue := func() map[string]any {
		return map[string]any{"type": "string", "maxLength": 84, "description": "Positive numeric Jira issue ID or uppercase project-key/issue-number, e.g. PROJ-123"}
	}
	project := func() map[string]any {
		return map[string]any{"type": "string", "maxLength": 64, "description": "Positive numeric project ID or uppercase Jira project key"}
	}
	pagination := func() map[string]any {
		return map[string]any{"start_at": integerProperty(0, 1000000), "max_results": integerProperty(1, 100)}
	}
	projectList := pagination()
	projectList["query"] = atlassianStringSchema(1, 255)
	search := map[string]any{"jql": atlassianStringSchema(1, 4096), "max_results": integerProperty(1, 100), "next_page_token": atlassianStringSchema(1, 4096), "fields": atlassianStringSchema(1, 4096)}
	comments := pagination()
	comments["issue_id_or_key"] = issue()
	operations := []OperationManifest{
		op("resources.list", "List sites granted to this OAuth token, including their IDs and scopes. This does not prove Jira user permissions or select the connection's site.", http.MethodGet, "/oauth/token/accessible-resources", nil, nil, map[string]any{}),
		op("projects.list", "Search one page of projects visible on the server-selected Jira site; follow startAt/maxResults explicitly.", http.MethodGet, base+"/project/search", nil, map[string]string{"start_at": "startAt", "max_results": "maxResults", "query": "query"}, projectList),
		op("projects.get", "Read a project on the server-selected Jira site.", http.MethodGet, base+"/project/{project_id_or_key}", []string{"project_id_or_key"}, nil, map[string]any{"project_id_or_key": project()}),
		op("issues.search", "Search one page with enhanced JQL search; follow nextPageToken until isLast. Recent writes may not immediately appear. The removed legacy /search endpoint is never used.", http.MethodGet, base+"/search/jql", []string{"jql"}, map[string]string{"jql": "jql", "max_results": "maxResults", "next_page_token": "nextPageToken", "fields": "fields"}, search),
		op("issues.get", "Read an issue's fields on the server-selected Jira site; fields optionally selects comma-separated field identifiers.", http.MethodGet, base+"/issue/{issue_id_or_key}", []string{"issue_id_or_key"}, map[string]string{"fields": "fields"}, map[string]any{"issue_id_or_key": issue(), "fields": atlassianStringSchema(1, 4096)}),
		op("issues.create", "Create an issue with explicit project and issue type. Only summary, flat text ADF description, labels, assignee and priority are supported; site-specific required custom fields may require another client.", http.MethodPost, base+"/issue", []string{"body"}, nil, map[string]any{"body": atlassianIssueBodySchema(true)}),
		op("issues.update", "Edit supported fields of an issue. No transitions, moving projects, bulk edits, properties or custom fields. Writes are never retried automatically.", http.MethodPut, base+"/issue/{issue_id_or_key}", []string{"issue_id_or_key", "body"}, nil, map[string]any{"issue_id_or_key": issue(), "body": atlassianIssueBodySchema(false)}),
		op("issue_comments.list", "Read one page of comments visible to this user on an issue; follow startAt/maxResults explicitly.", http.MethodGet, base+"/issue/{issue_id_or_key}/comment", []string{"issue_id_or_key"}, map[string]string{"start_at": "startAt", "max_results": "maxResults"}, comments),
		op("issue_comments.create", "Add a flat text ADF comment to an authorized issue. Visibility overrides and properties are not supported; the request is sent once.", http.MethodPost, base+"/issue/{issue_id_or_key}/comment", []string{"issue_id_or_key", "body"}, nil, map[string]any{"issue_id_or_key": issue(), "body": atlassianObjectSchema(map[string]any{"body": atlassianADFSchema()}, "body")}),
	}
	return Manifest{Provider: "atlassian", Capability: domain.Files, APIVersion: atlassianAPIVersion,
		OriginKind: OriginFixed, Origin: "https://api.atlassian.com", CredentialHeader: "Authorization", CredentialScheme: "Bearer",
		MaxRequestBytes: 1 << 20, MaxResponseBytes: 4 << 20, TypedOnly: true, Operations: operations}
}

func atlassianStringSchema(minimum, maximum int) map[string]any {
	return map[string]any{"type": "string", "minLength": minimum, "maxLength": maximum}
}
func atlassianObjectSchema(properties map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
func atlassianToolSchema(properties map[string]any, required []string) json.RawMessage {
	properties["connection_id"] = boundedStringProperty(128)
	properties["provider"] = map[string]any{"type": "string", "const": "atlassian"}
	properties["expected_external_id"] = boundedStringProperty(1024)
	b, _ := json.Marshal(atlassianObjectSchema(properties, required...))
	return b
}

// Keep ADF deliberately finite: documents with flat paragraphs and text nodes.
// Mentions, media, embeds, marks and arbitrary recursively nested nodes are not
// forwarded under a permissive "any" property.
func atlassianADFSchema() map[string]any {
	text := atlassianObjectSchema(map[string]any{"type": map[string]any{"const": "text", "type": "string"}, "text": atlassianStringSchema(1, 2000)}, "type", "text")
	paragraph := atlassianObjectSchema(map[string]any{"type": map[string]any{"const": "paragraph", "type": "string"}, "content": map[string]any{"type": "array", "maxItems": 32, "items": text}}, "type", "content")
	return atlassianObjectSchema(map[string]any{"version": map[string]any{"type": "integer", "const": 1}, "type": map[string]any{"type": "string", "const": "doc"}, "content": map[string]any{"type": "array", "minItems": 1, "maxItems": 100, "items": paragraph}}, "version", "type", "content")
}

func atlassianReferenceSchema(key string) map[string]any {
	id := atlassianObjectSchema(map[string]any{"id": map[string]any{"type": "string", "pattern": atlassianNumberPattern.String()}}, "id")
	if key == "" {
		return id
	}
	other := atlassianObjectSchema(map[string]any{key: atlassianStringSchema(1, 64)}, key)
	return map[string]any{"oneOf": []any{id, other}}
}

func atlassianIssueBodySchema(create bool) map[string]any {
	fields := map[string]any{
		"summary": atlassianStringSchema(1, 255), "description": atlassianADFSchema(),
		"labels":   map[string]any{"type": "array", "maxItems": 100, "uniqueItems": true, "items": atlassianStringSchema(1, 255)},
		"assignee": atlassianObjectSchema(map[string]any{"accountId": map[string]any{"type": "string", "pattern": atlassianAccountPattern.String()}}, "accountId"),
		"priority": atlassianReferenceSchema(""),
	}
	required := []string{}
	if create {
		fields["project"] = atlassianReferenceSchema("key")
		fields["issuetype"] = atlassianReferenceSchema("name")
		required = []string{"project", "issuetype", "summary"}
	} else {
		for _, name := range []string{"description", "assignee"} {
			fields[name] = map[string]any{"anyOf": []any{fields[name], map[string]any{"type": "null"}}}
		}
	}
	fieldObject := atlassianObjectSchema(fields, required...)
	fieldObject["minProperties"] = 1
	return atlassianObjectSchema(map[string]any{"fields": fieldObject}, "fields")
}

func atlassianText(raw json.RawMessage, minimum, maximum int, multiline bool) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '"' {
		return false
	}
	var s string
	if json.Unmarshal(t, &s) != nil || !utf8.ValidString(s) || utf8.RuneCountInString(s) < minimum || utf8.RuneCountInString(s) > maximum {
		return false
	}
	for _, r := range s {
		if r == 0 || (!multiline && (r < 0x20 || r == 0x7f)) {
			return false
		}
	}
	return true
}
func atlassianObject(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, bool) {
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	for name := range m {
		found := false
		for _, a := range allowed {
			if name == a {
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return m, true
}
func atlassianID(raw json.RawMessage) bool {
	return atlassianNumberPattern.MatchString(jsonString(raw))
}
func atlassianProject(raw json.RawMessage) bool {
	return atlassianID(raw) || atlassianProjectPattern.MatchString(jsonString(raw))
}
func atlassianIssue(raw json.RawMessage) bool {
	return atlassianID(raw) || atlassianIssuePattern.MatchString(jsonString(raw))
}
func atlassianReference(raw json.RawMessage, key string) bool {
	m, ok := atlassianObject(raw, "id", key)
	if !ok || len(m) != 1 {
		return false
	}
	if m["id"] != nil {
		return atlassianID(m["id"])
	}
	if key == "key" {
		return atlassianProjectPattern.MatchString(jsonString(m[key]))
	}
	return key == "name" && atlassianText(m[key], 1, 64, false)
}
func atlassianADF(raw json.RawMessage) bool {
	m, ok := atlassianObject(raw, "version", "type", "content")
	if !ok || len(m) != 3 || string(bytes.TrimSpace(m["version"])) != "1" || jsonString(m["type"]) != "doc" {
		return false
	}
	var paragraphs []json.RawMessage
	if !bytes.HasPrefix(bytes.TrimSpace(m["content"]), []byte("[")) || json.Unmarshal(m["content"], &paragraphs) != nil || len(paragraphs) < 1 || len(paragraphs) > 100 {
		return false
	}
	for _, p := range paragraphs {
		paragraph, ok := atlassianObject(p, "type", "content")
		if !ok || len(paragraph) != 2 || jsonString(paragraph["type"]) != "paragraph" {
			return false
		}
		var texts []json.RawMessage
		if !bytes.HasPrefix(bytes.TrimSpace(paragraph["content"]), []byte("[")) || json.Unmarshal(paragraph["content"], &texts) != nil || len(texts) > 32 {
			return false
		}
		for _, v := range texts {
			node, ok := atlassianObject(v, "type", "text")
			if !ok || len(node) != 2 || jsonString(node["type"]) != "text" || !atlassianText(node["text"], 1, 2000, true) {
				return false
			}
		}
	}
	return true
}

func validateAtlassianBody(operation string, raw json.RawMessage) bool {
	if operation == "files.atlassian.issue_comments.create" {
		m, ok := atlassianObject(raw, "body")
		return ok && len(m) == 1 && atlassianADF(m["body"])
	}
	m, ok := atlassianObject(raw, "fields")
	if !ok || len(m) != 1 {
		return false
	}
	allowed := []string{"summary", "description", "labels", "assignee", "priority"}
	create := operation == "files.atlassian.issues.create"
	if create {
		allowed = append(allowed, "project", "issuetype")
	}
	fields, ok := atlassianObject(m["fields"], allowed...)
	if !ok || len(fields) == 0 {
		return false
	}
	if create && (fields["project"] == nil || fields["issuetype"] == nil || fields["summary"] == nil) {
		return false
	}
	for name, value := range fields {
		switch name {
		case "summary":
			if !atlassianText(value, 1, 255, false) {
				return false
			}
		case "description":
			if !create && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				continue
			}
			if !atlassianADF(value) {
				return false
			}
		case "project":
			if !atlassianReference(value, "key") {
				return false
			}
		case "issuetype":
			if !atlassianReference(value, "name") {
				return false
			}
		case "priority":
			if !atlassianReference(value, "") {
				return false
			}
		case "assignee":
			if !create && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				continue
			}
			x, ok := atlassianObject(value, "accountId")
			if !ok || len(x) != 1 || !atlassianAccountPattern.MatchString(jsonString(x["accountId"])) {
				return false
			}
		case "labels":
			var labels []json.RawMessage
			if !bytes.HasPrefix(bytes.TrimSpace(value), []byte("[")) || json.Unmarshal(value, &labels) != nil || len(labels) > 100 {
				return false
			}
			seen := map[string]bool{}
			for _, label := range labels {
				if !atlassianText(label, 1, 255, false) {
					return false
				}
				s := jsonString(label)
				if strings.ContainsAny(s, " ,") || seen[s] {
					return false
				}
				seen[s] = true
			}
		}
	}
	return true
}

// Call this after decoding arguments and before path expansion or HTTP. It
// injects the one server-owned path slot only after rejecting every caller
// override, including an identical cloud_id. No network or credentials here.
func validateAtlassianArguments(operation OperationManifest, arguments map[string]json.RawMessage, connectionConfig json.RawMessage) error {
	if !strings.HasPrefix(operation.Name, "files.atlassian.") || operation.Raw != nil {
		return domain.ErrUnsupported
	}
	allowed := map[string]bool{"connection_id": true, "provider": true, "expected_external_id": true}
	for _, match := range pathTemplatePattern.FindAllStringSubmatch(operation.Path, -1) {
		if match[1] != "cloud_id" {
			allowed[match[1]] = true
		}
	}
	for name := range operation.Query {
		allowed[name] = true
	}
	if operation.Body == BodyJSON {
		allowed["body"] = true
	}
	for name, raw := range arguments {
		if !allowed[name] {
			return domain.ErrInvalidArguments
		}
		valid := false
		switch name {
		case "connection_id":
			valid = domain.ValidResourceID(jsonString(raw))
		case "provider":
			valid = jsonString(raw) == "atlassian"
		case "expected_external_id":
			valid = atlassianText(raw, 1, 1024, false)
		case "project_id_or_key":
			valid = atlassianProject(raw)
		case "issue_id_or_key":
			valid = atlassianIssue(raw)
		case "jql":
			valid = atlassianText(raw, 1, 4096, false)
		case "query":
			valid = atlassianText(raw, 1, 255, false)
		case "next_page_token":
			valid = atlassianText(raw, 1, 4096, false)
		case "start_at":
			valid = !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && optionalInteger(raw, 0, 1000000)
		case "max_results":
			valid = !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && optionalInteger(raw, 1, 100)
		case "fields":
			if atlassianText(raw, 1, 4096, false) {
				parts := strings.Split(jsonString(raw), ",")
				valid = len(parts) <= 50
				seen := map[string]bool{}
				for _, p := range parts {
					if !atlassianFieldPattern.MatchString(p) || seen[p] {
						valid = false
						break
					}
					seen[p] = true
				}
			}
		case "body":
			valid = validateAtlassianBody(operation.Name, raw)
		}
		if !valid {
			return domain.ErrInvalidArguments
		}
	}
	if operation.Name == "files.atlassian.resources.list" {
		return nil
	}
	config, ok := atlassianObject(connectionConfig, "cloud_id")
	if !ok || len(config) != 1 {
		return domain.ErrInvalidArguments
	}
	cloudID := jsonString(config["cloud_id"])
	if !atlassianCloudIDPattern.MatchString(cloudID) || cloudID == "00000000-0000-0000-0000-000000000000" {
		return domain.ErrInvalidArguments
	}
	arguments["cloud_id"], _ = json.Marshal(cloudID)
	return nil
}
