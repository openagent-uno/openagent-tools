package providers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// GitHub's versioned REST contract, not a caller-selectable request header.
// https://docs.github.com/en/rest/about-the-rest-api/api-versions
const GitHubAPIVersion = "2026-03-10"

// Includes JSON and base64 expansion; this is not a decoded-file size limit.
const githubMaxResponseBytes = int64(4 << 20)

var (
	githubOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepoPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	githubSHAPattern   = regexp.MustCompile(`^(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$`)
)

type githubArgument struct {
	schema map[string]any
	valid  func(json.RawMessage) bool
}

type githubOperation struct {
	name, description, method, path string
	query                           []string
}

// The Issues API also returns pull requests; callers must inspect pull_request
// rather than assuming every returned issue is an ordinary issue. Each list
// operation returns one page; use page/per_page for subsequent pages.
var githubOperations = []githubOperation{
	{"files.github.user.get", "Read the authenticated GitHub user", http.MethodGet, "/user", nil},
	{"files.github.repositories.list", "List one page of repositories accessible to the authenticated user", http.MethodGet, "/user/repos", []string{"visibility", "affiliation", "type", "sort", "direction", "per_page", "page"}},
	{"files.github.repositories.user.list", "List one page of public repositories for a user", http.MethodGet, "/users/{username}/repos", []string{"type", "sort", "direction", "per_page", "page"}},
	{"files.github.repositories.get", "Read a repository visible to this connection", http.MethodGet, "/repos/{owner}/{repo}", nil},
	{"files.github.repositories.branches.list", "List one page of branches and their commit SHAs; optionally filter by protection", http.MethodGet, "/repos/{owner}/{repo}/branches", []string{"protected", "per_page", "page"}},
	{"files.github.git.commits.get", "Read a Git commit by its full SHA, including tree.sha for subsequent trees.get", http.MethodGet, "/repos/{owner}/{repo}/git/commits/{commit_sha}", nil},
	{"files.github.git.trees.get", "Read a tree by its full SHA; recursive='1' includes subtrees. Inspect truncated before treating the listing as complete; JSON responses above 4 MiB fail with response_too_large", http.MethodGet, "/repos/{owner}/{repo}/git/trees/{tree_sha}", []string{"recursive"}},
	{"files.github.git.blobs.get", "Read a blob by its full SHA as JSON with base64 content; no download URL is followed. Responses above 4 MiB including JSON/base64 expansion fail with response_too_large", http.MethodGet, "/repos/{owner}/{repo}/git/blobs/{file_sha}", nil},
	{"files.github.issues.list", "List one page of repository issues, including pull requests identified by pull_request", http.MethodGet, "/repos/{owner}/{repo}/issues", []string{"state", "milestone", "assignee", "creator", "mentioned", "labels", "sort", "direction", "since", "per_page", "page"}},
	{"files.github.issues.get", "Read an issue or pull request by its issue number", http.MethodGet, "/repos/{owner}/{repo}/issues/{issue_number}", nil},
	{"files.github.issues.create", "Create an issue in a repository", http.MethodPost, "/repos/{owner}/{repo}/issues", nil},
	{"files.github.issues.update", "Update an issue's title, body, state, assignees, labels or milestone", http.MethodPatch, "/repos/{owner}/{repo}/issues/{issue_number}", nil},
	{"files.github.issue_comments.list", "List one page of comments on an issue or pull request", http.MethodGet, "/repos/{owner}/{repo}/issues/{issue_number}/comments", []string{"since", "per_page", "page"}},
	{"files.github.issue_comments.create", "Create a comment on an issue or pull request", http.MethodPost, "/repos/{owner}/{repo}/issues/{issue_number}/comments", nil},
	{"files.github.pulls.list", "List one page of pull requests in a repository", http.MethodGet, "/repos/{owner}/{repo}/pulls", []string{"state", "head", "base", "sort", "direction", "per_page", "page"}},
	{"files.github.pulls.get", "Read a pull request by its number", http.MethodGet, "/repos/{owner}/{repo}/pulls/{pull_number}", nil},
	{"files.github.pulls.files.list", "List one page of changed files in a pull request; GitHub limits this endpoint to 3000 files", http.MethodGet, "/repos/{owner}/{repo}/pulls/{pull_number}/files", []string{"per_page", "page"}},
}

func githubManifest() Manifest {
	operations := make([]OperationManifest, 0, len(githubOperations))
	for _, spec := range githubOperations {
		required := []string{}
		properties := map[string]any{
			"connection_id":        boundedStringProperty(128),
			"provider":             map[string]any{"type": "string", "const": "github"},
			"expected_external_id": boundedStringProperty(1024),
		}
		for _, match := range pathTemplatePattern.FindAllStringSubmatch(spec.path, -1) {
			name := match[1]
			required = append(required, name)
			properties[name] = githubArgumentFor(spec.name, name).schema
		}
		query := map[string]string{}
		for _, name := range spec.query {
			query[name] = name
			properties[name] = githubArgumentFor(spec.name, name).schema
		}
		op := OperationManifest{Name: spec.name, Description: spec.description, Risk: domain.RiskRead,
			Method: spec.method, Path: spec.path, Query: query, Body: BodyNone, Retry: readRetry}
		if spec.method != http.MethodGet {
			op.Risk, op.Body, op.Retry = domain.RiskWrite, BodyJSON, noRetry
			required = append(required, "body")
			properties["body"] = githubBodySchema(spec.name)
		}
		op.Required = required
		schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
		if len(required) > 0 {
			schema["required"] = required
		}
		op.InputSchema, _ = json.Marshal(schema)
		operations = append(operations, op)
	}
	return Manifest{Provider: "github", Capability: domain.Files, APIVersion: GitHubAPIVersion,
		OriginKind: OriginFixed, Origin: "https://api.github.com", CredentialHeader: "Authorization", CredentialScheme: "Bearer",
		MaxRequestBytes: 1 << 20, MaxResponseBytes: githubMaxResponseBytes, Operations: operations, TypedOnly: true}
}

func githubText(maximum int, empty bool) githubArgument {
	minimum := 1
	if empty {
		minimum = 0
	}
	return githubArgument{map[string]any{"type": "string", "minLength": minimum, "maxLength": maximum}, func(raw json.RawMessage) bool {
		if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '"' {
			return false
		}
		var value string
		return json.Unmarshal(raw, &value) == nil && utf8.ValidString(value) && utf8.RuneCountInString(value) >= minimum && utf8.RuneCountInString(value) <= maximum && !strings.ContainsRune(value, 0)
	}}
}

func githubEnum(values ...string) githubArgument {
	return githubArgument{map[string]any{"type": "string", "enum": values}, func(raw json.RawMessage) bool {
		v := jsonString(raw)
		for _, allowed := range values {
			if v == allowed {
				return true
			}
		}
		return false
	}}
}

func githubInteger(minimum, maximum int) githubArgument {
	return githubArgument{integerProperty(minimum, maximum), func(raw json.RawMessage) bool {
		return !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && len(raw) > 0 && optionalInteger(raw, minimum, maximum)
	}}
}

func githubOwner(raw json.RawMessage) bool {
	v := jsonString(raw)
	return githubOwnerPattern.MatchString(v) && !strings.Contains(v, "--")
}

func githubRef(raw json.RawMessage) bool {
	if !githubText(255, false).valid(raw) {
		return false
	}
	v := jsonString(raw)
	if strings.ContainsAny(v, " ~^:?*[\\\r\n\t") || strings.Contains(v, "..") || strings.Contains(v, "@{") || strings.Contains(v, "//") || strings.HasPrefix(v, "/") || strings.HasSuffix(v, "/") || strings.HasSuffix(v, ".") || v == "@" {
		return false
	}
	for _, part := range strings.Split(v, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
		for _, r := range part {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
	}
	return true
}

func githubArgumentFor(operation, name string) githubArgument {
	switch name {
	case "owner", "username", "creator", "mentioned":
		return githubArgument{map[string]any{"type": "string", "pattern": githubOwnerPattern.String(), "maxLength": 39}, githubOwner}
	case "repo":
		return githubArgument{map[string]any{"type": "string", "pattern": githubRepoPattern.String(), "maxLength": 100}, func(raw json.RawMessage) bool {
			v := jsonString(raw)
			return githubRepoPattern.MatchString(v) && v != "." && v != ".."
		}}
	case "issue_number", "pull_number":
		return githubInteger(1, 2147483647)
	case "tree_sha", "file_sha", "commit_sha":
		return githubArgument{map[string]any{"type": "string", "pattern": githubSHAPattern.String(), "description": "Full 40- or 64-character hexadecimal Git object SHA; abbreviated SHAs and refs are not accepted"}, func(raw json.RawMessage) bool {
			return githubSHAPattern.MatchString(jsonString(raw))
		}}
	case "recursive":
		return githubEnum("1")
	case "protected":
		return githubArgument{map[string]any{"type": "boolean"}, func(raw json.RawMessage) bool {
			return bytes.Equal(bytes.TrimSpace(raw), []byte("true")) || bytes.Equal(bytes.TrimSpace(raw), []byte("false"))
		}}
	case "page":
		return githubInteger(1, 1000000)
	case "per_page":
		return githubInteger(1, 100)
	case "state":
		return githubEnum("open", "closed", "all")
	case "direction":
		return githubEnum("asc", "desc")
	case "visibility":
		return githubEnum("all", "public", "private")
	case "type":
		if operation == "files.github.repositories.user.list" {
			return githubEnum("all", "owner", "member")
		}
		return githubEnum("all", "owner", "public", "private", "member")
	case "sort":
		if strings.Contains(operation, "repositories.") {
			return githubEnum("created", "updated", "pushed", "full_name")
		}
		if operation == "files.github.pulls.list" {
			return githubEnum("created", "updated", "popularity", "long-running")
		}
		return githubEnum("created", "updated", "comments")
	case "affiliation":
		return githubArgument{githubText(64, false).schema, func(raw json.RawMessage) bool {
			parts := strings.Split(jsonString(raw), ",")
			seen := map[string]bool{}
			for _, p := range parts {
				if seen[p] || (p != "owner" && p != "collaborator" && p != "organization_member") {
					return false
				}
				seen[p] = true
			}
			return len(parts) > 0 && len(parts) <= 3
		}}
	case "assignee":
		return githubArgument{githubText(39, false).schema, func(raw json.RawMessage) bool {
			v := jsonString(raw)
			return v == "*" || v == "none" || githubOwner(raw)
		}}
	case "milestone":
		return githubArgument{githubText(10, false).schema, func(raw json.RawMessage) bool {
			v := jsonString(raw)
			if v == "*" || v == "none" {
				return true
			}
			return len(v) > 0 && v[0] != '0' && len(v) <= 10 && strings.Trim(v, "0123456789") == "" && githubInteger(1, 2147483647).valid(json.RawMessage(v))
		}}
	case "labels":
		return githubArgument{githubText(2048, false).schema, func(raw json.RawMessage) bool {
			if !githubText(2048, false).valid(raw) {
				return false
			}
			parts := strings.Split(jsonString(raw), ",")
			if len(parts) > 100 {
				return false
			}
			for _, p := range parts {
				if strings.TrimSpace(p) == "" || strings.ContainsAny(p, "\r\n\t") {
					return false
				}
			}
			return true
		}}
	case "since":
		return githubArgument{map[string]any{"type": "string", "format": "date-time", "maxLength": 35}, func(raw json.RawMessage) bool {
			v := jsonString(raw)
			_, err := time.Parse(time.RFC3339, v)
			return len(v) <= 35 && err == nil
		}}
	case "base":
		return githubArgument{githubText(255, false).schema, githubRef}
	case "head":
		return githubArgument{githubText(295, false).schema, func(raw json.RawMessage) bool {
			v := strings.Split(jsonString(raw), ":")
			if len(v) != 2 {
				return false
			}
			owner, _ := json.Marshal(v[0])
			ref, _ := json.Marshal(v[1])
			return githubOwner(owner) && githubRef(ref)
		}}
	}
	return githubArgument{map[string]any{}, func(json.RawMessage) bool { return false }}
}

func githubStringList(maximum, width int, owner bool) githubArgument {
	item := githubText(width, false)
	if owner {
		item = githubArgumentFor("", "username")
	}
	return githubArgument{map[string]any{"type": "array", "maxItems": maximum, "uniqueItems": true, "items": item.schema}, func(raw json.RawMessage) bool {
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
			return false
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || len(values) > maximum {
			return false
		}
		seen := map[string]bool{}
		for _, v := range values {
			if !item.valid(v) {
				return false
			}
			s := jsonString(v)
			if seen[s] {
				return false
			}
			seen[s] = true
		}
		return true
	}}
}

func githubBodyFields(operation string) map[string]githubArgument {
	if operation == "files.github.issue_comments.create" {
		return map[string]githubArgument{"body": githubText(65536, false)}
	}
	fields := map[string]githubArgument{"title": githubText(256, false), "body": githubText(65536, true), "labels": githubStringList(100, 50, false), "assignees": githubStringList(10, 39, true), "milestone": githubInteger(1, 2147483647)}
	if operation == "files.github.issues.update" {
		fields["state"] = githubEnum("open", "closed")
		fields["state_reason"] = githubEnum("completed", "not_planned", "reopened")
	}
	return fields
}

func githubBodySchema(operation string) map[string]any {
	properties := map[string]any{}
	for name, field := range githubBodyFields(operation) {
		properties[name] = field.schema
	}
	// GitHub accepts null to clear an issue body or milestone.
	if operation != "files.github.issue_comments.create" {
		for _, name := range []string{"body", "milestone"} {
			properties[name] = map[string]any{"anyOf": []any{properties[name], map[string]any{"type": "null"}}}
		}
	}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false, "minProperties": 1}
	if operation == "files.github.issues.create" {
		schema["required"] = []string{"title"}
	}
	if operation == "files.github.issue_comments.create" {
		schema["required"] = []string{"body"}
	}
	return schema
}

func validateGitHubArguments(operation OperationManifest, arguments map[string]json.RawMessage) error {
	allowed := map[string]bool{"connection_id": true, "provider": true, "expected_external_id": true}
	for _, match := range pathTemplatePattern.FindAllStringSubmatch(operation.Path, -1) {
		allowed[match[1]] = true
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
		switch name {
		case "provider":
			if jsonString(raw) != "github" {
				return domain.ErrInvalidArguments
			}
		case "connection_id":
			if !domain.ValidResourceID(jsonString(raw)) {
				return domain.ErrInvalidArguments
			}
		case "expected_external_id":
			if !githubText(1024, false).valid(raw) {
				return domain.ErrInvalidArguments
			}
		case "body":
			body, err := decodeArguments(raw, 1<<20)
			if err != nil || len(body) == 0 {
				return domain.ErrInvalidArguments
			}
			fields := githubBodyFields(operation.Name)
			for key, value := range body {
				field, ok := fields[key]
				if !ok {
					return domain.ErrInvalidArguments
				}
				if operation.Name != "files.github.issue_comments.create" && (key == "body" || key == "milestone") && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					continue
				}
				if !field.valid(value) {
					return domain.ErrInvalidArguments
				}
			}
			if operation.Name == "files.github.issues.create" && body["title"] == nil {
				return domain.ErrInvalidArguments
			}
			if operation.Name == "files.github.issue_comments.create" && body["body"] == nil {
				return domain.ErrInvalidArguments
			}
		default:
			if !githubArgumentFor(operation.Name, name).valid(raw) {
				return domain.ErrInvalidArguments
			}
		}
	}
	// GitHub disallows type together with visibility or affiliation.
	if arguments["type"] != nil && (arguments["visibility"] != nil || arguments["affiliation"] != nil) {
		return domain.ErrInvalidArguments
	}
	return nil
}
