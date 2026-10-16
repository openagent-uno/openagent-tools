package providers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// Notion requires a version header on every request. The transport must inject
// this server-owned constant; neither arguments nor credentials choose it.
// Verified against https://developers.notion.com/reference/versioning and the
// search/page/block/user reference endpoints on 2026-10-16.
const notionAPIVersion = "2026-03-11"
const notionMaxRequestBytes = 500000

var notionIDPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)

func notionManifest() Manifest {
	read := func(name, description, path string, parameters map[string]any, required []string, query map[string]string) OperationManifest {
		return OperationManifest{Name: "files.notion." + name, Description: description, Risk: domain.RiskRead,
			Method: http.MethodGet, Path: path, Query: query, Required: required, Body: BodyNone,
			InputSchema: notionToolSchema(parameters, required), Retry: readRetry}
	}
	id := func() map[string]any { return stringProperty(notionIDPattern.String()) }
	pagination := func() map[string]any {
		return map[string]any{"start_cursor": notionCursorSchema(), "page_size": integerProperty(1, 100)}
	}
	query := map[string]string{"start_cursor": "start_cursor", "page_size": "page_size"}
	blocks := pagination()
	blocks["block_id"] = id()
	operations := []OperationManifest{
		{Name: "files.notion.search", Description: "Search titles of shared Notion pages and data sources; returns one page with next_cursor and has_more. This is not full-text content search.",
			Risk: domain.RiskRead, Method: http.MethodPost, Path: "/v1/search", Body: BodyJSON, Required: []string{"body"}, Retry: readRetry,
			InputSchema: notionToolSchema(map[string]any{"body": notionSearchSchema()}, []string{"body"})},
		read("pages.get", "Retrieve shared Notion page properties; use blocks.children.list to read its content.", "/v1/pages/{page_id}", map[string]any{"page_id": id()}, []string{"page_id"}, nil),
		read("blocks.children.list", "Read one page of immediate children of a shared Notion page or block; follow next_cursor explicitly and list nested blocks separately.", "/v1/blocks/{block_id}/children", blocks, []string{"block_id"}, query),
		read("users.get", "Retrieve a Notion user visible to the authorized integration; requires the provider's user-information capability.", "/v1/users/{user_id}", map[string]any{"user_id": id()}, []string{"user_id"}, nil),
		read("users.list", "List one page of Notion workspace users visible to the authorized integration; returns next_cursor without automatically fetching more pages.", "/v1/users", pagination(), nil, query),
	}
	for _, item := range []struct{ name, description, method, path, parameter string }{
		{"pages.create", "Create a Notion child page with an explicit page or data-source parent, title/rich_text properties and optional flat text blocks. No templates, uploads or implicit workspace parent.", http.MethodPost, "/v1/pages", ""},
		{"pages.update", "Update explicit title/rich_text properties of an authorized Notion page. Other properties, trash, templates and moving pages are not supported.", http.MethodPatch, "/v1/pages/{page_id}", "page_id"},
		{"blocks.children.append", "Append up to 100 flat text blocks to an authorized Notion page or block. Existing blocks are not moved or replaced.", http.MethodPatch, "/v1/blocks/{block_id}/children", "block_id"},
	} {
		properties := map[string]any{"body": notionWriteSchema(item.name)}
		required := []string{"body"}
		if item.parameter != "" {
			properties[item.parameter] = id()
			required = []string{item.parameter, "body"}
		}
		operations = append(operations, OperationManifest{Name: "files.notion." + item.name, Description: item.description,
			Risk: domain.RiskWrite, Method: item.method, Path: item.path, Body: BodyJSON, Required: required,
			InputSchema: notionToolSchema(properties, required), Retry: noRetry})
	}
	return Manifest{Provider: "notion", Capability: domain.Files, APIVersion: notionAPIVersion,
		OriginKind: OriginFixed, Origin: "https://api.notion.com", CredentialHeader: "Authorization", CredentialScheme: "Bearer",
		TypedOnly: true, MaxRequestBytes: notionMaxRequestBytes, MaxResponseBytes: defaultMaxResponseBytes, Operations: operations}
}

func notionObjectSchema(properties map[string]any, required ...string) map[string]any {
	result := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		result["required"] = required
	}
	return result
}

func notionToolSchema(properties map[string]any, required []string) json.RawMessage {
	properties["connection_id"] = boundedStringProperty(128)
	properties["provider"] = map[string]any{"type": "string", "const": "notion"}
	properties["expected_external_id"] = boundedStringProperty(1024)
	encoded, _ := json.Marshal(notionObjectSchema(properties, required...))
	return encoded
}

func notionSearchSchema() map[string]any {
	return notionObjectSchema(map[string]any{
		"query":        map[string]any{"type": "string", "maxLength": 2000},
		"start_cursor": notionCursorSchema(), "page_size": integerProperty(1, 100),
		"filter": notionObjectSchema(map[string]any{
			"property": map[string]any{"type": "string", "const": "object"},
			"value":    map[string]any{"type": "string", "enum": []string{"page", "data_source"}},
		}, "property", "value"),
		"sort": notionObjectSchema(map[string]any{
			"timestamp": map[string]any{"type": "string", "const": "last_edited_time"},
			"direction": map[string]any{"type": "string", "enum": []string{"ascending", "descending"}},
		}, "timestamp", "direction"),
	})
}

func notionRichTextSchema() map[string]any {
	item := notionObjectSchema(map[string]any{
		"type": map[string]any{"type": "string", "const": "text"},
		"text": notionObjectSchema(map[string]any{"content": map[string]any{"type": "string", "maxLength": 2000}}, "content"),
	}, "text")
	return arrayProperty(item, 100)
}

var notionTextBlocks = []string{"paragraph", "heading_1", "heading_2", "heading_3", "bulleted_list_item", "numbered_list_item", "quote", "to_do"}

func notionChildrenSchema() map[string]any {
	variants := make([]any, 0, len(notionTextBlocks))
	for _, kind := range notionTextBlocks {
		content := map[string]any{"rich_text": notionRichTextSchema()}
		if kind == "to_do" {
			content["checked"] = map[string]any{"type": "boolean"}
		}
		variants = append(variants, notionObjectSchema(map[string]any{
			"object": map[string]any{"type": "string", "const": "block"},
			"type":   map[string]any{"type": "string", "const": kind},
			kind:     notionObjectSchema(content, "rich_text"),
		}, "type", kind))
	}
	return map[string]any{"type": "array", "minItems": 1, "maxItems": 100, "items": map[string]any{"oneOf": variants}}
}

func notionWriteSchema(operation string) map[string]any {
	if operation == "blocks.children.append" {
		return notionObjectSchema(map[string]any{"children": notionChildrenSchema()}, "children")
	}
	properties := map[string]any{"type": "object", "minProperties": 1, "maxProperties": 100,
		"additionalProperties": map[string]any{"oneOf": []any{
			notionObjectSchema(map[string]any{"title": notionRichTextSchema()}, "title"),
			notionObjectSchema(map[string]any{"rich_text": notionRichTextSchema()}, "rich_text"),
		}}}
	fields := map[string]any{"properties": properties}
	if operation == "pages.create" {
		fields["parent"] = map[string]any{"oneOf": []any{
			notionObjectSchema(map[string]any{"page_id": stringProperty(notionIDPattern.String())}, "page_id"),
			notionObjectSchema(map[string]any{"data_source_id": stringProperty(notionIDPattern.String())}, "data_source_id"),
		}}
		fields["children"] = notionChildrenSchema()
		return notionObjectSchema(fields, "parent", "properties")
	}
	return notionObjectSchema(fields, "properties")
}

// validateNotionArguments is called by the shared adapter before credential
// resolution/approval. Writes deliberately accept a bounded documented subset,
// not arbitrary provider JSON; all unsupported fields fail closed.
func validateNotionArguments(operation OperationManifest, arguments map[string]json.RawMessage) error {
	allowed := map[string]bool{"connection_id": true, "provider": true, "expected_external_id": true}
	for _, name := range clickupPathParameters(operation.Path) {
		allowed[name] = true
	}
	for name := range operation.Query {
		allowed[name] = true
	}
	if operation.Body == BodyJSON {
		allowed["body"] = true
	}
	for _, name := range operation.Required {
		if _, exists := arguments[name]; !exists {
			return domain.ErrInvalidArguments
		}
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
			valid = jsonString(raw) == "notion"
		case "expected_external_id":
			valid = optionalBoundedString(raw, 1024)
		case "page_id", "block_id", "user_id":
			valid = notionIDPattern.MatchString(jsonString(raw))
		case "start_cursor":
			valid = notionCursor(raw)
		case "page_size":
			valid = notionPageSize(raw)
		case "body":
			valid = len(raw) <= notionMaxRequestBytes && notionBody(operation.Name, raw)
		}
		if !valid {
			return domain.ErrInvalidArguments
		}
	}
	return nil
}

func notionPageSize(raw json.RawMessage) bool {
	var size int
	return json.Unmarshal(raw, &size) == nil && size >= 1 && size <= 100
}

func notionCursorSchema() map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": 2048, "pattern": `^[^\x00-\x1f\x7f]+$`}
}

func notionCursor(raw json.RawMessage) bool {
	value := jsonString(raw)
	return utf8.Valid(raw) && len(value) > 0 && len(value) <= 2048 && !containsControl(value)
}

// Every object is decoded with duplicate-key and trailing-value rejection.
// Nested objects are checked by their explicit bounded shape below; no block
// nesting, external file/link URLs, mentions or template execution is admitted.
func notionObject(raw json.RawMessage, allowed string, required ...string) (map[string]json.RawMessage, bool) {
	if !utf8.Valid(raw) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	result := map[string]json.RawMessage{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || strings.Contains(key, "|") || !containsString(strings.Split(allowed, "|"), key) {
			return nil, false
		}
		if _, duplicate := result[key]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		result[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return nil, false
	}
	for _, key := range required {
		if _, exists := result[key]; !exists {
			return nil, false
		}
	}
	return result, true
}

func notionBody(operation string, raw json.RawMessage) bool {
	switch operation {
	case "files.notion.search":
		body, ok := notionObject(raw, "query|start_cursor|page_size|filter|sort")
		if !ok {
			return false
		}
		for key, value := range body {
			switch key {
			case "query":
				if !notionText(value) {
					return false
				}
			case "start_cursor":
				if !notionCursor(value) {
					return false
				}
			case "page_size":
				if !notionPageSize(value) {
					return false
				}
			case "filter":
				filter, valid := notionObject(value, "property|value", "property", "value")
				if !valid || jsonString(filter["property"]) != "object" || !containsString([]string{"page", "data_source"}, jsonString(filter["value"])) {
					return false
				}
			case "sort":
				sort, valid := notionObject(value, "timestamp|direction", "timestamp", "direction")
				if !valid || jsonString(sort["timestamp"]) != "last_edited_time" || !containsString([]string{"ascending", "descending"}, jsonString(sort["direction"])) {
					return false
				}
			}
		}
		return true
	case "files.notion.pages.create":
		body, ok := notionObject(raw, "parent|properties|children", "parent", "properties")
		if !ok {
			return false
		}
		parent, valid := notionObject(body["parent"], "page_id|data_source_id")
		if !valid || len(parent) != 1 {
			return false
		}
		for _, id := range parent {
			if !notionIDPattern.MatchString(jsonString(id)) {
				return false
			}
		}
		_, pageParent := parent["page_id"]
		if !notionProperties(body["properties"], pageParent) {
			return false
		}
		if children, exists := body["children"]; exists && !notionChildren(children) {
			return false
		}
		return true
	case "files.notion.pages.update":
		body, ok := notionObject(raw, "properties", "properties")
		return ok && notionProperties(body["properties"], false)
	case "files.notion.blocks.children.append":
		body, ok := notionObject(raw, "children", "children")
		return ok && notionChildren(body["children"])
	default:
		return false
	}
}

func notionProperties(raw json.RawMessage, pageParent bool) bool {
	// Property names are provider schema data, not request destinations. Decode
	// their names first, then use the same duplicate-rejecting object decoder.
	var names map[string]json.RawMessage
	if json.Unmarshal(raw, &names) != nil || len(names) < 1 || len(names) > 100 {
		return false
	}
	keys := make([]string, 0, len(names))
	for key := range names {
		if len(key) < 1 || len(key) > 200 || strings.ContainsAny(key, "|\x00\r\n") {
			return false
		}
		keys = append(keys, key)
	}
	properties, valid := notionObject(raw, strings.Join(keys, "|"))
	if !valid || pageParent && (len(properties) != 1 || properties["title"] == nil) {
		return false
	}
	for name, raw := range properties {
		value, ok := notionObject(raw, "title|rich_text")
		if !ok || len(value) != 1 {
			return false
		}
		for kind, rich := range value {
			if pageParent && (name != "title" || kind != "title") || !notionRichText(rich) {
				return false
			}
		}
	}
	return true
}

func notionText(raw json.RawMessage) bool {
	var text string
	return utf8.Valid(raw) && json.Unmarshal(raw, &text) == nil && string(bytes.TrimSpace(raw)) != "null" && len(text) <= 2000 && !strings.ContainsRune(text, '\x00')
}

func notionRichText(raw json.RawMessage) bool {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || items == nil || len(items) > 100 {
		return false
	}
	for _, raw := range items {
		item, ok := notionObject(raw, "type|text", "text")
		if !ok {
			return false
		}
		if kind, exists := item["type"]; exists && jsonString(kind) != "text" {
			return false
		}
		text, ok := notionObject(item["text"], "content", "content")
		if !ok || !notionText(text["content"]) {
			return false
		}
	}
	return true
}

func notionChildren(raw json.RawMessage) bool {
	var children []json.RawMessage
	if json.Unmarshal(raw, &children) != nil || len(children) < 1 || len(children) > 100 {
		return false
	}
	for _, raw := range children {
		block, ok := notionObject(raw, "object|type|"+strings.Join(notionTextBlocks, "|"), "type")
		kind := jsonString(block["type"])
		if !ok || !containsString(notionTextBlocks, kind) {
			return false
		}
		if object, exists := block["object"]; exists && jsonString(object) != "block" {
			return false
		}
		expected := 2
		if _, exists := block["object"]; exists {
			expected++
		}
		if len(block) != expected {
			return false
		}
		fields := "rich_text"
		if kind == "to_do" {
			fields += "|checked"
		}
		content, ok := notionObject(block[kind], fields, "rich_text")
		if !ok || !notionRichText(content["rich_text"]) {
			return false
		}
		if checked, exists := content["checked"]; exists && string(bytes.TrimSpace(checked)) != "true" && string(bytes.TrimSpace(checked)) != "false" {
			return false
		}
	}
	return true
}
