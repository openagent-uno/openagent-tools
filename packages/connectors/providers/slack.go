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

// Slack Web API has no date-version header. Keep the existing slack_import
// provider identity; this adapter does not claim access to Slack's separate MCP.
// Method/argument references verified at https://docs.slack.dev/reference/methods/
// on 2026-10-16. All requests target the fixed https://slack.com/api/ prefix.
const slackMaxRequestBytes = 1 << 20

var (
	slackChannelID = regexp.MustCompile(`^[CGD][A-Z0-9]{8,63}$`)
	slackUserID    = regexp.MustCompile(`^[UW][A-Z0-9]{8,63}$`)
	// Message timestamps are string identifiers, never parsed through float64.
	slackTimestamp = regexp.MustCompile(`^[0-9]{1,20}\.[0-9]{6}$`)
)

func slackToolName(method string) string {
	return "social.slack_import." + strings.ReplaceAll(method, "postMessage", "post_message")
}

func slackManifest() Manifest {
	read := func(name, description string, parameters map[string]any, required ...string) OperationManifest {
		query := make(map[string]string, len(parameters))
		for key := range parameters {
			query[key] = key
		}
		return OperationManifest{Name: slackToolName(name), Description: description, Risk: domain.RiskRead,
			Method: http.MethodGet, Path: "/api/" + name, Query: query, Body: BodyNone, Required: required,
			InputSchema: slackToolSchema(parameters, required), Retry: noRetry}
	}
	id := func() map[string]any { return stringProperty(slackChannelID.String()) }
	cursor := func() map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": 2048, "pattern": `^[^\x00-\x1f\x7f]+$`}
	}
	history := func() map[string]any {
		return map[string]any{"channel": id(), "cursor": cursor(), "limit": integerProperty(1, 15),
			"oldest": stringProperty(slackTimestamp.String()), "latest": stringProperty(slackTimestamp.String()), "inclusive": map[string]any{"type": "boolean"}}
	}
	replies := history()
	replies["ts"] = stringProperty(slackTimestamp.String())
	operations := []OperationManifest{
		{Name: "social.slack_import.auth.test", Description: "Check the authorized Slack token's identity without exposing its value. Slack documents POST for this read-only operation.",
			Risk: domain.RiskRead, Method: http.MethodPost, Path: "/api/auth.test", Body: BodyJSON,
			InputSchema: slackToolSchema(map[string]any{}, nil), Retry: noRetry},
		read("conversations.list", "List one cursor page of conversations visible to the authorized Slack token; scopes and membership remain provider-enforced.",
			map[string]any{"cursor": cursor(), "limit": integerProperty(1, 200), "exclude_archived": map[string]any{"type": "boolean"},
				"types": map[string]any{"type": "string", "maxLength": 64, "description": "Comma-separated distinct public_channel, private_channel, mpim or im values."}}),
		read("conversations.info", "Retrieve a conversation visible to the authorized Slack token.", map[string]any{"channel": id(), "include_num_members": map[string]any{"type": "boolean"}}, "channel"),
		read("conversations.history", "Read one page of conversation history, capped at 15 messages for compatibility with unlisted commercial-app limits. No automatic pagination or retry; respect Slack Retry-After on rate limits.", history(), "channel"),
		read("conversations.replies", "Read one page of a message thread by its exact parent ts string, capped at 15 messages. Token type/scopes can restrict channel threads; respect Slack Retry-After without automatic retry.", replies, "channel", "ts"),
		read("users.info", "Retrieve a user visible to this connection; Slack requires users:read and separately gates email visibility.", map[string]any{"user": stringProperty(slackUserID.String())}, "user"),
	}
	for _, item := range []struct {
		name, description string
		risk              domain.Risk
	}{
		{"chat.postMessage", "Post an authorized text message to an explicit conversation ID, optionally replying to an exact parent thread_ts. No impersonation, attachments or blocks.", domain.RiskPublish},
		{"chat.update", "Update an authorized existing message's text using the exact channel and ts. Slack restricts which messages the token can edit.", domain.RiskWrite},
		{"chat.delete", "Delete an authorized existing message by exact channel and ts. Slack restricts deletion to messages the token is permitted to delete.", domain.RiskDestructive},
	} {
		operations = append(operations, OperationManifest{Name: slackToolName(item.name), Description: item.description, Risk: item.risk,
			Method: http.MethodPost, Path: "/api/" + item.name, Body: BodyJSON, Required: []string{"body"}, RequiredScopes: []string{"chat:write"},
			InputSchema: slackToolSchema(map[string]any{"body": slackWriteSchema(item.name)}, []string{"body"}), Retry: noRetry})
	}
	// A short shared backoff must not retry history/replies before a 60-second
	// Slack Retry-After. Therefore every Slack operation is sent once, including
	// reads; callers receive rate_limited rather than a hidden pagination loop.
	// Official policy: https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps/
	// New unlisted commercial apps/installations: 1 request/minute and 15 items
	// on history/replies; Marketplace and internal customer-built apps differ.
	return Manifest{Provider: "slack_import", Capability: domain.Social, APIVersion: "web-api", OriginKind: OriginFixed, Origin: "https://slack.com",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer", TypedOnly: true, MaxRequestBytes: slackMaxRequestBytes,
		MaxResponseBytes: defaultMaxResponseBytes, Operations: operations}
}

func slackObjectSchema(properties map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func slackToolSchema(properties map[string]any, required []string) json.RawMessage {
	properties["connection_id"] = boundedStringProperty(128)
	properties["provider"] = map[string]any{"type": "string", "const": "slack_import"}
	properties["expected_external_id"] = boundedStringProperty(1024)
	schema, _ := json.Marshal(slackObjectSchema(properties, required...))
	return schema
}

func slackWriteSchema(method string) map[string]any {
	fields := map[string]any{"channel": stringProperty(slackChannelID.String())}
	required := []string{"channel"}
	if method != "chat.postMessage" {
		fields["ts"] = stringProperty(slackTimestamp.String())
		required = append(required, "ts")
	}
	if method != "chat.delete" {
		fields["text"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 4000}
		required = append(required, "text")
	}
	if method == "chat.postMessage" {
		fields["thread_ts"] = stringProperty(slackTimestamp.String())
		for _, name := range []string{"mrkdwn", "unfurl_links", "unfurl_media"} {
			fields[name] = map[string]any{"type": "boolean"}
		}
	}
	return slackObjectSchema(fields, required...)
}

func validateSlackArguments(operation OperationManifest, arguments map[string]json.RawMessage) error {
	allowed := map[string]bool{"connection_id": true, "provider": true, "expected_external_id": true}
	for key := range operation.Query {
		allowed[key] = true
	}
	if operation.Risk != domain.RiskRead {
		allowed["body"] = true
	}
	for _, name := range operation.Required {
		if _, ok := arguments[name]; !ok {
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
			valid = jsonString(raw) == "slack_import"
		case "expected_external_id":
			valid = optionalBoundedString(raw, 1024)
		case "channel":
			valid = slackChannelID.MatchString(jsonString(raw))
		case "user":
			valid = slackUserID.MatchString(jsonString(raw))
		case "ts", "oldest", "latest":
			valid = slackTimestamp.MatchString(jsonString(raw))
		case "cursor":
			valid = utf8.Valid(raw) && optionalBoundedString(raw, 2048)
		case "limit":
			var count int
			maximum := 200
			if operation.Name == "social.slack_import.conversations.history" || operation.Name == "social.slack_import.conversations.replies" {
				maximum = 15
			}
			valid = json.Unmarshal(raw, &count) == nil && count >= 1 && count <= maximum
		case "inclusive", "exclude_archived", "include_num_members":
			valid = slackBool(raw)
		case "types":
			values := strings.Split(jsonString(raw), ",")
			seen := map[string]bool{}
			valid = len(values) >= 1 && len(values) <= 4
			for _, value := range values {
				if !containsString([]string{"public_channel", "private_channel", "mpim", "im"}, value) || seen[value] {
					valid = false
				}
				seen[value] = true
			}
		case "body":
			valid = len(raw) <= slackMaxRequestBytes && slackWriteBody(operation.Name, raw)
		}
		if !valid {
			return domain.ErrInvalidArguments
		}
	}
	if operation.Name == "social.slack_import.auth.test" {
		// Construct the only body auth.test needs; callers cannot put a token,
		// team selector or arbitrary headers into this read-only POST.
		arguments["body"] = json.RawMessage(`{}`)
	}
	if operation.Name == "social.slack_import.conversations.history" || operation.Name == "social.slack_import.conversations.replies" {
		if _, exists := arguments["limit"]; !exists {
			arguments["limit"] = json.RawMessage(`15`)
		}
	}
	return nil
}

func slackBool(raw json.RawMessage) bool {
	value := string(bytes.TrimSpace(raw))
	return value == "true" || value == "false"
}

// A bounded strict JSON object decoder rejects duplicate keys and trailing
// JSON values. nil allowed is used for provider responses whose other fields
// must be preserved rather than silently stripped by a response schema.
func slackObject(raw json.RawMessage, allowed map[string]bool) (map[string]json.RawMessage, bool) {
	if !utf8.Valid(raw) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	object := map[string]json.RawMessage{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || (allowed != nil && !allowed[key]) {
			return nil, false
		}
		if _, duplicate := object[key]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		object[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return nil, false
	}
	return object, true
}

func slackWriteBody(operation string, raw json.RawMessage) bool {
	allowed := map[string]bool{"channel": true}
	switch operation {
	case "social.slack_import.chat.post_message":
		for _, key := range []string{"text", "thread_ts", "mrkdwn", "unfurl_links", "unfurl_media"} {
			allowed[key] = true
		}
	case "social.slack_import.chat.update":
		allowed["text"] = true
		allowed["ts"] = true
	case "social.slack_import.chat.delete":
		allowed["ts"] = true
	default:
		return false
	}
	body, ok := slackObject(raw, allowed)
	if !ok || !slackChannelID.MatchString(jsonString(body["channel"])) {
		return false
	}
	if operation != "social.slack_import.chat.post_message" && !slackTimestamp.MatchString(jsonString(body["ts"])) {
		return false
	}
	if operation != "social.slack_import.chat.delete" {
		var text string
		if json.Unmarshal(body["text"], &text) != nil || len(text) == 0 || utf8.RuneCountInString(text) > 4000 || strings.ContainsRune(text, '\x00') {
			return false
		}
	}
	for name, value := range body {
		switch name {
		case "thread_ts":
			if !slackTimestamp.MatchString(jsonString(value)) {
				return false
			}
		case "mrkdwn", "unfurl_links", "unfurl_media":
			if !slackBool(value) {
				return false
			}
		}
	}
	return true
}

// slackResponseFailure must run after HTTP status processing and credential
// redaction, before publishing a domain.Result. Slack HTTP 200 is not success
// unless the top-level ok flag is exactly true. Returned classifications never
// contain untrusted provider strings or response payloads. The transport adds
// its own attempt/byte/status/request-ID accounting to the ProviderError.
func slackResponseFailure(raw json.RawMessage) (kind string, permission bool) {
	object, valid := slackObject(raw, nil)
	if !valid || !slackBool(object["ok"]) {
		return "invalid_response", false
	}
	if string(bytes.TrimSpace(object["ok"])) == "true" {
		if _, exists := object["error"]; exists {
			return "invalid_response", false
		}
		return "", false
	}
	code := jsonString(object["error"])
	if code == "" {
		return "invalid_response", false
	}
	if containsString([]string{"not_authed", "invalid_auth", "token_revoked", "token_expired", "account_inactive", "missing_scope", "no_permission", "access_denied", "not_allowed_token_type", "team_access_not_granted", "ekm_access_denied"}, code) {
		return "provider_permission", true
	}
	if code == "ratelimited" || code == "rate_limited" {
		return "rate_limited", false
	}
	return "provider_error", false
}
