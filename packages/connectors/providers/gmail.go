package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/mail"
	"regexp"
	"strings"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const (
	maxGmailDecodedMessageBytes = 8 << 20
	// Gmail attachment IDs can exceed message/thread IDs. This local bound
	// applies only to attachment IDs, not other IDs or generic path segments.
	maxGmailAttachmentIDBytes      = 4096
	gmailAttachmentIDSchemaPattern = `^[A-Za-z0-9_-]+$`
)

var (
	gmailOpaqueIDPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
	gmailAttachmentIDPattern = regexp.MustCompile(gmailAttachmentIDSchemaPattern)
	gmailHistoryIDPattern    = regexp.MustCompile(`^[0-9]{1,32}$`)
	gmailTopicPattern        = regexp.MustCompile(
		`^projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/topics/[A-Za-z][A-Za-z0-9._~+%-]{2,254}$`,
	)
)

func validGmailAttachmentID(value string) bool {
	return len(value) <= maxGmailAttachmentIDBytes && gmailAttachmentIDPattern.MatchString(value)
}

func gmailHistorySchema() json.RawMessage {
	return gmailSchema(
		map[string]any{
			"start_history_id": stringProperty(`^[0-9]{1,32}$`),
			"label_id":         stringProperty(`^[A-Za-z0-9_-]{1,256}$`),
			"history_types": arrayProperty(map[string]any{
				"type": "string", "enum": []string{"messageAdded", "messageDeleted", "labelAdded", "labelRemoved"},
			}, 4),
			"max_results": integerProperty(1, 500),
			"page_token":  boundedStringProperty(2048),
		},
		[]string{"start_history_id"},
	)
}

func gmailMessagesListSchema() json.RawMessage {
	return gmailSchema(
		map[string]any{
			"query":              boundedStringProperty(2048),
			"label_ids":          arrayProperty(stringProperty(`^[A-Za-z0-9_-]{1,256}$`), 50),
			"include_spam_trash": map[string]any{"type": "boolean"},
			"max_results":        integerProperty(1, 500),
			"page_token":         boundedStringProperty(2048),
		},
		nil,
	)
}

func gmailMessageGetSchema() json.RawMessage {
	return gmailSchema(
		map[string]any{
			"message_id":       stringProperty(`^[A-Za-z0-9_-]{1,256}$`),
			"format":           map[string]any{"type": "string", "enum": []string{"minimal", "full", "raw", "metadata"}},
			"metadata_headers": arrayProperty(boundedStringProperty(128), 50),
		},
		[]string{"message_id"},
	)
}

func gmailThreadGetSchema() json.RawMessage {
	return gmailSchema(
		map[string]any{
			"thread_id": stringProperty(`^[A-Za-z0-9_-]{1,256}$`),
			"format": map[string]any{
				"type": "string", "enum": []string{"minimal", "full", "metadata"},
			},
			"metadata_headers": arrayProperty(boundedStringProperty(128), 50),
		},
		[]string{"thread_id"},
	)
}

func gmailAttachmentGetSchema() json.RawMessage {
	return gmailSchema(
		map[string]any{
			"message_id":    stringProperty(`^[A-Za-z0-9_-]{1,256}$`),
			"attachment_id": map[string]any{"type": "string", "pattern": gmailAttachmentIDSchemaPattern, "minLength": 1, "maxLength": maxGmailAttachmentIDBytes},
		},
		[]string{"message_id", "attachment_id"},
	)
}

func gmailWatchSchema() json.RawMessage {
	return gmailSchema(
		map[string]any{
			"body": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"topicName":           boundedStringProperty(512),
					"labelIds":            arrayProperty(stringProperty(`^[A-Za-z0-9_-]{1,256}$`), 50),
					"labelFilterBehavior": map[string]any{"type": "string", "enum": []string{"include", "exclude"}},
				},
				"required":             []string{"topicName"},
				"additionalProperties": false,
			},
		},
		[]string{"body"},
	)
}

func gmailDraftCreateSchema() json.RawMessage {
	return gmailSchema(map[string]any{"body": gmailDraftBodySchema(true)}, []string{"body"})
}

func gmailDraftSendSchema() json.RawMessage {
	return gmailSchema(
		map[string]any{
			"body": map[string]any{
				"type": "object", "properties": map[string]any{
					"id": stringProperty(`^[A-Za-z0-9_-]{1,256}$`),
				}, "required": []string{"id"}, "additionalProperties": false,
			},
		},
		[]string{"body"},
	)
}

func gmailMessageSendSchema() json.RawMessage {
	return gmailSchema(map[string]any{"body": gmailMessageBodySchema()}, []string{"body"})
}

func gmailDraftBodySchema(nested bool) map[string]any {
	if !nested {
		return gmailMessageBodySchema()
	}
	return map[string]any{
		"type": "object", "properties": map[string]any{
			"message": gmailMessageBodySchema(),
		}, "required": []string{"message"}, "additionalProperties": false,
	}
}

func gmailMessageBodySchema() map[string]any {
	return map[string]any{
		"type": "object", "properties": map[string]any{
			"raw":      boundedStringProperty(defaultGmailRequestBytes),
			"threadId": stringProperty(`^[A-Za-z0-9_-]{1,256}$`),
		}, "required": []string{"raw"}, "additionalProperties": false,
	}
}

func gmailSchema(properties map[string]any, required []string) json.RawMessage {
	properties["connection_id"] = boundedStringProperty(128)
	properties["provider"] = map[string]any{"type": "string", "const": "gmail"}
	schema := map[string]any{
		"type": "object", "properties": properties, "additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	encoded, _ := json.Marshal(schema)
	return encoded
}

func stringProperty(pattern string) map[string]any {
	return map[string]any{"type": "string", "pattern": pattern}
}

func boundedStringProperty(maximum any) map[string]any {
	return map[string]any{"type": "string", "maxLength": maximum}
}

func integerProperty(minimum, maximum int) map[string]any {
	return map[string]any{"type": "integer", "minimum": minimum, "maximum": maximum}
}

func arrayProperty(items map[string]any, maximum int) map[string]any {
	return map[string]any{"type": "array", "items": items, "maxItems": maximum}
}

func validateGmailArguments(
	operation OperationManifest,
	arguments map[string]json.RawMessage,
	connectionConfig json.RawMessage,
) error {
	if operation.Raw != nil {
		return nil
	}
	allowed := map[string]bool{"connection_id": true, "provider": true}
	switch operation.Name {
	case "outreach.gmail.history.list":
		addAllowed(allowed, "start_history_id", "label_id", "history_types", "max_results", "page_token")
		if !gmailHistoryIDPattern.MatchString(jsonString(arguments["start_history_id"])) ||
			!optionalOpaqueID(arguments["label_id"]) ||
			!optionalStringList(arguments["history_types"], 4, validHistoryType) ||
			!optionalInteger(arguments["max_results"], 1, 500) ||
			!optionalBoundedString(arguments["page_token"], 2048) {
			return domain.ErrInvalidArguments
		}
	case "outreach.gmail.messages.list":
		addAllowed(allowed, "query", "label_ids", "include_spam_trash", "max_results", "page_token")
		if !optionalBoundedString(arguments["query"], 2048) ||
			!optionalStringList(arguments["label_ids"], 50, func(value string) bool {
				return gmailOpaqueIDPattern.MatchString(value)
			}) ||
			!optionalBoolean(arguments["include_spam_trash"]) ||
			!optionalInteger(arguments["max_results"], 1, 500) ||
			!optionalBoundedString(arguments["page_token"], 2048) {
			return domain.ErrInvalidArguments
		}
	case "outreach.gmail.messages.get":
		addAllowed(allowed, "message_id", "format", "metadata_headers")
		format := jsonString(arguments["format"])
		if !gmailOpaqueIDPattern.MatchString(jsonString(arguments["message_id"])) ||
			format != "" && format != "minimal" && format != "full" && format != "raw" && format != "metadata" ||
			!optionalStringList(arguments["metadata_headers"], 50, func(value string) bool {
				return value != "" && len(value) <= 128 && !containsControl(value)
			}) {
			return domain.ErrInvalidArguments
		}
	case "outreach.gmail.threads.get":
		addAllowed(allowed, "thread_id", "format", "metadata_headers")
		format := jsonString(arguments["format"])
		if !gmailOpaqueIDPattern.MatchString(jsonString(arguments["thread_id"])) ||
			format != "" && format != "minimal" && format != "full" && format != "metadata" ||
			!optionalStringList(arguments["metadata_headers"], 50, func(value string) bool {
				return value != "" && len(value) <= 128 && !containsControl(value)
			}) {
			return domain.ErrInvalidArguments
		}
	case "outreach.gmail.attachments.get":
		addAllowed(allowed, "message_id", "attachment_id")
		attachmentID := jsonString(arguments["attachment_id"])
		if !gmailOpaqueIDPattern.MatchString(jsonString(arguments["message_id"])) ||
			!validGmailAttachmentID(attachmentID) {
			return domain.ErrInvalidArguments
		}
	case "outreach.gmail.watch":
		addAllowed(allowed, "body")
		if !validGmailWatch(arguments["body"], connectionConfig) {
			return domain.ErrInvalidArguments
		}
	case "outreach.gmail.drafts.create":
		addAllowed(allowed, "body")
		var body struct {
			Message gmailMessageBody `json:"message"`
		}
		if strictJSON(arguments["body"], &body) != nil || !body.Message.valid() {
			return domain.ErrInvalidArguments
		}
	case "outreach.gmail.drafts.send":
		addAllowed(allowed, "body")
		var body struct {
			ID string `json:"id"`
		}
		if strictJSON(arguments["body"], &body) != nil || !gmailOpaqueIDPattern.MatchString(body.ID) {
			return domain.ErrInvalidArguments
		}
	case "outreach.gmail.messages.send":
		addAllowed(allowed, "body")
		var body gmailMessageBody
		if strictJSON(arguments["body"], &body) != nil || !body.valid() {
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
	if provider := jsonString(arguments["provider"]); provider != "" && provider != "gmail" {
		return domain.ErrInvalidArguments
	}
	return nil
}

type gmailMessageBody struct {
	Raw      string `json:"raw"`
	ThreadID string `json:"threadId,omitempty"`
}

func (body gmailMessageBody) valid() bool {
	if body.ThreadID != "" && !gmailOpaqueIDPattern.MatchString(body.ThreadID) {
		return false
	}
	decoded, err := decodeGmailRaw(body.Raw)
	if err != nil || len(decoded) == 0 || len(decoded) > maxGmailDecodedMessageBytes {
		return false
	}
	message, err := mail.ReadMessage(bytes.NewReader(decoded))
	if err != nil {
		return false
	}
	if message.Header.Get("To") == "" && message.Header.Get("Cc") == "" && message.Header.Get("Bcc") == "" {
		return false
	}
	return true
}

func decodeGmailRaw(value string) ([]byte, error) {
	if value == "" || int64(len(value)) > defaultGmailRequestBytes || containsControl(value) {
		return nil, domain.ErrInvalidArguments
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(value)
	}
	return decoded, err
}

func validGmailWatch(raw, connectionConfig json.RawMessage) bool {
	var body struct {
		TopicName           string   `json:"topicName"`
		LabelIDs            []string `json:"labelIds,omitempty"`
		LabelFilterBehavior string   `json:"labelFilterBehavior,omitempty"`
	}
	if strictJSON(raw, &body) != nil || !gmailTopicPattern.MatchString(body.TopicName) ||
		len(body.LabelIDs) > 50 ||
		body.LabelFilterBehavior != "" && body.LabelFilterBehavior != "include" && body.LabelFilterBehavior != "exclude" {
		return false
	}
	for _, label := range body.LabelIDs {
		if !gmailOpaqueIDPattern.MatchString(label) {
			return false
		}
	}
	var config struct {
		TopicName string `json:"gmail_topic_name"`
	}
	return json.Unmarshal(connectionConfig, &config) == nil &&
		config.TopicName != "" && config.TopicName == body.TopicName
}

func strictJSON(raw json.RawMessage, destination any) error {
	if len(raw) == 0 {
		return domain.ErrInvalidArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return domain.ErrInvalidArguments
	}
	return nil
}

func addAllowed(target map[string]bool, values ...string) {
	for _, value := range values {
		target[value] = true
	}
}

func jsonString(raw json.RawMessage) string {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || containsControl(value) {
		return ""
	}
	return value
}

func optionalOpaqueID(raw json.RawMessage) bool {
	return len(raw) == 0 || gmailOpaqueIDPattern.MatchString(jsonString(raw))
}

func optionalStringList(raw json.RawMessage, maximum int, valid func(string) bool) bool {
	if len(raw) == 0 {
		return true
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil || len(values) > maximum {
		return false
	}
	for _, value := range values {
		if !valid(value) {
			return false
		}
	}
	return true
}

func optionalInteger(raw json.RawMessage, minimum, maximum int) bool {
	if len(raw) == 0 {
		return true
	}
	var value int
	return json.Unmarshal(raw, &value) == nil && value >= minimum && value <= maximum
}

func optionalBoolean(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var value bool
	return json.Unmarshal(raw, &value) == nil
}

func optionalBoundedString(raw json.RawMessage, maximum int) bool {
	if len(raw) == 0 {
		return true
	}
	value := jsonString(raw)
	return value != "" && len(value) <= maximum
}

func validHistoryType(value string) bool {
	switch value {
	case "messageAdded", "messageDeleted", "labelAdded", "labelRemoved":
		return true
	default:
		return false
	}
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0
}
