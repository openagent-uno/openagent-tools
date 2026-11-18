package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const smtpMaxTextBytes = 128 << 10
const smtpMaxRecipients = 50

type smtpArguments struct {
	ConnectionID string   `json:"connection_id,omitempty"`
	To           []string `json:"to"`
	CC           []string `json:"cc,omitempty"`
	BCC          []string `json:"bcc,omitempty"`
	Subject      string   `json:"subject"`
	Text         string   `json:"text"`
}

func smtpSendSchema() json.RawMessage {
	addressList := map[string]any{"type": "array", "maxItems": smtpMaxRecipients, "items": map[string]any{"type": "string", "format": "email", "maxLength": 254}}
	toList := map[string]any{"type": "array", "minItems": 1, "maxItems": smtpMaxRecipients, "items": map[string]any{"type": "string", "format": "email", "maxLength": 254}}
	encoded, _ := json.Marshal(map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"to", "subject", "text"},
		"properties": map[string]any{
			"connection_id": boundedStringProperty(128),
			"to":            toList, "cc": addressList, "bcc": addressList,
			"subject": map[string]any{"type": "string", "minLength": 1, "maxLength": 512},
			"text":    map[string]any{"type": "string", "minLength": 1, "maxLength": smtpMaxTextBytes},
		},
	})
	return encoded
}

func decodeSMTPArguments(raw json.RawMessage) (smtpArguments, error) {
	var args smtpArguments
	if len(raw) == 0 || len(raw) > 256<<10 || strictJSON(raw, &args) != nil || !analyticsNonNullJSON(raw) ||
		len(args.To) < 1 || len(args.To)+len(args.CC)+len(args.BCC) > smtpMaxRecipients ||
		args.Subject == "" || len(args.Subject) > 512 || containsControl(args.Subject) || !utf8.ValidString(args.Subject) ||
		args.Text == "" || len(args.Text) > smtpMaxTextBytes || strings.ContainsRune(args.Text, '\x00') || !utf8.ValidString(args.Text) {
		return args, domain.ErrInvalidArguments
	}
	if args.ConnectionID != "" && !domain.ValidResourceID(args.ConnectionID) {
		return args, domain.ErrInvalidArguments
	}
	seen := map[string]bool{}
	for _, list := range [][]string{args.To, args.CC, args.BCC} {
		for _, address := range list {
			key := strings.ToLower(address)
			if !validSMTPAddress(address) || seen[key] {
				return args, domain.ErrInvalidArguments
			}
			seen[key] = true
		}
	}
	return args, nil
}

func validateSMTPArguments(raw json.RawMessage) error {
	_, err := decodeSMTPArguments(raw)
	return err
}

func validSMTPAddress(value string) bool {
	if value == "" || len(value) > 254 || containsControl(value) || strings.ContainsAny(value, "<> \t") {
		return false
	}
	for _, r := range value {
		if r > 127 {
			return false
		}
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Name != "" || address.Address != value {
		return false
	}
	parts := strings.Split(value, "@")
	return len(parts) == 2 && len(parts[0]) <= 64 && validIMAPHost(parts[1])
}

func validSMTPConfig(config imapConfig) bool {
	return validIMAPHost(config.SMTPHost) && validIMAPText(config.Username, 320) && validSMTPAddress(effectiveSMTPFrom(config)) &&
		((config.SMTPPort == 465 && config.SMTPTLSMode == "implicit_tls") || (config.SMTPPort == 587 && config.SMTPTLSMode == "starttls"))
}

func effectiveSMTPFrom(config imapConfig) string {
	if config.SMTPFrom != "" {
		return config.SMTPFrom
	}
	return config.Username
}

func smtpSendPreview(input domain.Invocation, config imapConfig) (domain.ActionPreview, error) {
	args, err := decodeSMTPArguments(input.Arguments)
	if err != nil || !validSMTPConfig(config) || args.ConnectionID != "" && args.ConnectionID != input.Connection.ID {
		return domain.ActionPreview{}, domain.ErrInvalidArguments
	}
	return domain.ActionPreview{Method: "SMTP", Path: "configured-mailbox/send", Summary: fmt.Sprintf("Send one email from the configured mailbox to %d recipients", len(args.To)+len(args.CC)+len(args.BCC))}, nil
}

// sendSMTP makes exactly one non-retryable delivery attempt. An ambiguous
// response after DATA must never be presented as a safe invitation to retry.
func (a *imapAdapter) sendSMTP(ctx context.Context, input domain.Invocation, config imapConfig) (domain.Result, error) {
	args, err := decodeSMTPArguments(input.Arguments)
	if err != nil || !validSMTPConfig(config) || args.ConnectionID != "" && args.ConnectionID != input.Connection.ID {
		return domain.Result{}, domain.ErrInvalidArguments
	}
	transport := &SMTPTransport{mail: a}
	defer transport.Close()
	return transport.Deliver(ctx, SMTPConfig{Host: config.SMTPHost, Port: config.SMTPPort, TLSMode: config.SMTPTLSMode, Username: config.Username, From: effectiveSMTPFrom(config)}, input.Credential, SMTPMessage{To: args.To, CC: args.CC, BCC: args.BCC, Subject: args.Subject, Text: args.Text})
}

// Extract only a bounded opaque receipt from recognized acceptance syntax. Never
// retain arbitrary server text, and never claim this is the delivered RFC Message-ID.
func smtpAcceptanceID(response string) string {
	if len(response) > 1024 || containsControl(response) {
		return ""
	}
	fields := strings.Fields(response)
	candidate := ""
	if len(fields) == 2 && strings.EqualFold(fields[0], "Ok") {
		candidate = fields[1]
	}
	if len(fields) >= 3 && strings.EqualFold(fields[len(fields)-3], "queued") && strings.EqualFold(fields[len(fields)-2], "as") {
		candidate = fields[len(fields)-1]
	}
	if len(candidate) < 3 || len(candidate) > 200 {
		return ""
	}
	hasDigit := false
	for _, c := range candidate {
		if c >= '0' && c <= '9' {
			hasDigit = true
			continue
		}
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '_' || c == '-' {
			continue
		}
		return ""
	}
	if !hasDigit {
		return ""
	}
	return candidate
}

func buildSMTPMessage(from string, args smtpArguments, now time.Time) ([]byte, string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "", err
	}
	messageID := "<" + hex.EncodeToString(nonce[:]) + "@" + strings.Split(from, "@")[1] + ">"
	var message bytes.Buffer
	fmt.Fprintf(&message, "From: %s\r\n", from)
	writeSMTPAddressHeader(&message, "To", args.To)
	writeSMTPAddressHeader(&message, "Cc", args.CC)
	// Bcc participates only in SMTP RCPT, never in the MIME headers.
	fmt.Fprintf(&message, "Subject: %s\r\nDate: %s\r\nMessage-ID: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n", mime.BEncoding.Encode("UTF-8", args.Subject), now.Format(time.RFC1123Z), messageID)
	text := strings.ReplaceAll(strings.ReplaceAll(args.Text, "\r\n", "\n"), "\r", "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(text, "\n", "\r\n")))
	for len(encoded) > 76 {
		message.WriteString(encoded[:76])
		message.WriteString("\r\n")
		encoded = encoded[76:]
	}
	message.WriteString(encoded)
	message.WriteString("\r\n")
	return message.Bytes(), messageID, nil
}

func writeSMTPAddressHeader(message *bytes.Buffer, name string, addresses []string) {
	if len(addresses) == 0 {
		return
	}
	fmt.Fprintf(message, "%s: %s", name, addresses[0])
	for _, address := range addresses[1:] {
		fmt.Fprintf(message, ",\r\n %s", address)
	}
	message.WriteString("\r\n")
}
