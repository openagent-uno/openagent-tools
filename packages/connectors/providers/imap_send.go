package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
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
	from := effectiveSMTPFrom(config)
	message, messageID, err := buildSMTPMessage(from, args, time.Now().UTC())
	if err != nil {
		return domain.Result{}, imapFailure("smtp_message_failed")
	}
	defer clear(message)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	socket, err := a.dial(ctx, "tcp", net.JoinHostPort(config.SMTPHost, strconv.Itoa(config.SMTPPort)))
	if err != nil {
		return domain.Result{}, imapFailure("smtp_connection_failed")
	}
	defer socket.Close()
	deadline, _ := ctx.Deadline()
	_ = socket.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	tlsConfig := a.tlsConfig(config.SMTPHost).Clone()
	tlsConfig.ServerName = config.SMTPHost
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS12)
	tlsConfig.InsecureSkipVerify = false
	// Bound the underlying socket before TLS wrapping. net/smtp then sees the
	// actual *tls.Conn, so PLAIN authentication cannot mistake TLS for plaintext.
	var transport net.Conn = &imapBoundedConn{Conn: socket, remaining: 4 << 20}
	if config.SMTPTLSMode == "implicit_tls" {
		secure := tls.Client(transport, tlsConfig)
		if secure.HandshakeContext(ctx) != nil {
			return domain.Result{}, imapFailure("smtp_tls_failed")
		}
		transport = secure
	}
	client, err := smtp.NewClient(transport, config.SMTPHost)
	if err != nil {
		return domain.Result{}, imapFailure("smtp_greeting_failed")
	}
	defer client.Close()
	if config.SMTPTLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return domain.Result{}, imapFailure("smtp_tls_required")
		}
		if client.StartTLS(tlsConfig) != nil {
			return domain.Result{}, imapFailure("smtp_tls_failed")
		}
	}
	if state, ok := client.TLSConnectionState(); !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return domain.Result{}, imapFailure("smtp_tls_failed")
	}
	if ok, methods := client.Extension("AUTH"); !ok || !containsString(strings.Fields(methods), "PLAIN") {
		return domain.Result{}, imapFailure("smtp_authentication_unsupported")
	}
	err = input.Credential.WithSecret(time.Now().UTC(), func(kind domain.CredentialKind, secret []byte) error {
		if kind != domain.CredentialAPIToken || !bytes.HasPrefix(secret, []byte("gp_imap_v1.")) {
			return domain.ErrDenied
		}
		decoded, err := base64.RawURLEncoding.DecodeString(string(secret[len("gp_imap_v1."):]))
		if err != nil {
			return domain.ErrDenied
		}
		defer clear(decoded)
		var bundle struct {
			IMAPPassword string `json:"imap_password"`
			SMTPPassword string `json:"smtp_password"`
		}
		if len(decoded) > 64<<10 || strictJSON(decoded, &bundle) != nil || !validIMAPText(bundle.SMTPPassword, 16384) {
			return domain.ErrDenied
		}
		defer func() { bundle.IMAPPassword = ""; bundle.SMTPPassword = "" }()
		if client.Auth(smtp.PlainAuth("", config.Username, bundle.SMTPPassword, config.SMTPHost)) != nil {
			return errors.Join(domain.ErrProviderPermission, imapFailure("smtp_authentication_failed"))
		}
		return nil
	})
	if err != nil {
		return domain.Result{}, err
	}
	if client.Mail(from) != nil {
		return domain.Result{}, imapFailure("smtp_sender_rejected")
	}
	for _, list := range [][]string{args.To, args.CC, args.BCC} {
		for _, recipient := range list {
			if client.Rcpt(recipient) != nil {
				return domain.Result{}, imapFailure("smtp_recipient_rejected")
			}
		}
	}
	writer, err := client.Data()
	if err != nil {
		return domain.Result{}, imapFailure("smtp_data_rejected")
	}
	if _, err := writer.Write(message); err != nil {
		// Do not Close the DATA writer after a failed write: that could submit
		// a truncated message. Closing the socket aborts this SMTP transaction.
		return domain.Result{}, imapFailure("smtp_delivery_unknown")
	}
	if writer.Close() != nil {
		return domain.Result{}, imapFailure("smtp_delivery_unknown")
	}
	return domain.Result{
		Data:       map[string]any{"status": "accepted", "message_id": messageID, "accepted_recipients": len(args.To) + len(args.CC) + len(args.BCC)},
		ProviderID: messageID, Attempts: 1, RequestBytes: int64(len(message)),
		Metadata: map[string]string{"provider": "imap_smtp", "operation": "outreach.imap.messages.send", "delivery": "accepted_by_smtp_server", "retry_safe": "false"},
	}, nil
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
