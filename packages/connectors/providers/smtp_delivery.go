package providers

// The host API is independent from IMAP and from the model-facing text-only tool.
// A trusted host supplies already-authorized account settings and a credential
// separately from message arguments. No account, grant or durable receipt is stored here.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const SMTPMaxAttachmentBytes = 10_000_000
const SMTPMaxBodyBytes = 1 << 20

type SMTPConfig struct {
	Host           string  `json:"host"`
	Port           int     `json:"port"`
	TLSMode        string  `json:"tlsMode"`
	Username       string  `json:"username"`
	From           string  `json:"from"`
	FromName       string  `json:"fromName,omitempty"`
	MaxConnections int     `json:"maxConnections,omitempty"`
	MaxPerSecond   float64 `json:"maxPerSecond,omitempty"`
}
type SMTPAttachment struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Content     []byte `json:"content"`
}
type SMTPMessage struct {
	To             []string         `json:"to"`
	CC             []string         `json:"cc,omitempty"`
	BCC            []string         `json:"bcc,omitempty"`
	Subject        string           `json:"subject"`
	Text           string           `json:"text"`
	HTML           string           `json:"html,omitempty"`
	MessageID      string           `json:"messageId,omitempty"`
	ReplyTo        string           `json:"replyTo,omitempty"`
	InReplyTo      string           `json:"inReplyTo,omitempty"`
	References     []string         `json:"references,omitempty"`
	Language       string           `json:"language,omitempty"`
	UnsubscribeURL string           `json:"unsubscribeUrl,omitempty"`
	Attachments    []SMTPAttachment `json:"attachments,omitempty"`
}

// SMTPDeliveryError contains no server response, recipient, body or credential.
// Uncertain means a message may have been accepted and must not be auto-retried.
type SMTPDeliveryError struct {
	Code      string
	Temporary bool
	Uncertain bool
}

func (e *SMTPDeliveryError) Error() string { return e.Code }
func (e *SMTPDeliveryError) Unwrap() error { return &domain.ProviderError{Kind: e.Code, Attempts: 1} }
func smtpFailure(code string, cause error, uncertain bool) error {
	var status *textproto.Error
	temporary := code == "smtp_connection_failed" || code == "smtp_greeting_failed" || code == "smtp_account_capacity"
	if errors.As(cause, &status) {
		temporary = status.Code >= 400 && status.Code < 500
	} else if cause != nil && (code == "smtp_sender_rejected" || code == "smtp_recipient_rejected" || code == "smtp_data_rejected" || code == "smtp_authentication_failed") {
		temporary = true
	}
	return &SMTPDeliveryError{Code: code, Temporary: temporary, Uncertain: uncertain}
}

type smtpSession struct {
	client   *smtp.Client
	socket   net.Conn
	bounded  *imapBoundedConn
	lastUsed time.Time
}
type smtpGate struct {
	idle       []*smtpSession
	closed     bool
	slots      chan struct{}
	mu         sync.Mutex
	next       time.Time
	interval   time.Duration
	lastActive time.Time
}

// SMTPTransport owns only bounded in-process pressure. The host still owns
// durable idempotency, shared budgets, authorizations and outcome reconciliation.
type SMTPTransport struct {
	mail   *imapAdapter
	mu     sync.Mutex
	gates  map[string]*smtpGate
	closed bool
	slots  chan struct{}
}

type SMTPTransportOptions struct{ MaxConcurrentDeliveries int }

func NewSMTPTransport(options ...SMTPTransportOptions) *SMTPTransport {
	limit := 4
	if len(options) > 0 && options[0].MaxConcurrentDeliveries > 0 {
		limit = min(32, options[0].MaxConcurrentDeliveries)
	}
	return &SMTPTransport{mail: newIMAPAdapter(), slots: make(chan struct{}, limit)}
}

// NewSMTPCredential encodes host-held material using the shared mail credential
// contract. The value must never be placed in model/tool message arguments.
func NewSMTPCredential(password string, expiresAt *time.Time) (domain.Credential, error) {
	if !validIMAPText(password, 16384) {
		return domain.Credential{}, domain.ErrInvalidArguments
	}
	b, err := json.Marshal(map[string]string{"smtp_password": password})
	if err != nil {
		return domain.Credential{}, err
	}
	defer clear(b)
	return domain.NewCredential(domain.CredentialAPIToken, "gp_imap_v1."+base64.RawURLEncoding.EncodeToString(b), "", "", "1", expiresAt)
}
func (s *SMTPTransport) acquire(ctx context.Context, c SMTPConfig, credential domain.Credential) (*smtpGate, func(), error) {
	count := c.MaxConnections
	if count == 0 {
		count = 2
	}
	fingerprint := ""
	err := credential.WithSecret(time.Now().UTC(), func(_ domain.CredentialKind, secret []byte) error {
		sum := sha256.Sum256(secret)
		fingerprint = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	keyBytes, _ := json.Marshal([]any{c.Host, c.Port, c.Username, c.TLSMode, fingerprint, count, c.MaxPerSecond})
	sum := sha256.Sum256(keyBytes)
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, smtpFailure("smtp_transport_closed", nil, false)
	}
	if s.gates == nil {
		s.gates = map[string]*smtpGate{}
	}
	gate := s.gates[key]
	if gate == nil {
		for key, old := range s.gates {
			old.mu.Lock()
			idle := len(old.slots) == 0 && time.Since(old.lastActive) > 5*time.Minute
			for _, session := range old.idle {
				if time.Since(session.lastUsed) < 5*time.Minute {
					idle = false
				}
			}
			if idle {
				old.closed = true
				for _, session := range old.idle {
					session.client.Close()
				}
				old.idle = nil
				delete(s.gates, key)
			}
			old.mu.Unlock()
		}
		if len(s.gates) >= 1024 {
			s.mu.Unlock()
			return nil, nil, smtpFailure("smtp_account_capacity", nil, false)
		}
		interval := time.Duration(0)
		if c.MaxPerSecond > 0 {
			interval = time.Duration(float64(time.Second) / c.MaxPerSecond)
		}
		gate = &smtpGate{slots: make(chan struct{}, count), interval: interval, lastActive: time.Now()}
		s.gates[key] = gate
	}
	s.mu.Unlock()
	select {
	case gate.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	release := func() { <-gate.slots }
	gate.mu.Lock()
	closed := gate.closed
	gate.lastActive = time.Now()
	gate.mu.Unlock()
	if closed {
		release()
		return nil, nil, smtpFailure("smtp_transport_closed", nil, false)
	}
	gate.mu.Lock()
	now := time.Now()
	at := gate.next
	if at.Before(now) {
		at = now
	}
	gate.next = at.Add(gate.interval)
	gate.mu.Unlock()
	if delay := time.Until(at); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			release()
			return nil, nil, ctx.Err()
		}
	}
	return gate, release, nil
}

func validSMTPHeaderID(value string) bool {
	if len(value) < 3 || len(value) > 254 || containsControl(value) {
		return false
	}
	if strings.HasPrefix(value, "<") != strings.HasSuffix(value, ">") {
		return false
	}
	value = strings.TrimPrefix(strings.TrimSuffix(value, ">"), "<")
	for _, c := range value {
		if c > 127 {
			return false
		}
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value && strings.Count(value, "@") == 1
}
func validateSMTPEnvelope(c SMTPConfig, m SMTPMessage) error {
	if !validSMTPConfig(imapConfig{SMTPHost: c.Host, SMTPPort: c.Port, SMTPTLSMode: c.TLSMode, Username: c.Username, SMTPFrom: c.From}) ||
		c.MaxConnections < 0 || c.MaxConnections > 32 || c.MaxPerSecond < 0 || c.MaxPerSecond > 1000 || math.IsNaN(c.MaxPerSecond) || math.IsInf(c.MaxPerSecond, 0) ||
		len(c.FromName) > 512 || containsControl(c.FromName) || !utf8.ValidString(c.FromName) ||
		len(m.To) < 1 || len(m.To)+len(m.CC)+len(m.BCC) > smtpMaxRecipients || len(m.Subject) < 1 || len(m.Subject) > 512 || containsControl(m.Subject) || !utf8.ValidString(m.Subject) ||
		len(m.Text) > SMTPMaxBodyBytes || len(m.HTML) > SMTPMaxBodyBytes || m.Text == "" && m.HTML == "" || !utf8.ValidString(m.Text) || !utf8.ValidString(m.HTML) || strings.ContainsRune(m.Text, '\x00') || strings.ContainsRune(m.HTML, '\x00') ||
		len(m.Attachments) > 5 || len(m.References) > 100 {
		return domain.ErrInvalidArguments
	}
	seen := map[string]bool{}
	for _, list := range [][]string{m.To, m.CC, m.BCC} {
		for _, address := range list {
			key := strings.ToLower(address)
			if !validSMTPAddress(address) || seen[key] {
				return domain.ErrInvalidArguments
			}
			seen[key] = true
		}
	}
	if m.MessageID != "" && !validSMTPHeaderID(m.MessageID) || m.InReplyTo != "" && !validSMTPHeaderID(m.InReplyTo) || m.ReplyTo != "" && !validSMTPAddress(m.ReplyTo) {
		return domain.ErrInvalidArguments
	}
	for _, id := range m.References {
		if !validSMTPHeaderID(id) {
			return domain.ErrInvalidArguments
		}
	}
	if len(m.Language) > 100 || containsControl(m.Language) {
		return domain.ErrInvalidArguments
	}
	for _, c := range m.Language {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return domain.ErrInvalidArguments
		}
	}
	if m.UnsubscribeURL != "" {
		u, e := url.Parse(m.UnsubscribeURL)
		if e != nil || len(m.UnsubscribeURL) > 8192 || containsControl(m.UnsubscribeURL) || u.User != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" {
			return domain.ErrInvalidArguments
		}
	}
	total := 0
	for _, a := range m.Attachments {
		total += len(a.Content)
		kind, _, err := mime.ParseMediaType(a.ContentType)
		if len(a.Name) < 1 || len(a.Name) > 256 || containsControl(a.Name) || strings.ContainsAny(a.Name, "/\\") || !utf8.ValidString(a.Name) || len(a.ContentType) > 256 || containsControl(a.ContentType) || err != nil || !strings.Contains(kind, "/") || total > SMTPMaxAttachmentBytes {
			return domain.ErrInvalidArguments
		}
	}
	return nil
}

func smtpHeaderID(id string) string {
	return "<" + strings.TrimPrefix(strings.TrimSuffix(id, ">"), "<") + ">"
}
func smtpBase64(value []byte) []byte {
	raw := base64.StdEncoding.EncodeToString(value)
	var result strings.Builder
	for len(raw) > 76 {
		result.WriteString(raw[:76])
		result.WriteString("\r\n")
		raw = raw[76:]
	}
	result.WriteString(raw)
	result.WriteString("\r\n")
	return []byte(result.String())
}
func smtpTextPart(kind, text string) (textproto.MIMEHeader, []byte) {
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", kind+"; charset=UTF-8")
	h.Set("Content-Transfer-Encoding", "base64")
	normalized := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	return h, smtpBase64([]byte(strings.ReplaceAll(normalized, "\n", "\r\n")))
}
func smtpBody(m SMTPMessage) (string, []byte, error) {
	textHeader, text := smtpTextPart("text/plain", m.Text)
	kind := "text/plain; charset=UTF-8"
	body := text
	if m.HTML != "" {
		var data bytes.Buffer
		multi := multipart.NewWriter(&data)
		for _, part := range []struct{ kind, text string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
			h, b := smtpTextPart(part.kind, part.text)
			writer, err := multi.CreatePart(h)
			if err != nil {
				return "", nil, err
			}
			if _, err = writer.Write(b); err != nil {
				return "", nil, err
			}
		}
		if err := multi.Close(); err != nil {
			return "", nil, err
		}
		kind = "multipart/alternative; boundary=" + multi.Boundary()
		body = data.Bytes()
	}
	if len(m.Attachments) > 0 {
		var data bytes.Buffer
		multi := multipart.NewWriter(&data)
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", kind)
		if m.HTML == "" {
			h = textHeader
		}
		writer, err := multi.CreatePart(h)
		if err != nil {
			return "", nil, err
		}
		if _, err = writer.Write(body); err != nil {
			return "", nil, err
		}
		for _, a := range m.Attachments {
			h = textproto.MIMEHeader{}
			h.Set("Content-Type", a.ContentType)
			h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Name}))
			h.Set("Content-Transfer-Encoding", "base64")
			writer, err = multi.CreatePart(h)
			if err != nil {
				return "", nil, err
			}
			if _, err = writer.Write(smtpBase64(a.Content)); err != nil {
				return "", nil, err
			}
		}
		if err := multi.Close(); err != nil {
			return "", nil, err
		}
		kind = "multipart/mixed; boundary=" + multi.Boundary()
		body = data.Bytes()
	}
	return kind, body, nil
}
func buildSMTPEnvelope(c SMTPConfig, m SMTPMessage, now time.Time) ([]byte, string, error) {
	if err := validateSMTPEnvelope(c, m); err != nil {
		return nil, "", err
	}
	id := m.MessageID
	if id == "" {
		var err error
		_, id, err = buildSMTPMessage(c.From, smtpArguments{To: m.To, CC: m.CC, BCC: m.BCC, Subject: m.Subject, Text: m.Text}, now)
		if err != nil {
			return nil, "", err
		}
	}
	id = smtpHeaderID(id)
	var result bytes.Buffer
	from := c.From
	if c.FromName != "" {
		from = (&mail.Address{Name: c.FromName, Address: c.From}).String()
	}
	fmt.Fprintf(&result, "From: %s\r\n", from)
	writeSMTPAddressHeader(&result, "To", m.To)
	writeSMTPAddressHeader(&result, "Cc", m.CC)
	fmt.Fprintf(&result, "Subject: %s\r\nDate: %s\r\nMessage-ID: %s\r\nMIME-Version: 1.0\r\n", mime.BEncoding.Encode("UTF-8", m.Subject), now.Format(time.RFC1123Z), id)
	if m.ReplyTo != "" {
		fmt.Fprintf(&result, "Reply-To: %s\r\n", m.ReplyTo)
	}
	if m.InReplyTo != "" {
		fmt.Fprintf(&result, "In-Reply-To: %s\r\n", smtpHeaderID(m.InReplyTo))
	}
	if len(m.References) > 0 {
		ids := make([]string, len(m.References))
		for i, v := range m.References {
			ids[i] = smtpHeaderID(v)
		}
		fmt.Fprintf(&result, "References: %s\r\n", strings.Join(ids, " "))
	}
	if m.Language != "" {
		fmt.Fprintf(&result, "Content-Language: %s\r\n", m.Language)
	}
	if m.UnsubscribeURL != "" {
		fmt.Fprintf(&result, "List-Unsubscribe: <%s>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n", m.UnsubscribeURL)
	}
	kind, body, err := smtpBody(m)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(&result, "Content-Type: %s\r\n", kind)
	if len(m.Attachments) == 0 && m.HTML == "" {
		result.WriteString("Content-Transfer-Encoding: base64\r\n")
	}
	result.WriteString("\r\n")
	result.Write(body)
	return result.Bytes(), id, nil
}

// Deliver makes exactly one verified-TLS attempt, returning distinct submission
// and relay receipt identities. It never polls or retries a provider operation.
func (s *SMTPTransport) Deliver(ctx context.Context, c SMTPConfig, credential domain.Credential, m SMTPMessage) (domain.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := validateSMTPEnvelope(c, m); err != nil {
		return domain.Result{}, err
	}
	s.mu.Lock()
	if s.slots == nil {
		s.slots = make(chan struct{}, 4)
	}
	slots := s.slots
	s.mu.Unlock()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return domain.Result{}, smtpFailure("smtp_admission_cancelled", ctx.Err(), false)
	}
	defer func() { <-slots }()
	gate, release, err := s.acquire(ctx, c, credential)
	if err != nil {
		return domain.Result{}, err
	}
	defer release()
	message, id, err := buildSMTPEnvelope(c, m, time.Now().UTC())
	if err != nil {
		return domain.Result{}, err
	}
	defer clear(message)
	return s.deliver(ctx, c, credential, m, message, id, gate)
}
func (s *SMTPTransport) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, g := range s.gates {
		g.mu.Lock()
		g.closed = true
		for _, session := range g.idle {
			session.client.Close()
		}
		g.idle = nil
		g.mu.Unlock()
	}
	return nil
}
func (g *smtpGate) take() *smtpSession {
	g.mu.Lock()
	defer g.mu.Unlock()
	for len(g.idle) > 0 {
		last := len(g.idle) - 1
		session := g.idle[last]
		g.idle = g.idle[:last]
		if !g.closed && time.Since(session.lastUsed) < 5*time.Minute {
			return session
		}
		session.client.Close()
	}
	return nil
}
func (g *smtpGate) put(session *smtpSession) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		session.client.Close()
		return
	}
	session.lastUsed = time.Now()
	g.idle = append(g.idle, session)
}
