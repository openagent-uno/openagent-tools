package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	messageMail "github.com/emersion/go-message/mail"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"io"
	"math"
	"net"
	"net/mail"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func hostMailFixture() (SMTPConfig, SMTPMessage, domain.Credential) {
	cfg := SMTPConfig{Host: "smtp.example.com", Port: 465, TLSMode: "implicit_tls", Username: "account-42", From: "sender@example.com", FromName: "Sender caffè", MaxConnections: 1}
	msg := SMTPMessage{To: []string{"to@example.com"}, BCC: []string{"hidden@example.com"}, Subject: "Caffè", Text: "Plain\nbody", HTML: "<p>HTML</p>", MessageID: "stable@host", InReplyTo: "prior@local-host", References: []string{"root@local-host", "prior@local-host"}, ReplyTo: "replies@example.com", Language: "it", UnsubscribeURL: "https://host.example/unsubscribe/test"}
	b, _ := json.Marshal(map[string]string{"smtp_password": "fixture-password"})
	cred, _ := domain.NewCredential(domain.CredentialAPIToken, "gp_imap_v1."+base64.RawURLEncoding.EncodeToString(b), "", "", "1", nil)
	return cfg, msg, cred
}
func TestSMTPHostMIMEPreservesHTMLAttachmentsHeadersAndPrivateEnvelope(t *testing.T) {
	cfg, msg, _ := hostMailFixture()
	msg.Attachments = []SMTPAttachment{{Name: "caffè.pdf", ContentType: "application/pdf", Content: []byte("PDF fixture")}, {Name: "audio.wav", ContentType: "audio/wav", Content: []byte{1, 2, 3}}, {Name: "video.mp4", ContentType: "video/mp4", Content: []byte{4, 5, 6}}}
	data, id, err := buildSMTPEnvelope(cfg, msg, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if id != "<stable@host>" {
		t.Fatal(id)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("Bcc") != "" || strings.Contains(string(data), "hidden@example.com") || parsed.Header.Get("In-Reply-To") != "<prior@local-host>" || parsed.Header.Get("Content-Language") != "it" || parsed.Header.Get("List-Unsubscribe-Post") != "List-Unsubscribe=One-Click" {
		t.Fatal("lost envelope or thread headers")
	}
	reader, err := messageMail.CreateReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	parts := 0
	attachments := map[string][]byte{}
	texts := map[string]string{}
	for {
		p, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		parts++
		body, err := io.ReadAll(p.Body)
		if err != nil {
			t.Fatal(err)
		}
		switch h := p.Header.(type) {
		case *messageMail.AttachmentHeader:
			name, err := h.Filename()
			if err != nil {
				t.Fatal(err)
			}
			attachments[name] = body
		case *messageMail.InlineHeader:
			kind, _, err := h.ContentType()
			if err != nil {
				t.Fatal(err)
			}
			texts[kind] = string(body)
		}
	}
	if parts != 5 || texts["text/plain"] != "Plain\r\nbody" || texts["text/html"] != "<p>HTML</p>" || !bytes.Equal(attachments["caffè.pdf"], msg.Attachments[0].Content) || !bytes.Equal(attachments["audio.wav"], msg.Attachments[1].Content) || !bytes.Equal(attachments["video.mp4"], msg.Attachments[2].Content) {
		t.Fatalf("MIME roundtrip failed: parts %d texts %v attachments %v", parts, texts, attachments)
	}
}
func TestSMTPHostReusesAuthenticatedTLSWithoutRetryingSubmittedMail(t *testing.T) {
	cfg, msg, cred := hostMailFixture()
	certificate, roots := smtpTestCertificate(t)
	transport := NewSMTPTransport()
	defer transport.Close()
	var dials atomic.Int32
	captures := make(chan smtpCapture, 2)
	transport.mail.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		server.SetDeadline(time.Now().Add(5 * time.Second))
		go func() {
			captures <- serveSMTPFixture(server, certificate, smtpTestOptions{mode: "implicit_tls", acceptanceResponse: "Ok queue-42"})
		}()
		return client, nil
	}
	transport.mail.tlsConfig = func(host string) *tls.Config { return &tls.Config{RootCAs: roots, ServerName: host} }
	for i := 0; i < 2; i++ {
		result, err := transport.Deliver(context.Background(), cfg, cred, msg)
		if err != nil {
			t.Fatal(err)
		}
		if result.ProviderID != "queue-42" || result.Data.(map[string]any)["message_id"] != "<stable@host>" {
			t.Fatalf("incorrect receipt %+v", result)
		}
	}
	transport.Close()
	capture := <-captures
	if capture.err != nil || dials.Load() != 1 || len(capture.messages) != 2 || !capture.authenticated {
		t.Fatalf("no TLS reuse: dials %d messages %d err %v", dials.Load(), len(capture.messages), capture.err)
	}
	if _, err := transport.Deliver(context.Background(), cfg, cred, msg); err == nil || dials.Load() != 1 {
		t.Fatal("closed transport sent")
	}
}
func TestSMTPHostRejectsMalformedHeadersAndAttachmentLimitsBeforeDial(t *testing.T) {
	base, msg, cred := hostMailFixture()
	cases := []func(*SMTPConfig, *SMTPMessage){func(c *SMTPConfig, m *SMTPMessage) { m.Subject = "Injected\r\nBcc: other@example.com" }, func(c *SMTPConfig, m *SMTPMessage) { m.MessageID = "<bad@host" }, func(c *SMTPConfig, m *SMTPMessage) { m.References = []string{"bad\r\nvalue@host"} }, func(c *SMTPConfig, m *SMTPMessage) {
		m.Attachments = []SMTPAttachment{{Name: "../bad", ContentType: "text/plain"}}
	}, func(c *SMTPConfig, m *SMTPMessage) {
		m.Attachments = []SMTPAttachment{{Name: "large.bin", ContentType: "application/octet-stream", Content: make([]byte, SMTPMaxAttachmentBytes+1)}}
	}, func(c *SMTPConfig, m *SMTPMessage) { c.MaxPerSecond = math.NaN() }, func(c *SMTPConfig, m *SMTPMessage) { c.MaxConnections = 33 }}
	for _, mutate := range cases {
		c := base
		m := msg
		mutate(&c, &m)
		transport := NewSMTPTransport()
		var dials int
		transport.mail.dial = func(context.Context, string, string) (net.Conn, error) {
			dials++
			return nil, errors.New("must not dial")
		}
		_, err := transport.Deliver(context.Background(), c, cred, m)
		transport.Close()
		if err == nil || dials != 0 {
			t.Fatal("invalid host message reached transport")
		}
	}
}
