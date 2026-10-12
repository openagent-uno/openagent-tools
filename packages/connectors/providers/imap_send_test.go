package providers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type smtpCapture struct {
	authenticated bool
	startTLS      bool
	auth          string
	sender        string
	recipients    []string
	message       []byte
	err           error
}
type smtpTestOptions struct {
	mode                                                                    string
	username, from                                                          string
	imapPassword, smtpPassword                                              string
	disableSTARTTLS, wrongCertificate, rejectRecipient, disconnectAfterDATA bool
}

func smtpTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smtp.example.com"}, DNSNames: []string{"smtp.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, pool
}

func runSMTPFixture(t *testing.T, options smtpTestOptions) (domain.Result, error, smtpCapture, int) {
	t.Helper()
	certificate, roots := smtpTestCertificate(t)
	adapter := newIMAPAdapter()
	dials := 0
	captured := make(chan smtpCapture, 1)
	adapter.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dials++
		port := "465"
		if options.mode == "starttls" {
			port = "587"
		}
		if network != "tcp" || address != "smtp.example.com:"+port {
			t.Fatalf("wrong SMTP dial: %s %s", network, address)
		}
		client, server := net.Pipe()
		_ = server.SetDeadline(time.Now().Add(5 * time.Second))
		go func() { captured <- serveSMTPFixture(server, certificate, options) }()
		return client, nil
	}
	adapter.tlsConfig = func(host string) *tls.Config {
		if options.wrongCertificate {
			return &tls.Config{RootCAs: x509.NewCertPool(), ServerName: host, MinVersion: tls.VersionTLS12}
		}
		return &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12}
	}
	config := imapConfig{Host: "imap.example.com", Port: 993, TLSMode: "implicit_tls", Username: "sender@example.com", Mailbox: "INBOX", SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPTLSMode: options.mode}
	if options.username != "" {
		config.Username = options.username
	}
	config.SMTPFrom = options.from
	if options.mode == "starttls" {
		config.SMTPPort = 587
	}
	encodedConfig, _ := json.Marshal(config)
	imapPassword, smtpPassword := options.imapPassword, options.smtpPassword
	if imapPassword == "" {
		imapPassword = "imap-only-test"
	}
	if smtpPassword == "" {
		smtpPassword = "smtp-only-test"
	}
	passwordJSON, _ := json.Marshal(map[string]string{"imap_password": imapPassword, "smtp_password": smtpPassword})
	bundle := base64.RawURLEncoding.EncodeToString(passwordJSON)
	cred, err := domain.NewCredential(domain.CredentialAPIToken, "gp_imap_v1."+bundle, "", "", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	var operation domain.Operation
	for _, candidate := range adapter.Operations() {
		if candidate.Name == "outreach.imap.messages.send" {
			operation = candidate
		}
	}
	input := domain.Invocation{
		ID: "send-test", Principal: domain.Principal{WorkspaceID: "ws-1", ActorID: "workspace-agent", Role: "agent"},
		Connection: domain.Connection{ID: "conn-1", WorkspaceID: "ws-1", Provider: "imap_smtp", Capability: domain.Outreach, Config: encodedConfig, Enabled: true},
		Credential: cred, Operation: operation, Arguments: json.RawMessage(`{"connection_id":"conn-1","to":["to@example.com"],"cc":["cc@example.com"],"bcc":["hidden@example.com"],"subject":"Prova caffè","text":"Prima riga\n.\nSeconda riga"}`),
	}
	preview, err := adapter.Preview(input)
	if err != nil || preview.Method != "SMTP" || operation.Risk != domain.RiskPublish || operation.Retry.MaxAttempts != 1 {
		t.Fatalf("preview=%+v operation=%+v err=%v", preview, operation, err)
	}
	result, invokeErr := adapter.Invoke(context.Background(), input)
	select {
	case capture := <-captured:
		return result, invokeErr, capture, dials
	case <-time.After(6 * time.Second):
		t.Fatal("SMTP fixture did not stop")
		return result, invokeErr, smtpCapture{}, dials
	}
}

func serveSMTPFixture(socket net.Conn, certificate tls.Certificate, options smtpTestOptions) (capture smtpCapture) {
	defer socket.Close()
	var conn net.Conn = socket
	secure := options.mode == "implicit_tls"
	if secure {
		tlsSocket := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if err := tlsSocket.Handshake(); err != nil {
			capture.err = err
			return
		}
		conn = tlsSocket
	}
	text := textproto.NewConn(conn)
	if err := text.PrintfLine("220 smtp.example.com ESMTP fixture"); err != nil {
		capture.err = err
		return
	}
	for {
		line, err := text.ReadLine()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				capture.err = err
			}
			return
		}
		switch {
		case strings.HasPrefix(line, "EHLO "):
			response := "250-smtp.example.com\r\n"
			if !secure && !options.disableSTARTTLS {
				response += "250-STARTTLS\r\n"
			}
			response += "250 AUTH PLAIN\r\n"
			_, err = io.WriteString(conn, response)
		case line == "STARTTLS":
			if options.disableSTARTTLS || secure {
				capture.err = errors.New("unexpected STARTTLS")
				return
			}
			if err = text.PrintfLine("220 Ready for TLS"); err != nil {
				capture.err = err
				return
			}
			tlsSocket := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			if err = tlsSocket.Handshake(); err != nil {
				capture.err = err
				return
			}
			conn = tlsSocket
			text = textproto.NewConn(conn)
			secure = true
			capture.startTLS = true
		case strings.HasPrefix(line, "AUTH PLAIN "):
			if !secure {
				capture.err = errors.New("credentials sent without TLS")
				return
			}
			decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
			if decodeErr != nil {
				capture.err = decodeErr
				return
			}
			capture.auth = string(decoded)
			capture.authenticated = true
			err = text.PrintfLine("235 Authenticated")
		case strings.HasPrefix(line, "MAIL FROM:"):
			capture.sender = line
			err = text.PrintfLine("250 Sender accepted")
		case strings.HasPrefix(line, "RCPT TO:"):
			capture.recipients = append(capture.recipients, line)
			if options.rejectRecipient {
				err = text.PrintfLine("550 recipient rejected smtp-only-test")
			} else {
				err = text.PrintfLine("250 Recipient accepted")
			}
		case line == "DATA":
			if err = text.PrintfLine("354 End with dot"); err != nil {
				capture.err = err
				return
			}
			capture.message, err = io.ReadAll(text.DotReader())
			if err != nil {
				capture.err = err
				return
			}
			if options.disconnectAfterDATA {
				return
			}
			err = text.PrintfLine("250 Accepted message")
		case line == "QUIT":
			_ = text.PrintfLine("221 Bye")
			return
		default:
			capture.err = fmt.Errorf("unexpected SMTP command %q", line)
			return
		}
		if err != nil {
			capture.err = err
			return
		}
	}
}

func TestSMTPSendsWithVerifiedTLSAndNoBccHeader(t *testing.T) {
	for _, mode := range []string{"implicit_tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			result, err, capture, dials := runSMTPFixture(t, smtpTestOptions{mode: mode})
			if err != nil || capture.err != nil || dials != 1 || !capture.authenticated {
				t.Fatalf("result=%+v err=%v capture=%+v dials=%d", result, err, capture, dials)
			}
			if capture.auth != "\x00sender@example.com\x00smtp-only-test" || strings.Contains(capture.auth, "imap-only-test") {
				t.Fatalf("wrong SMTP credential: %q", capture.auth)
			}
			if capture.startTLS != (mode == "starttls") || capture.sender != "MAIL FROM:<sender@example.com>" || len(capture.recipients) != 3 {
				t.Fatalf("unexpected SMTP envelope: %+v", capture)
			}
			message, err := mail.ReadMessage(strings.NewReader(string(capture.message)))
			if err != nil {
				t.Fatal(err)
			}
			if message.Header.Get("Bcc") != "" || strings.Contains(string(capture.message), "hidden@example.com") {
				t.Fatal("Bcc leaked into MIME headers")
			}
			subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
			if err != nil || subject != "Prova caffè" {
				t.Fatalf("subject=%q err=%v", subject, err)
			}
			body, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, message.Body))
			if err != nil || string(body) != "Prima riga\r\n.\r\nSeconda riga" {
				t.Fatalf("body=%q err=%v", body, err)
			}
			data, _ := result.Data.(map[string]any)
			if data["status"] != "accepted" || data["accepted_recipients"] != 3 || result.Attempts != 1 || result.ProviderID != message.Header.Get("Message-ID") {
				t.Fatalf("result=%+v", result)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "smtp-only-test") || strings.Contains(string(encoded), "Prima riga") {
				t.Fatal("secret or message body leaked into result")
			}
		})
	}
}

func TestSMTPCredentialBoundsMatchOnboarding(t *testing.T) {
	for _, mode := range []string{"implicit_tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			password := strings.Repeat("s", 16384)
			result, err, capture, dials := runSMTPFixture(t, smtpTestOptions{mode: mode, imapPassword: strings.Repeat("i", 16384), smtpPassword: password})
			if err != nil || capture.err != nil || dials != 1 || result.Attempts != 1 || capture.auth != "\x00sender@example.com\x00"+password {
				t.Fatalf("maximum-length credential failed: err=%v serverErr=%v dials=%d authenticated=%v", err, capture.err, dials, capture.authenticated)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), strings.Repeat("s", 100)) || strings.Contains(string(encoded), strings.Repeat("i", 100)) {
				t.Fatal("long credential leaked into result")
			}
		})
	}
	_, err, capture, _ := runSMTPFixture(t, smtpTestOptions{mode: "implicit_tls", smtpPassword: strings.Repeat("s", 16385)})
	if !errors.Is(err, domain.ErrDenied) || capture.authenticated || len(capture.message) != 0 {
		t.Fatal("over-limit SMTP password was used")
	}
}

func TestSMTPConfiguredSenderIsSeparateFromLoginUsername(t *testing.T) {
	for _, mode := range []string{"implicit_tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			result, err, capture, dials := runSMTPFixture(t, smtpTestOptions{mode: mode, username: "mail-account-42", from: "support@example.com"})
			if err != nil || capture.err != nil || dials != 1 || result.Attempts != 1 {
				t.Fatalf("result=%+v err=%v capture=%+v dials=%d", result, err, capture, dials)
			}
			if capture.auth != "\x00mail-account-42\x00smtp-only-test" || capture.sender != "MAIL FROM:<support@example.com>" {
				t.Fatalf("login and sender mixed: auth=%q sender=%q", capture.auth, capture.sender)
			}
			message, err := mail.ReadMessage(strings.NewReader(string(capture.message)))
			if err != nil || message.Header.Get("From") != "support@example.com" || strings.Contains(string(capture.message), "mail-account-42") {
				t.Fatalf("configured sender missing or login leaked: message=%q err=%v", capture.message, err)
			}
		})
	}
}

func TestSMTPFailClosedBeforeAuthAndNeverRetriesAmbiguousDATA(t *testing.T) {
	cases := []struct {
		name                  string
		options               smtpTestOptions
		wantKind              string
		wantAuth, wantMessage bool
	}{
		{"no STARTTLS", smtpTestOptions{mode: "starttls", disableSTARTTLS: true}, "smtp_tls_required", false, false},
		{"invalid certificate", smtpTestOptions{mode: "implicit_tls", wrongCertificate: true}, "smtp_tls_failed", false, false},
		{"rejected recipient", smtpTestOptions{mode: "implicit_tls", rejectRecipient: true}, "smtp_recipient_rejected", true, false},
		{"lost DATA acknowledgement", smtpTestOptions{mode: "implicit_tls", disconnectAfterDATA: true}, "smtp_delivery_unknown", true, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err, capture, dials := runSMTPFixture(t, test.options)
			var providerErr *domain.ProviderError
			if !errors.As(err, &providerErr) || providerErr.Kind != test.wantKind || providerErr.Attempts != 1 || dials != 1 {
				t.Fatalf("err=%v dials=%d", err, dials)
			}
			if capture.authenticated != test.wantAuth || (len(capture.message) > 0) != test.wantMessage {
				t.Fatalf("unexpected SMTP progression: %+v", capture)
			}
			if strings.Contains(err.Error(), "smtp-only-test") {
				t.Fatal("provider text leaked credential into public error")
			}
		})
	}
}

func TestSMTPRejectsCallerHeadersEnvelopeInjectionAndBounds(t *testing.T) {
	base := map[string]any{"to": []string{"to@example.com"}, "subject": "Test", "text": "Hello"}
	cases := []map[string]any{
		{"from": "attacker@example.com"}, {"smtp_from": "attacker@example.com"}, {"headers": map[string]string{"X-Test": "x"}}, {"raw": "fake"}, {"html": "<b>fake</b>"},
		{"to": []string{"victim@example.com\r\nBcc:evil@example.com"}}, {"to": []string{"Display <to@example.com>"}},
		{"to": []string{"to@example.com"}, "bcc": []string{"to@example.com"}}, {"to": []string{}}, {"cc": nil},
		{"subject": "Test\r\nBcc:evil@example.com"}, {"subject": ""}, {"subject": strings.Repeat("a", 513)},
		{"text": ""}, {"text": strings.Repeat("a", smtpMaxTextBytes+1)}, {"text": "x\x00y"},
	}
	for index, changes := range cases {
		args := map[string]any{}
		for key, value := range base {
			args[key] = value
		}
		for key, value := range changes {
			args[key] = value
		}
		encoded, _ := json.Marshal(args)
		if err := validateSMTPArguments(encoded); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("case %d accepted: %s err=%v", index, encoded, err)
		}
	}
	tooMany := make([]string, 51)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("person%d@example.com", index)
	}
	base["to"] = tooMany
	encoded, _ := json.Marshal(base)
	if validateSMTPArguments(encoded) == nil {
		t.Fatal("accepted more than 50 recipients")
	}
	for _, config := range []imapConfig{
		{SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPTLSMode: "implicit_tls", Username: "mail-account-42"},
		{SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPTLSMode: "implicit_tls", Username: "sender@example.com", SMTPFrom: "not-an-email"},
		{SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPTLSMode: "implicit_tls", Username: "mail-account-42", SMTPFrom: "support@example.com\r\nBcc:evil@example.com"},
		{SMTPHost: "smtp.example.com", SMTPPort: 25, SMTPTLSMode: "starttls", Username: "sender@example.com"},
		{SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPTLSMode: "plain", Username: "sender@example.com"},
		{SMTPHost: "127.0.0.1", SMTPPort: 465, SMTPTLSMode: "implicit_tls", Username: "sender@example.com"},
		{SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPTLSMode: "implicit_tls", Username: "sender\r\nBcc:evil@example.com"},
	} {
		if validSMTPConfig(config) {
			t.Fatalf("unsafe SMTP config accepted: %+v", config)
		}
	}
}
