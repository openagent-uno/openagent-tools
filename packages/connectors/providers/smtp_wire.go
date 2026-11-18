package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

func (s *SMTPTransport) connect(ctx context.Context, config SMTPConfig, credential domain.Credential) (*smtpSession, error) {
	socket, err := s.mail.dial(ctx, "tcp", net.JoinHostPort(config.Host, strconv.Itoa(config.Port)))
	if err != nil {
		return nil, smtpFailure("smtp_connection_failed", err, false)
	}
	ready := false
	defer func() {
		if !ready {
			socket.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	_ = socket.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	tlsConfig := s.mail.tlsConfig(config.Host).Clone()
	tlsConfig.ServerName = config.Host
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS12)
	tlsConfig.InsecureSkipVerify = false
	// Bound the underlying socket before TLS wrapping. net/smtp then sees the
	// actual *tls.Conn, so PLAIN authentication cannot mistake TLS for plaintext.
	bounded := &imapBoundedConn{Conn: socket, remaining: 4 << 20}
	var transport net.Conn = bounded
	if config.TLSMode == "implicit_tls" {
		secure := tls.Client(transport, tlsConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, smtpFailure("smtp_tls_failed", err, false)
		}
		transport = secure
	}
	client, err := smtp.NewClient(transport, config.Host)
	if err != nil {
		return nil, smtpFailure("smtp_greeting_failed", err, false)
	}

	if config.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return nil, smtpFailure("smtp_tls_required", err, false)
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return nil, smtpFailure("smtp_tls_failed", err, false)
		}
	}
	if state, ok := client.TLSConnectionState(); !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return nil, smtpFailure("smtp_tls_failed", err, false)
	}
	if ok, methods := client.Extension("AUTH"); !ok || !containsString(strings.Fields(methods), "PLAIN") {
		return nil, smtpFailure("smtp_authentication_unsupported", err, false)
	}
	err = credential.WithSecret(time.Now().UTC(), func(kind domain.CredentialKind, secret []byte) error {
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
		if err := client.Auth(smtp.PlainAuth("", config.Username, bundle.SMTPPassword, config.Host)); err != nil {
			return errors.Join(domain.ErrProviderPermission, smtpFailure("smtp_authentication_failed", err, false))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ready = true
	return &smtpSession{client: client, socket: socket, bounded: bounded, lastUsed: time.Now()}, nil
}
func (s *SMTPTransport) deliver(ctx context.Context, config SMTPConfig, credential domain.Credential, envelope SMTPMessage, message []byte, messageID string, gate *smtpGate) (domain.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	session := gate.take()
	if session != nil {
		session.bounded.remaining = 4 << 20
		deadline, _ := ctx.Deadline()
		session.socket.SetDeadline(deadline)
		probeSession := session
		stop := context.AfterFunc(ctx, func() { probeSession.socket.Close() })
		err := session.client.Noop()
		stop()
		if err != nil {
			session.client.Close()
			session = nil
		}
	}
	var err error
	if session == nil {
		session, err = s.connect(ctx, config, credential)
		if err != nil {
			return domain.Result{}, err
		}
	}
	client := session.client
	deadline, _ := ctx.Deadline()
	session.socket.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { session.socket.Close() })
	reusable := false
	defer func() {
		stop()
		if reusable && ctx.Err() == nil {
			session.socket.SetDeadline(time.Time{})
			gate.put(session)
		} else {
			client.Close()
		}
	}()
	if err := client.Mail(config.From); err != nil {
		return domain.Result{}, smtpFailure("smtp_sender_rejected", err, false)
	}
	for _, list := range [][]string{envelope.To, envelope.CC, envelope.BCC} {
		for _, recipient := range list {
			if err := client.Rcpt(recipient); err != nil {
				return domain.Result{}, smtpFailure("smtp_recipient_rejected", err, false)
			}
		}
	}
	// net/smtp.Data hides the final acknowledgement. Keep the same public
	// textproto transaction so submission Message-ID and relay receipt stay distinct.
	requestID, err := client.Text.Cmd("DATA")
	if err != nil {
		return domain.Result{}, smtpFailure("smtp_data_rejected", err, false)
	}
	client.Text.StartResponse(requestID)
	_, _, err = client.Text.ReadResponse(354)
	client.Text.EndResponse(requestID)
	if err != nil {
		return domain.Result{}, smtpFailure("smtp_data_rejected", err, false)
	}
	writer := client.Text.DotWriter()
	if _, err := writer.Write(message); err != nil {
		// Do not Close the DATA writer after a failed write: that could submit
		// a truncated message. Closing the socket aborts this SMTP transaction.
		return domain.Result{}, smtpFailure("smtp_delivery_unknown", err, true)
	}
	if err := writer.Close(); err != nil {
		return domain.Result{}, smtpFailure("smtp_delivery_unknown", err, true)
	}
	_, acknowledgement, err := client.Text.ReadResponse(250)
	if err != nil {
		var verdict *textproto.Error
		if errors.As(err, &verdict) && verdict.Code >= 400 && verdict.Code < 600 {
			return domain.Result{}, smtpFailure("smtp_data_refused", err, false)
		}
		return domain.Result{}, smtpFailure("smtp_delivery_unknown", err, true)
	}
	reusable = true
	acceptanceID := smtpAcceptanceID(acknowledgement)
	providerID, idKind := messageID, "submission_message_id"
	data := map[string]any{"status": "accepted", "message_id": messageID, "accepted_recipients": len(envelope.To) + len(envelope.CC) + len(envelope.BCC)}
	if acceptanceID != "" {
		providerID, idKind = acceptanceID, "smtp_acceptance_id"
		data["smtp_acceptance_id"] = acceptanceID
	}
	return domain.Result{
		Data:       data,
		ProviderID: providerID, Attempts: 1, RequestBytes: int64(len(message)),
		Metadata: map[string]string{"provider": "imap_smtp", "operation": "outreach.imap.messages.send", "delivery": "accepted_by_smtp_server", "retry_safe": "false", "provider_id_kind": idKind},
	}, nil
}
