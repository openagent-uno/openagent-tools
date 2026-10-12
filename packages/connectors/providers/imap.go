package providers

// Mail access is just-in-time: no polling worker, STORE command, or
// caller-selectable mailbox/host. SMTP sending is a separate publish action.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	imap "github.com/emersion/go-imap"
	imapclient "github.com/emersion/go-imap/client"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const imapMaxMessageBytes = 1 << 20

type imapConfig struct {
	Host        string `json:"imap_host"`
	Port        int    `json:"imap_port"`
	Username    string `json:"username"`
	Mailbox     string `json:"mailbox"`
	TLSMode     string `json:"tls_mode"`
	SMTPHost    string `json:"smtp_host"`
	SMTPPort    int    `json:"smtp_port"`
	SMTPTLSMode string `json:"smtp_tls_mode"`
	SMTPFrom    string `json:"smtp_from,omitempty"`
}

type imapArguments struct {
	ConnectionID string `json:"connection_id,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	BeforeUID    uint32 `json:"before_uid,omitempty"`
	UIDValidity  uint32 `json:"uid_validity,omitempty"`
	UID          uint32 `json:"uid,omitempty"`
}

type imapAdapter struct {
	dial      func(context.Context, string, string) (net.Conn, error)
	tlsConfig func(string) *tls.Config
}

func newIMAPAdapter() *imapAdapter {
	return &imapAdapter{dial: dialPublicIMAP, tlsConfig: func(host string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	}}
}

func (*imapAdapter) Provider() string              { return "imap_smtp" }
func (*imapAdapter) Capability() domain.Capability { return domain.Outreach }
func (*imapAdapter) Operations() []domain.Operation {
	items := []struct{ name, description, schema string }{
		{"outreach.imap.mailboxes.list", "Read the configured mailbox's status; no access to other mailboxes", `{"type":"object","properties":{},"additionalProperties":false}`},
		{"outreach.imap.messages.list", "List recent message headers in the configured mailbox. Follow next_before_uid with uid_validity, including after an empty page, until null", `{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":50},"before_uid":{"type":"integer","minimum":1,"maximum":4294967295},"uid_validity":{"type":"integer","minimum":1,"maximum":4294967295}},"additionalProperties":false}`},
		{"outreach.imap.messages.get", "Read a message as bounded RFC822 text without marking it read; use UID and UIDVALIDITY from list", `{"type":"object","properties":{"uid":{"type":"integer","minimum":1,"maximum":4294967295},"uid_validity":{"type":"integer","minimum":1,"maximum":4294967295}},"required":["uid","uid_validity"],"additionalProperties":false}`},
	}
	result := make([]domain.Operation, 0, len(items))
	for _, item := range items {
		result = append(result, domain.Operation{Name: item.name, Description: item.description, Provider: "imap_smtp", Capability: domain.Outreach, Risk: domain.RiskRead, Mode: domain.OperationTyped, InputSchema: json.RawMessage(item.schema), Retry: domain.RetryPolicy{MaxAttempts: 1}, Preview: domain.ActionPreview{Method: "IMAP", Path: "configured-mailbox", Summary: item.description}})
	}
	result = append(result, domain.Operation{Name: "outreach.imap.messages.send", Description: "Send an email via the configured SMTP account; requires an explicit agent write grant", Provider: "imap_smtp", Capability: domain.Outreach, Risk: domain.RiskPublish, Mode: domain.OperationTyped, InputSchema: smtpSendSchema(), Retry: domain.RetryPolicy{MaxAttempts: 1}, Preview: domain.ActionPreview{Method: "SMTP", Path: "configured-account", Summary: "Send an email"}})
	return result
}

func strictIMAPJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > 16<<10 || raw[0] != '{' {
		return domain.ErrInvalidArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return domain.ErrInvalidArguments
	}
	return nil
}

func (a *imapAdapter) validate(input domain.Invocation) (imapConfig, imapArguments, domain.Operation, error) {
	var config imapConfig
	var args imapArguments
	var operation domain.Operation
	if input.Connection.Provider != a.Provider() || input.Connection.Validate(input.Principal.WorkspaceID, domain.Outreach) != nil {
		return config, args, operation, domain.ErrDenied
	}
	for _, candidate := range a.Operations() {
		if candidate.Name == input.Operation.Name {
			operation = candidate
		}
	}
	if operation.Name == "" {
		return config, args, operation, domain.ErrUnsupported
	}
	if strictIMAPJSON(input.Connection.Config, &config) != nil || !validIMAPHost(config.Host) ||
		!((config.TLSMode == "implicit_tls" && config.Port == 993) || (config.TLSMode == "starttls" && config.Port == 143)) ||
		!validIMAPText(config.Username, 320) || !validIMAPText(config.Mailbox, 512) {
		return config, args, operation, domain.ErrInvalidArguments
	}
	if operation.Name == "outreach.imap.messages.send" {
		if !validIMAPHost(config.SMTPHost) || !((config.SMTPTLSMode == "implicit_tls" && config.SMTPPort == 465) || (config.SMTPTLSMode == "starttls" && config.SMTPPort == 587)) {
			return config, args, operation, domain.ErrInvalidArguments
		}
		return config, args, operation, validateSMTPArguments(input.Arguments)
	}
	if strictIMAPJSON(input.Arguments, &args) != nil {
		return config, args, operation, domain.ErrInvalidArguments
	}
	if args.ConnectionID != "" && args.ConnectionID != input.Connection.ID {
		return config, args, operation, domain.ErrDenied
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(input.Arguments, &fields)
	if _, ok := fields["connection_id"]; ok && args.ConnectionID == "" {
		return config, args, operation, domain.ErrDenied
	}
	delete(fields, "connection_id")
	switch operation.Name {
	case "outreach.imap.mailboxes.list":
		if len(fields) > 0 {
			return config, args, operation, domain.ErrInvalidArguments
		}
	case "outreach.imap.messages.list":
		if _, ok := fields["uid"]; ok {
			return config, args, operation, domain.ErrInvalidArguments
		}
		if _, ok := fields["limit"]; !ok {
			args.Limit = 20
		}
		if args.Limit < 1 || args.Limit > 50 || (args.BeforeUID != 0 && args.UIDValidity == 0) {
			return config, args, operation, domain.ErrInvalidArguments
		}
		for _, key := range []string{"before_uid", "uid_validity"} {
			if value, ok := fields[key]; ok && (string(value) == "null" || string(value) == "0") {
				return config, args, operation, domain.ErrInvalidArguments
			}
		}
	case "outreach.imap.messages.get":
		if args.UID == 0 || args.UIDValidity == 0 || len(fields) != 2 {
			return config, args, operation, domain.ErrInvalidArguments
		}
	}
	return config, args, operation, nil
}

func (a *imapAdapter) Preview(input domain.Invocation) (domain.ActionPreview, error) {
	config, _, operation, err := a.validate(input)
	if err == nil && operation.Name == "outreach.imap.messages.send" {
		return smtpSendPreview(input, config)
	}
	return operation.Preview, err
}

func (a *imapAdapter) Invoke(ctx context.Context, input domain.Invocation) (domain.Result, error) {
	config, args, operation, err := a.validate(input)
	if err != nil {
		return domain.Result{}, err
	}
	if operation.Name == "outreach.imap.messages.send" {
		return a.sendSMTP(ctx, input, config)
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	socket, err := a.dial(ctx, "tcp", net.JoinHostPort(config.Host, strconv.Itoa(config.Port)))
	if err != nil {
		return domain.Result{}, imapFailure("imap_connection_failed")
	}
	defer socket.Close()
	deadline, _ := ctx.Deadline()
	_ = socket.SetDeadline(deadline)
	cancelSocket := socket
	stop := context.AfterFunc(ctx, func() { _ = cancelSocket.Close() })
	defer stop()
	tlsConfig := a.tlsConfig(config.Host).Clone()
	tlsConfig.ServerName = config.Host
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS12)
	secured, err := openSecureIMAPStream(ctx, socket, config.TLSMode, tlsConfig)
	if err != nil {
		return domain.Result{}, imapFailure("imap_tls_failed")
	}
	client, err := imapclient.New(secured)
	if err != nil {
		return domain.Result{}, imapFailure("imap_greeting_failed")
	}
	client.ErrorLog = log.New(io.Discard, "", 0)
	defer client.Terminate()
	var password, smtpPassword string
	err = input.Credential.WithSecret(time.Now().UTC(), func(kind domain.CredentialKind, secret []byte) error {
		if kind != domain.CredentialAPIToken || !bytes.HasPrefix(secret, []byte("gp_imap_v1.")) {
			return domain.ErrDenied
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(secret[len("gp_imap_v1."):]))
		if decodeErr != nil {
			return domain.ErrDenied
		}
		defer clear(decoded)
		var bundle struct {
			Password     string `json:"imap_password"`
			SMTPPassword string `json:"smtp_password,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(decoded))
		decoder.DisallowUnknownFields()
		if len(decoded) > 64<<10 || decoder.Decode(&bundle) != nil || decoder.Decode(new(any)) != io.EOF || !validIMAPText(bundle.Password, 16384) {
			return domain.ErrDenied
		}
		password = bundle.Password
		smtpPassword = bundle.SMTPPassword
		if client.Login(config.Username, password) != nil {
			return errors.Join(domain.ErrProviderPermission, imapFailure("imap_authentication_failed"))
		}
		return nil
	})
	defer func() { password = ""; smtpPassword = "" }()
	if err != nil {
		return domain.Result{}, err
	}
	status, err := client.Select(config.Mailbox, true) // EXAMINE, never SELECT/read-write.
	if err != nil || status == nil || status.UidValidity == 0 {
		return domain.Result{}, imapFailure("imap_mailbox_failed")
	}
	if args.UIDValidity != 0 && args.UIDValidity != status.UidValidity {
		return domain.Result{}, domain.ErrConflict
	}
	var data any
	switch operation.Name {
	case "outreach.imap.mailboxes.list":
		data = map[string]any{"items": []any{map[string]any{"name": config.Mailbox, "messages": status.Messages, "uid_validity": status.UidValidity}}, "scope": "configured_mailbox"}
	case "outreach.imap.messages.list":
		data, err = listIMAPMessages(client, config.Mailbox, status, args)
	case "outreach.imap.messages.get":
		data, err = getIMAPMessage(client, config.Mailbox, status, args.UID)
	}
	if err != nil {
		return domain.Result{}, err
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return domain.Result{}, imapFailure("imap_response_failed")
	}
	encoded = input.Credential.Redact(encoded)
	for _, secret := range []string{password, smtpPassword} {
		if secret == "" {
			continue
		}
		encoded = bytes.ReplaceAll(encoded, []byte(secret), []byte("[REDACTED]"))
		if quoted, e := json.Marshal(secret); e == nil {
			encoded = bytes.ReplaceAll(encoded, quoted[1:len(quoted)-1], []byte("[REDACTED]"))
		}
	}
	if json.Unmarshal(encoded, &data) != nil {
		return domain.Result{}, imapFailure("imap_response_failed")
	}
	return domain.Result{Data: data, Attempts: 1, ResponseBytes: int64(len(encoded)), Metadata: map[string]string{"provider": "imap_smtp", "operation": operation.Name, "read_only": "true"}}, nil
}

func listIMAPMessages(client *imapclient.Client, mailbox string, status *imap.MailboxStatus, args imapArguments) (any, error) {
	result := map[string]any{"items": []any{}, "mailbox": mailbox, "uid_validity": status.UidValidity, "next_before_uid": nil}
	if status.Messages == 0 {
		return result, nil
	}
	if status.UidNext == 0 {
		return nil, imapFailure("imap_uidnext_missing")
	}
	last := status.UidNext - 1
	if args.BeforeUID != 0 && args.BeforeUID <= last {
		last = args.BeforeUID - 1
	}
	if last == 0 {
		return result, nil
	}
	first := uint32(1)
	if last >= 1000 {
		first = last - 999
	}
	criteria := imap.NewSearchCriteria()
	criteria.Uid = new(imap.SeqSet)
	criteria.Uid.AddRange(first, last)
	uids, err := client.UidSearch(criteria)
	if err != nil || len(uids) > 1000 {
		return nil, imapFailure("imap_search_failed")
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
	for i, uid := range uids {
		if uid < first || uid > last || i > 0 && uid == uids[i-1] {
			return nil, imapFailure("imap_search_failed")
		}
	}
	more := len(uids) > args.Limit
	if more {
		uids = uids[:args.Limit]
	}
	items := make([]any, 0, len(uids))
	for _, uid := range uids {
		message, err := fetchIMAPMessage(client, uid, nil)
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"uid": uid, "uid_validity": status.UidValidity, "envelope": message.Envelope, "flags": message.Flags, "size_bytes": message.Size})
	}
	result["items"] = items
	if more {
		result["next_before_uid"] = uids[len(uids)-1]
	} else if first > 1 {
		result["next_before_uid"] = first
	}
	return result, nil
}

func fetchIMAPMessage(client *imapclient.Client, uid uint32, section *imap.BodySectionName) (*imap.Message, error) {
	set := new(imap.SeqSet)
	set.AddNum(uid)
	items := []imap.FetchItem{imap.FetchUid, imap.FetchEnvelope, imap.FetchFlags, imap.FetchRFC822Size}
	if section != nil {
		items = append(items, section.FetchItem())
	}
	messages := make(chan *imap.Message, 1)
	done := make(chan error, 1)
	go func() { done <- client.UidFetch(set, items, messages) }()
	var found *imap.Message
	invalid := false
	for msg := range messages {
		if msg == nil || msg.Uid != uid || found != nil {
			invalid = true
			_ = client.Terminate()
			continue
		}
		found = msg
	}
	if <-done != nil || invalid {
		return nil, imapFailure("imap_fetch_failed")
	}
	if found == nil {
		return nil, domain.ErrNotFound
	}
	return found, nil
}

func getIMAPMessage(client *imapclient.Client, mailbox string, status *imap.MailboxStatus, uid uint32) (any, error) {
	section := &imap.BodySectionName{Peek: true, Partial: []int{0, imapMaxMessageBytes + 1}}
	message, err := fetchIMAPMessage(client, uid, section)
	if err != nil {
		return nil, err
	}
	if message.Size > imapMaxMessageBytes {
		return nil, imapFailure("imap_message_too_large")
	}
	body := message.GetBody(section)
	if body == nil {
		return nil, imapFailure("imap_body_missing")
	}
	raw, err := io.ReadAll(io.LimitReader(body, imapMaxMessageBytes+1))
	defer clear(raw)
	if err != nil || len(raw) > imapMaxMessageBytes || len(raw) == 0 {
		return nil, imapFailure("imap_message_too_large")
	}
	return map[string]any{"mailbox": mailbox, "uid": uid, "uid_validity": status.UidValidity, "envelope": message.Envelope, "size_bytes": message.Size, "rfc822": string(raw)}, nil
}

func imapFailure(kind string) error { return &domain.ProviderError{Kind: kind, Attempts: 1} }
func validIMAPText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}
func validIMAPHost(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

type imapBoundedConn struct {
	net.Conn
	remaining int64
}

func (c *imapBoundedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}

func dialPublicIMAP(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || network != "tcp" || !validIMAPHost(host) || (port != "993" && port != "143" && port != "465" && port != "587") {
		return nil, domain.ErrDenied
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, domain.ErrDenied
	}
	for _, ip := range addresses {
		if !publicIMAPAddress(ip) {
			return nil, domain.ErrDenied
		}
	}
	// Pin the validated address. The TLS peer name remains the original host.
	pinned := net.JoinHostPort(addresses[0].String(), port)
	proxy, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: address}})
	if err != nil {
		return nil, domain.ErrDenied
	}
	if proxy != nil {
		return dialMailProxy(ctx, pinned, proxy)
	}
	return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", pinned)
}

// The deployment-controlled proxy is the only production egress. CONNECT is
// pinned to the already-validated public IP; no credential or mail data is
// transmitted until the subsequent provider TLS handshake succeeds.
func dialMailProxy(ctx context.Context, pinned string, proxy *url.URL) (net.Conn, error) {
	if proxy.Scheme != "http" || proxy.User != nil || proxy.Hostname() == "" || proxy.RawQuery != "" || proxy.Fragment != "" || (proxy.Path != "" && proxy.Path != "/") {
		return nil, domain.ErrDenied
	}
	address := proxy.Host
	if proxy.Port() == "" {
		address = net.JoinHostPort(proxy.Hostname(), "80")
	}
	socket, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, imapFailure("mail_proxy_failed")
	}
	ok := false
	defer func() {
		if !ok {
			_ = socket.Close()
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	if value, has := ctx.Deadline(); has && value.Before(deadline) {
		deadline = value
	}
	_ = socket.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: pinned}, Host: pinned, Header: http.Header{"User-Agent": []string{"OpenAgent-Mail/1"}}}
	if request.Write(socket) != nil {
		return nil, imapFailure("mail_proxy_failed")
	}
	reader := bufio.NewReader(io.LimitReader(socket, 64<<10))
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, imapFailure("mail_proxy_denied")
	}
	buffered := make([]byte, reader.Buffered())
	_, _ = io.ReadFull(reader, buffered)
	_ = socket.SetDeadline(time.Time{})
	ok = true
	return &mailBufferedConn{Conn: socket, reader: io.MultiReader(bytes.NewReader(buffered), socket)}, nil
}

type mailBufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *mailBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func publicIMAPAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:2::/48", "2001:db8::/32", "2001:10::/28", "2001:20::/28", "2002::/16", "3fff::/20", "5f00::/16"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

var _ domain.Adapter = (*imapAdapter)(nil)
var _ domain.ActionPreviewer = (*imapAdapter)(nil)
