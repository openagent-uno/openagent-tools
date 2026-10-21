package slackchannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const clientDocumentLimit = 1 << 20
const clientTimeout = 25 * time.Second

var ErrClientResponse = errors.New("invalid Slack channel service response")
var ErrClientTransport = errors.New("Slack channel service transport unavailable")

// Client uses an already registered host identity. It never registers a host,
// imports Slack credentials, follows redirects or retries an operation itself.
// Configure its exported fields before concurrent use.
type Client struct {
	Origin        string
	Identity      auth.Identity
	HTTP          *http.Client
	AllowLoopback bool
}

// Session is a short-lived binding-scoped service credential, not a Slack bot
// token. Deliver it to an SDK child through a private pipe, never argv or logs.
type Session struct {
	Protocol  string    `json:"protocol"`
	BindingID string    `json:"binding_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (Session) String() string   { return "[redacted Slack channel session]" }
func (Session) GoString() string { return "[redacted Slack channel session]" }

// RemoteError contains only an HTTP status and a closed diagnostic code.
type RemoteError struct {
	Status int
	Code   string
}

func (e *RemoteError) Error() string {
	return "Slack channel service request failed: " + clientSafeCode(e.Code)
}
func (e *RemoteError) String() string   { return e.Error() }
func (e *RemoteError) GoString() string { return e.Error() }

func clientSafeCode(code string) string {
	switch code {
	case "invalid_request", "denied", "not_found", "binding_not_found", "binding_not_ready",
		"binding_revoked", "binding_conflict", "invalid_installation_signature", "invalid_recipient",
		"authorization_not_ready", "authorization_expired", "provider_exchange_failed", "provider_refresh_failed",
		"grant_revoked", "rate_limited", "request_too_large", "vault_unavailable", "busy":
		return code
	}
	return "request_failed"
}

func clientText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func clientRecipient(value Recipient) bool {
	return clientText(value.WorkspaceID, 128) && clientText(value.SubjectID, 256) && clientText(value.AgentID, 256)
}

func (c *Client) clientOrigin() (*url.URL, error) {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" ||
		(u.Scheme != "https" && !(c.AllowLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) {
		return nil, auth.ErrDenied
	}
	return u, nil
}

// Reject duplicate object keys as well as unknown fields and trailing values.
func decodeClientResponse(data []byte, target any) error {
	if !utf8.Valid(data) {
		return ErrClientResponse
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return ErrClientResponse
		}
		token, err := d.Token()
		if err != nil {
			return ErrClientResponse
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return ErrClientResponse
					}
					seen[name] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return ErrClientResponse
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return ErrClientResponse
				}
			default:
				return ErrClientResponse
			}
		}
		return nil
	}
	if value(0) != nil {
		return ErrClientResponse
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrClientResponse
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrClientResponse
	}
	return nil
}

func (c *Client) call(ctx context.Context, method, path string, input, output any) error {
	if _, err := c.clientOrigin(); err != nil || len(c.Identity.PrivateKey) != ed25519.PrivateKeySize {
		return auth.ErrDenied
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil || len(body) > clientDocumentLimit {
			return auth.ErrDenied
		}
	}
	ctx, cancel := context.WithTimeout(ctx, clientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.Origin+path, bytes.NewReader(body))
	if err != nil {
		return auth.ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	c.Identity.Sign(req, body)
	httpClient := http.Client{Timeout: clientTimeout}
	if c.HTTP != nil {
		httpClient = *c.HTTP
	}
	if httpClient.Timeout <= 0 || httpClient.Timeout > clientTimeout {
		httpClient.Timeout = clientTimeout
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		return ErrClientTransport
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, clientDocumentLimit+1))
	if err != nil || len(data) > clientDocumentLimit {
		return ErrClientResponse
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		failure := struct {
			Error string `json:"error"`
		}{}
		code := "request_failed"
		if decodeClientResponse(data, &failure) == nil {
			code = clientSafeCode(failure.Error)
		}
		return &RemoteError{Status: response.StatusCode, Code: code}
	}
	if output == nil {
		return nil
	}
	return decodeClientResponse(data, output)
}

func (c *Client) validateBinding(binding Binding, id string) error {
	if !domain.ValidResourceID(binding.ID) || id != "" && binding.ID != id || binding.Installation != c.Identity.ID() ||
		!clientRecipient(binding.Recipient) || !clientText(binding.AgentLabel, 256) || !domain.ValidResourceID(binding.TeamID) ||
		!domain.ValidResourceID(binding.ChannelID) || !clientText(binding.Status, 64) {
		return ErrClientResponse
	}
	if binding.AuthorizationURL != "" {
		u, err := url.Parse(binding.AuthorizationURL)
		loopback := err == nil && c.AllowLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Scheme != "https" && !loopback {
			return ErrClientResponse
		}
	}
	return nil
}

func (c *Client) Start(ctx context.Context, request StartRequest) (Binding, error) {
	if !clientRecipient(request.Recipient) || !clientText(request.AgentLabel, 256) || !domain.ValidResourceID(request.TeamID) || !domain.ValidResourceID(request.ChannelID) {
		return Binding{}, auth.ErrDenied
	}
	var binding Binding
	if err := c.call(ctx, http.MethodPost, Prefix+"/bindings", request, &binding); err != nil {
		return Binding{}, err
	}
	if c.validateBinding(binding, "") != nil || binding.Recipient != request.Recipient || binding.AgentLabel != request.AgentLabel || binding.TeamID != request.TeamID || binding.ChannelID != request.ChannelID {
		return Binding{}, ErrClientResponse
	}
	return binding, nil
}

func (c *Client) bindingAction(ctx context.Context, id, action string) (Binding, error) {
	if !domain.ValidResourceID(id) {
		return Binding{}, auth.ErrDenied
	}
	method, path := http.MethodGet, Prefix+"/bindings/"+url.PathEscape(id)
	var body any
	if action != "" {
		method, path, body = http.MethodPost, path+"/"+action, struct{}{}
	}
	var binding Binding
	if err := c.call(ctx, method, path, body, &binding); err != nil {
		return Binding{}, err
	}
	if err := c.validateBinding(binding, id); err != nil {
		return Binding{}, err
	}
	return binding, nil
}
func (c *Client) Status(ctx context.Context, id string) (Binding, error) {
	return c.bindingAction(ctx, id, "")
}
func (c *Client) Activate(ctx context.Context, id string) (Binding, error) {
	return c.bindingAction(ctx, id, "activate")
}
func (c *Client) Session(ctx context.Context, id string) (Session, error) {
	if !domain.ValidResourceID(id) {
		return Session{}, auth.ErrDenied
	}
	var session Session
	if err := c.call(ctx, http.MethodPost, Prefix+"/bindings/"+url.PathEscape(id)+"/session", struct{}{}, &session); err != nil {
		return Session{}, err
	}
	now := time.Now()
	if session.Protocol != Protocol || session.BindingID != id || !clientText(session.Token, 16384) || !session.ExpiresAt.After(now) || session.ExpiresAt.After(now.Add(8*time.Hour+time.Minute)) {
		return Session{}, ErrClientResponse
	}
	return session, nil
}
func (c *Client) Disconnect(ctx context.Context, id string) error {
	if !domain.ValidResourceID(id) {
		return auth.ErrDenied
	}
	return c.call(ctx, http.MethodDelete, Prefix+"/bindings/"+url.PathEscape(id), nil, nil)
}
