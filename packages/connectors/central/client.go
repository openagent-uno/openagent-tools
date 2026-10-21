package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// Configure before concurrent use; a Client must not be copied after first use.
type Client struct {
	Origin        string
	Identity      auth.Identity
	HTTP          *http.Client
	AllowLoopback bool
	TrustKeys     map[string]ed25519.PublicKey
	mu            sync.Mutex
	revision      uint64
	catalogHash   [32]byte
}

// RemoteError deliberately excludes server messages and response bodies.
type RemoteError struct {
	Status int
	Code   string
}

func (e *RemoteError) Error() string { return "central connector request failed: " + e.Code }

func (c *Client) call(ctx context.Context, method, path string, input, output any, signed bool) error {
	origin, err := url.Parse(c.Origin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Scheme != "https" && !(c.AllowLoopback && origin.Scheme == "http" && (origin.Hostname() == "127.0.0.1" || origin.Hostname() == "localhost"))) {
		return auth.ErrDenied
	}
	if signed && len(c.Identity.PrivateKey) != ed25519.PrivateKeySize {
		return auth.ErrDenied
	}
	var body []byte
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil || len(body) > maxDocument {
			return auth.ErrDenied
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.Origin+path, bytes.NewReader(body))
	if err != nil {
		return auth.ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	if signed {
		c.Identity.Sign(req, body)
	}
	client := http.Client{}
	if c.HTTP != nil {
		client = *c.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return errors.New("central connector transport unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDocument+1))
	if err != nil || len(data) > maxDocument {
		return ErrInvalidResponse
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		code := "request_failed"
		if strictJSON(data, &failure) == nil && safeErrorCode(failure.Error) {
			code = failure.Error
		}
		return &RemoteError{Status: response.StatusCode, Code: code}
	}
	if output == nil {
		return nil
	}
	return strictJSON(data, output)
}

func safeErrorCode(code string) bool {
	// Never forward an arbitrary server message (which may contain credentials).
	switch code {
	case "invalid_request", "not_found", "denied", "invalid_installation_signature", "catalog_changed", "contract_mismatch",
		"authorization_not_ready", "authorization_expired", "provider_not_configured", "provider_exchange_failed",
		"provider_refresh_failed", "token_grant_revoked", "grant_revoked", "grant_changed", "rate_limited",
		"approval_required", "invocation_conflict", "outcome_unknown", "unsupported_protocol", "connection_unavailable",
		"request_too_large", "busy", "connection_not_admitted", "invocation_not_admitted", "invalid_recipient",
		"connection_not_found", "invocation_not_found", "vault_unavailable", "connection_not_ready":
		return true
	}
	return false
}

func (c *Client) Catalog(ctx context.Context) (Catalog, error) {
	var envelope SignedCatalog
	if err := c.call(ctx, http.MethodGet, "/v1/registry/catalog", nil, &envelope, false); err != nil {
		return Catalog{}, err
	}
	key := c.TrustKeys[envelope.KeyID]
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !domain.ValidResourceID(envelope.KeyID) || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, envelope.Payload, signature) {
		return Catalog{}, ErrInvalidCatalog
	}
	var catalog Catalog
	if strictJSON(envelope.Payload, &catalog) != nil || catalog.Protocol != Protocol || catalog.Revision == 0 ||
		catalog.IssuedAt.IsZero() || catalog.IssuedAt.After(time.Now().Add(time.Minute)) || !catalog.ExpiresAt.After(time.Now()) ||
		!catalog.ExpiresAt.After(catalog.IssuedAt) || catalog.ExpiresAt.Sub(catalog.IssuedAt) > 24*time.Hour || validateDescriptors(catalog.Connectors) != nil {
		return Catalog{}, ErrInvalidCatalog
	}
	// Freshly signed timestamps can change without a registry revision. Every
	// descriptor field, including availability/presentation, remains drift-bound.
	content, _ := json.Marshal(struct {
		Protocol   string       `json:"protocol"`
		Revision   uint64       `json:"revision"`
		Connectors []Descriptor `json:"connectors"`
	}{catalog.Protocol, catalog.Revision, catalog.Connectors})
	digest := sha256.Sum256(content)
	c.mu.Lock()
	defer c.mu.Unlock()
	if catalog.Revision < c.revision || catalog.Revision == c.revision && digest != c.catalogHash {
		return Catalog{}, ErrCatalogRollback
	}
	c.revision, c.catalogHash = catalog.Revision, digest
	return catalog, nil
}

func validRecipient(r Recipient) bool {
	return r.WorkspaceID != "" && r.SubjectID != "" && strings.TrimSpace(r.WorkspaceID) == r.WorkspaceID &&
		strings.TrimSpace(r.SubjectID) == r.SubjectID && validText(r.WorkspaceID, 128) && validText(r.SubjectID, 256)
}

func validateConnection(value Connection, recipient Recipient, id string, loopback ...bool) error {
	if value.Protocol != Protocol || !domain.ValidResourceID(value.ID) || id != "" && value.ID != id ||
		value.Recipient != recipient || !domain.ValidResourceID(value.CatalogID) || !validHash(value.ContractSHA256) ||
		!validNames(value.Operations) {
		return ErrInvalidResponse
	}
	if value.Status != "pending" && value.Status != "connected" && value.Status != "disconnected" && value.Status != "failed" && value.Status != "revoked" {
		return ErrInvalidResponse
	}
	if value.Status == "connected" && value.GrantRevision == 0 {
		return ErrInvalidResponse
	}
	if value.AuthorizationURL != "" {
		u, err := url.Parse(value.AuthorizationURL)
		fixture := err == nil && len(loopback) == 1 && loopback[0] && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")
		if err != nil || u.Scheme != "https" && !fixture || u.Host == "" || u.User != nil || u.Fragment != "" {
			return ErrInvalidResponse
		}
	}
	return nil
}

func validNames(names []string) bool {
	if len(names) == 0 || len(names) > 2048 {
		return false
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || !validText(name, 256) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

func (c *Client) Create(ctx context.Context, request CreateRequest) (Connection, error) {
	if !domain.ValidResourceID(request.CatalogID) || !validHash(request.ContractSHA256) || !validRecipient(request.Recipient) || !validNames(request.Operations) {
		return Connection{}, auth.ErrDenied
	}
	if len(request.Config) > 256<<10 {
		return Connection{}, auth.ErrDenied
	}
	if len(request.Config) != 0 {
		var config map[string]any
		if strictJSON(request.Config, &config) != nil || config == nil || hasCredentialKeys(config) {
			return Connection{}, auth.ErrDenied
		}
	}
	var connection Connection
	if err := c.call(ctx, http.MethodPost, "/v1/execution/connections", request, &connection, true); err != nil {
		return Connection{}, err
	}
	if validateConnection(connection, request.Recipient, "", c.AllowLoopback) != nil || connection.CatalogID != request.CatalogID || connection.ContractSHA256 != request.ContractSHA256 {
		return Connection{}, ErrInvalidResponse
	}
	// The service may narrow the request, never silently expand the local grant.
	allowed := map[string]bool{}
	for _, op := range request.Operations {
		allowed[op] = true
	}
	for _, op := range connection.Operations {
		if !allowed[op] {
			return Connection{}, ErrInvalidResponse
		}
	}
	return connection, nil
}

func (c *Client) connectionAction(ctx context.Context, id string, recipient Recipient, action string) (Connection, error) {
	if !domain.ValidResourceID(id) || !validRecipient(recipient) {
		return Connection{}, auth.ErrDenied
	}
	var connection Connection
	request := struct {
		Recipient Recipient `json:"recipient"`
	}{recipient}
	err := c.call(ctx, http.MethodPost, "/v1/execution/connections/"+url.PathEscape(id)+"/"+action, request, &connection, true)
	if err != nil {
		return Connection{}, err
	}
	if err := validateConnection(connection, recipient, id, c.AllowLoopback); err != nil {
		return Connection{}, err
	}
	return connection, nil
}

func (c *Client) Connection(ctx context.Context, id string, r Recipient) (Connection, error) {
	return c.connectionAction(ctx, id, r, "status")
}
func (c *Client) Complete(ctx context.Context, id string, r Recipient) (Connection, error) {
	return c.connectionAction(ctx, id, r, "complete")
}
func (c *Client) Refresh(ctx context.Context, id string, r Recipient) (Connection, error) {
	return c.connectionAction(ctx, id, r, "refresh")
}
func (c *Client) Disconnect(ctx context.Context, id string, r Recipient) (Connection, error) {
	return c.connectionAction(ctx, id, r, "disconnect")
}

func validateInvocation(result InvocationResult, id string) error {
	if result.InvocationID != id || (result.Status != "pending" && result.Status != "running" && result.Status != "succeeded" && result.Status != "failed" && result.Status != "outcome_unknown") {
		return ErrInvalidResponse
	}
	if result.Result != nil && (result.Status != "succeeded" || !result.ResultAvailable) || result.ResultAvailable && result.Result == nil {
		return ErrInvalidResponse
	}
	return nil
}

func hasCredentialKeys(value any) bool {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "secret") ||
				strings.Contains(strings.ToLower(key), "password") || strings.Contains(strings.ToLower(key), "credential") {
				return true
			}
			switch strings.ToLower(key) {
			case "token", "access_token", "refresh_token", "client_secret", "secret", "password", "authorization", "credential", "credentials", "api_key", "apikey":
				return true
			}
			if hasCredentialKeys(child) {
				return true
			}
		}
	case []any:
		for _, child := range node {
			if hasCredentialKeys(child) {
				return true
			}
		}
	}
	return false
}

func (c *Client) Invoke(ctx context.Context, id string, request InvokeRequest) (InvocationResult, error) {
	if !domain.ValidResourceID(id) || !domain.ValidResourceID(request.InvocationID) || !validRecipient(request.Recipient) ||
		!validHash(request.ContractSHA256) || request.GrantRevision == 0 || !validNames([]string{request.Operation}) ||
		len(request.Arguments) > 256<<10 || !validText(request.ApprovalID, 256) {
		return InvocationResult{}, auth.ErrDenied
	}
	var arguments map[string]json.RawMessage
	if strictJSON(request.Arguments, &arguments) != nil || arguments == nil {
		return InvocationResult{}, auth.ErrDenied
	}
	var result InvocationResult
	err := c.call(ctx, http.MethodPost, "/v1/execution/connections/"+url.PathEscape(id)+"/invoke", request, &result, true)
	if err != nil {
		return InvocationResult{}, err
	}
	if err := validateInvocation(result, request.InvocationID); err != nil {
		return InvocationResult{}, err
	}
	return result, nil
}

func (c *Client) Invocation(ctx context.Context, id, invocationID string, recipient Recipient) (InvocationResult, error) {
	if !domain.ValidResourceID(id) || !domain.ValidResourceID(invocationID) || !validRecipient(recipient) {
		return InvocationResult{}, auth.ErrDenied
	}
	var result InvocationResult
	request := struct {
		Recipient Recipient `json:"recipient"`
	}{recipient}
	err := c.call(ctx, http.MethodPost, "/v1/execution/connections/"+url.PathEscape(id)+"/invocations/"+url.PathEscape(invocationID), request, &result, true)
	if err != nil {
		return InvocationResult{}, err
	}
	if err := validateInvocation(result, invocationID); err != nil {
		return InvocationResult{}, err
	}
	return result, nil
}
