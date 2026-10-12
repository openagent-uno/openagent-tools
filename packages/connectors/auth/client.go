package auth

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// LoadIdentity persists installation keys only on the consuming product's server.
func LoadIdentity(path, product, name string) (Identity, error) {
	type wire struct {
		Private    string `json:"private_key"`
		Encryption string `json:"encryption_key"`
		Product    string `json:"product"`
		Name       string `json:"name"`
	}
	if data, err := os.ReadFile(path); err == nil {
		var value wire
		if json.Unmarshal(data, &value) != nil {
			return Identity{}, ErrDenied
		}
		private, err := encoding.DecodeString(value.Private)
		if err != nil || len(private) != ed25519.PrivateKeySize {
			return Identity{}, ErrDenied
		}
		keyBytes, err := encoding.DecodeString(value.Encryption)
		if err != nil {
			return Identity{}, ErrDenied
		}
		key, err := ecdh.X25519().NewPrivateKey(keyBytes)
		if err != nil {
			return Identity{}, ErrDenied
		}
		return Identity{PrivateKey: private, EncryptionKey: key, Product: value.Product, Name: value.Name}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, err
	}
	identity, err := NewIdentity(product, name)
	if err != nil {
		return identity, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return Identity{}, err
	}
	data, _ := json.Marshal(wire{Private: encoding.EncodeToString(identity.PrivateKey), Encryption: encoding.EncodeToString(identity.EncryptionKey.Bytes()), Product: product, Name: name})
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return LoadIdentity(path, product, name)
	}
	if err != nil {
		return Identity{}, err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	return identity, err
}

type Client struct {
	Origin        string
	Identity      Identity
	HTTP          *http.Client
	AllowLoopback bool
}
type RemoteError struct {
	Status int
	Code   string
}

func (e *RemoteError) Error() string { return "connector authentication service: " + e.Code }
func (c *Client) call(ctx context.Context, method, path string, input, output any) error {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(c.AllowLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))) {
		return ErrDenied
	}
	var body []byte
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.Origin+path, bytes.NewReader(body))
	if err != nil {
		return ErrDenied
	}
	req.Header.Set("Content-Type", "application/json")
	c.Identity.Sign(req, body)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("connector authentication service unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return ErrDenied
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &failure)
		allowed := map[string]bool{"provider_not_configured": true, "authorization_not_ready": true, "authorization_expired": true, "oauth_app_mismatch": true, "credential_recovery_required": true, "rotation_in_progress": true, "rate_limited": true, "provider_exchange_failed": true, "provider_refresh_failed": true}
		code := "request_failed"
		if allowed[failure.Error] {
			code = failure.Error
		}
		return &RemoteError{Status: response.StatusCode, Code: code}
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		return ErrDenied
	}
	return nil
}
func (c *Client) Register(ctx context.Context) error {
	return c.call(ctx, "POST", "/v1/installations", c.Identity.Installation(), nil)
}
func (c *Client) Start(ctx context.Context, start Start) (Transaction, error) {
	var tx Transaction
	err := c.call(ctx, "POST", "/v1/transactions", start, &tx)
	return tx, err
}
func (c *Client) Transaction(ctx context.Context, id string) (Transaction, error) {
	var tx Transaction
	err := c.call(ctx, "GET", "/v1/transactions/"+url.PathEscape(id), nil, &tx)
	return tx, err
}
func (c *Client) Redeem(ctx context.Context, id string) (Rotation, error) {
	var result Rotation
	err := c.call(ctx, "POST", "/v1/transactions/"+url.PathEscape(id)+"/redeem", struct{}{}, &result)
	return result, err
}
func (c *Client) Refresh(ctx context.Context, provider string, token oauth.Token) (Rotation, error) {
	var result Rotation
	err := c.call(ctx, "POST", "/v1/refresh", Refresh{Provider: provider, AppID: token.AppID, RefreshToken: token.RefreshToken, Shop: token.ExternalID, Scopes: token.Scopes, Version: token.Version}, &result)
	return result, err
}
func (c *Client) Commit(ctx context.Context, group string, version uint64) error {
	return c.call(ctx, "POST", "/v1/groups/"+url.PathEscape(group)+"/commit", map[string]uint64{"version": version}, nil)
}
func (c *Client) Disconnect(ctx context.Context, group string) error {
	return c.call(ctx, "POST", "/v1/groups/"+url.PathEscape(group)+"/disconnect", map[string]uint64{"version": 0}, nil)
}

type Recovery struct {
	Group     string       `json:"group"`
	Version   uint64       `json:"version"`
	Recipient Installation `json:"recipient"`
}
type RecoveryResult struct {
	Group     string         `json:"group"`
	Version   uint64         `json:"version"`
	Reconnect bool           `json:"reconnect"`
	Members   []Installation `json:"members"`
}

func (c *Client) Recover(ctx context.Context, group string) (RecoveryResult, error) {
	var result RecoveryResult
	err := c.call(ctx, "POST", "/v1/groups/"+url.PathEscape(group)+"/recover", map[string]uint64{"version": 0}, &result)
	return result, err
}

// GroupInfo is authoritative broker metadata; it contains no usable credentials.
type GroupInfo struct {
	ShopID           uint64    `json:"shop_id,omitempty"`
	ID               string    `json:"id"`
	AppID            string    `json:"app_id"`
	Shop             string    `json:"shop"`
	Version          uint64    `json:"version"`
	Scopes           []string  `json:"scopes"`
	AuthorizedAt     time.Time `json:"authorized_at"`
	CredentialDigest string    `json:"credential_digest"`
}

func tokenDigest(token oauth.Token) string {
	digest := sha256.Sum256([]byte(token.AccessToken + "\x00" + token.RefreshToken))
	return hex.EncodeToString(digest[:])
}
func (g GroupInfo) Validates(token oauth.Token) bool {
	return g.AppID == token.AppID && g.Shop == token.ExternalID && g.ShopID != 0 && g.ShopID == token.ShopID && g.Version == token.Version &&
		token.AuthorizedAt != nil && g.AuthorizedAt.Equal(*token.AuthorizedAt) && sameScopes(g.Scopes, token.Scopes) &&
		g.CredentialDigest != "" && g.CredentialDigest == tokenDigest(token)
}

type Mail struct {
	Groups        map[string]GroupInfo    `json:"groups"`
	Envelopes     []Envelope              `json:"envelopes"`
	Installations map[string]Installation `json:"installations"`
	Recoveries    []Recovery              `json:"recoveries"`
}

func (c *Client) Mail(ctx context.Context) (Mail, error) {
	var result Mail
	err := c.call(ctx, "GET", "/v1/mail", nil, &result)
	return result, err
}
func (c *Client) Send(ctx context.Context, e Envelope) error {
	return c.call(ctx, "POST", "/v1/mail", e, nil)
}

// Publish is called after the host has durably saved the rotated credential.
func (c *Client) Publish(ctx context.Context, rotation Rotation) error {
	if rotation.Group == "" {
		return nil
	}
	if err := c.Commit(ctx, rotation.Group, rotation.Token.Version); err != nil {
		return err
	}
	data, err := json.Marshal(rotation.Token)
	if err != nil {
		return err
	}
	for _, recipient := range rotation.Recipients {
		e, err := Seal(c.Identity, recipient, rotation.Group, rotation.Token.Version, data, time.Now())
		if err != nil {
			return err
		}
		if err = c.Send(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

type Delivery struct {
	ID         string          `json:"id"`
	Group      string          `json:"group"`
	Topic      string          `json:"topic"`
	Payload    json.RawMessage `json:"payload"`
	CreatedAt  time.Time       `json:"created_at"`
	OccurredAt time.Time       `json:"occurred_at"`
}

func (c *Client) Events(ctx context.Context) ([]Delivery, error) {
	var result struct {
		Events []Delivery `json:"events"`
	}
	err := c.call(ctx, "GET", "/v1/events", nil, &result)
	return result.Events, err
}
func (c *Client) Acknowledge(ctx context.Context, id string) error {
	return c.call(ctx, "POST", "/v1/events/"+url.PathEscape(id)+"/ack", struct{}{}, nil)
}
