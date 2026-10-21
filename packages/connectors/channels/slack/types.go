// Package slackchannel implements the optional official Slack conversational
// channel. Bot custody, event routing and lifecycle are separate from MCP OAuth.
package slackchannel

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

const Protocol = "openagent-slack-channel/v1"
const Prefix = "/v1/channels/slack"

var BotScopes = []string{"app_mentions:read", "channels:history", "channels:read", "chat:write", "groups:history", "groups:read"}

type InstallationAuthorizer interface {
	AuthenticateInstallation(*http.Request, []byte) (auth.Installation, error)
	WithCentralInstallation(auth.Installation, func() error) error
}

type Config struct {
	Origin               string            `json:"origin"`
	AppID                string            `json:"app_id"`
	ClientID             string            `json:"client_id"`
	ClientSecretFile     string            `json:"client_secret_file"`
	SigningSecretFile    string            `json:"signing_secret_file"`
	VaultPath            string            `json:"vault_path"`
	VaultKeyID           string            `json:"vault_key_id"`
	VaultKeyFiles        map[string]string `json:"vault_key_files"`
	AllowedInstallations []string          `json:"allowed_installations"`
}

type Recipient struct {
	WorkspaceID string `json:"workspace_id"`
	SubjectID   string `json:"subject_id"`
	AgentID     string `json:"agent_id"`
}

type StartRequest struct {
	Recipient  Recipient `json:"recipient"`
	AgentLabel string    `json:"agent_label"`
	TeamID     string    `json:"team_id"`
	ChannelID  string    `json:"channel_id"`
}

type Binding struct {
	ID               string    `json:"id"`
	Installation     string    `json:"installation"`
	Recipient        Recipient `json:"recipient"`
	AgentLabel       string    `json:"agent_label"`
	TeamID           string    `json:"team_id"`
	ChannelID        string    `json:"channel_id"`
	BotUserID        string    `json:"bot_user_id,omitempty"`
	AuthorizedUserID string    `json:"authorized_user_id,omitempty"`
	Status           string    `json:"status"`
	Version          uint64    `json:"version"`
	AuthorizationURL string    `json:"authorization_url,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	AuthorizedAt     time.Time `json:"authorized_at,omitempty"`
}

type bindingRecord struct {
	Public           Binding           `json:"public"`
	Host             auth.Installation `json:"host"`
	SessionDigest    string            `json:"session_digest,omitempty"`
	SessionExpiresAt time.Time         `json:"session_expires_at,omitempty"`
}

type BotGrant struct {
	AppID            string    `json:"app_id"`
	TeamID           string    `json:"team_id"`
	BotUserID        string    `json:"bot_user_id"`
	AuthorizedUserID string    `json:"authorized_user_id"`
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	ExpiresAt        time.Time `json:"expires_at"`
	Scopes           []string  `json:"scopes"`
	Status           string    `json:"status"`
	Version          uint64    `json:"version"`
	AuthorizedAt     time.Time `json:"authorized_at"`
}

func (BotGrant) String() string   { return "[redacted Slack bot grant]" }
func (BotGrant) GoString() string { return "[redacted Slack bot grant]" }

type transaction struct {
	BindingID string    `json:"binding_id"`
	State     string    `json:"state"`
	CSRF      string    `json:"csrf"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	StartedAt time.Time `json:"started_at"`
}

type Delivery struct {
	ID             string          `json:"id"`
	BindingID      string          `json:"binding_id"`
	BindingVersion uint64          `json:"binding_version"`
	TeamID         string          `json:"team_id"`
	EventID        string          `json:"event_id"`
	BodySHA256     string          `json:"body_sha256"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	Status         string          `json:"status"`
	EventType      string          `json:"event_type,omitempty"`
	OccurredAt     time.Time       `json:"occurred_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type operation struct {
	BindingID  string          `json:"binding_id"`
	DeliveryID string          `json:"delivery_id"`
	BodySHA256 string          `json:"body_sha256"`
	Status     string          `json:"status"`
	Result     json.RawMessage `json:"result,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

type state struct {
	Bindings     map[string]bindingRecord `json:"bindings"`
	Grants       map[string]BotGrant      `json:"grants"`
	Transactions map[string]transaction   `json:"transactions"`
	Deliveries   map[string]Delivery      `json:"deliveries"`
	Operations   map[string]operation     `json:"operations"`
}

type Provider interface {
	AuthorizationURL(state string) (string, error)
	Exchange(context.Context, string, time.Time) (BotGrant, error)
	Refresh(context.Context, BotGrant, time.Time) (BotGrant, error)
	Call(context.Context, BotGrant, string, map[string]any) (json.RawMessage, error)
}
