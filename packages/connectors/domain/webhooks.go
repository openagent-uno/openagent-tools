package domain

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// WebhookBinding is retained only for compliance, uninstall and remote
// provider lifecycle deletion. Ordinary data-change callbacks are not routed.
type WebhookBinding struct {
	WorkspaceID  string `json:"workspace_id"`
	ConnectionID string `json:"connection_id"`
	Provider     string `json:"provider"`
	ShopDomain   string `json:"shop_domain,omitempty"`
	Version      string `json:"version"`
	secret       string
}

func (b *WebhookBinding) UnmarshalJSON(data []byte) error {
	var wire struct {
		WorkspaceID, ConnectionID, Provider, ShopDomain, Version, Secret string
	}
	var raw struct {
		WorkspaceID  string `json:"workspace_id"`
		ConnectionID string `json:"connection_id"`
		Provider     string `json:"provider"`
		ShopDomain   string `json:"shop_domain"`
		Version      string `json:"version"`
		Secret       string `json:"secret"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return errors.New("invalid webhook binding")
	}
	wire.WorkspaceID, wire.ConnectionID, wire.Provider = raw.WorkspaceID, raw.ConnectionID, raw.Provider
	wire.ShopDomain, wire.Version, wire.Secret = raw.ShopDomain, raw.Version, raw.Secret
	if !ValidResourceID(wire.WorkspaceID) || !ValidResourceID(wire.ConnectionID) || !providerPattern.MatchString(wire.Provider) ||
		wire.Version == "" || strings.TrimSpace(wire.Version) != wire.Version || len(wire.Version) > 128 ||
		strings.ContainsAny(wire.Version, "\r\n\x00") || len(wire.Secret) < 16 || len(wire.Secret) > 64<<10 ||
		!validHeaderToken(wire.Secret) || wire.Provider == "shopify" && !ValidShopifyDomain(wire.ShopDomain) ||
		wire.Provider != "shopify" && wire.ShopDomain != "" {
		return errors.New("invalid webhook binding")
	}
	*b = WebhookBinding{WorkspaceID: wire.WorkspaceID, ConnectionID: wire.ConnectionID, Provider: wire.Provider,
		ShopDomain: wire.ShopDomain, Version: wire.Version, secret: wire.Secret}
	return nil
}

func (b WebhookBinding) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"workspace_id": b.WorkspaceID, "connection_id": b.ConnectionID,
		"provider": b.Provider, "shop_domain": b.ShopDomain, "version": b.Version, "redacted": true})
}

func (b WebhookBinding) SecretBytes() []byte { return append([]byte(nil), b.secret...) }

func ValidShopifyDomain(value string) bool {
	if len(value) < len("a.myshopify.com") || len(value) > 253 || !strings.HasSuffix(value, ".myshopify.com") {
		return false
	}
	prefix := strings.TrimSuffix(value, ".myshopify.com")
	if len(prefix) > 63 || prefix[0] == '-' || prefix[len(prefix)-1] == '-' {
		return false
	}
	for _, character := range prefix {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

type WebhookAccepted struct {
	EventID            string          `json:"event_id"`
	Topic              string          `json:"topic"`
	OccurredAt         time.Time       `json:"occurred_at"`
	ProviderOccurredAt time.Time       `json:"provider_occurred_at,omitempty"`
	Payload            json.RawMessage `json:"payload,omitempty"`
}

type WebhookControl interface {
	ResolveWebhook(context.Context, string, string) (WebhookBinding, error)
	AcceptWebhook(context.Context, string, string, WebhookAccepted) error
}
