// Package central provides the opt-in shared catalog and credential execution
// protocol. It never imports credentials from the legacy host-token protocol.
package central

import (
	"encoding/json"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

const Protocol = "openagent-connectors-central/v1"

type Recipient struct {
	WorkspaceID string `json:"workspace_id"`
	SubjectID   string `json:"subject_id"`
}

type Descriptor struct {
	Item           connectors.Item    `json:"item"`
	ContractSHA256 string             `json:"contract_sha256"`
	Operations     []domain.Operation `json:"operations"`
	Setup          Setup              `json:"setup"`
}

type Setup struct {
	Mode              string `json:"mode"`
	CredentialCustody string `json:"credential_custody"`
	Execution         string `json:"execution"`
	// Hosted setup keeps provider-specific forms and secrets off consumers.
	Interaction string `json:"interaction,omitempty"`
}

type Catalog struct {
	Protocol   string       `json:"protocol"`
	Revision   uint64       `json:"revision"`
	IssuedAt   time.Time    `json:"issued_at"`
	ExpiresAt  time.Time    `json:"expires_at"`
	Connectors []Descriptor `json:"connectors"`
}

// The signature covers exactly Payload, not a re-encoding of parsed JSON.
type SignedCatalog struct {
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type CreateRequest struct {
	CatalogID      string          `json:"catalog_id"`
	ContractSHA256 string          `json:"contract_sha256"`
	Recipient      Recipient       `json:"recipient"`
	Operations     []string        `json:"operations"`
	Config         json.RawMessage `json:"config,omitempty"`
}

type Connection struct {
	Protocol         string    `json:"protocol"`
	ID               string    `json:"id"`
	CatalogID        string    `json:"catalog_id"`
	ContractSHA256   string    `json:"contract_sha256"`
	Recipient        Recipient `json:"recipient"`
	Operations       []string  `json:"operations"`
	GrantRevision    uint64    `json:"grant_revision"`
	Status           string    `json:"status"`
	AuthorizationURL string    `json:"authorization_url,omitempty"`
}

type InvokeRequest struct {
	Recipient      Recipient       `json:"recipient"`
	ContractSHA256 string          `json:"contract_sha256"`
	GrantRevision  uint64          `json:"grant_revision"`
	InvocationID   string          `json:"invocation_id"`
	Operation      string          `json:"operation"`
	Arguments      json.RawMessage `json:"arguments"`
	// Host attestation of per-action admission; never sourced from model args.
	ApprovalID string `json:"approval_id,omitempty"`
}

type InvocationResult struct {
	InvocationID    string         `json:"invocation_id"`
	Status          string         `json:"status"`
	Result          *domain.Result `json:"result,omitempty"`
	ResultAvailable bool           `json:"result_available"`
}

// These records are serialized only inside the encrypted vault, never HTTP.
type CredentialRecord struct {
	Installation  string            `json:"installation"`
	Public        Connection        `json:"public"`
	Binding       domain.Connection `json:"binding"`
	Token         oauth.Token       `json:"token"`
	TransactionID string            `json:"transaction_id,omitempty"`
}

type InvocationRecord struct {
	ConnectionID string    `json:"connection_id"`
	BodySHA256   string    `json:"body_sha256"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	Operation    string    `json:"operation"`
	ApprovalID   string    `json:"approval_id,omitempty"`
}

type VaultState struct {
	Connections map[string]CredentialRecord `json:"connections"`
	Invocations map[string]InvocationRecord `json:"invocations"`
}
