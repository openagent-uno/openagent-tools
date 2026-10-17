package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Capability string

const (
	Commerce Capability = "commerce"
	Files    Capability = "files"
	Social   Capability = "social"
	Ads      Capability = "ads"
	Outreach Capability = "outreach"
	Media    Capability = "media"
	// Insights is a OpenAgent-owned, read-only workspace capability. Unlike
	// connector capabilities it never resolves a provider connection or
	// credential; the gateway serves it through a narrowly scoped internal
	// adapter after authenticating the workspace workload identity.
	Insights Capability = "insights"
)

func (c Capability) Valid() bool {
	switch c {
	case Commerce, Files, Social, Ads, Outreach, Media, Insights:
		return true
	default:
		return false
	}
}

type Risk string

const (
	RiskRead        Risk = "read"
	RiskDraft       Risk = "draft"
	RiskWrite       Risk = "write"
	RiskPublish     Risk = "publish"
	RiskSpend       Risk = "spend"
	RiskDestructive Risk = "destructive"
	// RiskRaw identifies provider escape hatches and other operations whose
	// concrete effect cannot be determined from the manifest alone. Raw
	// operations are denied while protected action controls are being redesigned.
	RiskRaw Risk = "raw"
)

func (r Risk) Valid() bool {
	switch r {
	case RiskRead, RiskDraft, RiskWrite, RiskPublish, RiskSpend, RiskDestructive, RiskRaw:
		return true
	default:
		return false
	}
}

// Connection is secret-free metadata returned by the control plane. Config is
// provider-specific but may never contain OAuth or API credentials.
type Connection struct {
	ID               string          `json:"id"`
	WorkspaceID      string          `json:"workspace_id"`
	Capability       Capability      `json:"capability"`
	Provider         string          `json:"provider"`
	DisplayName      string          `json:"display_name"`
	ExternalID       string          `json:"external_id"`
	Scopes           []string        `json:"scopes,omitempty"`
	Config           json.RawMessage `json:"config,omitempty"`
	Enabled          bool            `json:"enabled"`
	LifecycleCleanup bool            `json:"lifecycle_cleanup,omitempty"`
}

var (
	resourceIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sessionIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)
	providerPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	providerScopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	headerPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	schemePattern        = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,31}$`)
	actorUserPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func ValidResourceID(value string) bool { return resourceIDPattern.MatchString(value) }

// ValidSessionID accepts the namespace separator used by durable OpenAgent
// child and automation sessions. Other product resource IDs remain on the
// narrower grammar above, so accepting an automation session never widens a
// connector, installation, project or channel identifier.
func ValidSessionID(value string) bool { return sessionIDPattern.MatchString(value) }

func validScopeSet(scopes []string) bool {
	if len(scopes) > 256 {
		return false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !providerScopePattern.MatchString(scope) {
			return false
		}
		if _, duplicate := seen[scope]; duplicate {
			return false
		}
		seen[scope] = struct{}{}
	}
	return true
}

func ValidProviderScopes(scopes []string) bool { return validScopeSet(scopes) }

// GrantsScopes performs exact, case-sensitive OAuth scope matching. Empty
// requirements are intentionally allowed so providers can adopt scope-aware
// manifests incrementally; any declared requirement is fail-closed.
func GrantsScopes(granted, required []string) bool {
	if len(required) == 0 {
		return true
	}
	grants := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		grants[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := grants[scope]; !ok {
			return false
		}
	}
	return true
}

func (c Connection) Validate(workspaceID string, capability Capability) error {
	if !ValidResourceID(c.ID) || c.WorkspaceID != workspaceID || c.Capability != capability || !c.Capability.Valid() ||
		!providerPattern.MatchString(c.Provider) || !c.Enabled {
		return errors.New("invalid or disabled connection")
	}
	if !validScopeSet(c.Scopes) {
		return errors.New("invalid connection scopes")
	}
	if len(c.Config) > 256<<10 || (len(c.Config) > 0 && !json.Valid(c.Config)) {
		return errors.New("invalid connection config")
	}
	return nil
}

type Principal struct {
	WorkspaceID       string   `json:"workspace_id"`
	AgentID           string   `json:"agent_id,omitempty"`
	SessionID         string   `json:"session_id,omitempty"`
	ProjectID         string   `json:"project_id,omitempty"`
	ChannelID         string   `json:"channel_id,omitempty"`
	ActorType         string   `json:"actor_type,omitempty"`
	ActorID           string   `json:"actor_id"`
	Role              string   `json:"role"`
	BoundConnectionID string   `json:"bound_connection_id,omitempty"`
	ToolScope         []string `json:"tool_scope,omitempty"`
}

type CredentialKind string

const (
	// CredentialNone is an explicit no-auth contract, never an absent token.
	CredentialNone         CredentialKind = "none"
	CredentialOAuth2Bearer CredentialKind = "oauth2_bearer"
	CredentialAPIToken     CredentialKind = "api_token"
)

// Credential deliberately keeps its secret unexported. JSON decoding is
// supported for the just-in-time control-plane response, while JSON encoding
// emits metadata and a redaction marker only.
type Credential struct {
	kind      CredentialKind
	secret    string
	header    string
	scheme    string
	version   string
	expiresAt *time.Time
}

type credentialWire struct {
	Kind      CredentialKind `json:"kind"`
	Secret    string         `json:"secret"`
	Header    string         `json:"header"`
	Scheme    string         `json:"scheme"`
	Version   string         `json:"version"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
}

func NewCredential(kind CredentialKind, secret, header, scheme, version string, expiresAt *time.Time) (Credential, error) {
	wire := credentialWire{Kind: kind, Secret: secret, Header: header, Scheme: scheme, Version: version, ExpiresAt: expiresAt}
	return credentialFromWire(wire)
}

func credentialFromWire(wire credentialWire) (Credential, error) {
	if wire.Kind == CredentialNone {
		if wire.Secret != "" || wire.Header != "" || wire.Scheme != "" || wire.Version != "" || wire.ExpiresAt != nil {
			return Credential{}, errors.New("no-auth credential contains credential material")
		}
		return Credential{kind: CredentialNone}, nil
	}
	if wire.Kind != CredentialOAuth2Bearer && wire.Kind != CredentialAPIToken {
		return Credential{}, errors.New("unsupported credential kind")
	}
	if wire.Secret == "" || len(wire.Secret) > 64<<10 || !validHeaderToken(wire.Secret) {
		return Credential{}, errors.New("invalid credential secret")
	}
	if wire.Header != "" && !headerPattern.MatchString(wire.Header) {
		return Credential{}, errors.New("invalid credential header")
	}
	if wire.Scheme != "" && !schemePattern.MatchString(wire.Scheme) {
		return Credential{}, errors.New("invalid credential scheme")
	}
	if len(wire.Version) > 128 {
		return Credential{}, errors.New("invalid credential version")
	}
	return Credential{
		kind: wire.Kind, secret: wire.Secret, header: wire.Header, scheme: wire.Scheme,
		version: wire.Version, expiresAt: wire.ExpiresAt,
	}, nil
}

func validHeaderToken(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func (c *Credential) UnmarshalJSON(data []byte) error {
	var wire credentialWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return errors.New("invalid credential response")
	}
	if wire.Kind == CredentialNone {
		decoder := json.NewDecoder(bytes.NewReader(data))
		open, openErr := decoder.Token()
		key, keyErr := decoder.Token()
		var kind CredentialKind
		valueErr := decoder.Decode(&kind)
		close, closeErr := decoder.Token()
		if openErr != nil || keyErr != nil || valueErr != nil || closeErr != nil || open != json.Delim('{') || key != "kind" || kind != CredentialNone || close != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
			return errors.New("no-auth credential must contain only kind")
		}
	}
	credential, err := credentialFromWire(wire)
	if err != nil {
		return err
	}
	*c = credential
	return nil
}

func (c Credential) MarshalJSON() ([]byte, error) {
	if c.IsNone() {
		return []byte(`{"kind":"none"}`), nil
	}
	return json.Marshal(map[string]any{
		"kind": c.kind, "header": c.header, "scheme": c.scheme, "version": c.version,
		"expires_at": c.expiresAt, "redacted": true,
	})
}

// IsNone distinguishes the explicit no-auth credential from an omitted value.
func (c Credential) IsNone() bool { return c.kind == CredentialNone }

// Apply writes a credential only to the fixed header/scheme declared by the
// provider manifest. Control-plane data cannot select an arbitrary header.
func (c Credential) Apply(headers http.Header, expectedHeader, expectedScheme string, now time.Time) error {
	if headers == nil || !headerPattern.MatchString(expectedHeader) {
		return errors.New("invalid provider credential target")
	}
	if c.secret == "" {
		return errors.New("credential is empty")
	}
	if c.expiresAt != nil && !now.Add(15*time.Second).Before(*c.expiresAt) {
		return errors.New("credential is expired")
	}
	header := c.header
	if header == "" {
		header = expectedHeader
	}
	if !strings.EqualFold(header, expectedHeader) {
		return errors.New("credential header does not match provider manifest")
	}
	scheme := c.scheme
	if scheme == "" {
		scheme = expectedScheme
	}
	if scheme != expectedScheme {
		return errors.New("credential scheme does not match provider manifest")
	}
	value := c.secret
	if scheme != "" {
		value = scheme + " " + value
	}
	headers.Set(expectedHeader, value)
	return nil
}

func (c Credential) Redact(value []byte) []byte {
	if c.secret == "" {
		return value
	}
	redacted := bytes.ReplaceAll(value, []byte(c.secret), []byte("[REDACTED]"))
	// JSON string encoding escapes quotes, backslashes, and HTML-sensitive
	// bytes. Replace that representation as well before provider JSON is
	// decoded and exposed to the workspace.
	if encoded, err := json.Marshal(c.secret); err == nil && len(encoded) >= 2 {
		redacted = bytes.ReplaceAll(redacted, encoded[1:len(encoded)-1], []byte("[REDACTED]"))
	}
	return redacted
}

// WithSecret provides callback-scoped access for non-HTTP protocols such as
// IMAP and SMTP. The temporary byte copy is cleared immediately after the
// callback returns; callers cannot serialize Credential and obtain the secret.
func (c Credential) WithSecret(
	now time.Time,
	use func(CredentialKind, []byte) error,
) error {
	if use == nil || c.secret == "" {
		return errors.New("credential secret callback is invalid")
	}
	if c.expiresAt != nil && !now.Add(15*time.Second).Before(*c.expiresAt) {
		return errors.New("credential is expired")
	}
	secret := []byte(c.secret)
	defer clear(secret)
	return use(c.kind, secret)
}

type OperationMode string

const (
	OperationTyped OperationMode = "typed"
	OperationRaw   OperationMode = "raw"
)

type RetryPolicy struct {
	MaxAttempts         int   `json:"max_attempts"`
	BaseDelayMillis     int64 `json:"base_delay_ms"`
	SupportsIdempotency bool  `json:"supports_idempotency"`
}

type ActionPreview struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Summary string `json:"summary"`
}

type Operation struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Capability     Capability      `json:"capability"`
	Provider       string          `json:"provider"`
	Risk           Risk            `json:"risk"`
	Mode           OperationMode   `json:"mode"`
	InputSchema    json.RawMessage `json:"inputSchema"`
	RequiredScopes []string        `json:"required_scopes,omitempty"`
	InternalOnly   bool            `json:"-"`
	Retry          RetryPolicy     `json:"retry"`
	Preview        ActionPreview   `json:"preview"`
}

func (o Operation) Validate() error {
	if !resourceIDPattern.MatchString(strings.ReplaceAll(o.Name, ":", "_")) || !o.Capability.Valid() ||
		!providerPattern.MatchString(o.Provider) || !o.Risk.Valid() ||
		(o.Mode != OperationTyped && o.Mode != OperationRaw) || !json.Valid(o.InputSchema) ||
		!validScopeSet(o.RequiredScopes) {
		return errors.New("invalid provider operation")
	}
	if o.Retry.MaxAttempts < 1 || o.Retry.MaxAttempts > 5 || o.Retry.BaseDelayMillis < 0 || o.Retry.BaseDelayMillis > 30_000 {
		return errors.New("invalid retry policy")
	}
	return nil
}

type Invocation struct {
	ID          string
	Principal   Principal
	Connection  Connection
	Credential  Credential
	Operation   Operation
	Arguments   json.RawMessage
	RequestedAt time.Time
	Idempotency string
}

type Result struct {
	Data           any               `json:"data,omitempty"`
	ProviderID     string            `json:"provider_request_id,omitempty"`
	ProviderStatus int               `json:"provider_status,omitempty"`
	Attempts       int               `json:"attempts"`
	RequestBytes   int64             `json:"request_bytes,omitempty"`
	ResponseBytes  int64             `json:"response_bytes,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type Adapter interface {
	Provider() string
	Capability() Capability
	Operations() []Operation
	Invoke(context.Context, Invocation) (Result, error)
}

// OperationScopePolicy lets a reviewed provider express documented scope
// implications for its own compiled operations. Hosts retain their local grants;
// adapters without this optional policy keep exact RequiredScopes matching.
// Unknown operation names must return false.
type OperationScopePolicy interface {
	OperationScopesGranted(granted []string, operationName string) bool
}

// CredentialFreeAdapter declares a reviewed no-auth provider. Connections and
// host authorization are still required; this does not grant workspace access.
type CredentialFreeAdapter interface {
	Adapter
	CredentialFree()
}

type ProviderCallReservation struct {
	Provider  string `json:"provider"`
	Source    string `json:"source"`
	Operation string `json:"operation"`
}

type ProviderCallAllowance struct {
	Allowed   bool      `json:"allowed"`
	Used      int       `json:"used"`
	Limit     int       `json:"limit"`
	ResetAt   time.Time `json:"reset_at"`
	SyncUsed  int       `json:"sync_used"`
	SyncLimit int       `json:"sync_limit"`
}

type ProviderCallBudget interface {
	ReserveProviderCall(context.Context, string, string, ProviderCallReservation) (ProviderCallAllowance, error)
}

// ApprovalOnlyAdapter marks a reviewed adapter that exists solely to execute
// an already-fenced control-plane approval. Its operations are registered by
// the approval worker but never exposed in an MCP tool inventory.
type ApprovalOnlyAdapter interface {
	Adapter
	ApprovalExecutionOnly()
}

// WorkspaceReadAdapter marks the only class of adapter that may run without a
// user-managed Connection and Credential. The gateway accepts this marker only
// for the Insights capability and only when every operation is RiskRead.
// The gateway still validates capability, provider and risk at registration;
// the explicit marker keeps ordinary provider adapters on the connection path.
type WorkspaceReadAdapter interface {
	Adapter
	WorkspaceReadOnly()
}

type ActionPreviewer interface {
	Preview(Invocation) (ActionPreview, error)
}

type ConnectionCatalog interface {
	ListConnections(context.Context, string, Capability) ([]Connection, error)
}

type CredentialResolver interface {
	ResolveConnectionCredential(context.Context, string, string) (Connection, Credential, error)
}

type Actor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (a Actor) Valid() bool {
	return (a.Type == "workspace_agent" && a.ID == "workspace-agent") ||
		(a.Type == "user" && actorUserPattern.MatchString(a.ID))
}

type ApprovalRequest struct {
	InvocationID   string          `json:"invocation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Actor          Actor           `json:"actor"`
	Capability     Capability      `json:"capability"`
	Provider       string          `json:"provider"`
	Operation      string          `json:"operation"`
	Risk           Risk            `json:"risk"`
	Payload        json.RawMessage `json:"payload"`
	PayloadHash    string          `json:"payload_hash"`
	Preview        ActionPreview   `json:"preview"`
	RequestedAt    time.Time       `json:"requested_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
}

type ApprovalDecision struct {
	Decision       string `json:"decision"`
	ApprovalID     string `json:"approval_id,omitempty"`
	ExecutionNonce string `json:"execution_nonce,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

func (d ApprovalDecision) Validate() error {
	switch d.Decision {
	case "allowed":
		if len(d.ExecutionNonce) > 512 || strings.ContainsAny(d.ExecutionNonce, "\r\n\x00") ||
			(d.ApprovalID != "" && !ValidResourceID(d.ApprovalID)) {
			return errors.New("invalid allowed decision")
		}
	case "approval_required":
		if !ValidResourceID(d.ApprovalID) {
			return errors.New("approval id is required")
		}
	case "queued":
		if !ValidResourceID(d.ApprovalID) || d.ExecutionNonce != "" {
			return errors.New("queued approval id is required")
		}
	case "denied":
	default:
		return errors.New("invalid approval decision")
	}
	return nil
}

type AuditEvent struct {
	EventID           string            `json:"event_id"`
	InvocationID      string            `json:"invocation_id"`
	IdempotencyKey    string            `json:"idempotency_key"`
	Actor             Actor             `json:"actor"`
	Capability        Capability        `json:"capability"`
	Provider          string            `json:"provider"`
	Operation         string            `json:"operation"`
	Risk              Risk              `json:"risk"`
	Phase             string            `json:"phase"`
	ApprovalID        string            `json:"approval_id,omitempty"`
	ExecutionNonce    string            `json:"execution_nonce,omitempty"`
	PayloadHash       string            `json:"payload_hash"`
	OccurredAt        time.Time         `json:"occurred_at"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	ProviderRetrySafe bool              `json:"provider_retry_safe"`
}

type UsageOutcome struct {
	OutcomeID         string    `json:"outcome_id"`
	InvocationID      string    `json:"invocation_id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	Operation         string    `json:"operation"`
	Outcome           string    `json:"outcome"`
	ProviderStatus    int       `json:"provider_status,omitempty"`
	ProviderRequestID string    `json:"provider_request_id,omitempty"`
	AttemptCount      int       `json:"attempt_count"`
	StartedAt         time.Time `json:"started_at"`
	FinishedAt        time.Time `json:"finished_at"`
	RequestBytes      int64     `json:"request_bytes,omitempty"`
	ResponseBytes     int64     `json:"response_bytes,omitempty"`
}

// ConnectorInstallationAuditRequest preserves the exact AgentRuntime session
// scope used to authorize a custom MCP provider call. Custom installations do
// not have a legacy connection ID, so their durable audit boundary must remain
// installation-scoped all the way to the control plane.
type ConnectorInstallationAuditRequest struct {
	ProjectedToken string     `json:"-"`
	ActorContext   string     `json:"actor_context"`
	AgentID        string     `json:"agent_id"`
	SessionID      string     `json:"session_id"`
	ProjectID      string     `json:"project_id"`
	Event          AuditEvent `json:"event"`
}

type ConnectorInstallationOutcomeRequest struct {
	ProjectedToken string       `json:"-"`
	ActorContext   string       `json:"actor_context"`
	AgentID        string       `json:"agent_id"`
	SessionID      string       `json:"session_id"`
	ProjectID      string       `json:"project_id"`
	Outcome        UsageOutcome `json:"outcome"`
}

type ActionControl interface {
	Authorize(context.Context, string, string, ApprovalRequest) (ApprovalDecision, error)
	RecordAudit(context.Context, string, string, AuditEvent) error
	RecordOutcome(context.Context, string, string, UsageOutcome) error
	RecordInstallationAudit(context.Context, string, string, ConnectorInstallationAuditRequest) error
	RecordInstallationOutcome(context.Context, string, string, ConnectorInstallationOutcomeRequest) error
}

type ProviderError struct {
	Kind          string
	StatusCode    int
	ProviderID    string
	Attempts      int
	RequestBytes  int64
	ResponseBytes int64
}

func (e *ProviderError) Error() string { return "provider operation failed" }

var (
	ErrNotFound           = errors.New("not found")
	ErrAmbiguous          = errors.New("multiple connections available; connection_id is required")
	ErrApprovalRequired   = errors.New("approval required")
	ErrDenied             = errors.New("connector action denied")
	ErrConflict           = errors.New("state conflict")
	ErrInvalidArguments   = errors.New("invalid connector arguments")
	ErrUnsupported        = errors.New("unsupported provider operation")
	ErrProviderPermission = errors.New("provider permission denied")
)
