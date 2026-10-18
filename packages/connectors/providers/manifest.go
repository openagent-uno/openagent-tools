package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const (
	ShopifyAPIVersion = "2026-07"
	DriveAPIVersion   = "v3"
	PostizAPIVersion  = "public/v1"
	PipeboardVersion  = "mcp-v1"
)

type OriginKind string

const (
	OriginFixed     OriginKind = "fixed"
	OriginShopify   OriginKind = "shopify_connection"
	OriginPipeboard OriginKind = "pipeboard_connection"
)

type BodyMode string

const (
	BodyNone            BodyMode = "none"
	BodyJSON            BodyMode = "json"
	BodyGraphQL         BodyMode = "graphql"
	BodyRPC             BodyMode = "rpc"
	BodyRaw             BodyMode = "raw"
	BodyBase64          BodyMode = "base64"
	BodyMultipartBase64 BodyMode = "multipart_base64"
	// BodyDriveUpload is a provider-neutral file-content contract implemented
	// by the Google Drive adapter with media, multipart, or resumable transport.
	// Callers never receive or supply a resumable session URL.
	BodyDriveUpload BodyMode = "drive_upload"
)

// RetrySpec is deliberately manifest data rather than transport policy hidden
// in code. A write is retried only when both RetryableWrite and an invocation
// idempotency key are present.
type RetrySpec struct {
	MaxAttempts    int
	BaseDelay      time.Duration
	MaxDelay       time.Duration
	Statuses       []int
	RetryableWrite bool
}

type SyncSpec struct {
	Strategy       string
	CursorField    string
	WebhookCapable bool
	Resource       string
}

type RawPolicy struct {
	Methods      []string
	PathPrefixes []string
}

// GraphQLIDSearchFilter maps one trusted, typed resource ID to a provider
// search-filter variable. The adapter validates and canonicalizes the ID before
// constructing the fixed filter; callers never supply free-form search syntax.
type GraphQLIDSearchFilter struct {
	InputVariable string
	QueryVariable string
	FilterName    string
	GIDType       string
}

// OperationManifest describes all request construction. Arguments may select
// path and query values, but never origins, credential headers, API versions,
// or arbitrary request headers.
type OperationManifest struct {
	Name        string
	Description string
	Risk        domain.Risk
	Method      string
	Path        string
	// Origin is an optional server-owned HTTPS origin for providers whose typed
	// APIs span multiple hosts. It is never obtained from invocation arguments.
	Origin                string
	Query                 map[string]string // invocation argument -> provider query key
	FixedQuery            map[string]string
	Required              []string
	RequiredScopes        []string
	InternalOnly          bool
	Body                  BodyMode
	GraphQLDocument       string
	GraphQLIDSearchFilter *GraphQLIDSearchFilter
	// GraphQLIdempotencyVariable is injected from Invocation.Idempotency and
	// always overwrites an identically named caller variable.
	GraphQLIdempotencyVariable string
	RPCAction                  string
	RPCActions                 map[string]string
	InputSchema                json.RawMessage
	IdempotencyHeader          string
	Retry                      RetrySpec
	Sync                       *SyncSpec
	Raw                        *RawPolicy
}

type Manifest struct {
	Provider         string
	Capability       domain.Capability
	APIVersion       string
	OriginKind       OriginKind
	Origin           string
	CredentialHeader string
	CredentialScheme string
	MaxRequestBytes  int64
	MaxResponseBytes int64
	Operations       []OperationManifest
	// ReadOnly manifests deliberately expose no raw escape hatch or mutations.
	ReadOnly bool
	// TypedOnly manifests may include writes but never expose raw requests.
	TypedOnly bool
}

type FeatureFlagDefinition struct {
	Key            string            `json:"key"`
	Provider       string            `json:"provider"`
	Capability     domain.Capability `json:"capability"`
	DefaultEnabled bool              `json:"default_enabled"`
	Description    string            `json:"description"`
}

const (
	FeatureDirectMetaAds   = "connectors.ads.meta_direct"
	FeatureDirectGoogleAds = "connectors.ads.google_ads_direct"
)

func DirectAdsFeatureFlags() []FeatureFlagDefinition {
	return []FeatureFlagDefinition{
		{Key: FeatureDirectMetaAds, Provider: "meta_ads", Capability: domain.Ads, DefaultEnabled: false, Description: "Direct Meta Marketing API adapter (provider setup required)"},
		{Key: FeatureDirectGoogleAds, Provider: "google_ads", Capability: domain.Ads, DefaultEnabled: false, Description: "Direct Google Ads API adapter (developer-token access required)"},
	}
}

var (
	providerNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)
	operationNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,127}$`)
	headerNamePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	toolNamePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	pipeboardOrigins     = map[string]string{
		"meta_ads":   "https://meta-ads.mcp.pipeboard.co",
		"google_ads": "https://google-ads.mcp.pipeboard.co",
		"tiktok_ads": "https://tiktok-ads.mcp.pipeboard.co",
		"snap_ads":   "https://snap-ads.mcp.pipeboard.co",
	}
)

func validPipeboardEndpoint(value string) bool { _, ok := pipeboardOrigins[value]; return ok }
func safeToolName(value string) bool           { return toolNamePattern.MatchString(value) }

func (m Manifest) validate() error {
	if !providerNamePattern.MatchString(m.Provider) || !m.Capability.Valid() {
		return errors.New("invalid provider manifest identity")
	}
	if m.APIVersion == "" || strings.ContainsAny(m.APIVersion, "\r\n") {
		return errors.New("provider API version is required")
	}
	if !headerNamePattern.MatchString(m.CredentialHeader) {
		return errors.New("invalid fixed credential header")
	}
	if strings.ContainsAny(m.CredentialScheme, "\r\n") {
		return errors.New("invalid fixed credential scheme")
	}
	if m.MaxRequestBytes <= 0 || m.MaxRequestBytes > 32<<20 || m.MaxResponseBytes <= 0 || m.MaxResponseBytes > 64<<20 {
		return errors.New("provider body bounds are invalid")
	}
	switch m.OriginKind {
	case OriginFixed:
		if _, err := fixedHTTPSOrigin(m.Origin); err != nil {
			return err
		}
	case OriginShopify:
		if m.Origin != "" {
			return errors.New("dynamic Shopify origin cannot define a fallback")
		}
	case OriginPipeboard:
		if m.Origin != "" || m.Provider != "pipeboard" {
			return errors.New("dynamic Pipeboard origin cannot define a fallback")
		}
	default:
		return errors.New("invalid provider origin policy")
	}
	if len(m.Operations) == 0 {
		return errors.New("provider manifest has no operations")
	}
	seen := make(map[string]struct{}, len(m.Operations))
	rawCount := 0
	for _, operation := range m.Operations {
		if !operationNamePattern.MatchString(operation.Name) || !strings.HasPrefix(operation.Name, string(m.Capability)+".") {
			return fmt.Errorf("invalid operation name %q", operation.Name)
		}
		if _, ok := seen[operation.Name]; ok {
			return fmt.Errorf("duplicate operation %q", operation.Name)
		}
		seen[operation.Name] = struct{}{}
		if err := operation.validate(); err != nil {
			return fmt.Errorf("operation %s: %w", operation.Name, err)
		}
		if operation.Origin != "" {
			if m.OriginKind != OriginFixed || operation.Raw != nil {
				return fmt.Errorf("operation %s: an origin override requires a fixed-origin typed manifest", operation.Name)
			}
			if _, err := fixedHTTPSOrigin(operation.Origin); err != nil {
				return fmt.Errorf("operation %s: %w", operation.Name, err)
			}
		}
		if m.ReadOnly && (operation.Risk != domain.RiskRead || operation.Raw != nil || operation.Sync != nil) {
			return fmt.Errorf("operation %s: read-only manifests cannot expose writes, raw calls or sync", operation.Name)
		}
		if operation.Body == BodyDriveUpload && (m.Provider != "google_drive" ||
			(operation.Method != http.MethodPost && operation.Method != http.MethodPatch) ||
			!strings.HasPrefix(operation.Path, "/upload/drive/v3/files")) {
			return fmt.Errorf("operation %s: Drive upload body is bound to a fixed Drive upload endpoint", operation.Name)
		}
		if operation.Raw != nil {
			if m.TypedOnly {
				return errors.New("typed-only manifests cannot expose raw operations")
			}
			rawCount++
		}
	}
	if !m.ReadOnly && !m.TypedOnly && rawCount != 1 {
		return fmt.Errorf("provider %s must expose exactly one raw operation", m.Provider)
	}
	return nil
}

func (o OperationManifest) validate() error {
	if o.Description == "" || !validRisk(o.Risk) || !domain.ValidProviderScopes(o.RequiredScopes) {
		return errors.New("description and valid risk are required")
	}
	if o.Raw != nil {
		if o.Method != "" || o.Path != "" || o.Body != BodyRaw {
			return errors.New("raw operation must obtain method/path/body from its constrained raw policy")
		}
		if o.Risk != domain.RiskRaw {
			return errors.New("raw operation must use the non-bypassable raw risk")
		}
		if len(o.Raw.Methods) == 0 || len(o.Raw.PathPrefixes) == 0 {
			return errors.New("raw policy needs methods and path prefixes")
		}
		for _, method := range o.Raw.Methods {
			if !allowedMethod(method) {
				return errors.New("raw policy contains unsafe HTTP method")
			}
		}
		for _, prefix := range o.Raw.PathPrefixes {
			if err := validateProviderPath(prefix, true); err != nil {
				return fmt.Errorf("invalid raw path prefix: %w", err)
			}
		}
		return validateSchema(o.InputSchema)
	}
	if !allowedMethod(o.Method) || o.Path == "" {
		return errors.New("typed operation has invalid method or empty path")
	}
	if err := validateProviderPath(o.Path, false); err != nil {
		return err
	}
	for key, value := range o.Query {
		if !safeArgumentName(key) || !safeQueryName(value) {
			return errors.New("invalid query mapping")
		}
	}
	for _, name := range o.Required {
		if !safeArgumentName(name) {
			return errors.New("invalid required argument")
		}
	}
	for key, value := range o.FixedQuery {
		if !safeQueryName(key) || len(value) > 2048 || strings.ContainsAny(value, "\r\n") {
			return errors.New("invalid fixed query value")
		}
	}
	if o.Body == BodyGraphQL && o.GraphQLDocument == "" {
		return errors.New("GraphQL body requires a fixed document")
	}
	if filter := o.GraphQLIDSearchFilter; filter != nil {
		if o.Body != BodyGraphQL || !safeArgumentName(filter.InputVariable) ||
			!safeArgumentName(filter.QueryVariable) || !safeArgumentName(filter.FilterName) ||
			!safeArgumentName(filter.GIDType) || !containsString(o.Required, filter.InputVariable) {
			return errors.New("GraphQL ID search filter requires fixed safe variables and a required typed input")
		}
	}
	if o.GraphQLIdempotencyVariable != "" && (o.Body != BodyGraphQL || !safeArgumentName(o.GraphQLIdempotencyVariable)) {
		return errors.New("GraphQL idempotency variable requires a fixed GraphQL operation")
	}
	if o.Body == BodyRPC && o.RPCAction == "" && len(o.RPCActions) == 0 {
		return errors.New("RPC body requires a fixed endpoint-bound action")
	}
	for endpoint, action := range o.RPCActions {
		if !validPipeboardEndpoint(endpoint) || !safeToolName(action) {
			return errors.New("RPC action map is invalid")
		}
	}
	if o.IdempotencyHeader != "" && !headerNamePattern.MatchString(o.IdempotencyHeader) {
		return errors.New("invalid idempotency header")
	}
	if o.Retry.MaxAttempts < 1 || o.Retry.MaxAttempts > 5 || o.Retry.BaseDelay < 0 || o.Retry.MaxDelay < o.Retry.BaseDelay {
		return errors.New("invalid retry policy")
	}
	for _, status := range o.Retry.Statuses {
		if status < 400 || status > 599 {
			return errors.New("invalid retry status")
		}
	}
	return validateSchema(o.InputSchema)
}

func validateSchema(schema json.RawMessage) error {
	if len(schema) == 0 || !json.Valid(schema) {
		return errors.New("operation input schema must be valid JSON")
	}
	return nil
}

func validRisk(risk domain.Risk) bool {
	switch risk {
	case domain.RiskRead, domain.RiskDraft, domain.RiskWrite, domain.RiskPublish, domain.RiskSpend, domain.RiskDestructive, domain.RiskRaw:
		return true
	default:
		return false
	}
}

func allowedMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func fixedHTTPSOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.Port() != "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("provider origin must be a fixed HTTPS origin without credentials, port, path, query, or fragment")
	}
	if parsed.Host != strings.ToLower(parsed.Host) {
		return nil, errors.New("provider origin hostname must be canonical lowercase ASCII")
	}
	hostname := parsed.Hostname()
	if net.ParseIP(hostname) != nil || !strings.Contains(hostname, ".") || strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".internal") || strings.HasSuffix(hostname, ".localhost") || strings.HasSuffix(hostname, ".svc") || strings.HasSuffix(hostname, ".svc.cluster.local") {
		return nil, errors.New("provider origin must use a public DNS hostname")
	}
	for _, label := range strings.Split(hostname, ".") {
		if !shopLabelPattern.MatchString(label) {
			return nil, errors.New("provider origin hostname must be canonical lowercase ASCII")
		}
	}
	return parsed, nil
}

func validateProviderPath(path string, prefix bool) error {
	if path == "" || path[0] != '/' || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\?#\r\n") || strings.Contains(path, "://") || strings.Contains(path, "%") {
		return errors.New("provider path must be an unescaped absolute path")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return errors.New("provider path contains traversal")
		}
		if strings.ContainsAny(segment, "{}") && !validTemplateSegment(segment) {
			return errors.New("provider path contains an invalid template")
		}
	}
	return nil
}

func validTemplateSegment(segment string) bool {
	if strings.Count(segment, "{") != 1 || strings.Count(segment, "}") != 1 {
		return false
	}
	open := strings.IndexByte(segment, '{')
	close := strings.IndexByte(segment, '}')
	if open < 0 || close <= open+1 {
		return false
	}
	for _, value := range []string{segment[:open], segment[close+1:]} {
		for _, char := range value {
			// A static colon suffix supports Google gRPC-transcoded methods
			// such as {property_id}:runReport. Values still pass expandPath.
			if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && !strings.ContainsRune("._~-:", char) {
				return false
			}
		}
	}
	return safeArgumentName(segment[open+1 : close])
}

func safeArgumentName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '_' {
			return false
		}
		if index == 0 && char >= '0' && char <= '9' {
			return false
		}
	}
	return true
}

func safeQueryName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '_' && char != '.' && char != '$' && char != '[' && char != ']' {
			return false
		}
	}
	return true
}

func operationNames(manifest Manifest) []string {
	names := make([]string, 0, len(manifest.Operations))
	for _, operation := range manifest.Operations {
		names = append(names, operation.Name)
	}
	sort.Strings(names)
	return names
}
