package providers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/definitions"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type reviewedAuthentication struct {
	Mode               string            `json:"mode"`
	Permissions        []string          `json:"permissions"`
	PrimarySources     []string          `json:"primary_sources"`
	CommonOAuthEnabled bool              `json:"common_oauth_enabled"`
	RealQA             bool              `json:"real_qa"`
	FixedHeaders       map[string]string `json:"fixed_headers"`
	// These audit fields never configure authentication or execution.
	CredentialKind                  string `json:"credential_kind,omitempty"`
	OAuthRegistrationPerformed      bool   `json:"oauth_registration_performed,omitempty"`
	SecretInQuery                   bool   `json:"secret_in_query,omitempty"`
	CredentialHeaderOverrideAllowed bool   `json:"credential_header_override_allowed,omitempty"`
}
type reviewedPagination struct {
	Mode                     string   `json:"mode"`
	RequestArguments         []string `json:"request_arguments"`
	ResponseFields           []string `json:"response_fields"`
	AutomaticFollow          bool     `json:"automatic_follow"`
	ExternalNextURLsFollowed bool     `json:"external_next_urls_followed,omitempty"`
}
type reviewedResponse struct {
	JSONType               string   `json:"json_type"`
	RequiredFields         []string `json:"required_fields"`
	OutputProjection       []string `json:"output_projection"`
	ApplicationErrorFields []string `json:"application_error_fields"`
	SuccessField           *struct {
		Path  string `json:"path"`
		Value any    `json:"value"`
	} `json:"success_field,omitempty"`
	UnknownFieldsNotReturned     bool `json:"unknown_fields_not_returned,omitempty"`
	ReturnedURLsFollowed         bool `json:"returned_urls_followed,omitempty"`
	PartialGraphQLErrorsRejected bool `json:"partial_graphql_errors_rejected,omitempty"`
}
type reviewedOperationContract struct {
	PrimarySources   []string           `json:"primary_sources"`
	Pagination       reviewedPagination `json:"pagination"`
	Response         reviewedResponse   `json:"response"`
	ExampleArguments json.RawMessage    `json:"example_arguments,omitempty"`
}
type reviewedDefinition struct {
	Catalog                 definitions.Catalog                  `json:"catalog"`
	Manifest                Manifest                             `json:"manifest"`
	Authentication          reviewedAuthentication               `json:"authentication"`
	Contracts               map[string]reviewedOperationContract `json:"operation_contracts"`
	Research                json.RawMessage                      `json:"research,omitempty"`
	IntegrationRequirements []string                             `json:"integration_requirements,omitempty"`
}
type reviewedDocument struct {
	SchemaVersion int                  `json:"schema_version"`
	BatchID       string               `json:"batch_id"`
	Status        string               `json:"status"`
	Providers     []reviewedDefinition `json:"providers"`
}
type reviewedOperation struct {
	contract             reviewedOperationContract
	schema, publicSchema *reviewedSchema
	publicJSON           json.RawMessage
	projection           *reviewedProjection
	cursorPath           []string
	cursorSchema         *reviewedSchema
	scopes               []string
}

// ReviewedBatchAdapter wraps the existing fixed-origin HTTP engine. Definitions
// are compiled SDK data; schema and response contracts are enforced here, never
// inferred from a successful status or supplied by an invocation.
type ReviewedBatchAdapter struct {
	definition reviewedDefinition
	http       *HTTPAdapter
	operations map[string]reviewedOperation
}

func reviewedDecode(raw []byte, target any) error {
	if _, e := microsoftGraphJSONBudget(raw, 500000, 32); e != nil {
		return errors.New("invalid reviewed connector definition")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if e := d.Decode(target); e != nil {
		return errors.New("unsupported reviewed connector definition")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid reviewed connector definition")
	}
	return nil
}
func reviewedSourceURLs(values []string) bool {
	if len(values) == 0 || len(values) > 16 {
		return false
	}
	for _, raw := range values {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(raw) > 2048 {
			return false
		}
	}
	return true
}
func loadReviewedDefinitions() ([]reviewedDefinition, error) {
	docs, e := definitions.Documents()
	if e != nil {
		return nil, e
	}
	out := []reviewedDefinition{}
	ids, providers, tools := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, raw := range docs {
		var doc reviewedDocument
		if reviewedDecode(raw, &doc) != nil || doc.SchemaVersion != 1 || doc.BatchID == "" || doc.Status == "" || len(doc.Providers) == 0 || len(doc.Providers) > 100 {
			return nil, errors.New("invalid reviewed connector batch")
		}
		for _, def := range doc.Providers {
			if ids[def.Catalog.ID] || providers[def.Manifest.Provider] {
				return nil, errors.New("duplicate reviewed connector identity")
			}
			ids[def.Catalog.ID], providers[def.Manifest.Provider] = true, true
			for _, op := range def.Manifest.Operations {
				if tools[op.Name] {
					return nil, errors.New("duplicate reviewed connector operation")
				}
				tools[op.Name] = true
			}
			out = append(out, def)
		}
	}
	return out, nil
}

var reviewedCatalogOnce sync.Once
var reviewedCatalogCache []definitions.Catalog
var reviewedCatalogError error

func ReviewedBatchCatalog() ([]definitions.Catalog, error) {
	reviewedCatalogOnce.Do(func() { reviewedCatalogCache, reviewedCatalogError = buildReviewedBatchCatalog() })
	if reviewedCatalogError != nil {
		return nil, reviewedCatalogError
	}
	out := append([]definitions.Catalog(nil), reviewedCatalogCache...)
	for i := range out {
		out[i].ReadTools = append([]string(nil), out[i].ReadTools...)
		out[i].AgentTools = []string{}
	}
	return out, nil
}
func buildReviewedBatchCatalog() ([]definitions.Catalog, error) {
	defs, e := loadReviewedDefinitions()
	if e != nil {
		return nil, e
	}
	out := []definitions.Catalog{}
	for _, def := range defs {
		if _, e := newReviewedBatchAdapter(def, secureHTTPDoer()); e != nil {
			return nil, e
		}
		item := def.Catalog
		item.SetupURL, item.SetupInstructions = reviewedSetup(def)
		item.Available = true
		item.ReadTools = append([]string(nil), item.ReadTools...)
		item.AgentTools = []string{}
		out = append(out, item)
	}
	return out, nil
}
func reviewedBatchAdapters(doer HTTPDoer) ([]domain.Adapter, error) {
	defs, e := loadReviewedDefinitions()
	if e != nil {
		return nil, e
	}
	out := []domain.Adapter{}
	for _, def := range defs {
		a, e := newReviewedBatchAdapter(def, doer)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, nil
}
func reviewedGraphQL(document string) bool {
	if len(document) == 0 || len(document) > 65536 {
		return false
	}
	tokens := regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*|[{}]`).FindAllString(document, -1)
	if len(tokens) < 3 || tokens[0] != "query" && tokens[0] != "{" {
		return false
	}
	depth := 0
	for _, token := range tokens {
		if token == "mutation" || token == "subscription" || strings.HasPrefix(token, "__") {
			return false
		}
		if token == "{" {
			depth++
		}
		if token == "}" {
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}
func reviewedSchemaAt(s *reviewedSchema, path []string) *reviewedSchema {
	for _, key := range path {
		if s == nil || s.kind != "object" {
			return nil
		}
		s = s.properties[key]
	}
	return s
}
func reviewedRemoveSchema(raw map[string]any, path []string) bool {
	if len(path) == 0 {
		return false
	}
	properties, ok := raw["properties"].(map[string]any)
	if !ok {
		return false
	}
	if len(path) > 1 {
		nested, ok := properties[path[0]].(map[string]any)
		return ok && reviewedRemoveSchema(nested, path[1:])
	}
	delete(properties, path[0])
	if values, ok := raw["required"].([]any); ok {
		keep := []any{}
		for _, value := range values {
			if value != path[0] {
				keep = append(keep, value)
			}
		}
		raw["required"] = keep
	}
	return true
}
func newReviewedBatchAdapter(def reviewedDefinition, doer HTTPDoer) (*ReviewedBatchAdapter, error) {
	fail := func() (*ReviewedBatchAdapter, error) {
		return nil, errors.New("unsupported reviewed connector contract")
	}
	m, c, auth := def.Manifest, def.Catalog, def.Authentication
	if doer == nil || !domain.ValidResourceID(c.ID) || c.Provider != m.Provider || c.Capability != string(m.Capability) || c.Name == "" || c.Description == "" || c.Category == "" || c.Icon == "" || c.Auth != "token" || len(c.AgentTools) != 0 || len(c.WriteTools) != 0 || len(c.ReadTools) != len(m.Operations) || !m.ReadOnly || !m.TypedOnly || m.OriginKind != OriginFixed || m.MaxRequestBytes > 1<<20 || m.MaxResponseBytes > 4<<20 || m.validate() != nil || auth.Mode != "manual_token" || auth.CommonOAuthEnabled || auth.RealQA || auth.OAuthRegistrationPerformed || auth.SecretInQuery || auth.CredentialHeaderOverrideAllowed || !reviewedSourceURLs(auth.PrimarySources) {
		return fail()
	}
	switch strings.ToLower(m.CredentialHeader) {
	case "cookie", "proxy-authorization", "host", "content-length", "content-type", "connection", "transfer-encoding", "te", "trailer", "upgrade", "referer", "origin", "user-agent", "accept", "accept-encoding":
		return fail()
	}
	for k, v := range auth.FixedHeaders {
		if !headerNamePattern.MatchString(k) || len(v) == 0 || len(v) > 1024 || !microsoftGraphText(v, 1024, false) || strings.EqualFold(k, m.CredentialHeader) {
			return fail()
		}
		switch strings.ToLower(k) {
		case "authorization", "cookie", "proxy-authorization", "host", "content-length", "content-type", "connection", "transfer-encoding":
			return fail()
		}
	}
	// A manually supplied API token carries no locally attested OAuth scopes.
	// Vendor permissions remain setup requirements; the provider enforces the
	// token's actual grants. Only this admitted manual-token contract is changed.
	// Never mutate the embedded definition or another adapter's operation list.
	m.Operations = append([]OperationManifest(nil), m.Operations...)
	for i := range m.Operations {
		m.Operations[i].RequiredScopes = nil
	}
	origin, e := fixedHTTPSOrigin(m.Origin)
	if e != nil {
		return fail()
	}
	if client, ok := doer.(*http.Client); ok {
		copy := *client
		copy.Jar = nil
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		doer = &copy
	}
	// Clone the request and header map; never mutate caller-owned transport state.
	isolated := reviewedHeaderDoer{next: doer, origin: origin.String(), headers: cloneStringMap(auth.FixedHeaders)}
	inner, e := NewHTTPAdapter(m, isolated)
	if e != nil {
		return fail()
	}
	a := &ReviewedBatchAdapter{definition: def, http: inner, operations: map[string]reviewedOperation{}}
	readNames := map[string]bool{}
	for _, name := range c.ReadTools {
		if readNames[name] {
			return fail()
		}
		readNames[name] = true
	}
	if len(def.Contracts) != len(m.Operations) {
		return fail()
	}
	for _, op := range m.Operations {
		if !readNames[op.Name] || op.Risk != domain.RiskRead || op.Origin != "" || op.Raw != nil || op.Sync != nil || op.RPCAction != "" || len(op.RPCActions) != 0 || op.InternalOnly || op.Retry.MaxAttempts != 1 || op.Retry.RetryableWrite || op.Retry.BaseDelay != 0 || op.Retry.MaxDelay != 0 || len(op.Retry.Statuses) > 0 || op.IdempotencyHeader != "" || op.GraphQLIdempotencyVariable != "" || op.GraphQLIDSearchFilter != nil || op.Method != "GET" && op.Method != "POST" || op.Method == "GET" && op.Body != BodyNone || op.Method == "POST" && op.Body != BodyJSON && op.Body != BodyGraphQL {
			return fail()
		}
		if op.Body == BodyGraphQL && !reviewedGraphQL(op.GraphQLDocument) || op.Body != BodyGraphQL && op.GraphQLDocument != "" {
			return fail()
		}
		contract, ok := def.Contracts[op.Name]
		if !ok || !reviewedSourceURLs(contract.PrimarySources) || contract.Pagination.AutomaticFollow || contract.Pagination.ExternalNextURLsFollowed || contract.Response.ReturnedURLsFollowed || contract.Response.JSONType != "object" && contract.Response.JSONType != "array" || len(contract.Response.OutputProjection) == 0 || len(contract.Response.OutputProjection) > 128 {
			return fail()
		}
		raw, e := microsoftGraphJSON(op.InputSchema)
		if e != nil {
			return fail()
		}
		schema, ok := compileReviewedSchema(raw, 0)
		if !ok || schema.kind != "object" {
			return fail()
		}
		compiled := reviewedOperation{contract: contract, schema: schema, projection: &reviewedProjection{}, scopes: append([]string(nil), op.RequiredScopes...)}
		for _, path := range contract.Response.OutputProjection {
			if contract.Pagination.Mode == "cursor" && len(contract.Pagination.ResponseFields) == 1 && path == contract.Pagination.ResponseFields[0] {
				continue
			}
			parts, ok := reviewedPath(path)
			if !ok || !compiled.projection.add(parts) {
				return fail()
			}
		}
		for _, paths := range [][]string{contract.Response.RequiredFields, contract.Response.ApplicationErrorFields} {
			for _, path := range paths {
				if _, ok := reviewedPath(path); !ok {
					return fail()
				}
			}
		}
		if f := contract.Response.SuccessField; f != nil {
			parts, ok := reviewedPath(f.Path)
			if !ok || len(parts) > 8 {
				return fail()
			}
			switch f.Value.(type) {
			case string, bool, json.Number, float64:
			default:
				return fail()
			}
		}
		if op.Body == BodyGraphQL {
			found := false
			for _, path := range contract.Response.ApplicationErrorFields {
				if path == "errors" {
					found = true
				}
			}
			if !found {
				return fail()
			}
		}
		// Every argument is either a fixed path/query slot, a body field, or an
		// explicitly checked connection fence. A GET cannot carry ignored arguments.
		consumed := map[string]bool{"connection_id": true, "provider": true, "expected_external_id": true}
		for _, match := range pathTemplatePattern.FindAllStringSubmatch(op.Path, -1) {
			consumed[match[1]] = true
			if schema.properties[match[1]] == nil || !schema.required[match[1]] {
				return fail()
			}
		}
		for key := range op.FixedQuery {
			if sensitiveQueryKey(key) {
				return fail()
			}
		}
		wireQueries := map[string]bool{}
		for arg, key := range op.Query {
			if wireQueries[key] {
				return fail()
			}
			if _, exists := op.FixedQuery[key]; exists {
				return fail()
			}
			wireQueries[key] = true
			consumed[arg] = true
			if schema.properties[arg] == nil || sensitiveQueryKey(key) {
				return fail()
			}
		}
		if op.Body == BodyNone {
			for key := range schema.properties {
				if !consumed[key] {
					return fail()
				}
			}
		}
		public := raw.(map[string]any)
		switch contract.Pagination.Mode {
		case "none", "first_page":
			for _, arg := range contract.Pagination.RequestArguments {
				if _, ok := reviewedPath(arg); !ok {
					return fail()
				}
			}
		case "cursor":
			if len(contract.Pagination.RequestArguments) != 1 || len(contract.Pagination.ResponseFields) != 1 {
				return fail()
			}
			parts, ok := reviewedPath(contract.Pagination.RequestArguments[0])
			if !ok || strings.Contains(contract.Pagination.RequestArguments[0], "[]") {
				return fail()
			}
			cursor := reviewedSchemaAt(schema, parts)
			if cursor == nil || cursor.kind != "string" || cursor.max > 8192 {
				return fail()
			}
			parent := reviewedSchemaAt(schema, parts[:len(parts)-1])
			if parent.required[parts[len(parts)-1]] {
				return fail()
			}
			responsePath, ok := reviewedPath(contract.Pagination.ResponseFields[0])
			if !ok || strings.Contains(contract.Pagination.ResponseFields[0], "[]") || len(responsePath) > 12 {
				return fail()
			}
			compiled.cursorPath, compiled.cursorSchema = parts, cursor
			if !reviewedRemoveSchema(public, parts) {
				return fail()
			}
			properties := public["properties"].(map[string]any)
			if _, exists := properties["page_token"]; exists {
				return fail()
			}
			properties["page_token"] = map[string]any{"type": "string", "minLength": json.Number("1"), "maxLength": json.Number("16384")}
		default:
			return fail()
		}
		publicSchema, ok := compileReviewedSchema(public, 0)
		if !ok {
			return fail()
		}
		compiled.publicSchema = publicSchema
		compiled.publicJSON, _ = json.Marshal(public)
		a.operations[op.Name] = compiled
	}
	return a, nil
}

type reviewedHeaderDoer struct {
	next    HTTPDoer
	origin  string
	headers map[string]string
}

func (d reviewedHeaderDoer) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme+"://"+req.URL.Host != d.origin || req.URL.User != nil || req.URL.Fragment != "" {
		return nil, domain.ErrDenied
	}
	copy := req.Clone(req.Context())
	copy.Header = req.Header.Clone()
	for k, v := range d.headers {
		copy.Header.Set(k, v)
	}
	return d.next.Do(copy)
}
func (a *ReviewedBatchAdapter) Provider() string { return a.definition.Manifest.Provider }
func (a *ReviewedBatchAdapter) Capability() domain.Capability {
	return a.definition.Manifest.Capability
}
func (a *ReviewedBatchAdapter) Operations() []domain.Operation {
	out := a.http.Operations()
	for i := range out {
		out[i].InputSchema = cloneBytes(a.operations[out[i].Name].publicJSON)
	}
	return out
}

type reviewedCursor struct {
	CredentialBinding string `json:"credential_binding"`
	Signature         string `json:"signature"`
	Connection        string `json:"connection"`
	Account           string `json:"account"`
	Provider          string `json:"provider"`
	Operation         string `json:"operation"`
	Binding           string `json:"binding"`
	Value             string `json:"value"`
}

func reviewedSet(v map[string]any, path []string, value any) bool {
	for _, key := range path[:len(path)-1] {
		next, ok := v[key].(map[string]any)
		if !ok {
			if _, exists := v[key]; exists {
				return false
			}
			next = map[string]any{}
			v[key] = next
		}
		v = next
	}
	v[path[len(path)-1]] = value
	return true
}
func (a *ReviewedBatchAdapter) prepare(inv domain.Invocation, authenticate bool) (domain.Invocation, reviewedOperation, string, error) {
	op, ok := a.operations[inv.Operation.Name]
	if !ok {
		return inv, op, "", domain.ErrUnsupported
	}
	if inv.ID == "" || inv.Operation.Provider != a.Provider() || inv.Operation.Capability != a.Capability() || inv.Operation.Risk != domain.RiskRead || inv.Operation.Mode != domain.OperationTyped || inv.Connection.Provider != a.Provider() || inv.Connection.Validate(inv.Principal.WorkspaceID, a.Capability()) != nil || inv.Principal.BoundConnectionID != "" && inv.Principal.BoundConnectionID != inv.Connection.ID || len(inv.Connection.Config) > 0 && string(bytes.TrimSpace(inv.Connection.Config)) != "{}" || !domain.GrantsScopes(inv.Connection.Scopes, op.scopes) {
		return inv, op, "", domain.ErrDenied
	}
	if len(inv.Arguments) == 0 || int64(len(inv.Arguments)) > a.definition.Manifest.MaxRequestBytes {
		return inv, op, "", domain.ErrInvalidArguments
	}
	v, e := microsoftGraphJSON(inv.Arguments)
	if e != nil || !op.publicSchema.valid(v) {
		return inv, op, "", domain.ErrInvalidArguments
	}
	args := v.(map[string]any)
	for key, want := range map[string]string{"connection_id": inv.Connection.ID, "provider": a.Provider(), "expected_external_id": inv.Connection.ExternalID} {
		if got, exists := args[key]; exists && got != want {
			return inv, op, "", domain.ErrDenied
		}
	}
	token, _ := args["page_token"].(string)
	delete(args, "page_token")
	canonical, _ := json.Marshal(struct {
		Config    json.RawMessage
		Arguments map[string]any
	}{inv.Connection.Config, args})
	sum := sha256.Sum256(canonical)
	binding := hex.EncodeToString(sum[:])
	if token != "" {
		if len(op.cursorPath) == 0 {
			return inv, op, "", domain.ErrInvalidArguments
		}
		raw, e := base64.RawURLEncoding.DecodeString(token)
		if e != nil || len(raw) > 12288 {
			return inv, op, "", domain.ErrInvalidArguments
		}
		var c reviewedCursor
		if reviewedDecode(raw, &c) != nil || c.Connection != inv.Connection.ID || c.Account != inv.Connection.ExternalID || c.Provider != a.Provider() || c.Operation != inv.Operation.Name || c.Binding != binding || !op.cursorSchema.valid(c.Value) || !reviewedSignatureFormat(c.Signature) || !reviewedSignatureFormat(c.CredentialBinding) || (authenticate && !reviewedVerifyCursor(c, inv.Credential)) || !reviewedSet(args, op.cursorPath, c.Value) {
			return inv, op, "", domain.ErrInvalidArguments
		}
	}
	if !op.schema.valid(args) {
		return inv, op, "", domain.ErrInvalidArguments
	}
	inv.Arguments, _ = json.Marshal(args)
	return inv, op, binding, nil
}
func (a *ReviewedBatchAdapter) Preview(inv domain.Invocation) (domain.ActionPreview, error) {
	prepared, _, _, e := a.prepare(inv, false)
	if e != nil {
		return domain.ActionPreview{}, e
	}
	preview, e := a.http.Preview(prepared)
	if e != nil {
		return domain.ActionPreview{}, e
	}
	for _, op := range a.definition.Manifest.Operations {
		if op.Name == inv.Operation.Name {
			preview.Path = op.Path
		}
	}
	return preview, nil
}
func (a *ReviewedBatchAdapter) Invoke(ctx context.Context, inv domain.Invocation) (domain.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	prepared, op, binding, e := a.prepare(inv, true)
	if e != nil {
		return domain.Result{}, e
	}
	if inv.Credential.IsNone() {
		return domain.Result{}, domain.ErrDenied
	}
	capture := &reviewedCaptureDoer{next: a.http.doer, maximum: a.definition.Manifest.MaxResponseBytes, credential: inv.Credential}
	engine := *a.http
	engine.doer = capture
	result, e := engine.Invoke(ctx, prepared)
	if capture.failure != nil {
		return domain.Result{}, capture.failure
	}
	if e != nil {
		return domain.Result{}, e
	}
	fail := func() (domain.Result, error) {
		return domain.Result{}, &domain.ProviderError{Kind: "invalid_response", StatusCode: result.ProviderStatus, Attempts: result.Attempts}
	}
	// The per-invocation capture preserves the exact strict JSON values before
	// the legacy decoder can discard duplicate keys or round integer IDs.
	v := capture.decoded
	if result.ProviderStatus != http.StatusOK || v == nil {
		return fail()
	}
	if op.contract.Response.JSONType == "object" {
		if _, ok := v.(map[string]any); !ok {
			return fail()
		}
	} else if _, ok := v.([]any); !ok {
		return fail()
	}
	errorsToCheck := append([]string{"error", "errors"}, op.contract.Response.ApplicationErrorFields...)
	for _, path := range errorsToCheck {
		parts, _ := reviewedPath(path)
		values, exists := reviewedPathValues(v, parts)
		if exists {
			for _, value := range values {
				if reviewedTruthy(value) {
					return fail()
				}
			}
		}
	}
	for _, path := range op.contract.Response.RequiredFields {
		parts, _ := reviewedPath(path)
		values, exists := reviewedPathValues(v, parts)
		if !exists {
			return fail()
		}
		for _, value := range values {
			if value == nil {
				return fail()
			}
		}
	}
	if f := op.contract.Response.SuccessField; f != nil {
		parts, _ := reviewedPath(f.Path)
		values, exists := reviewedPathValues(v, parts)
		if !exists || len(values) != 1 || !reflect.DeepEqual(values[0], f.Value) {
			return fail()
		}
	}
	clean, ok := op.projection.project(v)
	if !ok {
		return fail()
	}
	var next string
	if op.contract.Pagination.Mode == "cursor" {
		parts, _ := reviewedPath(op.contract.Pagination.ResponseFields[0])
		values, exists := reviewedPathValues(v, parts)
		if exists {
			if len(values) != 1 {
				return fail()
			}
			if values[0] != nil && values[0] != "" {
				next, ok = values[0].(string)
				if !ok || !op.cursorSchema.valid(next) || strings.Contains(next, "://") {
					return fail()
				}
			}
		}
	}
	cursorOutput := map[string]any{"data": clean}
	if next != "" {
		c := reviewedCursor{Connection: inv.Connection.ID, Account: inv.Connection.ExternalID, Provider: a.Provider(), Operation: inv.Operation.Name, Binding: binding, Value: next}
		c.CredentialBinding = reviewedCredentialBinding(inv.Credential)
		signature, err := reviewedCursorSignature(c, inv.Credential)
		if err != nil {
			return domain.Result{}, domain.ErrDenied
		}
		c.Signature = signature
		cursor, _ := json.Marshal(c)
		cursorOutput["next_page_token"] = base64.RawURLEncoding.EncodeToString(cursor)
	}
	if op.contract.Pagination.Mode == "cursor" {
		clean = cursorOutput
	}
	result.Data = clean
	result.ProviderID = ""
	return result, nil
}

var _ domain.Adapter = (*ReviewedBatchAdapter)(nil)

type reviewedCaptureDoer struct {
	next       HTTPDoer
	maximum    int64
	credential domain.Credential
	decoded    any
	failure    error
}

func (d *reviewedCaptureDoer) Do(req *http.Request) (*http.Response, error) {
	response, err := d.next.Do(req)
	if err != nil || response == nil {
		return response, err
	}
	if response.Body == nil {
		d.failure = &domain.ProviderError{Kind: "invalid_response", StatusCode: response.StatusCode, Attempts: 1}
		return nil, d.failure
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response, nil
	}
	raw, large, err := readBounded(response.Body, d.maximum)
	_ = response.Body.Close()
	if err != nil || large {
		d.failure = &domain.ProviderError{Kind: "invalid_response", StatusCode: response.StatusCode, Attempts: 1}
		return nil, d.failure
	}
	clean := d.credential.Redact(raw)
	decoded, err := microsoftGraphJSONBudget(clean, 100000, 32)
	if err != nil {
		d.failure = &domain.ProviderError{Kind: "invalid_response", StatusCode: response.StatusCode, Attempts: 1}
		return nil, d.failure
	}
	d.decoded = decoded
	response.Body = io.NopCloser(bytes.NewReader(raw))
	return response, nil
}

func reviewedCredentialBinding(credential domain.Credential) string {
	metadata, _ := credential.MarshalJSON()
	sum := sha256.Sum256(metadata)
	return hex.EncodeToString(sum[:])
}
func reviewedCursorSignature(cursor reviewedCursor, credential domain.Credential) (string, error) {
	cursor.Signature = ""
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", domain.ErrDenied
	}
	var signature string
	err = credential.WithSecret(time.Now().UTC(), func(_ domain.CredentialKind, secret []byte) error {
		keyMAC := hmac.New(sha256.New, secret)
		_, _ = keyMAC.Write([]byte("OpenAgent-Reviewed-Cursor-v1\x00"))
		key := keyMAC.Sum(nil)
		defer clear(key)
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(payload)
		signature = hex.EncodeToString(mac.Sum(nil))
		return nil
	})
	return signature, err
}
func reviewedVerifyCursor(cursor reviewedCursor, credential domain.Credential) bool {
	if cursor.CredentialBinding != reviewedCredentialBinding(credential) {
		return false
	}
	provided, err := hex.DecodeString(cursor.Signature)
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	expected, err := reviewedCursorSignature(cursor, credential)
	if err != nil {
		return false
	}
	decoded, _ := hex.DecodeString(expected)
	return hmac.Equal(provided, decoded)
}

func reviewedSetup(def reviewedDefinition) (string, string) {
	instructions := "Use your authorized API or access token. "
	switch def.Manifest.CredentialScheme {
	case "":
		instructions += "Paste the credential exactly as issued. "
	case "Basic":
		instructions += "Use the Base64-encoded credential value specified in the provider documentation, without the Basic prefix. "
	default:
		instructions += "Paste only the credential, without the " + def.Manifest.CredentialScheme + " prefix. "
	}
	if len(def.Authentication.Permissions) > 0 {
		permissions := strings.Join(def.Authentication.Permissions, "; ")
		if len(permissions) > 2048 {
			permissions = permissions[:2048]
		}
		instructions += "Required permissions: " + permissions + ". "
	}
	instructions += "This credential is supplied manually; replace it with the provider when it expires or is revoked."
	source := ""
	if len(def.Authentication.PrimarySources) > 0 {
		source = def.Authentication.PrimarySources[0]
	}
	return source, instructions
}

func reviewedSignatureFormat(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, e := hex.DecodeString(value)
	return e == nil && len(decoded) == sha256.Size
}
