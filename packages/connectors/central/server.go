package central

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// Executor is server-owned. Network requests cannot inject an adapter, URL,
// credential or replacement operation description into this boundary.
type Executor interface {
	Tools(connectors.Binding) ([]domain.Operation, error)
	Invoke(context.Context, connectors.Call) (domain.Result, error)
}

type Config struct {
	Auth     *auth.Server
	Vault    *Vault
	Registry *Registry
	Executor Executor
}

type Server struct {
	config Config
	gate   chan struct{}
}

func NewServer(config Config) (*Server, error) {
	if config.Auth == nil || config.Vault == nil || config.Registry == nil || config.Executor == nil {
		return nil, errors.New("central service configuration is incomplete")
	}
	if _, err := config.Vault.View(); err != nil {
		return nil, err
	}
	return &Server{config: config, gate: make(chan struct{}, 1)}, nil
}

// BuildDescriptors describes all compiled entries, but enables only explicit
// operator-qualified providers supported by this executor profile. Visibility
// is never evidence of provider approval. Shopify requires its separate privacy
// and rotation qualification and is not enrolled through central v1.
func BuildDescriptors(runtime *connectors.Runtime, qualified map[string]bool, providers map[string]oauth.Provider) []Descriptor {
	out := []Descriptor{}
	for _, entry := range connectors.Catalog() {
		item := entry.Item
		operations := []domain.Operation{}
		allowed := map[string]bool{}
		for _, name := range append(append([]string{}, item.ReadTools...), item.AgentTools...) {
			allowed[name] = true
		}
		for _, op := range runtime.Operations(item.Provider) {
			if allowed[op.Name] && !op.InternalOnly && op.Mode == domain.OperationTyped && op.Risk != domain.RiskRaw {
				operations = append(operations, op)
			}
		}
		item.ReadTools = []string{}
		item.AgentTools = []string{}
		for _, op := range operations {
			if op.Risk == domain.RiskRead {
				item.ReadTools = append(item.ReadTools, op.Name)
			} else {
				item.AgentTools = append(item.AgentTools, op.Name)
			}
		}
		item.Available = item.Available && entry.NativeKind == "" && len(operations) > 0 && qualified[item.ID]
		if !item.Available {
			item.UnavailableReason = "Central execution has not been qualified for this connector."
		}
		if item.Auth != "none" && item.Auth != "oauth" {
			item.Available = false
			item.UnavailableReason = "Central credential setup is not supported for this connector."
		}
		if item.Auth == "oauth" && providers[item.Provider].ID == "" {
			item.Available = false
			item.UnavailableReason = "Official OAuth is not configured on this service."
		}
		if item.Provider == "shopify" {
			item.Available = false
			item.UnavailableReason = "Central Shopify enrollment requires separate privacy and rotation qualification."
		}
		if item.Available {
			item.UnavailableReason = ""
		}
		interaction := "hosted"
		if item.Auth == "none" {
			interaction = "none"
		}
		descriptor := Descriptor{Item: item, Operations: operations, Setup: Setup{Mode: item.Auth, CredentialCustody: "service", Execution: "service", Interaction: interaction}}
		descriptor.ContractSHA256 = ComputeContract(descriptor)
		out = append(out, descriptor)
	}
	return out
}

func centralJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 4<<20 {
		http.Error(w, "central_response_unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
func centralFail(w http.ResponseWriter, status int, code string) {
	centralJSON(w, status, map[string]string{"error": code})
}
func strict(data []byte, value any) bool {
	return strictJSON(data, value) == nil
}
func recipientValid(r Recipient) bool {
	return cleanText(r.WorkspaceID, 128) && cleanText(r.SubjectID, 256)
}
func cleanText(s string, n int) bool {
	if len(s) == 0 || len(s) > n || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func recipientKey(r Recipient) string { b, _ := json.Marshal(r); return string(b) }
func randomHandle() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodGet && r.URL.Path == "/v1/registry/schema" {
		centralJSON(w, 200, json.RawMessage(ProtocolSchema()))
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/registry/catalog" {
		centralJSON(w, 200, s.config.Registry.Snapshot(time.Now().UTC()))
		return
	}
	// All state and execution routes have installation signatures. Registration
	// and browser consent remain on the unchanged broker routes.
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/v1/execution/connections") {
		centralFail(w, 404, "not_found")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		centralFail(w, 413, "request_too_large")
		return
	}
	installation, err := s.config.Auth.AuthenticateInstallation(r, body)
	if err != nil {
		centralFail(w, 401, "invalid_installation_signature")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "execution" || parts[2] != "connections" {
		centralFail(w, 404, "not_found")
		return
	}
	if len(parts) == 3 {
		var input CreateRequest
		if !strict(body, &input) {
			centralFail(w, 400, "invalid_request")
			return
		}
		if !s.enter(r.Context()) {
			centralFail(w, 503, "busy")
			return
		}
		defer s.leave()
		connection, err := s.create(installation, input)
		if err != nil {
			centralFail(w, 409, "connection_not_admitted")
			return
		}
		centralJSON(w, 201, connection)
		return
	}
	if len(parts) < 5 || !domain.ValidResourceID(parts[3]) {
		centralFail(w, 404, "not_found")
		return
	}
	id, action := parts[3], parts[4]
	if action == "invoke" && len(parts) == 5 {
		var input InvokeRequest
		if !strict(body, &input) || !recipientValid(input.Recipient) {
			centralFail(w, 400, "invalid_request")
			return
		}
		if !s.enter(r.Context()) {
			centralFail(w, 503, "busy")
			return
		}
		defer s.leave()
		result, err := s.invoke(r.Context(), installation, id, input)
		if err != nil {
			centralFail(w, 409, "invocation_not_admitted")
			return
		}
		centralJSON(w, 200, result)
		return
	}
	var envelope struct {
		Recipient Recipient `json:"recipient"`
	}
	if !strict(body, &envelope) || !recipientValid(envelope.Recipient) {
		centralFail(w, 400, "invalid_recipient")
		return
	}
	input := envelope.Recipient
	if action == "invocations" && len(parts) == 6 && domain.ValidResourceID(parts[5]) {
		record, err := s.record(installation, id, input)
		if err != nil {
			centralFail(w, 404, "connection_not_found")
			return
		}
		state, err := s.config.Vault.View()
		if err != nil {
			centralFail(w, 503, "vault_unavailable")
			return
		}
		inv, ok := state.Invocations[record.Public.ID+":"+parts[5]]
		if !ok {
			centralFail(w, 404, "invocation_not_found")
			return
		}
		centralJSON(w, 200, InvocationResult{InvocationID: parts[5], Status: inv.Status})
		return
	}
	if len(parts) != 5 {
		centralFail(w, 404, "not_found")
		return
	}
	if action == "status" {
		record, err := s.record(installation, id, input)
		if err != nil {
			centralFail(w, 404, "connection_not_found")
			return
		}
		if record.Public.Status == "pending" && record.TransactionID != "" {
			if !s.enter(r.Context()) {
				centralFail(w, 503, "busy")
				return
			}
			defer s.leave()
			record, err = s.record(installation, id, input)
			if err == nil && record.Public.Status == "pending" {
				var tx auth.Transaction
				tx, err = s.config.Auth.CentralTransaction(installation, record.TransactionID, recipientKey(input))
				if err == nil && tx.Status == "ready" {
					record, err = s.complete(r.Context(), installation, record)
				}
			}
			if err != nil {
				centralFail(w, 409, "connection_not_ready")
				return
			}
		}
		centralJSON(w, 200, record.Public)
		return
	}
	if action != "complete" && action != "refresh" && action != "disconnect" {
		centralFail(w, 404, "not_found")
		return
	}
	if !s.enter(r.Context()) {
		centralFail(w, 503, "busy")
		return
	}
	defer s.leave()
	record, err := s.record(installation, id, input)
	if err != nil {
		centralFail(w, 404, "connection_not_found")
		return
	}
	switch action {
	case "complete":
		record, err = s.complete(r.Context(), installation, record)
	case "refresh":
		record, err = s.refresh(r.Context(), installation, record)
	case "disconnect":
		err = s.config.Auth.WithCentralInstallation(installation, func() error {
			return s.config.Vault.Update(func(state *VaultState) error {
				current := state.Connections[id]
				current.Public.Status = "disconnected"
				current.Public.AuthorizationURL = ""
				current.Public.GrantRevision++
				current.Binding.Enabled = false
				current.Token = oauth.Token{}
				current.TransactionID = ""
				state.Connections[id] = current
				record = current
				return nil
			})
		})
	}
	if err != nil {
		centralFail(w, 409, "connection_not_ready")
		return
	}
	centralJSON(w, 200, record.Public)
}
func (s *Server) enter(ctx context.Context) bool {
	select {
	case s.gate <- struct{}{}:
		if ctx.Err() != nil {
			s.leave()
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}
func (s *Server) leave() { <-s.gate }
func (s *Server) record(i auth.Installation, id string, recipient Recipient) (CredentialRecord, error) {
	var record CredentialRecord
	err := s.config.Auth.WithCentralInstallation(i, func() error {
		state, err := s.config.Vault.View()
		if err != nil {
			return err
		}
		var ok bool
		record, ok = state.Connections[id]
		if !ok || record.Installation != i.ID || record.Public.Recipient != recipient {
			return auth.ErrDenied
		}
		return nil
	})
	return record, err
}
func safeConfig(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	if len(raw) > 256<<10 {
		return false
	}
	var object map[string]json.RawMessage
	if !strict(raw, &object) || object == nil {
		return false
	}
	var visit func(any) bool
	visit = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				key := strings.ToLower(k)
				if strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "password") || strings.Contains(key, "credential") || key == "authorization" || key == "api_key" || key == "apikey" {
					return false
				}
				if !visit(v) {
					return false
				}
			}
		case []any:
			for _, v := range x {
				if !visit(v) {
					return false
				}
			}
		}
		return true
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	return visit(value)
}
func (s *Server) create(i auth.Installation, input CreateRequest) (Connection, error) {
	d, ok := s.config.Registry.Lookup(input.CatalogID)
	if !ok || !d.Item.Available || d.Item.Provider == "shopify" || input.ContractSHA256 != d.ContractSHA256 || !recipientValid(input.Recipient) || len(input.Operations) == 0 || len(input.Operations) > 256 || !safeConfig(input.Config) {
		return Connection{}, auth.ErrDenied
	}
	names := map[string]domain.Operation{}
	for _, op := range d.Operations {
		names[op.Name] = op
	}
	allowed, seen, scopes := []string{}, map[string]bool{}, map[string]bool{}
	for _, name := range input.Operations {
		op, ok := names[name]
		if !ok || seen[name] || op.Risk == domain.RiskRaw {
			return Connection{}, auth.ErrDenied
		}
		seen[name] = true
		allowed = append(allowed, name)
		for _, scope := range op.RequiredScopes {
			scopes[scope] = true
		}
	}
	sort.Strings(allowed)
	id := randomHandle()
	scopeList := []string{}
	for scope := range scopes {
		scopeList = append(scopeList, scope)
	}
	sort.Strings(scopeList)
	record := CredentialRecord{Installation: i.ID, Public: Connection{Protocol: Protocol, ID: id, CatalogID: d.Item.ID, ContractSHA256: d.ContractSHA256, Recipient: input.Recipient, Operations: allowed, GrantRevision: 1, Status: "connected"}, Binding: domain.Connection{ID: id, WorkspaceID: input.Recipient.WorkspaceID, Capability: domain.Capability(d.Item.Capability), Provider: d.Item.Provider, DisplayName: d.Item.Name, Scopes: scopeList, Config: input.Config, Enabled: true}}
	if d.Item.Auth == "oauth" {
		// Workspace protocols with app-defined capabilities still need the existing
		// broker's configured scope contract when operations declare none.
		if len(scopeList) == 0 {
			scopeList = append([]string{}, s.config.Auth.Providers[d.Item.Provider].Scopes...)
		}
		tx, err := s.config.Auth.BeginCentral(i, auth.Start{Provider: d.Item.Provider, Scopes: scopeList}, recipientKey(input.Recipient))
		if err != nil {
			return Connection{}, err
		}
		record.TransactionID = tx.ID
		record.Public.Status = "pending"
		record.Public.AuthorizationURL = tx.AuthorizationURL
	} else if d.Item.Auth != "none" {
		return Connection{}, auth.ErrDenied
	}
	if err := record.Binding.Validate(input.Recipient.WorkspaceID, record.Binding.Capability); err != nil {
		return Connection{}, auth.ErrDenied
	}
	err := s.config.Auth.WithCentralInstallation(i, func() error {
		return s.config.Vault.Update(func(state *VaultState) error {
			if len(state.Connections) >= 10000 {
				return errors.New("connection limit")
			}
			state.Connections[id] = record
			return nil
		})
	})
	return record.Public, err
}
func (s *Server) current(record CredentialRecord) (Descriptor, error) {
	d, ok := s.config.Registry.Lookup(record.Public.CatalogID)
	if !ok || !d.Item.Available || d.ContractSHA256 != record.Public.ContractSHA256 || d.Item.Provider != record.Binding.Provider {
		return Descriptor{}, auth.ErrDenied
	}
	return d, nil
}
func (s *Server) complete(ctx context.Context, i auth.Installation, record CredentialRecord) (CredentialRecord, error) {
	if _, err := s.current(record); err != nil {
		return record, err
	}
	if record.Public.Status == "connected" {
		return record, nil
	}
	if record.Public.Status != "pending" || record.TransactionID == "" {
		return record, auth.ErrDenied
	}
	err := s.config.Auth.CompleteCentral(ctx, i, record.TransactionID, recipientKey(record.Public.Recipient), func(token oauth.Token) error {
		return s.config.Vault.Update(func(state *VaultState) error {
			current := state.Connections[record.Public.ID]
			if current.Public.Status != "pending" || current.Installation != i.ID || current.Public.Recipient != record.Public.Recipient {
				return auth.ErrDenied
			}
			current.Token = token
			current.Binding.Scopes = append([]string{}, token.Scopes...)
			current.Binding.ExternalID = token.ExternalID
			// Partial provider consent may narrow a grant, never leave tools
			// advertised as granted when their scopes were not returned.
			principal := domain.Principal{WorkspaceID: current.Public.Recipient.WorkspaceID, ActorID: current.Public.Recipient.SubjectID, BoundConnectionID: current.Public.ID}
			tools, err := s.config.Executor.Tools(connectors.Binding{CatalogID: current.Public.CatalogID, Connection: current.Binding, Principal: principal, AllowWrite: true})
			if err != nil {
				return auth.ErrDenied
			}
			available := map[string]bool{}
			for _, op := range tools {
				available[op.Name] = true
			}
			granted := []string{}
			for _, name := range current.Public.Operations {
				if available[name] {
					granted = append(granted, name)
				}
			}
			if len(granted) == 0 {
				return auth.ErrDenied
			}
			current.Public.Operations = granted
			current.Public.Status = "connected"
			current.Public.AuthorizationURL = ""
			current.TransactionID = ""
			state.Connections[current.Public.ID] = current
			record = current
			return nil
		})
	})
	return record, err
}
func (s *Server) refresh(ctx context.Context, i auth.Installation, record CredentialRecord) (CredentialRecord, error) {
	d, err := s.current(record)
	if err != nil || record.Public.Status != "connected" {
		return record, auth.ErrDenied
	}
	if d.Item.Auth == "none" {
		return record, nil
	}
	token, err := s.config.Auth.RefreshCentral(ctx, i, d.Item.Provider, record.Token)
	if err != nil {
		return record, err
	}
	err = s.config.Auth.WithCentralToken(i, d.Item.Provider, token, func() error {
		return s.config.Vault.Update(func(state *VaultState) error {
			current := state.Connections[record.Public.ID]
			if current.Public.Status != "connected" || current.Public.GrantRevision != record.Public.GrantRevision {
				return auth.ErrDenied
			}
			current.Token = token
			current.Binding.Scopes = append([]string{}, token.Scopes...)
			state.Connections[current.Public.ID] = current
			record = current
			return nil
		})
	})
	return record, err
}
func (s *Server) invoke(ctx context.Context, i auth.Installation, id string, input InvokeRequest) (InvocationResult, error) {
	record, err := s.record(i, id, input.Recipient)
	if err != nil {
		return InvocationResult{}, err
	}
	d, err := s.current(record)
	if err != nil || record.Public.Status != "connected" || input.ContractSHA256 != record.Public.ContractSHA256 || input.GrantRevision != record.Public.GrantRevision || !domain.ValidResourceID(input.InvocationID) || len(input.Arguments) == 0 || len(input.Arguments) > 256<<10 {
		return InvocationResult{}, auth.ErrDenied
	}
	permitted := false
	for _, name := range record.Public.Operations {
		if name == input.Operation {
			permitted = true
		}
	}
	var selected *domain.Operation
	for _, op := range d.Operations {
		if op.Name == input.Operation {
			copy := op
			selected = &copy
		}
	}
	if !permitted || selected == nil || selected.Risk == domain.RiskRaw || selected.Mode != domain.OperationTyped || selected.Risk != domain.RiskRead && !cleanText(input.ApprovalID, 256) {
		return InvocationResult{}, auth.ErrDenied
	}
	var args map[string]json.RawMessage
	if json.Unmarshal(input.Arguments, &args) != nil || args == nil {
		return InvocationResult{}, auth.ErrDenied
	}
	encoded, _ := json.Marshal(input)
	digest := sha256.Sum256(encoded)
	hash := hex.EncodeToString(digest[:])
	key := id + ":" + input.InvocationID
	state, err := s.config.Vault.View()
	if err != nil {
		return InvocationResult{}, err
	}
	if old, ok := state.Invocations[key]; ok {
		if old.BodySHA256 != hash {
			return InvocationResult{}, auth.ErrConflict
		}
		return InvocationResult{InvocationID: input.InvocationID, Status: old.Status}, nil
	}
	if record.Token.ExpiresAt != nil && !time.Now().Add(time.Minute).Before(*record.Token.ExpiresAt) {
		record, err = s.refresh(ctx, i, record)
		if err != nil {
			return InvocationResult{}, err
		}
	}
	principal := domain.Principal{WorkspaceID: record.Public.Recipient.WorkspaceID, ActorID: record.Public.Recipient.SubjectID, ActorType: "user", Role: "member", BoundConnectionID: id, ToolScope: append([]string{}, record.Public.Operations...)}
	binding := connectors.Binding{CatalogID: record.Public.CatalogID, Connection: record.Binding, Principal: principal, AllowWrite: selected.Risk != domain.RiskRead}
	tools, err := s.config.Executor.Tools(binding)
	if err != nil {
		return InvocationResult{}, err
	}
	exists := false
	for _, op := range tools {
		if op.Name == selected.Name {
			a, _ := json.Marshal(op)
			b, _ := json.Marshal(selected)
			exists = bytes.Equal(a, b)
		}
	}
	if !exists {
		return InvocationResult{}, auth.ErrDenied
	}
	credential, err := domain.NewCredential(domain.CredentialNone, "", "", "", "", nil)
	if d.Item.Auth == "oauth" {
		credential, err = domain.NewCredential(domain.CredentialOAuth2Bearer, record.Token.AccessToken, "Authorization", "Bearer", "central", record.Token.ExpiresAt)
	}
	if err != nil {
		return InvocationResult{}, auth.ErrDenied
	}
	admission := func() error {
		return s.config.Vault.Update(func(next *VaultState) error {
			if len(next.Invocations) >= 100000 {
				return errors.New("invocation limit")
			}
			if _, ok := next.Invocations[key]; ok {
				return auth.ErrConflict
			}
			next.Invocations[key] = InvocationRecord{ConnectionID: id, BodySHA256: hash, Status: "running", CreatedAt: time.Now().UTC(), Operation: input.Operation, ApprovalID: input.ApprovalID}
			return nil
		})
	}
	if d.Item.Auth == "oauth" {
		err = s.config.Auth.WithCentralToken(i, d.Item.Provider, record.Token, admission)
	} else {
		err = s.config.Auth.WithCentralInstallation(i, admission)
	}
	if err != nil {
		return InvocationResult{}, err
	}
	value, providerErr := s.config.Executor.Invoke(ctx, connectors.Call{Binding: binding, Tool: input.Operation, Arguments: input.Arguments, Credential: credential, InvocationID: input.InvocationID})
	status := "succeeded"
	if providerErr != nil {
		status = "failed"
		if selected.Risk != domain.RiskRead {
			status = "outcome_unknown"
		}
	}
	// Persist only admission/outcome metadata; never provider content or tokens
	// in idempotency/audit records. A repeated invocation never executes again.
	finish := func() error {
		return s.config.Vault.Update(func(next *VaultState) error {
			v := next.Invocations[key]
			v.Status = status
			next.Invocations[key] = v
			return nil
		})
	}
	if d.Item.Auth == "oauth" {
		err = s.config.Auth.WithCentralToken(i, d.Item.Provider, record.Token, finish)
	} else {
		err = s.config.Auth.WithCentralInstallation(i, finish)
	}
	if err != nil {
		return InvocationResult{}, err
	}
	result := InvocationResult{InvocationID: input.InvocationID, Status: status}
	if providerErr == nil {
		data, marshalErr := json.Marshal(value)
		if marshalErr == nil && len(data) < (4<<20)-4096 {
			data = credential.Redact(data)
			if record.Token.RefreshToken != "" {
				extra, e := domain.NewCredential(domain.CredentialAPIToken, record.Token.RefreshToken, "", "", "central", nil)
				if e != nil {
					return result, nil
				}
				data = extra.Redact(data)
			}
			if json.Unmarshal(data, &value) == nil {
				result.Result = &value
				result.ResultAvailable = true
			}
		}
	}
	return result, nil
}
