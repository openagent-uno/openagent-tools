package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"github.com/openagent-uno/openagent-tools/packages/connectors/providers"
)

// Runtime receives already authorized host bindings. Tool arguments never select a credential.
type Runtime struct{ adapters map[string]domain.Adapter }

func NewRuntime(client providers.HTTPDoer) (*Runtime, error) {
	if client == nil {
		runtime := &Runtime{adapters: map[string]domain.Adapter{}}
		for _, adapter := range providers.Catalog() {
			runtime.adapters[adapter.Provider()] = adapter
		}
		return runtime, nil
	}
	adapters, err := providers.CatalogWithDoer(client)
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{adapters: map[string]domain.Adapter{}}
	for _, adapter := range adapters {
		runtime.adapters[adapter.Provider()] = adapter
	}
	return runtime, nil
}

type Binding struct {
	CatalogID  string            `json:"catalog_id"`
	Connection domain.Connection `json:"connection"`
	Principal  domain.Principal  `json:"principal"`
	AllowWrite bool              `json:"allow_write"`
}
type Call struct {
	Binding        Binding           `json:"binding"`
	Tool           string            `json:"tool"`
	Arguments      json.RawMessage   `json:"arguments"`
	Credential     domain.Credential `json:"credential"`
	InvocationID   string            `json:"invocation_id"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
}

func (r *Runtime) Tools(binding Binding) ([]domain.Operation, error) {
	item, ok := Lookup(binding.CatalogID)
	if !ok || !item.Available || item.NativeKind != "" || item.Provider != binding.Connection.Provider || item.Capability != string(binding.Connection.Capability) {
		return nil, domain.ErrDenied
	}
	if binding.Connection.Validate(binding.Principal.WorkspaceID, binding.Connection.Capability) != nil {
		return nil, domain.ErrDenied
	}
	adapter := r.adapters[item.Provider]
	if adapter == nil {
		return nil, domain.ErrUnsupported
	}
	allowed := map[string]bool{}
	for _, tool := range item.ReadTools {
		allowed[tool] = true
	}
	if binding.AllowWrite {
		for _, tool := range item.AgentTools {
			allowed[tool] = true
		}
	}
	tools := []domain.Operation{}
	for _, tool := range adapter.Operations() {
		scopesGranted := domain.GrantsScopes(binding.Connection.Scopes, tool.RequiredScopes)
		if policy, ok := adapter.(domain.OperationScopePolicy); ok {
			scopesGranted = policy.OperationScopesGranted(binding.Connection.Scopes, tool.Name)
		}
		if allowed[tool.Name] && !tool.InternalOnly && scopesGranted {
			tools = append(tools, tool)
		}
	}
	return tools, nil
}
func (r *Runtime) Invoke(ctx context.Context, call Call) (domain.Result, error) {
	tools, err := r.Tools(call.Binding)
	if err != nil {
		return domain.Result{}, err
	}
	var selected *domain.Operation
	for _, tool := range tools {
		if tool.Name == call.Tool {
			copy := tool
			selected = &copy
			break
		}
	}
	if selected == nil {
		return domain.Result{}, domain.ErrDenied
	}
	item, _ := Lookup(call.Binding.CatalogID)
	_, credentialFree := r.adapters[item.Provider].(domain.CredentialFreeAdapter)
	if item.Auth == "none" {
		if !credentialFree || !call.Credential.IsNone() {
			return domain.Result{}, domain.ErrDenied
		}
	} else if call.Credential.IsNone() {
		return domain.Result{}, domain.ErrDenied
	}
	if call.InvocationID == "" || len(call.InvocationID) > 256 {
		return domain.Result{}, domain.ErrInvalidArguments
	}
	if len(call.Arguments) == 0 {
		call.Arguments = json.RawMessage(`{}`)
	}
	var arguments map[string]json.RawMessage
	if json.Unmarshal(call.Arguments, &arguments) != nil || arguments == nil {
		return domain.Result{}, domain.ErrInvalidArguments
	}
	if raw, exists := arguments["connection_id"]; exists {
		var id string
		if json.Unmarshal(raw, &id) != nil || id != call.Binding.Connection.ID {
			return domain.Result{}, domain.ErrDenied
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	result, err := r.adapters[call.Binding.Connection.Provider].Invoke(ctx, domain.Invocation{ID: call.InvocationID, Principal: call.Binding.Principal, Connection: call.Binding.Connection, Credential: call.Credential, Operation: *selected, Arguments: call.Arguments, RequestedAt: time.Now().UTC(), Idempotency: call.IdempotencyKey})
	if err != nil {
		return domain.Result{}, errors.New("connector provider request failed")
	}
	return result, nil
}
