package providers

import (
	"context"
	"errors"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type budgetedAdapter struct {
	inner  domain.Adapter
	budget domain.ProviderCallBudget
}

func WithProviderCallBudget(inner domain.Adapter, budget domain.ProviderCallBudget) (domain.Adapter, error) {
	if inner == nil || budget == nil || inner.Provider() != "pipeboard" || inner.Capability() != domain.Ads {
		return nil, errors.New("Pipeboard call budget configuration is invalid")
	}
	if _, ok := inner.(domain.ActionPreviewer); !ok {
		return nil, errors.New("Pipeboard adapter does not support previews")
	}
	return &budgetedAdapter{inner: inner, budget: budget}, nil
}

func (a *budgetedAdapter) Provider() string               { return a.inner.Provider() }
func (a *budgetedAdapter) Capability() domain.Capability  { return a.inner.Capability() }
func (a *budgetedAdapter) Operations() []domain.Operation { return a.inner.Operations() }
func (a *budgetedAdapter) Preview(input domain.Invocation) (domain.ActionPreview, error) {
	return a.inner.(domain.ActionPreviewer).Preview(input)
}

func (a *budgetedAdapter) Invoke(ctx context.Context, invocation domain.Invocation) (domain.Result, error) {
	source := "interactive"
	if invocation.Principal.ActorID == "connector-sync" {
		source = "sync"
	}
	allowance, err := a.budget.ReserveProviderCall(
		ctx,
		invocation.Connection.WorkspaceID,
		invocation.Connection.ID,
		domain.ProviderCallReservation{
			Provider: a.Provider(), Source: source, Operation: invocation.Operation.Name,
		},
	)
	if err != nil {
		return domain.Result{}, err
	}
	if !allowance.Allowed {
		return domain.Result{}, &domain.ProviderError{Kind: "provider_quota_exceeded", StatusCode: 429}
	}
	return a.inner.Invoke(ctx, invocation)
}
