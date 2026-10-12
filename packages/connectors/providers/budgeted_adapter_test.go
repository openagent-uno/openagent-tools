package providers

import (
	"context"
	"errors"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type budgetTestAdapter struct{ calls int }

func (*budgetTestAdapter) Provider() string              { return "pipeboard" }
func (*budgetTestAdapter) Capability() domain.Capability { return domain.Ads }
func (*budgetTestAdapter) Operations() []domain.Operation {
	return []domain.Operation{{Name: "ads.pipeboard.metrics.get", Provider: "pipeboard", Capability: domain.Ads, Risk: domain.RiskRead}}
}
func (*budgetTestAdapter) Preview(domain.Invocation) (domain.ActionPreview, error) {
	return domain.ActionPreview{Method: "POST", Path: "/mcp", Summary: "Pipeboard command"}, nil
}
func (a *budgetTestAdapter) Invoke(context.Context, domain.Invocation) (domain.Result, error) {
	a.calls++
	return domain.Result{Data: map[string]any{"ok": true}}, nil
}

type budgetTestStore struct {
	allowance   domain.ProviderCallAllowance
	reservation domain.ProviderCallReservation
}

func (s *budgetTestStore) ReserveProviderCall(_ context.Context, workspaceID, connectionID string, reservation domain.ProviderCallReservation) (domain.ProviderCallAllowance, error) {
	if workspaceID != "workspace-1" || connectionID != "connection-1" {
		return domain.ProviderCallAllowance{}, errors.New("unexpected reservation scope")
	}
	s.reservation = reservation
	return s.allowance, nil
}

func TestPipeboardBudgetReservesBeforeEveryProviderInvocation(t *testing.T) {
	for _, test := range []struct {
		name      string
		actorID   string
		allowed   bool
		source    string
		wantCalls int
	}{
		{name: "interactive reserve", actorID: "user-1", allowed: true, source: "interactive", wantCalls: 1},
		{name: "sync reserve", actorID: "connector-sync", allowed: true, source: "sync", wantCalls: 1},
		{name: "quota exhausted", actorID: "user-1", allowed: false, source: "interactive", wantCalls: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := &budgetTestAdapter{}
			budget := &budgetTestStore{allowance: domain.ProviderCallAllowance{Allowed: test.allowed, Limit: 30, SyncLimit: 18}}
			adapter, err := WithProviderCallBudget(inner, budget)
			if err != nil {
				t.Fatal(err)
			}
			_, invokeErr := adapter.Invoke(context.Background(), domain.Invocation{
				Principal:  domain.Principal{ActorID: test.actorID},
				Connection: domain.Connection{ID: "connection-1", WorkspaceID: "workspace-1"},
				Operation:  inner.Operations()[0],
			})
			if budget.reservation.Source != test.source || budget.reservation.Provider != "pipeboard" || budget.reservation.Operation != "ads.pipeboard.metrics.get" {
				t.Fatalf("reservation = %#v", budget.reservation)
			}
			if inner.calls != test.wantCalls {
				t.Fatalf("provider calls = %d, want %d", inner.calls, test.wantCalls)
			}
			if test.allowed && invokeErr != nil {
				t.Fatal(invokeErr)
			}
			if !test.allowed {
				var providerErr *domain.ProviderError
				if !errors.As(invokeErr, &providerErr) || providerErr.Kind != "provider_quota_exceeded" || providerErr.StatusCode != 429 {
					t.Fatalf("quota error = %v", invokeErr)
				}
			}
		})
	}
}
