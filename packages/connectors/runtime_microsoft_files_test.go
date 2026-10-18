package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestMicrosoftFilesRuntimeOnlyReadToolsAndBoundedFailures(t *testing.T) {
	for _, id := range []string{"onedrive", "sharepoint"} {
		item, ok := Lookup(id)
		if !ok || !item.Available || len(item.AgentTools) != 0 {
			t.Fatal("missing read-only catalog implementation")
		}
		scope := "Files.Read"
		if id == "sharepoint" {
			scope = "Sites.Read.All"
		}
		for _, status := range []int{401, 410, 429, 503} {
			d := &providerFailureDoer{status: status}
			runtime, err := NewRuntime(d)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := domain.NewCredential(domain.CredentialOAuth2Bearer, "token-secret", "Authorization", "Bearer", "fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			config := `{"drive_id":"drive!bound"}`
			if id == "sharepoint" {
				config = `{"drive_id":"drive!bound","site_id":"tenant.sharepoint.com,11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222"}`
			}
			binding := Binding{CatalogID: id, AllowWrite: false, Principal: domain.Principal{WorkspaceID: "workspace-one", ActorID: "owner"}, Connection: domain.Connection{ID: "connection-one", WorkspaceID: "workspace-one", Provider: id, Capability: domain.Files, Enabled: true, ExternalID: "verified-account", Config: json.RawMessage(config), Scopes: []string{scope}}}
			tools, err := runtime.Tools(binding)
			if err != nil || len(tools) != len(item.ReadTools) {
				t.Fatal("read tool visibility mismatch", err)
			}
			result, err := runtime.Invoke(context.Background(), Call{Binding: binding, Tool: "files." + id + ".items.get", Arguments: json.RawMessage(`{"item_id":"item!1"}`), Credential: credential, InvocationID: "files-error-fixture"})
			var safe *domain.ProviderError
			if !errors.As(err, &safe) || safe.StatusCode != status || safe.ProviderID != "" || safe.ResponseBytes != 0 || result.Data != nil || d.calls != 1 {
				t.Fatal("failure was not reduced or request retried", err)
			}
			binding.Connection.Scopes = []string{"Sites.Selected"}
			tools, err = runtime.Tools(binding)
			if err != nil || len(tools) != 0 {
				t.Fatal("Selected permission was silently widened")
			}
		}
	}
}
