package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// These are documented-example/schema fixtures with synthetic or public values,
// not observations of authenticated provider traffic or live OAuth qualification.
func TestReviewedDocumentedProviderDispatchFixtures(t *testing.T) {
	defs, err := loadReviewedDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	byProvider := map[string]reviewedDefinition{}
	for _, def := range defs {
		byProvider[def.Manifest.Provider] = def
	}
	files, err := filepath.Glob("../definitions/batch*/response-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no reviewed vendor response fixtures available")
	}
	covered := map[string]bool{}
	missing := map[string]string{}
	cases := 0
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			SchemaVersion     int    `json:"schema_version"`
			BatchID           string `json:"batch_id"`
			Status            string `json:"status,omitempty"`
			RealProviderCalls int    `json:"real_provider_calls,omitempty"`
			Note              string `json:"note,omitempty"`
			Cases             []struct {
				Provider        string          `json:"provider"`
				Operation       string          `json:"operation"`
				Arguments       json.RawMessage `json:"arguments"`
				Response        json.RawMessage `json:"response"`
				Status          int             `json:"status"`
				PrimarySource   string          `json:"primary_source"`
				ShapeSource     string          `json:"shape_source"`
				SyntheticValues bool            `json:"synthetic_values"`
			} `json:"cases"`
			Missing []struct {
				Provider      string `json:"provider"`
				Reason        string `json:"reason"`
				PrimarySource string `json:"primary_source"`
			} `json:"missing"`
		}
		if reviewedDecode(raw, &document) != nil || document.SchemaVersion != 1 || document.RealProviderCalls != 0 || document.BatchID != filepath.Base(filepath.Dir(file)) {
			t.Fatal("invalid documented response fixture")
		}
		if len(document.Missing) != 0 {
			t.Errorf("batch %s still has unresolved documented provider fixture gaps", document.BatchID)
		}
		for _, entry := range document.Missing {
			if entry.Reason == "" || byProvider[entry.Provider].Manifest.Provider == "" {
				t.Fatal("untracked fixture gap")
			}
			missing[entry.Provider] = entry.Reason
		}
		for _, entry := range document.Cases {
			entry := entry
			cases++
			t.Run(entry.Provider+"/"+entry.Operation, func(t *testing.T) {
				def, ok := byProvider[entry.Provider]
				if !ok || entry.Status != 200 || !reviewedSourceURLs([]string{entry.PrimarySource}) || entry.ShapeSource != "official_example" && entry.ShapeSource != "official_schema" {
					t.Fatal("unreviewed fixture provenance")
				}
				calls := 0
				a, err := newReviewedBatchAdapter(def, doerFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					if request.URL.Scheme+"://"+request.URL.Host != def.Manifest.Origin || request.Header.Get(def.Manifest.CredentialHeader) == "" || request.Method != "GET" && request.Method != "POST" {
						t.Fatal("provider request target/auth mismatch")
					}
					deadline, ok := request.Context().Deadline()
					if !ok || time.Until(deadline) > 31*time.Second {
						t.Fatal("missing finite deadline")
					}
					return reviewedResponseBody(200, string(entry.Response)), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				var selected domain.Operation
				for _, op := range a.Operations() {
					if op.Name == entry.Operation {
						selected = op
					}
				}
				if selected.Name == "" {
					t.Fatal("fixture operation unavailable")
				}
				value, err := microsoftGraphJSON(entry.Arguments)
				args, ok := value.(map[string]any)
				if err != nil || !ok {
					t.Fatal("fixture arguments invalid")
				}
				for key, value := range map[string]string{"connection_id": "fixture-connection", "provider": def.Manifest.Provider, "expected_external_id": "fixture-account"} {
					if a.operations[selected.Name].publicSchema.properties[key] != nil {
						args[key] = value
					}
				}
				arguments, _ := json.Marshal(args)
				credential, err := domain.NewCredential(domain.CredentialAPIToken, "c2FtcGxlLXVzZXI6c2FtcGxlLXRva2Vu", "", "", "fixture-v1", nil)
				if err != nil {
					t.Fatal(err)
				}
				inv := domain.Invocation{ID: "fixture-invocation", Principal: domain.Principal{WorkspaceID: "fixture-workspace", ActorID: "fixture-owner"}, Connection: domain.Connection{ID: "fixture-connection", WorkspaceID: "fixture-workspace", Provider: def.Manifest.Provider, Capability: def.Manifest.Capability, Enabled: true, ExternalID: "fixture-account", Scopes: nil, Config: json.RawMessage(`{}`)}, Operation: selected, Arguments: arguments, Credential: credential}
				if _, err = a.Preview(inv); err != nil || calls != 0 {
					t.Fatal("documented fixture preview failed", err)
				}
				result, err := a.Invoke(context.Background(), inv)
				if err != nil || calls != 1 || result.Data == nil || result.Attempts != 1 {
					t.Fatal("documented fixture invocation failed", err)
				}
				covered[entry.Provider] = true
			})
		}
	}
	// A fixture omission is explicit and reported, never an invented response or a
	// claim that an external API was reached. Release reporting must retain this.
	gaps := []string{}
	for provider := range byProvider {
		if !covered[provider] {
			reason, ok := missing[provider]
			if !ok {
				reason = "no documented response fixture"
			}
			t.Errorf("provider %s has no passing documented transport fixture: %s", provider, reason)
			gaps = append(gaps, provider+": "+reason)
		}
	}
	t.Logf("documented transport fixtures: cases=%d providers_passed=%d provider_calls=0; missing=%s", cases, len(covered), strings.Join(gaps, "; "))
}
