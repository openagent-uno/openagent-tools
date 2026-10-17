package providers

import (
	"encoding/json"
	"strings"
	"testing"
)

// A noncompliant response must never turn a provider error into successful
// output merely by including a result field alongside its error field.
func TestMCPResponseRejectsErrorAlongsideResult(t *testing.T) {
	for _, errorValue := range []string{`{"code":-32000,"message":"private-provider-detail"}`, `"private-provider-detail"`, `false`, `{}`} {
		raw := json.RawMessage(`{"jsonrpc":"2.0","id":"expected","result":{"content":[]},"error":` + errorValue + `}`)
		if err := validateMCPResponse(raw, "expected"); err == nil || strings.Contains(err.Error(), "private-provider-detail") {
			t.Fatalf("envelope error was accepted or leaked: %v", err)
		}
		if _, err := mcpResult(raw, "expected"); err == nil {
			t.Fatal("provider error became successful tool output")
		}
	}
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":"expected","result":{"content":[]}}`,
		`{"jsonrpc":"2.0","id":"expected","result":{"content":[]},"error":null}`,
	} {
		if err := validateMCPResponse(json.RawMessage(raw), "expected"); err != nil {
			t.Fatalf("valid response rejected: %v", err)
		}
	}
}
