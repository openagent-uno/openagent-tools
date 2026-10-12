package providers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func reviewedHiggsfieldSnapshot() HiggsfieldToolSnapshot {
	return HiggsfieldToolSnapshot{
		SchemaVersion: HiggsfieldSnapshotVersion,
		Provider:      "higgsfield",
		Origin:        HiggsfieldMCPOrigin + HiggsfieldMCPPath,
		CapturedAt:    "2024-01-01T00:00:00Z",
		Operations: []HiggsfieldToolMapping{
			{
				Name: "media.higgsfield.history.list", RemoteTool: "list_history",
				Description: "List generation history", Risk: domain.RiskRead,
				InputSchema: json.RawMessage(`{"type":"object","properties":{"limit":{"type":"integer"}},"additionalProperties":false}`),
			},
			{
				Name: "media.higgsfield.images.generate", RemoteTool: "generate_image",
				Description: "Generate a reviewed image job", Risk: domain.RiskSpend,
				InputSchema: json.RawMessage(`{"type":"object","properties":{"prompt":{"type":"string"}},"required":["prompt"],"additionalProperties":false}`),
			},
		},
	}
}

func TestHiggsfieldSnapshotIsDigestPinnedAndFailClosed(t *testing.T) {
	snapshot := reviewedHiggsfieldSnapshot()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "higgsfield-tools.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	adapter, err := LoadHiggsfieldMCPAdapter(path, hex.EncodeToString(digest[:]), successDoer())
	if err != nil {
		t.Fatal(err)
	}
	operations := adapter.Operations()
	if len(operations) != 2 || operations[0].Name != "media.higgsfield.history.list" ||
		operations[1].Risk != domain.RiskSpend {
		t.Fatalf("operations=%#v", operations)
	}
	if !bytes.Contains(operations[1].InputSchema, []byte(`"connection_id"`)) {
		t.Fatalf("public schema is missing OpenAgent connection selection: %s", operations[1].InputSchema)
	}
	if _, err := LoadHiggsfieldMCPAdapter(path, strings.Repeat("0", 64), successDoer()); err == nil {
		t.Fatal("snapshot with an unreviewed digest was accepted")
	}

	snapshot.Operations[0].RemoteTool = "train_soul"
	if _, err := NewHiggsfieldMCPAdapter(snapshot, successDoer()); err == nil {
		t.Fatal("excluded identity-training tool was accepted")
	}
}

type recordingHiggsfieldDoer struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
}

func (d *recordingHiggsfieldDoer) Do(request *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(request.Body)
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	d.mu.Lock()
	index := len(d.requests)
	d.requests = append(d.requests, clone)
	d.bodies = append(d.bodies, body)
	d.mu.Unlock()
	switch index {
	case 0:
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"application/json"},
				"MCP-Session-Id": []string{"hf-session-1"},
			},
			Body: io.NopCloser(strings.NewReader(
				`{"jsonrpc":"2.0","id":"inv_1:initialize","result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"higgsfield","version":"1"}}}`,
			)),
		}, nil
	case 1:
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	default:
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"text/event-stream"},
				"X-Request-Id": []string{"hf-request-1"},
			},
			Body: io.NopCloser(strings.NewReader(
				"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"inv_1:call\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"queued\"}],\"structuredContent\":{\"job_id\":\"job-1\"}}}\n\n",
			)),
		}, nil
	}
}

func TestHiggsfieldAdapterUsesFixedOriginReviewedToolAndOAuthCredential(t *testing.T) {
	doer := &recordingHiggsfieldDoer{}
	adapter, err := NewHiggsfieldMCPAdapter(reviewedHiggsfieldSnapshot(), doer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := domain.NewCredential(
		domain.CredentialOAuth2Bearer, "higgsfield-oauth-token",
		"Authorization", "Bearer", "v1", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	operation := adapter.Operations()[1]
	result, err := adapter.Invoke(context.Background(), domain.Invocation{
		ID: "inv_1",
		Principal: domain.Principal{
			WorkspaceID: "ws-1", ActorID: "workspace-agent", Role: "agent",
		},
		Connection: domain.Connection{
			ID: "conn-higgsfield", WorkspaceID: "ws-1", Capability: domain.Media,
			Provider: "higgsfield", Enabled: true,
		},
		Credential: credential, Operation: operation,
		Arguments: json.RawMessage(`{"connection_id":"conn-higgsfield","provider":"higgsfield","prompt":"studio product shot"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderID != "hf-request-1" || result.Attempts != 1 {
		t.Fatalf("result=%#v", result)
	}
	doer.mu.Lock()
	defer doer.mu.Unlock()
	if len(doer.requests) != 3 {
		t.Fatalf("requests=%d", len(doer.requests))
	}
	for index, request := range doer.requests {
		if request.URL.String() != HiggsfieldMCPOrigin+HiggsfieldMCPPath {
			t.Fatalf("request %d escaped fixed origin: %s", index, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer higgsfield-oauth-token" {
			t.Fatalf("request %d has wrong credential target", index)
		}
	}
	if doer.requests[1].Header.Get("MCP-Session-Id") != "hf-session-1" ||
		doer.requests[2].Header.Get("MCP-Session-Id") != "hf-session-1" {
		t.Fatal("MCP session binding was not preserved")
	}
	var call struct {
		Method string `json:"method"`
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if json.Unmarshal(doer.bodies[2], &call) != nil ||
		call.Method != "tools/call" || call.Params.Name != "generate_image" {
		t.Fatalf("unexpected remote call: %s", doer.bodies[2])
	}
	if _, present := call.Params.Arguments["connection_id"]; present {
		t.Fatal("OpenAgent connection id leaked into remote tool arguments")
	}
	if _, present := call.Params.Arguments["provider"]; present {
		t.Fatal("OpenAgent provider discriminator leaked into remote tool arguments")
	}
}

func TestHiggsfieldAdapterValidatesReviewedSchemaAndExcludedInputs(t *testing.T) {
	t.Parallel()
	snapshot := reviewedHiggsfieldSnapshot()
	snapshot.Operations[1].InputSchema = json.RawMessage(`{
		"type":"object",
		"properties":{
			"model":{"type":"string","enum":["reviewed-model"]},
			"prompt":{"type":"string","minLength":1,"maxLength":20},
			"params":{"type":"object","maxProperties":4,"additionalProperties":true}
		},
		"required":["model","prompt"],
		"additionalProperties":false
	}`)
	adapter, err := NewHiggsfieldMCPAdapter(snapshot, successDoer())
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := domain.NewCredential(
		domain.CredentialOAuth2Bearer, "higgsfield-oauth-token",
		"Authorization", "Bearer", "v1", nil,
	)
	invocation := domain.Invocation{
		ID: "inv-schema",
		Principal: domain.Principal{
			WorkspaceID: "ws-1", ActorID: "workspace-agent", Role: "agent",
		},
		Connection: domain.Connection{
			ID: "conn-higgsfield", WorkspaceID: "ws-1", Capability: domain.Media,
			Provider: "higgsfield", Enabled: true,
		},
		Credential: credential, Operation: adapter.Operations()[1],
	}
	for name, arguments := range map[string]string{
		"unknown model":    `{"model":"unreviewed","prompt":"hello"}`,
		"unknown property": `{"model":"reviewed-model","prompt":"hello","url":"https://evil.example"}`,
		"wrong connection": `{"connection_id":"other","model":"reviewed-model","prompt":"hello"}`,
		"excluded face":    `{"model":"reviewed-model","prompt":"hello","params":{"face_id":"abc"}}`,
		"oversized prompt": `{"model":"reviewed-model","prompt":"this prompt is much too long"}`,
	} {
		t.Run(name, func(t *testing.T) {
			invocation.Arguments = json.RawMessage(arguments)
			if _, _, err := adapter.validateInvocation(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	invocation.Arguments = json.RawMessage(
		`{"connection_id":"conn-higgsfield","provider":"higgsfield","model":"reviewed-model","prompt":"hello","params":{"seed":1}}`,
	)
	_, arguments, err := adapter.validateInvocation(invocation)
	if err != nil || arguments["model"] != "reviewed-model" {
		t.Fatalf("arguments=%#v error=%v", arguments, err)
	}
}

func TestHiggsfieldSnapshotRejectsUnsupportedSchemaKeywords(t *testing.T) {
	t.Parallel()
	snapshot := reviewedHiggsfieldSnapshot()
	snapshot.Operations[0].InputSchema = json.RawMessage(
		`{"type":"object","properties":{},"oneOf":[{"type":"object"}]}`,
	)
	if _, err := NewHiggsfieldMCPAdapter(snapshot, successDoer()); err == nil {
		t.Fatal("snapshot with an unsupported schema keyword was accepted")
	}
}

func TestHiggsfieldSnapshotRejectsExcludedModelEnums(t *testing.T) {
	t.Parallel()
	snapshot := reviewedHiggsfieldSnapshot()
	snapshot.Operations[1].InputSchema = json.RawMessage(
		`{"type":"object","properties":{"model":{"type":"string","enum":["reviewed","soul_id_v2"]}},"required":["model"],"additionalProperties":false}`,
	)
	if _, err := NewHiggsfieldMCPAdapter(snapshot, successDoer()); err == nil {
		t.Fatal("snapshot with an excluded identity model enum was accepted")
	}
}
