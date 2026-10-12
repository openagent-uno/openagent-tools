package providers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const (
	HiggsfieldMCPOrigin       = "https://mcp.higgsfield.ai"
	HiggsfieldMCPPath         = "/mcp"
	HiggsfieldSnapshotVersion = 1
	higgsfieldMaxSnapshot     = 256 << 10
	higgsfieldMaxRequest      = 8 << 20
	higgsfieldMaxResponse     = 16 << 20
	higgsfieldProtocolVersion = "2025-06-18"
)

var (
	higgsfieldOperationName = regexp.MustCompile(`^media\.higgsfield\.[a-z0-9][a-z0-9._-]{1,95}$`)
	higgsfieldDigest        = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	// V1 deliberately excludes identity/voice training surfaces. The remote
	// server may add them, but a reviewed snapshot containing one still fails
	// closed instead of silently widening the OpenAgent Media product.
	higgsfieldExcludedTool = regexp.MustCompile(`(?i)(?:^|[._-])(soul|face|voice|clone|train|identity)(?:$|[._-])`)
)

type HiggsfieldToolSnapshot struct {
	SchemaVersion int                     `json:"schema_version"`
	Provider      string                  `json:"provider"`
	Origin        string                  `json:"origin"`
	CapturedAt    string                  `json:"captured_at"`
	Operations    []HiggsfieldToolMapping `json:"operations"`
}

type HiggsfieldToolMapping struct {
	Name        string          `json:"name"`
	RemoteTool  string          `json:"remote_tool"`
	Description string          `json:"description"`
	Risk        domain.Risk     `json:"risk"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type HiggsfieldMCPAdapter struct {
	doer       HTTPDoer
	operations map[string]HiggsfieldToolMapping
	public     []domain.Operation
	now        func() time.Time
}

func LoadHiggsfieldMCPAdapter(snapshotPath, expectedSHA256 string, doer HTTPDoer) (*HiggsfieldMCPAdapter, error) {
	if snapshotPath == "" || expectedSHA256 == "" {
		return nil, errors.New("Higgsfield MCP snapshot path and SHA-256 are both required")
	}
	if !higgsfieldDigest.MatchString(expectedSHA256) {
		return nil, errors.New("Higgsfield MCP snapshot SHA-256 is invalid")
	}
	file, err := os.Open(snapshotPath)
	if err != nil {
		return nil, errors.New("Higgsfield MCP snapshot is unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, higgsfieldMaxSnapshot+1))
	if err != nil || len(raw) == 0 || len(raw) > higgsfieldMaxSnapshot {
		return nil, errors.New("Higgsfield MCP snapshot is invalid")
	}
	actual := sha256.Sum256(raw)
	expected, _ := hex.DecodeString(strings.ToLower(expectedSHA256))
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return nil, errors.New("Higgsfield MCP snapshot digest does not match the reviewed value")
	}
	var snapshot HiggsfieldToolSnapshot
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("Higgsfield MCP snapshot is not strict JSON")
	}
	return NewHiggsfieldMCPAdapter(snapshot, doer)
}

func NewHiggsfieldMCPAdapter(snapshot HiggsfieldToolSnapshot, doer HTTPDoer) (*HiggsfieldMCPAdapter, error) {
	if doer == nil {
		return nil, errors.New("Higgsfield MCP transport is required")
	}
	if snapshot.SchemaVersion != HiggsfieldSnapshotVersion ||
		snapshot.Provider != "higgsfield" ||
		snapshot.Origin != HiggsfieldMCPOrigin+HiggsfieldMCPPath {
		return nil, errors.New("Higgsfield MCP snapshot identity is invalid")
	}
	capturedAt, err := time.Parse(time.RFC3339, snapshot.CapturedAt)
	if err != nil || capturedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return nil, errors.New("Higgsfield MCP snapshot timestamp is invalid")
	}
	if len(snapshot.Operations) == 0 || len(snapshot.Operations) > 64 {
		return nil, errors.New("Higgsfield MCP snapshot must contain 1 to 64 reviewed operations")
	}
	operations := make(map[string]HiggsfieldToolMapping, len(snapshot.Operations))
	remoteNames := make(map[string]struct{}, len(snapshot.Operations))
	public := make([]domain.Operation, 0, len(snapshot.Operations))
	for _, mapping := range snapshot.Operations {
		if err := validateHiggsfieldMapping(mapping); err != nil {
			return nil, err
		}
		if _, duplicate := operations[mapping.Name]; duplicate {
			return nil, fmt.Errorf("duplicate Higgsfield operation %q", mapping.Name)
		}
		if _, duplicate := remoteNames[mapping.RemoteTool]; duplicate {
			return nil, fmt.Errorf("duplicate Higgsfield remote tool %q", mapping.RemoteTool)
		}
		operations[mapping.Name] = cloneHiggsfieldMapping(mapping)
		remoteNames[mapping.RemoteTool] = struct{}{}
		public = append(public, domain.Operation{
			Name: mapping.Name, Description: mapping.Description,
			Capability: domain.Media, Provider: "higgsfield", Risk: mapping.Risk,
			Mode: domain.OperationTyped, InputSchema: publicHiggsfieldSchema(mapping.InputSchema),
			Retry: domain.RetryPolicy{MaxAttempts: 1, SupportsIdempotency: false},
			Preview: domain.ActionPreview{
				Method:  http.MethodPost,
				Path:    HiggsfieldMCPPath + "#tools/call:" + mapping.RemoteTool,
				Summary: mapping.Description,
			},
		})
	}
	sort.Slice(public, func(i, j int) bool { return public[i].Name < public[j].Name })
	return &HiggsfieldMCPAdapter{
		doer: doer, operations: operations, public: public, now: time.Now,
	}, nil
}

func validateHiggsfieldMapping(mapping HiggsfieldToolMapping) error {
	if !higgsfieldOperationName.MatchString(mapping.Name) ||
		!safeToolName(mapping.RemoteTool) ||
		higgsfieldExcludedTool.MatchString(mapping.Name) ||
		higgsfieldExcludedTool.MatchString(mapping.RemoteTool) {
		return fmt.Errorf("Higgsfield operation %q is not in the V1 allowlist", mapping.Name)
	}
	if mapping.Description == "" || len(mapping.Description) > 512 ||
		strings.ContainsAny(mapping.Description, "\r\n\x00") {
		return fmt.Errorf("Higgsfield operation %q has an invalid description", mapping.Name)
	}
	if mapping.Risk != domain.RiskRead && mapping.Risk != domain.RiskSpend {
		return fmt.Errorf("Higgsfield operation %q must be classified read or spend", mapping.Name)
	}
	if len(mapping.InputSchema) == 0 || len(mapping.InputSchema) > 64<<10 ||
		validateHiggsfieldSchema(mapping.InputSchema) != nil {
		return fmt.Errorf("Higgsfield operation %q has an invalid input schema", mapping.Name)
	}
	return nil
}

func cloneHiggsfieldMapping(value HiggsfieldToolMapping) HiggsfieldToolMapping {
	value.InputSchema = append(json.RawMessage(nil), value.InputSchema...)
	return value
}

func publicHiggsfieldSchema(remote json.RawMessage) json.RawMessage {
	var schema map[string]any
	if json.Unmarshal(remote, &schema) != nil {
		return append(json.RawMessage(nil), remote...)
	}
	properties, _ := schema["properties"].(map[string]any)
	if properties == nil {
		properties = make(map[string]any)
		schema["properties"] = properties
	}
	properties["connection_id"] = map[string]any{
		"type": "string", "description": "OpenAgent Higgsfield connection identifier",
	}
	properties["provider"] = map[string]any{"type": "string", "enum": []string{"higgsfield"}}
	encoded, _ := json.Marshal(schema)
	return encoded
}

func (a *HiggsfieldMCPAdapter) Provider() string              { return "higgsfield" }
func (a *HiggsfieldMCPAdapter) Capability() domain.Capability { return domain.Media }
func (a *HiggsfieldMCPAdapter) Operations() []domain.Operation {
	result := make([]domain.Operation, len(a.public))
	copy(result, a.public)
	for index := range result {
		result[index].InputSchema = append(json.RawMessage(nil), result[index].InputSchema...)
	}
	return result
}

func (a *HiggsfieldMCPAdapter) Preview(invocation domain.Invocation) (domain.ActionPreview, error) {
	mapping, arguments, err := a.validateInvocation(invocation)
	if err != nil {
		return domain.ActionPreview{}, err
	}
	_ = arguments
	return domain.ActionPreview{
		Method:  http.MethodPost,
		Path:    HiggsfieldMCPPath + "#tools/call:" + mapping.RemoteTool,
		Summary: mapping.Description,
	}, nil
}

func (a *HiggsfieldMCPAdapter) Invoke(ctx context.Context, invocation domain.Invocation) (domain.Result, error) {
	mapping, arguments, err := a.validateInvocation(invocation)
	if err != nil {
		return domain.Result{}, err
	}
	initialize := map[string]any{
		"jsonrpc": "2.0", "id": invocation.ID + ":initialize", "method": "initialize",
		"params": map[string]any{
			"protocolVersion": higgsfieldProtocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]string{"name": "OpenAgent", "version": "1"},
		},
	}
	initializeResponse, sessionID, requestBytes, responseBytes, status, providerID, err :=
		a.call(ctx, invocation, initialize, "", true)
	if err != nil {
		return domain.Result{}, err
	}
	if err := validateMCPResponse(initializeResponse, invocation.ID+":initialize"); err != nil {
		return domain.Result{}, &domain.ProviderError{
			Kind: "provider_protocol_error", StatusCode: status, ProviderID: providerID,
			Attempts: 1, RequestBytes: requestBytes, ResponseBytes: responseBytes,
		}
	}
	notification := map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}
	_, _, notifyRequest, notifyResponse, _, _, err := a.call(
		ctx, invocation, notification, sessionID, false,
	)
	requestBytes += notifyRequest
	responseBytes += notifyResponse
	if err != nil {
		return domain.Result{}, err
	}
	callID := invocation.ID + ":call"
	call := map[string]any{
		"jsonrpc": "2.0", "id": callID, "method": "tools/call",
		"params": map[string]any{"name": mapping.RemoteTool, "arguments": arguments},
	}
	raw, _, callRequest, callResponse, status, providerID, err := a.call(
		ctx, invocation, call, sessionID, true,
	)
	requestBytes += callRequest
	responseBytes += callResponse
	if err != nil {
		return domain.Result{}, err
	}
	result, err := mcpResult(raw, callID)
	if err != nil {
		return domain.Result{}, &domain.ProviderError{
			Kind: "provider_operation_error", StatusCode: status, ProviderID: providerID,
			Attempts: 1, RequestBytes: requestBytes, ResponseBytes: responseBytes,
		}
	}
	return domain.Result{
		Data: result, ProviderID: providerID, ProviderStatus: status, Attempts: 1,
		RequestBytes: requestBytes, ResponseBytes: responseBytes,
		Metadata: map[string]string{
			"provider": "higgsfield", "protocol": "mcp", "snapshot": "reviewed",
			"remote_tool": mapping.RemoteTool,
		},
	}, nil
}

func (a *HiggsfieldMCPAdapter) validateInvocation(invocation domain.Invocation) (HiggsfieldToolMapping, map[string]any, error) {
	mapping, ok := a.operations[invocation.Operation.Name]
	if !ok || invocation.Operation.Provider != "higgsfield" ||
		invocation.Operation.Capability != domain.Media ||
		invocation.Connection.Provider != "higgsfield" {
		return HiggsfieldToolMapping{}, nil, domain.ErrUnsupported
	}
	if err := invocation.Connection.Validate(invocation.Principal.WorkspaceID, domain.Media); err != nil {
		return HiggsfieldToolMapping{}, nil, domain.ErrInvalidArguments
	}
	if len(invocation.Arguments) == 0 || len(invocation.Arguments) > higgsfieldMaxRequest {
		return HiggsfieldToolMapping{}, nil, domain.ErrInvalidArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(invocation.Arguments))
	decoder.UseNumber()
	var arguments map[string]any
	if decoder.Decode(&arguments) != nil || decoder.Decode(&struct{}{}) != io.EOF || arguments == nil {
		return HiggsfieldToolMapping{}, nil, domain.ErrInvalidArguments
	}
	if connectionID, present := arguments["connection_id"]; present {
		value, valid := connectionID.(string)
		if !valid || value != invocation.Connection.ID {
			return HiggsfieldToolMapping{}, nil, domain.ErrInvalidArguments
		}
	}
	if provider, present := arguments["provider"]; present {
		value, valid := provider.(string)
		if !valid || value != "higgsfield" {
			return HiggsfieldToolMapping{}, nil, domain.ErrInvalidArguments
		}
	}
	delete(arguments, "connection_id")
	delete(arguments, "provider")
	if validateHiggsfieldArguments(mapping.InputSchema, arguments) != nil {
		return HiggsfieldToolMapping{}, nil, domain.ErrInvalidArguments
	}
	return mapping, arguments, nil
}

func (a *HiggsfieldMCPAdapter) call(
	ctx context.Context,
	invocation domain.Invocation,
	payload map[string]any,
	sessionID string,
	expectResponse bool,
) (json.RawMessage, string, int64, int64, int, string, error) {
	body, err := json.Marshal(payload)
	if err != nil || len(body) > higgsfieldMaxRequest {
		return nil, "", 0, 0, 0, "", domain.ErrInvalidArguments
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, HiggsfieldMCPOrigin+HiggsfieldMCPPath, bytes.NewReader(body),
	)
	if err != nil {
		return nil, "", 0, 0, 0, "", domain.ErrInvalidArguments
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("MCP-Protocol-Version", higgsfieldProtocolVersion)
	request.Header.Set("User-Agent", "OpenAgent-Higgsfield-MCP/1")
	if sessionID != "" {
		request.Header.Set("MCP-Session-Id", sessionID)
	}
	if err := invocation.Credential.Apply(request.Header, "Authorization", "Bearer", a.now().UTC()); err != nil {
		return nil, "", int64(len(body)), 0, 0, "", &domain.ProviderError{
			Kind: "credential_error", Attempts: 1, RequestBytes: int64(len(body)),
		}
	}
	response, err := a.doer.Do(request)
	if err != nil || response == nil {
		return nil, "", int64(len(body)), 0, 0, "", &domain.ProviderError{
			Kind: "network_error", Attempts: 1, RequestBytes: int64(len(body)),
		}
	}
	data, tooLarge, readErr := readBounded(response.Body, higgsfieldMaxResponse)
	_ = response.Body.Close()
	data = invocation.Credential.Redact(data)
	providerID := providerRequestID(response.Header)
	if readErr != nil || tooLarge {
		kind := "response_error"
		if tooLarge {
			kind = "response_too_large"
		}
		return nil, "", int64(len(body)), int64(len(data)), response.StatusCode, providerID, &domain.ProviderError{
			Kind: kind, StatusCode: response.StatusCode, ProviderID: providerID,
			Attempts: 1, RequestBytes: int64(len(body)), ResponseBytes: int64(len(data)),
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		providerErr := &domain.ProviderError{
			Kind: "provider_error", StatusCode: response.StatusCode, ProviderID: providerID,
			Attempts: 1, RequestBytes: int64(len(body)), ResponseBytes: int64(len(data)),
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return nil, "", int64(len(body)), int64(len(data)), response.StatusCode, providerID,
				errors.Join(domain.ErrProviderPermission, providerErr)
		}
		return nil, "", int64(len(body)), int64(len(data)), response.StatusCode, providerID, providerErr
	}
	if !expectResponse && len(bytes.TrimSpace(data)) == 0 {
		return nil, caseInsensitiveHeader(response.Header, "MCP-Session-Id"), int64(len(body)), 0,
			response.StatusCode, providerID, nil
	}
	raw, err := decodeMCPBody(data, response.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", int64(len(body)), int64(len(data)), response.StatusCode, providerID, &domain.ProviderError{
			Kind: "provider_protocol_error", StatusCode: response.StatusCode, ProviderID: providerID,
			Attempts: 1, RequestBytes: int64(len(body)), ResponseBytes: int64(len(data)),
		}
	}
	return raw, caseInsensitiveHeader(response.Header, "MCP-Session-Id"), int64(len(body)), int64(len(data)),
		response.StatusCode, providerID, nil
}

func caseInsensitiveHeader(header http.Header, name string) string {
	if value := header.Get(name); value != "" {
		return value
	}
	for key, values := range header {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func decodeMCPBody(data []byte, contentType string) (json.RawMessage, error) {
	if strings.HasPrefix(strings.ToLower(contentType), "text/event-stream") {
		var latest json.RawMessage
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			candidate := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if bytes.Equal(candidate, []byte("[DONE]")) {
				continue
			}
			if json.Valid(candidate) {
				latest = append(json.RawMessage(nil), candidate...)
			}
		}
		if len(latest) == 0 {
			return nil, errors.New("MCP event stream contained no JSON response")
		}
		return latest, nil
	}
	if !json.Valid(data) {
		return nil, errors.New("MCP response is not JSON")
	}
	return append(json.RawMessage(nil), data...), nil
}

func validateMCPResponse(raw json.RawMessage, expectedID string) error {
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	errorValue := bytes.TrimSpace(response.Error)
	if json.Unmarshal(raw, &response) != nil || response.JSONRPC != "2.0" ||
		response.ID != expectedID ||
		(len(errorValue) > 0 && !bytes.Equal(errorValue, []byte("null"))) ||
		len(response.Result) == 0 {
		return errors.New("invalid MCP response")
	}
	return nil
}

func mcpResult(raw json.RawMessage, expectedID string) (map[string]any, error) {
	if err := validateMCPResponse(raw, expectedID); err != nil {
		return nil, err
	}
	var response struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return nil, errors.New("invalid MCP result")
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.UseNumber()
	var result map[string]any
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result == nil {
		return nil, errors.New("MCP result is not an object")
	}
	if isError, _ := result["isError"].(bool); isError {
		return nil, errors.New("remote MCP tool returned an error")
	}
	return result, nil
}
