package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const keylessMCPProtocol = "2025-06-18"
const keylessMCPMaxRequest = 64 << 10
const keylessMCPMaxResponse = 4 << 20

// The compiled read-only subset is reviewed against official MCP sources:
// exa-labs/exa-mcp-server e9c3b0126a3373eb1aeaca162e84d0791ff4c7f7
// firecrawl/firecrawl-mcp-server 26a23f28ec22241cb16e2115f27a6370ce2a00e0
// Hosted keyless contracts: https://exa.ai/docs/get-started/exa-mcp and
// https://docs.firecrawl.dev/mcp-server/keyless. No paid/authenticated fallback.
type keylessMCPTool struct {
	name, remote, description string
	properties                map[string]any
	required                  []string
}

type KeylessMCPAdapter struct {
	provider string
	endpoint string
	doer     HTTPDoer
	tools    []keylessMCPTool
}

// NewKeylessMCPAdapter accepts only compiled providers and fixed endpoints.
// Neither connection config nor tool arguments can choose transport or tools.
func NewKeylessMCPAdapter(provider string, doer HTTPDoer) (*KeylessMCPAdapter, error) {
	if doer == nil {
		return nil, errors.New("keyless MCP transport is required")
	}
	a := &KeylessMCPAdapter{provider: provider, doer: doer}
	query := map[string]any{"type": "string", "minLength": 1, "maxLength": 2048}
	limit := map[string]any{"type": "integer", "minimum": 1, "maximum": 10}
	webURL := map[string]any{"type": "string", "minLength": 1, "maxLength": 2048, "description": "Public HTTP(S) page URL; no local hosts, IP literals or credentials."}
	switch provider {
	case "exa":
		a.endpoint = "https://mcp.exa.ai/mcp?tools=web_search_exa,web_fetch_exa"
		a.tools = []keylessMCPTool{
			{"files.exa.search", "web_search_exa", "Search the public web with Exa. Keyless provider limits apply.", map[string]any{"query": query, "numResults": limit}, []string{"query"}},
			{"files.exa.fetch", "web_fetch_exa", "Read up to five public web pages with Exa. Keyless provider limits apply.", map[string]any{"urls": map[string]any{"type": "array", "minItems": 1, "maxItems": 5, "items": webURL}, "maxCharacters": map[string]any{"type": "integer", "minimum": 1, "maximum": 20000}}, []string{"urls"}},
		}
	case "firecrawl":
		a.endpoint = "https://mcp.firecrawl.dev/v2/mcp"
		a.tools = []keylessMCPTool{
			{"files.firecrawl.search", "firecrawl_search", "Search the public web with Firecrawl. Keyless provider limits apply.", map[string]any{"query": query, "limit": limit}, []string{"query"}},
			{"files.firecrawl.scrape", "firecrawl_scrape", "Read a public page as Markdown with Firecrawl. Keyless provider limits apply.", map[string]any{"url": webURL, "onlyMainContent": map[string]any{"type": "boolean"}}, []string{"url"}},
		}
	default:
		return nil, domain.ErrUnsupported
	}
	return a, nil
}

func (a *KeylessMCPAdapter) Provider() string              { return a.provider }
func (a *KeylessMCPAdapter) Capability() domain.Capability { return domain.Files }
func (a *KeylessMCPAdapter) CredentialFree()               {}
func (a *KeylessMCPAdapter) Operations() []domain.Operation {
	operations := make([]domain.Operation, 0, len(a.tools))
	endpoint, _ := url.Parse(a.endpoint)
	for _, tool := range a.tools {
		properties := map[string]any{
			"connection_id": map[string]any{"type": "string", "description": "Must match the authorized connection."},
			"provider":      map[string]any{"type": "string", "enum": []string{a.provider}},
		}
		for key, value := range tool.properties {
			properties[key] = value
		}
		schema, _ := json.Marshal(map[string]any{"type": "object", "properties": properties, "required": tool.required, "additionalProperties": false})
		operations = append(operations, domain.Operation{
			Name: tool.name, Description: tool.description, Capability: domain.Files, Provider: a.provider,
			Risk: domain.RiskRead, Mode: domain.OperationTyped, InputSchema: schema,
			Retry:   domain.RetryPolicy{MaxAttempts: 1},
			Preview: domain.ActionPreview{Method: http.MethodPost, Path: endpoint.Path + "#tools/call:" + tool.remote, Summary: tool.description},
		})
	}
	return operations
}

func (a *KeylessMCPAdapter) arguments(inv domain.Invocation) (keylessMCPTool, map[string]any, error) {
	var tool keylessMCPTool
	for _, candidate := range a.tools {
		if candidate.name == inv.Operation.Name {
			tool = candidate
			break
		}
	}
	if tool.name == "" || inv.Operation.Provider != a.provider || inv.Operation.Capability != domain.Files || inv.Operation.Risk != domain.RiskRead || inv.Connection.Provider != a.provider || !inv.Credential.IsNone() {
		return tool, nil, domain.ErrDenied
	}
	if inv.ID == "" || len(inv.ID) > 256 || inv.Connection.Validate(inv.Principal.WorkspaceID, domain.Files) != nil {
		return tool, nil, domain.ErrDenied
	}
	// These providers have no account, endpoint, key or remote-tool configuration.
	var config map[string]json.RawMessage
	if len(inv.Connection.Config) > 0 && (json.Unmarshal(inv.Connection.Config, &config) != nil || config == nil || len(config) != 0) {
		return tool, nil, domain.ErrInvalidArguments
	}
	if len(inv.Arguments) == 0 || len(inv.Arguments) > keylessMCPMaxRequest {
		return tool, nil, domain.ErrInvalidArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(inv.Arguments))
	decoder.UseNumber()
	var args map[string]any
	if decoder.Decode(&args) != nil || args == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return tool, nil, domain.ErrInvalidArguments
	}
	for key, value := range args {
		switch key {
		case "connection_id":
			if value != inv.Connection.ID {
				return tool, nil, domain.ErrDenied
			}
		case "provider":
			if value != a.provider {
				return tool, nil, domain.ErrDenied
			}
		default:
			if _, allowed := tool.properties[key]; !allowed {
				return tool, nil, domain.ErrInvalidArguments
			}
		}
	}
	delete(args, "connection_id")
	delete(args, "provider")
	for _, key := range tool.required {
		if _, present := args[key]; !present {
			return tool, nil, domain.ErrInvalidArguments
		}
	}
	for key, value := range args {
		valid := false
		switch key {
		case "query":
			s, ok := value.(string)
			valid = ok && strings.TrimSpace(s) != "" && utf8.ValidString(s) && utf8.RuneCountInString(s) <= 2048 && !strings.ContainsRune(s, 0)
		case "numResults", "limit", "maxCharacters":
			n, ok := value.(json.Number)
			maximum := int64(10)
			if key == "maxCharacters" {
				maximum = 20000
			}
			integer, err := n.Int64()
			valid = ok && err == nil && integer >= 1 && integer <= maximum
		case "url":
			s, ok := value.(string)
			valid = ok && keylessPublicURL(s)
		case "urls":
			list, ok := value.([]any)
			valid = ok && len(list) >= 1 && len(list) <= 5
			for _, entry := range list {
				s, ok := entry.(string)
				if !ok || !keylessPublicURL(s) {
					valid = false
				}
			}
		case "onlyMainContent":
			_, valid = value.(bool)
		}
		if !valid {
			return tool, nil, domain.ErrInvalidArguments
		}
	}
	if a.provider == "firecrawl" && tool.remote == "firecrawl_scrape" {
		args["formats"] = []string{"markdown"}
	}
	return tool, args, nil
}

func keylessPublicURL(raw string) bool {
	if len(raw) > 2048 || strings.TrimSpace(raw) != raw {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if u.Port() != "" && u.Port() != "443" && u.Port() != "80" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

func (a *KeylessMCPAdapter) Invoke(ctx context.Context, inv domain.Invocation) (domain.Result, error) {
	tool, arguments, err := a.arguments(inv)
	if err != nil {
		return domain.Result{}, err
	}
	protocol := keylessMCPProtocol
	initID := inv.ID + ":initialize"
	init, session, reqBytes, respBytes, status, providerID, err := a.call(ctx, map[string]any{
		"jsonrpc": "2.0", "id": initID, "method": "initialize", "params": map[string]any{
			"protocolVersion": protocol, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "OpenAgent", "version": "1"},
		},
	}, "", protocol, true)
	if err != nil {
		return domain.Result{}, err
	}
	initialized, err := keylessMCPResult(init, initID)
	if err != nil {
		return domain.Result{}, &domain.ProviderError{Kind: "provider_protocol_error", StatusCode: status, Attempts: 1}
	}
	protocol, _ = initialized["protocolVersion"].(string)
	if protocol != "2025-06-18" && protocol != "2025-03-26" && protocol != "2024-11-05" {
		return domain.Result{}, &domain.ProviderError{Kind: "provider_protocol_error", Attempts: 1}
	}
	_, _, sent, received, _, _, err := a.call(ctx, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, session, protocol, false)
	reqBytes += sent
	respBytes += received
	if err != nil {
		return domain.Result{}, err
	}
	callID := inv.ID + ":call"
	raw, _, sent, received, status, providerID, err := a.call(ctx, map[string]any{
		"jsonrpc": "2.0", "id": callID, "method": "tools/call", "params": map[string]any{"name": tool.remote, "arguments": arguments},
	}, session, protocol, true)
	reqBytes += sent
	respBytes += received
	if err != nil {
		return domain.Result{}, err
	}
	result, err := keylessMCPResult(raw, callID)
	if err != nil {
		return domain.Result{}, &domain.ProviderError{Kind: "provider_operation_error", StatusCode: status, Attempts: 1, RequestBytes: reqBytes, ResponseBytes: respBytes}
	}
	return domain.Result{Data: result, ProviderID: providerID, ProviderStatus: status, Attempts: 1, RequestBytes: reqBytes, ResponseBytes: respBytes,
		Metadata: map[string]string{"provider": a.provider, "protocol": "mcp", "snapshot": "compiled-read-only-v1", "remote_tool": tool.remote}}, nil
}

// Reuse the shared envelope/isError checks, also rejecting structured tool errors.
func keylessMCPResult(raw json.RawMessage, id string) (map[string]any, error) {
	result, err := mcpResult(raw, id)
	if err == nil && pipeboardMCPResultError(result) {
		return nil, errors.New("MCP operation error")
	}
	return result, err
}

func (a *KeylessMCPAdapter) call(ctx context.Context, payload map[string]any, session, protocol string, expectResponse bool) (json.RawMessage, string, int64, int64, int, string, error) {
	body, err := json.Marshal(payload)
	if err != nil || len(body) > keylessMCPMaxRequest {
		return nil, "", 0, 0, 0, "", domain.ErrInvalidArguments
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "", 0, 0, 0, "", domain.ErrInvalidArguments
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", protocol)
	request.Header.Set("User-Agent", "OpenAgent-Keyless-MCP/1")
	if session != "" {
		request.Header.Set("MCP-Session-Id", session)
	}
	response, err := a.doer.Do(request)
	if err != nil || response == nil {
		return nil, "", int64(len(body)), 0, 0, "", &domain.ProviderError{Kind: "network_error", Attempts: 1}
	}
	if response.Body == nil {
		return nil, "", int64(len(body)), 0, response.StatusCode, "", &domain.ProviderError{Kind: "response_error", Attempts: 1}
	}
	defer response.Body.Close()
	if response.Request != nil && (response.Request.URL == nil || response.Request.URL.String() != a.endpoint) {
		return nil, "", int64(len(body)), 0, response.StatusCode, "", &domain.ProviderError{Kind: "provider_redirect_error", Attempts: 1}
	}
	data, tooLarge, err := readBounded(response.Body, keylessMCPMaxResponse)
	providerID := providerRequestID(response.Header)
	failure := func(kind string) (json.RawMessage, string, int64, int64, int, string, error) {
		return nil, "", int64(len(body)), int64(len(data)), response.StatusCode, providerID, &domain.ProviderError{Kind: kind, StatusCode: response.StatusCode, ProviderID: providerID, Attempts: 1, RequestBytes: int64(len(body)), ResponseBytes: int64(len(data))}
	}
	if err != nil || tooLarge {
		return failure("response_error")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return failure("provider_error")
	}
	newSession := caseInsensitiveHeader(response.Header, "MCP-Session-Id")
	if len(newSession) > 256 || strings.ContainsAny(newSession, "\r\n") {
		return failure("provider_protocol_error")
	}
	for _, ch := range newSession {
		if ch < 0x21 || ch > 0x7e {
			return failure("provider_protocol_error")
		}
	}
	if !expectResponse && len(bytes.TrimSpace(data)) == 0 {
		return nil, newSession, int64(len(body)), 0, response.StatusCode, providerID, nil
	}
	raw, err := decodeMCPBody(data, response.Header.Get("Content-Type"))
	if err != nil {
		return failure("provider_protocol_error")
	}
	return raw, newSession, int64(len(body)), int64(len(data)), response.StatusCode, providerID, nil
}
