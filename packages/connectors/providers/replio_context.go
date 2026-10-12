package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const (
	replioContextURL      = "https://api.replio.to/mcp/"
	replioContextID       = "glasspalace-replio-context"
	replioContextMaxBytes = 64 << 10
	replioContextRequest  = `{"jsonrpc":"2.0","id":"glasspalace-replio-context","method":"tools/call","params":{"name":"mcp_context","arguments":{}}}`
)

// Replio's REST routes bind the organization, but currently do not enforce the
// finer app/channel restrictions on organization API keys. Its stateless MCP
// mcp_context tool exposes the authenticated key's scope. Check it on every
// attempt before REST; never cache this authorization decision or accept scope
// supplied by the tool caller. A restricted or unknown context fails closed.
func (a *HTTPAdapter) validateReplioContext(ctx context.Context, invocation domain.Invocation, authorization string) (requestBytes, responseBytes int64, err error) {
	if validatePlatformCredential("replio", authorization) != nil {
		return 0, 0, domain.ErrProviderPermission
	}
	var config struct {
		OrganizationID string `json:"organization_id"`
	}
	if json.Unmarshal(invocation.Connection.Config, &config) != nil || !platformUUIDPattern.MatchString(config.OrganizationID) {
		return 0, 0, domain.ErrProviderPermission
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, replioContextURL, bytes.NewBufferString(replioContextRequest))
	if err != nil {
		return 0, 0, domain.ErrProviderPermission
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("MCP-Protocol-Version", "2025-03-26")
	request.Header.Set("User-Agent", "OpenAgent-Replio-Context/1")
	requestBytes = int64(len(replioContextRequest))
	response, err := a.doer.Do(request)
	if err != nil || response == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return requestBytes, 0, domain.ErrProviderPermission
	}
	if response.Body == nil {
		return requestBytes, 0, domain.ErrProviderPermission
	}
	defer response.Body.Close()
	data, tooLarge, err := readBounded(response.Body, replioContextMaxBytes)
	responseBytes = int64(len(data))
	if err != nil || tooLarge || response.StatusCode != http.StatusOK {
		return requestBytes, responseBytes, domain.ErrProviderPermission
	}
	raw, err := decodeMCPBody(data, response.Header.Get("Content-Type"))
	if err != nil || !validReplioContext(raw, config.OrganizationID) {
		// No response body, key metadata, request ID, or transport error leaves
		// this scope gate: any of them could contain credentials or private data.
		return requestBytes, responseBytes, domain.ErrProviderPermission
	}
	return requestBytes, responseBytes, nil
}

func validReplioContext(raw json.RawMessage, organizationID string) bool {
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Error   json.RawMessage `json:"error"`
		Result  struct {
			IsError           bool            `json:"isError"`
			StructuredContent json.RawMessage `json:"structuredContent"`
			Content           []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.JSONRPC != "2.0" || envelope.ID != replioContextID || envelope.Result.IsError ||
		(len(envelope.Error) > 0 && !bytes.Equal(bytes.TrimSpace(envelope.Error), []byte("null"))) {
		return false
	}
	contextData := envelope.Result.StructuredContent
	if len(contextData) == 0 {
		if len(envelope.Result.Content) != 1 || envelope.Result.Content[0].Type != "text" {
			return false
		}
		contextData = json.RawMessage(envelope.Result.Content[0].Text)
	}
	var result struct {
		OrganizationID string   `json:"organization_id"`
		Scopes         []string `json:"scopes"`
		AppIDs         []string `json:"app_ids"`
		ChannelIDs     []string `json:"channel_ids"`
	}
	if json.Unmarshal(contextData, &result) != nil || result.OrganizationID != organizationID ||
		result.Scopes == nil || result.AppIDs == nil || result.ChannelIDs == nil || len(result.AppIDs) != 0 || len(result.ChannelIDs) != 0 {
		return false
	}
	// Empty scopes and '*' are legacy unrestricted keys in Replio. Known
	// global grants do not narrow reads; reject everything else, including
	// malformed app:/channel: scopes and future restrictions we cannot enforce.
	for _, scope := range result.Scopes {
		switch scope {
		case "*", "mcp:read", "mcp:write", "threads:write", "channels:write":
		default:
			return false
		}
	}
	return true
}
