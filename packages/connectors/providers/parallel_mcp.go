package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Validate the advertised Parallel output contract, not just HTTP200 or an MCP
// success envelope. No content, error payload or input is added to an error.
// Snapshot: docs/qualification/parallel-search-interface-2026-10-17.json.
func validateParallelMCPResult(result map[string]any, remote string, arguments map[string]any) error {
	invalid := errors.New("invalid Parallel tool output")
	var payload map[string]any
	if structured, present := result["structuredContent"]; present {
		payload, _ = structured.(map[string]any)
	} else {
		// Older MCP clients/servers can carry the same typed JSON as text. Do
		// not guess a payload out of arbitrary prose or concatenate blocks.
		content, _ := result["content"].([]any)
		if len(content) != 1 {
			return invalid
		}
		entry, _ := content[0].(map[string]any)
		text, ok := entry["text"].(string)
		if entry["type"] != "text" || !ok {
			return invalid
		}
		decoder := json.NewDecoder(bytes.NewBufferString(text))
		decoder.UseNumber()
		if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return invalid
		}
	}
	if payload == nil || !keylessMCPText(payload["session_id"], 100) {
		return invalid
	}
	idField := "search_id"
	if remote == "web_fetch" {
		idField = "extract_id"
	} else if remote != "web_search" {
		return invalid
	}
	if !keylessMCPText(payload[idField], 256) {
		return invalid
	}
	results, ok := payload["results"].([]any)
	if !ok || len(results) > 100 {
		return invalid
	}
	requested := map[string]bool{}
	if remote == "web_fetch" {
		failures, ok := payload["errors"].([]any)
		if !ok || len(failures) != 0 {
			return invalid
		}
		urls, ok := arguments["urls"].([]any)
		if !ok || len(urls) == 0 || len(results) != len(urls) {
			return invalid
		}
		for _, value := range urls {
			rawURL, ok := value.(string)
			if !ok || requested[rawURL] {
				return invalid
			}
			requested[rawURL] = true
		}
	}
	seen := map[string]bool{}
	for _, value := range results {
		row, ok := value.(map[string]any)
		if !ok {
			return invalid
		}
		rawURL, ok := row["url"].(string)
		// A search result may point at an anchor; the URL remains public.
		pageURL, _, _ := strings.Cut(rawURL, "#")
		if !ok || len(rawURL) > 2048 || !keylessPublicURL(pageURL) || seen[rawURL] ||
			(remote == "web_fetch" && !requested[rawURL]) {
			return invalid
		}
		seen[rawURL] = true
		excerpts, ok := row["excerpts"].([]any)
		if !ok || len(excerpts) == 0 || len(excerpts) > 1000 {
			return invalid
		}
		for _, excerpt := range excerpts {
			if !keylessMCPText(excerpt, keylessMCPMaxResponse) {
				return invalid
			}
		}
		// full_content=false is compiled, so unexpected full page text is not
		// accepted as the bounded excerpt-only operation requested by the host.
		if full, present := row["full_content"]; present && full != nil && full != "" {
			return invalid
		}
	}
	return nil
}
