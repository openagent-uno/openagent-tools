package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

// Only these two trusted-host protocol requests negotiate privacy receipts.
// The SDK never infers v2 capability from its own package version.
func receiptObject(raw json.RawMessage, allowed map[string]bool) (map[string]json.RawMessage, error) {
	result := map[string]json.RawMessage{}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return result, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, auth.ErrDenied
	}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] {
			return nil, auth.ErrDenied
		}
		if _, exists := result[name]; exists {
			return nil, auth.ErrDenied
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, auth.ErrDenied
		}
		result[name] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, auth.ErrDenied
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, auth.ErrDenied
	}
	return result, nil
}

func eventsReceiptVersion(raw json.RawMessage) (int, error) {
	params, err := receiptObject(raw, map[string]bool{"receipt_version": true})
	if err != nil {
		return 0, err
	}
	if len(params) == 0 {
		return 1, nil
	}
	var version int
	if json.Unmarshal(params["receipt_version"], &version) != nil || (version != 1 && version != 2) {
		return 0, auth.ErrDenied
	}
	return version, nil
}

func startReceiptParams(raw json.RawMessage) (auth.Start, error) {
	var start auth.Start
	params, err := receiptObject(raw, map[string]bool{"provider": true, "shop": true, "scopes": true, "receipt_version": true})
	if err != nil {
		return start, err
	}
	encoded, err := json.Marshal(params)
	if err != nil || json.Unmarshal(encoded, &start) != nil || start.Provider == "" {
		return start, auth.ErrDenied
	}
	if _, ok := params["receipt_version"]; ok && (start.ReceiptVersion != 1 && start.ReceiptVersion != 2) {
		return start, auth.ErrDenied
	}
	return start, nil
}

func dispatchEvents(ctx context.Context, client *auth.Client, raw json.RawMessage) (any, error) {
	version, err := eventsReceiptVersion(raw)
	if err != nil {
		return nil, err
	}
	if version == 2 {
		return client.EventsV2(ctx)
	}
	return client.Events(ctx)
}
