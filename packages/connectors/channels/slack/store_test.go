//go:build darwin || linux

package slackchannel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/central"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func storeKeys() map[string][]byte {
	return map[string][]byte{"current": bytes.Repeat([]byte{7}, 32)}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := OpenStore(path, "current", storeKeys())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStoreRestartEncryptedPayloadsACKAndDetachedViews(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.vault")
	store := openTestStore(t, path)
	if err := store.Update(func(next *state) error {
		next.Grants["grant"] = BotGrant{AccessToken: "synthetic-bot-token", RefreshToken: "synthetic-rotating-token", Status: "connected"}
		next.Deliveries["event"] = Delivery{Status: "acknowledged", Payload: json.RawMessage(`{"text":"synthetic-private-message"}`)}
		next.Operations["operation"] = operation{Status: "completed", Result: json.RawMessage(`{"ok":true}`)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	view, err := store.View()
	if err != nil {
		t.Fatal(err)
	}
	delete(view.Grants, "grant")
	view.Deliveries["event"] = Delivery{Status: "changed"}
	current, _ := store.View()
	if current.Grants["grant"].AccessToken != "synthetic-bot-token" || current.Deliveries["event"].Status != "acknowledged" {
		t.Fatal("a view mutated persisted state")
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.Contains(data, []byte("synthetic-")) || bytes.Contains(data, []byte("access_token")) || bytes.Contains(data, []byte("payload")) {
		t.Fatal("encrypted storage required")
	}
	for _, file := range []string{path, path + ".lock"} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private state and lock permissions required")
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatal("plaintext or temporary files retained")
	}
	_ = store.Close()
	store = openTestStore(t, path)
	current, err = store.View()
	if err != nil || current.Grants["grant"].RefreshToken != "synthetic-rotating-token" ||
		current.Deliveries["event"].Status != "acknowledged" || current.Operations["operation"].Status != "completed" {
		t.Fatal("restart lost durable grant, ACK or operation")
	}
}

func TestStoreStartupRecoveryIsDurableAndDoesNotRetryProviderIO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.vault")
	store := openTestStore(t, path)
	if err := store.Update(func(next *state) error {
		next.Grants["rotating"] = BotGrant{Status: "refreshing", AccessToken: "synthetic-old", RefreshToken: "synthetic-refresh", Version: 3}
		next.Grants["ready"] = BotGrant{Status: "connected", Version: 4}
		next.Operations["running"] = operation{Status: "running", Result: json.RawMessage(`{"stale":true}`)}
		next.Operations["done"] = operation{Status: "completed"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	store = openTestStore(t, path)
	view, err := store.View()
	if err != nil || view.Grants["rotating"].Status != "reconnect_required" || view.Grants["rotating"].Version != 3 ||
		view.Grants["ready"].Status != "connected" || view.Operations["running"].Status != "outcome_unknown" ||
		len(view.Operations["running"].Result) != 0 || view.Operations["done"].Status != "completed" {
		t.Fatal("ambiguous provider outcome was not fenced")
	}
	recovered, _ := os.ReadFile(path)
	_ = store.Close()
	store = openTestStore(t, path)
	view, err = store.View()
	again, _ := os.ReadFile(path)
	if err != nil || view.Grants["rotating"].Status != "reconnect_required" || view.Operations["running"].Status != "outcome_unknown" || !bytes.Equal(recovered, again) {
		t.Fatal("recovery was not committed before serving or was repeated")
	}
}

func TestStoreAbortedUpdateAndPanicLeaveCiphertextUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.vault")
	store := openTestStore(t, path)
	before, _ := os.ReadFile(path)
	cases := []func(*state) error{
		func(next *state) error {
			next.Grants["no-save"] = BotGrant{AccessToken: "synthetic-leak"}
			return errors.New("synthetic-secret-error")
		},
		func(next *state) error { next.Grants["no-save"] = BotGrant{}; panic("synthetic-secret-panic") },
		func(next *state) error {
			next.Deliveries["invalid"] = Delivery{Payload: json.RawMessage(`{`)}
			return nil
		},
	}
	for index, change := range cases {
		err := store.Update(change)
		after, _ := os.ReadFile(path)
		view, readErr := store.View()
		if !errors.Is(err, ErrStoreUpdate) || strings.Contains(err.Error(), "synthetic") || !bytes.Equal(before, after) || readErr != nil || len(view.Grants) != 0 || len(view.Deliveries) != 0 {
			t.Fatalf("aborted callback %d changed state or disclosed details", index)
		}
	}
}

func TestStorePreservesOtherExtensionsWithoutCreatingConnectorRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.vault")
	vault, err := central.OpenVault(path, "current", storeKeys())
	if err != nil {
		t.Fatal(err)
	}
	other := json.RawMessage(`{"format":1,"value":"other-service"}`)
	if err = vault.Update(func(next *central.VaultState) error {
		next.Extensions = map[string]json.RawMessage{"other/v1": other}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = vault.Close()
	store := openTestStore(t, path)
	if err = store.Update(func(next *state) error { next.Bindings["binding"] = bindingRecord{}; return nil }); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	vault, err = central.OpenVault(path, "current", storeKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	view, err := vault.View()
	if err != nil || !bytes.Equal(view.Extensions["other/v1"], other) || len(view.Connections) != 0 || len(view.Invocations) != 0 || len(view.Extensions[storeNamespace]) == 0 {
		t.Fatal("unrelated extension or connector state changed")
	}
}

func TestStoreRejectsUnknownFieldsOrNullStateWithoutRewrite(t *testing.T) {
	for _, raw := range []string{`null`, `{"unknown":true}`, `{"grants":{"grant":{"unknown":true}}}`, `{"deliveries":{"event":{"unknown":true}}}`} {
		t.Run(raw, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "channels.vault")
			vault, err := central.OpenVault(path, "current", storeKeys())
			if err != nil {
				t.Fatal(err)
			}
			if err = vault.Update(func(next *central.VaultState) error {
				next.Extensions = map[string]json.RawMessage{storeNamespace: json.RawMessage(raw)}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			_ = vault.Close()
			before, _ := os.ReadFile(path)
			store, err := OpenStore(path, "current", storeKeys())
			if store != nil || !errors.Is(err, ErrStore) {
				t.Fatal("unknown state was accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("invalid state was rewritten")
			}
		})
	}
}

func TestStoreExclusiveWriterAndSeparateMCPPath(t *testing.T) {
	dir := t.TempDir()
	mcpPath := filepath.Join(dir, "mcp.vault")
	mcp, err := central.OpenVault(mcpPath, "current", storeKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer mcp.Close()
	if err = mcp.Update(func(next *central.VaultState) error {
		next.Connections["mcp-connection"] = central.CredentialRecord{Token: oauth.Token{AccessToken: "synthetic-mcp-token"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(mcpPath)
	if second, err := OpenStore(mcpPath, "current", storeKeys()); second != nil || !errors.Is(err, ErrStore) {
		t.Fatal("MCP writer lock was bypassed")
	}
	path := filepath.Join(dir, "channels.vault")
	store := openTestStore(t, path)
	if second, err := OpenStore(path, "current", storeKeys()); second != nil || !errors.Is(err, ErrStore) {
		t.Fatal("second channel writer was accepted")
	}
	if err = store.Update(func(next *state) error { next.Bindings["binding"] = bindingRecord{}; return nil }); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(mcpPath)
	view, err := mcp.View()
	if err != nil || !bytes.Equal(before, after) || view.Connections["mcp-connection"].Token.AccessToken != "synthetic-mcp-token" || len(view.Extensions) != 0 {
		t.Fatal("channel storage modified the MCP vault")
	}
	_ = mcp.Close()
	if invalid, err := OpenStore(mcpPath, "current", storeKeys()); invalid != nil || !errors.Is(err, ErrStore) {
		t.Fatal("populated connector records were repurposed as channel state")
	}
	final, _ := os.ReadFile(mcpPath)
	if !bytes.Equal(before, final) {
		t.Fatal("populated connector vault was overwritten")
	}
}

func TestStoreWrongKeyTamperClosedAndRedaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.vault")
	store := openTestStore(t, path)
	if strings.Contains(fmt.Sprintf("%v %#v", store, store), "vault:") {
		t.Fatal("store formatting exposed internals")
	}
	_ = store.Close()
	if _, err := store.View(); !errors.Is(err, ErrStore) {
		t.Fatal("closed store remained readable")
	}
	if err := store.Update(func(*state) error { return nil }); !errors.Is(err, ErrStoreUpdate) {
		t.Fatal("closed store remained writable")
	}
	if wrong, err := OpenStore(path, "current", map[string][]byte{"current": bytes.Repeat([]byte{8}, 32)}); wrong != nil || !errors.Is(err, ErrStore) {
		t.Fatal("wrong key accepted")
	}
	data, _ := os.ReadFile(path)
	var envelope map[string]json.RawMessage
	if json.Unmarshal(data, &envelope) != nil {
		t.Fatal("missing encrypted envelope")
	}
	envelope["ciphertext"] = json.RawMessage(`"dGFtcGVyZWQ="`)
	data, _ = json.Marshal(envelope)
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("could not create tampered test fixture")
	}
	if tampered, err := OpenStore(path, "current", storeKeys()); tampered != nil || !errors.Is(err, ErrStore) {
		t.Fatal("tampered ciphertext accepted")
	}
}
