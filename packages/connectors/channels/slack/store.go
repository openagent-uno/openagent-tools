package slackchannel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/openagent-uno/openagent-tools/packages/connectors/central"
)

const storeNamespace = "slack-channel/v1"

var (
	ErrStore       = errors.New("Slack channel store unavailable")
	ErrStoreUpdate = errors.New("Slack channel store update rejected")
)

// Store reuses the encrypted vault's atomic persistence and exclusive OS lock.
// Its path MUST be dedicated to this service, never the MCP credential vault.
// The service configuration owner must compare canonical paths before opening
// either vault. It must not open an MCP vault as a way of probing its contents:
// OpenVault itself performs recovery before returning to this wrapper.
type Store struct {
	vault *central.Vault
}

func (*Store) String() string   { return "[redacted Slack channel store]" }
func (*Store) GoString() string { return "[redacted Slack channel store]" }

func initializeState(value *state) {
	if value.Bindings == nil {
		value.Bindings = map[string]bindingRecord{}
	}
	if value.Grants == nil {
		value.Grants = map[string]BotGrant{}
	}
	if value.Transactions == nil {
		value.Transactions = map[string]transaction{}
	}
	if value.Deliveries == nil {
		value.Deliveries = map[string]Delivery{}
	}
	if value.Operations == nil {
		value.Operations = map[string]operation{}
	}
}

func channelState(vault central.VaultState) (state, bool, error) {
	var result state
	// A channel store must not repurpose or overwrite connector records.
	if len(vault.Connections) != 0 || len(vault.Invocations) != 0 {
		return result, false, ErrStore
	}
	raw, exists := vault.Extensions[storeNamespace]
	if exists {
		defer clear(raw)
		if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
			return result, false, ErrStore
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
			return state{}, false, ErrStore
		}
	}
	initializeState(&result)
	return result, exists, nil
}

// OpenStore opens one dedicated channel-state file. Ambiguous provider IO is
// never retried on restart: an interrupted operation has unknown outcome, and
// an interrupted rotating refresh requires an explicit new consent. Recovery
// must be durably committed before the Store is returned to its caller.
func OpenStore(path, keyID string, keys map[string][]byte) (*Store, error) {
	vault, err := central.OpenVault(path, keyID, keys)
	if err != nil {
		return nil, ErrStore
	}
	store := &Store{vault: vault}
	snapshot, err := vault.View()
	if err != nil {
		_ = vault.Close()
		return nil, ErrStore
	}
	value, exists, err := channelState(snapshot)
	if err != nil {
		_ = vault.Close()
		return nil, ErrStore
	}
	changed := !exists
	for _, record := range value.Operations {
		changed = changed || record.Status == "running"
	}
	for _, grant := range value.Grants {
		changed = changed || grant.Status == "refreshing"
	}
	if changed {
		err = store.Update(func(next *state) error {
			for id, record := range next.Operations {
				if record.Status == "running" {
					record.Status = "outcome_unknown"
					record.Result = nil
					next.Operations[id] = record
				}
			}
			for id, grant := range next.Grants {
				if grant.Status == "refreshing" {
					grant.Status = "reconnect_required"
					next.Grants[id] = grant
				}
			}
			return nil
		})
		if err != nil {
			_ = vault.Close()
			return nil, ErrStore
		}
	}
	return store, nil
}

// View returns a detached decrypted snapshot. The caller must not log, persist
// or retain grant tokens or provider payloads outside its authorized operation.
func (s *Store) View() (state, error) {
	if s == nil || s.vault == nil {
		return state{}, ErrStore
	}
	snapshot, err := s.vault.View()
	if err != nil {
		return state{}, ErrStore
	}
	value, _, err := channelState(snapshot)
	if err != nil {
		return state{}, ErrStore
	}
	return value, nil
}

// Update serializes with other readers/writers and publishes only a fully
// encoded, encrypted durable replacement. The callback must not reenter Store.
// Its error/panic details never cross this boundary. Unrelated extensions are
// preserved, and no connector record is created or changed by this service.
func (s *Store) Update(change func(*state) error) error {
	if s == nil || s.vault == nil || change == nil {
		return ErrStoreUpdate
	}
	var plaintext []byte
	defer func() { clear(plaintext) }()
	err := s.vault.Update(func(vault *central.VaultState) error {
		value, _, err := channelState(*vault)
		if err != nil {
			return ErrStoreUpdate
		}
		if change(&value) != nil {
			return ErrStoreUpdate
		}
		initializeState(&value)
		plaintext, err = json.Marshal(value)
		if err != nil {
			return ErrStoreUpdate
		}
		if vault.Extensions == nil {
			vault.Extensions = map[string]json.RawMessage{}
		}
		vault.Extensions[storeNamespace] = plaintext
		return nil
	})
	if err != nil {
		return ErrStoreUpdate
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil || s.vault == nil {
		return nil
	}
	if s.vault.Close() != nil {
		return ErrStore
	}
	return nil
}
