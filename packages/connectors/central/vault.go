package central

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const maxVaultState = 32 << 20
const maxVaultEnvelope = (maxVaultState+1024)*4/3 + 4096

var (
	ErrVaultKey    = errors.New("central vault: invalid or unavailable encryption key")
	ErrVaultRead   = errors.New("central vault: cannot read encrypted state")
	ErrVaultState  = errors.New("central vault: invalid encrypted state")
	ErrVaultWrite  = errors.New("central vault: cannot durably persist encrypted state")
	ErrVaultUpdate = errors.New("central vault: update rejected")
	ErrVaultClosed = errors.New("central vault: unavailable or closed")
	ErrVaultInUse  = errors.New("central vault: path already open")
	ErrVaultLock   = errors.New("central vault: exclusive writer lock unavailable")
	vaultPaths     = struct {
		sync.Mutex
		paths map[string]bool
	}{paths: make(map[string]bool)}
)

type vaultEnvelope struct {
	Format     int    `json:"format"`
	KeyID      string `json:"key_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Vault is a single-writer encrypted state store. Linux and macOS hold an OS
// advisory lock until Close. Other platforms fail closed until a qualified OS
// lock is implemented. The host must provide a private local directory supporting
// atomic rename, file locks and directory fsync, never a shared multi-node mount.
// No stale-lock removal or multi-writer support exists.
// Views and callback values contain secrets: callers must not log or retain them.
type Vault struct {
	mu         sync.Mutex
	path       string
	keyID      string
	keys       map[string][]byte
	sealed     []byte
	closed     bool
	lock       *os.File
	registered bool
}

func (*Vault) String() string   { return "[redacted central vault]" }
func (*Vault) GoString() string { return "[redacted central vault]" }

func vaultAAD(format int, keyID string) []byte {
	b, _ := json.Marshal(struct {
		Format int    `json:"format"`
		KeyID  string `json:"key_id"`
	}{format, keyID})
	return b
}

func vaultJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrVaultState
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrVaultState
	}
	return nil
}

func (v *Vault) unseal(data []byte) (VaultState, error) {
	var state VaultState
	if len(data) > maxVaultEnvelope {
		return state, ErrVaultState
	}
	var envelope vaultEnvelope
	if vaultJSON(data, &envelope) != nil || envelope.Format != 1 || envelope.KeyID == "" {
		return state, ErrVaultState
	}
	key := v.keys[envelope.KeyID]
	if len(key) != 32 {
		return state, ErrVaultKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return state, ErrVaultKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(envelope.Nonce) != aead.NonceSize() {
		return state, ErrVaultState
	}
	plain, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, vaultAAD(envelope.Format, envelope.KeyID))
	if err != nil {
		return state, ErrVaultState
	}
	defer clear(plain)
	if len(plain) > maxVaultState || vaultJSON(plain, &state) != nil {
		return VaultState{}, ErrVaultState
	}
	if state.Connections == nil {
		state.Connections = make(map[string]CredentialRecord)
	}
	if state.Invocations == nil {
		state.Invocations = make(map[string]InvocationRecord)
	}
	return state, nil
}

func (v *Vault) seal(state VaultState) ([]byte, error) {
	plain, err := json.Marshal(state)
	if plain != nil {
		defer clear(plain)
	}
	if err != nil || len(plain) > maxVaultState {
		return nil, ErrVaultState
	}
	block, err := aes.NewCipher(v.keys[v.keyID])
	if err != nil {
		return nil, ErrVaultKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrVaultKey
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrVaultWrite
	}
	envelope := vaultEnvelope{Format: 1, KeyID: v.keyID, Nonce: nonce}
	envelope.Ciphertext = aead.Seal(nil, nonce, plain, vaultAAD(1, v.keyID))
	result, err := json.Marshal(envelope)
	if err != nil {
		return nil, ErrVaultState
	}
	return result, nil
}

// persist returns whether rename has occurred. An error after rename poisons
// the instance: disk may have the new state, so only reopening can recover it.
func (v *Vault) persist(sealed []byte) (renamed bool, err error) {
	dir := filepath.Dir(v.path)
	file, err := os.CreateTemp(dir, ".central-vault-*")
	if err != nil {
		return false, ErrVaultWrite
	}
	name := file.Name()
	defer func() { _ = file.Close(); _ = os.Remove(name) }()
	if file.Chmod(0600) != nil {
		return false, ErrVaultWrite
	}
	if n, e := file.Write(sealed); e != nil || n != len(sealed) {
		return false, ErrVaultWrite
	}
	if file.Sync() != nil || file.Close() != nil {
		return false, ErrVaultWrite
	}
	if os.Rename(name, v.path) != nil {
		return false, ErrVaultWrite
	}
	renamed = true
	directory, err := os.Open(dir)
	if err != nil {
		return true, ErrVaultWrite
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return true, ErrVaultWrite
	}
	return true, nil
}

// OpenVault retains copies of all supplied 256-bit keys for read compatibility
// and writes with keyID. Rotation and interrupted invocations are persisted
// before the returned vault can serve any caller. No plaintext is written.
func OpenVault(path, keyID string, keys map[string][]byte) (*Vault, error) {
	if keyID == "" || len(keyID) > 256 || len(keys[keyID]) != 32 {
		return nil, ErrVaultKey
	}
	for id, key := range keys {
		if id == "" || len(id) > 256 || len(key) != 32 {
			return nil, ErrVaultKey
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, ErrVaultRead
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, ErrVaultRead
	}
	abs = filepath.Join(dir, filepath.Base(abs))
	vaultPaths.Lock()
	if vaultPaths.paths[abs] {
		vaultPaths.Unlock()
		return nil, ErrVaultInUse
	}
	vaultPaths.paths[abs] = true
	vaultPaths.Unlock()
	v := &Vault{path: abs, keyID: keyID, keys: make(map[string][]byte), registered: true}
	for id, key := range keys {
		v.keys[id] = bytes.Clone(key)
	}
	ok := false
	defer func() {
		if !ok {
			_ = v.Close()
		}
	}()
	v.lock, err = lockVault(abs + ".lock")
	if err != nil {
		return nil, err
	}
	state := VaultState{Connections: make(map[string]CredentialRecord), Invocations: make(map[string]InvocationRecord)}
	rewrite := false
	info, err := os.Lstat(abs)
	if errors.Is(err, os.ErrNotExist) {
		rewrite = true
	} else if err != nil || !vaultRegularFile(info) || info.Size() > maxVaultEnvelope {
		return nil, ErrVaultRead
	} else {
		file, err := openVaultFile(abs)
		if err != nil {
			return nil, ErrVaultRead
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxVaultEnvelope+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > maxVaultEnvelope {
			return nil, ErrVaultRead
		}
		state, err = v.unseal(data)
		if err != nil {
			return nil, err
		}
		var envelope vaultEnvelope
		if vaultJSON(data, &envelope) != nil {
			return nil, ErrVaultState
		}
		rewrite = envelope.KeyID != keyID
		v.sealed = data
	}
	for id, invocation := range state.Invocations {
		if invocation.Status == "running" {
			invocation.Status = "outcome_unknown"
			state.Invocations[id] = invocation
			rewrite = true
		}
	}
	if rewrite {
		sealed, err := v.seal(state)
		if err != nil {
			return nil, err
		}
		if _, err := v.persist(sealed); err != nil {
			return nil, err
		}
		v.sealed = sealed
	}
	ok = true
	return v, nil
}

// View decrypts an isolated snapshot; mutations cannot alter the stored state.
func (v *Vault) View() (VaultState, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return VaultState{}, ErrVaultClosed
	}
	return v.unseal(v.sealed)
}

func applyVaultChange(change func(*VaultState) error, state *VaultState) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrVaultUpdate
		}
	}()
	if change(state) != nil {
		return ErrVaultUpdate
	}
	return nil
}

// Update serializes callbacks and commits only a successfully encoded, durable
// encrypted replacement. The callback must not call back into this Vault.
func (v *Vault) Update(change func(*VaultState) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrVaultClosed
	}
	if change == nil {
		return ErrVaultUpdate
	}
	state, err := v.unseal(v.sealed)
	if err != nil {
		return err
	}
	if applyVaultChange(change, &state) != nil {
		return ErrVaultUpdate
	}
	sealed, err := v.seal(state)
	if err != nil {
		return err
	}
	renamed, err := v.persist(sealed)
	if err != nil {
		if renamed {
			v.closed = true
			v.wipe()
		}
		return err
	}
	clear(v.sealed)
	v.sealed = sealed
	return nil
}

func (v *Vault) wipe() {
	for id, key := range v.keys {
		clear(key)
		delete(v.keys, id)
	}
	clear(v.sealed)
	v.sealed = nil
}

// Close clears owned key/buffer copies and releases the process-local path.
// Go strings in caller-owned snapshots and callback values cannot be zeroized.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	v.wipe()
	if v.lock != nil {
		unlockVault(v.lock)
		v.lock = nil
	}
	if v.registered {
		vaultPaths.Lock()
		delete(vaultPaths.paths, v.path)
		vaultPaths.Unlock()
		v.registered = false
	}
	return nil
}
