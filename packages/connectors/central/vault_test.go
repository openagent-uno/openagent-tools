//go:build darwin || linux

package central

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func vaultTestKeys() map[string][]byte {
	return map[string][]byte{"current": bytes.Repeat([]byte{7}, 32)}
}

func vaultTestOpen(t *testing.T, path string) *Vault {
	t.Helper()
	v, err := OpenVault(path, "current", vaultTestKeys())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func vaultTestPut(t *testing.T, v *Vault) {
	t.Helper()
	if err := v.Update(func(s *VaultState) error {
		s.Connections["connection"] = CredentialRecord{Token: oauth.Token{
			AccessToken: "synthetic-access-secret", RefreshToken: "synthetic-refresh-secret",
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVaultRestartCiphertextPermissionsAndDetachedViews(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	keys := vaultTestKeys()
	v, err := OpenVault(path, "current", keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	clear(keys["current"]) // The vault owns a copy, not the supplied key slice.
	vaultTestPut(t, v)
	view, err := v.View()
	if err != nil {
		t.Fatal(err)
	}
	delete(view.Connections, "connection")
	if next, _ := v.View(); len(next.Connections) != 1 {
		t.Fatal("view mutated state")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("synthetic-")) || bytes.Contains(data, []byte("access_token")) {
		t.Fatal("plaintext persisted")
	}
	for _, name := range []string{path, path + ".lock"} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private file mode required")
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatal("temporary files retained")
	}
	_ = v.Close()
	v = vaultTestOpen(t, path)
	view, err = v.View()
	if err != nil || view.Connections["connection"].Token.AccessToken != "synthetic-access-secret" {
		t.Fatal("restart lost state")
	}
}

func TestVaultInterruptedInvocationsRecoveredDurably(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := vaultTestOpen(t, path)
	if err := v.Update(func(s *VaultState) error {
		s.Invocations["running"] = InvocationRecord{Status: "running"}
		s.Invocations["finished"] = InvocationRecord{Status: "succeeded"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()
	v = vaultTestOpen(t, path)
	state, _ := v.View()
	if state.Invocations["running"].Status != "outcome_unknown" || state.Invocations["finished"].Status != "succeeded" {
		t.Fatal("incorrect recovery")
	}
	_ = v.Close()
	v = vaultTestOpen(t, path)
	state, _ = v.View()
	if state.Invocations["running"].Status != "outcome_unknown" {
		t.Fatal("recovery was not persisted")
	}
}

func TestVaultWrongKeyTamperAndAADFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := vaultTestOpen(t, path)
	vaultTestPut(t, v)
	_ = v.Close()
	original, _ := os.ReadFile(path)
	if _, err := OpenVault(path, "current", map[string][]byte{"current": bytes.Repeat([]byte{9}, 32)}); !errors.Is(err, ErrVaultState) {
		t.Fatal("wrong key accepted")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, original) {
		t.Fatal("failed open changed file")
	}
	for _, mutation := range []func(*vaultEnvelope){
		func(e *vaultEnvelope) { e.Ciphertext[0] ^= 1 },
		func(e *vaultEnvelope) { e.Nonce[0] ^= 1 },
		func(e *vaultEnvelope) { e.KeyID = "alias" },
		func(e *vaultEnvelope) { e.Format = 2 },
	} {
		var e vaultEnvelope
		if json.Unmarshal(original, &e) != nil {
			t.Fatal("fixture envelope")
		}
		mutation(&e)
		bad, _ := json.Marshal(e)
		if os.WriteFile(path, bad, 0600) != nil {
			t.Fatal("fixture write")
		}
		keys := vaultTestKeys()
		keys["alias"] = bytes.Clone(keys["current"])
		if opened, err := OpenVault(path, "current", keys); err == nil {
			_ = opened.Close()
			t.Fatal("tampered envelope accepted")
		}
	}
}

func TestVaultRotationRewritesWithCurrentKeyAndRetainsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := vaultTestOpen(t, path)
	vaultTestPut(t, v)
	_ = v.Close()
	keys := vaultTestKeys()
	keys["next"] = bytes.Repeat([]byte{8}, 32)
	v, err := OpenVault(path, "next", keys)
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()
	data, _ := os.ReadFile(path)
	var e vaultEnvelope
	if json.Unmarshal(data, &e) != nil || e.KeyID != "next" {
		t.Fatal("rotation not persisted")
	}
	v, err = OpenVault(path, "next", map[string][]byte{"next": keys["next"]})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	state, err := v.View()
	if err != nil || state.Connections["connection"].Token.RefreshToken != "synthetic-refresh-secret" {
		t.Fatal("rotation lost credentials")
	}
}

func TestVaultUpdateRollbackAndSanitizedErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := vaultTestOpen(t, path)
	vaultTestPut(t, v)
	original, _ := os.ReadFile(path)
	err := v.Update(func(s *VaultState) error {
		delete(s.Connections, "connection")
		return errors.New("synthetic-callback-secret")
	})
	if !errors.Is(err, ErrVaultUpdate) || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("callback error disclosure")
	}
	if err := v.Update(func(*VaultState) error { panic("synthetic-panic-secret") }); !errors.Is(err, ErrVaultUpdate) {
		t.Fatal("callback panic was not sanitized")
	}
	err = v.Update(func(s *VaultState) error {
		s.Connections["large"] = CredentialRecord{Token: oauth.Token{AccessToken: strings.Repeat("x", maxVaultState)}}
		return nil
	})
	if !errors.Is(err, ErrVaultState) {
		t.Fatal("oversized state accepted")
	}
	if current, _ := os.ReadFile(path); !bytes.Equal(original, current) {
		t.Fatal("rejected update persisted")
	}
	state, _ := v.View()
	if len(state.Connections) != 1 {
		t.Fatal("rejected update changed view")
	}
	for _, printed := range []string{fmt.Sprintf("%v", v), fmt.Sprintf("%#v", v)} {
		if strings.Contains(printed, "synthetic") || strings.Contains(printed, "777") {
			t.Fatal("vault formatting disclosure")
		}
	}
}

func TestVaultCredentialRemovalPersistsWithoutPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := vaultTestOpen(t, path)
	vaultTestPut(t, v)
	if err := v.Update(func(s *VaultState) error { delete(s.Connections, "connection"); return nil }); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()
	v = vaultTestOpen(t, path)
	state, err := v.View()
	if err != nil || len(state.Connections) != 0 {
		t.Fatal("removed credential recovered")
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte("synthetic-")) {
		t.Fatal("credential plaintext persisted")
	}
}

func TestVaultPersistenceFailureLeavesOldState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("fixture directory")
	}
	v := vaultTestOpen(t, filepath.Join(dir, "vault.json"))
	vaultTestPut(t, v)
	// Replace the parent path with a regular file. This causes an actual
	// filesystem failure before rename, without permission/root assumptions.
	saved := dir + "-saved"
	if os.Rename(dir, saved) != nil || os.WriteFile(dir, []byte("fixture"), 0600) != nil {
		t.Fatal("fixture setup")
	}
	err := v.Update(func(s *VaultState) error { delete(s.Connections, "connection"); return nil })
	if !errors.Is(err, ErrVaultWrite) {
		t.Fatal("filesystem failure was accepted")
	}
	if os.Remove(dir) != nil || os.Rename(saved, dir) != nil {
		t.Fatal("fixture restore")
	}
	state, _ := v.View()
	if len(state.Connections) != 1 {
		t.Fatal("failed write changed state")
	}
	_ = v.Close()
	v = vaultTestOpen(t, filepath.Join(dir, "vault.json"))
	state, _ = v.View()
	if len(state.Connections) != 1 {
		t.Fatal("failed write changed disk")
	}
}

func TestVaultExclusiveOSLockAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := vaultTestOpen(t, path)
	if _, err := OpenVault(path, "current", vaultTestKeys()); !errors.Is(err, ErrVaultInUse) {
		t.Fatal("duplicate open admitted")
	}
	// Bypass only the in-process registry to exercise the real OS lock.
	if lock, err := lockVault(path + ".lock"); err == nil {
		unlockVault(lock)
		t.Fatal("OS lock not exclusive")
	}
	owned := v.keys["current"]
	_ = v.Close()
	if !bytes.Equal(owned, make([]byte, 32)) {
		t.Fatal("owned key not cleared")
	}
	if _, err := v.View(); !errors.Is(err, ErrVaultClosed) {
		t.Fatal("closed vault readable")
	}
	if err := v.Update(func(*VaultState) error { return nil }); !errors.Is(err, ErrVaultClosed) {
		t.Fatal("closed vault writable")
	}
	next := vaultTestOpen(t, path)
	_ = v.Close() // Repeated Close cannot release another instance's reservation.
	if _, err := OpenVault(path, "current", vaultTestKeys()); !errors.Is(err, ErrVaultInUse) {
		t.Fatal("repeated close released reservation")
	}
	_ = next.Close()
}

func TestVaultRejectsUnsafeFilesAndInvalidKeys(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "vault.json")
			v := vaultTestOpen(t, path)
			_ = v.Close()
			if kind == "public" {
				if os.Chmod(path, 0644) != nil {
					t.Fatal("fixture chmod")
				}
			} else {
				other := path + "-original"
				if os.Rename(path, other) != nil {
					t.Fatal("fixture rename")
				}
				var err error
				if kind == "symlink" {
					err = os.Symlink(other, path)
				} else {
					err = os.Link(other, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if opened, err := OpenVault(path, "current", vaultTestKeys()); err == nil {
				_ = opened.Close()
				t.Fatal("unsafe file admitted")
			}
		})
	}
	if _, err := OpenVault(filepath.Join(t.TempDir(), "vault.json"), "current", map[string][]byte{"current": []byte("secret")}); !errors.Is(err, ErrVaultKey) {
		t.Fatal("short key accepted")
	}
}
