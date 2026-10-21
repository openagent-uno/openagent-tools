//go:build darwin || linux

package central

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func projectedKeysFixture(t *testing.T) (string, string, map[string][]byte) {
	t.Helper()
	source, destination := t.TempDir(), t.TempDir()
	if err := os.Chmod(destination, 0770); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(source, "..version-fixture")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	keys := map[string][]byte{
		"registry-signing.hex": []byte(hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, 32))) + "\n"),
		"vault-current.hex":    []byte(hex.EncodeToString(bytes.Repeat([]byte{0x62}, 32)) + "\n"),
	}
	if err := os.Symlink("..version-fixture", filepath.Join(source, "..data")); err != nil {
		t.Fatal(err)
	}
	for name, raw := range keys {
		if err := os.WriteFile(filepath.Join(target, name), raw, 0440); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	return source, destination, keys
}

func TestPrepareKeyFilesCopiesProjectedSecretPrivatelyAndIsIdempotent(t *testing.T) {
	source, destination, keys := projectedKeysFixture(t)
	if err := PrepareKeyFiles(source, destination); err != nil {
		t.Fatal("projected key preparation rejected", err)
	}
	before := map[string]os.FileInfo{}
	for name, expected := range keys {
		path := filepath.Join(destination, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("prepared key is not a private regular file")
		}
		before[name] = info
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("prepared key bytes changed")
		}
		clear(actual)
		key, err := configSecret(path, preparedKeySize(name))
		clear(key)
		if err != nil {
			t.Fatal("prepared key failed service validation")
		}
	}
	if err := PrepareKeyFiles(source, destination); err != nil {
		t.Fatal("identical repeat rejected", err)
	}
	for name, original := range before {
		current, err := os.Lstat(filepath.Join(destination, name))
		if err != nil || !os.SameFile(original, current) || !original.ModTime().Equal(current.ModTime()) {
			t.Fatal("idempotent preparation replaced or rewrote an existing key")
		}
	}
}

func TestPrepareKeyFilesRejectsUnexpectedOrInvalidSourceWithoutCopying(t *testing.T) {
	for _, mode := range []string{"provider-credential", "unknown-file", "directory", "oversize", "bad-hex", "wrong-key-size", "missing-signing", "missing-vault", "bad-vault-name"} {
		t.Run(mode, func(t *testing.T) {
			source, destination, _ := projectedKeysFixture(t)
			name, raw := "registry-signing.hex", []byte("invalid hex")
			switch mode {
			case "provider-credential":
				name, raw = "google-client-secret", []byte("synthetic credential fixture")
			case "unknown-file":
				name = "unexpected.hex"
			case "directory":
				if err := os.Mkdir(filepath.Join(source, "vault-directory.hex"), 0700); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				raw = []byte(strings.Repeat("a", 4097))
			case "wrong-key-size":
				raw = []byte(strings.Repeat("ab", 32))
			case "missing-signing":
				if err := os.Remove(filepath.Join(source, "registry-signing.hex")); err != nil {
					t.Fatal(err)
				}
			case "missing-vault":
				if err := os.Remove(filepath.Join(source, "vault-current.hex")); err != nil {
					t.Fatal(err)
				}
			case "bad-vault-name":
				name = "vault-.hex"
			}
			if mode != "directory" && mode != "missing-signing" && mode != "missing-vault" {
				if err := os.Remove(filepath.Join(source, name)); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, name), raw, 0440); err != nil {
					t.Fatal(err)
				}
			}
			if err := PrepareKeyFiles(source, destination); err != errKeyPreparation {
				t.Fatal("invalid source was not rejected with a sanitized error")
			}
			entries, _ := os.ReadDir(destination)
			if len(entries) != 0 {
				t.Fatal("invalid source caused partial key copying")
			}
		})
	}
}

func TestPrepareKeyFilesNeverOverwritesExistingKeysOrFollowsDestinationLinks(t *testing.T) {
	for _, mode := range []string{"different-key", "different-format", "public-permissions", "key-symlink", "directory-symlink", "same-directory", "relative-source", "relative-destination"} {
		t.Run(mode, func(t *testing.T) {
			source, destination, keys := projectedKeysFixture(t)
			path := filepath.Join(destination, "registry-signing.hex")
			expected := keys["registry-signing.hex"]
			switch mode {
			case "different-key":
				expected = []byte(strings.Repeat("cd", 64))
			case "different-format":
				expected = bytes.TrimSpace(expected)
			case "public-permissions":
				if err := os.WriteFile(path, expected, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "key-symlink":
				if err := os.Symlink(filepath.Join(source, "registry-signing.hex"), path); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				link := filepath.Join(t.TempDir(), "destination")
				if err := os.Symlink(destination, link); err != nil {
					t.Fatal(err)
				}
				destination = link
			case "same-directory":
				destination = source
			case "relative-source":
				source = "relative-source"
			case "relative-destination":
				destination = "relative-destination"
			}
			if mode == "different-key" || mode == "different-format" {
				if err := os.WriteFile(path, expected, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := PrepareKeyFiles(source, destination); err != errKeyPreparation {
				t.Fatal("unsafe destination accepted or error exposed details")
			}
			if mode == "different-key" || mode == "different-format" || mode == "public-permissions" {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("existing key was overwritten")
				}
				clear(actual)
			}
		})
	}
}
