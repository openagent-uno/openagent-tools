//go:build darwin || linux

package central

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

type serviceConfigFixture struct {
	path     string
	config   ServiceConfig
	broker   *auth.Server
	runtime  *connectors.Runtime
	signing  []byte
	vaultKey []byte
}

func newServiceConfigFixture(t *testing.T) serviceConfigFixture {
	t.Helper()
	directory := t.TempDir()
	_, signing := fixtureSigningKey(t)
	vaultKey := bytes.Repeat([]byte{0x93}, 32)
	config := ServiceConfig{Revision: 1, SigningKeyID: "registry-key", SigningKeyFile: filepath.Join(directory, "signing.hex"),
		VaultPath: filepath.Join(directory, "vault.json"), VaultKeyID: "vault-key", VaultKeyFiles: map[string]string{"vault-key": filepath.Join(directory, "vault.hex")}}
	for path, key := range map[string][]byte{config.SigningKeyFile: signing, config.VaultKeyFiles[config.VaultKeyID]: vaultKey} {
		if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := auth.NewStore(filepath.Join(directory, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewServer(store, oauth.Engine{}, nil, "https://fixture.invalid", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := connectors.NewRuntime(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture := serviceConfigFixture{path: filepath.Join(directory, "central.json"), config: config, broker: broker, runtime: runtime, signing: signing, vaultKey: vaultKey}
	fixture.write(t)
	return fixture
}

func (f serviceConfigFixture) write(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadServiceAllCatalogEntriesAreDisabledByDefault(t *testing.T) {
	f := newServiceConfigFixture(t)
	service, closeVault, err := LoadService(f.path, f.broker, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeVault() })
	snapshot := service.config.Registry.Snapshot(time.Now())
	var catalog Catalog
	if strictJSON(snapshot.Payload, &catalog) != nil {
		t.Fatal("invalid generated catalog")
	}
	if len(catalog.Connectors) != 115 || len(catalog.Connectors) != len(connectors.Catalog()) {
		t.Fatalf("compiled catalog coverage changed: %d", len(catalog.Connectors))
	}
	for _, descriptor := range catalog.Connectors {
		if descriptor.Item.Available || descriptor.Item.UnavailableReason == "" {
			t.Fatal("catalog presence enabled an unqualified provider")
		}
		if descriptor.Setup.CredentialCustody != "service" || descriptor.Setup.Execution != "service" || descriptor.ContractSHA256 != ComputeContract(descriptor) {
			t.Fatal("invalid central descriptor authority")
		}
	}
	// Configuration/public descriptors contain file references and signatures,
	// never key material loaded from those files.
	config, _ := json.Marshal(f.config)
	for _, output := range [][]byte{config, snapshot.Payload} {
		if bytes.Contains(output, []byte(hex.EncodeToString(f.signing))) || bytes.Contains(output, []byte(hex.EncodeToString(f.vaultKey))) {
			t.Fatal("key material escaped configuration or public catalog")
		}
	}
}

func TestLoadServiceExplicitQualificationDoesNotEnableOtherEntries(t *testing.T) {
	f := newServiceConfigFixture(t)
	f.config.QualifiedCatalogIDs = []string{"coingecko"}
	f.write(t)
	service, closeVault, err := LoadService(f.path, f.broker, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeVault() })
	var catalog Catalog
	_ = json.Unmarshal(service.config.Registry.Snapshot(time.Now()).Payload, &catalog)
	enabled := 0
	for _, descriptor := range catalog.Connectors {
		if descriptor.Item.Available {
			enabled++
			if descriptor.Item.ID != "coingecko" || descriptor.Item.Auth != "none" {
				t.Fatal("qualification expanded to another connector")
			}
		}
	}
	if enabled != 1 {
		t.Fatalf("qualified credential-free adapter unavailable: %d", enabled)
	}
}

func TestLoadServiceRejectsUnknownDuplicateOrInvalidConfiguration(t *testing.T) {
	for _, mode := range []string{"unknown-field", "duplicate-field", "unknown-id", "duplicate-id", "provider-instead-of-catalog-id", "zero-revision", "missing-active-key", "relative-vault", "nil-broker", "nil-runtime", "private-key-in-config"} {
		t.Run(mode, func(t *testing.T) {
			f := newServiceConfigFixture(t)
			switch mode {
			case "unknown-id":
				f.config.QualifiedCatalogIDs = []string{"does-not-exist"}
			case "duplicate-id":
				f.config.QualifiedCatalogIDs = []string{"coingecko", "coingecko"}
			case "provider-instead-of-catalog-id":
				f.config.QualifiedCatalogIDs = []string{"slack_import"}
			case "zero-revision":
				f.config.Revision = 0
			case "missing-active-key":
				f.config.VaultKeyID = "missing"
			case "relative-vault":
				f.config.VaultPath = "relative.json"
			case "nil-broker":
				f.broker = nil
			case "nil-runtime":
				f.runtime = nil
			}
			f.write(t)
			if mode == "unknown-field" || mode == "duplicate-field" || mode == "private-key-in-config" {
				data, _ := os.ReadFile(f.path)
				extra := `,"unknown":true}`
				if mode == "duplicate-field" {
					extra = `,"revision":2}`
				}
				if mode == "private-key-in-config" {
					extra = `,"signing_private_key":"PRIVATE_CANARY"}`
				}
				if err := os.WriteFile(f.path, append(data[:len(data)-1], []byte(extra)...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			service, closeVault, err := LoadService(f.path, f.broker, f.runtime)
			if closeVault != nil {
				_ = closeVault()
			}
			if err == nil || service != nil || closeVault != nil {
				t.Fatal("invalid service configuration admitted")
			}
			if strings.Contains(err.Error(), "PRIVATE_CANARY") || strings.Contains(err.Error(), hex.EncodeToString(f.signing)) {
				t.Fatal("key/config data escaped safe error")
			}
		})
	}
}

func TestLoadServiceStrictSecretFiles(t *testing.T) {
	for _, mode := range []string{"relative", "missing", "directory", "symlink", "public-permissions", "invalid-hex", "short-key", "oversized", "inconsistent-private-key", "vault-public-permissions", "vault-short-key", "vault-symlink"} {
		t.Run(mode, func(t *testing.T) {
			f := newServiceConfigFixture(t)
			keyPath := f.config.SigningKeyFile
			switch mode {
			case "relative":
				f.config.SigningKeyFile = "signing.hex"
			case "missing":
				f.config.SigningKeyFile = filepath.Join(t.TempDir(), "missing.hex")
			case "directory":
				f.config.SigningKeyFile = t.TempDir()
			case "symlink":
				link := filepath.Join(t.TempDir(), "linked.hex")
				if err := os.Symlink(keyPath, link); err != nil {
					t.Fatal(err)
				}
				f.config.SigningKeyFile = link
			case "public-permissions":
				if err := os.Chmod(keyPath, 0644); err != nil {
					t.Fatal(err)
				}
			case "invalid-hex":
				if err := os.WriteFile(keyPath, []byte("PRIVATE_CANARY"), 0600); err != nil {
					t.Fatal(err)
				}
			case "short-key":
				if err := os.WriteFile(keyPath, []byte(strings.Repeat("01", 32)), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(keyPath, bytes.Repeat([]byte{'1'}, 4097), 0600); err != nil {
					t.Fatal(err)
				}
			case "inconsistent-private-key":
				key := append([]byte(nil), f.signing...)
				key[ed25519.SeedSize] ^= 1
				if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0600); err != nil {
					t.Fatal(err)
				}
			case "vault-public-permissions":
				if err := os.Chmod(f.config.VaultKeyFiles[f.config.VaultKeyID], 0644); err != nil {
					t.Fatal(err)
				}
			case "vault-short-key":
				if err := os.WriteFile(f.config.VaultKeyFiles[f.config.VaultKeyID], []byte("0102"), 0600); err != nil {
					t.Fatal(err)
				}
			case "vault-symlink":
				link := filepath.Join(t.TempDir(), "vault-link.hex")
				if err := os.Symlink(f.config.VaultKeyFiles[f.config.VaultKeyID], link); err != nil {
					t.Fatal(err)
				}
				f.config.VaultKeyFiles[f.config.VaultKeyID] = link
			}
			f.write(t)
			service, closeVault, err := LoadService(f.path, f.broker, f.runtime)
			if closeVault != nil {
				_ = closeVault()
			}
			if err == nil || service != nil {
				t.Fatal("unsafe signing key admitted")
			}
			if strings.Contains(err.Error(), "PRIVATE_CANARY") {
				t.Fatal("unsafe key file content leaked")
			}
		})
	}
}
