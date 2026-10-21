//go:build darwin || linux

package slackchannel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/central"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

type channelConfigFixture struct {
	directory string
	path      string
	config    Config
	broker    *auth.Server
	metadata  string
}

func newChannelConfigFixture(t *testing.T) channelConfigFixture {
	t.Helper()
	dir := t.TempDir()
	identity, err := auth.NewIdentity("fixture-host", "Fixture destination")
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(dir, "legacy-metadata.json")
	store, err := auth.NewStore(metadata)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewServer(store, oauth.Engine{}, nil, "https://fixture.invalid", bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(identity.Installation())
	req := httptest.NewRequest(http.MethodPost, "https://fixture.invalid/v1/installations", bytes.NewReader(body))
	identity.Sign(req, body)
	reply := httptest.NewRecorder()
	broker.ServeHTTP(reply, req)
	if reply.Code != http.StatusCreated {
		t.Fatal("could not initialize real legacy installation metadata")
	}
	f := channelConfigFixture{directory: dir, path: filepath.Join(dir, "channel-config.json"), broker: broker, metadata: metadata,
		config: Config{Origin: "https://fixture.invalid", AppID: "ATEST", ClientID: "fixture-client-id",
			ClientSecretFile: filepath.Join(dir, "client-secret"), SigningSecretFile: filepath.Join(dir, "signing-secret"),
			VaultPath: filepath.Join(dir, "slack-channel-v1.vault"), VaultKeyID: "current",
			VaultKeyFiles: map[string]string{"current": filepath.Join(dir, "vault-key")}, AllowedInstallations: []string{identity.ID()}}}
	for name, value := range map[string]string{
		f.config.ClientSecretFile:                   "synthetic-client-secret",
		f.config.SigningSecretFile:                  "synthetic-signing-secret-32-bytes",
		f.config.VaultKeyFiles[f.config.VaultKeyID]: hex.EncodeToString(bytes.Repeat([]byte{7}, 32)) + "\n",
	} {
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.write(t)
	return f
}

func (f channelConfigFixture) write(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(f.path, data, 0600) != nil {
		t.Fatal("could not write source-only configuration fixture")
	}
}

func assertConfigurationRejected(t *testing.T, f channelConfigFixture, forbidden ...string) {
	t.Helper()
	service, closeStore, err := LoadService(f.path, f.broker, forbidden...)
	if closeStore != nil {
		_ = closeStore()
	}
	if service != nil || closeStore != nil || !errors.Is(err, ErrConfiguration) || err.Error() != ErrConfiguration.Error() {
		t.Fatal("invalid configuration accepted or exposed diagnostic details")
	}
}

func TestChannelLoadServiceGroupReadableSecretsAndSeparateLegacyState(t *testing.T) {
	f := newChannelConfigFixture(t)
	for _, path := range []string{f.config.ClientSecretFile, f.config.SigningSecretFile, f.config.VaultKeyFiles["current"]} {
		if os.Chmod(path, 0640) != nil {
			t.Fatal("could not set projected-secret fixture permissions")
		}
	}
	mcpPath := filepath.Join(f.directory, "legacy-mcp.vault")
	mcp, err := central.OpenVault(mcpPath, "current", storeKeys())
	if err != nil {
		t.Fatal(err)
	}
	if err := mcp.Update(func(next *central.VaultState) error {
		next.Connections["existing-connection"] = central.CredentialRecord{Token: oauth.Token{AccessToken: "synthetic-existing-mcp-token"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = mcp.Close()
	metadataBefore, _ := os.ReadFile(f.metadata)
	mcpBefore, _ := os.ReadFile(mcpPath)
	service, closeStore, err := LoadService(f.path, f.broker, f.metadata, mcpPath)
	if err != nil || service == nil || closeStore == nil {
		t.Fatal("group-readable namespace secret references should be accepted")
	}
	defer closeStore()
	view, err := service.store.View()
	if err != nil || len(view.Bindings) != 0 || len(view.Grants) != 0 || len(view.Deliveries) != 0 {
		t.Fatal("new service imported an existing connector or installation grant")
	}
	if err := service.store.Update(func(next *state) error {
		next.Bindings["synthetic-binding"] = bindingRecord{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	metadataAfter, _ := os.ReadFile(f.metadata)
	mcpAfter, _ := os.ReadFile(mcpPath)
	if !bytes.Equal(metadataBefore, metadataAfter) || !bytes.Equal(mcpBefore, mcpAfter) || len(f.broker.Providers) != 0 {
		t.Fatal("channel startup or state update modified legacy OAuth or MCP state")
	}
	if actual, err := os.Stat(f.config.VaultPath); err != nil || actual.Mode().Perm() != 0600 {
		t.Fatal("channel state must remain private despite group-readable secret inputs")
	}
}

func TestChannelLoadServiceRejectsWorldReadableSecretReferences(t *testing.T) {
	for _, field := range []string{"client", "signing", "vault-key"} {
		t.Run(field, func(t *testing.T) {
			f := newChannelConfigFixture(t)
			path := f.config.ClientSecretFile
			if field == "signing" {
				path = f.config.SigningSecretFile
			} else if field == "vault-key" {
				path = f.config.VaultKeyFiles["current"]
			}
			if os.Chmod(path, 0644) != nil {
				t.Fatal("could not set unsafe fixture permissions")
			}
			assertConfigurationRejected(t, f, f.metadata)
			if _, err := os.Stat(f.config.VaultPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe secret configuration opened channel state")
			}
		})
	}
}

func TestChannelLoadServicePathCollisionRejectedBeforeVaultRecovery(t *testing.T) {
	for _, alias := range []bool{false, true} {
		name := "literal"
		if alias {
			name = "parent-symlink"
		}
		t.Run(name, func(t *testing.T) {
			f := newChannelConfigFixture(t)
			// This deliberately misnamed existing MCP file contains a running
			// operation: OpenVault would persist recovery if reached at all.
			mcp, err := central.OpenVault(f.config.VaultPath, "current", storeKeys())
			if err != nil {
				t.Fatal(err)
			}
			if err := mcp.Update(func(next *central.VaultState) error {
				next.Connections["existing"] = central.CredentialRecord{Token: oauth.Token{AccessToken: "synthetic-preserved-token"}}
				next.Invocations["running"] = central.InvocationRecord{Status: "running"}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			_ = mcp.Close()
			forbidden := f.config.VaultPath
			if alias {
				link := filepath.Join(t.TempDir(), "state-alias")
				if os.Symlink(f.directory, link) != nil {
					t.Fatal("could not prepare parent alias")
				}
				forbidden = filepath.Join(link, filepath.Base(f.config.VaultPath))
			}
			before, _ := os.ReadFile(f.config.VaultPath)
			assertConfigurationRejected(t, f, forbidden)
			after, _ := os.ReadFile(f.config.VaultPath)
			if !bytes.Equal(before, after) {
				t.Fatal("path collision reached vault open/recovery and mutated existing state")
			}
		})
	}
}

func TestChannelLoadServicePlaintextCollisionDoesNotEvenCreateLock(t *testing.T) {
	f := newChannelConfigFixture(t)
	original := []byte("synthetic-legacy-metadata-not-a-vault")
	if err := os.WriteFile(f.config.VaultPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	assertConfigurationRejected(t, f, f.config.VaultPath)
	if after, _ := os.ReadFile(f.config.VaultPath); !bytes.Equal(original, after) {
		t.Fatal("plaintext legacy metadata changed")
	}
	if _, err := os.Stat(f.config.VaultPath + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("path collision was checked only after opening the vault")
	}
}

func TestChannelLoadServiceStrictConfigurationAndRequiredAllowlist(t *testing.T) {
	for _, mode := range []string{"unknown", "trailing", "oversize", "missing-allowlist", "empty-allowlist", "invalid-host-id", "relative-vault", "wrong-vault-name"} {
		t.Run(mode, func(t *testing.T) {
			f := newChannelConfigFixture(t)
			switch mode {
			case "missing-allowlist":
				f.config.AllowedInstallations = nil
			case "empty-allowlist":
				f.config.AllowedInstallations = []string{}
			case "invalid-host-id":
				f.config.AllowedInstallations = []string{strings.Repeat("z", 64)}
			case "relative-vault":
				f.config.VaultPath = "slack-channel-v1.vault"
			case "wrong-vault-name":
				f.config.VaultPath = filepath.Join(f.directory, "mcp.vault")
			}
			f.write(t)
			if mode == "unknown" {
				raw, _ := os.ReadFile(f.path)
				var values map[string]any
				_ = json.Unmarshal(raw, &values)
				values["client_secret"] = "synthetic-forbidden-inline-secret"
				modified, _ := json.Marshal(values)
				if err := os.WriteFile(f.path, modified, 0600); err != nil {
					t.Fatal(err)
				}
			} else if mode == "trailing" {
				raw, _ := os.ReadFile(f.path)
				if err := os.WriteFile(f.path, append(raw, []byte(" {}")...), 0600); err != nil {
					t.Fatal(err)
				}
			} else if mode == "oversize" {
				if err := os.WriteFile(f.path, bytes.Repeat([]byte{' '}, (128<<10)+1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			assertConfigurationRejected(t, f, f.metadata)
		})
	}
}
