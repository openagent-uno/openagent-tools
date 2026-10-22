package central

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors"
	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

// ServiceConfig contains secret-file references, never credentials. Activation
// is startup-only and requires an explicit reviewed qualification list.
type ServiceConfig struct {
	Revision            uint64                  `json:"revision"`
	SigningKeyID        string                  `json:"signing_key_id"`
	SigningKeyFile      string                  `json:"signing_key_file"`
	VaultPath           string                  `json:"vault_path"`
	VaultKeyID          string                  `json:"vault_key_id"`
	VaultKeyFiles       map[string]string       `json:"vault_key_files"`
	QualifiedCatalogIDs []string                `json:"qualified_catalog_ids"`
	GmailQualification  *QualificationAdmission `json:"gmail_qualification,omitempty"`
}

func configSecret(path string, size int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("central secret reference must be absolute")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("central secret reference invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("central secret unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return nil, errors.New("central secret permissions invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("central secret unavailable")
	}
	defer clear(raw)
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != size {
		clear(key)
		return nil, errors.New("central secret invalid")
	}
	return key, nil
}

// LoadService builds a separate opt-in central profile next to the legacy
// broker. The caller owns Close; no provider is enabled by catalog presence.
func LoadService(path string, broker *auth.Server, runtime *connectors.Runtime) (*Server, func() error, error) {
	fail := func() (*Server, func() error, error) {
		return nil, nil, errors.New("central service configuration invalid")
	}
	if broker == nil || runtime == nil {
		return fail()
	}
	file, err := os.Open(path)
	if err != nil {
		return fail()
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	if err != nil || len(raw) > 128<<10 {
		return fail()
	}
	var config ServiceConfig
	if !strict(raw, &config) || config.Revision == 0 || config.SigningKeyID == "" || config.VaultKeyID == "" || !filepath.IsAbs(config.VaultPath) || len(config.VaultKeyFiles) == 0 || len(config.VaultKeyFiles) > 8 {
		return fail()
	}
	keys := map[string][]byte{}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for id, path := range config.VaultKeyFiles {
		if !cleanText(id, 128) {
			return fail()
		}
		key, e := configSecret(path, 32)
		if e != nil {
			return fail()
		}
		keys[id] = key
	}
	signing, err := configSecret(config.SigningKeyFile, ed25519.PrivateKeySize)
	if err != nil {
		return fail()
	}
	defer clear(signing)
	derived := ed25519.NewKeyFromSeed(signing[:ed25519.SeedSize])
	defer clear(derived)
	if !strings.EqualFold(hex.EncodeToString(derived), hex.EncodeToString(signing)) {
		return fail()
	}
	known := map[string]bool{}
	for _, entry := range connectors.Catalog() {
		known[entry.ID] = true
	}
	qualified := map[string]bool{}
	for _, id := range config.QualifiedCatalogIDs {
		if !known[id] || qualified[id] {
			return fail()
		}
		qualified[id] = true
	}
	registry, err := NewRegistry(config.Revision, config.SigningKeyID, ed25519.PrivateKey(signing), BuildDescriptors(runtime, qualified, broker.Providers))
	if err != nil {
		return fail()
	}
	if _, _, err := prepareQualification(config.GmailQualification, registry, broker.Providers, time.Now()); err != nil {
		return fail()
	}
	vault, err := OpenVault(config.VaultPath, config.VaultKeyID, keys)
	if err != nil {
		return fail()
	}
	server, err := NewServer(Config{Auth: broker, Vault: vault, Registry: registry, Executor: runtime, GmailQualification: config.GmailQualification})
	if err != nil {
		_ = vault.Close()
		return fail()
	}
	return server, vault.Close, nil
}
