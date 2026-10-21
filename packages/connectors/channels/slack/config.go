package slackchannel

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var ErrConfiguration = errors.New("Slack channel service configuration invalid")

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrConfiguration
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, ErrConfiguration
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > maximum || info.Mode().Perm()&0007 != 0 {
		return nil, ErrConfiguration
	}
	b, e := io.ReadAll(io.LimitReader(file, maximum+1))
	if e != nil || int64(len(b)) > maximum {
		return nil, ErrConfiguration
	}
	return b, nil
}
func canonical(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrConfiguration
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return "", ErrConfiguration
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

// LoadService is startup-only. The channel vault MUST be separate from both the
// plaintext OAuth metadata and the existing encrypted MCP credential vault.
// Existing app secret references are reused; this does not enable bot scopes.
func LoadService(path string, authorizer InstallationAuthorizer, forbiddenStatePaths ...string) (*Server, func() error, error) {
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 128<<10 {
		return nil, nil, ErrConfiguration
	}
	var config Config
	if strict(raw, &config) != nil {
		return nil, nil, ErrConfiguration
	}
	actual, e := canonical(config.VaultPath)
	if e != nil {
		return nil, nil, ErrConfiguration
	}
	if filepath.Base(actual) != "slack-channel-v1.vault" {
		return nil, nil, ErrConfiguration
	}
	for _, other := range forbiddenStatePaths {
		if other == "" {
			continue
		}
		canonicalOther, e := canonical(other)
		if e != nil || actual == canonicalOther {
			return nil, nil, ErrConfiguration
		}
	}
	if len(config.VaultKeyFiles) == 0 || len(config.VaultKeyFiles) > 8 || !text(config.VaultKeyID, 128) {
		return nil, nil, ErrConfiguration
	}
	keys := map[string][]byte{}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for keyID, keyPath := range config.VaultKeyFiles {
		if !text(keyID, 128) {
			return nil, nil, ErrConfiguration
		}
		raw, e := readPrivateFile(keyPath, 4096)
		if e != nil {
			return nil, nil, ErrConfiguration
		}
		key, e := hex.DecodeString(strings.TrimSpace(string(raw)))
		clear(raw)
		if e != nil || len(key) != 32 {
			clear(key)
			return nil, nil, ErrConfiguration
		}
		keys[keyID] = key
	}
	secret, e := readPrivateFile(config.ClientSecretFile, 8192)
	if e != nil {
		return nil, nil, ErrConfiguration
	}
	defer clear(secret)
	signing, e := readPrivateFile(config.SigningSecretFile, 8192)
	if e != nil {
		return nil, nil, ErrConfiguration
	}
	defer clear(signing)
	provider, e := NewProvider(config.ClientID, config.AppID, strings.TrimSpace(string(secret)), config.Origin, nil)
	if e != nil {
		return nil, nil, ErrConfiguration
	}
	store, e := OpenStore(actual, config.VaultKeyID, keys)
	if e != nil {
		return nil, nil, ErrConfiguration
	}
	server, e := NewServer(config, authorizer, store, provider, []byte(strings.TrimSpace(string(signing))))
	if e != nil {
		_ = store.Close()
		return nil, nil, ErrConfiguration
	}
	return server, store.Close, nil
}
