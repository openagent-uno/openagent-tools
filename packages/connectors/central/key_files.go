package central

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errKeyPreparation = errors.New("central key preparation failed")

func preparedKeySize(name string) int {
	if len(name) > 128 || filepath.Base(name) != name {
		return 0
	}
	if name == "registry-signing.hex" {
		return 64
	}
	if !strings.HasPrefix(name, "vault-") || !strings.HasSuffix(name, ".hex") {
		return 0
	}
	id := strings.TrimSuffix(strings.TrimPrefix(name, "vault-"), ".hex")
	if id == "" {
		return 0
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return 0
		}
	}
	return 32
}

// readProjectedKey permits Kubernetes' projected file symlinks, but only reads
// bounded regular targets. It never changes the source's mount permissions.
func readProjectedKey(path string, private bool) ([]byte, error) {
	var before os.FileInfo
	if private {
		var err error
		before, err = os.Lstat(path)
		if err != nil || before.Mode()&os.ModeSymlink != 0 {
			return nil, errKeyPreparation
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errKeyPreparation
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 ||
		private && (!os.SameFile(before, info) || info.Mode().Perm()&0077 != 0) {
		return nil, errKeyPreparation
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		clear(raw)
		return nil, errKeyPreparation
	}
	return raw, nil
}

// PrepareKeyFiles copies only central signing/vault keys from a projected Secret
// to an existing private memory-volume directory. New files are exclusive and
// private; an existing file is accepted only with identical bytes and the same
// strict private-file validation used by LoadService. It never overwrites keys.
func PrepareKeyFiles(sourceDir, destinationDir string) error {
	if !filepath.IsAbs(sourceDir) || !filepath.IsAbs(destinationDir) {
		return errKeyPreparation
	}
	source, err := os.Lstat(sourceDir)
	if err != nil || !source.IsDir() || source.Mode()&os.ModeSymlink != 0 {
		return errKeyPreparation
	}
	destination, err := os.Lstat(destinationDir)
	if err != nil || !destination.IsDir() || destination.Mode()&os.ModeSymlink != 0 || os.SameFile(source, destination) {
		return errKeyPreparation
	}
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return errKeyPreparation
	}
	keys := map[string][]byte{}
	defer func() {
		for _, raw := range keys {
			clear(raw)
		}
	}()
	// Validate the full source before creating anything: provider credentials or
	// an unexpected mount entry must not produce a partially accepted key set.
	vaults := 0
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		size := preparedKeySize(name)
		if size == 0 || entry.IsDir() {
			return errKeyPreparation
		}
		raw, err := readProjectedKey(filepath.Join(sourceDir, name), false)
		if err != nil {
			return errKeyPreparation
		}
		keys[name] = raw
		encoded := bytes.TrimSpace(raw)
		key := make([]byte, hex.DecodedLen(len(encoded)))
		n, err := hex.Decode(key, encoded)
		clear(key)
		if err != nil || n != size {
			return errKeyPreparation
		}
		if size == 32 {
			vaults++
		}
	}
	if keys["registry-signing.hex"] == nil || vaults == 0 {
		return errKeyPreparation
	}
	dir, err := os.Open(destinationDir)
	if err != nil {
		return errKeyPreparation
	}
	defer dir.Close()
	for name, raw := range keys {
		path := filepath.Join(destinationDir, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			key, validationErr := configSecret(path, preparedKeySize(name))
			clear(key)
			if validationErr != nil {
				return errKeyPreparation
			}
			existing, readErr := readProjectedKey(path, true)
			identical := readErr == nil && bytes.Equal(existing, raw)
			clear(existing)
			if !identical {
				return errKeyPreparation
			}
			continue
		}
		if err != nil {
			return errKeyPreparation
		}
		// Chmod only our newly O_EXCL-created file, never an existing mount/key.
		err = file.Chmod(0600)
		if err == nil {
			var n int
			n, err = file.Write(raw)
			if err == nil && n != len(raw) {
				err = io.ErrShortWrite
			}
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return errKeyPreparation
		}
	}
	if dir.Sync() != nil {
		return errKeyPreparation
	}
	return nil
}
