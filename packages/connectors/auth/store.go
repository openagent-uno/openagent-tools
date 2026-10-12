package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State deliberately cannot hold OAuth tokens, authorization codes, or private installation keys.
type State struct {
	TokenBindings map[string]TokenBinding `json:"token_bindings"`
	Installations map[string]Installation `json:"installations"`
	Groups        map[string]*Group       `json:"groups"`
	Events        map[string]*Event       `json:"events"`
}
type TokenBinding struct {
	Installation string   `json:"installation"`
	Provider     string   `json:"provider"`
	AppID        string   `json:"app_id"`
	Scopes       []string `json:"scopes"`
}
type Group struct {
	CredentialDigest     string            `json:"credential_digest"`
	RefreshHash          string            `json:"refresh_hash"`
	Scopes               []string          `json:"scopes"`
	ID                   string            `json:"id"`
	AppID                string            `json:"app_id"`
	Shop                 string            `json:"shop"`
	Version              uint64            `json:"version"`
	Members              map[string]uint64 `json:"members"`
	Pending              string            `json:"pending,omitempty"`
	PendingUntil         time.Time         `json:"pending_until,omitempty"`
	Reconnect            bool              `json:"reconnect"`
	Revoked              bool              `json:"revoked"`
	AuthorizedAt         time.Time         `json:"authorized_at"`
	PendingAuthorization bool              `json:"pending_authorization"`
	PrivacyRecipients    map[string]bool   `json:"privacy_recipients"`
}
type Event struct {
	ID           string          `json:"id"`
	Group        string          `json:"group"`
	Topic        string          `json:"topic"`
	Ciphertext   string          `json:"ciphertext"`
	Nonce        string          `json:"nonce"`
	CreatedAt    time.Time       `json:"created_at"`
	Acknowledged map[string]bool `json:"acknowledged"`
	OccurredAt   time.Time       `json:"occurred_at"`
	BodySHA256   string          `json:"body_sha256"`
}
type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, state: State{Installations: map[string]Installation{}, Groups: map[string]*Group{}, Events: map[string]*Event{}}}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil {
			if json.Unmarshal(data, &s.state) != nil || s.state.Installations == nil || s.state.Groups == nil || s.state.Events == nil {
				return nil, errors.New("invalid connector broker state")
			}
		}
	}
	if s.state.TokenBindings == nil {
		s.state.TokenBindings = map[string]TokenBinding{}
	}
	for _, g := range s.state.Groups {
		if g.PrivacyRecipients == nil {
			g.PrivacyRecipients = map[string]bool{}
			for id := range g.Members {
				g.PrivacyRecipients[id] = true
			}
		}
	}
	return s, nil
}

// update atomically persists metadata before publishing it to other requests.
func (s *Store) update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, _ := json.Marshal(s.state)
	var next State
	if err := json.Unmarshal(before, &next); err != nil {
		return err
	}
	if err := fn(&next); err != nil {
		return err
	}
	if s.path != "" {
		data, err := json.Marshal(next)
		if err != nil {
			return err
		}
		dir := filepath.Dir(s.path)
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		file, err := os.CreateTemp(dir, ".broker-state-")
		if err != nil {
			return err
		}
		name := file.Name()
		defer os.Remove(name)
		if err = file.Chmod(0600); err == nil {
			_, err = file.Write(data)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(name, s.path)
		}
		if err != nil {
			return err
		}
		if directory, err := os.Open(dir); err == nil {
			_ = directory.Sync()
			_ = directory.Close()
		}
	}
	s.state = next
	return nil
}
func (s *Store) snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.state)
	var result State
	_ = json.Unmarshal(b, &result)
	return result
}
