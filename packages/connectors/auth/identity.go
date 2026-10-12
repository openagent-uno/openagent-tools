// Package auth supplies the optional official-app broker and its host client.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

var ErrDenied = errors.New("connector authorization denied")
var ErrConflict = errors.New("connector credential version conflict")
var ErrReconnect = errors.New("connector needs authorization again")
var encoding = base64.RawURLEncoding

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return encoding.EncodeToString(b)
}
func InstallationID(public ed25519.PublicKey) string {
	h := sha256.Sum256(public)
	return hex.EncodeToString(h[:])
}

type Identity struct {
	PrivateKey    ed25519.PrivateKey
	EncryptionKey *ecdh.PrivateKey
	Product       string
	Name          string
}

func NewIdentity(product, name string) (Identity, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	return Identity{PrivateKey: private, EncryptionKey: key, Product: product, Name: name}, err
}
func (i Identity) ID() string { return InstallationID(i.PrivateKey.Public().(ed25519.PublicKey)) }

type Installation struct {
	ID            string `json:"id"`
	PublicKey     string `json:"public_key"`
	EncryptionKey string `json:"encryption_key"`
	Product       string `json:"product"`
	Name          string `json:"name"`
}

func (i Identity) Installation() Installation {
	return Installation{ID: i.ID(), PublicKey: encoding.EncodeToString(i.PrivateKey.Public().(ed25519.PublicKey)), EncryptionKey: encoding.EncodeToString(i.EncryptionKey.PublicKey().Bytes()), Product: i.Product, Name: i.Name}
}
func signingMessage(req *http.Request, stamp, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(req.Method + "\n" + req.URL.EscapedPath() + "\n" + req.URL.RawQuery + "\n" + stamp + "\n" + nonce + "\n" + hex.EncodeToString(h[:]))
}
func (i Identity) Sign(req *http.Request, body []byte) {
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := randomID()
	req.Header.Set("X-OpenAgent-Installation", i.ID())
	req.Header.Set("X-OpenAgent-Time", stamp)
	req.Header.Set("X-OpenAgent-Nonce", nonce)
	req.Header.Set("X-OpenAgent-Signature", encoding.EncodeToString(ed25519.Sign(i.PrivateKey, signingMessage(req, stamp, nonce, body))))
}
func verifySignature(req *http.Request, body []byte, installation Installation, now time.Time) error {
	public, err := encoding.DecodeString(installation.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || InstallationID(public) != installation.ID || req.Header.Get("X-OpenAgent-Installation") != installation.ID {
		return ErrDenied
	}
	seconds, err := strconv.ParseInt(req.Header.Get("X-OpenAgent-Time"), 10, 64)
	if err != nil || now.Sub(time.Unix(seconds, 0)) > 2*time.Minute || time.Unix(seconds, 0).Sub(now) > time.Minute {
		return ErrDenied
	}
	nonce, err := encoding.DecodeString(req.Header.Get("X-OpenAgent-Nonce"))
	if err != nil || len(nonce) != 32 {
		return ErrDenied
	}
	signature, err := encoding.DecodeString(req.Header.Get("X-OpenAgent-Signature"))
	if err != nil || !ed25519.Verify(public, signingMessage(req, req.Header.Get("X-OpenAgent-Time"), req.Header.Get("X-OpenAgent-Nonce"), body), signature) {
		return ErrDenied
	}
	return nil
}

// Envelope binds ciphertext to a group, generation and exact destination.
type Envelope struct {
	Group      string    `json:"group"`
	Version    uint64    `json:"version"`
	Sender     string    `json:"sender"`
	Recipient  string    `json:"recipient"`
	PublicKey  string    `json:"public_key"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	Signature  string    `json:"signature"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (e Envelope) aad() []byte {
	return []byte(fmt.Sprintf("openagent-connectors/v1/%s/%d/%s/%s/%d", e.Group, e.Version, e.Sender, e.Recipient, e.ExpiresAt.Unix()))
}
func (e Envelope) signed() []byte {
	return append(append(e.aad(), []byte("/"+e.PublicKey+"/"+e.Nonce+"/")...), []byte(e.Ciphertext)...)
}
func Seal(identity Identity, recipient Installation, group string, version uint64, plaintext []byte, now time.Time) (Envelope, error) {
	publicBytes, err := encoding.DecodeString(recipient.EncryptionKey)
	if err != nil {
		return Envelope{}, ErrDenied
	}
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return Envelope{}, ErrDenied
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Envelope{}, err
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return Envelope{}, ErrDenied
	}
	e := Envelope{Group: group, Version: version, Sender: identity.ID(), Recipient: recipient.ID, PublicKey: encoding.EncodeToString(private.PublicKey().Bytes()), ExpiresAt: now.UTC().Add(10 * time.Minute).Truncate(time.Second)}
	key := sha256.Sum256(append(shared, e.aad()...))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	e.Nonce = encoding.EncodeToString(nonce)
	e.Ciphertext = encoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, e.aad()))
	e.Signature = encoding.EncodeToString(ed25519.Sign(identity.PrivateKey, e.signed()))
	return e, nil
}
func Open(identity Identity, sender Installation, e Envelope, now time.Time) ([]byte, error) {
	if e.Sender != sender.ID || e.Recipient != identity.ID() || !now.Before(e.ExpiresAt) || e.ExpiresAt.After(now.Add(10*time.Minute)) {
		return nil, ErrDenied
	}
	public, err := encoding.DecodeString(sender.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, ErrDenied
	}
	signature, err := encoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(public, e.signed(), signature) {
		return nil, ErrDenied
	}
	ephemeral, err := encoding.DecodeString(e.PublicKey)
	if err != nil {
		return nil, ErrDenied
	}
	peer, err := ecdh.X25519().NewPublicKey(ephemeral)
	if err != nil {
		return nil, ErrDenied
	}
	shared, err := identity.EncryptionKey.ECDH(peer)
	if err != nil {
		return nil, ErrDenied
	}
	key := sha256.Sum256(append(shared, e.aad()...))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce, err := encoding.DecodeString(e.Nonce)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, ErrDenied
	}
	data, err := encoding.DecodeString(e.Ciphertext)
	if err != nil {
		return nil, ErrDenied
	}
	plaintext, err := gcm.Open(nil, nonce, data, e.aad())
	if err != nil {
		return nil, ErrDenied
	}
	return plaintext, nil
}
