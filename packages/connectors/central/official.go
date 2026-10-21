package central

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

// OfficialOrigin is the shared service origin. Registry trust is pinned in the
// adopted SDK; it is never discovered from an untrusted network response.
const OfficialOrigin = "https://auth.openagent.uno"
const OfficialKeyID = "central-registry-20261021-1"
const OfficialPublicKey = "35N3Qb16evtD9iJGSZ-OqkCpUv092HEySnz9e4Z1pR0"

// OfficialClient constructs an independent client for the shared service.
// Hosts still enforce their own admission and recipient authorization.
func OfficialClient(identity auth.Identity) *Client {
	key, err := base64.RawURLEncoding.DecodeString(OfficialPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		panic("invalid compiled registry trust key")
	}
	return &Client{Origin: OfficialOrigin, Identity: identity, TrustKeys: map[string]ed25519.PublicKey{OfficialKeyID: key}}
}

// Register registers the public installation identity with the shared broker.
// It does not grant provider access or create a connector connection.
func (c *Client) Register(ctx context.Context) error {
	return c.call(ctx, http.MethodPost, "/v1/installations", c.Identity.Installation(), nil, true)
}
