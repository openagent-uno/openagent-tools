package central

import (
	"encoding/base64"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

func TestOfficialTrustIsPinnedAndIndependent(t *testing.T) {
	a, b := OfficialClient(auth.Identity{}), OfficialClient(auth.Identity{})
	if a.Origin != "https://auth.openagent.uno" || a.AllowLoopback || base64.RawURLEncoding.EncodeToString(a.TrustKeys[OfficialKeyID]) != OfficialPublicKey {
		t.Fatal("invalid official trust configuration")
	}
	a.TrustKeys[OfficialKeyID][0] ^= 1
	if base64.RawURLEncoding.EncodeToString(b.TrustKeys[OfficialKeyID]) != OfficialPublicKey {
		t.Fatal("clients share mutable trust material")
	}
}
