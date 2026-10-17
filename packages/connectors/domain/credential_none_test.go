package domain

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestCredentialNoneIsExplicitAndContainsNoMaterial(t *testing.T) {
	var credential Credential
	if credential.IsNone() {
		t.Fatal("omitted credential became anonymous")
	}
	if err := json.Unmarshal([]byte(`{"kind":"none"}`), &credential); err != nil || !credential.IsNone() {
		t.Fatalf("explicit none: %v", err)
	}
	raw, err := json.Marshal(credential)
	if err != nil || string(raw) != `{"kind":"none"}` {
		t.Fatalf("no-auth wire: %s %v", raw, err)
	}
	if err := credential.Apply(make(http.Header), "Authorization", "Bearer", time.Now()); err == nil {
		t.Fatal("none supplied an authenticated provider header")
	}
	for _, raw := range []string{
		`{}`, `null`, `{"kind":"oauth2_bearer"}`, `{"kind":"api_token","secret":""}`,
		`{"kind":"none","secret":""}`, `{"kind":"none","secret":"token"}`, `{"kind":"none","header":""}`,
		`{"kind":"none","scheme":""}`, `{"kind":"none","version":""}`, `{"kind":"none","expires_at":null}`,
		`{"kind":"none","unknown":null}`, `{"kind":"none","kind":"none"}`,
	} {
		var rejected Credential
		if json.Unmarshal([]byte(raw), &rejected) == nil {
			t.Fatalf("accepted invalid no-auth credential: %s", raw)
		}
	}
	if _, err := NewCredential(CredentialNone, "", "", "", "", nil); err != nil {
		t.Fatal(err)
	}
	for field := 0; field < 5; field++ {
		values := [4]string{}
		var expires *time.Time
		if field < 4 {
			values[field] = "material"
		} else {
			now := time.Now()
			expires = &now
		}
		if _, err := NewCredential(CredentialNone, values[0], values[1], values[2], values[3], expires); err == nil {
			t.Fatalf("accepted material field %d", field)
		}
	}
}
