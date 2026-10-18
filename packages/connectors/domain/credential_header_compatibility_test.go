package domain

import (
	"net/http"
	"testing"
	"time"
)

func TestCredentialAcceptsFixedRFCUnderscoreHeaderWithoutTargetOverride(t *testing.T) {
	for _, header := range []string{"", "X-CMC_PRO_API_KEY"} {
		c, e := NewCredential(CredentialAPIToken, "fixture-token", header, "", "fixture", nil)
		if e != nil {
			t.Fatal(e)
		}
		headers := make(http.Header)
		if e = c.Apply(headers, "X-CMC_PRO_API_KEY", "", time.Now()); e != nil || headers.Get("X-CMC_PRO_API_KEY") != "fixture-token" {
			t.Fatal("documented fixed header rejected", e)
		}
	}
	c, e := NewCredential(CredentialAPIToken, "fixture-token", "X-CMC_PRO_API_KEY", "", "fixture", nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Apply(make(http.Header), "Authorization", "Bearer", time.Now()); e == nil {
		t.Fatal("credential target override accepted")
	}
	for _, header := range []string{"X-Bad Header", "X-Bad\r\nInjected", "X-Bad:Header", "X-Bad/Header", "X-Bad\x00Header"} {
		if _, e := NewCredential(CredentialAPIToken, "fixture-token", header, "", "fixture", nil); e == nil {
			t.Fatal("unsafe credential header accepted")
		}
	}
}
