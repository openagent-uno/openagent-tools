package auth

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func getConsent(t *testing.T, tx Transaction) (*http.Response, string) {
	t.Helper()
	response, err := http.Get(tx.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

func TestApprovedConsentGETRecoversLinkWithoutNewConsent(t *testing.T) {
	f, tx, cookie := clickUpConsent(t)
	before, body := getConsent(t, tx)
	if before.StatusCode != 200 || !strings.Contains(body, "<form") || strings.Contains(body, "<a href=") {
		t.Fatal("unapproved GET exposed provider navigation")
	}
	cookie = before.Cookies()[0]
	approved, body := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
	if approved.StatusCode != 200 {
		t.Fatal("valid POST failed")
	}
	expected := providerLink(t, body).String()
	for i := 0; i < 2; i++ {
		response, body := getConsent(t, tx)
		if response.StatusCode != 200 || response.Header.Get("Location") != "" || response.Header.Get("Content-Security-Policy") != unchangedConsentCSP || response.Header.Get("Referrer-Policy") != "no-referrer" || len(response.Cookies()) != 0 || strings.Contains(body, "<form") || providerLink(t, body).String() != expected {
			t.Fatal("approved GET changed consent or provider link")
		}
	}
	replay, _ := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
	if replay.StatusCode != 403 {
		t.Fatal("GET recovery rearmed consent POST replay")
	}
	if f.calls.Load() != 0 {
		t.Fatal("recovery exchanged provider credentials")
	}
}

func TestConsentGETNeverApprovesMissingOrRejectedPOST(t *testing.T) {
	for _, post := range []bool{false, true} {
		f, tx, cookie := clickUpConsent(t)
		if post {
			response, _ := postConsent(t, f, tx, cookie, "wrong-csrf", f.http.URL)
			if response.StatusCode != 403 {
				t.Fatal("bad consent accepted")
			}
		}
		response, body := getConsent(t, tx)
		if response.StatusCode != 200 || !strings.Contains(body, "<form") || strings.Contains(body, "<a href=") {
			t.Fatal("GET approved a consent never received successfully")
		}
		f.server.mu.Lock()
		approved := f.server.transactions[tx.ID].approved
		f.server.mu.Unlock()
		if approved {
			t.Fatal("GET changed approval state")
		}
	}
}

func TestApprovedConsentRecoveryKeepsExpiryRecipientAndProviderFences(t *testing.T) {
	for _, scenario := range []string{"expired", "cancelled", "provider removed", "app replaced", "recipient removed", "recipient not admitted", "unsafe target"} {
		t.Run(scenario, func(t *testing.T) {
			f, tx, cookie := clickUpConsent(t)
			response, _ := postConsent(t, f, tx, cookie, cookie.Value, f.http.URL)
			if response.StatusCode != 200 {
				t.Fatal("valid POST failed")
			}
			switch scenario {
			case "expired":
				f.server.now = func() time.Time { return tx.ExpiresAt.Add(time.Second) }
			case "cancelled":
				f.server.mu.Lock()
				f.server.transactions[tx.ID].Status = "cancelled"
				f.server.mu.Unlock()
			case "provider removed":
				delete(f.server.Providers, "clickup")
			case "app replaced":
				p := f.server.Providers["clickup"]
				p.AppID = "different-app"
				f.server.Providers["clickup"] = p
			case "recipient removed":
				if err := f.server.Store.update(func(state *State) error { delete(state.Installations, tx.Installation); return nil }); err != nil {
					t.Fatal(err)
				}
			case "recipient not admitted":
				f.server.qa = &qaAdmission{installations: map[string]bool{}, stores: map[string]bool{}}
			case "unsafe target":
				p := f.server.Providers["clickup"]
				p.AuthorizationURL = "javascript:alert(1)"
				f.server.Providers["clickup"] = p
			}
			response, body := getConsent(t, tx)
			if response.StatusCode < 400 || strings.Contains(body, "<a href=") {
				t.Fatal("expired/revoked context exposed recovery link")
			}
		})
	}
}
