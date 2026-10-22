//go:build darwin || linux

package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func qualificationSigned(t *testing.T, f *qualificationFixture) SignedCatalog {
	t.Helper()
	var signed SignedCatalog
	input := struct {
		Recipient Recipient `json:"recipient"`
	}{f.rule.Recipient}
	if err := f.client.call(context.Background(), http.MethodPost, "/v1/registry/qualification", input, &signed, true); err != nil {
		t.Fatal(err)
	}
	return signed
}

type qualificationRoundTrip func(*http.Request) (*http.Response, error)

func (fn qualificationRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// A signed, controlled server response isolates SDK signature/scope verification
// from server admission tests, which use the real authenticated HTTP endpoint.
func qualificationSDKClient(f *qualificationFixture, response func(*http.Request) SignedCatalog) *Client {
	return &Client{Origin: "https://catalog.fixture.invalid", Identity: f.client.Identity,
		TrustKeys: f.client.TrustKeys, HTTP: &http.Client{Transport: qualificationRoundTrip(func(r *http.Request) (*http.Response, error) {
			data, err := json.Marshal(response(r))
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
		})}}
}

func qualificationResign(t *testing.T, f *qualificationFixture, original SignedCatalog, mutate func(*Catalog)) SignedCatalog {
	t.Helper()
	var catalog Catalog
	if err := json.Unmarshal(original.Payload, &catalog); err != nil {
		t.Fatal(err)
	}
	mutate(&catalog)
	payload, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return SignedCatalog{KeyID: original.KeyID, Payload: payload, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, payload))}
}

func TestGmailQualificationPrivateCatalogIsExactAndPublicRemainsClosed(t *testing.T) {
	f := newQualificationFixture(t)
	ctx := context.Background()
	before := f.config.Registry.Snapshot(f.now())
	public, err := f.client.Catalog(ctx)
	if err != nil || public.Qualification != nil || public.Revision != 9 {
		t.Fatalf("public registry unavailable: %v", err)
	}
	private, err := f.client.QualificationCatalog(ctx, f.rule.Recipient)
	if err != nil || private.Qualification == nil || *private.Qualification != f.rule || private.Revision != f.rule.Revision || len(private.Connectors) != 1 {
		t.Fatalf("exact private Gmail scope unavailable: %v", err)
	}
	if d := private.Connectors[0]; !d.Item.Available || !qualificationDescriptor(d) || d.ContractSHA256 != f.descriptor.ContractSHA256 || len(d.Item.ReadTools) != 4 || len(d.Item.AgentTools) != 3 {
		t.Fatal("private catalog replaced compiled operations or changed the contract")
	}
	if private.ExpiresAt.After(private.IssuedAt.Add(5*time.Minute)) || private.ExpiresAt.After(f.rule.ExpiresAt) {
		t.Fatal("private catalog escaped its bounded expiry")
	}
	for _, d := range public.Connectors {
		if d.Item.ID == "gmail" && d.Item.Available {
			t.Fatal("private qualification enabled public Gmail")
		}
	}
	after := f.config.Registry.Snapshot(f.now())
	if !bytes.Equal(before.Payload, after.Payload) || before.Signature != after.Signature {
		t.Fatal("qualification mutated the immutable public registry")
	}
	// Same contract is intentionally not authority: callers must explicitly
	// identify the qualification, not merely copy its descriptor hash.
	request := f.createRequest()
	request.QualificationID = ""
	if _, err := f.client.Create(ctx, request); err == nil || f.exchanges.Load() != 0 {
		t.Fatal("private contract hash bypassed public admission")
	}
	request.QualificationID = "wrong-qualification"
	if _, err := f.client.Create(ctx, request); err == nil {
		t.Fatal("another qualification ID was admitted")
	}
	f.assertPrivate(t)
}

func TestGmailQualificationExactInstallationRecipientAndSignature(t *testing.T) {
	f := newQualificationFixture(t)
	ctx := context.Background()
	for _, recipient := range []Recipient{{"workspace", "different-subject"}, {"different-workspace", "owner"}} {
		if _, err := f.client.QualificationCatalog(ctx, recipient); err == nil {
			t.Fatal("private descriptor crossed the exact recipient boundary")
		}
		request := f.createRequest()
		request.Recipient = recipient
		if _, err := f.client.Create(ctx, request); err == nil {
			t.Fatal("private grant crossed the exact recipient boundary")
		}
	}
	identity, err := auth.NewIdentity("other-host", "Another registered host")
	if err != nil {
		t.Fatal(err)
	}
	registration := &auth.Client{Origin: f.http.URL, Identity: identity, HTTP: f.client.HTTP, AllowLoopback: true}
	if err := registration.Register(ctx); err != nil {
		t.Fatal(err)
	}
	other := &Client{Origin: f.http.URL, Identity: identity, HTTP: f.client.HTTP, AllowLoopback: true, TrustKeys: f.client.TrustKeys}
	if _, err := other.QualificationCatalog(ctx, f.rule.Recipient); err == nil {
		t.Fatal("a different registered installation received the private scope")
	}
	if _, err := other.Create(ctx, f.createRequest()); err == nil {
		t.Fatal("a different installation created the qualification grant")
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, _ := http.NewRequest(method, f.http.URL+"/v1/registry/qualification", strings.NewReader(`{"recipient":{"workspace_id":"workspace","subject_id":"owner"}}`))
		response, err := f.client.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode == 200 || bytes.Contains(body, []byte(f.rule.ID)) || bytes.Contains(body, []byte(f.rule.InstallationID)) || bytes.Contains(body, []byte("outreach.gmail")) {
			t.Fatal("unsigned endpoint disclosed private admission metadata")
		}
	}
	if f.apiCalls.Load() != 0 || f.exchanges.Load() != 0 {
		t.Fatal("rejected private admission performed provider IO")
	}
}

func TestGmailQualificationCatalogExpiryAndCallerPolicyOwnership(t *testing.T) {
	f := newQualificationFixture(t)
	q := f.rule
	q.ExpiresAt = f.now().Add(2 * time.Minute)
	wanted := q
	f.replace(t, &q, f.config.Registry)
	q.Recipient.SubjectID = "mutated-caller-pointer"
	q.ExpiresAt = f.now().Add(10 * time.Hour)
	catalog, err := f.client.QualificationCatalog(context.Background(), f.rule.Recipient)
	if err != nil || catalog.Qualification == nil || *catalog.Qualification != wanted || !catalog.ExpiresAt.Equal(wanted.ExpiresAt) {
		t.Fatal("caller mutation extended or redirected the admitted scope")
	}
	f.clock.Store(wanted.ExpiresAt.UnixNano())
	if _, err := f.client.QualificationCatalog(context.Background(), f.rule.Recipient); err == nil {
		t.Fatal("qualification remained active at its exact expiry")
	}
}

func TestGmailQualificationSDKRejectsValidlySignedWrongScope(t *testing.T) {
	f := newQualificationFixture(t)
	original := qualificationSigned(t, f)
	cases := map[string]func(*Catalog){
		"public-envelope":  func(c *Catalog) { c.Qualification = nil },
		"installation":     func(c *Catalog) { c.Qualification.InstallationID = strings.Repeat("a", 64) },
		"workspace":        func(c *Catalog) { c.Qualification.Recipient.WorkspaceID = "another-workspace" },
		"subject":          func(c *Catalog) { c.Qualification.Recipient.SubjectID = "another-subject" },
		"provider":         func(c *Catalog) { c.Qualification.CatalogID = "google-drive" },
		"revision":         func(c *Catalog) { c.Qualification.Revision++ },
		"expired":          func(c *Catalog) { c.Qualification.ExpiresAt = time.Now().Add(-time.Minute) },
		"expiry-overrun":   func(c *Catalog) { c.Qualification.ExpiresAt = c.ExpiresAt.Add(-time.Second) },
		"unbounded-expiry": func(c *Catalog) { c.Qualification.ExpiresAt = c.IssuedAt.Add(25 * time.Hour) },
		"unavailable":      func(c *Catalog) { c.Connectors[0].Item.Available = false },
		"extra-descriptor": func(c *Catalog) { c.Connectors = append(c.Connectors, c.Connectors[0]) },
		"altered-tool": func(c *Catalog) {
			c.Connectors[0].Operations[0].Name = "outreach.gmail.internal.raw"
			c.Connectors[0].ContractSHA256 = ComputeContract(c.Connectors[0])
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			envelope := qualificationResign(t, f, original, mutate)
			client := qualificationSDKClient(f, func(*http.Request) SignedCatalog { return envelope })
			if _, err := client.QualificationCatalog(context.Background(), f.rule.Recipient); err == nil {
				t.Fatal("trusted signature alone authorized the wrong private scope")
			}
		})
	}
	// Private descriptors are never accepted by the public verifier, even when
	// signed by the public registry key and fetched from the public URL.
	client := qualificationSDKClient(f, func(*http.Request) SignedCatalog { return original })
	if _, err := client.Catalog(context.Background()); err == nil {
		t.Fatal("private catalog was usable as a public catalog")
	}
}

func TestGmailQualificationSDKCacheSeparatedAndDriftBound(t *testing.T) {
	f := newQualificationFixture(t)
	private := qualificationSigned(t, f)
	public := f.config.Registry.Snapshot(time.Now())
	for _, privateFirst := range []bool{false, true} {
		client := qualificationSDKClient(f, func(r *http.Request) SignedCatalog {
			if r.URL.Path == "/v1/registry/qualification" {
				return private
			}
			return public
		})
		privateCall := func() {
			t.Helper()
			if catalog, err := client.QualificationCatalog(context.Background(), f.rule.Recipient); err != nil || catalog.Revision != 1 {
				t.Fatalf("public revision contaminated private cache: %v", err)
			}
		}
		publicCall := func() {
			t.Helper()
			if catalog, err := client.Catalog(context.Background()); err != nil || catalog.Revision != 9 {
				t.Fatalf("private revision contaminated public cache: %v", err)
			}
		}
		if privateFirst {
			privateCall()
			publicCall()
		} else {
			publicCall()
			privateCall()
		}
		privateCall()
		publicCall()
	}
	served := private
	client := qualificationSDKClient(f, func(*http.Request) SignedCatalog { return served })
	if _, err := client.QualificationCatalog(context.Background(), f.rule.Recipient); err != nil {
		t.Fatal(err)
	}
	served = qualificationResign(t, f, private, func(c *Catalog) { c.Qualification.ExpiresAt = c.Qualification.ExpiresAt.Add(time.Minute) })
	if _, err := client.QualificationCatalog(context.Background(), f.rule.Recipient); err == nil {
		t.Fatal("same-revision policy expiry drift created a fresh cache slot")
	}
	served = qualificationResign(t, f, private, func(c *Catalog) { c.Revision = 2; c.Qualification.Revision = 2 })
	if _, err := client.QualificationCatalog(context.Background(), f.rule.Recipient); err != nil {
		t.Fatal("explicit higher private revision was rejected")
	}
	served = private
	if _, err := client.QualificationCatalog(context.Background(), f.rule.Recipient); err == nil {
		t.Fatal("private cache accepted a rollback")
	}
}

func TestGmailQualificationConfigRejectsBroaderOrAmbiguousAdmission(t *testing.T) {
	mutations := map[string]func(*QualificationAdmission){
		"blank-id":              func(q *QualificationAdmission) { q.ID = "" },
		"wildcard-id":           func(q *QualificationAdmission) { q.ID = "*" },
		"zero-revision":         func(q *QualificationAdmission) { q.Revision = 0 },
		"other-provider":        func(q *QualificationAdmission) { q.CatalogID = "google-drive" },
		"missing-installation":  func(q *QualificationAdmission) { q.InstallationID = "" },
		"wildcard-installation": func(q *QualificationAdmission) { q.InstallationID = "*" },
		"blank-workspace":       func(q *QualificationAdmission) { q.Recipient.WorkspaceID = "" },
		"wildcard-workspace":    func(q *QualificationAdmission) { q.Recipient.WorkspaceID = "*" },
		"blank-subject":         func(q *QualificationAdmission) { q.Recipient.SubjectID = "" },
		"wildcard-subject":      func(q *QualificationAdmission) { q.Recipient.SubjectID = "*" },
		"unlimited":             func(q *QualificationAdmission) { q.ExpiresAt = time.Time{} },
		"too-long":              func(q *QualificationAdmission) { q.ExpiresAt = time.Now().Add(25 * time.Hour) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newQualificationFixture(t)
			q := f.rule
			mutate(&q)
			config := f.config
			config.GmailQualification = &q
			if _, err := NewServer(config); err == nil {
				t.Fatal("invalid or broad private admission accepted")
			}
		})
	}
	for _, scopes := range [][]string{{centralOAuthModify}, {centralOAuthModify, centralOAuthSend, "https://www.googleapis.com/auth/drive"}, {centralOAuthModify, centralOAuthModify}} {
		f := newQualificationFixture(t)
		p := f.config.Auth.Providers["gmail"]
		p.Scopes = scopes
		f.config.Auth.Providers["gmail"] = p
		config := f.config
		config.GmailQualification = &f.rule
		if _, err := NewServer(config); err == nil {
			t.Fatal("private Gmail admission accepted a different configured scope set")
		}
	}
	for _, fragment := range []string{`"unknown":true,`, `"revision":2,`} {
		f := newServiceConfigFixture(t)
		f.config.GmailQualification = &QualificationAdmission{ID: "gmail-qa-fixture", Revision: 1, CatalogID: "gmail", InstallationID: strings.Repeat("a", 64), Recipient: Recipient{"workspace", "owner"}, ExpiresAt: time.Now().Add(-time.Hour)}
		data, _ := json.Marshal(f.config)
		data = bytes.Replace(data, []byte(`"gmail_qualification":{`), []byte(`"gmail_qualification":{`+fragment), 1)
		if err := os.WriteFile(f.path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, closeVault, err := LoadService(f.path, f.broker, f.runtime); err == nil {
			_ = closeVault()
			t.Fatal("unknown/duplicate qualification config field accepted")
		}
	}
}

func TestGmailQualificationExpiredRetainedPolicyAllowsUnrelatedRestart(t *testing.T) {
	for _, providers := range []map[string]oauth.Provider{nil, {"gmail": {ID: "gmail", Scopes: []string{"removed-old-scope"}}}} {
		f := newServiceConfigFixture(t)
		f.broker.Providers = providers
		f.config.GmailQualification = &QualificationAdmission{ID: "expired-gmail-qa", Revision: 1, CatalogID: "gmail", InstallationID: strings.Repeat("a", 64), Recipient: Recipient{"workspace", "owner"}, ExpiresAt: time.Now().Add(-time.Hour)}
		f.write(t)
		server, closeVault, err := LoadService(f.path, f.broker, f.runtime)
		if err != nil {
			t.Fatalf("expired retained policy prevented unrelated startup: %v", err)
		}
		t.Cleanup(func() { _ = closeVault() })
		server.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
		if server.qualificationActive(strings.Repeat("a", 64), Recipient{"workspace", "owner"}, "expired-gmail-qa") {
			t.Fatal("clock rollback reopened a policy expired at startup")
		}
		if server.privateRegistry != nil {
			t.Fatal("expired policy generated a private catalog")
		}
		for _, descriptor := range server.config.Registry.descriptors {
			if descriptor.Item.Available {
				t.Fatal("expired policy enabled an unrelated public connector")
			}
		}
	}
}
