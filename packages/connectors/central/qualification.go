package central

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// QualificationAdmission is an operator-configured, temporary Gmail trial for
// one existing installation and one trusted host principal. It never changes
// public availability or grants a consumer permission to configure admission.
type QualificationAdmission struct {
	ID             string    `json:"id"`
	Revision       uint64    `json:"revision"`
	CatalogID      string    `json:"catalog_id"`
	InstallationID string    `json:"installation_id"`
	Recipient      Recipient `json:"recipient"`
	ExpiresAt      time.Time `json:"expires_at"`
}

const gmailReadScope = "https://www.googleapis.com/auth/gmail.readonly"
const gmailComposeScope = "https://www.googleapis.com/auth/gmail.compose"

func validQualification(q QualificationAdmission) bool {
	return domain.ValidResourceID(q.ID) && q.Revision > 0 && q.CatalogID == "gmail" &&
		validHash(q.InstallationID) && recipientValid(q.Recipient) &&
		!strings.Contains(q.Recipient.WorkspaceID, "*") && !strings.Contains(q.Recipient.SubjectID, "*") && !q.ExpiresAt.IsZero()
}

func qualificationHash(q QualificationAdmission) string {
	raw, _ := json.Marshal(q)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// Validate the fixed catalog surface, not just a count of arbitrary tools.
func qualificationDescriptor(d Descriptor) bool {
	if d.Item.ID != "gmail" || d.Item.Provider != "gmail" || d.Item.Auth != "oauth" ||
		d.Setup.Mode != "oauth" || d.Setup.CredentialCustody != "service" || d.Setup.Execution != "service" || d.Setup.Interaction != "hosted" || len(d.Operations) != 7 {
		return false
	}
	names := map[string]domain.Risk{
		"outreach.gmail.messages.list":   domain.RiskRead,
		"outreach.gmail.messages.get":    domain.RiskRead,
		"outreach.gmail.threads.get":     domain.RiskRead,
		"outreach.gmail.attachments.get": domain.RiskRead,
		"outreach.gmail.drafts.create":   domain.RiskDraft,
		"outreach.gmail.drafts.send":     domain.RiskPublish,
		"outreach.gmail.messages.send":   domain.RiskPublish,
	}
	for _, op := range d.Operations {
		risk, ok := names[op.Name]
		if !ok || op.Risk != risk || op.Provider != "gmail" || op.Mode != domain.OperationTyped || op.InternalOnly {
			return false
		}
		delete(names, op.Name)
	}
	return len(names) == 0
}

func prepareQualification(q *QualificationAdmission, registry *Registry, providers map[string]oauth.Provider, now time.Time) (*QualificationAdmission, *Registry, error) {
	if q == nil {
		return nil, nil, nil
	}
	copy := *q
	copy.ExpiresAt = copy.ExpiresAt.UTC()
	// An expired retained row disables the trial without preventing the public
	// service from restarting. Far-future and unlimited trials are invalid.
	if !validQualification(copy) || copy.ExpiresAt.After(now.Add(24*time.Hour)) {
		return nil, nil, auth.ErrDenied
	}
	if !now.Before(copy.ExpiresAt) {
		// Permanently closed for this service lifetime, even if the wall clock
		// later moves backwards. No provider prerequisites remain for expiry.
		return nil, nil, nil
	}
	p := providers["gmail"]
	if p.ID != "gmail" || !p.PKCE || len(p.Scopes) != 2 ||
		!((p.Scopes[0] == gmailReadScope && p.Scopes[1] == gmailComposeScope) || (p.Scopes[1] == gmailReadScope && p.Scopes[0] == gmailComposeScope)) {
		return nil, nil, auth.ErrDenied
	}
	d, ok := registry.Lookup("gmail")
	if !ok || !qualificationDescriptor(d) {
		return nil, nil, auth.ErrDenied
	}
	d.Item.Available, d.Item.UnavailableReason = true, ""
	private, err := NewRegistry(copy.Revision, registry.keyID, registry.key, []Descriptor{d})
	if err != nil {
		return nil, nil, err
	}
	return &copy, private, nil
}

func (s *Server) qualificationActive(installation string, recipient Recipient, id string) bool {
	q := s.qualification
	return q != nil && q.ID == id && q.InstallationID == installation && q.Recipient == recipient && s.now().Before(q.ExpiresAt)
}

func (s *Server) qualificationCatalog(i auth.Installation, recipient Recipient) (SignedCatalog, error) {
	q := s.qualification
	if q == nil || !s.qualificationActive(i.ID, recipient, q.ID) {
		return SignedCatalog{}, auth.ErrDenied
	}
	var result SignedCatalog
	err := s.config.Auth.WithCentralInstallation(i, func() error {
		now := s.now().UTC()
		if !s.qualificationActive(i.ID, recipient, q.ID) {
			return auth.ErrDenied
		}
		expiry := now.Add(catalogLifetime)
		if q.ExpiresAt.Before(expiry) {
			expiry = q.ExpiresAt
		}
		payload, err := json.Marshal(Catalog{Protocol: Protocol, Revision: q.Revision, IssuedAt: now, ExpiresAt: expiry, Connectors: s.privateRegistry.descriptors, Qualification: q})
		if err != nil {
			return err
		}
		result = SignedCatalog{KeyID: s.privateRegistry.keyID, Payload: payload, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.privateRegistry.key, payload))}
		if !s.qualificationActive(i.ID, recipient, q.ID) {
			return auth.ErrDenied
		}
		return nil
	})
	return result, err
}
