package auth

import (
	"encoding/hex"

	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// QAEnrollment is an explicit startup-only gate. Installation names or product
// labels never confer admission; only the pinned signing-key fingerprints do.
// Shopify stores must be dedicated QA stores, not existing production grants.
type QAEnrollment struct {
	Installations []string `json:"installations"`
	ShopifyStores []string `json:"shopify_stores,omitempty"`
}

func (s *Server) ConfigureQAEnrollment(config QAEnrollment) error {
	if s.qa != nil || len(s.legacyShopifyWebhooks) != 0 || len(config.Installations) == 0 || len(config.Installations) > 50 || len(config.ShopifyStores) > 10 {
		return ErrDenied
	}
	installations := map[string]bool{}
	for _, id := range config.Installations {
		fingerprint, err := hex.DecodeString(id)
		if err != nil || len(fingerprint) != 32 || hex.EncodeToString(fingerprint) != id || installations[id] {
			return ErrDenied
		}
		installations[id] = true
	}
	stores := map[string]bool{}
	for _, shop := range config.ShopifyStores {
		if !oauth.ValidShop(shop) || stores[shop] {
			return ErrDenied
		}
		stores[shop] = true
	}
	if s.Providers["shopify"].ID != "" && len(stores) == 0 {
		return ErrDenied
	}
	// A production synchronization group cannot become a QA group by changing
	// a configuration file. Keep metadata on rollback, but refuse mixed cohorts.
	for _, group := range s.Store.snapshot().Groups {
		if !stores[group.Shop] {
			return ErrDenied
		}
		for member := range group.PrivacyRecipients {
			if !installations[member] {
				return ErrDenied
			}
		}
	}
	for _, binding := range s.Store.snapshot().TokenBindings {
		if !installations[binding.Installation] {
			return ErrDenied
		}
	}
	s.qa = &qaAdmission{installations: installations, stores: stores}
	return nil
}

type qaAdmission struct {
	installations map[string]bool
	stores        map[string]bool
}

// QAEnrollmentEnabled lets the process expose QA as not publicly ready.
func (s *Server) QAEnrollmentEnabled() bool { return s.qa != nil }

func (s *Server) admittedInstallation(id string) bool {
	return s.qa == nil || s.qa.installations[id]
}

func (s *Server) admittedShop(shop string) bool {
	return s.qa == nil || s.qa.stores[shop]
}
