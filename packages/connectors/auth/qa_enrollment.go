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
	if s.qa != nil || s.shopifyQA != nil || len(s.legacyShopifyWebhooks) != 0 || len(config.Installations) == 0 || len(config.Installations) > 50 || len(config.ShopifyStores) > 10 {
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
	return (s.qa == nil || s.qa.stores[shop]) && (s.shopifyQA == nil || s.shopifyQA.stores[shop])
}

// ConfigureShopifyQAEnrollment restricts only Shopify. Other providers retain
// public enrollment, existing token bindings and public readiness. The broker
// remains the single writer; this gate does not create another token authority.
func (s *Server) ConfigureShopifyQAEnrollment(config QAEnrollment) error {
	if s.qa != nil || s.shopifyQA != nil || len(s.legacyShopifyWebhooks) != 0 || s.Providers["shopify"].ID != "shopify" || len(config.Installations) == 0 || len(config.Installations) > 50 || len(config.ShopifyStores) == 0 || len(config.ShopifyStores) > 10 {
		return ErrDenied
	}
	admission := &qaAdmission{installations: map[string]bool{}, stores: map[string]bool{}}
	for _, id := range config.Installations {
		fingerprint, err := hex.DecodeString(id)
		if err != nil || len(fingerprint) != 32 || hex.EncodeToString(fingerprint) != id || admission.installations[id] {
			return ErrDenied
		}
		admission.installations[id] = true
	}
	for _, shop := range config.ShopifyStores {
		if !oauth.ValidShop(shop) || admission.stores[shop] {
			return ErrDenied
		}
		admission.stores[shop] = true
	}
	state := s.Store.snapshot()
	for _, group := range state.Groups {
		if group.AppID != s.Providers["shopify"].AppID || !admission.stores[group.Shop] {
			return ErrDenied
		}
		for member := range group.Members {
			if !admission.installations[member] {
				return ErrDenied
			}
		}
		for member := range group.PrivacyRecipients {
			if !admission.installations[member] {
				return ErrDenied
			}
		}
		if group.Pending != "" && !admission.installations[group.Pending] {
			return ErrDenied
		}
	}
	for _, binding := range state.TokenBindings {
		if binding.Provider == "shopify" && (!admission.installations[binding.Installation] || !admission.stores[binding.ExternalID] || binding.AppID != s.Providers["shopify"].AppID) {
			return ErrDenied
		}
	}
	// A queued legacy delivery must never resume under a scoped QA deployment.
	for _, event := range state.Events {
		if event.Legacy != nil || state.Groups[event.Group] == nil {
			return ErrDenied
		}
		for recipient := range event.Acknowledged {
			if !admission.installations[recipient] {
				return ErrDenied
			}
		}
	}
	s.shopifyQA = admission
	return nil
}

func (s *Server) admittedProviderInstallation(provider, id string) bool {
	return s.admittedInstallation(id) && (provider != "shopify" || s.shopifyQA == nil || s.shopifyQA.installations[id])
}
