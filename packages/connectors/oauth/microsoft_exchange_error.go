package oauth

import "encoding/json"

// MicrosoftExchangeError exposes closed diagnostic labels, never token values,
// provider response bodies, account IDs or arbitrary provider messages.
type MicrosoftExchangeError struct{ stage, reason, providerCode string }

func (e *MicrosoftExchangeError) Error() string    { return ErrAuthentication.Error() }
func (e *MicrosoftExchangeError) GoString() string { return ErrAuthentication.Error() }
func (e *MicrosoftExchangeError) Unwrap() error    { return ErrAuthentication }
func (e *MicrosoftExchangeError) Stage() string {
	switch e.stage {
	case "preflight", "request", "response", "token", "scopes", "identity":
		return e.stage
	}
	return "unknown"
}
func (e *MicrosoftExchangeError) Reason() string {
	switch e.reason {
	case "code_or_scopes", "request_context", "requested_scopes", "protocol", "target", "secret", "request_invalid", "network", "response_read", "http_status", "response_size", "json", "provider_error", "token_bounds", "token_type", "expiry_invalid", "refresh_missing", "scope_missing", "scope_format", "scope_identity", "scope_config", "scope_subset", "account_verification":
		return e.reason
	}
	return "unknown"
}
func (e *MicrosoftExchangeError) ProviderCode() string {
	switch e.providerCode {
	case "none", "invalid_request", "invalid_grant", "invalid_scope", "invalid_client", "unauthorized_client", "access_denied", "interaction_required", "consent_required", "temporarily_unavailable", "server_error":
		return e.providerCode
	}
	return "other"
}
func microsoftExchangeFailure(stage, reason, code string) error {
	e := &MicrosoftExchangeError{stage, reason, code}
	return &MicrosoftExchangeError{e.Stage(), e.Reason(), e.ProviderCode()}
}
func microsoftExchangeProviderCode(body []byte) string {
	if len(body) > 1<<20 || !validAPIOnlyOAuthJSON(body) {
		return "none"
	}
	var response struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil || response.Error == "" {
		return "none"
	}
	return (&MicrosoftExchangeError{providerCode: response.Error}).ProviderCode()
}
