package oauth

import "encoding/json"

// PostizExchangeError exposes only closed rejection labels, never a provider
// response, authorization code, client secret, token, identity or URL.
type PostizExchangeError struct {
	stage, reason, providerCode string
	status                      int
}

func (e *PostizExchangeError) Error() string    { return ErrAuthentication.Error() }
func (e *PostizExchangeError) GoString() string { return ErrAuthentication.Error() }
func (e *PostizExchangeError) Unwrap() error    { return ErrAuthentication }
func (e *PostizExchangeError) Stage() string {
	switch e.stage {
	case "preflight", "request", "response", "token", "scopes":
		return e.stage
	}
	return "unknown"
}
func (e *PostizExchangeError) Reason() string {
	switch e.reason {
	case "code_or_scopes", "protocol", "target", "secret", "request_invalid", "network", "response_read", "http_status", "response_size", "json", "token_bounds", "token_type", "scope_config", "scope_subset":
		return e.reason
	}
	return "unknown"
}
func (e *PostizExchangeError) ProviderCode() string {
	switch e.providerCode {
	case "none", "invalid_request", "invalid_grant", "invalid_scope", "invalid_client", "unauthorized_client", "access_denied", "temporarily_unavailable", "server_error":
		return e.providerCode
	}
	return "other"
}
func (e *PostizExchangeError) HTTPStatus() int {
	if e.status >= 100 && e.status <= 599 {
		return e.status
	}
	return 0
}
func postizExchangeFailure(stage, reason, code string, status int) error {
	e := &PostizExchangeError{stage, reason, code, status}
	return &PostizExchangeError{e.Stage(), e.Reason(), e.ProviderCode(), e.HTTPStatus()}
}
func postizExchangeProviderCode(body []byte) string {
	if len(body) > 1<<20 || !validAPIOnlyOAuthJSON(body) {
		return "none"
	}
	var response struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil || response.Error == "" {
		return "none"
	}
	return (&PostizExchangeError{providerCode: response.Error}).ProviderCode()
}
