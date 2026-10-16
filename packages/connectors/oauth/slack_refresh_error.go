package oauth

// SlackRefreshError exposes only fixed diagnostic labels, never provider bodies
// or credentials. The public authentication error contract stays unchanged.
type SlackRefreshError struct{ stage, reason, providerCode string }

func (e *SlackRefreshError) Error() string { return ErrAuthentication.Error() }
func (e *SlackRefreshError) Unwrap() error { return ErrAuthentication }
func (e *SlackRefreshError) Stage() string {
	switch e.stage {
	case "preflight", "request", "response", "token", "scopes":
		return e.stage
	}
	return "unknown"
}
func (e *SlackRefreshError) Reason() string {
	switch e.reason {
	case "refresh_invalid", "scope_config", "team_invalid", "protocol", "target", "secret", "request_invalid", "network", "response_read", "response_size", "http_status", "json", "ok_missing", "ok_false", "enterprise", "unexpected_nested", "refresh_missing", "expiry_invalid", "team_mismatch", "token_type", "scope_missing", "token_prefix", "rotation_shape", "token_bounds", "scope_subset":
		return e.reason
	}
	return "unknown"
}
func (e *SlackRefreshError) ProviderCode() string {
	switch e.providerCode {
	case "none", "invalid_refresh_token", "token_expired", "token_revoked", "bad_client_secret", "invalid_client_id", "bad_redirect_uri", "invalid_grant_type", "ratelimited", "service_unavailable", "invalid_auth", "invalid_arguments", "not_allowed_token_type", "access_denied", "internal_error":
		return e.providerCode
	}
	return "other"
}
func slackRefreshFailure(stage, reason, providerCode string) error {
	e := &SlackRefreshError{stage, reason, providerCode}
	return &SlackRefreshError{e.Stage(), e.Reason(), e.ProviderCode()}
}
