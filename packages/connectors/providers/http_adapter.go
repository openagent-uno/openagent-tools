package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type HTTPAdapter struct {
	manifest                  Manifest
	doer                      HTTPDoer
	operations                map[string]OperationManifest
	shopifyThemeWritesEnabled bool
	driveUpload               driveUploadLimits
	now                       func() time.Time
	sleep                     func(context.Context, time.Duration) error
}

type AdapterOptions struct {
	ShopifyThemeWritesEnabled bool
	DriveSimpleUploadMaxBytes int64
	DriveUploadMaxBytes       int64
	DriveResumableChunkBytes  int64
}

type CatalogOptions struct {
	ShopifyThemeWritesEnabled bool
	DriveSimpleUploadMaxBytes int64
	DriveUploadMaxBytes       int64
	DriveResumableChunkBytes  int64
}

type requestPlan struct {
	operation   OperationManifest
	method      string
	target      *url.URL
	body        []byte
	contentType string
	driveUpload *driveUploadRequest
}

var (
	pathTemplatePattern              = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]{0,63})\}`)
	pathValuePattern                 = regexp.MustCompile(`^[A-Za-z0-9._~:@+\-]{1,512}$`)
	shopLabelPattern                 = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	shopifyThemeMutationFieldPattern = regexp.MustCompile(`\btheme[A-Z][A-Za-z0-9_]*\b`)
)

func NewHTTPAdapter(manifest Manifest, doer HTTPDoer) (*HTTPAdapter, error) {
	return NewHTTPAdapterWithOptions(manifest, doer, AdapterOptions{})
}

func NewHTTPAdapterWithOptions(manifest Manifest, doer HTTPDoer, options AdapterOptions) (*HTTPAdapter, error) {
	if doer == nil {
		return nil, errors.New("provider HTTP transport is required")
	}
	manifest = cloneManifest(manifest)
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	operations := make(map[string]OperationManifest, len(manifest.Operations))
	for _, operation := range manifest.Operations {
		operations[operation.Name] = operation
	}
	driveUpload, err := newDriveUploadLimits(options.DriveSimpleUploadMaxBytes, options.DriveUploadMaxBytes, options.DriveResumableChunkBytes)
	if err != nil {
		return nil, err
	}
	return &HTTPAdapter{
		manifest:                  manifest,
		doer:                      doer,
		operations:                operations,
		shopifyThemeWritesEnabled: options.ShopifyThemeWritesEnabled,
		driveUpload:               driveUpload,
		now:                       time.Now,
		sleep:                     sleepContext,
	}, nil
}

func (a *HTTPAdapter) Provider() string { return a.manifest.Provider }

func (a *HTTPAdapter) Capability() domain.Capability { return a.manifest.Capability }

func (a *HTTPAdapter) Operations() []domain.Operation {
	result := make([]domain.Operation, 0, len(a.manifest.Operations))
	for _, operation := range a.manifest.Operations {
		mode := domain.OperationTyped
		previewMethod := operation.Method
		previewPath := operation.Path
		if operation.Raw != nil {
			mode = domain.OperationRaw
			previewMethod = strings.Join(operation.Raw.Methods, "|")
			previewPath = strings.Join(operation.Raw.PathPrefixes, ",")
		}
		retry := domain.RetryPolicy{MaxAttempts: operation.Retry.MaxAttempts, BaseDelayMillis: operation.Retry.BaseDelay.Milliseconds(), SupportsIdempotency: operation.Retry.RetryableWrite}
		result = append(result, domain.Operation{
			Name: operation.Name, Description: operation.Description, Capability: a.manifest.Capability,
			Provider: a.manifest.Provider, Risk: operation.Risk, Mode: mode, InputSchema: cloneBytes(operation.InputSchema),
			RequiredScopes: append([]string(nil), operation.RequiredScopes...), InternalOnly: operation.InternalOnly,
			Retry:   retry,
			Preview: domain.ActionPreview{Method: previewMethod, Path: previewPath, Summary: operation.Description},
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// Preview validates and normalizes the complete provider request without
// resolving or applying a credential. The gateway calls this before policy
// approval, so raw method/path validation cannot be deferred until execution.
func (a *HTTPAdapter) Preview(invocation domain.Invocation) (domain.ActionPreview, error) {
	plan, err := a.buildPlan(invocation)
	if err != nil {
		return domain.ActionPreview{}, err
	}
	path := plan.target.EscapedPath()
	if plan.target.RawQuery != "" {
		path += "?" + plan.target.RawQuery
	}
	return domain.ActionPreview{Method: plan.method, Path: path, Summary: plan.operation.Description}, nil
}

func (a *HTTPAdapter) Invoke(ctx context.Context, invocation domain.Invocation) (domain.Result, error) {
	if len(invocation.Idempotency) > 256 || strings.ContainsAny(invocation.Idempotency, "\r\n\x00") {
		return domain.Result{}, domain.ErrInvalidArguments
	}
	plan, err := a.buildPlan(invocation)
	if err != nil {
		return domain.Result{}, err
	}
	if plan.driveUpload != nil {
		return a.invokeDriveUpload(ctx, invocation, plan)
	}
	maxAttempts := plan.operation.Retry.MaxAttempts
	if plan.operation.Risk != domain.RiskRead && !safeMethod(plan.method) && (!plan.operation.Retry.RetryableWrite || invocation.Idempotency == "") {
		maxAttempts = 1
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var requestBytes, responseBytes int64
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		request, requestErr := http.NewRequestWithContext(ctx, plan.method, plan.target.String(), bytes.NewReader(plan.body))
		if requestErr != nil {
			return domain.Result{}, domain.ErrInvalidArguments
		}
		request.Header.Set("Accept", "application/json, application/octet-stream;q=0.9, */*;q=0.8")
		request.Header.Set("User-Agent", "OpenAgent-Connector/1.0")
		if a.manifest.Provider == "github" {
			request.Header.Set("Accept", "application/vnd.github+json")
			request.Header.Set("X-GitHub-Api-Version", GitHubAPIVersion)
		}
		if a.manifest.Provider == "notion" {
			request.Header.Set("Notion-Version", notionAPIVersion)
		}
		if len(plan.body) > 0 {
			request.Header.Set("Content-Type", plan.contentType)
		}
		if invocation.Idempotency != "" && plan.operation.IdempotencyHeader != "" {
			request.Header.Set(plan.operation.IdempotencyHeader, invocation.Idempotency)
		}
		if credentialErr := invocation.Credential.Apply(request.Header, a.manifest.CredentialHeader, a.manifest.CredentialScheme, a.now().UTC()); credentialErr != nil {
			return domain.Result{}, &domain.ProviderError{Kind: "credential_error", Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes}
		}
		if err := validatePlatformCredential(a.manifest.Provider, request.Header.Get("Authorization")); err != nil {
			return domain.Result{}, err
		}
		if a.manifest.Provider == "replio" {
			sent, received, err := a.validateReplioContext(ctx, invocation, request.Header.Get("Authorization"))
			requestBytes += sent
			responseBytes += received
			if err != nil {
				return domain.Result{}, errors.Join(err, &domain.ProviderError{
					Kind: "credential_scope_error", Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes,
				})
			}
		}

		requestBytes += int64(len(plan.body))
		response, requestErr := a.doer.Do(request)
		if requestErr != nil || response == nil {
			if attempt < maxAttempts {
				if err := a.sleep(ctx, retryDelay(plan.operation.Retry, attempt, "")); err != nil {
					return domain.Result{}, err
				}
				continue
			}
			return domain.Result{}, &domain.ProviderError{Kind: "network_error", Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes}
		}

		data, tooLarge, readErr := readBounded(response.Body, a.manifest.MaxResponseBytes)
		_ = response.Body.Close()
		responseBytes += int64(len(data))
		providerID := providerRequestID(response.Header)
		if readErr != nil {
			return domain.Result{}, &domain.ProviderError{Kind: "response_error", StatusCode: response.StatusCode, ProviderID: providerID, Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes}
		}
		if tooLarge {
			return domain.Result{}, &domain.ProviderError{Kind: "response_too_large", StatusCode: response.StatusCode, ProviderID: providerID, Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes}
		}
		data = invocation.Credential.Redact(data)

		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			if attempt < maxAttempts && retryableStatus(plan.operation.Retry, response.StatusCode) {
				if err := a.sleep(ctx, retryDelay(plan.operation.Retry, attempt, response.Header.Get("Retry-After"))); err != nil {
					return domain.Result{}, err
				}
				continue
			}
			kind := "provider_error"
			if response.StatusCode == http.StatusTooManyRequests {
				kind = "rate_limited"
			}
			providerErr := &domain.ProviderError{Kind: kind, StatusCode: response.StatusCode, ProviderID: providerID, Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes}
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
				return domain.Result{}, errors.Join(domain.ErrProviderPermission, providerErr)
			}
			return domain.Result{}, providerErr
		}

		if a.manifest.Provider == "slack_import" {
			if kind, permission := slackResponseFailure(data); kind != "" {
				providerErr := &domain.ProviderError{Kind: kind, StatusCode: response.StatusCode, ProviderID: providerID,
					Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes}
				if permission {
					return domain.Result{}, errors.Join(domain.ErrProviderPermission, providerErr)
				}
				return domain.Result{}, providerErr
			}
		}
		decoded := decodeProviderBody(data, response.Header.Get("Content-Type"))
		if shopifyGraphQLPermissionDenied(a.manifest.Provider, plan, data) {
			providerErr := &domain.ProviderError{
				Kind: "provider_permission", StatusCode: response.StatusCode, ProviderID: providerID,
				Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes,
			}
			return domain.Result{}, errors.Join(domain.ErrProviderPermission, providerErr)
		}
		if providerApplicationError(a.manifest.Provider, plan, data) {
			return domain.Result{}, &domain.ProviderError{
				Kind: "provider_operation_error", StatusCode: response.StatusCode, ProviderID: providerID,
				Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes,
			}
		}
		metadata := map[string]string{
			"provider": a.manifest.Provider, "api_version": a.manifest.APIVersion,
			"operation": plan.operation.Name, "idempotency_applied": strconv.FormatBool(idempotencyApplied(plan.operation, invocation.Idempotency)),
		}
		return domain.Result{Data: decoded, ProviderID: providerID, ProviderStatus: response.StatusCode, Attempts: attempt, RequestBytes: requestBytes, ResponseBytes: responseBytes, Metadata: metadata}, nil
	}
	return domain.Result{}, &domain.ProviderError{Kind: "provider_error", Attempts: maxAttempts, RequestBytes: requestBytes, ResponseBytes: responseBytes}
}

func (a *HTTPAdapter) buildPlan(invocation domain.Invocation) (requestPlan, error) {
	operation, ok := a.operations[invocation.Operation.Name]
	if !ok || invocation.Connection.Provider != a.manifest.Provider || invocation.Connection.Capability != a.manifest.Capability {
		return requestPlan{}, domain.ErrUnsupported
	}
	if err := invocation.Connection.Validate(invocation.Principal.WorkspaceID, a.manifest.Capability); err != nil {
		return requestPlan{}, domain.ErrInvalidArguments
	}
	arguments, err := decodeArguments(invocation.Arguments, a.manifest.MaxRequestBytes)
	if err != nil {
		return requestPlan{}, err
	}
	for _, required := range operation.Required {
		value, exists := arguments[required]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return requestPlan{}, domain.ErrInvalidArguments
		}
	}
	if a.manifest.Provider == "postiz" {
		if err := validatePostizArguments(operation, arguments); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "gmail" {
		if err := validateGmailArguments(operation, arguments, invocation.Connection.Config); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "google_analytics" {
		if err := validateGoogleAnalyticsArguments(operation, arguments); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "replio" || a.manifest.Provider == "billingbear" {
		if err := validatePlatformArguments(operation, arguments, invocation.Connection.Config); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "clickup" {
		if err := validateClickUpArguments(operation, arguments); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "github" {
		if err := validateGitHubArguments(operation, arguments); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "notion" {
		if err := validateNotionArguments(operation, arguments); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "slack_import" {
		if err := validateSlackArguments(operation, arguments); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "atlassian" {
		if err := validateAtlassianArguments(operation, arguments, invocation.Connection.Config); err != nil {
			return requestPlan{}, err
		}
	}
	origin, err := a.origin(invocation.Connection)
	if err != nil {
		return requestPlan{}, err
	}
	if operation.Origin != "" {
		origin, err = fixedHTTPSOrigin(operation.Origin)
		if err != nil {
			return requestPlan{}, domain.ErrInvalidArguments
		}
	}

	method, path := operation.Method, operation.Path
	query := make(url.Values)
	var body []byte
	var driveUpload *driveUploadRequest
	contentType := "application/json"
	if operation.Raw != nil {
		method, path, query, body, err = buildRaw(arguments, operation.Raw, a.manifest.MaxRequestBytes)
		if err != nil {
			return requestPlan{}, err
		}
	} else {
		consumed := map[string]bool{"connection_id": true, "provider": true, "expected_external_id": true}
		if a.manifest.Provider == "gmail" && operation.Name == "outreach.gmail.attachments.get" {
			path, err = expandPathWithValidators(path, arguments, consumed, map[string]func(string) bool{"attachment_id": validGmailAttachmentID})
		} else {
			path, err = expandPath(path, arguments, consumed)
		}
		if err != nil {
			return requestPlan{}, err
		}
		for argumentName, queryName := range operation.Query {
			value, exists := arguments[argumentName]
			if !exists {
				continue
			}
			if err := addQueryValue(query, queryName, value); err != nil {
				return requestPlan{}, domain.ErrInvalidArguments
			}
			consumed[argumentName] = true
		}
		for queryName, value := range operation.FixedQuery {
			query.Set(queryName, value)
		}
		if operation.Body == BodyRPC && len(operation.RPCActions) > 0 {
			endpoint, endpointErr := pipeboardEndpoint(invocation.Connection.Config)
			action, supported := operation.RPCActions[endpoint]
			if endpointErr != nil || !supported {
				return requestPlan{}, domain.ErrUnsupported
			}
			operation.RPCAction = action
		}
		if operation.Body == BodyDriveUpload {
			driveUpload, err = buildDriveUploadRequest(operation, arguments, consumed, a.driveUpload)
			if err != nil {
				return requestPlan{}, err
			}
			query.Set("uploadType", string(driveUpload.mode))
			body, contentType, err = driveUpload.initialBody()
			if err != nil {
				return requestPlan{}, err
			}
		} else {
			body, contentType, err = buildTypedBody(operation, arguments, consumed, invocation.ID, invocation.Idempotency, a.manifest.MaxRequestBytes)
			if err != nil {
				return requestPlan{}, err
			}
		}
	}
	if int64(len(body)) > a.manifest.MaxRequestBytes || encodedQueryBytes(query) > 64<<10 {
		return requestPlan{}, domain.ErrInvalidArguments
	}
	if err := validateProviderPath(path, true); err != nil {
		return requestPlan{}, domain.ErrInvalidArguments
	}
	if a.manifest.Provider == "pipeboard" && operation.Raw != nil {
		if err := validatePipeboardRawRPC(body); err != nil {
			return requestPlan{}, err
		}
	}
	if a.manifest.Provider == "shopify" && isShopifyThemeMutation(method, path, body) &&
		(!a.shopifyThemeWritesEnabled || !shopifyConnectionThemeWritesEnabled(invocation.Connection.Config)) {
		return requestPlan{}, domain.ErrUnsupported
	}
	target := *origin
	target.Path = path
	target.RawQuery = query.Encode()
	return requestPlan{operation: operation, method: method, target: &target, body: body, contentType: contentType, driveUpload: driveUpload}, nil
}

func validatePostizArguments(operation OperationManifest, arguments map[string]json.RawMessage) error {
	if operation.Raw != nil {
		return nil
	}
	if _, explicitBody := arguments["body"]; explicitBody {
		return domain.ErrInvalidArguments
	}
	switch operation.Name {
	case "social.postiz.posts.list":
		start, err := postizUTCDateTime(arguments["start_date"])
		if err != nil {
			return err
		}
		end, err := postizUTCDateTime(arguments["end_date"])
		if err != nil || end.Before(start) {
			return domain.ErrInvalidArguments
		}
	case "social.postiz.posts.create", "social.postiz.drafts.create":
		postType, err := strictJSONString(arguments["type"], 32)
		if err != nil || postType != "now" && postType != "schedule" && postType != "draft" {
			return domain.ErrInvalidArguments
		}
		if operation.Name == "social.postiz.drafts.create" && postType != "draft" {
			return domain.ErrInvalidArguments
		}
		if _, err = postizUTCDateTime(arguments["date"]); err != nil {
			return err
		}
		var shortLink bool
		if json.Unmarshal(arguments["shortLink"], &shortLink) != nil {
			return domain.ErrInvalidArguments
		}
		var tags []any
		if json.Unmarshal(arguments["tags"], &tags) != nil || len(tags) > 100 {
			return domain.ErrInvalidArguments
		}
		if postType != "draft" {
			var posts []any
			if json.Unmarshal(arguments["posts"], &posts) != nil || len(posts) == 0 || len(posts) > 100 {
				return domain.ErrInvalidArguments
			}
		}
	case "social.postiz.posts.status.update":
		status, err := strictJSONString(arguments["status"], 16)
		if err != nil || status != "draft" && status != "schedule" {
			return domain.ErrInvalidArguments
		}
	case "social.postiz.posts.release_id.update":
		if _, err := strictJSONString(arguments["releaseId"], 1024); err != nil {
			return err
		}
	}
	return nil
}

func postizUTCDateTime(raw json.RawMessage) (time.Time, error) {
	value, err := strictJSONString(raw, 128)
	if err != nil {
		return time.Time{}, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	_, offset := parsed.Zone()
	if err != nil || offset != 0 {
		return time.Time{}, domain.ErrInvalidArguments
	}
	return parsed, nil
}

func strictJSONString(raw json.RawMessage, maximum int) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || value == "" || len(value) > maximum || strings.ContainsAny(value, "\r\n\x00") {
		return "", domain.ErrInvalidArguments
	}
	return value, nil
}

func isShopifyThemeMutation(method, path string, body []byte) bool {
	if safeMethod(method) {
		return false
	}
	if !strings.HasSuffix(path, "/graphql.json") {
		return false
	}
	var envelope struct {
		Query string `json:"query"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return false
	}
	return strings.Contains(envelope.Query, "mutation") && shopifyThemeMutationFieldPattern.MatchString(envelope.Query)
}

func shopifyConnectionThemeWritesEnabled(configuration json.RawMessage) bool {
	var config struct {
		ThemeWritesEnabled bool `json:"theme_writes_enabled"`
	}
	return len(configuration) > 0 && json.Unmarshal(configuration, &config) == nil && config.ThemeWritesEnabled
}

func (a *HTTPAdapter) origin(connection domain.Connection) (*url.URL, error) {
	if a.manifest.OriginKind == OriginFixed {
		return fixedHTTPSOrigin(a.manifest.Origin)
	}
	if a.manifest.OriginKind == OriginPipeboard {
		endpoint, err := pipeboardEndpoint(connection.Config)
		if err != nil {
			return nil, err
		}
		return fixedHTTPSOrigin(pipeboardOrigins[endpoint])
	}
	// The OAuth-verified shop identity is stored as the connection external ID.
	// Config is merchant-editable feature configuration and must never be the
	// authority for the provider origin. Accept the legacy duplicated field only
	// when it agrees exactly, so an existing mismatch fails closed.
	shopDomain := connection.ExternalID
	if !validShopifyDomain(shopDomain) {
		return nil, domain.ErrInvalidArguments
	}
	if len(connection.Config) > 0 {
		var config struct {
			ShopDomain string `json:"shop_domain"`
		}
		if json.Unmarshal(connection.Config, &config) != nil ||
			config.ShopDomain != "" && config.ShopDomain != shopDomain {
			return nil, domain.ErrInvalidArguments
		}
	}
	return &url.URL{Scheme: "https", Host: shopDomain}, nil
}

func pipeboardEndpoint(configuration json.RawMessage) (string, error) {
	var config struct {
		AdsProvider string `json:"ads_provider"`
	}
	if len(configuration) == 0 || json.Unmarshal(configuration, &config) != nil || !validPipeboardEndpoint(config.AdsProvider) {
		return "", domain.ErrInvalidArguments
	}
	return config.AdsProvider, nil
}

func validatePipeboardRawRPC(body []byte) error {
	var request struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.JSONRPC != "2.0" || len(request.ID) == 0 {
		return domain.ErrInvalidArguments
	}
	switch request.Method {
	case "tools/list":
		if len(request.Params) > 0 && !isJSONObject(request.Params) {
			return domain.ErrInvalidArguments
		}
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		paramsDecoder := json.NewDecoder(bytes.NewReader(request.Params))
		paramsDecoder.DisallowUnknownFields()
		if paramsDecoder.Decode(&params) != nil || paramsDecoder.Decode(&struct{}{}) != io.EOF || !safeToolName(params.Name) || !isJSONObject(params.Arguments) {
			return domain.ErrInvalidArguments
		}
	default:
		return domain.ErrInvalidArguments
	}
	return nil
}

func validShopifyDomain(host string) bool {
	if host == "" || host != strings.ToLower(host) || len(host) > 253 || strings.ContainsAny(host, ":/@?#%\\\r\n") || !strings.HasSuffix(host, ".myshopify.com") {
		return false
	}
	prefix := strings.TrimSuffix(host, ".myshopify.com")
	if prefix == "" {
		return false
	}
	for _, label := range strings.Split(prefix, ".") {
		if !shopLabelPattern.MatchString(label) {
			return false
		}
	}
	return net.ParseIP(host) == nil
}

func decodeArguments(raw json.RawMessage, maximum int64) (map[string]json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	if int64(len(raw)) > maximum || !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, domain.ErrInvalidArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, domain.ErrInvalidArguments
	}
	result := map[string]json.RawMessage{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, domain.ErrInvalidArguments
		}
		if _, duplicate := result[key]; duplicate {
			return nil, domain.ErrInvalidArguments
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, domain.ErrInvalidArguments
		}
		result[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, domain.ErrInvalidArguments
	}
	return result, nil
}

func expandPath(template string, arguments map[string]json.RawMessage, consumed map[string]bool) (string, error) {
	return expandPathWithValidators(template, arguments, consumed, nil)
}

func expandPathWithValidators(template string, arguments map[string]json.RawMessage, consumed map[string]bool, validators map[string]func(string) bool) (string, error) {
	var expansionErr error
	path := pathTemplatePattern.ReplaceAllStringFunc(template, func(match string) string {
		name := match[1 : len(match)-1]
		value, exists := arguments[name]
		if !exists {
			expansionErr = domain.ErrInvalidArguments
			return match
		}
		stringValue, err := scalarString(value)
		valid := pathValuePattern.MatchString
		if override := validators[name]; override != nil {
			valid = override
		}
		if err != nil || !valid(stringValue) || stringValue == "." || stringValue == ".." {
			expansionErr = domain.ErrInvalidArguments
			return match
		}
		consumed[name] = true
		return stringValue
	})
	if expansionErr != nil || strings.ContainsAny(path, "{}") {
		return "", domain.ErrInvalidArguments
	}
	return path, nil
}

func buildTypedBody(operation OperationManifest, arguments map[string]json.RawMessage, consumed map[string]bool, invocationID, idempotencyKey string, maximum int64) ([]byte, string, error) {
	switch operation.Body {
	case BodyNone:
		return nil, "", nil
	case BodyJSON:
		body, err := payloadJSON(arguments, consumed)
		return body, "application/json", err
	case BodyGraphQL:
		variables, exists := arguments["variables"]
		if !exists {
			payload, err := payloadMap(arguments, consumed)
			if err != nil {
				return nil, "", err
			}
			variables, _ = json.Marshal(payload)
		} else if !isJSONObject(variables) {
			return nil, "", domain.ErrInvalidArguments
		}
		var err error
		variables, err = normalizeGraphQLVariables(operation, variables)
		if err != nil {
			return nil, "", err
		}
		if operation.GraphQLIdempotencyVariable != "" {
			if idempotencyKey == "" {
				return nil, "", domain.ErrInvalidArguments
			}
			var decodedVariables map[string]json.RawMessage
			if json.Unmarshal(variables, &decodedVariables) != nil || decodedVariables == nil {
				return nil, "", domain.ErrInvalidArguments
			}
			encodedKey, _ := json.Marshal(idempotencyKey)
			decodedVariables[operation.GraphQLIdempotencyVariable] = encodedKey
			variables, _ = json.Marshal(decodedVariables)
		}
		body, err := json.Marshal(map[string]any{"query": operation.GraphQLDocument, "variables": json.RawMessage(variables)})
		return body, "application/json", err
	case BodyRPC:
		payload, err := payloadMap(arguments, consumed)
		if err != nil {
			return nil, "", err
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": invocationID, "method": "tools/call", "params": map[string]any{"name": operation.RPCAction, "arguments": payload}})
		return body, "application/json", err
	case BodyBase64:
		var encoded, mediaType string
		if json.Unmarshal(arguments["content_base64"], &encoded) != nil || encoded == "" || int64(base64.StdEncoding.DecodedLen(len(encoded))) > maximum {
			return nil, "", domain.ErrInvalidArguments
		}
		body, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || int64(len(body)) > maximum {
			return nil, "", domain.ErrInvalidArguments
		}
		mediaType = "application/octet-stream"
		if value, exists := arguments["mime_type"]; exists {
			if json.Unmarshal(value, &mediaType) != nil {
				return nil, "", domain.ErrInvalidArguments
			}
			parsed, parameters, err := mime.ParseMediaType(mediaType)
			if err != nil || len(parameters) != 0 || parsed != mediaType || len(mediaType) > 128 {
				return nil, "", domain.ErrInvalidArguments
			}
		}
		return body, mediaType, nil
	case BodyMultipartBase64:
		var encoded, mediaType string
		if json.Unmarshal(arguments["content_base64"], &encoded) != nil || encoded == "" || int64(base64.StdEncoding.DecodedLen(len(encoded))) > maximum {
			return nil, "", domain.ErrInvalidArguments
		}
		content, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || int64(len(content)) > maximum || json.Unmarshal(arguments["mime_type"], &mediaType) != nil {
			return nil, "", domain.ErrInvalidArguments
		}
		parsedType, parameters, err := mime.ParseMediaType(mediaType)
		if err != nil || len(parameters) != 0 || parsedType != mediaType || len(mediaType) > 128 {
			return nil, "", domain.ErrInvalidArguments
		}
		fileName := "upload"
		if value, exists := arguments["file_name"]; exists {
			if json.Unmarshal(value, &fileName) != nil || !safeMultipartFileName(fileName) {
				return nil, "", domain.ErrInvalidArguments
			}
		}
		var buffer bytes.Buffer
		writer := multipart.NewWriter(&buffer)
		disposition := mime.FormatMediaType("form-data", map[string]string{"name": "file", "filename": fileName})
		headers := make(textproto.MIMEHeader)
		headers.Set("Content-Disposition", disposition)
		headers.Set("Content-Type", mediaType)
		part, err := writer.CreatePart(headers)
		if err != nil {
			return nil, "", domain.ErrInvalidArguments
		}
		if _, err = part.Write(content); err != nil || writer.Close() != nil || int64(buffer.Len()) > maximum {
			return nil, "", domain.ErrInvalidArguments
		}
		return buffer.Bytes(), writer.FormDataContentType(), nil
	default:
		return nil, "", domain.ErrInvalidArguments
	}
}

func normalizeGraphQLVariables(operation OperationManifest, variables json.RawMessage) (json.RawMessage, error) {
	filter := operation.GraphQLIDSearchFilter
	if filter == nil {
		return variables, nil
	}
	var decoded map[string]json.RawMessage
	if json.Unmarshal(variables, &decoded) != nil || decoded == nil {
		return nil, domain.ErrInvalidArguments
	}
	if operation.Name == "commerce.shopify.products.variants.list" {
		for name := range decoded {
			if name != filter.InputVariable && name != "first" && name != "after" {
				return nil, domain.ErrInvalidArguments
			}
		}
		if rawFirst, exists := decoded["first"]; exists {
			var first int
			if json.Unmarshal(rawFirst, &first) != nil || first < 1 || first > 250 {
				return nil, domain.ErrInvalidArguments
			}
		}
		if rawAfter, exists := decoded["after"]; exists {
			var after string
			if json.Unmarshal(rawAfter, &after) != nil || after == "" || len(after) > 2048 || strings.ContainsAny(after, "\r\n") {
				return nil, domain.ErrInvalidArguments
			}
		}
	}
	rawID, exists := decoded[filter.InputVariable]
	if !exists {
		return nil, domain.ErrInvalidArguments
	}
	var resourceID string
	if json.Unmarshal(rawID, &resourceID) != nil {
		return nil, domain.ErrInvalidArguments
	}
	prefix := "gid://shopify/" + filter.GIDType + "/"
	resourceID = strings.TrimPrefix(resourceID, prefix)
	if resourceID == "" || len(resourceID) > 20 || resourceID[0] == '0' {
		return nil, domain.ErrInvalidArguments
	}
	for _, character := range resourceID {
		if character < '0' || character > '9' {
			return nil, domain.ErrInvalidArguments
		}
	}
	delete(decoded, filter.InputVariable)
	encodedFilter, _ := json.Marshal(filter.FilterName + ":" + resourceID)
	decoded[filter.QueryVariable] = encodedFilter
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return nil, domain.ErrInvalidArguments
	}
	return encoded, nil
}

func payloadJSON(arguments map[string]json.RawMessage, consumed map[string]bool) ([]byte, error) {
	if explicit, exists := arguments["body"]; exists {
		if !json.Valid(explicit) {
			return nil, domain.ErrInvalidArguments
		}
		return compactJSON(explicit)
	}
	payload, err := payloadMap(arguments, consumed)
	if err != nil || len(payload) == 0 {
		return nil, err
	}
	return json.Marshal(payload)
}

func payloadMap(arguments map[string]json.RawMessage, consumed map[string]bool) (map[string]json.RawMessage, error) {
	payload := make(map[string]json.RawMessage)
	for key, value := range arguments {
		if consumed[key] || key == "body" || key == "variables" || key == "content_base64" || key == "mime_type" || key == "file_name" {
			continue
		}
		if !safeArgumentName(key) || !json.Valid(value) {
			return nil, domain.ErrInvalidArguments
		}
		payload[key] = value
	}
	return payload, nil
}

func buildRaw(arguments map[string]json.RawMessage, policy *RawPolicy, maximum int64) (string, string, url.Values, []byte, error) {
	encoded, err := json.Marshal(arguments)
	if err != nil {
		return "", "", nil, nil, domain.ErrInvalidArguments
	}
	var raw struct {
		ConnectionID string                     `json:"connection_id"`
		Provider     string                     `json:"provider"`
		Method       string                     `json:"method"`
		Path         string                     `json:"path"`
		Query        map[string]json.RawMessage `json:"query"`
		Body         json.RawMessage            `json:"body"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&raw) != nil || decoder.Decode(&struct{}{}) != io.EOF || !containsString(policy.Methods, raw.Method) || validateProviderPath(raw.Path, true) != nil || !pathAllowed(raw.Path, policy.PathPrefixes) {
		return "", "", nil, nil, domain.ErrInvalidArguments
	}
	query := make(url.Values)
	for key, value := range raw.Query {
		if !safeQueryName(key) || sensitiveQueryKey(key) || addQueryValue(query, key, value) != nil {
			return "", "", nil, nil, domain.ErrInvalidArguments
		}
	}
	if len(raw.Body) > 0 {
		if !json.Valid(raw.Body) || int64(len(raw.Body)) > maximum {
			return "", "", nil, nil, domain.ErrInvalidArguments
		}
		raw.Body, err = compactJSON(raw.Body)
		if err != nil {
			return "", "", nil, nil, domain.ErrInvalidArguments
		}
	}
	return raw.Method, raw.Path, query, raw.Body, nil
}

func pathAllowed(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix == "/" {
			if path == "/" {
				return true
			}
			continue
		}
		// A trailing slash denotes a subtree. A path without one is an exact
		// endpoint, which lets manifests expose GraphQL without accidentally
		// reopening sibling or legacy REST resources.
		if strings.HasSuffix(prefix, "/") {
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if path == prefix {
			return true
		}
	}
	return false
}

func sensitiveQueryKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_", "$", "").Replace(key))
	switch normalized {
	case "access_token", "oauth_token", "api_key", "apikey", "key", "authorization", "client_secret", "credential", "signature":
		return true
	default:
		return false
	}
}

func addQueryValue(query url.Values, name string, raw json.RawMessage) error {
	if len(raw) > 16<<10 {
		return domain.ErrInvalidArguments
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return domain.ErrInvalidArguments
	}
	values, err := queryStrings(value)
	if err != nil {
		return err
	}
	for _, item := range values {
		query.Add(name, item)
	}
	return nil
}

func queryStrings(value any) ([]string, error) {
	switch typed := value.(type) {
	case string:
		return []string{typed}, nil
	case bool:
		return []string{strconv.FormatBool(typed)}, nil
	case json.Number:
		return []string{typed.String()}, nil
	case []any:
		if len(typed) > 100 {
			return nil, domain.ErrInvalidArguments
		}
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			values, err := queryStrings(item)
			if err != nil || len(values) != 1 {
				return nil, domain.ErrInvalidArguments
			}
			result = append(result, values[0])
		}
		return result, nil
	default:
		return nil, domain.ErrInvalidArguments
	}
}

func scalarString(raw json.RawMessage) (string, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return "", domain.ErrInvalidArguments
	}
	values, err := queryStrings(value)
	if err != nil || len(values) != 1 {
		return "", domain.ErrInvalidArguments
	}
	return values[0], nil
}

func encodedQueryBytes(query url.Values) int64 { return int64(len(query.Encode())) }

func compactJSON(raw json.RawMessage) ([]byte, error) {
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, raw); err != nil {
		return nil, domain.ErrInvalidArguments
	}
	return buffer.Bytes(), nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' && json.Valid(trimmed)
}

func safeMethod(method string) bool { return method == http.MethodGet }

func idempotencyApplied(operation OperationManifest, key string) bool {
	return key != "" && (operation.IdempotencyHeader != "" || operation.GraphQLIdempotencyVariable != "")
}

func safeMultipartFileName(value string) bool {
	if value == "" || len(value) > 255 || strings.ContainsAny(value, "/\\\r\n\x00") {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func retryableStatus(retry RetrySpec, status int) bool {
	for _, candidate := range retry.Statuses {
		if status == candidate {
			return true
		}
	}
	return false
}

func retryDelay(retry RetrySpec, attempt int, retryAfter string) time.Duration {
	delay := retry.BaseDelay
	for count := 1; count < attempt && delay < retry.MaxDelay; count++ {
		delay *= 2
	}
	if delay > retry.MaxDelay {
		delay = retry.MaxDelay
	}
	if seconds, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && seconds >= 0 {
		providerDelay := time.Duration(seconds) * time.Second
		if providerDelay < retry.MaxDelay || retry.MaxDelay == 0 {
			delay = providerDelay
		} else {
			delay = retry.MaxDelay
		}
	}
	return delay
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func readBounded(reader io.Reader, maximum int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	return data, int64(len(data)) > maximum, err
}

func providerRequestID(headers http.Header) string {
	for _, name := range []string{"X-Request-ID", "X-Shopify-Request-ID", "X-GUploader-UploadID", "X-Google-Request-ID", "X-Slack-Req-Id"} {
		if value := strings.TrimSpace(headers.Get(name)); value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n") {
			return value
		}
	}
	return ""
}

func shopifyGraphQLPermissionDenied(provider string, plan requestPlan, data []byte) bool {
	if provider != "shopify" ||
		(plan.operation.Body != BodyGraphQL && !strings.HasSuffix(plan.target.Path, "/graphql.json")) {
		return false
	}
	var payload struct {
		Errors []struct {
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &payload) != nil {
		return false
	}
	for _, graphqlError := range payload.Errors {
		if strings.EqualFold(strings.TrimSpace(graphqlError.Extensions.Code), "ACCESS_DENIED") {
			return true
		}
	}
	return false
}

func decodeProviderBody(data []byte, contentType string) any {
	if len(data) == 0 {
		return nil
	}
	var decoded any
	if json.Unmarshal(data, &decoded) == nil {
		return decoded
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	return map[string]any{"encoding": "base64", "media_type": mediaType, "data": base64.StdEncoding.EncodeToString(data)}
}

// Provider APIs can report application-level failures in an otherwise
// successful HTTP response. Treat these envelopes as failures so approval
// execution, usage attribution, and audit outcome never record them as
// succeeded.
func providerApplicationError(provider string, plan requestPlan, data []byte) bool {
	if provider == "google_drive" {
		if plan.operation.Name == "files.drive.files.download" || plan.operation.Name == "files.drive.files.export" ||
			plan.target.Query().Get("alt") == "media" {
			return false
		}
		var payload map[string]any
		if json.Unmarshal(data, &payload) != nil || payload == nil {
			return false
		}
		if value, exists := payload["error"]; exists && value != nil {
			return true
		}
		if value, exists := payload["errors"]; exists && nonEmptyErrorCollection(value) {
			return true
		}
		return false
	}
	if provider != "shopify" && provider != "pipeboard" {
		return false
	}
	var payload any
	if json.Unmarshal(data, &payload) != nil {
		return provider == "pipeboard" ||
			(provider == "shopify" && (plan.operation.Body == BodyGraphQL || strings.HasSuffix(plan.target.Path, "/graphql.json")))
	}
	root, ok := payload.(map[string]any)
	if !ok {
		return true
	}
	if provider == "pipeboard" {
		if root["jsonrpc"] != "2.0" {
			return true
		}
		requestID, hasRequestID := rpcEnvelopeID(plan.body)
		responseID, hasResponseID := root["id"]
		if !hasRequestID || !hasResponseID || !reflect.DeepEqual(requestID, responseID) {
			return true
		}
		errorValue, hasError := root["error"]
		if hasError && errorValue != nil {
			return true
		}
		result, hasResult := root["result"]
		return !hasResult || pipeboardMCPResultError(result)
	}
	if plan.operation.Body != BodyGraphQL && !strings.HasSuffix(plan.target.Path, "/graphql.json") {
		return false
	}
	if errorsValue, exists := root["errors"]; exists && nonEmptyErrorCollection(errorsValue) {
		return true
	}
	if hasShopifyUserErrors(root) {
		return true
	}
	_, hasData := root["data"]
	return !hasData
}

// MCP servers may return a successful JSON-RPC envelope even when the tool
// itself failed. FastMCP uses result.isError for raised tool errors, while a
// number of Pipeboard tools return a JSON string containing {"error": ...}.
// Treat both shapes as provider failures so a broken fan-out cannot advance a
// sync cursor or finalize a resource snapshot.
func pipeboardMCPResultError(value any) bool {
	result, ok := value.(map[string]any)
	if !ok || result == nil {
		return true
	}
	if isError, _ := result["isError"].(bool); isError {
		return true
	}
	if pipeboardPayloadError(result["structuredContent"]) {
		return true
	}
	content, _ := result["content"].([]any)
	for _, candidate := range content {
		entry, _ := candidate.(map[string]any)
		text, _ := entry["text"].(string)
		if text == "" {
			continue
		}
		var decoded any
		if json.Unmarshal([]byte(text), &decoded) != nil {
			continue
		}
		if pipeboardPayloadError(decoded) {
			return true
		}
	}
	return false
}

func pipeboardPayloadError(value any) bool {
	payload, ok := value.(map[string]any)
	if !ok || payload == nil {
		return false
	}
	if errorValue, exists := payload["error"]; exists && errorValue != nil {
		switch typed := errorValue.(type) {
		case string:
			return strings.TrimSpace(typed) != ""
		case []any:
			return len(typed) > 0
		case map[string]any:
			return len(typed) > 0
		default:
			return true
		}
	}
	if errorsValue, exists := payload["errors"]; exists && nonEmptyErrorCollection(errorsValue) {
		return true
	}
	return false
}

func rpcEnvelopeID(body []byte) (any, bool) {
	var request map[string]any
	if json.Unmarshal(body, &request) != nil {
		return nil, false
	}
	id, exists := request["id"]
	return id, exists
}

func nonEmptyErrorCollection(value any) bool {
	switch typed := value.(type) {
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	case string:
		return strings.TrimSpace(typed) != ""
	default:
		return typed != nil
	}
}

func hasShopifyUserErrors(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			normalized := strings.ToLower(key)
			if (strings.HasSuffix(normalized, "usererrors") || normalized == "parseerrors") &&
				nonEmptyErrorCollection(nested) {
				return true
			}
			if hasShopifyUserErrors(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if hasShopifyUserErrors(nested) {
				return true
			}
		}
	}
	return false
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func cloneManifest(manifest Manifest) Manifest {
	clone := manifest
	clone.Operations = make([]OperationManifest, len(manifest.Operations))
	for index, operation := range manifest.Operations {
		cloneOperation := operation
		cloneOperation.Query = cloneStringMap(operation.Query)
		cloneOperation.FixedQuery = cloneStringMap(operation.FixedQuery)
		cloneOperation.RPCActions = cloneStringMap(operation.RPCActions)
		cloneOperation.Required = append([]string(nil), operation.Required...)
		cloneOperation.RequiredScopes = append([]string(nil), operation.RequiredScopes...)
		cloneOperation.InputSchema = cloneBytes(operation.InputSchema)
		cloneOperation.Retry.Statuses = append([]int(nil), operation.Retry.Statuses...)
		if operation.GraphQLIDSearchFilter != nil {
			copy := *operation.GraphQLIDSearchFilter
			cloneOperation.GraphQLIDSearchFilter = &copy
		}
		if operation.Sync != nil {
			copy := *operation.Sync
			cloneOperation.Sync = &copy
		}
		if operation.Raw != nil {
			cloneOperation.Raw = &RawPolicy{Methods: append([]string(nil), operation.Raw.Methods...), PathPrefixes: append([]string(nil), operation.Raw.PathPrefixes...)}
		}
		clone.Operations[index] = cloneOperation
	}
	return clone
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneBytes(source []byte) []byte { return append([]byte(nil), source...) }

func secureHTTPDoer() HTTPDoer {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		MaxIdleConns: 100, MaxIdleConnsPerHost: 20, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 60 * time.Second, ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: transport, Timeout: 90 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func Catalog() []domain.Adapter {
	adapters, err := CatalogWithDoer(secureHTTPDoer())
	if err != nil {
		panic("invalid built-in provider manifest: " + err.Error())
	}
	return adapters
}

func CatalogWithDoer(doer HTTPDoer, configured ...CatalogOptions) ([]domain.Adapter, error) {
	if len(configured) > 1 {
		return nil, errors.New("at most one provider catalog options value is allowed")
	}
	options := CatalogOptions{}
	if len(configured) == 1 {
		options = configured[0]
	}
	manifests := Manifests()
	adapters := make([]domain.Adapter, 0, len(manifests))
	for _, manifest := range manifests {
		adapter, err := NewHTTPAdapterWithOptions(manifest, doer, AdapterOptions{
			ShopifyThemeWritesEnabled: options.ShopifyThemeWritesEnabled,
			DriveSimpleUploadMaxBytes: options.DriveSimpleUploadMaxBytes,
			DriveUploadMaxBytes:       options.DriveUploadMaxBytes,
			DriveResumableChunkBytes:  options.DriveResumableChunkBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", manifest.Provider, err)
		}
		adapters = append(adapters, adapter)
	}
	adapters = append(adapters, newIMAPAdapter())
	calendar, err := NewGoogleCalendarAdapter(doer)
	if err != nil {
		return nil, err
	}
	adapters = append(adapters, calendar)
	for _, provider := range []string{"outlook_mail", "outlook_calendar"} {
		adapter, err := NewMicrosoftGraphAdapter(provider, doer)
		if err != nil {
			return nil, err
		}
		adapters = append(adapters, adapter)
	}
	for _, provider := range []string{"onedrive", "sharepoint"} {
		adapter, err := NewMicrosoftFilesAdapter(provider, doer)
		if err != nil {
			return nil, err
		}
		adapters = append(adapters, adapter)
	}
	for _, provider := range []string{"exa", "firecrawl", "parallel_search", "context7", "coingecko"} {
		adapter, err := NewKeylessMCPAdapter(provider, doer)
		if err != nil {
			return nil, err
		}
		adapters = append(adapters, adapter)
	}
	batch, err := reviewedBatchAdapters(doer)
	if err != nil {
		return nil, err
	}
	seenProviders := map[string]bool{}
	for _, adapter := range adapters {
		seenProviders[adapter.Provider()] = true
	}
	for _, adapter := range batch {
		if seenProviders[adapter.Provider()] {
			return nil, errors.New("reviewed connector duplicates an existing provider")
		}
		seenProviders[adapter.Provider()] = true
		adapters = append(adapters, adapter)
	}
	return adapters, nil
}
