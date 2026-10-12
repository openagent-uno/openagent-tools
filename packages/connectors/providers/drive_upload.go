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
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const (
	// These are deliberately product limits, not Google Drive's theoretical
	// storage limits. The current MCP contract carries one base64 value in
	// memory; a future streaming transport can preserve the same tool names.
	DefaultDriveSimpleUploadMaxBytes int64 = 5 << 20
	DefaultDriveUploadMaxBytes       int64 = 16 << 20
	DefaultDriveResumableChunkBytes  int64 = 8 << 20

	driveResumableQuantum    int64 = 256 << 10
	maxDriveUploadBytes      int64 = 16 << 20
	maxDriveUploadRecoveries       = 3
	maxDriveSessionRestarts        = 1
)

type driveUploadMode string

const (
	driveUploadMedia     driveUploadMode = "media"
	driveUploadMultipart driveUploadMode = "multipart"
	driveUploadResumable driveUploadMode = "resumable"
)

type driveUploadLimits struct {
	simpleMaxBytes int64
	maxBytes       int64
	chunkBytes     int64
}

func newDriveUploadLimits(simpleMaximum, maximum, chunkBytes int64) (driveUploadLimits, error) {
	if simpleMaximum == 0 {
		simpleMaximum = DefaultDriveSimpleUploadMaxBytes
	}
	if maximum == 0 {
		maximum = DefaultDriveUploadMaxBytes
	}
	if chunkBytes == 0 {
		chunkBytes = DefaultDriveResumableChunkBytes
	}
	if simpleMaximum <= 0 || simpleMaximum > DefaultDriveSimpleUploadMaxBytes ||
		maximum < simpleMaximum || maximum > maxDriveUploadBytes ||
		chunkBytes < driveResumableQuantum || chunkBytes > maxDriveUploadBytes ||
		chunkBytes%driveResumableQuantum != 0 {
		return driveUploadLimits{}, errors.New("invalid Google Drive upload limits")
	}
	return driveUploadLimits{simpleMaxBytes: simpleMaximum, maxBytes: maximum, chunkBytes: chunkBytes}, nil
}

type driveUploadRequest struct {
	content    []byte
	mediaType  string
	metadata   json.RawMessage
	metadataID string
	mode       driveUploadMode
	update     bool
}

func buildDriveUploadRequest(operation OperationManifest, arguments map[string]json.RawMessage, consumed map[string]bool, limits driveUploadLimits) (*driveUploadRequest, error) {
	encodedRaw, exists := arguments["content_base64"]
	if !exists {
		return nil, domain.ErrInvalidArguments
	}
	var encoded string
	if json.Unmarshal(encodedRaw, &encoded) != nil || int64(base64.StdEncoding.DecodedLen(len(encoded))) > limits.maxBytes {
		return nil, domain.ErrInvalidArguments
	}
	content, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || int64(len(content)) > limits.maxBytes {
		return nil, domain.ErrInvalidArguments
	}
	consumed["content_base64"] = true

	mediaType, err := strictJSONString(arguments["mime_type"], 128)
	if err != nil {
		return nil, err
	}
	parsedMediaType, parameters, err := mime.ParseMediaType(mediaType)
	if err != nil || len(parameters) != 0 || parsedMediaType != mediaType {
		return nil, domain.ErrInvalidArguments
	}
	consumed["mime_type"] = true

	var metadata json.RawMessage
	var metadataID string
	if raw, present := arguments["metadata"]; present {
		if !isJSONObject(raw) {
			return nil, domain.ErrInvalidArguments
		}
		metadata, err = compactJSON(raw)
		if err != nil {
			return nil, domain.ErrInvalidArguments
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(metadata, &object) != nil || object == nil {
			return nil, domain.ErrInvalidArguments
		}
		if rawID, hasID := object["id"]; hasID {
			metadataID, err = strictJSONString(rawID, 512)
			if err != nil || !pathValuePattern.MatchString(metadataID) || metadataID == "." || metadataID == ".." {
				return nil, domain.ErrInvalidArguments
			}
		}
		consumed["metadata"] = true
	}

	requestedMode := "auto"
	if raw, present := arguments["upload_mode"]; present {
		requestedMode, err = strictJSONString(raw, 16)
		if err != nil {
			return nil, err
		}
		consumed["upload_mode"] = true
	}
	var mode driveUploadMode
	switch requestedMode {
	case "auto":
		switch {
		case int64(len(content)) > limits.simpleMaxBytes:
			mode = driveUploadResumable
		case len(metadata) > 0:
			mode = driveUploadMultipart
		default:
			mode = driveUploadMedia
		}
	case "simple":
		if int64(len(content)) > limits.simpleMaxBytes || len(metadata) > 0 {
			return nil, domain.ErrInvalidArguments
		}
		mode = driveUploadMedia
	case "multipart":
		if int64(len(content)) > limits.simpleMaxBytes {
			return nil, domain.ErrInvalidArguments
		}
		if len(metadata) == 0 {
			metadata = json.RawMessage(`{}`)
		}
		mode = driveUploadMultipart
	case "resumable":
		if len(content) == 0 {
			return nil, domain.ErrInvalidArguments
		}
		mode = driveUploadResumable
	default:
		return nil, domain.ErrInvalidArguments
	}
	for name := range arguments {
		if !consumed[name] {
			return nil, domain.ErrInvalidArguments
		}
	}
	return &driveUploadRequest{
		content: content, mediaType: mediaType, metadata: metadata, metadataID: metadataID,
		mode: mode, update: operation.Method == http.MethodPatch,
	}, nil
}

func (upload *driveUploadRequest) initialBody() ([]byte, string, error) {
	switch upload.mode {
	case driveUploadMedia:
		return upload.content, upload.mediaType, nil
	case driveUploadMultipart:
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		metadataHeader := make(textproto.MIMEHeader)
		metadataHeader.Set("Content-Type", "application/json; charset=UTF-8")
		metadataPart, err := writer.CreatePart(metadataHeader)
		if err != nil {
			return nil, "", domain.ErrInvalidArguments
		}
		if _, err = metadataPart.Write(upload.metadata); err != nil {
			return nil, "", domain.ErrInvalidArguments
		}
		mediaHeader := make(textproto.MIMEHeader)
		mediaHeader.Set("Content-Type", upload.mediaType)
		mediaPart, err := writer.CreatePart(mediaHeader)
		if err != nil {
			return nil, "", domain.ErrInvalidArguments
		}
		if _, err = mediaPart.Write(upload.content); err != nil || writer.Close() != nil {
			return nil, "", domain.ErrInvalidArguments
		}
		contentType := mime.FormatMediaType("multipart/related", map[string]string{"boundary": writer.Boundary()})
		return body.Bytes(), contentType, nil
	case driveUploadResumable:
		if len(upload.metadata) == 0 {
			return []byte(`{}`), "application/json; charset=UTF-8", nil
		}
		return upload.metadata, "application/json; charset=UTF-8", nil
	default:
		return nil, "", domain.ErrInvalidArguments
	}
}

type driveTransferStats struct {
	attempts      int
	requestBytes  int64
	responseBytes int64
	providerID    string
}

type driveHTTPResponse struct {
	status     int
	header     http.Header
	data       []byte
	providerID string
}

type driveNetworkError struct{}

func (*driveNetworkError) Error() string { return "Google Drive transport failed" }

func (a *HTTPAdapter) invokeDriveUpload(ctx context.Context, invocation domain.Invocation, plan requestPlan) (domain.Result, error) {
	if plan.driveUpload.mode == driveUploadResumable {
		return a.invokeDriveResumableUpload(ctx, invocation, plan)
	}
	return a.invokeDriveBoundedUpload(ctx, invocation, plan)
}

func (a *HTTPAdapter) invokeDriveBoundedUpload(ctx context.Context, invocation domain.Invocation, plan requestPlan) (domain.Result, error) {
	stats := &driveTransferStats{}
	maxAttempts := 1
	safeCreateRetry := !plan.driveUpload.update && plan.driveUpload.metadataID != "" && invocation.Idempotency != ""
	// A repeated one-shot content update can create an extra Drive revision
	// even when the final bytes are identical. Only a create with a provider
	// pre-generated ID is safely recoverable here. Callers that need transport
	// recovery for updates use the same tool with upload_mode=resumable.
	if safeCreateRetry {
		maxAttempts = idempotentWriteRetry.MaxAttempts
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		response, err := a.doDriveRequest(ctx, invocation, plan.method, plan.target, plan.body, plan.contentType, nil, stats)
		if err != nil {
			var networkErr *driveNetworkError
			if !errors.As(err, &networkErr) {
				return domain.Result{}, err
			}
			if safeCreateRetry {
				if result, found, probeErr := a.probeCreatedDriveFile(ctx, invocation, plan, stats); probeErr != nil {
					return domain.Result{}, probeErr
				} else if found {
					return result, nil
				}
			}
			if attempt < maxAttempts {
				if err = a.sleep(ctx, retryDelay(idempotentWriteRetry, attempt, "")); err != nil {
					return domain.Result{}, err
				}
				continue
			}
			return domain.Result{}, driveProviderFailure("network_error", nil, stats)
		}
		if response.status >= http.StatusOK && response.status < http.StatusMultipleChoices {
			data, valid := decodeDriveObject(response.data)
			if !valid {
				return domain.Result{}, driveProviderFailure("provider_operation_error", response, stats)
			}
			return driveUploadResult(data, response, stats, plan, safeCreateRetry), nil
		}
		if safeCreateRetry && (response.status == http.StatusConflict || retryableStatus(idempotentWriteRetry, response.status)) {
			if result, found, probeErr := a.probeCreatedDriveFile(ctx, invocation, plan, stats); probeErr != nil {
				return domain.Result{}, probeErr
			} else if found {
				return result, nil
			}
		}
		if attempt < maxAttempts && retryableStatus(idempotentWriteRetry, response.status) {
			if err = a.sleep(ctx, retryDelay(idempotentWriteRetry, attempt, response.header.Get("Retry-After"))); err != nil {
				return domain.Result{}, err
			}
			continue
		}
		return domain.Result{}, driveHTTPFailure(response, stats)
	}
	return domain.Result{}, driveProviderFailure("provider_error", nil, stats)
}

func (a *HTTPAdapter) probeCreatedDriveFile(ctx context.Context, invocation domain.Invocation, plan requestPlan, stats *driveTransferStats) (domain.Result, bool, error) {
	fileID := plan.driveUpload.metadataID
	if fileID == "" {
		return domain.Result{}, false, nil
	}
	target := &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/drive/v3/files/" + fileID}
	query := make(url.Values)
	query.Set("fields", "id")
	target.RawQuery = query.Encode()
	response, err := a.doDriveRequest(ctx, invocation, http.MethodGet, target, nil, "", nil, stats)
	if err != nil {
		var networkErr *driveNetworkError
		if errors.As(err, &networkErr) {
			return domain.Result{}, false, nil
		}
		return domain.Result{}, false, err
	}
	if response.status == http.StatusNotFound {
		return domain.Result{}, false, nil
	}
	if response.status < http.StatusOK || response.status >= http.StatusMultipleChoices {
		return domain.Result{}, false, driveHTTPFailure(response, stats)
	}
	object, valid := decodeDriveObject(response.data)
	id, _ := object["id"].(string)
	if !valid || id != fileID {
		return domain.Result{}, false, driveProviderFailure("provider_operation_error", response, stats)
	}
	return driveUploadResult(object, response, stats, plan, true), true, nil
}

func (a *HTTPAdapter) invokeDriveResumableUpload(ctx context.Context, invocation domain.Invocation, plan requestPlan) (domain.Result, error) {
	stats := &driveTransferStats{}
	for restart := 0; restart <= maxDriveSessionRestarts; restart++ {
		session, err := a.startDriveResumableSession(ctx, invocation, plan, stats)
		if err != nil {
			return domain.Result{}, err
		}
		result, expired, err := a.transferDriveChunks(ctx, invocation, plan, session, stats)
		if err != nil {
			return domain.Result{}, err
		}
		if !expired {
			return result, nil
		}
	}
	return domain.Result{}, driveProviderFailure("resumable_session_expired", nil, stats)
}

func (a *HTTPAdapter) startDriveResumableSession(ctx context.Context, invocation domain.Invocation, plan requestPlan, stats *driveTransferStats) (*url.URL, error) {
	headers := make(http.Header)
	headers.Set("X-Upload-Content-Type", plan.driveUpload.mediaType)
	headers.Set("X-Upload-Content-Length", strconv.FormatInt(int64(len(plan.driveUpload.content)), 10))
	for attempt := 1; attempt <= idempotentWriteRetry.MaxAttempts; attempt++ {
		response, err := a.doDriveRequest(ctx, invocation, plan.method, plan.target, plan.body, plan.contentType, headers, stats)
		if err != nil {
			var networkErr *driveNetworkError
			if !errors.As(err, &networkErr) {
				return nil, err
			}
			if attempt < idempotentWriteRetry.MaxAttempts {
				if err = a.sleep(ctx, retryDelay(idempotentWriteRetry, attempt, "")); err != nil {
					return nil, err
				}
				continue
			}
			return nil, driveProviderFailure("network_error", nil, stats)
		}
		if response.status == http.StatusOK || response.status == http.StatusCreated {
			session, locationErr := validateDriveSessionLocation(response.header.Values("Location"), plan.target.Path)
			if locationErr != nil {
				return nil, driveProviderFailure("unsafe_resumable_location", response, stats)
			}
			return session, nil
		}
		if attempt < idempotentWriteRetry.MaxAttempts && retryableStatus(idempotentWriteRetry, response.status) {
			if err = a.sleep(ctx, retryDelay(idempotentWriteRetry, attempt, response.header.Get("Retry-After"))); err != nil {
				return nil, err
			}
			continue
		}
		return nil, driveHTTPFailure(response, stats)
	}
	return nil, driveProviderFailure("provider_error", nil, stats)
}

func (a *HTTPAdapter) transferDriveChunks(ctx context.Context, invocation domain.Invocation, plan requestPlan, session *url.URL, stats *driveTransferStats) (domain.Result, bool, error) {
	total := int64(len(plan.driveUpload.content))
	offset := int64(0)
	noProgress := 0
	for offset < total {
		end := offset + a.driveUpload.chunkBytes
		if end > total {
			end = total
		}
		headers := make(http.Header)
		headers.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, end-1, total))
		response, err := a.doDriveRequest(ctx, invocation, http.MethodPut, session, plan.driveUpload.content[offset:end], plan.driveUpload.mediaType, headers, stats)
		if err != nil {
			var networkErr *driveNetworkError
			if !errors.As(err, &networkErr) {
				return domain.Result{}, false, err
			}
			if sleepErr := a.sleep(ctx, retryDelay(idempotentWriteRetry, noProgress+1, "")); sleepErr != nil {
				return domain.Result{}, false, sleepErr
			}
			recovery, recoveryErr := a.probeDriveResumableSession(ctx, invocation, plan, session, end, stats)
			if recoveryErr != nil {
				return domain.Result{}, false, recoveryErr
			}
			if recovery.expired {
				return domain.Result{}, true, nil
			}
			if recovery.complete != nil {
				if end != total {
					return domain.Result{}, false, driveProviderFailure("provider_operation_error", recovery.complete, stats)
				}
				return a.completedDriveUpload(plan, recovery.complete, stats)
			}
			previous := offset
			next, progressErr := recoveredDriveOffset(offset, recovery.offset, &noProgress)
			if progressErr != nil {
				return domain.Result{}, false, driveProviderFailure("resumable_no_progress", nil, stats)
			}
			offset = next
			if offset == previous {
				if sleepErr := a.sleep(ctx, retryDelay(idempotentWriteRetry, noProgress, "")); sleepErr != nil {
					return domain.Result{}, false, sleepErr
				}
			}
			continue
		}
		switch {
		case response.status == http.StatusOK || response.status == http.StatusCreated:
			if end != total {
				return domain.Result{}, false, driveProviderFailure("provider_operation_error", response, stats)
			}
			return a.completedDriveUpload(plan, response, stats)
		case response.status == 308:
			next, rangeErr := nextDriveUploadOffset(response.header.Get("Range"), total, end)
			if rangeErr != nil || next < offset {
				return domain.Result{}, false, driveProviderFailure("invalid_resumable_range", response, stats)
			}
			previous := offset
			next, progressErr := recoveredDriveOffset(offset, next, &noProgress)
			if progressErr != nil {
				return domain.Result{}, false, driveProviderFailure("resumable_no_progress", response, stats)
			}
			offset = next
			if offset == previous {
				if sleepErr := a.sleep(ctx, retryDelay(idempotentWriteRetry, noProgress, response.header.Get("Retry-After"))); sleepErr != nil {
					return domain.Result{}, false, sleepErr
				}
			}
			if offset == total {
				recovery, recoveryErr := a.probeDriveResumableSession(ctx, invocation, plan, session, total, stats)
				if recoveryErr != nil {
					return domain.Result{}, false, recoveryErr
				}
				if recovery.expired {
					return domain.Result{}, true, nil
				}
				if recovery.complete != nil {
					return a.completedDriveUpload(plan, recovery.complete, stats)
				}
				return domain.Result{}, false, driveProviderFailure("resumable_no_completion", response, stats)
			}
		case response.status == http.StatusNotFound:
			return domain.Result{}, true, nil
		case retryableStatus(idempotentWriteRetry, response.status):
			if sleepErr := a.sleep(ctx, retryDelay(idempotentWriteRetry, noProgress+1, response.header.Get("Retry-After"))); sleepErr != nil {
				return domain.Result{}, false, sleepErr
			}
			recovery, recoveryErr := a.probeDriveResumableSession(ctx, invocation, plan, session, end, stats)
			if recoveryErr != nil {
				return domain.Result{}, false, recoveryErr
			}
			if recovery.expired {
				return domain.Result{}, true, nil
			}
			if recovery.complete != nil {
				if end != total {
					return domain.Result{}, false, driveProviderFailure("provider_operation_error", recovery.complete, stats)
				}
				return a.completedDriveUpload(plan, recovery.complete, stats)
			}
			previous := offset
			next, progressErr := recoveredDriveOffset(offset, recovery.offset, &noProgress)
			if progressErr != nil {
				return domain.Result{}, false, driveProviderFailure("resumable_no_progress", response, stats)
			}
			offset = next
			if offset == previous {
				if sleepErr := a.sleep(ctx, retryDelay(idempotentWriteRetry, noProgress, response.header.Get("Retry-After"))); sleepErr != nil {
					return domain.Result{}, false, sleepErr
				}
			}
		default:
			return domain.Result{}, false, driveHTTPFailure(response, stats)
		}
	}
	return domain.Result{}, false, driveProviderFailure("resumable_no_completion", nil, stats)
}

type driveSessionRecovery struct {
	offset   int64
	complete *driveHTTPResponse
	expired  bool
}

func (a *HTTPAdapter) probeDriveResumableSession(ctx context.Context, invocation domain.Invocation, plan requestPlan, session *url.URL, maximum int64, stats *driveTransferStats) (driveSessionRecovery, error) {
	total := int64(len(plan.driveUpload.content))
	headers := make(http.Header)
	headers.Set("Content-Range", fmt.Sprintf("bytes */%d", total))
	for attempt := 1; attempt <= maxDriveUploadRecoveries; attempt++ {
		response, err := a.doDriveRequest(ctx, invocation, http.MethodPut, session, nil, plan.driveUpload.mediaType, headers, stats)
		if err != nil {
			var networkErr *driveNetworkError
			if !errors.As(err, &networkErr) {
				return driveSessionRecovery{}, err
			}
			if attempt < maxDriveUploadRecoveries {
				if err = a.sleep(ctx, retryDelay(idempotentWriteRetry, attempt, "")); err != nil {
					return driveSessionRecovery{}, err
				}
				continue
			}
			return driveSessionRecovery{}, driveProviderFailure("network_error", nil, stats)
		}
		switch {
		case response.status == http.StatusOK || response.status == http.StatusCreated:
			return driveSessionRecovery{offset: total, complete: response}, nil
		case response.status == 308:
			offset, rangeErr := nextDriveUploadOffset(response.header.Get("Range"), total, maximum)
			if rangeErr != nil {
				return driveSessionRecovery{}, driveProviderFailure("invalid_resumable_range", response, stats)
			}
			return driveSessionRecovery{offset: offset}, nil
		case response.status == http.StatusNotFound:
			return driveSessionRecovery{expired: true}, nil
		case retryableStatus(idempotentWriteRetry, response.status) && attempt < maxDriveUploadRecoveries:
			if err = a.sleep(ctx, retryDelay(idempotentWriteRetry, attempt, response.header.Get("Retry-After"))); err != nil {
				return driveSessionRecovery{}, err
			}
		default:
			return driveSessionRecovery{}, driveHTTPFailure(response, stats)
		}
	}
	return driveSessionRecovery{}, driveProviderFailure("provider_error", nil, stats)
}

func recoveredDriveOffset(previous, recovered int64, noProgress *int) (int64, error) {
	if recovered < previous {
		return 0, errors.New("resumable upload offset regressed")
	}
	if recovered == previous {
		(*noProgress)++
		if *noProgress > maxDriveUploadRecoveries {
			return 0, errors.New("resumable upload made no progress")
		}
		return recovered, nil
	}
	*noProgress = 0
	return recovered, nil
}

var driveRangePattern = regexp.MustCompile(`^bytes=0-([0-9]+)$`)

func nextDriveUploadOffset(header string, total, maximum int64) (int64, error) {
	if header == "" {
		return 0, nil
	}
	match := driveRangePattern.FindStringSubmatch(header)
	if match == nil {
		return 0, errors.New("invalid Google Drive resumable Range")
	}
	last, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || last < 0 || last >= total || last+1 > maximum {
		return 0, errors.New("Google Drive resumable Range is outside the upload")
	}
	return last + 1, nil
}

func validateDriveSessionLocation(values []string, expectedPath string) (*url.URL, error) {
	if len(values) != 1 {
		return nil, errors.New("Google Drive resumable Location must occur exactly once")
	}
	parsed, err := url.Parse(values[0])
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.Port() != "" || parsed.RawPath != "" || parsed.Path != expectedPath {
		return nil, errors.New("unsafe Google Drive resumable Location")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host != parsed.Hostname() || host != "www.googleapis.com" && host != "content.googleapis.com" {
		return nil, errors.New("unexpected Google Drive resumable host")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) != 2 || len(query["uploadType"]) != 1 || query.Get("uploadType") != "resumable" ||
		len(query["upload_id"]) != 1 || query.Get("upload_id") == "" || len(query.Get("upload_id")) > 4096 ||
		strings.ContainsAny(query.Get("upload_id"), "\r\n\x00") {
		return nil, errors.New("unsafe Google Drive resumable query")
	}
	for key := range query {
		if key != "uploadType" && key != "upload_id" || sensitiveQueryKey(key) {
			return nil, errors.New("unsafe Google Drive resumable query")
		}
	}
	return parsed, nil
}

func (a *HTTPAdapter) completedDriveUpload(plan requestPlan, response *driveHTTPResponse, stats *driveTransferStats) (domain.Result, bool, error) {
	data, valid := decodeDriveObject(response.data)
	if !valid {
		return domain.Result{}, false, driveProviderFailure("provider_operation_error", response, stats)
	}
	return driveUploadResult(data, response, stats, plan, true), false, nil
}

func (a *HTTPAdapter) doDriveRequest(ctx context.Context, invocation domain.Invocation, method string, target *url.URL, body []byte, contentType string, extraHeaders http.Header, stats *driveTransferStats) (*driveHTTPResponse, error) {
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, domain.ErrInvalidArguments
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "OpenAgent-Connector/1.0")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for name, values := range extraHeaders {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	stats.attempts++
	stats.requestBytes += int64(len(body))
	if err = invocation.Credential.Apply(request.Header, a.manifest.CredentialHeader, a.manifest.CredentialScheme, a.now().UTC()); err != nil {
		return nil, driveProviderFailure("credential_error", nil, stats)
	}
	response, err := a.doer.Do(request)
	if err != nil || response == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &driveNetworkError{}
	}
	data, tooLarge, readErr := readBounded(response.Body, a.manifest.MaxResponseBytes)
	_ = response.Body.Close()
	stats.responseBytes += int64(len(data))
	providerID := providerRequestID(response.Header)
	if providerID != "" {
		stats.providerID = providerID
	}
	snapshot := &driveHTTPResponse{
		status: response.StatusCode, header: response.Header.Clone(),
		data: invocation.Credential.Redact(data), providerID: providerID,
	}
	if readErr != nil {
		return nil, driveProviderFailure("response_error", snapshot, stats)
	}
	if tooLarge {
		return nil, driveProviderFailure("response_too_large", snapshot, stats)
	}
	return snapshot, nil
}

func decodeDriveObject(data []byte) (map[string]any, bool) {
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&object) != nil || object == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	if value, exists := object["error"]; exists && value != nil {
		return nil, false
	}
	if value, exists := object["errors"]; exists && nonEmptyErrorCollection(value) {
		return nil, false
	}
	return object, true
}

func driveUploadResult(data map[string]any, response *driveHTTPResponse, stats *driveTransferStats, plan requestPlan, idempotencyApplied bool) domain.Result {
	providerID := stats.providerID
	status := http.StatusOK
	if response != nil {
		status = response.status
		if response.providerID != "" {
			providerID = response.providerID
		}
	}
	return domain.Result{
		Data: data, ProviderID: providerID, ProviderStatus: status, Attempts: stats.attempts,
		RequestBytes: stats.requestBytes, ResponseBytes: stats.responseBytes,
		Metadata: map[string]string{
			"provider": "google_drive", "api_version": DriveAPIVersion, "operation": plan.operation.Name,
			"upload_transport": string(plan.driveUpload.mode), "idempotency_applied": strconv.FormatBool(idempotencyApplied),
		},
	}
}

func driveHTTPFailure(response *driveHTTPResponse, stats *driveTransferStats) error {
	kind := "provider_error"
	if response != nil && response.status == http.StatusTooManyRequests {
		kind = "rate_limited"
	}
	err := driveProviderFailure(kind, response, stats)
	if response != nil && (response.status == http.StatusUnauthorized || response.status == http.StatusForbidden) {
		return errors.Join(domain.ErrProviderPermission, err)
	}
	return err
}

func driveProviderFailure(kind string, response *driveHTTPResponse, stats *driveTransferStats) *domain.ProviderError {
	status := 0
	providerID := stats.providerID
	if response != nil {
		status = response.status
		if response.providerID != "" {
			providerID = response.providerID
		}
	}
	return &domain.ProviderError{
		Kind: kind, StatusCode: status, ProviderID: providerID, Attempts: stats.attempts,
		RequestBytes: stats.requestBytes, ResponseBytes: stats.responseBytes,
	}
}
