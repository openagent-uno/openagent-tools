package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

type driveServerDoer struct {
	client *http.Client
	base   *url.URL
}

func newDriveServerDoer(t *testing.T, server *httptest.Server) HTTPDoer {
	t.Helper()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &driveServerDoer{client: client, base: base}
}

func (doer *driveServerDoer) Do(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	target := *request.URL
	originalHost := target.Host
	target.Scheme = doer.base.Scheme
	target.Host = doer.base.Host
	clone.URL = &target
	clone.Host = originalHost
	clone.Header = request.Header.Clone()
	return doer.client.Do(clone)
}

func TestDriveMultipartAndSimpleUploadsUseExactTypedRequests(t *testing.T) {
	t.Run("multipart create", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.URL.Path != "/upload/drive/v3/files" ||
				request.URL.Query().Get("uploadType") != "multipart" || request.URL.Query().Get("supportsAllDrives") != "true" ||
				request.Host != "www.googleapis.com" || request.Header.Get("Authorization") != "Bearer provider-secret" ||
				request.Header.Get("Idempotency-Key") != "" {
				t.Errorf("unexpected request: %s %s host=%q headers=%v", request.Method, request.URL, request.Host, request.Header)
			}
			mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
			if err != nil || mediaType != "multipart/related" || parameters["boundary"] == "" {
				t.Fatalf("Content-Type = %q err=%v", request.Header.Get("Content-Type"), err)
			}
			reader := multipart.NewReader(request.Body, parameters["boundary"])
			metadataPart, err := reader.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			metadata, _ := io.ReadAll(metadataPart)
			var decoded map[string]any
			if metadataPart.Header.Get("Content-Type") != "application/json; charset=UTF-8" ||
				json.Unmarshal(metadata, &decoded) != nil || decoded["name"] != "report.txt" {
				t.Errorf("metadata part type=%q body=%s", metadataPart.Header.Get("Content-Type"), metadata)
			}
			mediaPart, err := reader.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			content, _ := io.ReadAll(mediaPart)
			if mediaPart.Header.Get("Content-Type") != "text/plain" || string(content) != "hello" {
				t.Errorf("media part type=%q body=%q", mediaPart.Header.Get("Content-Type"), content)
			}
			if _, err = reader.NextPart(); !errors.Is(err, io.EOF) {
				t.Errorf("unexpected multipart tail: %v", err)
			}
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte(`{"id":"file-1","name":"report.txt"}`))
		}))
		defer server.Close()

		manifest := driveManifest()
		adapter, err := NewHTTPAdapter(manifest, newDriveServerDoer(t, server))
		if err != nil {
			t.Fatal(err)
		}
		operation := findOperation(t, adapter, "files.drive.files.content.create")
		arguments := uploadArguments([]byte("hello"), "text/plain", map[string]any{
			"metadata": map[string]any{"name": "report.txt"}, "upload_mode": "multipart", "supports_all_drives": true,
		})
		result, err := adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, arguments))
		if err != nil {
			t.Fatal(err)
		}
		if result.Metadata["upload_transport"] != "multipart" || result.ProviderStatus != http.StatusOK || result.Attempts != 1 {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("simple update", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			content, _ := io.ReadAll(request.Body)
			if request.Method != http.MethodPatch || request.URL.Path != "/upload/drive/v3/files/file-7" ||
				request.URL.Query().Get("uploadType") != "media" || request.Header.Get("Content-Type") != "application/octet-stream" ||
				!bytes.Equal(content, []byte{0, 1, 2, 3}) {
				t.Errorf("unexpected simple update: %s %s type=%q body=%v", request.Method, request.URL, request.Header.Get("Content-Type"), content)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"id":"file-7"}`))
		}))
		defer server.Close()

		manifest := driveManifest()
		adapter, err := NewHTTPAdapter(manifest, newDriveServerDoer(t, server))
		if err != nil {
			t.Fatal(err)
		}
		operation := findOperation(t, adapter, "files.drive.files.content.update")
		arguments := uploadArguments([]byte{0, 1, 2, 3}, "application/octet-stream", map[string]any{
			"file_id": "file-7", "upload_mode": "simple",
		})
		if _, err = adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, arguments)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDriveResumableUploadFollowsAcceptedRangeAcrossMultipleChunks(t *testing.T) {
	content := makePatternBytes(600 << 10)
	const chunk = 256 << 10
	var mu sync.Mutex
	var chunkCalls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Method == http.MethodPost {
			body, _ := io.ReadAll(request.Body)
			if request.URL.Path != "/upload/drive/v3/files" || request.URL.Query().Get("uploadType") != "resumable" ||
				request.Header.Get("X-Upload-Content-Type") != "application/octet-stream" ||
				request.Header.Get("X-Upload-Content-Length") != strconv.Itoa(len(content)) ||
				string(body) != `{"name":"large.bin"}` {
				t.Errorf("invalid initiation: %s %s headers=%v body=%s", request.Method, request.URL, request.Header, body)
			}
			response.Header().Set("Location", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=session-1")
			response.WriteHeader(http.StatusOK)
			return
		}
		chunkCalls++
		ranges := []struct {
			header string
			start  int
			end    int
			accept string
			status int
		}{
			{"bytes 0-262143/614400", 0, 262144, "bytes=0-262143", 308},
			{"bytes 262144-524287/614400", 262144, 524288, "bytes=0-393215", 308},
			{"bytes 393216-614399/614400", 393216, 614400, "", http.StatusOK},
		}
		if chunkCalls > len(ranges) {
			t.Fatalf("unexpected extra chunk %d", chunkCalls)
		}
		want := ranges[chunkCalls-1]
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPut || request.URL.Path != "/upload/drive/v3/files" ||
			request.URL.Query().Get("upload_id") != "session-1" || request.Header.Get("Content-Range") != want.header ||
			request.ContentLength != int64(want.end-want.start) || !bytes.Equal(body, content[want.start:want.end]) {
			t.Errorf("chunk %d invalid: %s %s range=%q length=%d body=%d", chunkCalls, request.Method, request.URL, request.Header.Get("Content-Range"), request.ContentLength, len(body))
		}
		if want.accept != "" {
			response.Header().Set("Range", want.accept)
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(want.status)
		if want.status == http.StatusOK {
			_, _ = response.Write([]byte(`{"id":"large-file"}`))
		}
	}))
	defer server.Close()

	manifest := driveManifest()
	adapter, err := NewHTTPAdapterWithOptions(manifest, newDriveServerDoer(t, server), AdapterOptions{
		DriveSimpleUploadMaxBytes: 256 << 10,
		DriveUploadMaxBytes:       1 << 20,
		DriveResumableChunkBytes:  chunk,
	})
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "files.drive.files.content.create")
	arguments := uploadArguments(content, "application/octet-stream", map[string]any{"metadata": map[string]any{"name": "large.bin"}})
	result, err := adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, arguments))
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata["upload_transport"] != "resumable" || result.Attempts != 4 || result.RequestBytes <= int64(len(content)) {
		t.Fatalf("result = %+v", result)
	}
}

func TestDriveResumableUploadRecoversLostFinalResponseWithStatusProbe(t *testing.T) {
	content := makePatternBytes(300 << 10)
	const chunk = 256 << 10
	var mu sync.Mutex
	var accepted int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Method == http.MethodPost {
			response.Header().Set("Location", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=recover-1")
			response.WriteHeader(http.StatusOK)
			return
		}
		switch request.Header.Get("Content-Range") {
		case "bytes 0-262143/307200":
			_, _ = io.Copy(io.Discard, request.Body)
			accepted = 262144
			response.Header().Set("Range", "bytes=0-262143")
			response.WriteHeader(308)
		case "bytes 262144-307199/307200":
			_, _ = io.Copy(io.Discard, request.Body)
			accepted = int64(len(content))
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"id":"recovered-file"}`))
		case "bytes */307200":
			if request.ContentLength != 0 || accepted != int64(len(content)) {
				t.Errorf("invalid status probe: length=%d accepted=%d", request.ContentLength, accepted)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"id":"recovered-file"}`))
		default:
			t.Errorf("unexpected Content-Range %q", request.Header.Get("Content-Range"))
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	baseDoer := newDriveServerDoer(t, server)
	var dropped bool
	doer := doerFunc(func(request *http.Request) (*http.Response, error) {
		response, err := baseDoer.Do(request)
		if err == nil && request.Header.Get("Content-Range") == "bytes 262144-307199/307200" && !dropped {
			dropped = true
			_ = response.Body.Close()
			return nil, io.ErrUnexpectedEOF
		}
		return response, err
	})
	manifest := driveManifest()
	adapter, err := NewHTTPAdapterWithOptions(manifest, doer, AdapterOptions{
		DriveSimpleUploadMaxBytes: 1,
		DriveUploadMaxBytes:       1 << 20,
		DriveResumableChunkBytes:  chunk,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error { return nil }
	operation := findOperation(t, adapter, "files.drive.files.content.create")
	result, err := adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, uploadArguments(content, "application/octet-stream", nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !dropped || result.Attempts != 4 || result.ProviderStatus != http.StatusOK {
		t.Fatalf("dropped=%v result=%+v", dropped, result)
	}
}

func TestDriveResumableUploadBacksOffAndProbesAfterRetryableStatus(t *testing.T) {
	content := makePatternBytes(300 << 10)
	var mu sync.Mutex
	var firstChunkCalls, probes int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Method == http.MethodPost {
			response.Header().Set("Location", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=retry-1")
			return
		}
		switch request.Header.Get("Content-Range") {
		case "bytes 0-262143/307200":
			firstChunkCalls++
			_, _ = io.Copy(io.Discard, request.Body)
			if firstChunkCalls == 1 {
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			response.Header().Set("Range", "bytes=0-262143")
			response.WriteHeader(308)
		case "bytes */307200":
			probes++
			response.WriteHeader(308)
		case "bytes 262144-307199/307200":
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"id":"retry-file"}`))
		default:
			t.Errorf("unexpected range %q", request.Header.Get("Content-Range"))
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	manifest := driveManifest()
	adapter, err := NewHTTPAdapterWithOptions(manifest, newDriveServerDoer(t, server), AdapterOptions{
		DriveSimpleUploadMaxBytes: 1,
		DriveUploadMaxBytes:       1 << 20,
		DriveResumableChunkBytes:  256 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sleeps int
	adapter.sleep = func(context.Context, time.Duration) error {
		sleeps++
		return nil
	}
	operation := findOperation(t, adapter, "files.drive.files.content.create")
	if _, err = adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, uploadArguments(content, "application/octet-stream", nil))); err != nil {
		t.Fatal(err)
	}
	if firstChunkCalls != 2 || probes != 1 || sleeps < 2 {
		t.Fatalf("chunk calls=%d probes=%d sleeps=%d", firstChunkCalls, probes, sleeps)
	}
}

func TestDriveResumableLocationIsFailClosed(t *testing.T) {
	cases := map[string][]string{
		"non HTTPS":          {"http://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=x"},
		"hostile host":       {"https://evil.example/upload/drive/v3/files?uploadType=resumable&upload_id=x"},
		"credential URL":     {"https://user:secret@www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=x"},
		"credential query":   {"https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=x&access_token=secret"},
		"wrong path":         {"https://www.googleapis.com/drive/v3/files?uploadType=resumable&upload_id=x"},
		"duplicate session":  {"https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=x&upload_id=y"},
		"unexpected port":    {"https://www.googleapis.com:443/upload/drive/v3/files?uploadType=resumable&upload_id=x"},
		"duplicate Location": {"https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=x", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=y"},
	}
	for name, locations := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				for _, location := range locations {
					response.Header().Add("Location", location)
				}
				response.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			manifest := driveManifest()
			adapter, err := NewHTTPAdapterWithOptions(manifest, newDriveServerDoer(t, server), AdapterOptions{
				DriveSimpleUploadMaxBytes: 1,
				DriveUploadMaxBytes:       1 << 20,
				DriveResumableChunkBytes:  256 << 10,
			})
			if err != nil {
				t.Fatal(err)
			}
			operation := findOperation(t, adapter, "files.drive.files.content.create")
			_, err = adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, uploadArguments([]byte("large"), "application/octet-stream", map[string]any{"upload_mode": "resumable"})))
			var providerErr *domain.ProviderError
			if !errors.As(err, &providerErr) || providerErr.Kind != "unsafe_resumable_location" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDriveUploadPayloadBoundsModesAndEnvelopesFailClosed(t *testing.T) {
	manifest := driveManifest()
	adapter, err := NewHTTPAdapterWithOptions(manifest, successDoer(), AdapterOptions{
		DriveSimpleUploadMaxBytes: 256 << 10,
		DriveUploadMaxBytes:       256 << 10,
		DriveResumableChunkBytes:  256 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	create := findOperation(t, adapter, "files.drive.files.content.create")
	cases := map[string]json.RawMessage{
		"over cap":             uploadArguments(makePatternBytes((256<<10)+1), "application/octet-stream", nil),
		"malformed base64":     json.RawMessage(`{"content_base64":"!!!!","mime_type":"application/octet-stream"}`),
		"MIME parameters":      json.RawMessage(`{"content_base64":"eA==","mime_type":"text/plain; charset=utf-8"}`),
		"scalar metadata":      json.RawMessage(`{"content_base64":"eA==","mime_type":"text/plain","metadata":"name"}`),
		"simple with metadata": json.RawMessage(`{"content_base64":"eA==","mime_type":"text/plain","metadata":{"name":"x"},"upload_mode":"simple"}`),
		"empty resumable":      json.RawMessage(`{"content_base64":"","mime_type":"text/plain","upload_mode":"resumable"}`),
		"unknown argument":     json.RawMessage(`{"content_base64":"eA==","mime_type":"text/plain","url":"https://evil.example"}`),
	}
	for name, arguments := range cases {
		t.Run(name, func(t *testing.T) {
			invocation := testInvocation(t, manifest, create, arguments)
			if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Fatalf("Preview error = %v", err)
			}
		})
	}
	if _, err = NewHTTPAdapterWithOptions(manifest, successDoer(), AdapterOptions{
		DriveSimpleUploadMaxBytes: DefaultDriveSimpleUploadMaxBytes + 1,
		DriveUploadMaxBytes:       DefaultDriveUploadMaxBytes,
		DriveResumableChunkBytes:  DefaultDriveResumableChunkBytes,
	}); err == nil {
		t.Fatal("adapter accepted a simple threshold above the Drive v3 recommendation")
	}

	envelopes := []string{`{"error":{"code":403,"message":"denied"}}`, `{"errors":[{"reason":"denied"}]}`, `"unexpected"`, `{not-json`}
	for _, envelope := range envelopes {
		adapter, err = NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, envelope, nil), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		create = findOperation(t, adapter, "files.drive.files.content.create")
		_, err = adapter.Invoke(context.Background(), testInvocation(t, manifest, create, uploadArguments([]byte("x"), "text/plain", nil)))
		var providerErr *domain.ProviderError
		if !errors.As(err, &providerErr) || providerErr.Kind != "provider_operation_error" {
			t.Fatalf("envelope %q error = %v", envelope, err)
		}
	}
}

func TestDrivePreGeneratedIDRecoversAmbiguousCreateWithoutDuplicate(t *testing.T) {
	var createCalls, probeCalls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost:
			createCalls++
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"id":"generated-1"}`))
		case request.Method == http.MethodGet && request.URL.Path == "/drive/v3/files/generated-1":
			probeCalls++
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"id":"generated-1"}`))
		default:
			t.Errorf("unexpected request %s %s", request.Method, request.URL)
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	baseDoer := newDriveServerDoer(t, server)
	var dropped bool
	doer := doerFunc(func(request *http.Request) (*http.Response, error) {
		response, err := baseDoer.Do(request)
		if err == nil && request.Method == http.MethodPost && !dropped {
			dropped = true
			_ = response.Body.Close()
			return nil, io.ErrUnexpectedEOF
		}
		return response, err
	})
	manifest := driveManifest()
	adapter, err := NewHTTPAdapter(manifest, doer)
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error { return nil }
	operation := findOperation(t, adapter, "files.drive.files.content.create")
	invocation := testInvocation(t, manifest, operation, uploadArguments([]byte("x"), "text/plain", map[string]any{
		"metadata": map[string]any{"id": "generated-1", "name": "safe.txt"},
	}))
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if createCalls != 1 || probeCalls != 1 || !dropped || result.Metadata["idempotency_applied"] != "true" {
		t.Fatalf("create=%d probe=%d dropped=%v result=%+v", createCalls, probeCalls, dropped, result)
	}
}

func TestDriveManifestReachesRevisionsCollaborationSharedDrivesAndChanges(t *testing.T) {
	manifest := driveManifest()
	wanted := map[string]struct {
		method string
		path   string
		body   BodyMode
	}{
		"files.drive.files.content.create": {http.MethodPost, "/upload/drive/v3/files", BodyDriveUpload},
		"files.drive.files.content.update": {http.MethodPatch, "/upload/drive/v3/files/{file_id}", BodyDriveUpload},
		"files.drive.files.generate_ids":   {http.MethodGet, "/drive/v3/files/generateIds", BodyNone},
		"files.drive.revisions.list":       {http.MethodGet, "/drive/v3/files/{file_id}/revisions", BodyNone},
		"files.drive.revisions.get":        {http.MethodGet, "/drive/v3/files/{file_id}/revisions/{revision_id}", BodyNone},
		"files.drive.revisions.update":     {http.MethodPatch, "/drive/v3/files/{file_id}/revisions/{revision_id}", BodyJSON},
		"files.drive.revisions.delete":     {http.MethodDelete, "/drive/v3/files/{file_id}/revisions/{revision_id}", BodyJSON},
		"files.drive.comments.get":         {http.MethodGet, "/drive/v3/files/{file_id}/comments/{comment_id}", BodyNone},
		"files.drive.replies.list":         {http.MethodGet, "/drive/v3/files/{file_id}/comments/{comment_id}/replies", BodyNone},
		"files.drive.replies.get":          {http.MethodGet, "/drive/v3/files/{file_id}/comments/{comment_id}/replies/{reply_id}", BodyNone},
		"files.drive.replies.create":       {http.MethodPost, "/drive/v3/files/{file_id}/comments/{comment_id}/replies", BodyJSON},
		"files.drive.replies.update":       {http.MethodPatch, "/drive/v3/files/{file_id}/comments/{comment_id}/replies/{reply_id}", BodyJSON},
		"files.drive.replies.delete":       {http.MethodDelete, "/drive/v3/files/{file_id}/comments/{comment_id}/replies/{reply_id}", BodyJSON},
		"files.drive.permissions.get":      {http.MethodGet, "/drive/v3/files/{file_id}/permissions/{permission_id}", BodyNone},
		"files.drive.shared_drives.list":   {http.MethodGet, "/drive/v3/drives", BodyNone},
		"files.drive.changes.list":         {http.MethodGet, "/drive/v3/changes", BodyNone},
		"files.drive.changes.watch":        {http.MethodPost, "/drive/v3/changes/watch", BodyJSON},
	}
	for _, operation := range manifest.Operations {
		if expected, exists := wanted[operation.Name]; exists {
			if operation.Method != expected.method || operation.Path != expected.path || operation.Body != expected.body {
				t.Errorf("%s = %s %s %s", operation.Name, operation.Method, operation.Path, operation.Body)
			}
			delete(wanted, operation.Name)
		}
		if operation.Name == "files.drive.files.upload" {
			t.Error("legacy one-shot upload operation remains exposed")
		}
	}
	if len(wanted) != 0 {
		t.Fatalf("unreachable typed Drive operations: %v", wanted)
	}
	raw := manifest.Operations[len(manifest.Operations)-1]
	if raw.Name != "files.drive.raw" || raw.Raw == nil ||
		!containsString(raw.Raw.PathPrefixes, "/drive/v3/") || !containsString(raw.Raw.PathPrefixes, "/upload/drive/v3/") {
		t.Fatalf("Drive constrained raw fallback = %#v", raw)
	}
}

func uploadArguments(content []byte, mediaType string, extras map[string]any) json.RawMessage {
	arguments := map[string]any{
		"content_base64": base64.StdEncoding.EncodeToString(content),
		"mime_type":      mediaType,
	}
	for key, value := range extras {
		arguments[key] = value
	}
	encoded, _ := json.Marshal(arguments)
	return encoded
}

func makePatternBytes(size int) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = byte(index % 251)
	}
	return result
}

func TestDriveSuccessfulHTTPErrorEnvelopeIsDetectedForMetadataCalls(t *testing.T) {
	manifest := driveManifest()
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"error":{"code":403,"message":"denied"}}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "files.drive.search")
	_, err = adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, json.RawMessage(`{}`)))
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "provider_operation_error" {
		t.Fatalf("error = %v", err)
	}
}

func TestDriveSimpleCreateWithoutGeneratedIDDoesNotRetryAmbiguousTransport(t *testing.T) {
	manifest := driveManifest()
	var calls int
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	}))
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error {
		t.Fatal("unsafe create attempted backoff")
		return nil
	}
	operation := findOperation(t, adapter, "files.drive.files.content.create")
	invocation := testInvocation(t, manifest, operation, uploadArguments([]byte("x"), "text/plain", nil))
	invocation.Idempotency = "trusted-key"
	_, err = adapter.Invoke(context.Background(), invocation)
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "network_error" || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestDriveOneShotUpdateDoesNotRetryAndCreateExtraRevision(t *testing.T) {
	manifest := driveManifest()
	var calls int
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	}))
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error {
		t.Fatal("ambiguous one-shot update attempted backoff")
		return nil
	}
	operation := findOperation(t, adapter, "files.drive.files.content.update")
	invocation := testInvocation(t, manifest, operation, uploadArguments([]byte("x"), "text/plain", map[string]any{
		"file_id": "file-1", "upload_mode": "simple",
	}))
	_, err = adapter.Invoke(context.Background(), invocation)
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "network_error" || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestDriveStatusProbeRangeCannotSkipUnsentBytes(t *testing.T) {
	content := makePatternBytes(300 << 10)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			response.Header().Set("Location", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=hostile-range")
			return
		}
		if strings.HasPrefix(request.Header.Get("Content-Range"), "bytes 0-") {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if request.Header.Get("Content-Range") == "bytes */307200" {
			// Only the first 256 KiB could have been sent. Claiming more must
			// not make the adapter skip bytes.
			response.Header().Set("Range", "bytes=0-307199")
			response.WriteHeader(308)
			return
		}
		response.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	manifest := driveManifest()
	adapter, err := NewHTTPAdapterWithOptions(manifest, newDriveServerDoer(t, server), AdapterOptions{
		DriveSimpleUploadMaxBytes: 1,
		DriveUploadMaxBytes:       1 << 20,
		DriveResumableChunkBytes:  256 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter.sleep = func(context.Context, time.Duration) error { return nil }
	operation := findOperation(t, adapter, "files.drive.files.content.create")
	_, err = adapter.Invoke(context.Background(), testInvocation(t, manifest, operation, uploadArguments(content, "application/octet-stream", nil)))
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "invalid_resumable_range" {
		t.Fatalf("error = %v", err)
	}
}
