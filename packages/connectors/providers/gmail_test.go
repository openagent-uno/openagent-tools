package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func TestGmailManifestIsFixedTypedAndPolicyClassified(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	if manifest.OriginKind != OriginFixed || manifest.Origin != "https://www.googleapis.com" ||
		manifest.CredentialHeader != "Authorization" || manifest.CredentialScheme != "Bearer" {
		t.Fatalf("unsafe Gmail provider binding: %+v", manifest)
	}
	if err := manifest.validate(); err != nil {
		t.Fatalf("manifest validation failed: %v", err)
	}
	wanted := map[string]domain.Risk{
		"outreach.gmail.history.list":    domain.RiskRead,
		"outreach.gmail.messages.list":   domain.RiskRead,
		"outreach.gmail.messages.get":    domain.RiskRead,
		"outreach.gmail.threads.get":     domain.RiskRead,
		"outreach.gmail.attachments.get": domain.RiskRead,
		"outreach.gmail.watch":           domain.RiskWrite,
		"outreach.gmail.drafts.create":   domain.RiskDraft,
		"outreach.gmail.drafts.send":     domain.RiskPublish,
		"outreach.gmail.messages.send":   domain.RiskPublish,
		"outreach.gmail.raw":             domain.RiskRaw,
	}
	for _, operation := range manifest.Operations {
		risk, exists := wanted[operation.Name]
		if !exists {
			t.Errorf("unexpected operation %q", operation.Name)
			continue
		}
		delete(wanted, operation.Name)
		if operation.Risk != risk {
			t.Errorf("%s risk=%q want=%q", operation.Name, operation.Risk, risk)
		}
		if risk != domain.RiskRead && operation.Raw == nil && operation.Retry.MaxAttempts != 1 {
			t.Errorf("%s may retry an ambiguous Gmail write", operation.Name)
		}
		if operation.Raw != nil &&
			(len(operation.Raw.Methods) != 1 || operation.Raw.Methods[0] != http.MethodGet) {
			t.Errorf("Gmail raw escape is not read-only: %+v", operation.Raw)
		}
	}
	if len(wanted) != 0 {
		t.Fatalf("missing Gmail operations: %v", wanted)
	}
}

func TestProviderCatalogPublishesGmailOnOutreachMCP(t *testing.T) {
	t.Parallel()
	adapters, err := CatalogWithDoer(successDoer())
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range adapters {
		if adapter.Provider() != "gmail" {
			continue
		}
		if adapter.Capability() != domain.Outreach {
			t.Fatalf("Gmail capability=%q", adapter.Capability())
		}
		operations := adapter.Operations()
		if len(operations) != 10 {
			t.Fatalf("Gmail tools=%d want=10", len(operations))
		}
		return
	}
	t.Fatal("Gmail adapter is missing from the built-in MCP catalog")
}

func TestGmailUsesFixedOriginBearerAndRedactsResponse(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	var captured *http.Request
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		captured = request.Clone(context.Background())
		return jsonResponse(http.StatusOK, `{"messages":[],"echo":"gmail-secret"}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "outreach.gmail.messages.list")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{
		"query":"from:customer@example.com",
		"label_ids":["INBOX"],
		"include_spam_trash":false,
		"max_results":50
	}`))
	invocation.Credential = credentialWithSecret(t, "gmail-secret", "Authorization", "Bearer")
	result, err := adapter.Invoke(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if captured.URL.Scheme != "https" || captured.URL.Host != "www.googleapis.com" ||
		captured.URL.Path != "/gmail/v1/users/me/messages" {
		t.Fatalf("unexpected target: %s", captured.URL)
	}
	if got := captured.Header.Get("Authorization"); got != "Bearer gmail-secret" {
		t.Fatalf("Authorization=%q", got)
	}
	if captured.Header.Get("Cookie") != "" || captured.Header.Get("X-OpenAgent-Workspace-ID") != "" {
		t.Fatal("ambient identity reached Gmail")
	}
	if captured.URL.Query().Get("q") != "from:customer@example.com" ||
		captured.URL.Query().Get("labelIds") != "INBOX" {
		t.Fatalf("unexpected Gmail query: %s", captured.URL.RawQuery)
	}
	encoded, _ := json.Marshal(result.Data)
	if strings.Contains(string(encoded), "gmail-secret") || !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("credential leaked in result: %s", encoded)
	}
}

func TestGmailWatchIsBoundToConfiguredTopic(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	adapter, err := NewHTTPAdapter(manifest, successDoer())
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "outreach.gmail.watch")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{
		"body":{"topicName":"projects/attacker-project/topics/stolen","labelIds":["INBOX"]}
	}`))
	if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
		t.Fatalf("mismatched watch topic error=%v", err)
	}
	invocation.Arguments = json.RawMessage(`{
		"body":{"topicName":"projects/openagent-test/topics/gmail-events","labelIds":["INBOX"]}
	}`)
	preview, err := adapter.Preview(invocation)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Method != http.MethodPost || preview.Path != "/gmail/v1/users/me/watch" {
		t.Fatalf("preview=%+v", preview)
	}
}

func TestGmailSendDoesNotRetryAmbiguousNetworkFailure(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	var calls int
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("connection reset after write")
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "outreach.gmail.messages.send")
	invocation := testInvocation(t, manifest, operation, json.RawMessage(`{
		"body":{"raw":"VG86IHVzZXJAZXhhbXBsZS5jb20NClN1YmplY3Q6IFRlc3QNCg0KSGVsbG8"}
	}`))
	_, err = adapter.Invoke(context.Background(), invocation)
	var providerErr *domain.ProviderError
	if !errors.As(err, &providerErr) || providerErr.Kind != "network_error" ||
		providerErr.Attempts != 1 || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestGmailRawEscapeCannotSendOrChangeOrigin(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	adapter, err := NewHTTPAdapter(manifest, successDoer())
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "outreach.gmail.raw")
	for name, arguments := range map[string]string{
		"send":   `{"method":"POST","path":"/gmail/v1/users/me/messages/send","body":{}}`,
		"origin": `{"method":"GET","path":"https://attacker.invalid/gmail/v1/users/me/messages"}`,
		"watch":  `{"method":"GET","path":"/gmail/v1/users/me/watch"}`,
	} {
		t.Run(name, func(t *testing.T) {
			invocation := testInvocation(t, manifest, operation, json.RawMessage(arguments))
			if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestGmailTypedOperationsRejectUnknownArgumentsAndMalformedMail(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	adapter, err := NewHTTPAdapter(manifest, successDoer())
	if err != nil {
		t.Fatal(err)
	}
	list := findOperation(t, adapter, "outreach.gmail.messages.list")
	invocation := testInvocation(t, manifest, list, json.RawMessage(`{
		"query":"in:inbox","headers":{"Authorization":"stolen"}
	}`))
	if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
		t.Fatalf("unknown argument error=%v", err)
	}

	send := findOperation(t, adapter, "outreach.gmail.messages.send")
	invocation = testInvocation(t, manifest, send, json.RawMessage(`{"body":{"raw":"bm90LWEtbWFpbA"}}`))
	if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
		t.Fatalf("malformed mail error=%v", err)
	}
}

func TestGmailAttachmentIdentifiersUseTheirOwnBoundedSchemaAndRequestPath(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	var captured *http.Request
	calls := 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		captured = request.Clone(context.Background())
		return jsonResponse(http.StatusOK, `{"size":1,"data":"Zg"}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "outreach.gmail.attachments.get")
	var schema struct {
		Properties map[string]struct {
			Type      string `json:"type"`
			Pattern   string `json:"pattern"`
			MaxLength int    `json:"maxLength"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(operation.InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	attachmentProperty := schema.Properties["attachment_id"]
	if attachmentProperty.Type != "string" || attachmentProperty.Pattern != `^[A-Za-z0-9_-]+$` || attachmentProperty.MaxLength != 4096 ||
		schema.Properties["message_id"].Pattern != `^[A-Za-z0-9_-]{1,256}$` {
		t.Fatal("attachment and message identifiers do not have independent bounds")
	}
	pattern, err := regexp.Compile(attachmentProperty.Pattern)
	if err != nil {
		t.Fatal(err)
	}
	// The 404-byte synthetic identifier reproduces the length observed in
	// Gmail's attachment response without retaining an actual account's ID.
	for _, length := range []int{404, 512, 513, 4096} {
		id := strings.Repeat("Ab9_-", length/5) + strings.Repeat("Z", length%5)
		if !pattern.MatchString(id) || len(id) > attachmentProperty.MaxLength {
			t.Fatalf("advertised schema rejected valid attachment ID length %d", length)
		}
		arguments, _ := json.Marshal(map[string]string{"message_id": "message-1", "attachment_id": id})
		invocation := testInvocation(t, manifest, operation, arguments)
		before := calls
		preview, err := adapter.Preview(invocation)
		wantedPath := "/gmail/v1/users/me/messages/message-1/attachments/" + id
		if err != nil || preview.Method != http.MethodGet || preview.Path != wantedPath || calls != before {
			t.Fatalf("attachment ID length %d did not preserve exact preview path: %v", length, err)
		}
		if _, err := adapter.Invoke(context.Background(), invocation); err != nil {
			t.Fatalf("attachment ID length %d rejected before synthetic provider: %v", length, err)
		}
		if calls != before+1 || captured.Method != http.MethodGet || captured.URL.Scheme != "https" || captured.URL.Host != "www.googleapis.com" ||
			captured.URL.Path != wantedPath || captured.URL.RawQuery != "" || captured.Header.Get("Authorization") != "Bearer provider-secret" {
			t.Fatal("attachment identifier changed the fixed provider, credential, or request path")
		}
	}
}

func TestGmailAttachmentIdentifiersRejectUnsafeAndOversizedValuesBeforeIO(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	calls := 0
	adapter, err := NewHTTPAdapter(manifest, doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(http.StatusOK, `{}`, nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	operation := findOperation(t, adapter, "outreach.gmail.attachments.get")
	var schema struct {
		Properties map[string]struct {
			Pattern   string `json:"pattern"`
			MaxLength int    `json:"maxLength"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(operation.InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	pattern, err := regexp.Compile(schema.Properties["attachment_id"].Pattern)
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{
		"empty": "", "oversized": strings.Repeat("a", 4097), "slash": "part/other", "encoded-slash": "part%2Fother",
		"query": "part?alt=media", "fragment": "part#other", "traversal": "..", "url": "https://other.invalid/a",
		"carriage-return": "part\r", "newline": "part\n", "unicode": "parté", "padding": "part=", "plus": "part+", "space": "part other", "backslash": `part\other`,
	} {
		t.Run(name, func(t *testing.T) {
			if pattern.MatchString(id) && len(id) <= schema.Properties["attachment_id"].MaxLength {
				t.Fatal("advertised attachment schema accepted unsafe identifier")
			}
			arguments, _ := json.Marshal(map[string]string{"message_id": "message-1", "attachment_id": id})
			invocation := testInvocation(t, manifest, operation, arguments)
			if _, err := adapter.Preview(invocation); !errors.Is(err, domain.ErrInvalidArguments) {
				t.Fatal("unsafe attachment identifier was accepted by preview")
			}
			if _, err := adapter.Invoke(context.Background(), invocation); !errors.Is(err, domain.ErrInvalidArguments) || calls != 0 {
				t.Fatal("unsafe attachment identifier reached provider IO")
			}
		})
	}
}

func TestGmailLongAttachmentSupportDoesNotWidenOtherIdentifiers(t *testing.T) {
	t.Parallel()
	manifest := gmailManifest()
	adapter, err := NewHTTPAdapter(manifest, successDoer())
	if err != nil {
		t.Fatal(err)
	}
	longID := strings.Repeat("a", 257)
	for _, sample := range []struct {
		operation string
		arguments any
	}{
		{"outreach.gmail.attachments.get", map[string]string{"message_id": longID, "attachment_id": "attachment-1"}},
		{"outreach.gmail.messages.get", map[string]string{"message_id": longID}},
		{"outreach.gmail.threads.get", map[string]string{"thread_id": longID}},
		{"outreach.gmail.drafts.send", map[string]any{"body": map[string]string{"id": longID}}},
		{"outreach.gmail.messages.list", map[string]any{"label_ids": []string{longID}}},
	} {
		operation := findOperation(t, adapter, sample.operation)
		arguments, _ := json.Marshal(sample.arguments)
		if _, err := adapter.Preview(testInvocation(t, manifest, operation, arguments)); !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatalf("attachment-specific change widened %s identifiers", sample.operation)
		}
	}
}

func TestGmailAttachmentExceptionDoesNotWidenGenericPathExpansion(t *testing.T) {
	t.Parallel()
	for _, length := range []int{512, 513} {
		value := strings.Repeat("a", length)
		raw, _ := json.Marshal(value)
		path, err := expandPath("/items/{id}", map[string]json.RawMessage{"id": raw}, map[string]bool{})
		if length == 512 {
			if err != nil || path != "/items/"+value {
				t.Fatal("generic path expansion lost its existing 512-byte bound")
			}
		} else if !errors.Is(err, domain.ErrInvalidArguments) {
			t.Fatal("Gmail attachment exception widened generic path expansion")
		}
	}
}
