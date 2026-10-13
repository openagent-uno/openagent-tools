package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
