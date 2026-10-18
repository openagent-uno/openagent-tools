package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const microsoftFilesTestSite = "tenant.sharepoint.com,11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222"

func microsoftFilesResponse(status int, raw string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(raw))}
}
func microsoftFilesInvocation(t *testing.T, a *MicrosoftFilesAdapter, suffix, args string) domain.Invocation {
	t.Helper()
	for _, op := range a.Operations() {
		if op.Name == "files."+a.Provider()+"."+suffix {
			cfg := `{"drive_id":"drive!bound"}`
			if a.Provider() == "sharepoint" {
				b, _ := json.Marshal(map[string]string{"drive_id": "drive!bound", "site_id": microsoftFilesTestSite})
				cfg = string(b)
			}
			return domain.Invocation{ID: "inv-files-1", Principal: domain.Principal{WorkspaceID: "ws-1", ActorID: "actor-1", Role: "agent"}, Connection: domain.Connection{ID: "conn-1", WorkspaceID: "ws-1", Provider: a.Provider(), Capability: domain.Files, Enabled: true, ExternalID: "verified-account", Scopes: append([]string(nil), op.RequiredScopes...), Config: json.RawMessage(cfg)}, Operation: op, Arguments: json.RawMessage(args), Credential: credential(t, "Authorization", "Bearer"), RequestedAt: time.Now()}
		}
	}
	t.Fatal("unknown operation")
	return domain.Invocation{}
}
func TestMicrosoftFilesFiniteReadOnlyContract(t *testing.T) {
	for _, provider := range []string{"onedrive", "sharepoint"} {
		a, e := NewMicrosoftFilesAdapter(provider, doerFunc(func(*http.Request) (*http.Response, error) { t.Fatal("metadata performed IO"); return nil, nil }))
		if e != nil {
			t.Fatal(e)
		}
		want := 5
		if provider == "sharepoint" {
			want = 7
		}
		if len(a.Operations()) != want {
			t.Fatal("inventory mismatch")
		}
		if e = a.manifest.validate(); e != nil {
			t.Fatal(e)
		}
		for _, op := range a.Operations() {
			if e = op.Validate(); e != nil {
				t.Fatal(e)
			}
			if op.Risk != domain.RiskRead || op.Retry.MaxAttempts != 1 || op.Retry.SupportsIdempotency || op.Mode != domain.OperationTyped {
				t.Fatal("not finite read-only")
			}
			if !a.OperationScopesGranted(op.RequiredScopes, op.Name) || a.OperationScopesGranted([]string{"Sites.Selected"}, op.Name) || a.OperationScopesGranted(nil, op.Name) {
				t.Fatal("scope policy")
			}
			var schema map[string]any
			_ = json.Unmarshal(op.InputSchema, &schema)
			if schema["additionalProperties"] != false {
				t.Fatal("open schema")
			}
		}
		if a.OperationScopesGranted([]string{"Sites.ReadWrite.All"}, "files."+provider+".raw") {
			t.Fatal("unknown operation admitted")
		}
	}
	if _, e := NewMicrosoftFilesAdapter("outlook_mail", successDoer()); !errors.Is(e, domain.ErrUnsupported) {
		t.Fatal("provider widening")
	}
	a, _ := NewMicrosoftFilesAdapter("onedrive", successDoer())
	for _, scope := range []string{"Files.Read.All", "Files.ReadWrite", "Files.ReadWrite.All", "Sites.Read.All", "Sites.ReadWrite.All"} {
		if !a.OperationScopesGranted([]string{scope}, "files.onedrive.items.get") {
			t.Fatal("documented higher permission denied")
		}
	}
}
func TestMicrosoftFilesDocumentedRoutesAndClosedBinding(t *testing.T) {
	cases := []struct{ provider, op, args, path string }{
		{"onedrive", "drives.list", `{"top":100}`, "/v1.0/me/drives"},
		{"onedrive", "drives.get", `{}`, "/v1.0/drives/drive%21bound"},
		{"onedrive", "items.list", `{}`, "/v1.0/drives/drive%21bound/root/children"},
		{"onedrive", "items.list", `{"parent_id":"opaque+/=!"}`, "/v1.0/drives/drive%21bound/items/opaque+%2F=%21/children"},
		{"onedrive", "items.get", `{"item_id":"item!1"}`, "/v1.0/drives/drive%21bound/items/item%211"},
		{"sharepoint", "sites.search", `{"query":"project"}`, "/v1.0/sites"},
		{"sharepoint", "sites.get", `{}`, "/v1.0/sites/" + url.PathEscape(microsoftFilesTestSite)},
		{"sharepoint", "drives.list", `{}`, "/v1.0/sites/" + url.PathEscape(microsoftFilesTestSite) + "/drives"},
		{"sharepoint", "items.get", `{"item_id":"item!1"}`, "/v1.0/drives/drive%21bound/items/item%211"},
	}
	for _, tc := range cases {
		t.Run(tc.provider+tc.op+tc.args, func(t *testing.T) {
			calls := 0
			a, _ := NewMicrosoftFilesAdapter(tc.provider, doerFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "https" || r.URL.Host != "graph.microsoft.com" || r.URL.EscapedPath() != tc.path || r.Method != "GET" || r.Header.Get("Authorization") == "" {
					t.Fatalf("wrong bound Graph route %s", r.URL.EscapedPath())
				}
				raw := `{"id":"item!1","name":"QA"}`
				switch {
				case tc.op == "sites.search":
					raw = `{"value":[{"id":"` + microsoftFilesTestSite + `","displayName":"QA"}]}`
				case tc.op == "sites.get":
					raw = `{"id":"` + microsoftFilesTestSite + `","displayName":"QA"}`
				case strings.HasSuffix(tc.op, ".list"):
					raw = `{"value":[]}`
				case tc.op == "drives.get":
					raw = `{"id":"drive!bound","driveType":"personal"}`
				}
				return microsoftFilesResponse(200, raw), nil
			}))
			inv := microsoftFilesInvocation(t, a, tc.op, tc.args)
			if _, e := a.Invoke(context.Background(), inv); e != nil {
				t.Fatal(e)
			}
			if calls != 1 {
				t.Fatal("unexpected attempts")
			}
		})
	}
}
func TestMicrosoftFilesRejectsInvalidInputsBeforeIO(t *testing.T) {
	a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid request reached provider")
		return nil, nil
	}))
	for _, args := range []string{`{}`, `{"item_id":".."}`, `{"item_id":"item","item_id":"other"}`, `{"item_id":"x","drive_id":"other"}`, `{"item_id":"x","url":"https://evil.invalid"}`, `{"item_id":"x","headers":{}}`, `{"item_id":1}`, `{"item_id":"x\u0000"}`} {
		inv := microsoftFilesInvocation(t, a, "items.get", args)
		if _, e := a.Invoke(context.Background(), inv); e == nil {
			t.Fatal("invalid args admitted", args)
		}
	}
	for _, mutate := range []func(*domain.Invocation){
		func(i *domain.Invocation) { i.Connection.Config = json.RawMessage(`{}`) },
		func(i *domain.Invocation) {
			i.Connection.Config = json.RawMessage(`{"drive_id":"d","download_host":"tenant.sharepoint.com.evil.invalid"}`)
		},
		func(i *domain.Invocation) {
			i.Connection.Config = json.RawMessage(`{"drive_id":"d","site_id":"evil.invalid,a,b"}`)
		},
		func(i *domain.Invocation) {
			i.Connection.Config = json.RawMessage(`{"drive_id":"d","endpoint":"https://evil.invalid"}`)
		},
		func(i *domain.Invocation) { i.Connection.Enabled = false }, func(i *domain.Invocation) { i.Connection.Provider = "sharepoint" }, func(i *domain.Invocation) { i.Connection.ExternalID = "" }, func(i *domain.Invocation) { i.Principal.BoundConnectionID = "other" }, func(i *domain.Invocation) { i.Connection.Scopes = []string{"Mail.Read"} }, func(i *domain.Invocation) { i.Operation.Risk = domain.RiskWrite },
	} {
		inv := microsoftFilesInvocation(t, a, "items.get", `{"item_id":"x"}`)
		mutate(&inv)
		if _, e := a.Invoke(context.Background(), inv); e == nil {
			t.Fatal("invalid binding admitted")
		}
	}
}
func TestMicrosoftFilesCannotUseKeylessCredential(t *testing.T) {
	a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("no-auth credential reached Graph")
		return nil, nil
	}))
	inv := microsoftFilesInvocation(t, a, "items.get", `{"item_id":"item!1"}`)
	none, e := domain.NewCredential(domain.CredentialNone, "", "", "", "", nil)
	if e != nil {
		t.Fatal(e)
	}
	inv.Credential = none
	if _, e = a.Invoke(context.Background(), inv); e == nil {
		t.Fatal("explicit no-auth admitted")
	}
	inv.Credential = domain.Credential{}
	if _, e = a.Invoke(context.Background(), inv); e == nil {
		t.Fatal("absent credential admitted")
	}
}

func TestMicrosoftFilesBootstrapHasNoProvisionOrSelectionByModel(t *testing.T) {
	for _, provider := range []string{"onedrive", "sharepoint"} {
		calls := 0
		a, _ := NewMicrosoftFilesAdapter(provider, doerFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Path == "/v1.0/me/drive" {
				t.Fatal("drive provisioned")
			}
			return microsoftFilesResponse(200, `{"value":[]}`), nil
		}))
		suffix, args := "drives.list", `{}`
		if provider == "sharepoint" {
			suffix, args = "sites.search", `{"query":"project"}`
		}
		inv := microsoftFilesInvocation(t, a, suffix, args)
		inv.Connection.Config = json.RawMessage(`{}`)
		if _, e := a.Invoke(context.Background(), inv); e != nil {
			t.Fatal(e)
		}
		if calls != 1 {
			t.Fatal("discovery failed")
		}
		inv = microsoftFilesInvocation(t, a, "items.get", `{"item_id":"x"}`)
		inv.Connection.Config = json.RawMessage(`{}`)
		if _, e := a.Invoke(context.Background(), inv); e == nil || calls != 1 {
			t.Fatal("unbound resource request admitted")
		}
	}
	a, _ := NewMicrosoftFilesAdapter("sharepoint", successDoer())
	inv := microsoftFilesInvocation(t, a, "sites.get", `{}`)
	inv.Connection.Config = json.RawMessage(`{"site_id":"` + microsoftFilesTestSite + `"}`)
	if _, e := a.plan(inv, false); e != nil {
		t.Fatal("site-only bootstrap binding rejected", e)
	}
}
func TestMicrosoftFilesOpaquePagesAreConnectionAccountResourceAndQueryBound(t *testing.T) {
	calls := 0
	a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			next := *r.URL
			q := next.Query()
			q.Set("$skiptoken", "opaque-first")
			next.RawQuery = q.Encode()
			b, _ := json.Marshal(map[string]any{"value": []any{}, "@odata.nextLink": next.String()})
			return microsoftFilesResponse(200, string(b)), nil
		}
		if r.URL.Query().Get("$skiptoken") != "opaque-first" {
			t.Fatal("cursor changed")
		}
		next := *r.URL
		q := next.Query()
		q.Set("$skiptoken", "opaque-second")
		next.RawQuery = q.Encode()
		b, _ := json.Marshal(map[string]any{"value": []any{}, "@odata.nextLink": next.String()})
		return microsoftFilesResponse(200, string(b)), nil
	}))
	inv := microsoftFilesInvocation(t, a, "items.list", `{"parent_id":"folder","top":2}`)
	result, e := a.Invoke(context.Background(), inv)
	if e != nil {
		t.Fatal(e)
	}
	token := result.Data.(map[string]any)["next_page_token"].(string)
	raw, _ := json.Marshal(map[string]any{"parent_id": "folder", "top": 2, "page_token": token})
	next := inv
	next.Arguments = raw
	if _, e = a.Invoke(context.Background(), next); e != nil {
		t.Fatal("second-page continuation rejected", e)
	}
	for _, change := range []func(*domain.Invocation){func(i *domain.Invocation) { i.Connection.ID = "conn-other" }, func(i *domain.Invocation) { i.Connection.ExternalID = "other-account" }, func(i *domain.Invocation) { i.Connection.Config = json.RawMessage(`{"drive_id":"other"}`) }, func(i *domain.Invocation) {
		i.Arguments = json.RawMessage(strings.Replace(string(raw), `"folder"`, `"other-folder"`, 1))
	}, func(i *domain.Invocation) {
		i.Arguments = json.RawMessage(strings.Replace(string(raw), `"top":2`, `"top":3`, 1))
	}} {
		candidate := next
		change(&candidate)
		before := calls
		if _, e = a.Invoke(context.Background(), candidate); e == nil || calls != before {
			t.Fatal("cursor escaped binding")
		}
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(token)
	var c map[string]any
	_ = json.Unmarshal(decoded, &c)
	for _, link := range []string{"https://graph.microsoft.com.evil.invalid/v1.0/me/drives?$skiptoken=x", "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=x", "https://graph.microsoft.com/v1.0/me/drives?$expand=permissions"} {
		c["url"] = link
		b, _ := json.Marshal(c)
		args, _ := json.Marshal(map[string]any{"parent_id": "folder", "top": 2, "page_token": base64.RawURLEncoding.EncodeToString(b)})
		candidate := inv
		candidate.Arguments = args
		before := calls
		if _, e = a.Invoke(context.Background(), candidate); e == nil || calls != before {
			t.Fatal("untrusted continuation accepted")
		}
	}
}
func TestMicrosoftFilesOutputIsWhitelistedAndCrossDriveIsDenied(t *testing.T) {
	a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(*http.Request) (*http.Response, error) {
		return microsoftFilesResponse(200, `{"id":"item!1","name":"document","size":4,"file":{"mimeType":"text/plain","secret":"private"},"@microsoft.graph.downloadUrl":"https://signed.invalid/token","webUrl":"https://private.invalid","permissions":["private"],"parentReference":{"driveId":"drive!bound","path":"private"}}`), nil
	}))
	result, e := a.Invoke(context.Background(), microsoftFilesInvocation(t, a, "items.get", `{"item_id":"item!1"}`))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(result.Data)
	for _, bad := range []string{"signed.invalid", "private", "permissions", "downloadUrl", "webUrl"} {
		if strings.Contains(string(raw), bad) {
			t.Fatal("unsafe metadata output")
		}
	}
	for _, body := range []string{`{"id":"other"}`, `{"id":"item!1","parentReference":{"driveId":"another-drive"}}`, `{"id":"item!1","remoteItem":{"id":"remote"}}`, `{"id":"item!1","size":-1}`, `{"id":"item!1","size":1.5}`, `{"id":"item!1","id":"other"}`, `{"error":{"message":"private-provider-body"}}`} {
		a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(*http.Request) (*http.Response, error) { return microsoftFilesResponse(200, body), nil }))
		if _, e := a.Invoke(context.Background(), microsoftFilesInvocation(t, a, "items.get", `{"item_id":"item!1"}`)); e == nil || strings.Contains(e.Error(), "private-provider-body") {
			t.Fatal("invalid successful response admitted/leaked")
		}
	}
}
func TestMicrosoftFilesDownloadURLAllowlist(t *testing.T) {
	allowed := []string{"https://one.files.1drv.com/path?signed=opaque", "https://one.files.1drv.com:443/path", "https://tenant.sharepoint.com/path?signed=opaque"}
	for _, raw := range allowed {
		if _, ok := microsoftFilesDownloadURL(raw, "tenant.sharepoint.com"); !ok {
			t.Fatal("approved download host denied")
		}
	}
	for _, raw := range []string{"http://one.files.1drv.com/path", "https://files.1drv.com/path", "https://one.files.1drv.com.evil.invalid/path", "https://evilfiles.1drv.com/path", "https://other.sharepoint.com/path", "https://tenant.sharepoint.com.evil.invalid/path", "https://127.0.0.1/path", "https://[::1]/path", "https://user:pass@one.files.1drv.com/path", "https://one.files.1drv.com:444/path", "https://one.files.1drv.com/path#fragment", "https://one.files.1drv.com./path", "https://ONE.files.1drv.com/path", "https://tenant.sharepoint.cn/path"} {
		if _, ok := microsoftFilesDownloadURL(raw, "tenant.sharepoint.com"); ok {
			t.Fatal("untrusted download host admitted", raw)
		}
	}
}
func TestMicrosoftFilesAnonymousTransportHasNoAmbientAuthentication(t *testing.T) {
	graphClient := &http.Client{Jar: nil, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	a, e := NewMicrosoftFilesAdapter("onedrive", graphClient)
	if e != nil {
		t.Fatal(e)
	}
	download, ok := a.downloadDoer.(*http.Client)
	if !ok || download == graphClient || download.Jar != nil || download.CheckRedirect == nil {
		t.Fatal("anonymous client inherited host state")
	}
	transport, ok := download.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig != nil || transport.DialTLSContext != nil || transport.DialContext == nil {
		t.Fatal("anonymous transport inherited proxy/client authentication")
	}
	if e := download.CheckRedirect(nil, nil); !errors.Is(e, http.ErrUseLastResponse) {
		t.Fatal("download redirects enabled")
	}
}
func TestMicrosoftFilesBoundedDownloadUTF8BinaryNoCredentialLeak(t *testing.T) {
	for _, payload := range []string{"hello world", string([]byte{0xff, 0, 1})} {
		calls, downloads := 0, 0
		a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Path != "/v1.0/drives/drive!bound/items/item!1/content" || r.Header.Get("Authorization") == "" {
				t.Fatal("wrong content source")
			}
			r2 := microsoftFilesResponse(302, "")
			r2.Header.Set("Location", "https://one.files.1drv.com/content?private-token=opaque")
			return r2, nil
		}))
		a.downloadDoer = doerFunc(func(r *http.Request) (*http.Response, error) {
			downloads++
			for _, key := range []string{"Authorization", "Cookie", "Referer", "Proxy-Authorization"} {
				if r.Header.Get(key) != "" {
					t.Fatal("credential sent to CDN")
				}
			}
			if len(r.Header) != 1 || r.Header.Get("Accept") != "application/octet-stream" || r.Context().Err() != nil {
				t.Fatal("unexpected download request")
			}
			r2 := microsoftFilesResponse(200, payload)
			r2.Header.Set("Content-Type", "text/plain; charset=utf-8")
			return r2, nil
		})
		result, e := a.Invoke(context.Background(), microsoftFilesInvocation(t, a, "items.content", `{"item_id":"item!1"}`))
		if e != nil {
			t.Fatal(e)
		}
		out := result.Data.(map[string]any)
		encoding := "utf8"
		if payload != "hello world" {
			encoding = "base64"
		}
		if out["encoding"] != encoding || out["bytes"] != len(payload) || calls != 1 || downloads != 1 || result.Attempts != 1 {
			t.Fatal("wrong bounded result")
		}
		raw, _ := json.Marshal(result)
		if strings.Contains(string(raw), "private-token") || strings.Contains(string(raw), "files.1drv.com") {
			t.Fatal("signed URL exposed")
		}
	}
}
func TestMicrosoftFilesDownloadFailuresNeverRetryOrLeak(t *testing.T) {
	cases := []struct {
		name, location string
		status         int
		body           string
		length         int64
	}{
		{"crosssite", "https://other.sharepoint.com/path?SECRET", 200, "text", 0},
		{"suffix", "https://one.files.1drv.com.evil.invalid/path?SECRET", 200, "text", 0},
		{"second_redirect", "https://one.files.1drv.com/path?SECRET", 302, "", 0},
		{"quota", "https://one.files.1drv.com/path?SECRET", 429, "PRIVATE BODY", 0},
		{"oversize_header", "https://one.files.1drv.com/path?SECRET", 200, "", microsoftFilesContentLimit + 1},
		{"oversize_stream", "https://one.files.1drv.com/path?SECRET", 200, strings.Repeat("x", microsoftFilesContentLimit+1), -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls, downloads := 0, 0
			a, _ := NewMicrosoftFilesAdapter("sharepoint", doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				r := microsoftFilesResponse(302, "")
				r.Header.Set("Location", tc.location)
				return r, nil
			}))
			a.downloadDoer = doerFunc(func(*http.Request) (*http.Response, error) {
				downloads++
				r := microsoftFilesResponse(tc.status, tc.body)
				r.ContentLength = tc.length
				r.Header.Set("Location", "https://one.files.1drv.com/second?SECRET")
				return r, nil
			})
			_, e := a.Invoke(context.Background(), microsoftFilesInvocation(t, a, "items.content", `{"item_id":"item!1"}`))
			if e == nil || strings.Contains(e.Error(), "SECRET") || strings.Contains(e.Error(), "PRIVATE") || calls != 1 || downloads > 1 {
				t.Fatal("unsafe failure/retry")
			}
			if tc.name == "crosssite" || tc.name == "suffix" {
				if downloads != 0 {
					t.Fatal("invalid host reached")
				}
			}
		})
	}
}
func TestMicrosoftFilesProviderErrorsAndCancellationOneAttempt(t *testing.T) {
	for _, status := range []int{401, 403, 410, 429, 500} {
		calls := 0
		a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return microsoftFilesResponse(status, `{"error":{"message":"PRIVATE"}}`), nil
		}))
		_, e := a.Invoke(context.Background(), microsoftFilesInvocation(t, a, "items.get", `{"item_id":"item!1"}`))
		var failure *domain.ProviderError
		if !errors.As(e, &failure) || failure.StatusCode != status || calls != 1 || strings.Contains(e.Error(), "PRIVATE") {
			t.Fatal("error contract")
		}
	}
	a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(r *http.Request) (*http.Response, error) {
		if !errors.Is(r.Context().Err(), context.Canceled) {
			t.Fatal("context lost")
		}
		return nil, r.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := a.Invoke(ctx, microsoftFilesInvocation(t, a, "items.get", `{"item_id":"item!1"}`)); e == nil {
		t.Fatal("cancelled call succeeded")
	}
}

func TestMicrosoftFilesCursorTamperAndCredentialRotationFailBeforeIO(t *testing.T) {
	calls := 0
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		next := *r.URL
		q := next.Query()
		q.Set("$skiptoken", "provider-cursor")
		next.RawQuery = q.Encode()
		raw, _ := json.Marshal(map[string]any{"value": []any{}, "@odata.nextLink": next.String()})
		return microsoftFilesResponse(200, string(raw)), nil
	})
	a, _ := NewMicrosoftFilesAdapter("onedrive", doer)
	inv := microsoftFilesInvocation(t, a, "items.list", `{}`)
	result, e := a.Invoke(context.Background(), inv)
	if e != nil {
		t.Fatal(e)
	}
	token := result.Data.(map[string]any)["next_page_token"].(string)
	args, _ := json.Marshal(map[string]string{"page_token": token})
	next := inv
	next.Arguments = args
	restarted, _ := NewMicrosoftFilesAdapter("onedrive", doer)
	if _, e = restarted.Invoke(context.Background(), next); e != nil {
		t.Fatal("cursor failed after restart", e)
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(token)
	var forged map[string]any
	_ = json.Unmarshal(decoded, &forged)
	forged["connection"] = "other-connection"
	raw, _ := json.Marshal(forged)
	bad := next
	bad.Connection.ID = "other-connection"
	bad.Arguments, _ = json.Marshal(map[string]string{"page_token": base64.RawURLEncoding.EncodeToString(raw)})
	before := calls
	if _, e = a.Invoke(context.Background(), bad); e == nil || calls != before {
		t.Fatal("reencoded cross-connection cursor authenticated")
	}
	for _, rotateSecret := range []bool{false, true} {
		bad := next
		err := inv.Credential.WithSecret(time.Now(), func(kind domain.CredentialKind, secret []byte) error {
			value, version := string(secret), "changed-version"
			if rotateSecret {
				value, version = "rotated-token", "fixture"
			}
			var e error
			bad.Credential, e = domain.NewCredential(kind, value, "Authorization", "Bearer", version, nil)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		before := calls
		if _, e = a.Invoke(context.Background(), bad); e == nil || calls != before {
			t.Fatal("changed credential accepted")
		}
	}
	preview := next
	preview.Credential = domain.Credential{}
	if _, e = a.Preview(preview); e != nil {
		t.Fatal("preview required secret", e)
	}
}

func TestMicrosoftFilesRejectsUntrustedProviderContinuationBeforeSigning(t *testing.T) {
	for _, link := range []string{"https://graph.microsoft.com.evil.invalid/v1.0/me/drives?$skiptoken=x", "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=x", "https://graph.microsoft.com/v1.0/me/drives?$expand=permissions", "https://graph.microsoft.com/v1.0/me/drives?$top=101&$skiptoken=x"} {
		calls := 0
		a, _ := NewMicrosoftFilesAdapter("onedrive", doerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			raw, _ := json.Marshal(map[string]any{"value": []any{}, "@odata.nextLink": link})
			return microsoftFilesResponse(200, string(raw)), nil
		}))
		if _, e := a.Invoke(context.Background(), microsoftFilesInvocation(t, a, "drives.list", `{}`)); e == nil || calls != 1 || strings.Contains(e.Error(), link) {
			t.Fatal("unsafe provider continuation accepted or exposed")
		}
	}
}
