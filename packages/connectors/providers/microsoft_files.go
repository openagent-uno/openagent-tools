package providers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const microsoftFilesContentLimit = 2 << 20

var microsoftFilesID = regexp.MustCompile(`^[A-Za-z0-9_+=!./-]+$`)
var microsoftFilesGUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var microsoftFilesSiteHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.sharepoint\.com$`)

// MicrosoftFilesAdapter exposes only delegated, read-only global-cloud Graph
// APIs. Config is host-owned binding metadata selected from authorized discovery,
// never model input: drive_id, site_id and an optional download_host derived from
// the selected drive's Graph webUrl. OAuth binds ExternalID through /me.
// A separate anonymous transport consumes one short-lived /content redirect.
// It has no proxy, cookie jar, client certificate or host authentication hooks.
type MicrosoftFilesAdapter struct {
	manifest           Manifest
	doer, downloadDoer HTTPDoer
}

func NewMicrosoftFilesAdapter(provider string, doer HTTPDoer) (*MicrosoftFilesAdapter, error) {
	if doer == nil {
		return nil, errors.New("Microsoft files transport is required")
	}
	m, err := microsoftFilesManifest(provider)
	if err != nil {
		return nil, err
	}
	if client, ok := doer.(*http.Client); ok {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		doer = &copy
	}
	return &MicrosoftFilesAdapter{manifest: m, doer: doer, downloadDoer: secureHTTPDoer()}, nil
}
func (a *MicrosoftFilesAdapter) Provider() string              { return a.manifest.Provider }
func (a *MicrosoftFilesAdapter) Capability() domain.Capability { return domain.Files }
func (a *MicrosoftFilesAdapter) Operations() []domain.Operation {
	out := make([]domain.Operation, 0, len(a.manifest.Operations))
	for _, op := range a.manifest.Operations {
		out = append(out, domain.Operation{Name: op.Name, Description: op.Description, Provider: a.Provider(), Capability: domain.Files, Mode: domain.OperationTyped, Risk: domain.RiskRead, RequiredScopes: append([]string(nil), op.RequiredScopes...), InputSchema: cloneBytes(op.InputSchema), Retry: domain.RetryPolicy{MaxAttempts: 1}, Preview: domain.ActionPreview{Method: "GET", Path: op.Path, Summary: op.Description}})
	}
	return out
}
func (a *MicrosoftFilesAdapter) OperationScopesGranted(scopes []string, name string) bool {
	if !domain.ValidProviderScopes(scopes) {
		return false
	}
	for _, op := range a.manifest.Operations {
		if op.Name == name {
			accepted := []string{"Files.Read", "Files.Read.All", "Files.ReadWrite", "Files.ReadWrite.All", "Sites.Read.All", "Sites.ReadWrite.All"}
			if a.Provider() == "sharepoint" {
				accepted = []string{"Sites.Read.All", "Sites.ReadWrite.All"}
			}
			for _, scope := range accepted {
				if domain.GrantsScopes(scopes, []string{scope}) {
					return true
				}
			}
			return false
		}
	}
	return false
}
func microsoftFilesManifest(provider string) (Manifest, error) {
	if provider != "onedrive" && provider != "sharepoint" {
		return Manifest{}, domain.ErrUnsupported
	}
	m := Manifest{Provider: provider, Capability: domain.Files, APIVersion: "v1.0", OriginKind: OriginFixed, Origin: microsoftGraphOrigin, CredentialHeader: "Authorization", CredentialScheme: "Bearer", MaxRequestBytes: 16384, MaxResponseBytes: microsoftGraphMaxResponse, TypedOnly: true, ReadOnly: true}
	scope := "Files.Read"
	if provider == "sharepoint" {
		scope = "Sites.Read.All"
	}
	add := func(suffix, path, description string, required ...string) {
		p := map[string]any{}
		if strings.HasSuffix(suffix, ".list") || suffix == "sites.search" {
			p["top"] = integerProperty(1, 100)
			p["page_token"] = microsoftGraphTextSchema(16384)
		}
		if suffix == "items.list" {
			p["parent_id"] = map[string]any{"type": "string", "pattern": microsoftFilesID.String(), "maxLength": 1024}
		}
		if suffix == "items.get" || suffix == "items.content" {
			p["item_id"] = map[string]any{"type": "string", "pattern": microsoftFilesID.String(), "maxLength": 1024}
		}
		if suffix == "sites.search" {
			p["query"] = microsoftGraphTextSchema(256)
		}
		schema, _ := json.Marshal(microsoftGraphObject(p, required...))
		m.Operations = append(m.Operations, OperationManifest{Name: "files." + provider + "." + suffix, Method: "GET", Path: "/v1.0" + path, Description: description, Risk: domain.RiskRead, RequiredScopes: []string{scope}, Required: required, Body: BodyNone, Retry: noRetry, InputSchema: schema})
	}
	if provider == "sharepoint" {
		add("sites.search", "/sites", "Search one bounded page of sites authorized by the delegated Sites.Read.All grant; this scope is broad and Selected scopes are not a fallback.", "query")
		add("sites.get", "/sites/{bound_site_id}", "Read metadata for the host-bound SharePoint site.")
		add("drives.list", "/sites/{bound_site_id}/drives", "List one page of document libraries in the host-bound site.")
	} else {
		add("drives.list", "/me/drives", "List one page of the signed-in account's existing drives. Does not call or provision /me/drive.")
	}
	add("drives.get", "/drives/{bound_drive_id}", "Read metadata for the host-bound drive.")
	add("items.list", "/drives/{bound_drive_id}/items/{parent_id}/children", "List one page of the bound drive's folder children; omitted parent_id means root.")
	add("items.get", "/drives/{bound_drive_id}/items/{item_id}", "Read bounded file/folder metadata; temporary download URLs and remote items are excluded.", "item_id")
	add("items.content", "/drives/{bound_drive_id}/items/{item_id}/content", "Read a complete file up to2MiB as UTF-8 text or base64. One anonymous, restricted Microsoft download hop; no temporary URL is returned.", "item_id")
	return m, nil
}

type microsoftFilesBinding struct {
	Drive        string `json:"drive_id"`
	Site         string `json:"site_id"`
	DownloadHost string `json:"download_host"`
}

func microsoftFilesOpaqueID(s string) bool {
	return len(s) >= 1 && len(s) <= 1024 && microsoftFilesID.MatchString(s) && s != "." && s != ".."
}
func microsoftFilesSite(s string) (string, bool) {
	p := strings.Split(s, ",")
	if len(p) != 3 || !microsoftFilesSiteHost.MatchString(p[0]) || !microsoftFilesGUID.MatchString(p[1]) || !microsoftFilesGUID.MatchString(p[2]) {
		return "", false
	}
	return p[0], true
}
func microsoftFilesConfig(raw json.RawMessage, provider string) (microsoftFilesBinding, error) {
	b := microsoftFilesBinding{}
	if len(raw) == 0 {
		return b, nil
	}
	if len(raw) > 4096 {
		return b, domain.ErrDenied
	}
	v, err := microsoftGraphJSON(raw)
	m, ok := microsoftGraphClosed(v, "drive_id", "site_id", "download_host")
	if err != nil || !ok {
		return b, domain.ErrDenied
	}
	for k, v := range m {
		s, ok := v.(string)
		if !ok || s == "" {
			return b, domain.ErrDenied
		}
		switch k {
		case "drive_id":
			b.Drive = s
		case "site_id":
			b.Site = s
		case "download_host":
			b.DownloadHost = s
		}
	}
	if b.Drive != "" && !microsoftFilesOpaqueID(b.Drive) {
		return b, domain.ErrDenied
	}
	if b.Site != "" {
		host, ok := microsoftFilesSite(b.Site)
		if !ok {
			return b, domain.ErrDenied
		}
		if b.DownloadHost != "" && b.DownloadHost != host {
			return b, domain.ErrDenied
		}
		b.DownloadHost = host
	}
	if b.DownloadHost != "" && !microsoftFilesSiteHost.MatchString(b.DownloadHost) {
		return b, domain.ErrDenied
	}
	if provider == "sharepoint" && b.Drive != "" && b.Site == "" {
		return b, domain.ErrDenied
	}
	return b, nil
}

type microsoftFilesCursor struct {
	CredentialBinding string `json:"credential_binding"`
	Signature         string `json:"signature"`
	Connection        string `json:"connection"`
	Account           string `json:"account"`
	Provider          string `json:"provider"`
	Binding           string `json:"binding"`
	Operation         string `json:"operation"`
	URL               string `json:"url"`
}
type microsoftFilesPlan struct {
	op          OperationManifest
	url         *url.URL
	binding     microsoftFilesBinding
	fingerprint string
	top         int
	suffix      string
}

func microsoftFilesSelect(suffix string) string {
	switch {
	case strings.HasPrefix(suffix, "sites."):
		return "id,name,displayName,description"
	case strings.HasPrefix(suffix, "drives."):
		return "id,name,driveType,webUrl"
	default:
		return "id,name,size,eTag,cTag,createdDateTime,lastModifiedDateTime,file,folder,parentReference"
	}
}
func microsoftFilesContinuation(raw string, expected *url.URL) (*url.URL, error) {
	if len(raw) > 8192 || !microsoftGraphText(raw, 8192, false) {
		return nil, domain.ErrInvalidArguments
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host != "graph.microsoft.com" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.EscapedPath() != expected.EscapedPath() {
		return nil, domain.ErrInvalidArguments
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return nil, domain.ErrInvalidArguments
	}
	base := expected.Query()
	skipped := false
	for k, v := range q {
		if len(v) != 1 || len(v[0]) > 4096 || !microsoftGraphText(v[0], 4096, false) {
			return nil, domain.ErrInvalidArguments
		}
		switch k {
		case "$select", "$top", "search":
			if v[0] != base.Get(k) {
				return nil, domain.ErrInvalidArguments
			}
		case "$skiptoken", "$skipToken":
			if skipped {
				return nil, domain.ErrInvalidArguments
			}
			skipped = true
		case "$skip":
			if skipped {
				return nil, domain.ErrInvalidArguments
			}
			n, e := strconv.ParseUint(v[0], 10, 32)
			if e != nil || n == 0 {
				return nil, domain.ErrInvalidArguments
			}
			skipped = true
		default:
			return nil, domain.ErrInvalidArguments
		}
	}
	for k, v := range base {
		if k == "$skiptoken" || k == "$skipToken" || k == "$skip" {
			continue
		}
		if q.Get(k) != v[0] {
			return nil, domain.ErrInvalidArguments
		}
	}
	if !skipped {
		return nil, domain.ErrInvalidArguments
	}
	return u, nil
}
func (a *MicrosoftFilesAdapter) plan(inv domain.Invocation, authenticate bool) (microsoftFilesPlan, error) {
	p := microsoftFilesPlan{}
	if inv.Connection.Provider != a.Provider() || inv.Credential.IsNone() || inv.Connection.Validate(inv.Principal.WorkspaceID, domain.Files) != nil || inv.Principal.BoundConnectionID != "" && inv.Principal.BoundConnectionID != inv.Connection.ID || !microsoftGraphText(inv.Connection.ExternalID, 1024, false) {
		return p, domain.ErrDenied
	}
	for _, op := range a.manifest.Operations {
		if op.Name == inv.Operation.Name {
			p.op = op
			p.suffix = strings.TrimPrefix(op.Name, "files."+a.Provider()+".")
		}
	}
	if p.op.Name == "" {
		return p, domain.ErrUnsupported
	}
	if inv.ID == "" || len(inv.ID) > 256 || inv.Operation.Provider != a.Provider() || inv.Operation.Capability != domain.Files || inv.Operation.Risk != domain.RiskRead || inv.Operation.Mode != domain.OperationTyped {
		return p, domain.ErrDenied
	}
	if len(inv.Arguments) == 0 || len(inv.Arguments) > 16384 {
		return p, domain.ErrInvalidArguments
	}
	if !a.OperationScopesGranted(inv.Connection.Scopes, p.op.Name) {
		return p, domain.ErrProviderPermission
	}
	binding, err := microsoftFilesConfig(inv.Connection.Config, a.Provider())
	if err != nil {
		return p, err
	}
	p.binding = binding
	v, err := microsoftGraphJSON(inv.Arguments)
	keys := []string{}
	isPage := strings.HasSuffix(p.suffix, ".list") || p.suffix == "sites.search"
	if isPage {
		keys = append(keys, "top", "page_token")
	}
	if p.suffix == "items.list" {
		keys = append(keys, "parent_id")
	}
	if p.suffix == "items.get" || p.suffix == "items.content" {
		keys = append(keys, "item_id")
	}
	if p.suffix == "sites.search" {
		keys = append(keys, "query")
	}
	args, ok := microsoftGraphClosed(v, keys...)
	if err != nil || !ok {
		return p, domain.ErrInvalidArguments
	}
	path := "/v1.0"
	q := url.Values{}
	p.top = 50
	switch p.suffix {
	case "sites.search":
		if !microsoftGraphText(args["query"], 256, false) || strings.TrimSpace(args["query"].(string)) == "" || strings.Contains(args["query"].(string), "*") {
			return p, domain.ErrInvalidArguments
		}
		path += "/sites"
		q.Set("search", args["query"].(string))
	case "sites.get":
		if binding.Site == "" {
			return p, domain.ErrDenied
		}
		path += "/sites/" + url.PathEscape(binding.Site)
	case "drives.list":
		if a.Provider() == "sharepoint" {
			if binding.Site == "" {
				return p, domain.ErrDenied
			}
			path += "/sites/" + url.PathEscape(binding.Site) + "/drives"
		} else {
			path += "/me/drives"
		}
	default:
		if binding.Drive == "" {
			return p, domain.ErrDenied
		}
		path += "/drives/" + url.PathEscape(binding.Drive)
		if p.suffix != "drives.get" {
			id, key := "root", "parent_id"
			if p.suffix != "items.list" {
				key = "item_id"
			}
			raw, exists := args[key]
			if exists {
				s, ok := raw.(string)
				if !ok || !microsoftFilesOpaqueID(s) {
					return p, domain.ErrInvalidArguments
				}
				id = s
			} else if key == "item_id" {
				return p, domain.ErrInvalidArguments
			}
			if id == "root" && !exists && p.suffix == "items.list" {
				path += "/root"
			} else {
				path += "/items/" + url.PathEscape(id)
			}
			if p.suffix == "items.list" {
				path += "/children"
			}
			if p.suffix == "items.content" {
				path += "/content"
			}
		}
	}
	if isPage {
		if top, exists := args["top"]; exists {
			n, ok := top.(json.Number)
			if !ok {
				return p, domain.ErrInvalidArguments
			}
			i, e := strconv.Atoi(n.String())
			if e != nil || i < 1 || i > 100 {
				return p, domain.ErrInvalidArguments
			}
			p.top = i
		}
		q.Set("$top", strconv.Itoa(p.top))
	}
	if p.suffix != "items.content" {
		q.Set("$select", microsoftFilesSelect(p.suffix))
	}
	p.url, err = url.Parse(microsoftGraphOrigin + path)
	if err != nil {
		return p, domain.ErrInvalidArguments
	}
	p.url.RawQuery = q.Encode()
	canonical, _ := json.Marshal(binding)
	fingerprint := sha256.Sum256(canonical)
	p.fingerprint = hex.EncodeToString(fingerprint[:])
	if raw, exists := args["page_token"]; exists {
		s, ok := raw.(string)
		if !ok || len(s) > 16384 {
			return p, domain.ErrInvalidArguments
		}
		b, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil {
			return p, domain.ErrInvalidArguments
		}
		v, e := microsoftGraphJSON(b)
		m, ok := microsoftGraphClosed(v, "connection", "account", "provider", "binding", "operation", "url", "credential_binding", "signature")
		if e != nil || !ok || len(m) != 8 || m["connection"] != inv.Connection.ID || m["account"] != inv.Connection.ExternalID || m["provider"] != a.Provider() || m["binding"] != p.fingerprint || m["operation"] != p.op.Name {
			return p, domain.ErrInvalidArguments
		}
		var cursor microsoftFilesCursor
		if reviewedDecode(b, &cursor) != nil || !reviewedSignatureFormat(cursor.Signature) || !reviewedSignatureFormat(cursor.CredentialBinding) || authenticate && !microsoftFilesVerifyCursor(cursor, inv.Credential) {
			return p, domain.ErrInvalidArguments
		}
		link, ok := m["url"].(string)
		if !ok {
			return p, domain.ErrInvalidArguments
		}
		p.url, e = microsoftFilesContinuation(link, p.url)
		if e != nil {
			return p, e
		}
	}
	return p, nil
}
func (a *MicrosoftFilesAdapter) Preview(inv domain.Invocation) (domain.ActionPreview, error) {
	p, e := a.plan(inv, false)
	if e != nil {
		return domain.ActionPreview{}, e
	}
	return domain.ActionPreview{Method: "GET", Path: p.op.Path, Summary: p.op.Description}, nil
}
func microsoftFilesError(status int, size int, kind string) error {
	if kind == "" {
		kind = "provider_error"
		switch status {
		case 401, 403:
			kind = "provider_permission"
		case 410:
			kind = "resource_gone"
		case 429:
			kind = "rate_limited"
		}
	}
	e := &domain.ProviderError{Kind: kind, StatusCode: status, Attempts: 1, ResponseBytes: int64(size)}
	if status == 401 || status == 403 {
		return errors.Join(domain.ErrProviderPermission, e)
	}
	return e
}
func microsoftFilesSharePointHost(raw string) string {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || !microsoftFilesSiteHost.MatchString(u.Host) {
		return ""
	}
	return u.Host
}
func microsoftFilesString(out, mapIn map[string]any, key string, max int) bool {
	if v, exists := mapIn[key]; exists {
		if !microsoftGraphText(v, max, key == "description") {
			return false
		}
		out[key] = v
	}
	return true
}
func microsoftFilesInteger(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, e := strconv.ParseInt(n.String(), 10, 64)
	return e == nil && i >= 0 && i <= 1<<53
}
func microsoftFilesObject(raw any, suffix string, binding microsoftFilesBinding) (map[string]any, bool) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	id, ok := m["id"].(string)
	if !ok {
		return nil, false
	}
	out := map[string]any{"id": id}
	if strings.HasPrefix(suffix, "sites.") {
		host, valid := microsoftFilesSite(id)
		if !valid || suffix == "sites.get" && id != binding.Site {
			return nil, false
		}
		out["sharepoint_host"] = host
		for _, k := range []string{"name", "displayName", "description"} {
			if !microsoftFilesString(out, m, k, 4096) {
				return nil, false
			}
		}
		return out, true
	}
	if !microsoftFilesOpaqueID(id) {
		return nil, false
	}
	if !microsoftFilesString(out, m, "name", 1024) {
		return nil, false
	}
	if strings.HasPrefix(suffix, "drives.") {
		if suffix == "drives.get" && id != binding.Drive {
			return nil, false
		}
		if !microsoftFilesString(out, m, "driveType", 64) {
			return nil, false
		}
		if v, exists := m["webUrl"]; exists {
			s, ok := v.(string)
			if !ok || len(s) > 4096 {
				return nil, false
			}
			host := microsoftFilesSharePointHost(s)
			if binding.DownloadHost != "" && host != binding.DownloadHost {
				return nil, false
			}
			if host != "" {
				out["sharepoint_host"] = host
			}
		}
		return out, true
	}
	if m["remoteItem"] != nil {
		return nil, false
	}
	for _, k := range []string{"createdDateTime", "lastModifiedDateTime"} {
		if v, exists := m[k]; exists {
			s, ok := v.(string)
			if !ok || len(s) > 64 {
				return nil, false
			}
			if _, e := time.Parse(time.RFC3339Nano, s); e != nil {
				return nil, false
			}
			out[k] = s
		}
	}
	for _, k := range []string{"eTag", "cTag"} {
		if v, exists := m[k]; exists {
			s, ok := v.(string)
			if !ok || !microsoftGraphETag.MatchString(s) {
				return nil, false
			}
			out[k] = s
		}
	}
	if v, exists := m["size"]; exists {
		if !microsoftFilesInteger(v) {
			return nil, false
		}
		out["size"] = v
	}
	if v, exists := m["parentReference"]; exists {
		r, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if d, exists := r["driveId"]; exists {
			if d != binding.Drive {
				return nil, false
			}
			out["parentReference"] = map[string]any{"driveId": d}
		}
	}
	if v, exists := m["file"]; exists {
		f, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		clean := map[string]any{}
		if !microsoftFilesString(clean, f, "mimeType", 256) {
			return nil, false
		}
		out["file"] = clean
	}
	if v, exists := m["folder"]; exists {
		f, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		clean := map[string]any{}
		if n, exists := f["childCount"]; exists {
			if !microsoftFilesInteger(n) {
				return nil, false
			}
			clean["childCount"] = n
		}
		out["folder"] = clean
	}
	return out, true
}
func microsoftFilesDownloadURL(raw, boundHost string) (*url.URL, bool) {
	if len(raw) == 0 || len(raw) > 8192 || !microsoftGraphText(raw, 8192, false) {
		return nil, false
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" || len(u.Hostname()) > 253 || (u.Host != u.Hostname() && u.Host != u.Hostname()+":443") || net.ParseIP(u.Hostname()) != nil || u.Hostname() != strings.ToLower(u.Hostname()) || strings.HasSuffix(u.Hostname(), ".") {
		return nil, false
	}
	host := u.Hostname()
	allowed := strings.HasSuffix(host, ".files.1drv.com") && len(host) > len(".files.1drv.com")
	if boundHost != "" && host == boundHost && microsoftFilesSiteHost.MatchString(boundHost) {
		allowed = true
	}
	if !allowed {
		return nil, false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return nil, false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return nil, false
			}
		}
	}
	return u, true
}
func (a *MicrosoftFilesAdapter) content(ctx context.Context, inv domain.Invocation, p microsoftFilesPlan, res *http.Response) (domain.Result, error) {
	status := res.StatusCode
	if status != http.StatusFound {
		if res.Body != nil {
			_ = res.Body.Close()
		}
		return domain.Result{}, microsoftFilesError(status, 0, "")
	}
	locations := res.Header.Values("Location")
	if len(locations) != 1 {
		if res.Body != nil {
			_ = res.Body.Close()
		}
		return domain.Result{}, microsoftFilesError(status, 0, "invalid_response")
	}
	location := locations[0]
	if res.Body != nil {
		_ = res.Body.Close()
	}
	u, ok := microsoftFilesDownloadURL(location, p.binding.DownloadHost)
	if !ok {
		return domain.Result{}, microsoftFilesError(status, 0, "invalid_response")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return domain.Result{}, microsoftFilesError(0, 0, "invalid_response")
	}
	req.Header.Set("Accept", "application/octet-stream")
	downloaded, e := a.downloadDoer.Do(req)
	if e != nil {
		if downloaded != nil && downloaded.Body != nil {
			_ = downloaded.Body.Close()
		}
		return domain.Result{}, microsoftFilesError(0, 0, "network_error")
	}
	if downloaded == nil || downloaded.Body == nil {
		return domain.Result{}, microsoftFilesError(0, 0, "invalid_response")
	}
	defer downloaded.Body.Close()
	if downloaded.StatusCode != http.StatusOK {
		return domain.Result{}, microsoftFilesError(downloaded.StatusCode, 0, "")
	}
	if downloaded.ContentLength > microsoftFilesContentLimit || downloaded.Header.Get("Content-Range") != "" {
		return domain.Result{}, microsoftFilesError(downloaded.StatusCode, 0, "invalid_response")
	}
	data, large, e := readBounded(downloaded.Body, microsoftFilesContentLimit)
	if e != nil || large {
		return domain.Result{}, microsoftFilesError(downloaded.StatusCode, len(data), "invalid_response")
	}
	// Opaque token bytes never appear in returned content, even for a malicious
	// upstream that reflects the Graph credential into an anonymous download.
	clean := inv.Credential.Redact(data)
	if !bytes.Equal(clean, data) || bytes.Contains(data, []byte(location)) {
		return domain.Result{}, microsoftFilesError(200, len(data), "invalid_response")
	}
	encoding := "base64"
	payload := base64.StdEncoding.EncodeToString(data)
	if utf8.Valid(data) && !strings.ContainsRune(string(data), 0) {
		encoding = "utf8"
		payload = string(data)
	}
	media := "application/octet-stream"
	if value, _, e := mime.ParseMediaType(downloaded.Header.Get("Content-Type")); e == nil && len(value) <= 256 {
		media = value
	}
	digest := sha256.Sum256(data)
	return domain.Result{Data: map[string]any{"encoding": encoding, "content": payload, "content_type": media, "bytes": len(data), "sha256": hex.EncodeToString(digest[:])}, ProviderStatus: 200, Attempts: 1, ResponseBytes: int64(len(data)), Metadata: map[string]string{"provider": a.Provider(), "operation": p.op.Name, "download_hops": "1"}}, nil
}
func (a *MicrosoftFilesAdapter) Invoke(ctx context.Context, inv domain.Invocation) (domain.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p, e := a.plan(inv, true)
	if e != nil {
		return domain.Result{}, e
	}
	req, e := http.NewRequestWithContext(ctx, "GET", p.url.String(), nil)
	if e != nil {
		return domain.Result{}, domain.ErrInvalidArguments
	}
	req.Header.Set("Accept", "application/json")
	if inv.Credential.Apply(req.Header, "Authorization", "Bearer", time.Now()) != nil {
		return domain.Result{}, domain.ErrProviderPermission
	}
	res, e := a.doer.Do(req)
	if e != nil {
		if res != nil && res.Body != nil {
			_ = res.Body.Close()
		}
		return domain.Result{}, microsoftFilesError(0, 0, "network_error")
	}
	if res == nil || res.Body == nil {
		return domain.Result{}, microsoftFilesError(0, 0, "invalid_response")
	}
	if p.suffix == "items.content" {
		return a.content(ctx, inv, p, res)
	}
	data, large, e := readBounded(res.Body, microsoftGraphMaxResponse)
	_ = res.Body.Close()
	if e != nil || large {
		return domain.Result{}, microsoftFilesError(res.StatusCode, len(data), "invalid_response")
	}
	if res.StatusCode != 200 {
		return domain.Result{}, microsoftFilesError(res.StatusCode, len(data), "")
	}
	data = inv.Credential.Redact(data)
	v, e := microsoftGraphJSONBudget(data, 100000, 32)
	m, ok := v.(map[string]any)
	_, hasError := m["error"]
	if e != nil || !ok || hasError {
		return domain.Result{}, microsoftFilesError(200, len(data), "invalid_response")
	}
	out := map[string]any{}
	page := strings.HasSuffix(p.suffix, ".list") || p.suffix == "sites.search"
	if page {
		items, ok := m["value"].([]any)
		if !ok || len(items) > p.top {
			return domain.Result{}, microsoftFilesError(200, len(data), "invalid_response")
		}
		clean := make([]any, 0, len(items))
		for _, item := range items {
			row, ok := microsoftFilesObject(item, p.suffix, p.binding)
			if !ok {
				return domain.Result{}, microsoftFilesError(200, len(data), "invalid_response")
			}
			clean = append(clean, row)
		}
		out["value"] = clean
	} else {
		out, ok = microsoftFilesObject(m, p.suffix, p.binding)
		if !ok {
			return domain.Result{}, microsoftFilesError(200, len(data), "invalid_response")
		}
		if strings.HasPrefix(p.suffix, "items.") {
			args, _ := microsoftGraphJSON(inv.Arguments)
			if args.(map[string]any)["item_id"] != out["id"] {
				return domain.Result{}, microsoftFilesError(200, len(data), "invalid_response")
			}
		}
	}
	if raw, exists := m["@odata.nextLink"]; exists {
		link, ok := raw.(string)
		if !page || !ok {
			return domain.Result{}, microsoftFilesError(200, len(data), "invalid_response")
		}
		if _, e := microsoftFilesContinuation(link, p.url); e != nil {
			return domain.Result{}, microsoftFilesError(200, len(data), "invalid_response")
		}
		c := microsoftFilesCursor{Connection: inv.Connection.ID, Account: inv.Connection.ExternalID, Provider: a.Provider(), Binding: p.fingerprint, Operation: p.op.Name, URL: link, CredentialBinding: microsoftFilesCredentialBinding(inv.Credential)}
		signature, e := microsoftFilesSignCursor(c, inv.Credential)
		if e != nil {
			return domain.Result{}, domain.ErrDenied
		}
		c.Signature = signature
		cursor, _ := json.Marshal(c)
		out["next_page_token"] = base64.RawURLEncoding.EncodeToString(cursor)
	}
	return domain.Result{Data: out, ProviderStatus: 200, Attempts: 1, ResponseBytes: int64(len(data)), Metadata: map[string]string{"provider": a.Provider(), "operation": p.op.Name, "api_version": "v1.0"}}, nil
}

// Ensure the anonymous transport remains an ordinary HTTP client without any
// ambient cookie/proxy/client-auth configuration. Tests inspect these fields.
var _ domain.Adapter = (*MicrosoftFilesAdapter)(nil)
var _ domain.OperationScopePolicy = (*MicrosoftFilesAdapter)(nil)

func microsoftFilesCredentialBinding(credential domain.Credential) string {
	metadata, _ := credential.MarshalJSON()
	sum := sha256.Sum256(metadata)
	return hex.EncodeToString(sum[:])
}
func microsoftFilesSignCursor(cursor microsoftFilesCursor, credential domain.Credential) (string, error) {
	cursor.Signature = ""
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", domain.ErrDenied
	}
	var signature string
	err = credential.WithSecret(time.Now().UTC(), func(_ domain.CredentialKind, secret []byte) error {
		keyMAC := hmac.New(sha256.New, secret)
		_, _ = keyMAC.Write([]byte("OpenAgent-Microsoft-Files-Cursor-v1\x00"))
		key := keyMAC.Sum(nil)
		defer clear(key)
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(payload)
		signature = hex.EncodeToString(mac.Sum(nil))
		return nil
	})
	return signature, err
}
func microsoftFilesVerifyCursor(cursor microsoftFilesCursor, credential domain.Credential) bool {
	if cursor.CredentialBinding != microsoftFilesCredentialBinding(credential) {
		return false
	}
	provided, err := hex.DecodeString(cursor.Signature)
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	expected, err := microsoftFilesSignCursor(cursor, credential)
	if err != nil {
		return false
	}
	decoded, _ := hex.DecodeString(expected)
	return hmac.Equal(provided, decoded)
}
