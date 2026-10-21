//go:build darwin || linux

package slackchannel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

// The network boundary is real TLS HTTP, installation authentication uses the
// public auth server and real Ed25519 signatures. Only Slack itself is fake.
type fixtureAuthorizer struct {
	broker     *auth.Server
	mu         sync.Mutex
	denied     map[string]bool
	afterFence func()
	onFence    func()
}

func (a *fixtureAuthorizer) revoked(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.denied[id]
}
func (a *fixtureAuthorizer) revoke(id string) { a.mu.Lock(); defer a.mu.Unlock(); a.denied[id] = true }
func (a *fixtureAuthorizer) AuthenticateInstallation(r *http.Request, b []byte) (auth.Installation, error) {
	i, err := a.broker.AuthenticateInstallation(r, b)
	if err != nil || a.revoked(i.ID) {
		return auth.Installation{}, auth.ErrDenied
	}
	return i, nil
}
func (a *fixtureAuthorizer) WithCentralInstallation(i auth.Installation, fn func() error) error {
	if a.revoked(i.ID) {
		return auth.ErrDenied
	}
	err := a.broker.WithCentralInstallation(i, fn)
	a.mu.Lock()
	hook := a.afterFence
	observe := a.onFence
	a.afterFence = nil
	a.mu.Unlock()
	if err == nil && hook != nil {
		hook()
	}
	if err == nil && observe != nil {
		observe()
	}
	return err
}

type fixtureProvider struct {
	mu                   sync.Mutex
	team                 string
	member               bool
	members              []string
	membersIncomplete    bool
	exchanges, refreshes int
	calls                map[string]int
	callError            bool
	onExchange           func()
	onRefresh            func()
	onCall               func(string)
}

func (p *fixtureProvider) AuthorizationURL(state string) (string, error) {
	return "https://slack.com/oauth/v2/authorize?" + url.Values{"state": {state}}.Encode(), nil
}
func (p *fixtureProvider) Exchange(_ context.Context, code string, now time.Time) (BotGrant, error) {
	p.mu.Lock()
	p.exchanges++
	hook := p.onExchange
	team := p.team
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	if code != "fixture-code" {
		return BotGrant{}, errors.New("synthetic-exchange-rejected")
	}
	return BotGrant{AppID: "ATEST", TeamID: team, BotUserID: "UBOT", AuthorizedUserID: "UOWNER",
		AccessToken: "xoxe.xoxb-synthetic-access", RefreshToken: "xoxe-synthetic-refresh", Scopes: append([]string{}, BotScopes...),
		Status: "active", AuthorizedAt: now, ExpiresAt: now.Add(12 * time.Hour)}, nil
}
func (p *fixtureProvider) Refresh(_ context.Context, old BotGrant, now time.Time) (BotGrant, error) {
	p.mu.Lock()
	p.refreshes++
	hook := p.onRefresh
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	old.AccessToken = "xoxe.xoxb-synthetic-rotated-access"
	old.RefreshToken = "xoxe-synthetic-rotated-refresh"
	old.ExpiresAt = now.Add(12 * time.Hour)
	return old, nil
}
func (p *fixtureProvider) Call(_ context.Context, grant BotGrant, method string, args map[string]any) (json.RawMessage, error) {
	p.mu.Lock()
	p.calls[method]++
	hook := p.onCall
	fail := p.callError
	member := p.member
	var members []string
	if p.members != nil {
		members = append([]string{}, p.members...)
	}
	incomplete := p.membersIncomplete
	p.mu.Unlock()
	if hook != nil {
		hook(method)
	}
	if fail && method == "chat.postMessage" {
		return nil, errors.New("synthetic-provider-failure-with-secret-body")
	}
	if grant.AccessToken == "" {
		return nil, errors.New("missing-fixture-grant")
	}
	var value any
	switch method {
	case "conversations.info":
		value = map[string]any{"ok": true, "channel": map[string]any{"id": args["channel"], "is_member": member}}
	case "auth.test":
		value = map[string]any{"ok": true, "team_id": "TONE", "user_id": "UBOT", "bot_id": "BONE"}
	case "conversations.members":
		if members == nil {
			members = []string{"UACTOR", "UOWNER", "UBOT"}
		}
		cursor := ""
		if incomplete {
			cursor = "repeated-incomplete-cursor"
		}
		value = map[string]any{"ok": true, "members": members, "has_more": incomplete, "response_metadata": map[string]any{"next_cursor": cursor}}
	case "conversations.history", "conversations.replies":
		value = map[string]any{"ok": true, "messages": []any{}}
	case "chat.postMessage":
		value = map[string]any{"ok": true, "channel": args["channel"], "ts": "200.000001"}
	default:
		return nil, errors.New("unsupported-fixture-method")
	}
	data, _ := json.Marshal(value)
	return data, nil
}
func (p *fixtureProvider) count(method string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[method]
}

type channelFixture struct {
	t            *testing.T
	http         *httptest.Server
	client       *http.Client
	owner, other auth.Identity
	authorizer   *fixtureAuthorizer
	provider     *fixtureProvider
	server       *Server
	store        *Store
	path         string
	clock        time.Time
}

func newChannelFixture(t *testing.T) *channelFixture {
	t.Helper()
	mux := http.NewServeMux()
	endpoint := httptest.NewUnstartedServer(mux)
	origin := "https://" + endpoint.Listener.Addr().String()
	owner, err := auth.NewIdentity("fixture-host", "Fixture recipient")
	if err != nil {
		t.Fatal(err)
	}
	other, err := auth.NewIdentity("other-host", "Other recipient")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := auth.NewStore(filepath.Join(t.TempDir(), "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewServer(metadata, oauth.Engine{}, nil, origin, bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &fixtureAuthorizer{broker: broker, denied: map[string]bool{}}
	path := filepath.Join(t.TempDir(), "channel.vault")
	store := openTestStore(t, path)
	provider := &fixtureProvider{team: "TONE", member: true, calls: map[string]int{}}
	service, err := NewServer(Config{Origin: origin, AppID: "ATEST", ClientID: "fixture-client", AllowedInstallations: []string{owner.ID(), other.ID()}}, authorizer, store, provider, []byte("synthetic-signing-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	f := &channelFixture{t: t, http: endpoint, owner: owner, other: other, authorizer: authorizer,
		provider: provider, server: service, store: store, path: path, clock: time.Now().UTC().Truncate(time.Second)}
	service.now = func() time.Time { return f.clock }
	mux.Handle(Prefix+"/", service)
	mux.Handle("/", broker)
	endpoint.StartTLS()
	t.Cleanup(endpoint.Close)
	f.client = endpoint.Client()
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f.client.Jar, _ = cookiejar.New(nil)
	for _, identity := range []auth.Identity{owner, other} {
		client := auth.Client{Origin: origin, Identity: identity, HTTP: f.client}
		if err := client.Register(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *channelFixture) publicClient(identity auth.Identity) *Client {
	return &Client{Origin: f.http.URL, Identity: identity, HTTP: f.client}
}
func (f *channelFixture) request(method, path string, data []byte, identity *auth.Identity, session string, headers map[string]string) (int, []byte, http.Header) {
	f.t.Helper()
	req, err := http.NewRequest(method, f.http.URL+path, bytes.NewReader(data))
	if err != nil {
		f.t.Fatal(err)
	}
	if identity != nil {
		identity.Sign(req, data)
	}
	if session != "" {
		req.Header.Set("Authorization", "Bearer "+session)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		f.t.Fatal(err)
	}
	for _, secret := range []string{"xoxe.xoxb-synthetic", "xoxe-synthetic-refresh", "synthetic-provider-failure-with-secret-body"} {
		if bytes.Contains(body, []byte(secret)) {
			f.t.Fatal("provider credential or raw diagnostic crossed HTTP boundary")
		}
	}
	return response.StatusCode, body, response.Header
}
func jsonBody(value any) []byte { data, _ := json.Marshal(value); return data }
func (f *channelFixture) start(channel string) Binding {
	f.t.Helper()
	binding, err := f.publicClient(f.owner).Start(context.Background(), StartRequest{
		Recipient:  Recipient{WorkspaceID: "workspace", SubjectID: "subject", AgentID: "agent"},
		AgentLabel: "Fixture agent", TeamID: "TONE", ChannelID: channel})
	if err != nil {
		f.t.Fatal(err)
	}
	return binding
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
var linkPattern = regexp.MustCompile(`href="([^"]+)"`)

func (f *channelFixture) consent(binding Binding) string {
	f.t.Helper()
	u, err := url.Parse(binding.AuthorizationURL)
	if err != nil {
		f.t.Fatal(err)
	}
	status, page, _ := f.request("GET", u.RequestURI(), nil, nil, "", nil)
	match := csrfPattern.FindSubmatch(page)
	if status != 200 || len(match) != 2 {
		f.t.Fatal("missing real consent form")
	}
	form := url.Values{"csrf": {html.UnescapeString(string(match[1]))}}
	status, page, header := f.request("POST", u.RequestURI(), []byte(form.Encode()), nil, "", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Origin": f.http.URL, "Referer": binding.AuthorizationURL})
	target := header.Get("Location")
	if status == 200 {
		match = linkPattern.FindSubmatch(page)
		if len(match) == 2 {
			target = html.UnescapeString(string(match[1]))
		}
	}
	provider, err := url.Parse(target)
	if (status != 200 && status != 303) || err != nil || provider.Scheme != "https" || provider.Host != "slack.com" || provider.Query().Get("state") == "" {
		f.t.Fatal("missing provider navigation after consent")
	}
	return provider.Query().Get("state")
}
func (f *channelFixture) callback(state string) int {
	status, _, _ := f.request("GET", Prefix+"/oauth/callback?"+url.Values{"state": {state}, "code": {"fixture-code"}}.Encode(), nil, nil, "", nil)
	return status
}
func (f *channelFixture) active() (Binding, Session) {
	f.t.Helper()
	binding := f.start("CONE")
	if f.callback(f.consent(binding)) != 200 {
		f.t.Fatal("consent callback failed")
	}
	client := f.publicClient(f.owner)
	active, err := client.Activate(context.Background(), binding.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	session, err := client.Session(context.Background(), binding.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return active, session
}
func (f *channelFixture) event(eventID string, event map[string]any) map[string]any {
	return map[string]any{"type": "event_callback", "api_app_id": "ATEST", "team_id": "TONE", "event_id": eventID, "event_time": f.clock.Unix(), "event": event}
}
func (f *channelFixture) postEvent(value map[string]any, stamp time.Time, valid bool) int {
	b := jsonBody(value)
	timestamp := strconv.FormatInt(stamp.Unix(), 10)
	mac := hmac.New(sha256.New, f.server.signing)
	_, _ = mac.Write([]byte("v0:" + timestamp + ":"))
	_, _ = mac.Write(b)
	signature := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !valid {
		signature = "v0=" + strings.Repeat("0", 64)
	}
	status, _, _ := f.request("POST", Prefix+"/events", b, nil, "", map[string]string{"X-Slack-Request-Timestamp": timestamp, "X-Slack-Signature": signature})
	return status
}
func (f *channelFixture) inbox(binding Binding, session Session) (int, []Delivery) {
	status, b, _ := f.request("GET", Prefix+"/bindings/"+binding.ID+"/inbox", nil, nil, session.Token, nil)
	var reply struct {
		Deliveries []Delivery `json:"deliveries"`
	}
	_ = json.Unmarshal(b, &reply)
	return status, reply.Deliveries
}
func (f *channelFixture) mention(binding Binding, session Session, eventID string, threaded bool) Delivery {
	f.t.Helper()
	event := map[string]any{"type": "app_mention", "user": "UACTOR", "channel": binding.ChannelID, "ts": "100.000002", "text": "<@UBOT> synthetic-private-message"}
	if threaded {
		event["thread_ts"] = "100.000001"
	}
	if f.postEvent(f.event(eventID, event), f.clock, true) != 200 {
		f.t.Fatal("signed event rejected")
	}
	status, deliveries := f.inbox(binding, session)
	if status != 200 || len(deliveries) != 1 {
		f.t.Fatal("verified event missing from bound inbox")
	}
	return deliveries[0]
}
func (f *channelFixture) api(binding Binding, session Session, delivery Delivery, method string, args map[string]any, opID string) (int, []byte) {
	status, data, _ := f.request("POST", Prefix+"/bindings/"+binding.ID+"/api", jsonBody(apiRequest{DeliveryID: delivery.ID, Method: method, Arguments: args, OperationID: opID}), nil, session.Token, nil)
	return status, data
}

func TestChannelSignedHostConsentActivationEventAPIAndDurableACK(t *testing.T) {
	f := newChannelFixture(t)
	binding := f.start("CONE")
	state := f.consent(binding)
	if f.callback(state) != 200 || f.callback(state) != 410 || f.provider.exchanges != 1 {
		t.Fatal("callback was not consumed exactly once")
	}
	f.provider.member = false
	if _, err := f.publicClient(f.owner).Activate(context.Background(), binding.ID); err == nil {
		t.Fatal("activation admitted bot absent from channel")
	}
	f.provider.member = true
	binding, err := f.publicClient(f.owner).Activate(context.Background(), binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	session, err := f.publicClient(f.owner).Session(context.Background(), binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	delivery := f.mention(binding, session, "EVENTONE", true)
	status, _ := f.api(binding, session, delivery, "conversations.members", map[string]any{"channel": "CONE", "limit": 100}, "")
	if status != 200 {
		t.Fatal("bound membership read failed")
	}
	ack := jsonBody(map[string]any{"delivery_id": delivery.ID, "body_sha256": delivery.BodySHA256, "outcome": "accepted"})
	status, _, _ = f.request("POST", Prefix+"/bindings/"+binding.ID+"/ack", ack, nil, session.Token, nil)
	if status != 200 {
		t.Fatal("durable ACK failed")
	}
	status, deliveries := f.inbox(binding, session)
	if status != 200 || len(deliveries) != 0 {
		t.Fatal("ACK did not remove pending delivery")
	}
	data, _ := os.ReadFile(f.path)
	if bytes.Contains(data, []byte("synthetic-private-message")) || bytes.Contains(data, []byte("xoxe")) || bytes.Contains(data, []byte(session.Token)) {
		t.Fatal("encrypted local custody required")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, f.path)
	f.server.store = reopened
	view, err := reopened.View()
	if err != nil || view.Deliveries[delivery.ID].Status != "acknowledged" {
		t.Fatal("ACK was not durable across restart")
	}
	if err = f.publicClient(f.owner).Disconnect(context.Background(), binding.ID); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.inbox(binding, session); status != 403 {
		t.Fatal("disconnected session remained usable")
	}
}

func TestChannelConsentRejectsCSRFAndReplayWithoutExternalPOSTRedirect(t *testing.T) {
	f := newChannelFixture(t)
	binding := f.start("CONE")
	u, _ := url.Parse(binding.AuthorizationURL)
	status, page, _ := f.request("GET", u.RequestURI(), nil, nil, "", nil)
	match := csrfPattern.FindSubmatch(page)
	if status != 200 || len(match) != 2 {
		t.Fatal("missing consent form")
	}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": f.http.URL, "Referer": binding.AuthorizationURL}
	status, _, _ = f.request("POST", u.RequestURI(), []byte("csrf=wrong"), nil, "", headers)
	if status != 403 {
		t.Fatal("wrong CSRF accepted")
	}
	form := []byte(url.Values{"csrf": {html.UnescapeString(string(match[1]))}}.Encode())
	status, navigation, header := f.request("POST", u.RequestURI(), form, nil, "", headers)
	if status != 200 || header.Get("Location") != "" || !strings.Contains(header.Get("Content-Security-Policy"), "form-action 'self'") || header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("provider navigation must preserve CSP without a cross-origin POST redirect")
	}
	link := linkPattern.FindSubmatch(navigation)
	if len(link) != 2 {
		t.Fatal("missing escaped provider link")
	}
	target, err := url.Parse(html.UnescapeString(string(link[1])))
	if err != nil || target.Scheme != "https" || target.Host != "slack.com" || target.Query().Get("state") == "" {
		t.Fatal("unexpected provider navigation target")
	}
	status, _, _ = f.request("POST", u.RequestURI(), form, nil, "", headers)
	if status != 410 || f.provider.exchanges != 0 {
		t.Fatal("consent POST replay was accepted or exchanged a provider code")
	}
}

func TestChannelWrongHostRecipientSessionAndProviderTeamAreDenied(t *testing.T) {
	f := newChannelFixture(t)
	binding, session := f.active()
	if _, err := f.publicClient(f.other).Status(context.Background(), binding.ID); err == nil {
		t.Fatal("other host read binding")
	}
	if _, err := f.publicClient(f.other).Session(context.Background(), binding.ID); err == nil {
		t.Fatal("other host acquired session")
	}
	delivery := f.mention(binding, session, "EVENTONE", false)
	b := jsonBody(map[string]any{"delivery_id": delivery.ID, "method": "auth.test", "arguments": map[string]any{}, "recipient": Recipient{WorkspaceID: "other", SubjectID: "owner", AgentID: "agent"}})
	status, _, _ := f.request("POST", Prefix+"/bindings/"+binding.ID+"/api", b, nil, session.Token, nil)
	if status != 400 {
		t.Fatal("caller supplied recipient override accepted")
	}
	second := f.start("CTWO")
	f.provider.team = "TOTHER"
	if f.callback(f.consent(second)) != 400 {
		t.Fatal("OAuth grant changed requested workspace")
	}
	if status, _, _ := f.request("GET", Prefix+"/bindings/"+second.ID+"/inbox", nil, nil, session.Token, nil); status != 403 {
		t.Fatal("session crossed binding")
	}
	f.clock = f.clock.Add(8*time.Hour + time.Second)
	if status, _ := f.inbox(binding, session); status != 403 {
		t.Fatal("expired session admitted")
	}
}

func TestChannelCallbackCannotReviveRevokedHostOrUninstalledWorkspace(t *testing.T) {
	for _, mode := range []string{"host", "uninstall"} {
		t.Run(mode, func(t *testing.T) {
			f := newChannelFixture(t)
			binding := f.start("CONE")
			state := f.consent(binding)
			f.provider.onExchange = func() {
				if mode == "host" {
					f.authorizer.revoke(f.owner.ID())
				} else if f.postEvent(f.event("UNINSTALL", map[string]any{"type": "app_uninstalled"}), f.clock, true) != 200 {
					t.Error("lifecycle fixture rejected")
				}
			}
			if f.callback(state) != 403 {
				t.Fatal("delayed callback revived revoked destination")
			}
			view, _ := f.store.View()
			if len(view.Grants) != 0 || view.Bindings[binding.ID].Public.Status == "active" {
				t.Fatal("revoked callback persisted bot access")
			}
		})
	}
}

func TestChannelIngressSignatureAppTeamSubtypeAndConflict(t *testing.T) {
	f := newChannelFixture(t)
	binding, session := f.active()
	event := map[string]any{"type": "app_mention", "user": "UACTOR", "channel": "CONE", "ts": "100.000002", "text": "synthetic"}
	for _, mode := range []string{"hmac", "stale", "app", "team", "subtype", "bot"} {
		payload := f.event("EVENT"+strings.ToUpper(mode), event)
		copied := map[string]any{}
		for k, v := range event {
			copied[k] = v
		}
		payload["event"] = copied
		stamp, valid, expected := f.clock, true, 200
		switch mode {
		case "hmac":
			valid = false
			expected = 403
		case "stale":
			stamp = stamp.Add(-6 * time.Minute)
			expected = 403
		case "app":
			payload["api_app_id"] = "AOTHER"
			expected = 403
		case "team":
			payload["team_id"] = "TOTHER"
		case "subtype":
			copied["subtype"] = "message_changed"
		case "bot":
			copied["bot_id"] = "BOTHER"
		}
		if got := f.postEvent(payload, stamp, valid); got != expected {
			t.Fatalf("ingress %s status %d", mode, got)
		}
	}
	if status, deliveries := f.inbox(binding, session); status != 200 || len(deliveries) != 0 {
		t.Fatal("untrusted or unbound event entered inbox")
	}
	payload := f.event("EVENTGOOD", event)
	if f.postEvent(payload, f.clock, true) != 200 || f.postEvent(payload, f.clock, true) != 200 {
		t.Fatal("exact event replay was not idempotent")
	}
	changed := map[string]any{}
	for k, v := range event {
		changed[k] = v
	}
	changed["text"] = "different body"
	payload["event"] = changed
	if f.postEvent(payload, f.clock, true) != 503 {
		t.Fatal("event ID with different body was accepted")
	}
	if _, deliveries := f.inbox(binding, session); len(deliveries) != 1 {
		t.Fatal("duplicate event created multiple deliveries")
	}
}

func TestChannelBoundAPIRejectsCrossChannelThreadAndUnknownMethodsBeforeIO(t *testing.T) {
	f := newChannelFixture(t)
	binding, session := f.active()
	delivery := f.mention(binding, session, "EVENTONE", true)
	cases := []apiRequest{
		{Method: "conversations.members", Arguments: map[string]any{"channel": "COTHER"}},
		{Method: "conversations.replies", Arguments: map[string]any{"channel": "CONE", "ts": "999.0", "latest": "100.000002", "inclusive": false}},
		{Method: "conversations.history", Arguments: map[string]any{"channel": "CONE", "latest": "999.0", "inclusive": false}},
		{Method: "chat.postMessage", Arguments: map[string]any{"channel": "CONE", "text": "reply", "thread_ts": "999.0"}, OperationID: "op"},
		{Method: "files.upload", Arguments: map[string]any{"channel": "CONE"}, OperationID: "op"},
		{Method: "auth.test", Arguments: map[string]any{"token": "forbidden"}},
	}
	before := f.provider.count("conversations.info")
	beforeMembers := f.provider.count("conversations.members")
	for _, input := range cases {
		input.DeliveryID = delivery.ID
		status, _, _ := f.request("POST", Prefix+"/bindings/"+binding.ID+"/api", jsonBody(input), nil, session.Token, nil)
		if status != 400 {
			t.Fatalf("unbound method %s accepted", input.Method)
		}
	}
	if f.provider.count("chat.postMessage") != 0 || f.provider.count("conversations.members") != beforeMembers || f.provider.count("conversations.info") != before {
		t.Fatal("invalid request reached provider")
	}
}

func TestChannelMutationReplayConflictAndUnknownOutcomeNeverResends(t *testing.T) {
	f := newChannelFixture(t)
	binding, session := f.active()
	delivery := f.mention(binding, session, "EVENTONE", true)
	args := map[string]any{"channel": "CONE", "text": "synthetic reply"}
	status, first := f.api(binding, session, delivery, "chat.postMessage", args, "operation-one")
	if status != 200 {
		t.Fatal("first write failed")
	}
	status, replay := f.api(binding, session, delivery, "chat.postMessage", args, "operation-one")
	if status != 200 || !bytes.Equal(first, replay) || f.provider.count("chat.postMessage") != 1 {
		t.Fatal("idempotent write replay called provider")
	}
	if status, _ := f.api(binding, session, delivery, "chat.postMessage", map[string]any{"channel": "CONE", "text": "different"}, "operation-one"); status != 409 {
		t.Fatal("operation ID accepted another body")
	}
	f.provider.callError = true
	if status, _ := f.api(binding, session, delivery, "chat.postMessage", args, "operation-unknown"); status != 503 {
		t.Fatal("uncertain write was not recorded")
	}
	if status, _ := f.api(binding, session, delivery, "chat.postMessage", args, "operation-unknown"); status != 409 || f.provider.count("chat.postMessage") != 2 {
		t.Fatal("uncertain write was automatically resent")
	}
	view, _ := f.store.View()
	for _, op := range view.Operations {
		if op.Status == "running" {
			t.Fatal("uncertain operation remained running")
		}
	}
}

func TestChannelRefreshAndConcurrentUninstallFence(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(strconv.FormatBool(revoked), func(t *testing.T) {
			f := newChannelFixture(t)
			binding, session := f.active()
			delivery := f.mention(binding, session, "EVENTONE", false)
			if err := f.store.Update(func(st *state) error {
				grant := st.Grants["TONE"]
				grant.ExpiresAt = f.clock.Add(time.Second)
				st.Grants["TONE"] = grant
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if revoked {
				f.provider.onRefresh = func() {
					if f.postEvent(f.event("UNINSTALL", map[string]any{"type": "app_uninstalled"}), f.clock, true) != 200 {
						t.Error("uninstall rejected")
					}
				}
			}
			status, _ := f.api(binding, session, delivery, "auth.test", map[string]any{}, "")
			view, _ := f.store.View()
			if f.provider.refreshes != 1 {
				t.Fatal("refresh count incorrect")
			}
			if revoked {
				if status == 200 || view.Grants["TONE"].Status != "revoked" || f.provider.count("auth.test") != 0 {
					t.Fatal("refresh overwrote uninstall or called provider after revocation")
				}
			} else if status != 200 || view.Grants["TONE"].Status != "active" || view.Grants["TONE"].Version != 2 {
				t.Fatal("same-grant refresh failed")
			}
		})
	}
}

func TestChannelUserTokenRevocationDoesNotRevokeBotButBotTokenDoes(t *testing.T) {
	f := newChannelFixture(t)
	binding, session := f.active()
	for index, tokens := range []map[string]any{{"oauth": []string{"UOWNER"}}, {"bot": []string{"UOTHER"}}} {
		if f.postEvent(f.event("REVOKE"+strconv.Itoa(index), map[string]any{"type": "tokens_revoked", "tokens": tokens}), f.clock, true) != 200 {
			t.Fatal("revocation event rejected")
		}
		if status, _ := f.inbox(binding, session); status != 200 {
			t.Fatal("user/unrelated token event revoked bot")
		}
	}
	if f.postEvent(f.event("REVOKEBOT", map[string]any{"type": "tokens_revoked", "tokens": map[string]any{"bot": []string{"UBOT"}}}), f.clock, true) != 200 {
		t.Fatal("bot revocation event rejected")
	}
	view, _ := f.store.View()
	if view.Grants["TONE"].Status != "revoked" || view.Grants["TONE"].AccessToken != "" || view.Grants["TONE"].RefreshToken != "" {
		t.Fatal("bot revocation did not fence and clear credential")
	}
	if status, _ := f.inbox(binding, session); status != 403 {
		t.Fatal("revoked bot session remained usable")
	}
}

func TestChannelReadAndCachedReplayCannotReturnAfterHostRevocation(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(strconv.FormatBool(cached), func(t *testing.T) {
			f := newChannelFixture(t)
			binding, session := f.active()
			delivery := f.mention(binding, session, "EVENTONE", false)
			method, args, opID := "auth.test", map[string]any{}, ""
			if cached {
				method, args, opID = "chat.postMessage", map[string]any{"channel": "CONE", "text": "synthetic reply"}, "cached-op"
				if status, _ := f.api(binding, session, delivery, method, args, opID); status != 200 {
					t.Fatal("could not seed completed operation")
				}
				f.authorizer.mu.Lock()
				f.authorizer.afterFence = func() { f.authorizer.revoke(f.owner.ID()) }
				f.authorizer.mu.Unlock()
			} else {
				f.provider.onCall = func(called string) {
					if called == method {
						f.authorizer.revoke(f.owner.ID())
					}
				}
			}
			if status, _ := f.api(binding, session, delivery, method, args, opID); status != 403 {
				t.Fatal("provider or cached data escaped after host revocation")
			}
		})
	}
}

func TestChannelInboxRechecksHostAndACKRejectsWrongReceiptDigest(t *testing.T) {
	f := newChannelFixture(t)
	binding, session := f.active()
	delivery := f.mention(binding, session, "EVENTONE", false)
	wrong := jsonBody(map[string]any{"delivery_id": delivery.ID, "body_sha256": strings.Repeat("0", 64), "outcome": "accepted"})
	status, _, _ := f.request("POST", Prefix+"/bindings/"+binding.ID+"/ack", wrong, nil, session.Token, nil)
	if status != 409 {
		t.Fatal("ACK accepted another payload digest")
	}
	if status, deliveries := f.inbox(binding, session); status != 200 || len(deliveries) != 1 {
		t.Fatal("rejected ACK consumed the delivery")
	}
	f.authorizer.mu.Lock()
	f.authorizer.afterFence = func() { f.authorizer.revoke(f.owner.ID()) }
	f.authorizer.mu.Unlock()
	if status, deliveries := f.inbox(binding, session); status != 403 || len(deliveries) != 0 {
		t.Fatal("queued provider payload escaped after admission revocation")
	}
}

func TestChannelActivationRequiresCompleteInstallerAndBotMembership(t *testing.T) {
	for _, mode := range []string{"installer_missing", "bot_missing", "empty", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			f := newChannelFixture(t)
			binding := f.start("CONE")
			if f.callback(f.consent(binding)) != 200 {
				t.Fatal("fixture OAuth callback failed")
			}
			f.provider.mu.Lock()
			switch mode {
			case "installer_missing":
				f.provider.members = []string{"UACTOR", "UBOT"}
			case "bot_missing":
				f.provider.members = []string{"UACTOR", "UOWNER"}
			case "empty":
				f.provider.members = []string{}
			case "incomplete":
				f.provider.membersIncomplete = true
			}
			f.provider.mu.Unlock()
			if _, err := f.publicClient(f.owner).Activate(context.Background(), binding.ID); err == nil {
				t.Fatal("activation admitted missing or incomplete installer/bot membership")
			}
			view, _ := f.store.View()
			if view.Bindings[binding.ID].Public.Status != "authorized" || view.Bindings[binding.ID].SessionDigest != "" {
				t.Fatal("failed membership proof published an active binding")
			}
			if _, err := f.publicClient(f.owner).Session(context.Background(), binding.ID); err == nil {
				t.Fatal("failed membership proof issued a delivery session")
			}
			if calls := f.provider.count("conversations.members"); calls < 1 || calls > 10 {
				t.Fatal("membership proof was absent or unbounded")
			}
		})
	}
}

func TestChannelDepartedInstallerCannotReadInboxWriteOrReceiveCachedResult(t *testing.T) {
	for _, mode := range []string{"inbox", "write", "cached"} {
		t.Run(mode, func(t *testing.T) {
			f := newChannelFixture(t)
			binding, session := f.active()
			delivery := f.mention(binding, session, "EVENTONE", false)
			args := map[string]any{"channel": "CONE", "text": "synthetic-private-reply"}
			if mode == "cached" {
				if status, _ := f.api(binding, session, delivery, "chat.postMessage", args, "same-operation"); status != 200 {
					t.Fatal("could not seed completed write")
				}
			}
			before := f.provider.count("chat.postMessage")
			f.provider.mu.Lock()
			f.provider.members = []string{"UACTOR", "UBOT"} // OAuth installer departed.
			f.provider.mu.Unlock()
			if mode == "inbox" {
				if status, deliveries := f.inbox(binding, session); status == 200 || len(deliveries) != 0 {
					t.Fatal("private event delivered after installer left the channel")
				}
			} else {
				if status, _ := f.api(binding, session, delivery, "chat.postMessage", args, "same-operation"); status == 200 {
					t.Fatal("API or cached private result returned after installer left")
				}
			}
			if f.provider.count("chat.postMessage") != before {
				t.Fatal("failed membership proof reached a provider mutation")
			}
		})
	}
}

func TestChannelQueuedAPIRevalidatesBeforeRefreshOrProviderMutation(t *testing.T) {
	for _, mode := range []string{"host", "session", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			f := newChannelFixture(t)
			binding, session := f.active()
			delivery := f.mention(binding, session, "EVENTONE", false)
			if err := f.store.Update(func(st *state) error {
				grant := st.Grants["TONE"]
				grant.ExpiresAt = f.clock.Add(time.Second)
				st.Grants["TONE"] = grant
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			queued := make(chan struct{})
			var observed sync.Once
			f.authorizer.mu.Lock()
			f.authorizer.onFence = func() {
				st, _ := f.store.View()
				for _, operation := range st.Operations {
					if operation.Status == "running" {
						observed.Do(func() { close(queued) })
					}
				}
			}
			f.authorizer.mu.Unlock()
			f.server.grantMu.Lock()
			locked := true
			defer func() {
				if locked {
					f.server.grantMu.Unlock()
				}
			}()
			done := make(chan int, 1)
			go func() {
				status, _ := f.api(binding, session, delivery, "chat.postMessage", map[string]any{"channel": "CONE", "text": "synthetic reply"}, "queued-operation")
				done <- status
			}()
			select {
			case <-queued:
			case <-time.After(3 * time.Second):
				t.Fatal("API did not durably queue before the grant lock")
			}
			switch mode {
			case "host":
				f.authorizer.revoke(f.owner.ID())
			case "session":
				if err := f.store.Update(func(st *state) error {
					current := st.Bindings[binding.ID]
					current.SessionDigest = ""
					st.Bindings[binding.ID] = current
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case "disconnect":
				if err := f.publicClient(f.owner).Disconnect(context.Background(), binding.ID); err != nil {
					t.Fatal(err)
				}
			}
			f.server.grantMu.Unlock()
			locked = false
			select {
			case status := <-done:
				if status == 200 {
					t.Fatal("queued API survived revoked admission")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("queued API did not terminate")
			}
			f.provider.mu.Lock()
			refreshes, mutations := f.provider.refreshes, f.provider.calls["chat.postMessage"]
			f.provider.mu.Unlock()
			if refreshes != 0 || mutations != 0 {
				t.Fatal("revoked queued request refreshed or called the provider")
			}
		})
	}
}

func TestChannelQueuedCallbackRechecksHostBindingAndExpiryBeforeExchange(t *testing.T) {
	for _, mode := range []string{"host", "disconnect", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newChannelFixture(t)
			binding := f.start("CONE")
			oauthState := f.consent(binding)
			queued := make(chan struct{})
			var observed sync.Once
			f.authorizer.mu.Lock()
			f.authorizer.onFence = func() {
				st, _ := f.store.View()
				for _, tx := range st.Transactions {
					if tx.BindingID == binding.ID && tx.Status == "consumed" {
						observed.Do(func() { close(queued) })
					}
				}
			}
			f.authorizer.mu.Unlock()
			f.server.grantMu.Lock()
			locked := true
			defer func() {
				if locked {
					f.server.grantMu.Unlock()
				}
			}()
			done := make(chan int, 1)
			go func() { done <- f.callback(oauthState) }()
			select {
			case <-queued:
			case <-time.After(3 * time.Second):
				t.Fatal("callback did not consume before grant lock")
			}
			switch mode {
			case "host":
				f.authorizer.revoke(f.owner.ID())
			case "disconnect":
				if err := f.publicClient(f.owner).Disconnect(context.Background(), binding.ID); err != nil {
					t.Fatal(err)
				}
			case "expired":
				f.clock = f.clock.Add(16 * time.Minute)
			}
			f.server.grantMu.Unlock()
			locked = false
			select {
			case status := <-done:
				if status == 200 {
					t.Fatal("revoked queued callback succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("queued callback did not terminate")
			}
			f.provider.mu.Lock()
			exchanges := f.provider.exchanges
			f.provider.mu.Unlock()
			if exchanges != 0 {
				t.Fatal("revoked or expired queued callback reached token exchange")
			}
		})
	}
}
