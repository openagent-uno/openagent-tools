package slackchannel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

var errDenied = errors.New("slack channel request denied")

type Server struct {
	config   Config
	auth     InstallationAuthorizer
	store    *Store
	provider Provider
	signing  []byte
	now      func() time.Time
	grantMu  sync.Mutex // One owner of the app/workspace rotating bot credential.
}

func NewServer(config Config, authorizer InstallationAuthorizer, store *Store, provider Provider, signing []byte) (*Server, error) {
	u, e := url.Parse(config.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !text(config.AppID, 128) || !text(config.ClientID, 256) || len(config.AllowedInstallations) == 0 || len(config.AllowedInstallations) > 1000 || len(signing) < 16 || len(signing) > 4096 || authorizer == nil || store == nil || provider == nil {
		return nil, errDenied
	}
	for _, id := range config.AllowedInstallations {
		if len(id) != 64 {
			return nil, errDenied
		}
		if _, e := hex.DecodeString(id); e != nil {
			return nil, errDenied
		}
	}
	return &Server{config: config, auth: authorizer, store: store, provider: provider, signing: bytes.Clone(signing), now: func() time.Time { return time.Now().UTC() }}, nil
}

func text(v string, n int) bool {
	return v != "" && len(v) <= n && utf8.ValidString(v) && strings.TrimSpace(v) == v && !strings.ContainsFunc(v, unicode.IsControl)
}
func id(v string) bool {
	if !text(v, 128) {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic("channel entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func digest(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func strict(b []byte, v any) error {
	if decodeClientResponse(b, v) != nil {
		return errDenied
	}
	return nil
}
func body(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	if e != nil || len(b) > 64<<10 {
		return nil, errDenied
	}
	return b, nil
}
func output(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, code string) {
	output(w, status, map[string]string{"error": code})
}
func (s *Server) allowed(i auth.Installation) bool {
	for _, allowed := range s.config.AllowedInstallations {
		if allowed == i.ID {
			return true
		}
	}
	return false
}
func (s *Server) fence(i auth.Installation, fn func() error) error {
	if !s.allowed(i) {
		return errDenied
	}
	return s.auth.WithCentralInstallation(i, fn)
}
func (s *Server) authenticated(r *http.Request, b []byte) (auth.Installation, error) {
	i, e := s.auth.AuthenticateInstallation(r, b)
	if e != nil || !s.allowed(i) {
		return auth.Installation{}, errDenied
	}
	return i, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	path := strings.TrimPrefix(r.URL.Path, Prefix)
	if !strings.HasPrefix(r.URL.Path, Prefix+"/") || r.URL.RawPath != "" {
		failure(w, 404, "not_found")
		return
	}
	if path == "/events" && r.Method == "POST" {
		s.events(w, r)
		return
	}
	if path == "/oauth/callback" && r.Method == "GET" {
		s.callback(w, r)
		return
	}
	if strings.HasPrefix(path, "/install/") {
		s.installPage(w, r, strings.TrimPrefix(path, "/install/"))
		return
	}
	if r.URL.RawQuery != "" {
		failure(w, 400, "invalid_request")
		return
	}
	if path == "/health" && r.Method == "GET" {
		output(w, 200, map[string]any{"protocol": Protocol, "app_id": s.config.AppID, "configured": true, "provider_connected": false})
		return
	}
	b, e := body(r)
	if e != nil {
		failure(w, 400, "invalid_request")
		return
	}
	if path == "/bindings" && r.Method == "POST" {
		i, e := s.authenticated(r, b)
		if e != nil {
			failure(w, 403, "denied")
			return
		}
		s.start(w, r, i, b)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/bindings/"), "/")
	if !strings.HasPrefix(path, "/bindings/") || len(parts) > 2 || !id(parts[0]) {
		failure(w, 404, "not_found")
		return
	}
	bindingID := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	if action == "inbox" || action == "ack" || action == "api" || action == "session-status" {
		record, e := s.session(r, bindingID)
		if e != nil {
			failure(w, 403, "denied")
			return
		}
		switch {
		case action == "inbox" && r.Method == "GET":
			s.inbox(w, record)
		case action == "ack" && r.Method == "POST":
			s.ack(w, record, b)
		case action == "api" && r.Method == "POST":
			s.api(w, r, record, b)
		case action == "session-status" && r.Method == "GET":
			output(w, 200, map[string]any{"protocol": Protocol, "binding": record.Public})
		default:
			failure(w, 405, "method_not_allowed")
		}
		return
	}
	i, e := s.authenticated(r, b)
	if e != nil {
		failure(w, 403, "denied")
		return
	}
	view, e := s.store.View()
	record, ok := view.Bindings[bindingID]
	if e != nil || !ok || record.Host != i {
		failure(w, 404, "not_found")
		return
	}
	switch {
	case action == "" && r.Method == "GET":
		output(w, 200, record.Public)
	case action == "activate" && r.Method == "POST":
		if string(b) != "{}" {
			failure(w, 400, "invalid_request")
			return
		}
		s.activate(w, r, i, record)
	case action == "session" && r.Method == "POST":
		if string(b) != "{}" {
			failure(w, 400, "invalid_request")
			return
		}
		s.issueSession(w, i, record)
	case action == "" && r.Method == "DELETE":
		s.disconnect(w, i, record)
	default:
		failure(w, 405, "method_not_allowed")
	}
}

func (s *Server) start(w http.ResponseWriter, r *http.Request, i auth.Installation, b []byte) {
	var input StartRequest
	if strict(b, &input) != nil || !text(input.Recipient.WorkspaceID, 256) || !text(input.Recipient.SubjectID, 256) || !text(input.Recipient.AgentID, 256) || !text(input.AgentLabel, 256) || !id(input.TeamID) || !id(input.ChannelID) {
		failure(w, 400, "invalid_binding")
		return
	}
	now := s.now()
	bindingID := "b_" + random()
	txID := random()
	public := Binding{ID: bindingID, Installation: i.ID, Recipient: input.Recipient, AgentLabel: input.AgentLabel, TeamID: input.TeamID, ChannelID: input.ChannelID, Status: "pending_consent", Version: 1, CreatedAt: now, AuthorizationURL: s.config.Origin + Prefix + "/install/" + txID}
	e := s.fence(i, func() error {
		return s.store.Update(func(st *state) error {
			for _, rec := range st.Bindings {
				if rec.Public.TeamID == input.TeamID && rec.Public.ChannelID == input.ChannelID && rec.Public.Status != "disconnected" && rec.Public.Status != "revoked" {
					return errDenied
				}
			}
			if len(st.Bindings) >= 1000 || len(st.Transactions) >= 1000 {
				return errDenied
			}
			st.Bindings[bindingID] = bindingRecord{Public: public, Host: i}
			st.Transactions[txID] = transaction{BindingID: bindingID, State: random(), CSRF: random(), Status: "pending", StartedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
			return nil
		})
	})
	if e != nil {
		failure(w, 409, "binding_unavailable")
		return
	}
	output(w, 201, public)
}

var consent = template.Must(template.New("slack-channel-consent").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Connect the OpenAgent Slack bot</title><style>body{font:17px system-ui;max-width:640px;margin:8vh auto;padding:24px;color:#17212b}button{font:inherit;padding:12px 20px}code{overflow-wrap:anywhere}</style><h1>Connect the OpenAgent Slack bot</h1><p>Destination: <strong>{{.Binding.AgentLabel}}</strong> on <strong>{{.Host.Name}}</strong> ({{.Host.Product}}).</p><p>Installation: <code>{{.Host.ID}}</code></p><p>Host recipient: <code>{{.Binding.Recipient.WorkspaceID}} / {{.Binding.Recipient.SubjectID}} / {{.Binding.Recipient.AgentID}}</code></p><p>Slack workspace: <code>{{.Binding.TeamID}}</code>; channel: <code>{{.Binding.ChannelID}}</code>.</p><p>The bot receives mentions in this selected channel. OpenAgent keeps the Slack bot credential encrypted centrally and temporarily queues the selected events. The destination server executes its own agent and applies its own user, tool and memory permissions. This does not connect a Slack MCP tool or grant the destination access to other channels.</p><p>Bot permissions requested: {{.Scopes}}. Invite the bot into the selected channel after installation. Complete recipient verification in your product before activation.</p><p>Host labels are supplied by its operator, not an OpenAgent endorsement. Disconnecting this destination leaves other authorized destinations connected; uninstalling the Slack app affects the workspace.</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Continue to Slack</button></form></html>`))
var slackNavigation = template.Must(template.New("slack-channel-navigation").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Continue to Slack</title><h1>Continue to Slack</h1><p><a href="{{.URL}}" rel="noreferrer">Open Slack authorization</a></p></html>`))

func (s *Server) installPage(w http.ResponseWriter, r *http.Request, txID string) {
	if !id(txID) || r.URL.RawQuery != "" || (r.Method != "GET" && r.Method != "POST") {
		failure(w, 404, "not_found")
		return
	}
	st, e := s.store.View()
	tx, ok := st.Transactions[txID]
	record, exists := st.Bindings[tx.BindingID]
	if e != nil || !ok || !exists || tx.Status != "pending" || record.Public.Status != "pending_consent" || !s.now().Before(tx.ExpiresAt) || s.fence(record.Host, func() error { return nil }) != nil {
		failure(w, 410, "consent_unavailable")
		return
	}
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = consent.Execute(w, map[string]any{"Binding": record.Public, "Host": record.Host, "Scopes": strings.Join(BotScopes, ", "), "CSRF": tx.CSRF})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil || len(r.PostForm) != 1 || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(tx.CSRF)) != 1 {
		failure(w, 403, "denied")
		return
	}
	target, e := s.provider.AuthorizationURL(tx.State)
	if e != nil {
		failure(w, 503, "provider_unavailable")
		return
	}
	e = s.fence(record.Host, func() error {
		return s.store.Update(func(st *state) error {
			current, ok := st.Transactions[txID]
			if !ok || current.Status != "pending" || !s.now().Before(current.ExpiresAt) {
				return errDenied
			}
			current.Status = "consenting"
			st.Transactions[txID] = current
			return nil
		})
	})
	if e != nil {
		failure(w, 410, "consent_unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = slackNavigation.Execute(w, struct{ URL string }{target})
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q["state"]) != 1 || !text(q.Get("state"), 256) || len(q["code"]) > 1 || len(q["error"]) > 1 {
		failure(w, 400, "invalid_callback")
		return
	}
	st, e := s.store.View()
	txID := ""
	var tx transaction
	var record bindingRecord
	for key, candidate := range st.Transactions {
		if subtle.ConstantTimeCompare([]byte(candidate.State), []byte(q.Get("state"))) == 1 {
			txID = key
			tx = candidate
			record = st.Bindings[tx.BindingID]
			break
		}
	}
	if e != nil || txID == "" || tx.Status != "consenting" || !s.now().Before(tx.ExpiresAt) || record.Public.Status != "pending_consent" {
		failure(w, 410, "consent_unavailable")
		return
	}
	e = s.fence(record.Host, func() error {
		return s.store.Update(func(st *state) error {
			current := st.Transactions[txID]
			if current.Status != "consenting" || st.Bindings[tx.BindingID].Public.Status != "pending_consent" {
				return errDenied
			}
			current.Status = "consumed"
			current.State = ""
			current.CSRF = ""
			st.Transactions[txID] = current
			return nil
		})
	})
	if e != nil {
		failure(w, 410, "consent_unavailable")
		return
	}
	if q.Get("error") != "" || !text(q.Get("code"), 4096) {
		s.failBinding(record.Public.ID)
		failure(w, 400, "consent_cancelled")
		return
	}
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	if s.fence(record.Host, func() error {
		current, e := s.store.View()
		if e != nil || current.Bindings[record.Public.ID].Public.Status != "pending_consent" || current.Bindings[record.Public.ID].Public.Version != record.Public.Version || current.Transactions[txID].Status != "consumed" || !s.now().Before(current.Transactions[txID].ExpiresAt) {
			return errDenied
		}
		for _, event := range current.Deliveries {
			if event.TeamID == record.Public.TeamID && event.Status == "lifecycle" && !event.OccurredAt.Before(tx.StartedAt.Truncate(time.Second)) {
				return errDenied
			}
		}
		return nil
	}) != nil {
		failure(w, 403, "destination_revoked")
		return
	}
	grant, e := s.provider.Exchange(r.Context(), q.Get("code"), s.now())
	if e != nil || grant.TeamID != record.Public.TeamID || grant.AppID != s.config.AppID {
		s.failBinding(record.Public.ID)
		failure(w, 400, "provider_grant_rejected")
		return
	}
	e = s.fence(record.Host, func() error {
		return s.store.Update(func(st *state) error {
			current := st.Bindings[record.Public.ID]
			if current.Public.Status != "pending_consent" {
				return errDenied
			}
			// An uninstall/revocation after consent began fences a delayed callback.
			for _, event := range st.Deliveries {
				if event.TeamID == grant.TeamID && event.Status == "lifecycle" && !event.OccurredAt.Before(tx.StartedAt.Truncate(time.Second)) {
					return errDenied
				}
			}
			old := st.Grants[grant.TeamID]
			grant.Version = old.Version + 1
			grant.Status = "active"
			grant.AuthorizedAt = s.now()
			st.Grants[grant.TeamID] = grant
			current.Public.Status = "authorized"
			current.Public.BotUserID = grant.BotUserID
			current.Public.AuthorizedUserID = grant.AuthorizedUserID
			current.Public.AuthorizedAt = s.now()
			current.Public.AuthorizationURL = ""
			st.Bindings[current.Public.ID] = current
			return nil
		})
	})
	if e != nil {
		failure(w, 403, "destination_revoked")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<!doctype html><meta charset=utf-8><title>OpenAgent Slack authorization received</title><h1>Slack authorization received</h1><p>Return to your product, invite OpenAgent into the selected channel, and complete activation. The bot is not connected to the agent until the destination verifies the channel and activates the binding.</p>")
}
func (s *Server) failBinding(bindingID string) {
	_ = s.store.Update(func(st *state) error {
		r, ok := st.Bindings[bindingID]
		if ok && r.Public.Status == "pending_consent" {
			r.Public.Status = "failed"
			r.Public.AuthorizationURL = ""
			st.Bindings[bindingID] = r
		}
		return nil
	})
}

func (s *Server) withGrant(ctx context.Context, team string, guard func() error, fn func(BotGrant) (json.RawMessage, error)) (json.RawMessage, error) {
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	if ctx.Err() != nil || guard == nil || guard() != nil {
		return nil, errDenied
	}
	st, e := s.store.View()
	grant, ok := st.Grants[team]
	if e != nil || !ok || grant.Status != "active" {
		return nil, errDenied
	}
	if !s.now().Add(90 * time.Second).Before(grant.ExpiresAt) {
		e = s.store.Update(func(st *state) error {
			current := st.Grants[team]
			if current.Status != "active" || current.Version != grant.Version {
				return errDenied
			}
			current.Status = "refreshing"
			st.Grants[team] = current
			return nil
		})
		if e != nil {
			return nil, errDenied
		}
		if guard() != nil {
			_ = s.store.Update(func(st *state) error {
				current := st.Grants[team]
				if current.Version == grant.Version && current.Status == "refreshing" {
					current.Status = "active"
					st.Grants[team] = current
				}
				return nil
			})
			return nil, errDenied
		}
		fresh, refreshErr := s.provider.Refresh(ctx, grant, s.now())
		if refreshErr != nil {
			_ = s.store.Update(func(st *state) error {
				current := st.Grants[team]
				if current.Version == grant.Version && current.Status == "refreshing" {
					current.Status = "reconnect_required"
					st.Grants[team] = current
				}
				return nil
			})
			return nil, errDenied
		}
		e = s.store.Update(func(st *state) error {
			current := st.Grants[team]
			if current.Version != grant.Version || current.Status != "refreshing" {
				return errDenied
			}
			fresh.Version = grant.Version + 1
			fresh.Status = "active"
			st.Grants[team] = fresh
			return nil
		})
		if e != nil {
			return nil, errDenied
		}
		grant = fresh
	}
	if guard() != nil {
		return nil, errDenied
	}
	result, e := fn(grant)
	if e != nil {
		return nil, e
	}
	st, e = s.store.View()
	current := st.Grants[team]
	if e != nil || current.Status != "active" || current.Version != grant.Version {
		return nil, errDenied
	}
	return result, nil
}

// Recheck after every wait on the rotating grant owner. This admits provider IO;
// the separate publication fence still rechecks after the network returns.
func (s *Server) admit(record bindingRecord, status, deliveryID string) error {
	return s.fence(record.Host, func() error {
		st, e := s.store.View()
		current, ok := st.Bindings[record.Public.ID]
		if e != nil || !ok || current.Host != record.Host || current.Public.Status != status || current.Public.Version != record.Public.Version {
			return errDenied
		}
		if status == "active" && (current.SessionDigest != record.SessionDigest || !s.now().Before(current.SessionExpiresAt)) {
			return errDenied
		}
		if deliveryID != "" {
			event, ok := st.Deliveries[deliveryID]
			if !ok || event.BindingID != record.Public.ID || event.BindingVersion != record.Public.Version || (event.Status != "pending" && event.Status != "acknowledged") {
				return errDenied
			}
		}
		return nil
	})
}

// Bot access to a private channel does not authorize a different workspace
// installer to route that channel to a host. The consenting human and the bot
// must both still be members of a complete, bounded current API snapshot.
func (s *Server) membership(ctx context.Context, record bindingRecord, grant BotGrant, status, deliveryID string) error {
	seen := map[string]bool{}
	cursors := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		if s.admit(record, status, deliveryID) != nil {
			return errDenied
		}
		args := map[string]any{"channel": record.Public.ChannelID, "limit": 100}
		if cursor != "" {
			args["cursor"] = cursor
		}
		raw, e := s.provider.Call(ctx, grant, "conversations.members", args)
		var response struct {
			OK       bool     `json:"ok"`
			Members  []string `json:"members"`
			HasMore  bool     `json:"has_more"`
			Metadata struct {
				Next string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if e != nil || json.Unmarshal(raw, &response) != nil || !response.OK || response.Members == nil || len(response.Members) > 100 {
			return errDenied
		}
		for _, member := range response.Members {
			if !id(member) || seen[member] {
				return errDenied
			}
			seen[member] = true
		}
		if len(seen) > 1000 {
			return errDenied
		}
		cursor = response.Metadata.Next
		if cursor == "" {
			if response.HasMore || !seen[record.Public.AuthorizedUserID] || !seen[grant.BotUserID] {
				return errDenied
			}
			return s.admit(record, status, deliveryID)
		}
		if !text(cursor, 1024) || cursors[cursor] || page == 9 {
			return errDenied
		}
		cursors[cursor] = true
	}
	return errDenied
}

func (s *Server) activate(w http.ResponseWriter, r *http.Request, i auth.Installation, record bindingRecord) {
	if record.Public.Status != "authorized" {
		failure(w, 409, "binding_not_authorized")
		return
	}
	raw, e := s.withGrant(r.Context(), record.Public.TeamID, func() error { return s.admit(record, "authorized", "") }, func(g BotGrant) (json.RawMessage, error) {
		if e := s.membership(r.Context(), record, g, "authorized", ""); e != nil {
			return nil, e
		}
		return s.provider.Call(r.Context(), g, "conversations.info", map[string]any{"channel": record.Public.ChannelID})
	})
	var info struct {
		OK      bool `json:"ok"`
		Channel struct {
			ID         string `json:"id"`
			IsMember   bool   `json:"is_member"`
			IsArchived bool   `json:"is_archived"`
			IsIM       bool   `json:"is_im"`
			IsMPIM     bool   `json:"is_mpim"`
		} `json:"channel"`
	}
	if e != nil || json.Unmarshal(raw, &info) != nil || !info.OK || info.Channel.ID != record.Public.ChannelID || !info.Channel.IsMember || info.Channel.IsArchived || info.Channel.IsIM || info.Channel.IsMPIM {
		failure(w, 409, "invite_bot_to_selected_channel")
		return
	}
	e = s.fence(i, func() error {
		return s.store.Update(func(st *state) error {
			current := st.Bindings[record.Public.ID]
			if current.Host != i || current.Public.Version != record.Public.Version || current.Public.Status != "authorized" || st.Grants[current.Public.TeamID].Status != "active" {
				return errDenied
			}
			current.Public.Status = "active"
			st.Bindings[current.Public.ID] = current
			record = current
			return nil
		})
	})
	if e != nil {
		failure(w, 403, "denied")
		return
	}
	output(w, 200, record.Public)
}
func (s *Server) issueSession(w http.ResponseWriter, i auth.Installation, record bindingRecord) {
	token := random()
	expires := s.now().Add(8 * time.Hour)
	e := s.fence(i, func() error {
		return s.store.Update(func(st *state) error {
			current := st.Bindings[record.Public.ID]
			if current.Host != i || current.Public.Status != "active" || current.Public.Version != record.Public.Version || st.Grants[current.Public.TeamID].Status != "active" {
				return errDenied
			}
			current.SessionDigest = digest([]byte(token))
			current.SessionExpiresAt = expires
			st.Bindings[current.Public.ID] = current
			return nil
		})
	})
	if e != nil {
		failure(w, 409, "binding_not_active")
		return
	}
	output(w, 200, Session{Protocol: Protocol, BindingID: record.Public.ID, Token: token, ExpiresAt: expires})
}
func (s *Server) session(r *http.Request, bindingID string) (bindingRecord, error) {
	if len(r.Header.Values("Authorization")) != 1 {
		return bindingRecord{}, errDenied
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return bindingRecord{}, errDenied
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if len(token) != 43 {
		return bindingRecord{}, errDenied
	}
	st, e := s.store.View()
	record, ok := st.Bindings[bindingID]
	if e != nil || !ok || record.Public.Status != "active" || !s.now().Before(record.SessionExpiresAt) || subtle.ConstantTimeCompare([]byte(record.SessionDigest), []byte(digest([]byte(token)))) != 1 || st.Grants[record.Public.TeamID].Status != "active" || s.fence(record.Host, func() error { return nil }) != nil {
		return bindingRecord{}, errDenied
	}
	return record, nil
}
func (s *Server) current(st *state, record bindingRecord) bool {
	r, ok := st.Bindings[record.Public.ID]
	return ok && r.Host == record.Host && r.Public.Status == "active" && r.Public.Version == record.Public.Version && r.SessionDigest == record.SessionDigest && s.now().Before(r.SessionExpiresAt) && st.Grants[r.Public.TeamID].Status == "active"
}
func (s *Server) disconnect(w http.ResponseWriter, i auth.Installation, record bindingRecord) {
	e := s.fence(i, func() error {
		return s.store.Update(func(st *state) error {
			current := st.Bindings[record.Public.ID]
			if current.Host != i {
				return errDenied
			}
			current.Public.Status = "disconnected"
			current.Public.Version++
			current.SessionDigest = ""
			current.Public.AuthorizationURL = ""
			st.Bindings[current.Public.ID] = current
			return nil
		})
	})
	if e != nil {
		failure(w, 403, "denied")
		return
	}
	output(w, 200, map[string]string{"status": "disconnected"})
}

func (s *Server) inbox(w http.ResponseWriter, record bindingRecord) {
	st, e := s.store.View()
	if e != nil || !s.current(&st, record) {
		failure(w, 403, "denied")
		return
	}
	hasPending := false
	for _, d := range st.Deliveries {
		if d.BindingID == record.Public.ID && d.BindingVersion == record.Public.Version && d.Status == "pending" {
			hasPending = true
			break
		}
	}
	if hasPending {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		_, e = s.withGrant(ctx, record.Public.TeamID, func() error { return s.admit(record, "active", "") }, func(g BotGrant) (json.RawMessage, error) { return nil, s.membership(ctx, record, g, "active", "") })
		if e != nil {
			failure(w, 403, "channel_membership_unavailable")
			return
		}
	}
	e = s.fence(record.Host, func() error {
		current, e := s.store.View()
		if e != nil || !s.current(&current, record) {
			return errDenied
		}
		deliveries := []Delivery{}
		for _, d := range current.Deliveries {
			if d.BindingID == record.Public.ID && d.BindingVersion == record.Public.Version && d.Status == "pending" {
				deliveries = append(deliveries, d)
			}
		}
		sort.Slice(deliveries, func(i, j int) bool { return deliveries[i].CreatedAt.Before(deliveries[j].CreatedAt) })
		if len(deliveries) > 10 {
			deliveries = deliveries[:10]
		}
		output(w, 200, map[string]any{"protocol": Protocol, "binding": record.Public, "deliveries": deliveries})
		return nil
	})
	if e != nil {
		failure(w, 403, "denied")
	}
}
func (s *Server) ack(w http.ResponseWriter, record bindingRecord, b []byte) {
	var input struct {
		DeliveryID string `json:"delivery_id"`
		BodySHA256 string `json:"body_sha256"`
		Outcome    string `json:"outcome"`
	}
	if strict(b, &input) != nil || !id(input.DeliveryID) || len(input.BodySHA256) != 64 || (input.Outcome != "accepted" && input.Outcome != "denied") {
		failure(w, 400, "invalid_ack")
		return
	}
	e := s.fence(record.Host, func() error {
		return s.store.Update(func(st *state) error {
			if !s.current(st, record) {
				return errDenied
			}
			delivery, ok := st.Deliveries[input.DeliveryID]
			if !ok || delivery.BindingID != record.Public.ID || delivery.BindingVersion != record.Public.Version || delivery.BodySHA256 != input.BodySHA256 {
				return errDenied
			}
			status := "acknowledged"
			if input.Outcome == "denied" {
				status = "denied"
			}
			if delivery.Status != "pending" && delivery.Status != status {
				return errDenied
			}
			delivery.Status = status
			st.Deliveries[input.DeliveryID] = delivery
			return nil
		})
	})
	if e != nil {
		failure(w, 409, "ack_rejected")
		return
	}
	output(w, 200, map[string]string{"status": "acknowledged"})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	b, e := body(r)
	stamp := r.Header.Get("X-Slack-Request-Timestamp")
	seconds, parseErr := strconv.ParseInt(stamp, 10, 64)
	if e != nil || len(r.Header.Values("X-Slack-Request-Timestamp")) != 1 || len(r.Header.Values("X-Slack-Signature")) != 1 || parseErr != nil || s.now().Sub(time.Unix(seconds, 0)) > 5*time.Minute || time.Unix(seconds, 0).Sub(s.now()) > time.Minute {
		failure(w, 403, "invalid_signature")
		return
	}
	mac := hmac.New(sha256.New, s.signing)
	_, _ = mac.Write([]byte("v0:" + stamp + ":"))
	_, _ = mac.Write(b)
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(r.Header.Get("X-Slack-Signature"))) != 1 {
		failure(w, 403, "invalid_signature")
		return
	}
	var envelope struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		AppID     string `json:"api_app_id"`
		TeamID    string `json:"team_id"`
		EventID   string `json:"event_id"`
		EventTime int64  `json:"event_time"`
		Event     struct {
			Type    string `json:"type"`
			User    string `json:"user"`
			Channel string `json:"channel"`
			TS      string `json:"ts"`
			BotID   string `json:"bot_id"`
			Subtype string `json:"subtype"`
			Tokens  struct {
				Bot []string `json:"bot"`
			} `json:"tokens"`
		} `json:"event"`
	}
	if json.Unmarshal(b, &envelope) != nil {
		failure(w, 400, "invalid_event")
		return
	}
	if envelope.Type == "url_verification" {
		if !text(envelope.Challenge, 1024) || (envelope.AppID != "" && envelope.AppID != s.config.AppID) {
			failure(w, 403, "denied")
			return
		}
		output(w, 200, map[string]string{"challenge": envelope.Challenge})
		return
	}
	if envelope.Type != "event_callback" || envelope.AppID != s.config.AppID || !id(envelope.TeamID) || !id(envelope.EventID) || envelope.EventTime <= 0 {
		failure(w, 403, "invalid_event")
		return
	}
	if envelope.Event.Type != "app_mention" && envelope.Event.Type != "app_uninstalled" && envelope.Event.Type != "tokens_revoked" {
		output(w, 200, map[string]string{"status": "ignored"})
		return
	}
	key := digest([]byte(s.config.AppID + "/" + envelope.TeamID + "/" + envelope.EventID))
	bodyHash := digest(b)
	e = s.store.Update(func(st *state) error {
		if previous, ok := st.Deliveries[key]; ok {
			if previous.BodySHA256 != bodyHash {
				return errDenied
			}
			return nil
		}
		now := s.now()
		for id, delivery := range st.Deliveries {
			if now.Sub(delivery.CreatedAt) > 7*24*time.Hour && delivery.Status != "pending" {
				delete(st.Deliveries, id)
			}
		}
		if len(st.Deliveries) >= 1000 {
			return errDenied
		}
		if envelope.Event.Type == "app_uninstalled" || envelope.Event.Type == "tokens_revoked" {
			grant, exists := st.Grants[envelope.TeamID]
			if envelope.Event.Type == "tokens_revoked" {
				affects := false
				for _, bot := range envelope.Event.Tokens.Bot {
					if bot == grant.BotUserID {
						affects = true
					}
				}
				if !affects {
					return nil
				}
			}
			if exists && !time.Unix(envelope.EventTime, 0).Before(grant.AuthorizedAt.Truncate(time.Second)) {
				grant.Status = "revoked"
				grant.AccessToken = ""
				grant.RefreshToken = ""
				grant.Version++
				st.Grants[envelope.TeamID] = grant
				for id, record := range st.Bindings {
					if record.Public.TeamID == envelope.TeamID && record.Public.Status != "disconnected" {
						record.Public.Status = "revoked"
						record.Public.AuthorizedAt = time.Unix(envelope.EventTime, 0)
						record.Public.Version++
						record.SessionDigest = ""
						st.Bindings[id] = record
					}
				}
			}
			st.Deliveries[key] = Delivery{ID: key, TeamID: envelope.TeamID, EventID: envelope.EventID, BodySHA256: bodyHash, Status: "lifecycle", EventType: envelope.Event.Type, OccurredAt: time.Unix(envelope.EventTime, 0), CreatedAt: now}
			return nil
		}
		if envelope.Event.BotID != "" || envelope.Event.Subtype != "" || !id(envelope.Event.User) || !id(envelope.Event.Channel) || !text(envelope.Event.TS, 64) {
			return nil
		}
		var chosen *bindingRecord
		for _, record := range st.Bindings {
			if record.Public.TeamID == envelope.TeamID && record.Public.ChannelID == envelope.Event.Channel && record.Public.Status == "active" && st.Grants[record.Public.TeamID].Status == "active" && !time.Unix(envelope.EventTime, 0).Before(record.Public.AuthorizedAt.Truncate(time.Second)) {
				copy := record
				if chosen != nil {
					return errDenied
				}
				chosen = &copy
			}
		}
		if chosen == nil {
			return nil
		}
		st.Deliveries[key] = Delivery{ID: key, BindingID: chosen.Public.ID, BindingVersion: chosen.Public.Version, TeamID: envelope.TeamID, EventID: envelope.EventID, BodySHA256: bodyHash, Payload: bytes.Clone(b), Status: "pending", EventType: envelope.Event.Type, OccurredAt: time.Unix(envelope.EventTime, 0), CreatedAt: now}
		return nil
	})
	if e != nil {
		failure(w, 503, "durable_acceptance_unavailable")
		return
	}
	output(w, 200, map[string]string{"status": "accepted"})
}
