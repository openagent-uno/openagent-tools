package slackchannel

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
)

func clientFixtureIdentity(t *testing.T) auth.Identity {
	t.Helper()
	identity, err := auth.NewIdentity("fixture-host", "Fixture host")
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
func clientFixtureBinding(identity auth.Identity) Binding {
	return Binding{ID: "opaque-binding", Installation: identity.ID(), Recipient: Recipient{WorkspaceID: "workspace", SubjectID: "owner", AgentID: "agent"},
		AgentLabel: "Fixture agent", TeamID: "T12345678", ChannelID: "C12345678", Status: "pending", Version: 1, CreatedAt: time.Now().UTC()}
}

type clientRoundTripFunc func(*http.Request) (*http.Response, error)

func (f clientRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHostClientSignsExactMethodsPathsBodiesWithFreshNonces(t *testing.T) {
	identity := clientFixtureIdentity(t)
	binding := clientFixtureBinding(identity)
	var requests []string
	nonces := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		stamp, nonce := r.Header.Get("X-OpenAgent-Time"), r.Header.Get("X-OpenAgent-Nonce")
		message := r.Method + "\n" + r.URL.EscapedPath() + "\n" + r.URL.RawQuery + "\n" + stamp + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
		signature, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-OpenAgent-Signature"))
		if r.Header.Get("X-OpenAgent-Installation") != identity.ID() || stamp == "" || nonce == "" || nonces[nonce] || !ed25519.Verify(identity.PrivateKey.Public().(ed25519.PublicKey), []byte(message), signature) {
			t.Error("request signature or nonce does not bind exact route/body")
		}
		nonces[nonce] = true
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == Prefix+"/bindings":
			var input StartRequest
			if json.Unmarshal(body, &input) != nil || input.Recipient != binding.Recipient || input.TeamID != binding.TeamID || input.ChannelID != binding.ChannelID {
				t.Error("wrong signed start body")
			}
		case strings.HasSuffix(r.URL.Path, "/activate"), strings.HasSuffix(r.URL.Path, "/session"):
			if string(body) != "{}" {
				t.Errorf("action body must be exact empty object: %q", body)
			}
		default:
			if len(body) != 0 {
				t.Error("GET/DELETE unexpectedly carried a body")
			}
		}
		if strings.HasSuffix(r.URL.Path, "/session") {
			_ = json.NewEncoder(w).Encode(Session{Protocol: Protocol, BindingID: binding.ID, Token: "service-session-private", ExpiresAt: time.Now().UTC().Add(8 * time.Hour)})
		} else if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
		} else {
			_ = json.NewEncoder(w).Encode(binding)
		}
	}))
	defer server.Close()
	client := Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
	ctx := context.Background()
	if _, err := client.Start(ctx, StartRequest{Recipient: binding.Recipient, AgentLabel: binding.AgentLabel, TeamID: binding.TeamID, ChannelID: binding.ChannelID}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Status(ctx, binding.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Status(ctx, binding.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Activate(ctx, binding.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Session(ctx, binding.ID); err != nil {
		t.Fatal(err)
	}
	if err := client.Disconnect(ctx, binding.ID); err != nil {
		t.Fatal(err)
	}
	expected := []string{"POST " + Prefix + "/bindings", "GET " + Prefix + "/bindings/opaque-binding", "GET " + Prefix + "/bindings/opaque-binding", "POST " + Prefix + "/bindings/opaque-binding/activate", "POST " + Prefix + "/bindings/opaque-binding/session", "DELETE " + Prefix + "/bindings/opaque-binding"}
	if strings.Join(requests, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("wrong public routes: %v", requests)
	}
}

func TestHostClientBlocksRedirectsAndDoesNotRetryOrLeakRemoteBodies(t *testing.T) {
	identity := clientFixtureIdentity(t)
	calls, forwarded := 0, 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded++ }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", target.URL+"/?secret=PRIVATE_CANARY")
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, `{"error":"PRIVATE_CANARY"}`)
	}))
	defer server.Close()
	configured := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		t.Error("caller redirect policy must not execute")
		return nil
	}}
	client := Client{Origin: server.URL, Identity: identity, AllowLoopback: true, HTTP: configured}
	_, err := client.Activate(context.Background(), "opaque-binding")
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Status != 307 || remote.Code != "request_failed" || calls != 1 || forwarded != 0 || strings.Contains(fmt.Sprint(err), "PRIVATE_CANARY") {
		t.Fatalf("redirect/retry/redaction boundary failed: %v", err)
	}
}

func TestHostClientBoundsResponsesAndRejectsMalformedOrSecretFields(t *testing.T) {
	identity := clientFixtureIdentity(t)
	binding := clientFixtureBinding(identity)
	plain, _ := json.Marshal(binding)
	for _, mode := range []string{"oversize", "duplicate", "unknown", "trailing", "wrong-id", "wrong-installation"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat(" ", clientDocumentLimit+1))
				case "duplicate":
					_, _ = w.Write(append(append([]byte{}, plain[:len(plain)-1]...), []byte(`,"status":"active"}`)...))
				case "unknown":
					_, _ = w.Write(append(append([]byte{}, plain[:len(plain)-1]...), []byte(`,"access_token":"PRIVATE_CANARY"}`)...))
				case "trailing":
					_, _ = w.Write(append(append([]byte{}, plain...), []byte(` {}`)...))
				default:
					value := binding
					if mode == "wrong-id" {
						value.ID = "other-binding"
					} else {
						value.Installation = "other-host"
					}
					_ = json.NewEncoder(w).Encode(value)
				}
			}))
			defer server.Close()
			client := Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
			_, err := client.Status(context.Background(), binding.ID)
			if !errors.Is(err, ErrClientResponse) || strings.Contains(fmt.Sprint(err), "PRIVATE_CANARY") {
				t.Fatalf("unsafe response accepted/leaked: %v", err)
			}
		})
	}
}

func TestHostClientRejectsUnsafeOriginsIDsAndMissingIdentityBeforeNetwork(t *testing.T) {
	calls := 0
	transport := clientRoundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("must not reach network") })
	client := Client{Identity: clientFixtureIdentity(t), HTTP: &http.Client{Transport: transport}}
	for _, origin := range []string{"http://example.invalid", "http://127.0.0.1", "https://user:PRIVATE_CANARY@example.invalid", "https://example.invalid/path", "https://example.invalid?query=PRIVATE_CANARY", "https://example.invalid#fragment", "https://example.invalid?"} {
		client.Origin = origin
		if _, err := client.Status(context.Background(), "binding"); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("unsafe origin accepted: %v", err)
		}
	}
	client.Origin = "https://example.invalid"
	for _, id := range []string{"", "../other", "a/b", "a?secret=PRIVATE_CANARY", "a%2fb"} {
		if _, err := client.Session(context.Background(), id); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("unsafe binding ID accepted: %v", err)
		}
	}
	client.Identity = auth.Identity{}
	if err := client.Disconnect(context.Background(), "binding"); !errors.Is(err, auth.ErrDenied) {
		t.Errorf("missing identity accepted: %v", err)
	}
	if calls != 0 {
		t.Fatalf("invalid request reached network %d times", calls)
	}
}

func TestHostClientSessionIsBoundExpiringAndRedacted(t *testing.T) {
	identity := clientFixtureIdentity(t)
	for _, mode := range []string{"valid", "wrong-protocol", "wrong-binding", "expired", "overlong", "token-control"} {
		t.Run(mode, func(t *testing.T) {
			session := Session{Protocol: Protocol, BindingID: "binding", Token: "PRIVATE_CANARY", ExpiresAt: time.Now().UTC().Add(time.Hour)}
			switch mode {
			case "wrong-protocol":
				session.Protocol = "other/v1"
			case "wrong-binding":
				session.BindingID = "other"
			case "expired":
				session.ExpiresAt = time.Now().Add(-time.Second)
			case "overlong":
				session.ExpiresAt = time.Now().Add(9 * time.Hour)
			case "token-control":
				session.Token += "\n"
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v %v %#v", session, session, session, &session, &session), "PRIVATE_CANARY") {
				t.Fatal("session formatting leaked credential")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(session) }))
			defer server.Close()
			client := Client{Origin: server.URL, Identity: identity, AllowLoopback: true}
			value, err := client.Session(context.Background(), "binding")
			if mode == "valid" {
				if err != nil || value.Token != session.Token {
					t.Fatalf("valid service session rejected: %v", err)
				}
			} else if !errors.Is(err, ErrClientResponse) {
				t.Fatalf("invalid service session accepted: %v", err)
			}
		})
	}
}

func TestHostClientSetsBoundedDeadlineWithoutMutatingConfiguredClientAndRedactsTransportError(t *testing.T) {
	configured := &http.Client{Timeout: time.Hour}
	calls := 0
	configured.Transport = clientRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > clientTimeout || time.Until(deadline) <= 0 {
			t.Error("missing bounded request deadline")
		}
		return nil, errors.New("PRIVATE_CANARY https://secret.invalid/?token=PRIVATE_CANARY")
	})
	client := Client{Origin: "https://fixture.invalid", Identity: clientFixtureIdentity(t), HTTP: configured}
	_, err := client.Status(context.Background(), "binding")
	if !errors.Is(err, ErrClientTransport) || strings.Contains(fmt.Sprint(err), "PRIVATE_CANARY") || calls != 1 || configured.Timeout != time.Hour {
		t.Fatalf("transport boundary failed: %v", err)
	}
}
