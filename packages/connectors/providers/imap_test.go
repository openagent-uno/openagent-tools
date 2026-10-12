package providers

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

func imapReadInvocation(t *testing.T, a *imapAdapter, name, args string) domain.Invocation {
	t.Helper()
	bundle := base64.RawURLEncoding.EncodeToString([]byte(`{"imap_password":"test-imap-password","smtp_password":"test-smtp-password"}`))
	credential, err := domain.NewCredential(domain.CredentialAPIToken, "gp_imap_v1."+bundle, "Authorization", "Bearer", "v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	var operation domain.Operation
	for _, op := range a.Operations() {
		if op.Name == name {
			operation = op
		}
	}
	return domain.Invocation{Principal: domain.Principal{WorkspaceID: "workspace-one"}, Connection: domain.Connection{ID: "connection-one", WorkspaceID: "workspace-one", Provider: "imap_smtp", Capability: domain.Outreach, Enabled: true, Config: json.RawMessage(`{"imap_host":"example.com","imap_port":993,"username":"user@example.com","mailbox":"INBOX","tls_mode":"implicit_tls","smtp_host":"example.com","smtp_port":465,"smtp_tls_mode":"implicit_tls"}`)}, Credential: credential, Operation: operation, Arguments: json.RawMessage(args)}
}

func imapReadTestServer(t *testing.T, mode string) (*imapAdapter, *[]string, *sync.Mutex) {
	t.Helper()
	certServer := httptest.NewTLSServer(nil)
	t.Cleanup(certServer.Close)
	pool := x509.NewCertPool()
	pool.AddCert(certServer.Certificate())
	commands := []string{}
	mu := new(sync.Mutex)
	a := newIMAPAdapter()
	a.tlsConfig = func(string) *tls.Config { return &tls.Config{RootCAs: pool} }
	a.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		go func() {
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			var socket net.Conn = server
			if mode != "starttls" {
				secure := tls.Server(server, certServer.TLS)
				if secure.Handshake() != nil {
					return
				}
				socket = secure
			}
			reader := bufio.NewReader(socket)
			fmt.Fprint(socket, "* OK [CAPABILITY IMAP4rev1 STARTTLS] test ready\r\n")
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
				if len(parts) != 2 {
					return
				}
				tag, command := parts[0], parts[1]
				mu.Lock()
				commands = append(commands, command)
				mu.Unlock()
				switch {
				case command == "STARTTLS":
					fmt.Fprintf(socket, "%s OK Start TLS\r\n", tag)
					secure := tls.Server(server, certServer.TLS)
					if secure.Handshake() != nil {
						return
					}
					socket = secure
					reader = bufio.NewReader(socket)
					continue
				case command == "CAPABILITY":
					fmt.Fprint(socket, "* CAPABILITY IMAP4rev1\r\n")
				case strings.HasPrefix(command, "LOGIN "):
					if !strings.Contains(command, "test-imap-password") {
						return
					}
				case strings.HasPrefix(command, "EXAMINE "):
					fmt.Fprint(socket, "* 2 EXISTS\r\n* OK [UIDVALIDITY 9] valid\r\n* OK [UIDNEXT 3] next\r\n")
				case strings.HasPrefix(command, "UID SEARCH "):
					fmt.Fprint(socket, "* SEARCH 1 2\r\n")
				case strings.HasPrefix(command, "UID FETCH "):
					uid := strings.Fields(command)[2]
					if strings.Contains(command, "BODY.PEEK[]") {
						body := "Subject: Hello\r\n\r\nTest message\r\n"
						fmt.Fprintf(socket, "* 2 FETCH (UID %s RFC822.SIZE %d BODY[]<0> {%d}\r\n%s)\r\n", uid, len(body), len(body), body)
					} else {
						fmt.Fprintf(socket, "* 2 FETCH (UID %s RFC822.SIZE 32 ENVELOPE (NIL \"Hello\" NIL NIL NIL NIL NIL NIL NIL NIL) FLAGS ())\r\n", uid)
					}
				default:
					fmt.Fprintf(socket, "%s BAD unexpected\r\n", tag)
					continue
				}
				fmt.Fprintf(socket, "%s OK completed\r\n", tag)
			}
		}()
		return client, nil
	}
	return a, &commands, mu
}

func TestIMAPListsAndReadsWithoutMarkingSeen(t *testing.T) {
	for _, mode := range []string{"implicit_tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			a, commands, mu := imapReadTestServer(t, mode)
			for _, name := range []string{"outreach.imap.mailboxes.list", "outreach.imap.messages.list", "outreach.imap.messages.get"} {
				args := "{}"
				if strings.HasSuffix(name, "messages.get") {
					args = `{"uid":2,"uid_validity":9}`
				}
				input := imapReadInvocation(t, a, name, args)
				if mode == "starttls" {
					input.Connection.Config = json.RawMessage(strings.ReplaceAll(strings.ReplaceAll(string(input.Connection.Config), `"imap_port":993`, `"imap_port":143`), `"tls_mode":"implicit_tls"`, `"tls_mode":"starttls"`))
				}
				result, err := a.Invoke(context.Background(), input)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				encoded, _ := json.Marshal(result)
				if strings.Contains(string(encoded), "test-imap-password") {
					t.Fatal("credential leaked")
				}
				if strings.HasSuffix(name, "messages.get") && !strings.Contains(string(encoded), "Test message") {
					t.Fatalf("missing body: %s", encoded)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			joined := strings.Join(*commands, "\n")
			if strings.Contains(joined, "SELECT ") || strings.Contains(joined, "STORE ") {
				t.Fatal("mailbox modified")
			}
			if !strings.Contains(joined, "EXAMINE ") || !strings.Contains(joined, "BODY.PEEK[]") {
				t.Fatalf("missing readonly primitives: %s", joined)
			}
		})
	}
}

func TestIMAPRejectsUnsafeScopeArgumentsAndUIDValidity(t *testing.T) {
	a := newIMAPAdapter()
	a.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("invalid input reached network")
		return nil, errors.New("no network")
	}
	for _, args := range []string{`{"host":"elsewhere.example.com"}`, `{"mailbox":"Other"}`, `{"connection_id":"another-connection"}`, `{"limit":51}`, `{"limit":null}`, `{"before_uid":1}`, `{"uid":1}`, `{"before_uid":null}`, `null`, `{} {}`} {
		if _, err := a.Invoke(context.Background(), imapReadInvocation(t, a, "outreach.imap.messages.list", args)); err == nil {
			t.Errorf("accepted %s", args)
		}
	}
	input := imapReadInvocation(t, a, "outreach.imap.messages.get", `{"uid":1,"uid_validity":9}`)
	input.Principal.WorkspaceID = "another-workspace"
	if _, err := a.Invoke(context.Background(), input); !errors.Is(err, domain.ErrDenied) {
		t.Fatalf("scope: %v", err)
	}
	a, _, _ = imapReadTestServer(t, "implicit_tls")
	if _, err := a.Invoke(context.Background(), imapReadInvocation(t, a, "outreach.imap.messages.get", `{"uid":1,"uid_validity":8}`)); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale UIDVALIDITY: %v", err)
	}
}

func TestIMAPAcceptsOnlyExactServerInjectedConnection(t *testing.T) {
	a, _, _ := imapReadTestServer(t, "implicit_tls")
	for _, name := range []string{"outreach.imap.mailboxes.list", "outreach.imap.messages.list", "outreach.imap.messages.get"} {
		args := `{"connection_id":"connection-one"}`
		if strings.HasSuffix(name, "messages.get") {
			args = `{"connection_id":"connection-one","uid":2,"uid_validity":9}`
		}
		input := imapReadInvocation(t, a, name, args)
		if _, err := a.Preview(input); err != nil {
			t.Fatalf("%s preview: %v", name, err)
		}
		if _, err := a.Invoke(context.Background(), input); err != nil {
			t.Fatalf("%s invoke: %v", name, err)
		}
	}
}

func TestIMAPPublicAddressPolicy(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "::1", "fd00::1", "::ffff:127.0.0.1", "64:ff9b::808:808", "2002:7f00:1::1"} {
		if publicIMAPAddress(netip.MustParseAddr(ip)) {
			t.Errorf("accepted %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIMAPAddress(netip.MustParseAddr(ip)) {
			t.Errorf("rejected public %s", ip)
		}
	}
	for _, host := range []string{"localhost", "127.0.0.1", "foo.test:443", "foo.test/path", "foo.test\r\nHOST evil", "foo..test"} {
		if validIMAPHost(host) {
			t.Errorf("accepted %s", host)
		}
	}
}

func TestMailProxyCONNECTPinsIPAndPreservesEarlyGreeting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "8.8.8.8:993" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected CONNECT target/credentials")
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n* OK early greeting\r\n")
	}))
	defer server.Close()
	proxy, _ := url.Parse(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialMailProxy(ctx, "8.8.8.8:993", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "* OK early greeting\r\n" {
		t.Fatalf("buffered greeting lost: %q %v", data, err)
	}
}
