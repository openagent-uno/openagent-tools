package providers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type imapStreamMemoryConn struct {
	io.Reader
	closed bool
}

func (*imapStreamMemoryConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *imapStreamMemoryConn) Close() error                   { c.closed = true; return nil }
func (*imapStreamMemoryConn) LocalAddr() net.Addr              { return nil }
func (*imapStreamMemoryConn) RemoteAddr() net.Addr             { return nil }
func (*imapStreamMemoryConn) SetDeadline(time.Time) error      { return nil }
func (*imapStreamMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*imapStreamMemoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestIMAPStreamRejectsHugeLiteralBeforeExposingAnnouncement(t *testing.T) {
	for _, line := range []string{"* 1 FETCH (BODY[] {4294967295}\r\n", "* 1 FETCH (BODY[] {4294967295+}\r\n", fmt.Sprintf("* 1 FETCH (BODY[] {%d}\r\n", imapMaxMessageBytes+2), strings.Repeat("a", imapMaxProtocolLineBytes) + "\r\n"} {
		conn := &imapStreamMemoryConn{Reader: strings.NewReader(line)}
		stream := newGuardedIMAPStream(conn, nil)
		buffer := make([]byte, 4096)
		if n, err := stream.Read(buffer); err == nil || n != 0 || !conn.closed {
			t.Fatalf("unbounded announcement exposed: n=%d err=%v closed=%v", n, err, conn.closed)
		}
	}
}

func TestIMAPStreamDoesNotParseLiteralContentsAsProtocol(t *testing.T) {
	literal := []byte("literal contains {4294967295}\r\nnot a protocol marker")
	wire := append([]byte(fmt.Sprintf("* 1 FETCH (BODY[] {%d+}\r\n", len(literal))), literal...)
	wire = append(wire, []byte(")\r\nA1 OK done\r\n")...)
	conn := &imapStreamMemoryConn{Reader: bytes.NewReader(wire)}
	stream := newGuardedIMAPStream(conn, nil)
	var actual bytes.Buffer
	buffer := make([]byte, 3)
	for {
		n, err := stream.Read(buffer)
		actual.Write(buffer[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(actual.Bytes(), wire) {
		t.Fatal("bounded literal framing corrupted bytes")
	}
}

func TestIMAPStreamRejectsLiteralBeyondRemainingBudget(t *testing.T) {
	conn := &imapStreamMemoryConn{Reader: strings.NewReader("* 1 FETCH (BODY[] {100}\r\n")}
	stream := newGuardedIMAPStream(conn, nil)
	stream.remaining = 30
	if n, err := stream.Read(make([]byte, 1024)); n != 0 || !errors.Is(err, errIMAPStreamLimit) {
		t.Fatalf("literal exceeds total budget: n=%d err=%v", n, err)
	}
}

func TestIMAPStreamFreeTextCannotHideNextHugeLiteral(t *testing.T) {
	// Deliberately exercise only our capped pre-parser, never Client.New's
	// uncapped parser against these hostile announcements.
	for _, prefix := range []string{
		"* OK ready {1000}\r\n", "* NO refused {1000}\r\n", "* BAD invalid {1000}\r\n",
		"* PREAUTH ready {1000}\r\n", "* BYE finished {1000}\r\n",
		"A1 OK complete {1000}\r\n", "+ continue {1000}\r\n",
		"* OK [CAPABILITY IMAP4rev1] ready {1000}\r\n",
		"* X BODY[weird{1000}\r\n",
	} {
		t.Run(strings.TrimSpace(prefix), func(t *testing.T) {
			wire := prefix + "* 1 FETCH (BODY[] {4294967295}\r\n"
			conn := &imapStreamMemoryConn{Reader: strings.NewReader(wire)}
			stream := newGuardedIMAPStream(conn, nil)
			buffer := make([]byte, len(wire)+1)
			n, err := stream.Read(buffer)
			if err != nil || string(buffer[:n]) != prefix {
				t.Fatalf("preflight corrupted a complete response: n=%d err=%v", n, err)
			}
			for range 2 {
				if n, err := stream.Read(buffer); n != 0 || !errors.Is(err, errIMAPStreamLimit) || !conn.closed {
					t.Fatalf("free text desynchronized literal guard: n=%d err=%v closed=%v", n, err, conn.closed)
				}
			}
		})
	}
}

func TestIMAPStreamMalformedResponseFailsBeforeAnyBytesEscape(t *testing.T) {
	for _, malformed := range []string{
		"* X atom{1000}\r\n",
		"* X \"unclosed{1000}\r\n",
		"* X \"bad\\q\" {1000}\r\n",
		"* X atom] {1000}\r\n",
		"* X (atom {0}\r\n", // A literal does not make an unfinished list safe.
		"* X {bad-private-server-data}\r\n",
	} {
		conn := &imapStreamMemoryConn{Reader: strings.NewReader(malformed + "* 1 FETCH (BODY[] {4294967295}\r\n")}
		stream := newGuardedIMAPStream(conn, nil)
		for range 2 {
			if n, err := stream.Read(make([]byte, 4096)); n != 0 || err != errIMAPStreamLimit || !conn.closed {
				t.Fatalf("invalid response leaked bytes or a raw parser error: n=%d err=%v closed=%v", n, err, conn.closed)
			}
		}
	}
}

func TestIMAPStreamPreflightPreservesReadAheadAndMultipleLiterals(t *testing.T) {
	wire := "* OK ready\r\n* LIST () \"/\" {5}\r\nINBOX\r\n" +
		"* 1 FETCH (UID 1 BODY[] {3}\r\na\nb ENVELOPE (\"date\" {7}\r\nsubject NIL NIL NIL NIL NIL NIL NIL NIL))\r\n" +
		"A1 OK finished\r\n"
	for _, readSize := range []int{1, 17, 65536} {
		stream := newGuardedIMAPStream(&imapStreamMemoryConn{Reader: strings.NewReader(wire)}, nil)
		var actual bytes.Buffer
		buffer := make([]byte, readSize)
		for {
			n, err := stream.Read(buffer)
			actual.Write(buffer[:n])
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("valid multi-response/literal framing rejected: %v", err)
			}
		}
		if actual.String() != wire {
			t.Fatalf("read-ahead corrupted responses at read size %d", readSize)
		}
	}
}

func TestIMAPStreamPreflightBoundsMetadataButNotOpaqueLiteralLines(t *testing.T) {
	for _, prefix := range []string{"* OK ", "* X \""} {
		stream := newGuardedIMAPStream(&imapStreamMemoryConn{Reader: strings.NewReader(prefix + strings.Repeat("a", imapMaxProtocolLineBytes) + "\r\n")}, nil)
		if n, err := stream.Read(make([]byte, 4096)); n != 0 || err != errIMAPStreamLimit {
			t.Fatalf("oversize metadata exposed: n=%d err=%v", n, err)
		}
	}
	literal := strings.Repeat("a", imapMaxProtocolLineBytes+1)
	wire := fmt.Sprintf("* 1 FETCH (BODY[] {%d}\r\n%s)\r\n", len(literal), literal)
	stream := newGuardedIMAPStream(&imapStreamMemoryConn{Reader: strings.NewReader(wire)}, nil)
	actual, err := io.ReadAll(stream)
	if err != nil || string(actual) != wire {
		t.Fatalf("valid bounded opaque literal was counted as metadata: err=%v", err)
	}
}

func TestSecureIMAPStreamGuardsImplicitTLSAndSTARTTLSPlaintext(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	cert := fixture.Certificate()
	fixture.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, mode := range []string{"implicit_tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			_ = clientSide.SetDeadline(deadline)
			_ = serverSide.SetDeadline(deadline)
			done := make(chan error, 1)
			go func() {
				if mode == "starttls" {
					if _, err := io.WriteString(serverSide, "* OK [CAPABILITY IMAP4rev1 STARTTLS] insecure greeting\r\n"); err != nil {
						done <- err
						return
					}
					line, err := bufio.NewReader(serverSide).ReadString('\n')
					if err != nil || line != "gpstarttls STARTTLS\r\n" {
						done <- fmt.Errorf("STARTTLS command mismatch: %v", err)
						return
					}
					if _, err := io.WriteString(serverSide, "gpstarttls OK begin TLS\r\n"); err != nil {
						done <- err
						return
					}
				}
				secure := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := secure.HandshakeContext(ctx); err != nil {
					done <- err
					return
				}
				_, err := io.WriteString(secure, "* 1 FETCH (BODY[] {4294967295}\r\n")
				done <- err
			}()
			stream, err := openSecureIMAPStream(ctx, clientSide, mode, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "starttls" {
				prefix := make([]byte, len("* OK OpenAgent TLS transport ready\r\n"))
				if _, err := io.ReadFull(stream, prefix); err != nil || bytes.Contains(prefix, []byte("CAPABILITY")) {
					t.Fatal("STARTTLS did not replay capability-free greeting")
				}
			}
			if n, err := stream.Read(make([]byte, 4096)); n != 0 || !errors.Is(err, errIMAPStreamLimit) {
				t.Fatalf("decrypted huge literal reached parser: n=%d err=%v", n, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIMAPSTARTTLSRejectsDenialAndOversizedGreeting(t *testing.T) {
	for _, greeting := range []string{"* PREAUTH unsafe\r\n", strings.Repeat("a", imapMaxProtocolLineBytes) + "\r\n"} {
		conn := &imapStreamMemoryConn{Reader: strings.NewReader(greeting)}
		if negotiateIMAPStartTLS(conn) == nil {
			t.Fatal("unsafe pre-TLS greeting accepted")
		}
	}
	conn := &imapStreamMemoryConn{Reader: strings.NewReader("* OK ready\r\ngpstarttls NO no TLS\r\n")}
	if negotiateIMAPStartTLS(conn) == nil {
		t.Fatal("server TLS refusal accepted")
	}
}
