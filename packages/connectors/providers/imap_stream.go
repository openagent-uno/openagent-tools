package providers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/emersion/go-imap"
)

const (
	imapMaxProtocolBytes     = 4 << 20
	imapMaxProtocolLineBytes = 64 << 10
)

var errIMAPStreamLimit = errors.New("IMAP response exceeds its protocol limit")

// openSecureIMAPStream establishes TLS before constructing go-imap's parser.
// go-imap v1 allocates a literal as soon as it sees {n}, before reading its
// bytes, and doesn't expose its Reader.MaxLiteralSize. A separate instance of
// the same parser validates complete decrypted responses with that cap enabled
// before the client's parser receives any bytes. Do not replace this with a
// line-suffix literal heuristic: status text, quotes and malformed atoms have
// different framing semantics, and the client continues after parse errors.
func openSecureIMAPStream(ctx context.Context, socket net.Conn, mode string, config *tls.Config) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	var prefix []byte
	switch mode {
	case "implicit_tls":
	case "starttls":
		if err := negotiateIMAPStartTLS(socket); err != nil {
			return nil, err
		}
		// STARTTLS consumes the server's initial greeting. Replay a local,
		// capability-free greeting so Client.New requests fresh TLS capabilities.
		// Never replay capabilities advertised on the unauthenticated channel.
		prefix = []byte("* OK OpenAgent TLS transport ready\r\n")
	default:
		return nil, errors.New("IMAP TLS mode is invalid")
	}
	secure := tls.Client(socket, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return newGuardedIMAPStream(secure, prefix), nil
}

func negotiateIMAPStartTLS(socket net.Conn) error {
	reader := bufio.NewReaderSize(io.LimitReader(socket, imapMaxProtocolLineBytes), imapMaxProtocolLineBytes)
	readLine := func() ([]string, error) {
		line, err := reader.ReadSlice('\n')
		if err != nil || !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, errors.New("IMAP STARTTLS response is invalid")
		}
		return strings.Fields(string(line)), nil
	}
	greeting, err := readLine()
	if err != nil || len(greeting) < 2 || greeting[0] != "*" || !strings.EqualFold(greeting[1], "OK") {
		return errors.New("IMAP STARTTLS greeting is invalid")
	}
	const tag = "gpstarttls"
	if _, err := io.WriteString(socket, tag+" STARTTLS\r\n"); err != nil {
		return err
	}
	for count := 0; count < 32; count++ {
		fields, err := readLine()
		if err != nil || len(fields) < 2 {
			return errors.New("IMAP STARTTLS response is invalid")
		}
		if fields[0] == tag {
			if !strings.EqualFold(fields[1], "OK") || reader.Buffered() != 0 {
				return errors.New("IMAP STARTTLS was not accepted cleanly")
			}
			return nil
		}
		if fields[0] != "*" || strings.EqualFold(fields[1], "BYE") {
			return errors.New("IMAP STARTTLS was rejected")
		}
	}
	return errors.New("IMAP STARTTLS response limit exceeded")
}

type guardedIMAPStream struct {
	net.Conn
	reader    *imapPreflightReader
	parser    *imap.Reader
	captured  bytes.Buffer
	pending   []byte
	remaining int64
	err       error
}

func newGuardedIMAPStream(conn net.Conn, prefix []byte) *guardedIMAPStream {
	s := &guardedIMAPStream{Conn: conn, remaining: imapMaxProtocolBytes}
	wire := io.LimitReader(io.MultiReader(bytes.NewReader(prefix), conn), imapMaxProtocolBytes)
	s.reader = &imapPreflightReader{reader: bufio.NewReaderSize(io.TeeReader(wire, &s.captured), imapMaxProtocolLineBytes)}
	s.parser = imap.NewReader(s.reader)
	s.parser.MaxLiteralSize = imapMaxMessageBytes + 1
	return s
}

func (s *guardedIMAPStream) fail(err error) (int, error) {
	s.err = err
	_ = s.Close()
	return 0, err
}

func (s *guardedIMAPStream) Close() error {
	// Do not wait for a malicious or abandoned peer to read TLS close_notify.
	// Closing the transport must immediately release the blocked IMAP reader.
	// tls.Conn.Close overrides the write deadline with its own five-second
	// grace period, so abort its owned transport directly on this JIT boundary.
	if secure, ok := s.Conn.(*tls.Conn); ok {
		return secure.NetConn().Close()
	}
	return s.Conn.Close()
}

func (s *guardedIMAPStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.err != nil {
		return 0, s.err
	}
	if s.remaining <= 0 {
		return s.fail(errIMAPStreamLimit)
	}
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		s.remaining -= int64(n)
		return n, nil
	}
	s.parser.MaxLiteralSize = uint32(min(s.remaining, imapMaxMessageBytes+1))
	if _, err := imap.ReadResp(s.parser); err != nil {
		if errors.Is(err, io.EOF) && s.captured.Len() == 0 {
			return s.fail(io.EOF)
		}
		// Parser errors can quote untrusted server text. Never expose them to
		// Client.New's default stderr logger or resume after an invalid response.
		return s.fail(errIMAPStreamLimit)
	}
	consumed := s.captured.Len() - s.reader.reader.Buffered()
	if consumed <= 0 || int64(consumed) > s.remaining {
		return s.fail(errIMAPStreamLimit)
	}
	// bufio may have read later responses, including an unsafe one. Keep that
	// read-ahead in captured (it will not pass through TeeReader twice), and
	// release only the exact byte prefix successfully consumed by ReadResp.
	s.pending = append([]byte(nil), s.captured.Next(consumed)...)
	return s.Read(p)
}

// Implement go-imap's reader contract without another buffer. Only Read is used
// for literal bytes; their size has already been checked by MaxLiteralSize.
// ReadRune and ReadString parse metadata and maintain a bounded line counter.
// UnreadRune restores that counter exactly when the parser looks ahead.
type imapPreflightReader struct {
	reader       *bufio.Reader
	lineBytes    int
	previousLine int
	canUnread    bool
	err          error
}

func (r *imapPreflightReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	r.canUnread = false
	return r.reader.Read(p)
}

func (r *imapPreflightReader) ReadRune() (rune, int, error) {
	if r.err != nil {
		return 0, 0, r.err
	}
	r.previousLine = r.lineBytes
	value, size, err := r.reader.ReadRune()
	r.canUnread = err == nil
	if err == nil {
		err = r.countMetadata(size, value == '\n')
	}
	return value, size, err
}

func (r *imapPreflightReader) UnreadRune() error {
	if r.err != nil {
		return r.err
	}
	if !r.canUnread {
		return errIMAPStreamLimit
	}
	if err := r.reader.UnreadRune(); err != nil {
		return err
	}
	r.lineBytes = r.previousLine
	r.canUnread = false
	return nil
}

func (r *imapPreflightReader) ReadString(delimiter byte) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	r.canUnread = false
	var result []byte
	for {
		value, err := r.reader.ReadByte()
		if err != nil {
			return string(result), err
		}
		if err := r.countMetadata(1, value == '\n'); err != nil {
			return "", err
		}
		result = append(result, value)
		if value == delimiter {
			return string(result), nil
		}
	}
}

func (r *imapPreflightReader) countMetadata(size int, newline bool) error {
	r.lineBytes += size
	if r.lineBytes > imapMaxProtocolLineBytes {
		r.err = errIMAPStreamLimit
		return r.err
	}
	if newline {
		r.lineBytes = 0
	}
	return nil
}
