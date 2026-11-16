package client

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestStreamPipeCarriesBytesBothWays(t *testing.T) {
	outer, inner := newStreamPipe()
	defer outer.Close()
	defer inner.Close()
	go func() { _, _ = outer.Write([]byte("up")) }()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(inner, buf); err != nil || string(buf) != "up" {
		t.Fatalf("inner read %q %v", buf, err)
	}
	go func() { _, _ = inner.Write([]byte("dn")) }()
	if _, err := io.ReadFull(outer, buf); err != nil || string(buf) != "dn" {
		t.Fatalf("outer read %q %v", buf, err)
	}
	var _ net.Conn = outer
}

// Half-close: the application ends its side and the tunnel's answer still arrives.
func TestStreamPipeHalfClose(t *testing.T) {
	outer, inner := newStreamPipe()
	defer outer.Close()
	defer inner.Close()
	if err := outer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := inner.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after CloseWrite the peer must read EOF, got %v", err)
	}
	go func() { _, _ = inner.Write([]byte("reply")) }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(outer, buf); err != nil || string(buf) != "reply" {
		t.Fatalf("the answer after a half-close: %q %v", buf, err)
	}
}

func TestStreamPipeCloseEndsBothDirections(t *testing.T) {
	outer, inner := newStreamPipe()
	if err := outer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := outer.Close(); err != nil {
		t.Fatalf("a second Close must be harmless: %v", err)
	}
	if _, err := inner.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the peer must read EOF, got %v", err)
	}
	if _, err := inner.Write([]byte("x")); err == nil {
		t.Fatal("the peer can still write to a closed connection")
	}
	if _, err := outer.Read(make([]byte, 1)); err == nil {
		t.Fatal("read on a closed connection succeeded")
	}
}

func TestStreamPipeDeadlines(t *testing.T) {
	outer, inner := newStreamPipe()
	defer outer.Close()
	defer inner.Close()
	if err := inner.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := inner.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected a deadline error, got %v", err)
	}
	if err := outer.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := outer.Write([]byte("nobody reads")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected a write deadline error, got %v", err)
	}
}

func TestDialErrorNamesTheReply(t *testing.T) {
	for reply, want := range map[byte]string{
		SOCKS5_REPLY_RULESET_DENIED:   "ruleset",
		SOCKS5_REPLY_HOST_UNREACHABLE: "host unreachable",
		SOCKS5_REPLY_TTL_EXPIRED:      "timed out",
		SOCKS5_REPLY_GENERAL_FAILURE:  "failed",
	} {
		if got := (&DialError{Reply: reply}).Error(); !contains(got, want) {
			t.Errorf("reply %d: %q does not mention %q", reply, got, want)
		}
	}
}

func contains(text, part string) bool {
	for i := 0; i+len(part) <= len(text); i++ {
		if text[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
