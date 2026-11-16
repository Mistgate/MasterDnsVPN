package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
)

// This file is the embedding API of the client (see package mgdns): streams are
// opened as in-process connections, with no SOCKS listener in between.

// ErrNoSession is returned when a stream or a DNS query is asked for while the
// client has no session.
var ErrNoSession = errors.New("the tunnel has no session")

// DialError is returned by OpenStream when the server refuses or fails the
// connect. Reply is the SOCKS5 reply code that describes the failure.
type DialError struct {
	Reply byte
}

func (e *DialError) Error() string {
	switch e.Reply {
	case SOCKS5_REPLY_RULESET_DENIED:
		return "connection refused by the server's ruleset"
	case SOCKS5_REPLY_NETWORK_UNREACHABLE:
		return "network unreachable"
	case SOCKS5_REPLY_HOST_UNREACHABLE:
		return "host unreachable"
	case SOCKS5_REPLY_CONNECTION_REFUSED:
		return "connection refused"
	case SOCKS5_REPLY_TTL_EXPIRED:
		return "connect timed out at the server"
	case SOCKS5_REPLY_ATYP_NOT_SUPPORTED:
		return "address type not supported"
	default:
		return "connect failed at the server"
	}
}

// ActiveStreams is the number of tunneled connections that are open.
func (c *Client) ActiveStreams() int {
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	count := 0
	for id, stream := range c.active_streams {
		if id != 0 && stream != nil {
			count++
		}
	}
	return count
}

// OpenStream connects host:port through the tunnel and returns the local end
// of the connection. The host is sent as given and resolved by the server, so
// a name never leaves this machine as a DNS query. It waits for the server's
// answer, for ctx, or for the connect timeout of the server, and fails with a
// *DialError when the server cannot connect.
func (c *Client) OpenStream(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if c == nil || !c.SessionReady() {
		return nil, ErrNoSession
	}
	var atyp byte
	var target []byte
	switch ip := net.ParseIP(host); {
	case ip != nil && ip.To4() != nil:
		atyp = SOCKS5_ATYP_IPV4
		target = ip.To4()
	case ip != nil:
		atyp = SOCKS5_ATYP_IPV6
		target = ip.To16()
	default:
		if host == "" || len(host) > 255 {
			return nil, fmt.Errorf("invalid host %q", host)
		}
		atyp = SOCKS5_ATYP_DOMAIN
		target = append([]byte{byte(len(host))}, host...)
	}
	targetPayload := append([]byte{atyp}, target...)
	targetPayload = binary.BigEndian.AppendUint16(targetPayload, port)

	streamID, ok := c.get_new_stream_id()
	if !ok {
		return nil, errors.New("no free stream id")
	}
	outer, inner := newStreamPipe()
	result := make(chan byte, 1)

	s := c.new_stream(streamID, inner, nil)
	if s == nil {
		_ = outer.Close()
		_ = inner.Close()
		return nil, errors.New("could not create a stream")
	}
	s.libResult = result
	s.LocalSocksVersion = SOCKS5_VERSION
	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		_ = outer.Close()
		return nil, errors.New("stream is not an ARQ stream")
	}
	if c.log != nil {
		c.log.Infof("\U0001F50C <green>New TCP CONNECT to <cyan>%s:%d</cyan>, Stream ID: <cyan>%d</cyan></green>", host, port, streamID)
	}

	fragments := fragmentPayload(targetPayload, c.syncedUploadMTU)
	total := uint8(len(fragments))
	for i, fragment := range fragments {
		arqObj.SendControlPacketWithTTL(
			Enums.PACKET_SOCKS5_SYN,
			0,
			uint8(i),
			total,
			fragment,
			Enums.DefaultPacketPriority(Enums.PACKET_SOCKS5_SYN),
			true,
			nil,
			120*time.Second,
		)
	}

	select {
	case reply := <-result:
		if reply != SOCKS5_REPLY_SUCCESS {
			_ = outer.Close()
			return nil, &DialError{Reply: reply}
		}
		return outer, nil
	case <-ctx.Done():
		c.handlePendingSOCKSLocalClose(streamID, "dial cancelled")
		_ = outer.Close()
		return nil, ctx.Err()
	}
}

// ResolveDNS sends a DNS query through the tunnel; the server resolves it. It
// returns the answer message, or an error when ctx ends first.
func (c *Client) ResolveDNS(ctx context.Context, query []byte) ([]byte, error) {
	if c == nil || !c.SessionReady() {
		return nil, ErrNoSession
	}
	answers := make(chan []byte, 1)
	respond := func(response []byte) {
		select {
		case answers <- response:
		default:
		}
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.ProcessDNSQuery(query, nil, respond) {
			select {
			case response := <-answers:
				return response, nil
			default:
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
		if !c.SessionReady() {
			return nil, ErrNoSession
		}
	}
}

// streamPipe is one end of an in-process connection that, unlike net.Pipe,
// can be half-closed: CloseWrite ends what the peer reads and leaves what the
// peer writes readable. It is made of two net.Pipes, one per direction.
type streamPipe struct {
	read  net.Conn // the end this side reads from
	write net.Conn // the end this side writes to
	// the ends of the two pipes that belong to the peer; kept so Close can
	// release both
	closeOnce sync.Once
}

var _ io.ReadWriteCloser = (*streamPipe)(nil)

func newStreamPipe() (outer, inner *streamPipe) {
	upRead, upWrite := net.Pipe()     // outer writes, inner reads
	downRead, downWrite := net.Pipe() // inner writes, outer reads
	outer = &streamPipe{read: downRead, write: upWrite}
	inner = &streamPipe{read: upRead, write: downWrite}
	return outer, inner
}

func (p *streamPipe) Read(b []byte) (int, error)  { return p.read.Read(b) }
func (p *streamPipe) Write(b []byte) (int, error) { return p.write.Write(b) }

// CloseWrite signals EOF to the peer's reads.
func (p *streamPipe) CloseWrite() error { return p.write.Close() }

// Close ends both directions.
func (p *streamPipe) Close() error {
	var err error
	p.closeOnce.Do(func() {
		err = p.write.Close()
		if e := p.read.Close(); err == nil {
			err = e
		}
	})
	return err
}

func (p *streamPipe) SetReadDeadline(t time.Time) error  { return p.read.SetReadDeadline(t) }
func (p *streamPipe) SetWriteDeadline(t time.Time) error { return p.write.SetWriteDeadline(t) }
func (p *streamPipe) SetDeadline(t time.Time) error {
	err := p.read.SetReadDeadline(t)
	if e := p.write.SetWriteDeadline(t); err == nil {
		err = e
	}
	return err
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "mgdns" }
func (pipeAddr) String() string  { return "mgdns" }

func (p *streamPipe) LocalAddr() net.Addr  { return pipeAddr{} }
func (p *streamPipe) RemoteAddr() net.Addr { return pipeAddr{} }
