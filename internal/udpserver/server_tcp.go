package udpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// tcpIdleTimeout closes a connection that sent no complete query for this
	// long.
	tcpIdleTimeout = 10 * time.Second
	// maxTCPConnsPerSource and maxTCPConns bound the connections one source
	// address and the whole server may hold.
	maxTCPConnsPerSource = 16
	maxTCPConns          = 256
	// maxTCPMessagesPerConn ends a connection that keeps asking: a resolver
	// reuses a connection for a while, it does not hold one forever.
	maxTCPMessagesPerConn = 4096
)

// tcpLimiter counts the open TCP connections of a server.
type tcpLimiter struct {
	mu       sync.Mutex
	total    int
	perAddr  map[netip.Addr]int
	perLimit int
	limit    int
}

func newTCPLimiter() *tcpLimiter {
	return &tcpLimiter{perAddr: make(map[netip.Addr]int), perLimit: maxTCPConnsPerSource, limit: maxTCPConns}
}

func (l *tcpLimiter) acquire(addr netip.Addr) bool {
	addr = addr.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.limit || l.perAddr[addr] >= l.perLimit {
		return false
	}
	l.total++
	l.perAddr[addr]++
	return true
}

func (l *tcpLimiter) release(addr netip.Addr) {
	addr = addr.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perAddr[addr] <= 1 {
		delete(l.perAddr, addr)
	} else {
		l.perAddr[addr]--
	}
}

// ServeTCP accepts DNS-over-TCP connections on ln until ctx ends or ln fails,
// and serves each with ServeTCPConn.
func (s *Server) ServeTCP(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.ServeTCPConn(ctx, conn)
		}()
	}
}

// ServeTCPConn serves one DNS-over-TCP connection (RFC 1035, a two-byte length
// before each message) and closes it when done. At most 16 connections per
// source address and 256 in all are served, an idle connection is closed
// after 10 seconds, and answers may be as long as the TCP frame allows
// (64 KiB). A query that gets no answer ends the connection.
func (s *Server) ServeTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	var src netip.AddrPort
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && addr != nil {
		src = addr.AddrPort()
	}
	if src.IsValid() {
		if !s.tcpLimiter.acquire(src.Addr()) {
			return
		}
		defer s.tcpLimiter.release(src.Addr())
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	var length [2]byte
	for messages := 0; messages < maxTCPMessagesPerConn; messages++ {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(length[:]))
		if size == 0 {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		response := s.HandleQuery(src, query, 0, true)
		if len(response) == 0 || len(response) > maxTCPMessage {
			return
		}
		out := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(out, uint16(len(response)))
		copy(out[2:], response)
		_ = conn.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}
