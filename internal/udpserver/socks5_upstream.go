// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/logger"
)

type upstreamSOCKS5Error struct {
	packetType uint8
	err        error
}

type blockedSOCKSTargetError struct {
	host string
}

type socks5FragmentKey struct {
	sessionID   uint8
	streamID    uint16
	sequenceNum uint16
}

func (e *upstreamSOCKS5Error) Error() string {
	if e == nil || e.err == nil {
		return "upstream socks5 error"
	}
	return e.err.Error()
}

func (e *upstreamSOCKS5Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (e *blockedSOCKSTargetError) Error() string {
	if e == nil || e.host == "" {
		return "blocked socks target"
	}
	return fmt.Sprintf("blocked socks target: %s", e.host)
}

func (s *Server) dialSOCKSStreamTarget(host string, port uint16) (net.Conn, error) {
	return s.dialSOCKSStreamTargetContext(context.Background(), "", host, port)
}

// dialSOCKSStreamTargetContext connects a stream of the session of a
// credential to host:port. The target comes from the client and is checked
// here before anything is dialed; the dialer (the Dial hook, or this package's
// own) decides what a name resolves to.
func (s *Server) dialSOCKSStreamTargetContext(ctx context.Context, credentialID string, host string, port uint16) (net.Conn, error) {
	if s == nil {
		return nil, &upstreamSOCKS5Error{err: errors.New("server unavailable")}
	}

	if err := validateSOCKSTargetHost(host); err != nil {
		return nil, err
	}

	return s.dialTCPTargetContext(ctx, credentialID, net.JoinHostPort(host, strconv.Itoa(int(port))))
}

// validateSOCKSTargetHost is the first of two checks of a target host: it
// rejects empty names, localhost and address literals that are not public
// unicast addresses. A name that resolves to a private address passes it; the
// standalone dialer rejects that after resolution (see controlBlockedAddress).
func validateSOCKSTargetHost(host string) error {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return &blockedSOCKSTargetError{host: host}
	}

	lower := strings.ToLower(trimmed)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return &blockedSOCKSTargetError{host: host}
	}

	ip := net.ParseIP(trimmed)
	if ip == nil {
		return nil
	}
	if blockedTargetIP(ip) {
		return &blockedSOCKSTargetError{host: host}
	}
	return nil
}

// blockedTargetIP reports whether a stream may not be connected to ip: anything
// that is not a public unicast address, and the shared and benchmarking ranges.
func blockedTargetIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() {
		return true
	}

	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return true
		}
	}
	return false
}

// controlBlockedAddress is the second check, made by the standalone dialer for
// every connection attempt after the name was resolved: an address that is
// private, loopback or link local is refused, so a name that points into the
// server's own network cannot be used to reach it. A host that supplies a Dial
// hook makes this decision itself.
func controlBlockedAddress(network, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return &blockedSOCKSTargetError{host: address}
	}
	if blockedTargetIP(net.IP(addrPort.Addr().Unmap().AsSlice())) {
		return &blockedSOCKSTargetError{host: addrPort.Addr().String()}
	}
	return nil
}

func (s *Server) dialTCPTarget(address string) (net.Conn, error) {
	return s.dialTCPTargetContext(context.Background(), "", address)
}

// dialTCPTargetContext dials a target that a client chose: the standalone
// dialer refuses private addresses after resolution.
func (s *Server) dialTCPTargetContext(ctx context.Context, credentialID string, address string) (net.Conn, error) {
	return s.dialTargetContext(ctx, credentialID, address, true)
}

// dialForwardContext dials the fixed forward target of PROTOCOL_TYPE "TCP",
// which the operator configured and which may well be local.
func (s *Server) dialForwardContext(ctx context.Context, credentialID string, address string) (net.Conn, error) {
	return s.dialTargetContext(ctx, credentialID, address, false)
}

func (s *Server) dialTargetContext(ctx context.Context, credentialID string, address string, restrict bool) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := s.socksConnectTimeout
	if timeout <= 0 {
		timeout = s.cfg.SOCKSConnectTimeout()
	}
	if deadline, ok := ctx.Deadline(); ok {
		untilDeadline := time.Until(deadline)
		if untilDeadline > 0 && (timeout <= 0 || untilDeadline < timeout) {
			timeout = untilDeadline
		}
	}
	startedAt := logger.NowUnixNano()

	hooks := s.hooks.Load()
	if hooks == nil || hooks.Dial == nil {
		dialer := net.Dialer{Timeout: timeout}
		if restrict {
			dialer.Control = controlBlockedAddress
		}
		return dialer.DialContext(ctx, "tcp", address)
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)
	go func() {
		conn, err := hooks.Dial(dialCtx, credentialID, "tcp", address)
		resultCh <- dialResult{conn: conn, err: err}
	}()
	select {
	case <-dialCtx.Done():
		// The hook did not return in time (or ignored the context): give up on
		// it and close whatever it returns later.
		go func() {
			result := <-resultCh
			cancel()
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.DeadlineExceeded
	case result := <-resultCh:
		cancel()
		if s != nil && s.log != nil {
			s.log.Debugf(
				"DEFER upstream-connect-finish | address=%s | dur_ms=%d | err=%v",
				address,
				(logger.NowUnixNano()-startedAt)/1_000_000,
				result.err,
			)
		}
		return result.conn, result.err
	}
}

func (s *Server) collectSOCKS5SynFragments(sessionID uint8, streamID uint16, sequenceNum uint16, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time) ([]byte, bool, bool) {
	if totalFragments == 0 {
		totalFragments = 1
	}

	assembled, ready, completed := s.socks5Fragments.Collect(
		socks5FragmentKey{
			sessionID:   sessionID,
			streamID:    streamID,
			sequenceNum: sequenceNum,
		},
		payload,
		fragmentID,
		totalFragments,
		now,
		s.dnsFragmentTimeout,
	)

	return assembled, ready, completed
}

func (s *Server) purgeSOCKS5SynFragments(now time.Time) {
	if s == nil || s.socks5Fragments == nil {
		return
	}
	s.socks5Fragments.Purge(now, s.dnsFragmentTimeout)
}

func (s *Server) removeSOCKS5SynFragmentsForSession(sessionID uint8) {
	if s == nil || s.socks5Fragments == nil || sessionID == 0 {
		return
	}
	s.socks5Fragments.RemoveIf(func(key socks5FragmentKey) bool {
		return key.sessionID == sessionID
	})
}

func (s *Server) removeSOCKS5SynFragmentsForStream(sessionID uint8, streamID uint16) {
	if s == nil || s.socks5Fragments == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.socks5Fragments.RemoveIf(func(key socks5FragmentKey) bool {
		return key.sessionID == sessionID && key.streamID == streamID
	})
}
