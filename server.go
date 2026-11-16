package mgdns

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/udpserver"
)

// DialFunc connects a stream of a session. address is "host:port" with the host
// as the client sent it, a name or an address; the hook resolves names and is
// the only place that decides where a tunneled connection may go.
type DialFunc func(ctx context.Context, credentialID, network, address string) (net.Conn, error)

// ResolveFunc answers a DNS query that a session tunneled; query and the answer
// are complete DNS messages.
type ResolveFunc func(ctx context.Context, credentialID string, query []byte) ([]byte, error)

// SessionInfo describes a live session: the credential, the address of the
// resolver that carried its last query, its age and its counters.
type SessionInfo = udpserver.SessionInfo

// QueryStats are the counters of HandleQuery: refused, truncated, replayed and
// rate-limited queries.
type QueryStats = udpserver.QueryStats

// ServerConfig configures a Server. The zero value of a field means its
// default, given in the comment.
type ServerConfig struct {
	// Domains are the tunnel zones the server is authoritative for.
	Domains []string
	// NSName is the name of the zone's name server (the SOA mname and the NS
	// record of the apex), NSAddress the A record of the apex. Both optional.
	NSName    string
	NSAddress netip.Addr
	// CheckKey (at least 16 bytes) enables the delegation check name
	// _mgchk-<nonce>.<zone>, which answers hex(HMAC-SHA256(CheckKey, nonce)).
	CheckKey []byte
	// MinLabelLength is the shortest tunnel name that is processed (3).
	MinLabelLength int

	// MaxSessions is the number of sessions the server holds, at most 255 (64).
	MaxSessions int
	// MaxSessionsPerCredential: a further INIT closes the idlest session (2).
	MaxSessionsPerCredential int
	// MaxStreamsPerSession is the number of tunneled connections of a session (64).
	MaxStreamsPerSession int
	// RequestsPerSessionPerSecond is the query rate one session may sustain; a
	// burst of twice that is allowed (2000).
	RequestsPerSessionPerSecond int
	// ConnectTimeout bounds one Dial (20 s).
	ConnectTimeout time.Duration
	// SourceBytesPerSecond caps the UDP answer bytes per second sent to one /24
	// (/56 for IPv6); past it answers become empty TC answers (4 MiB).
	SourceBytesPerSecond int
	// ARQWindow is the largest ARQ window a client may use (512).
	ARQWindow int

	// Dial and ResolveDNS are the hooks; without them the server dials and
	// resolves itself (standalone use, see NewServerFromConfig).
	Dial       DialFunc
	ResolveDNS ResolveFunc

	// LogLevel is "debug", "info", "warn" or "error" ("error"); LogWriter
	// receives the log lines (nil: discarded).
	LogLevel  string
	LogWriter io.Writer
}

// Server is the tunnel's server side, without sockets: the host gives it DNS
// messages and sends back its answers.
type Server struct {
	inner *udpserver.Server
}

// NewServer builds a server. Start must be called before it serves sessions.
func NewServer(cfg ServerConfig) (*Server, error) {
	internal := config.DefaultServerConfig()
	internal.Domain = append([]string(nil), cfg.Domains...)
	internal.ZoneNSName = cfg.NSName
	if cfg.NSAddress.IsValid() {
		internal.ZoneAddress = cfg.NSAddress.String()
	}
	if len(cfg.CheckKey) > 0 {
		internal.ZoneCheckKey = hex.EncodeToString(cfg.CheckKey)
	}
	if cfg.MinLabelLength > 0 {
		internal.MinVPNLabelLength = cfg.MinLabelLength
	}
	if cfg.MaxSessions > 0 {
		internal.MaxAllowedClientActiveSessions = cfg.MaxSessions
	}
	if cfg.MaxSessionsPerCredential > 0 {
		internal.MaxSessionsPerCredential = cfg.MaxSessionsPerCredential
	}
	if cfg.MaxStreamsPerSession > 0 {
		internal.MaxAllowedClientActiveStreams = cfg.MaxStreamsPerSession
	}
	if cfg.RequestsPerSessionPerSecond > 0 {
		internal.MaxRequestsPerSessionPerSecond = cfg.RequestsPerSessionPerSecond
	}
	if cfg.ConnectTimeout > 0 {
		internal.SOCKSConnectTimeoutSecs = cfg.ConnectTimeout.Seconds()
	}
	if cfg.SourceBytesPerSecond > 0 {
		internal.SourceBytesPerSecond = cfg.SourceBytesPerSecond
	}
	if cfg.ARQWindow > 0 {
		internal.ClientMaxARQWindowSize = cfg.ARQWindow
		internal.ARQWindowSize = min(internal.ARQWindowSize, cfg.ARQWindow)
	}
	level := cfg.LogLevel
	if level == "" {
		level = "error"
	}
	internal.LogLevel = level
	internal.TCPEnabled = false
	finalized, err := config.FinalizeServerConfig(internal)
	if err != nil {
		return nil, err
	}
	if len(finalized.Domain) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	server := &Server{inner: udpserver.New(finalized, logger.NewWithWriter("mgdns server", level, cfg.LogWriter))}
	server.inner.SetHooks(udpserver.Hooks{Dial: cfg.Dial, ResolveDNS: cfg.ResolveDNS})
	return server, nil
}

// NewServerFromConfig wraps a server that was configured with the standalone
// configuration of the fork (a TOML file or flags). It is meant for the
// standalone binary; Serve then opens the sockets itself.
func NewServerFromConfig(cfg config.ServerConfig, log *logger.Logger) *Server {
	return &Server{inner: udpserver.New(cfg, log)}
}

// Start runs the background work (the cleanup of expired sessions and the
// workers that connect streams and resolve tunneled DNS). It opens no socket
// and stops with ctx.
func (s *Server) Start(ctx context.Context) { s.inner.Start(ctx) }

// Serve is the standalone mode: it opens the UDP (and, when enabled, TCP)
// sockets of the configuration, serves until ctx ends, and runs the background
// work itself; do not call Start as well.
func (s *Server) Serve(ctx context.Context) error { return s.inner.Run(ctx) }

// HandleQuery answers one DNS message that came over UDP or TCP from src. maxResp
// is the largest message the host's transport can carry (0: no limit of its
// own). An empty result means: send nothing. A UDP answer never exceeds what
// the requester advertised (512 bytes without EDNS) and an answer to a query
// that did not authenticate is never longer than the query; a longer one is
// replaced by an empty answer with TC set, which a resolver repeats over TCP.
func (s *Server) HandleQuery(src netip.AddrPort, packet []byte, maxResp int, tcp bool) []byte {
	return s.inner.HandleQuery(src, packet, maxResp, tcp)
}

// ServeTCPConn serves one DNS-over-TCP connection (RFC 1035 framing) and closes
// it: at most 16 connections per source and 256 in all, 10 seconds idle. Hosts
// that accept TCP themselves can pass each connection to it instead of doing
// the framing.
func (s *Server) ServeTCPConn(ctx context.Context, conn net.Conn) { s.inner.ServeTCPConn(ctx, conn) }

// SetCredentialIndex replaces the set of credentials atomically. Sessions of a
// credential that left the set, or whose key changed, are closed.
func (s *Server) SetCredentialIndex(index *CredentialIndex) {
	if index == nil || index.inner == nil {
		s.inner.SetCredentialIndex(nil)
		return
	}
	s.inner.SetCredentialIndex(index.inner)
}

// CloseCredential closes every session of the credential at once: its next
// query finds no session. It returns the number of sessions closed. The
// credential stays valid; remove it from the index to ban it.
func (s *Server) CloseCredential(credentialID string) int {
	return s.inner.CloseCredential(credentialID)
}

// Sessions lists the live sessions.
func (s *Server) Sessions() []SessionInfo { return s.inner.Sessions() }

// Stats returns the counters of HandleQuery.
func (s *Server) Stats() QueryStats { return s.inner.Stats() }

// SetHooks replaces the Dial and ResolveDNS hooks.
func (s *Server) SetHooks(dial DialFunc, resolve ResolveFunc) {
	s.inner.SetHooks(udpserver.Hooks{Dial: dial, ResolveDNS: resolve})
}

// DelegationCheckAnswer is what a node answers to _mgchk-<nonce>: the panel
// computes the same value to prove that a query reached the node.
func DelegationCheckAnswer(key []byte, nonce string) string {
	return udpserver.DelegationCheckAnswer(key, nonce)
}
