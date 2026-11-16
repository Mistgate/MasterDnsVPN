package udpserver

import (
	"context"
	"net"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
)

// Hooks are the places where a host takes over what the server would otherwise
// do on its own. Both receive the id of the credential whose session asked, so
// that the host can account for and limit what it carries.
type Hooks struct {
	// Dial connects a stream of a session to address ("host:port"; the host may
	// be a name, which the hook resolves). When nil, the server dials with a
	// dialer that refuses private, loopback and link-local addresses after
	// resolution.
	Dial func(ctx context.Context, credentialID, network, address string) (net.Conn, error)
	// ResolveDNS answers a DNS query that a session tunneled. When nil, the
	// server asks DNS_UPSTREAM_SERVERS.
	ResolveDNS func(ctx context.Context, credentialID string, query []byte) ([]byte, error)
}

// SetHooks installs the hooks. It may be called while the server runs.
func (s *Server) SetHooks(hooks Hooks) {
	copied := hooks
	s.hooks.Store(&copied)
}

// dnsUpstreamBufferSize holds one DNS answer from an upstream server; an
// answer that fills it is treated as failed.
const dnsUpstreamBufferSize = 4096

// buildInZoneNoData is the empty authoritative answer given to queries that
// authenticated but carry nothing to answer with: a repeat, a rate-limited
// frame, a packet the session cannot use. It is never longer than the query.
func (s *Server) buildInZoneNoData(packet []byte, parsed DnsParser.LitePacket) []byte {
	response, err := DnsParser.BuildResponse(packet, parsed, DnsParser.Response{Authoritative: true})
	if err != nil {
		return nil
	}
	return response
}
