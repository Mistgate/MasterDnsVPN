package udpserver

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
)

// maxTCPMessage is the largest DNS message a TCP frame can carry (RFC 1035).
const maxTCPMessage = 65535

// queryContext carries what one query learns on its way through the handlers,
// so that HandleQuery can decide how large an answer it may send.
type queryContext struct {
	src     netip.AddrPort
	tcp     bool
	maxResp int

	parsed    DnsParser.LitePacket
	hasParsed bool

	// authenticated is set once an AEAD tag, a key-bound INIT or a key-bound
	// probe verified. Only an authenticated query may receive an answer longer
	// than itself.
	authenticated bool
	// inZone is set for names inside a served zone (the TC answer is then
	// authoritative too).
	inZone bool

	session    *sessionRecord
	counter    uint32
	hasCounter bool
}

// QueryStats counts what HandleQuery did. All counters only grow.
type QueryStats struct {
	Queries      uint64 // every packet given to HandleQuery
	Refused      uint64 // REFUSED: names outside every served zone
	Truncated    uint64 // answers replaced by an empty TC=1 answer
	Replays      uint64 // authenticated frames dropped by the replay window
	CacheServed  uint64 // replayed frames answered from the answer cache
	RateLimited  uint64 // frames dropped by the per-session request limit
	ProbeLimited uint64 // probes refused by the per-credential budget or replay
	Silent       uint64 // packets that got no answer at all
}

type serverStats struct {
	queries, refused, truncated, replays, cacheServed, rateLimited, probeLimited, silent atomic.Uint64
}

// Stats returns a snapshot of the query counters.
func (s *Server) Stats() QueryStats {
	return QueryStats{
		Queries:      s.stats.queries.Load(),
		Refused:      s.stats.refused.Load(),
		Truncated:    s.stats.truncated.Load(),
		Replays:      s.stats.replays.Load(),
		CacheServed:  s.stats.cacheServed.Load(),
		RateLimited:  s.stats.rateLimited.Load(),
		ProbeLimited: s.stats.probeLimited.Load(),
		Silent:       s.stats.silent.Load(),
	}
}

// HandleQuery answers one DNS message that arrived over UDP or TCP. The caller
// owns the sockets: src is the peer, maxResp the largest message its transport
// can carry (0 means no limit beyond the DNS ones), tcp whether the message
// came in a TCP frame. A nil or empty result means "send nothing".
//
// UDP answers never exceed the requester's EDNS size (512 without OPT), and an
// answer to a query that did not authenticate is never longer than the query;
// anything longer becomes an empty answer with TC set, which a real resolver
// retries over TCP. The TCP path has no size limit below 65535.
func (s *Server) HandleQuery(src netip.AddrPort, packet []byte, maxResp int, tcp bool) (response []byte) {
	if s == nil {
		return nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.log != nil {
				s.log.Errorf("\U0001F4A5 <red>Packet Handler Panic Recovered, <yellow>%v</yellow></red>", recovered)
			}
			response = nil
		}
	}()
	s.stats.queries.Add(1)
	qc := &queryContext{src: src, tcp: tcp, maxResp: maxResp}
	response = s.handlePacketCtx(qc, packet)
	response = s.finalizeResponse(qc, packet, response)
	if len(response) == 0 {
		s.stats.silent.Add(1)
	}
	if qc.session != nil {
		qc.session.rxQueries.Add(1)
		qc.session.rxBytes.Add(uint64(len(packet)))
		qc.session.txBytes.Add(uint64(len(response)))
	}
	return response
}

// responseLimit is the largest answer this query may get.
func (qc *queryContext) responseLimit(request []byte) int {
	if qc.tcp {
		limit := maxTCPMessage
		if qc.maxResp > 0 && qc.maxResp < limit {
			limit = qc.maxResp
		}
		return limit
	}
	limit := DnsParser.MinUDPPayload
	if qc.hasParsed {
		limit = DnsParser.RequestEDNS(request, qc.parsed).UDPLimit()
	}
	if qc.maxResp > 0 && qc.maxResp < limit {
		limit = qc.maxResp
	}
	if !qc.authenticated && len(request) < limit {
		limit = len(request)
	}
	return limit
}

// zoneLimit is the size an answer of the zone responder may have over UDP: the
// zone responder never authenticates anything.
func (qc *queryContext) zoneLimit(request []byte) int {
	saved := qc.authenticated
	qc.authenticated = false
	limit := qc.responseLimit(request)
	qc.authenticated = saved
	return limit
}

func (s *Server) finalizeResponse(qc *queryContext, request []byte, response []byte) []byte {
	if len(response) == 0 {
		return response
	}
	if !qc.hasParsed {
		// The answer was built from a request that did not parse as a whole;
		// it holds the header and at most the question, never more than the
		// request, but keep the guarantee explicit.
		if !qc.tcp && len(response) > len(request) && len(response) >= 12 {
			return truncatedHeader(response)
		}
		return response
	}
	limit := qc.responseLimit(request)
	if len(response) <= limit {
		if qc.tcp || !qc.src.IsValid() || s.sourceBudget.allow(qc.src.Addr(), len(response), time.Now()) {
			return response
		}
	}
	if qc.tcp {
		// A TCP answer that does not fit its frame cannot be truncated.
		return nil
	}
	truncated, err := DnsParser.BuildTruncated(request, qc.parsed, qc.inZone)
	if err != nil {
		return nil
	}
	s.stats.truncated.Add(1)
	return truncated
}

// truncatedHeader turns the header of an answer into a header-only TC answer.
func truncatedHeader(response []byte) []byte {
	out := make([]byte, 12)
	copy(out, response[:12])
	out[2] |= 0x02 // TC
	for i := 4; i < 12; i++ {
		out[i] = 0
	}
	return out
}

// sourceBudget caps the bytes of UDP answers sent per source network. A source
// that spoofs an address cannot be told apart from the address, so the cap is
// what keeps this server from becoming a reflector: past it, answers turn into
// empty TC answers that are no longer than the queries.
type sourceBudget struct {
	mu        sync.Mutex
	rate      float64 // bytes per second
	burst     float64
	buckets   map[netip.Prefix]*budgetBucket
	nextPurge time.Time
}

type budgetBucket struct {
	tokens float64
	last   time.Time
}

const maxBudgetBuckets = 16384

func newSourceBudget(bytesPerSecond int) *sourceBudget {
	rate := float64(bytesPerSecond)
	return &sourceBudget{rate: rate, burst: rate / 4, buckets: make(map[netip.Prefix]*budgetBucket)}
}

func budgetPrefix(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	bits := 24
	if addr.Is6() {
		bits = 56
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return prefix
}

// allow reports whether n more answer bytes may go to the network of addr.
func (b *sourceBudget) allow(addr netip.Addr, n int, now time.Time) bool {
	if b == nil || b.rate <= 0 || !addr.IsValid() {
		return true
	}
	key := budgetPrefix(addr)
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.nextPurge) {
		b.nextPurge = now.Add(10 * time.Second)
		for prefix, bucket := range b.buckets {
			if now.Sub(bucket.last) > 10*time.Second {
				delete(b.buckets, prefix)
			}
		}
	}
	bucket := b.buckets[key]
	if bucket == nil {
		if len(b.buckets) >= maxBudgetBuckets {
			// Too many networks to track: this is a spoofing flood. Answers
			// to untracked networks stay no longer than their queries, so
			// the amplification stays at 1.0.
			return true
		}
		bucket = &budgetBucket{tokens: b.burst, last: now}
		b.buckets[key] = bucket
	}
	if elapsed := now.Sub(bucket.last); elapsed > 0 {
		bucket.tokens += elapsed.Seconds() * b.rate
		if bucket.tokens > b.burst {
			bucket.tokens = b.burst
		}
		bucket.last = now
	}
	if bucket.tokens < float64(n) {
		return false
	}
	bucket.tokens -= float64(n)
	return true
}
