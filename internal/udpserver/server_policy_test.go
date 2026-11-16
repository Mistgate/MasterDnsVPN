package udpserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

// A data answer too big for the resolver's EDNS size comes back with TC=1; the
// query repeated over TCP carries the same frame counter, which the replay
// window has used, and is answered with the same sealed frame.
func TestTruncatedAnswerIsServedOverTCPFromTheAnswerCache(t *testing.T) {
	for _, tc := range []struct {
		name     string
		edns     uint16
		size     int
		truncate bool
	}{
		{name: "EDNS 1232, small answer fits", edns: 1232, size: 300, truncate: false},
		{name: "EDNS 1232, answer of 1500 bytes", edns: 1232, size: 1500, truncate: true},
		{name: "EDNS 512, answer of 700 bytes", edns: 512, size: 700, truncate: true},
		{name: "no OPT record means 512", edns: 0, size: 700, truncate: true},
		{name: "no OPT record, small answer", edns: 0, size: 200, truncate: false},
		{name: "EDNS 4096, answer of 3000 bytes", edns: 4096, size: 3000, truncate: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, credential := zoneTestServer(t)
			cipher, sessionID := sessionFor(t, server, credential)
			payload := queueDownlink(t, server, sessionID, tc.size)
			query := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 4096)
			answer, truncated := resolverRelay(t, server, resolverA, query, tc.edns)
			if truncated != tc.truncate {
				t.Fatalf("truncated=%v, want %v", truncated, tc.truncate)
			}
			packet := openFrame(t, cipher, answer)
			if packet.PacketType != Enums.PACKET_DNS_QUERY_RES || !bytes.Equal(packet.Payload, payload) {
				t.Fatalf("the data did not arrive: type %d, %d bytes", packet.PacketType, len(packet.Payload))
			}
			if !truncated && len(answer) > int(maxUint(tc.edns, 512)) {
				t.Fatalf("answer of %d bytes over UDP with EDNS %d", len(answer), tc.edns)
			}
		})
	}
}

func maxUint(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
}

// A resolver that lost the answer asks again with the same bytes. The sealed
// answer is repeated, to that resolver only and a few times.
func TestResolverRetryGetsTheSameDataFromTheAnswerCache(t *testing.T) {
	server, credential := zoneTestServer(t)
	cipher, sessionID := sessionFor(t, server, credential)
	payload := queueDownlink(t, server, sessionID, 400)
	query := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232)

	first := server.HandleQuery(resolverA, query, 0, false) // this answer is "lost"
	if len(first) == 0 {
		t.Fatal("no answer")
	}
	retry := server.HandleQuery(resolverA, query, 0, false)
	if packet := openFrame(t, cipher, retry); !bytes.Equal(packet.Payload, payload) {
		t.Fatal("the retry did not get the data of the lost answer")
	}
	if got := server.Stats().CacheServed; got != 1 {
		t.Fatalf("CacheServed=%d, want 1", got)
	}
	// The resolver also duplicated the query: the same, once more.
	dup := server.HandleQuery(resolverA, query, 0, false)
	retryWire, _ := extractOrNil(retry)
	dupWire, err := extractOrNil(dup)
	if err != nil || !bytes.Equal(dupWire, retryWire) {
		t.Fatal("the duplicate did not get the same sealed answer")
	}
	// Past the budget the answer is the plain empty one.
	late := server.HandleQuery(resolverA, query, 0, false)
	if len(late) > len(query) {
		t.Fatalf("a third repeat got %d bytes for a query of %d", len(late), len(query))
	}
	// Frames the server answered with PONG are not kept: nothing to recover.
	pingQuery := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232)
	pong := server.HandleQuery(resolverA, pingQuery, 0, false)
	if openFrame(t, cipher, pong).PacketType != Enums.PACKET_PONG {
		t.Fatal("expected a PONG")
	}
	if again := server.HandleQuery(resolverA, pingQuery, 0, false); len(again) > len(pingQuery) {
		t.Fatalf("a PONG was repeated with %d bytes", len(again))
	}
}

// The answer cache is bounded in time: after its TTL a repeat gets the empty answer.
func TestAnswerCacheEntriesExpire(t *testing.T) {
	cache := &answerCache{}
	now := time.Now()
	cache.put(7, []byte("frame"), resolverA.Addr(), now)
	if _, ok := cache.get(7, resolverA.Addr(), false, now.Add(answerCacheTTL-time.Second)); !ok {
		t.Fatal("entry gone before its TTL")
	}
	if _, ok := cache.get(7, resolverA.Addr(), false, now.Add(answerCacheTTL+time.Second)); ok {
		t.Fatal("entry still served after its TTL")
	}
	// The ring keeps the newest answerCacheSize entries.
	for i := uint32(0); i < answerCacheSize+4; i++ {
		cache.put(100+i, []byte{byte(i)}, resolverA.Addr(), now)
	}
	if _, ok := cache.get(100, resolverA.Addr(), true, now); ok {
		t.Fatal("the oldest entry should have been overwritten")
	}
	if _, ok := cache.get(100+answerCacheSize+3, resolverA.Addr(), true, now); !ok {
		t.Fatal("the newest entry is missing")
	}
	// TCP repeats need no source match but are bounded too.
	served := 0
	for i := 0; i < 10; i++ {
		if _, ok := cache.get(100+answerCacheSize+3, netip.MustParseAddr("192.0.2.1"), true, now); ok {
			served++
		}
	}
	if served != maxTCPAnswerRepeats-1 { // one repeat went to the check above
		t.Fatalf("TCP repeats %d, want %d", served, maxTCPAnswerRepeats)
	}
}

func TestSourceBudgetDrainsIntoTruncatedAnswers(t *testing.T) {
	server, _ := zoneTestServer(t, func(cfg *config.ServerConfig) { cfg.SourceBytesPerSecond = 1 << 16 })
	query := dnsQuery(t, "www.example.org", Enums.DNS_RECORD_TYPE_A, 1232)
	answered, truncated := 0, 0
	for i := 0; i < 3000; i++ {
		// Every address of one /24 shares the budget.
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 5300)
		response := server.HandleQuery(src, query, 0, false)
		if len(response) > len(query) {
			t.Fatalf("answer of %d bytes to a query of %d", len(response), len(query))
		}
		if hasTC(response) {
			truncated++
		} else {
			answered++
		}
	}
	if truncated == 0 || answered == 0 {
		t.Fatalf("answered=%d truncated=%d: the budget should let the first through and then drain", answered, truncated)
	}
	// A different network is not affected.
	other := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), 5300)
	if response := server.HandleQuery(other, query, 0, false); hasTC(response) {
		t.Fatal("another /24 shares the budget")
	}
	if server.Stats().Truncated < uint64(truncated) {
		t.Fatal("truncated answers are not counted")
	}
}

func TestSourceBudgetLeavesAuthenticatedDataRecoverableOverTCP(t *testing.T) {
	server, credential := zoneTestServer(t, func(cfg *config.ServerConfig) { cfg.SourceBytesPerSecond = 1 << 16 })
	cipher, sessionID := sessionFor(t, server, credential)
	// Drain the budget of resolverA's network with refused queries.
	query := dnsQuery(t, "www.example.org", Enums.DNS_RECORD_TYPE_A, 1232)
	for i := 0; i < 5000; i++ {
		server.HandleQuery(resolverA, query, 0, false)
	}
	payload := queueDownlink(t, server, sessionID, 800)
	frame := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232)
	answer, truncated := resolverRelay(t, server, resolverA, frame, 1232)
	if !truncated {
		t.Fatal("expected the drained budget to truncate the data answer")
	}
	if packet := openFrame(t, cipher, answer); !bytes.Equal(packet.Payload, payload) {
		t.Fatal("the data was lost with the truncated answer")
	}
}

func TestTCPQueryConnectionLimitsAndFraming(t *testing.T) {
	server, _ := zoneTestServer(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = server.ServeTCP(ctx, listener)
	}()
	defer func() {
		cancel()
		wg.Wait()
	}()

	ask := func(conn net.Conn, query []byte) []byte {
		t.Helper()
		out := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		out = append(out, query...)
		if _, err := conn.Write(out); err != nil {
			t.Fatal(err)
		}
		var length [2]byte
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := readFull(conn, length[:]); err != nil {
			t.Fatalf("no length prefix: %v", err)
		}
		response := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := readFull(conn, response); err != nil {
			t.Fatalf("short answer: %v", err)
		}
		return response
	}

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	soa := ask(conn, dnsQuery(t, testZone, Enums.DNS_RECORD_TYPE_SOA, 1232))
	if hasTC(soa) || binary.BigEndian.Uint16(soa[6:8]) != 1 {
		t.Fatal("TCP must carry the full SOA answer")
	}
	// The same connection answers a second query.
	refused := ask(conn, dnsQuery(t, "www.example.org", Enums.DNS_RECORD_TYPE_A, 0))
	if uint8(flagsOf(refused)&0x000F) != Enums.DNSR_CODE_REFUSED {
		t.Fatal("second query on the connection")
	}

	// Per-source limit: sixteen connections, the next ones are closed at once.
	conns := []net.Conn{conn}
	for i := 0; i < maxTCPConnsPerSource+3; i++ {
		c, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		conns = append(conns, c)
	}
	closed := 0
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		one := make([]byte, 1)
		if _, err := c.Read(one); err != nil && !isTimeout(err) {
			closed++
		}
	}
	if closed < 4 {
		t.Fatalf("%d connections were closed by the per-source limit, want at least 4 of %d", closed, len(conns))
	}
}

func isTimeout(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func readFull(conn net.Conn, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		n, err := conn.Read(buffer[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestTCPLimiterBoundsTotalAndPerSource(t *testing.T) {
	limiter := newTCPLimiter()
	addr := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < maxTCPConnsPerSource; i++ {
		if !limiter.acquire(addr) {
			t.Fatalf("connection %d refused", i)
		}
	}
	if limiter.acquire(addr) {
		t.Fatal("the seventeenth connection of one source was accepted")
	}
	limiter.release(addr)
	if !limiter.acquire(addr) {
		t.Fatal("a released slot was not reusable")
	}
	for i := 0; limiter.total < maxTCPConns; i++ {
		if !limiter.acquire(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})) {
			t.Fatalf("source %d refused below the total limit", i)
		}
	}
	if limiter.acquire(netip.MustParseAddr("198.51.100.99")) {
		t.Fatal("the 257th connection was accepted")
	}
}

func TestRequestRateLimitDropsFramesPastTheBudget(t *testing.T) {
	server, credential := zoneTestServer(t, func(cfg *config.ServerConfig) { cfg.MaxRequestsPerSessionPerSecond = 5 })
	cipher, _ := sessionFor(t, server, credential)
	limited := 0
	for i := 0; i < 40; i++ {
		query := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232)
		response := server.HandleQuery(resolverA, query, 0, false)
		if _, err := extractOrNil(response); err != nil {
			limited++
		}
	}
	if limited < 20 {
		t.Fatalf("only %d of 40 immediate frames were limited at 5 per second", limited)
	}
	if server.Stats().RateLimited == 0 {
		t.Fatal("rate limiting is not counted")
	}
}

func extractOrNil(response []byte) ([]byte, error) {
	return DnsParser.ExtractVPNResponsePayload(response, false)
}
