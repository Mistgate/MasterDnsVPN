package udpserver

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func tunnelQueryEDNS(t testing.TB, wire []byte, edns uint16) []byte {
	t.Helper()
	query, err := DnsParser.BuildTunnelTXTQuestionPacket(testZone, baseCodec.EncodeToBytes(wire), Enums.DNS_RECORD_TYPE_TXT, edns)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func randomBytes(n int) []byte {
	out := make([]byte, n)
	_, _ = rand.Read(out)
	return out
}

// TestUnauthenticatedAnswersAreNeverLongerThanTheQuery is the requirement of
// the design: whatever a query that did not authenticate looks like, the UDP
// answer has at most as many bytes as the query, otherwise it is an empty TC
// answer that has no more bytes than the query either.
func TestUnauthenticatedAnswersAreNeverLongerThanTheQuery(t *testing.T) {
	server, credential := zoneTestServer(t)
	cipher, _ := sessionFor(t, server, credential)

	// Material an on-path observer holds: a captured frame (already used), a
	// captured probe, a captured INIT, each of which it can send again.
	capturedFrame := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 4096)
	if len(server.HandleQuery(resolverA, capturedFrame, 0, false)) == 0 {
		t.Fatal("setup: the first copy of the frame must be answered")
	}
	var parameters [security.InitParametersSize]byte
	_, initMessage, err := security.NewClientHandshake(credential, parameters, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capturedInit := tunnelQueryEDNS(t, initMessage, 4096)
	for i := 0; i < maxInitUDPAnswers+4; i++ { // past the per-INIT answer budget
		server.HandleQuery(resolverA, capturedInit, 0, false)
	}

	probePayload := make([]byte, mtuProbeDownMinSize)
	copy(probePayload[1:1+mtuProbeCodeLength], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(probePayload[mtuProbeUpMinSize:], 3000)
	rawProbe, err := VpnProto.BuildRaw(VpnProto.BuildOptions{PacketType: Enums.PACKET_MTU_DOWN_REQ, Payload: probePayload})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := security.SealProbe(credential, rawProbe, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	capturedProbe := tunnelQueryEDNS(t, probe, 4096)
	if first := server.HandleQuery(resolverA, capturedProbe, 0, false); len(first) == 0 {
		t.Fatal("setup: the first copy of the probe must be answered")
	}
	// A probe sealed with a key the server does not know.
	other := credential
	other.Key[0] ^= 0xFF
	forgedProbe, err := security.SealProbe(other, rawProbe, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var unknownKID security.Credential
	copy(unknownKID.KID[:], []byte{9, 9, 9, 9, 9, 9, 9, 9})
	unknownKID.ID = "0909090909090909"
	unknownProbe, err := security.SealProbe(unknownKID, rawProbe, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	staleProbe, err := security.SealProbe(credential, rawProbe, time.Now().Add(-10*time.Minute), nil)
	if err != nil {
		t.Fatal(err)
	}
	// An INIT of the right length that does not authenticate.
	badInit := append([]byte(nil), initMessage...)
	badInit[len(badInit)-1] ^= 1
	unknownInit := append([]byte(nil), initMessage...)
	unknownInit[1] ^= 0xFF
	// A frame of a session that exists, with a flipped byte; and of one that does not.
	flipped := mustSeal(t, cipher)
	flipped[len(flipped)-1] ^= 1

	longName := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com"
	type kase struct {
		name  string
		query []byte
	}
	var cases []kase
	for _, edns := range []uint16{0, 512, 1232, 4096} {
		suffix := func(s string) string {
			if edns == 0 {
				return s + " (no OPT)"
			}
			return s
		}
		cases = append(cases,
			kase{suffix("name outside every zone"), dnsQuery(t, "www.example.org", Enums.DNS_RECORD_TYPE_A, edns)},
			kase{suffix("outside zone, TXT"), dnsQuery(t, "tunnel.example.org", Enums.DNS_RECORD_TYPE_TXT, edns)},
			kase{suffix("outside zone, ANY"), dnsQuery(t, "example.org", 255, edns)},
			kase{suffix("zone apex SOA"), dnsQuery(t, testZone, Enums.DNS_RECORD_TYPE_SOA, edns)},
			kase{suffix("zone apex NS"), dnsQuery(t, testZone, Enums.DNS_RECORD_TYPE_NS, edns)},
			kase{suffix("zone apex A"), dnsQuery(t, testZone, Enums.DNS_RECORD_TYPE_A, edns)},
			kase{suffix("zone apex ANY"), dnsQuery(t, testZone, 255, edns)},
			kase{suffix("zone apex TXT"), dnsQuery(t, testZone, Enums.DNS_RECORD_TYPE_TXT, edns)},
			kase{suffix("zone apex DNSKEY"), dnsQuery(t, testZone, Enums.DNS_RECORD_TYPE_DNSKEY, edns)},
			kase{suffix("delegation check"), dnsQuery(t, "_mgchk-abcdefgh.example.com", Enums.DNS_RECORD_TYPE_TXT, edns)},
			kase{suffix("intermediate name NS"), dnsQuery(t, "x.example.com", Enums.DNS_RECORD_TYPE_NS, edns)},
			kase{suffix("deep intermediate name A"), dnsQuery(t, longName, Enums.DNS_RECORD_TYPE_A, edns)},
			kase{suffix("zone without tunnel labels, TXT"), dnsQuery(t, "ab.example.com", Enums.DNS_RECORD_TYPE_TXT, edns)},
			kase{suffix("garbage tunnel labels"), dnsQuery(t, "!!!!!!!!.example.com", Enums.DNS_RECORD_TYPE_TXT, edns)},
			kase{suffix("tunnel labels, not base36 data"), dnsQuery(t, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.example.com", Enums.DNS_RECORD_TYPE_TXT, edns)},
			kase{suffix("random frame"), tunnelQueryEDNS(t, randomBytes(60), edns)},
			kase{suffix("random frame of INIT length"), tunnelQueryEDNS(t, randomBytes(security.SessionInitSize), edns)},
			kase{suffix("INIT with a bad tag"), tunnelQueryEDNS(t, badInit, edns)},
			kase{suffix("INIT of an unknown device"), tunnelQueryEDNS(t, unknownInit, edns)},
			kase{suffix("INIT replayed past its answer budget"), tunnelQueryEDNS(t, initMessage, edns)},
			kase{suffix("frame with a flipped byte"), tunnelQueryEDNS(t, flipped, edns)},
			kase{suffix("frame of a session that does not exist"), tunnelQueryEDNS(t, append([]byte{200, 0, 0, 0, 1}, randomBytes(40)...), edns)},
			kase{suffix("frame replayed"), rewriteEDNS(t, capturedFrame, edns)},
			kase{suffix("probe replayed"), rewriteEDNS(t, capturedProbe, edns)},
			kase{suffix("probe sealed with a wrong key"), tunnelQueryEDNS(t, forgedProbe, edns)},
			kase{suffix("probe of an unknown device"), tunnelQueryEDNS(t, unknownProbe, edns)},
			kase{suffix("stale probe"), tunnelQueryEDNS(t, staleProbe, edns)},
			kase{suffix("probe header with nothing behind it"), tunnelQueryEDNS(t, append([]byte{security.ProtocolVersion, security.ProbeKindMTU}, randomBytes(40)...), edns)},
		)
	}
	// A request with an opcode other than QUERY, QDCOUNT 2, a response, a
	// request with trailing garbage.
	update := dnsQuery(t, testZone, Enums.DNS_RECORD_TYPE_SOA, 1232)
	update[2] |= 5 << 3
	cases = append(cases, kase{"opcode UPDATE", update})
	trailing := append(dnsQuery(t, "www.example.org", Enums.DNS_RECORD_TYPE_A, 1232), randomBytes(30)...)
	cases = append(cases, kase{"trailing garbage after the query", trailing})
	twoQuestions := dnsQuery(t, testZone, Enums.DNS_RECORD_TYPE_SOA, 0)
	binary.BigEndian.PutUint16(twoQuestions[4:6], 2)
	cases = append(cases, kase{"QDCOUNT two", twoQuestions})
	chaos := dnsQuery(t, "version.bind", Enums.DNS_RECORD_TYPE_TXT, 1232)
	binary.BigEndian.PutUint16(chaos[len(chaos)-13-2:], 3) // class CH of the question
	cases = append(cases, kase{"class CHAOS", chaos})

	for _, tc := range cases {
		response := server.HandleQuery(resolverB, tc.query, 0, false)
		if len(response) > len(tc.query) {
			t.Errorf("%s: answer of %d bytes to a query of %d bytes (ratio %.2f)", tc.name, len(response), len(tc.query), float64(len(response))/float64(len(tc.query)))
		}
	}
}

func mustSeal(t testing.TB, cipher *security.SessionCipher) []byte {
	t.Helper()
	raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{PacketType: Enums.PACKET_PING, Payload: []byte("PING")})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := cipher.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// An answer to a query that authenticated may be longer than the query, but
// only for a fresh query: the same query again, from another source, is not.
func TestAuthenticatedAnswersCannotBeReplayedAtAnotherSource(t *testing.T) {
	server, credential := zoneTestServer(t)
	cipher, sessionID := sessionFor(t, server, credential)
	payload := queueDownlink(t, server, sessionID, 600)
	query := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232)
	first := server.HandleQuery(resolverA, query, 0, false)
	packet := openFrame(t, cipher, first)
	if packet.PacketType != Enums.PACKET_DNS_QUERY_RES || len(packet.Payload) != len(payload) {
		t.Fatalf("expected the queued 600 bytes, got %+v", packet)
	}
	if len(first) <= len(query) {
		t.Fatalf("setup: the data answer (%d) must be longer than the query (%d)", len(first), len(query))
	}
	// The same query from a victim's address.
	for i := 0; i < 5; i++ {
		replay := server.HandleQuery(resolverB, query, 0, false)
		if len(replay) > len(query) {
			t.Fatalf("replay %d from another source got %d bytes for a query of %d", i, len(replay), len(query))
		}
	}
	// And from the right source, the repeat budget (two) runs out.
	served := 0
	for i := 0; i < 6; i++ {
		if again := server.HandleQuery(resolverA, query, 0, false); len(again) > len(query) {
			served++
		}
	}
	if served != maxUDPAnswerRepeats {
		t.Fatalf("a captured query was repeated %d times to its own source, want %d", served, maxUDPAnswerRepeats)
	}
}

func FuzzHandleQueryNeverAmplifies(f *testing.F) {
	server, _ := zoneTestServer(f)
	server.SetCredentialIndex(nil) // nothing can authenticate: every query is an unauthenticated one
	for _, seed := range seedQueries(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 4096 {
			return
		}
		response := server.HandleQuery(resolverB, packet, 0, false)
		if len(response) > len(packet) {
			t.Fatalf("answer of %d bytes to a query of %d bytes: %x", len(response), len(packet), packet)
		}
		// Over TCP nothing may panic either; no size relation is promised.
		_ = server.HandleQuery(resolverB, packet, 0, true)
	})
}

func seedQueries(t testing.TB) [][]byte {
	t.Helper()
	var seeds [][]byte
	for _, edns := range []uint16{0, 512, 1232, 4096} {
		for _, name := range []string{testZone, "www.example.org", "x.example.com", "_mgchk-abcdefgh.example.com", "a.b.c.example.com"} {
			for _, qtype := range []uint16{Enums.DNS_RECORD_TYPE_A, Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_SOA, Enums.DNS_RECORD_TYPE_NS, 255, 252} {
				seeds = append(seeds, dnsQuery(t, name, qtype, edns))
			}
		}
		seeds = append(seeds, tunnelQueryEDNS(t, randomBytes(security.SessionInitSize), edns), tunnelQueryEDNS(t, randomBytes(80), edns))
	}
	return seeds
}

// FuzzHandleQueryWithSession feeds mutated queries to a server that has a live
// session: frames of the session with flipped bytes, truncated frames, probes.
// Nothing may panic and no answer may exceed 64 KiB.
func FuzzHandleQueryWithSession(f *testing.F) {
	server, credential := zoneTestServer(f)
	cipher, _ := sessionFor(f, server, credential)
	for _, edns := range []uint16{0, 1232, 4096} {
		f.Add(frameQuery(f, cipher, Enums.PACKET_PING, []byte("PING"), edns))
		f.Add(frameQuery(f, cipher, Enums.PACKET_STREAM_DATA, []byte("data"), edns))
		f.Add(frameQuery(f, cipher, Enums.PACKET_SOCKS5_SYN, []byte{3, 4, 'a', '.', 't', 'x', 0, 80}, edns))
		f.Add(frameQuery(f, cipher, Enums.PACKET_DNS_QUERY_REQ, []byte{1, 2, 3}, edns))
		f.Add(frameQuery(f, cipher, Enums.PACKET_PACKED_CONTROL_BLOCKS, make([]byte, 14), edns))
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 4096 {
			return
		}
		for _, tcp := range []bool{false, true} {
			if response := server.HandleQuery(resolverA, packet, 0, tcp); len(response) > maxTCPMessage {
				t.Fatalf("answer of %d bytes", len(response))
			}
		}
	})
}

// Garbage from many sources must not grow any table without bound.
func TestGarbageDoesNotGrowServerStateWithoutBound(t *testing.T) {
	if testing.Short() {
		t.Skip("memory measurement")
	}
	server, credential := zoneTestServer(t)
	sessionFor(t, server, credential)
	before := heapInUse()
	for i := 0; i < 120000; i++ {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 7}), 5300)
		var packet []byte
		switch i % 4 {
		case 0:
			packet = dnsQuery(t, "www.example.org", Enums.DNS_RECORD_TYPE_A, 1232)
		case 1:
			packet = tunnelQueryEDNS(t, randomBytes(60+i%90), 1232)
		case 2:
			packet = tunnelQueryEDNS(t, randomBytes(security.SessionInitSize), 1232)
		default:
			packet = dnsQuery(t, "_mgchk-abcdefgh.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
		}
		if response := server.HandleQuery(src, packet, 0, false); len(response) > len(packet) {
			t.Fatalf("answer of %d bytes to a query of %d", len(response), len(packet))
		}
	}
	grown := int64(heapInUse()) - int64(before)
	server.sourceBudget.mu.Lock()
	buckets := len(server.sourceBudget.buckets)
	server.sourceBudget.mu.Unlock()
	server.protocolMu.Lock()
	cached := len(server.initCache)
	server.protocolMu.Unlock()
	t.Logf("after 120000 garbage queries from 120000 networks: heap %+d KiB, %d source buckets, %d cached ACCEPTs", grown>>10, buckets, cached)
	if buckets > maxBudgetBuckets {
		t.Fatalf("%d source buckets, the cap is %d", buckets, maxBudgetBuckets)
	}
	if cached > 1 {
		t.Fatalf("%d cached ACCEPTs: garbage must not create INIT state", cached)
	}
	if grown > 16<<20 {
		t.Fatalf("heap grew by %d MiB", grown>>20)
	}
}
