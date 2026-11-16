package udpserver

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	testZone     = "example.com"
	testNSName   = "ns-k3x9ab.example.net"
	testZoneAddr = "192.0.2.10"
	testCheckKey = "00112233445566778899aabbccddeeff"
)

var (
	resolverA = netip.MustParseAddrPort("198.51.100.7:53000")
	resolverB = netip.MustParseAddrPort("203.0.113.9:41000")
)

func zoneTestServer(t testing.TB, mutate ...func(*config.ServerConfig)) (*Server, security.Credential) {
	t.Helper()
	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{testZone}
	cfg.MinVPNLabelLength = 3
	cfg.ZoneNSName = testNSName
	cfg.ZoneAddress = testZoneAddr
	cfg.ZoneCheckKey = testCheckKey
	for _, fn := range mutate {
		fn(&cfg)
	}
	return newProtocolTestServer(t, cfg, nil)
}

func flagsOf(response []byte) uint16 { return binary.BigEndian.Uint16(response[2:4]) }

func hasTC(response []byte) bool { return flagsOf(response)&0x0200 != 0 }

// dnsQuery builds a plain query; edns 0 sends no OPT record, a non-zero value
// sends an OPT record advertising that size.
func dnsQuery(t testing.TB, name string, qType uint16, edns uint16) []byte {
	t.Helper()
	query, err := DnsParser.BuildTXTQuestionPacket(name, qType, edns)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket(%q) failed: %v", name, err)
	}
	return query
}

// sessionFor runs a real INIT/ACCEPT exchange for a credential and returns the
// client cipher and the session id.
func sessionFor(t testing.TB, server *Server, credential security.Credential) (*security.SessionCipher, uint8) {
	t.Helper()
	var parameters [security.InitParametersSize]byte
	binary.BigEndian.PutUint16(parameters[1:3], 100)
	binary.BigEndian.PutUint16(parameters[3:5], 900)
	handshake, initMessage, err := security.NewClientHandshake(credential, parameters, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket(testZone, baseCodec.EncodeToBytes(initMessage), Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	response := server.HandleQuery(resolverA, query, 0, false)
	acceptWire, err := DnsParser.ExtractVPNResponsePayload(response, false)
	if err != nil {
		t.Fatalf("no ACCEPT: %v", err)
	}
	accepted, keys, err := handshake.OpenAccept(acceptWire)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewSessionCipher(accepted.SessionID, keys.ClientToServer, keys.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	return cipher, accepted.SessionID
}

// frameQuery seals an inner packet with a fresh counter and wraps it in a
// tunnel query advertising edns.
func frameQuery(t testing.TB, cipher *security.SessionCipher, packetType uint8, payload []byte, edns uint16) []byte {
	t.Helper()
	raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{PacketType: packetType, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := cipher.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket(testZone, baseCodec.EncodeToBytes(frame), Enums.DNS_RECORD_TYPE_TXT, edns)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

// openFrame decrypts an answer and returns its inner packet.
func openFrame(t testing.TB, cipher *security.SessionCipher, response []byte) VpnProto.Packet {
	t.Helper()
	wire, err := DnsParser.ExtractVPNResponsePayload(response, false)
	if err != nil {
		t.Fatalf("no tunnel answer: %v", err)
	}
	plain, _, err := cipher.Open(wire)
	if err != nil {
		t.Fatalf("answer does not authenticate: %v", err)
	}
	packet, err := VpnProto.Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

// resolverRelay stands in for a recursive resolver between a client and the
// server: it rewrites the EDNS size of the query the way a resolver does
// (0 strips the OPT record), asks the server over UDP and, when the answer is
// truncated, asks again over TCP.
func resolverRelay(t testing.TB, server *Server, from netip.AddrPort, query []byte, resolverEDNS uint16) (answer []byte, truncated bool) {
	t.Helper()
	forwarded := rewriteEDNS(t, query, resolverEDNS)
	answer = server.HandleQuery(from, forwarded, 0, false)
	if len(answer) >= 12 && hasTC(answer) {
		return server.HandleQuery(from, forwarded, 0, true), true
	}
	return answer, false
}

func rewriteEDNS(t testing.TB, query []byte, edns uint16) []byte {
	t.Helper()
	parsed, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	end := parsed.QuestionEndOffset
	out := append([]byte(nil), query[:end]...)
	if edns == 0 {
		binary.BigEndian.PutUint16(out[10:12], 0)
		return out
	}
	binary.BigEndian.PutUint16(out[10:12], 1)
	opt := []byte{0, 0, 41, byte(edns >> 8), byte(edns), 0, 0, 0, 0, 0, 0}
	return append(out, opt...)
}

func queueDownlink(t testing.TB, server *Server, sessionID uint8, size int) []byte {
	t.Helper()
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	ok := server.queueMainSessionPacket(sessionID, VpnProto.Packet{
		PacketType:     Enums.PACKET_DNS_QUERY_RES,
		SequenceNum:    1,
		FragmentID:     0,
		TotalFragments: 1,
		Payload:        payload,
	})
	if !ok {
		t.Fatal("could not queue a downlink packet")
	}
	return payload
}

func TestAcceptIsNoLongerThanTwiceItsInit(t *testing.T) {
	server, credential := zoneTestServer(t)
	var parameters [security.InitParametersSize]byte
	_, initMessage, err := security.NewClientHandshake(credential, parameters, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket(testZone, baseCodec.EncodeToBytes(initMessage), Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	response := server.HandleQuery(resolverA, query, 0, false)
	if len(response) == 0 || hasTC(response) {
		t.Fatalf("an authenticated INIT over UDP must get its ACCEPT (%d bytes, TC=%v)", len(response), len(response) >= 12 && hasTC(response))
	}
	ratio := float64(len(response)) / float64(len(query))
	t.Logf("INIT query %d bytes, ACCEPT answer %d bytes, ratio %.2f", len(query), len(response), ratio)
	if ratio > 1.6 {
		t.Fatalf("ACCEPT/INIT ratio %.2f is above the 1.6 the design allows (question echoed in both, one record added)", ratio)
	}
}

func TestZoneResponderAnswers(t *testing.T) {
	server, _ := zoneTestServer(t)
	type want struct {
		rcode   uint8
		aa      bool
		answers []uint16
		auth    []uint16
		tc      bool
	}
	cases := []struct {
		name  string
		qname string
		qtype uint16
		edns  uint16
		tcp   bool
		want  want
	}{
		{name: "outside zone is refused", qname: "www.example.org", qtype: Enums.DNS_RECORD_TYPE_A, edns: 1232, want: want{rcode: Enums.DNSR_CODE_REFUSED}},
		{name: "outside zone without EDNS", qname: "www.example.org", qtype: Enums.DNS_RECORD_TYPE_TXT, want: want{rcode: Enums.DNSR_CODE_REFUSED}},
		{name: "a sibling of the zone is outside it", qname: "notexample.com", qtype: Enums.DNS_RECORD_TYPE_A, edns: 1232, want: want{rcode: Enums.DNSR_CODE_REFUSED}},
		{name: "the parent of the zone is outside it", qname: "com", qtype: Enums.DNS_RECORD_TYPE_NS, edns: 1232, want: want{rcode: Enums.DNSR_CODE_REFUSED}},
		{name: "apex SOA is too long for UDP and truncated", qname: testZone, qtype: Enums.DNS_RECORD_TYPE_SOA, edns: 1232, want: want{tc: true}},
		{name: "apex SOA over TCP", qname: testZone, qtype: Enums.DNS_RECORD_TYPE_SOA, edns: 1232, tcp: true, want: want{answers: []uint16{Enums.DNS_RECORD_TYPE_SOA}}},
		{name: "apex NS over TCP", qname: testZone, qtype: Enums.DNS_RECORD_TYPE_NS, edns: 1232, tcp: true, want: want{answers: []uint16{Enums.DNS_RECORD_TYPE_NS}}},
		{name: "apex A over TCP", qname: testZone, qtype: Enums.DNS_RECORD_TYPE_A, edns: 1232, tcp: true, want: want{answers: []uint16{Enums.DNS_RECORD_TYPE_A}}},
		{name: "apex AAAA is empty with the SOA over TCP", qname: testZone, qtype: Enums.DNS_RECORD_TYPE_AAAA, edns: 1232, tcp: true, want: want{auth: []uint16{Enums.DNS_RECORD_TYPE_SOA}}},
		{name: "apex AAAA over UDP drops the SOA", qname: testZone, qtype: Enums.DNS_RECORD_TYPE_AAAA, edns: 1232, want: want{}},
		{name: "apex TXT is empty", qname: testZone, qtype: Enums.DNS_RECORD_TYPE_TXT, edns: 1232, tcp: true, want: want{auth: []uint16{Enums.DNS_RECORD_TYPE_SOA}}},
		{name: "ANY is empty over TCP", qname: testZone, qtype: 255, edns: 1232, tcp: true, want: want{auth: []uint16{Enums.DNS_RECORD_TYPE_SOA}}},
		{name: "ANY is empty over UDP", qname: testZone, qtype: 255, edns: 1232, want: want{}},
		{name: "AXFR is refused", qname: testZone, qtype: 252, edns: 1232, tcp: true, want: want{rcode: Enums.DNSR_CODE_REFUSED}},
		{name: "QNAME minimisation NS probe is NODATA, not NXDOMAIN", qname: "x1.example.com", qtype: Enums.DNS_RECORD_TYPE_NS, edns: 1232, want: want{}},
		{name: "QNAME minimisation A probe two labels deep", qname: "a.b.example.com", qtype: Enums.DNS_RECORD_TYPE_A, edns: 1232, tcp: true, want: want{auth: []uint16{Enums.DNS_RECORD_TYPE_SOA}}},
		{name: "short TXT label is NODATA", qname: "ab.example.com", qtype: Enums.DNS_RECORD_TYPE_TXT, edns: 1232, tcp: true, want: want{auth: []uint16{Enums.DNS_RECORD_TYPE_SOA}}},
		{name: "delegation check over TCP", qname: "_mgchk-abcdefgh.example.com", qtype: Enums.DNS_RECORD_TYPE_TXT, edns: 1232, tcp: true, want: want{answers: []uint16{Enums.DNS_RECORD_TYPE_TXT}}},
		{name: "delegation check over UDP is truncated", qname: "_mgchk-abcdefgh.example.com", qtype: Enums.DNS_RECORD_TYPE_TXT, edns: 1232, want: want{tc: true}},
		{name: "delegation nonce too short is NODATA", qname: "_mgchk-abc.example.com", qtype: Enums.DNS_RECORD_TYPE_TXT, edns: 1232, tcp: true, want: want{auth: []uint16{Enums.DNS_RECORD_TYPE_SOA}}},
		{name: "delegation nonce with a dash is NODATA", qname: "_mgchk-abcd-efgh.example.com", qtype: Enums.DNS_RECORD_TYPE_TXT, edns: 1232, tcp: true, want: want{auth: []uint16{Enums.DNS_RECORD_TYPE_SOA}}},
		{name: "delegation check one label too deep is a tunnel name that does not decode", qname: "x._mgchk-abcdefgh.example.com", qtype: Enums.DNS_RECORD_TYPE_TXT, edns: 1232, want: want{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query := dnsQuery(t, tc.qname, tc.qtype, tc.edns)
			response := server.HandleQuery(resolverA, query, 0, tc.tcp)
			if len(response) < 12 {
				t.Fatalf("no answer (%d bytes)", len(response))
			}
			flags := flagsOf(response)
			if got := hasTC(response); got != tc.want.tc {
				t.Fatalf("TC=%v, want %v", got, tc.want.tc)
			}
			if flags&0x0080 != 0 {
				t.Fatal("RA must be clear")
			}
			if !tc.tcp && len(response) > len(query) {
				t.Fatalf("answer of %d bytes to a query of %d bytes over UDP", len(response), len(query))
			}
			if tc.want.tc {
				if flags&0x000F != 0 || binary.BigEndian.Uint16(response[6:8]) != 0 {
					t.Fatal("a truncated answer carries no data")
				}
				return
			}
			if got := uint8(flags & 0x000F); got != tc.want.rcode {
				t.Fatalf("rcode %d, want %d", got, tc.want.rcode)
			}
			wantAA := tc.want.rcode != Enums.DNSR_CODE_REFUSED
			if got := flags&0x0400 != 0; got != wantAA {
				t.Fatalf("AA=%v, want %v", got, wantAA)
			}
			parsed, err := DnsParser.ParsePacket(response)
			if err != nil {
				t.Fatalf("answer does not parse: %v", err)
			}
			types := func(records []DnsParser.ResourceRecord) []uint16 {
				var out []uint16
				for _, record := range records {
					out = append(out, record.Type)
				}
				return out
			}
			if got := types(parsed.Answers); !equalTypes(got, tc.want.answers) {
				t.Fatalf("answer types %v, want %v", got, tc.want.answers)
			}
			if tc.tcp || len(parsed.Authorities) > 0 {
				if got := types(parsed.Authorities); !equalTypes(got, tc.want.auth) {
					t.Fatalf("authority types %v, want %v", got, tc.want.auth)
				}
			}
			if tc.edns != 0 {
				if len(parsed.Additional) != 1 || parsed.Additional[0].Type != Enums.DNS_RECORD_TYPE_OPT || parsed.Additional[0].Class != DnsParser.AdvertisedUDPSize || len(parsed.Additional[0].RData) != 0 {
					t.Fatalf("answer must carry exactly our own empty OPT record, got %+v", parsed.Additional)
				}
			} else if len(parsed.Additional) != 0 {
				t.Fatal("a query without OPT must not get an OPT record")
			}
		})
	}
}

func equalTypes(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestZoneApexRecordsHaveTheDocumentedContent(t *testing.T) {
	server, _ := zoneTestServer(t)
	parse := func(qtype uint16) DnsParser.Packet {
		response := server.HandleQuery(resolverA, dnsQuery(t, testZone, qtype, 1232), 0, true)
		parsed, err := DnsParser.ParsePacket(response)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	soa := parse(Enums.DNS_RECORD_TYPE_SOA).Answers[0]
	mname, off, _ := readName(soa.RData, 0)
	rname, off, _ := readName(soa.RData, off)
	values := soa.RData[off:]
	if mname != testNSName || rname != "hostmaster."+testZone {
		t.Fatalf("SOA names %q %q", mname, rname)
	}
	if len(values) != 20 || binary.BigEndian.Uint32(values[0:4]) != 1 || binary.BigEndian.Uint32(values[16:20]) != 60 {
		t.Fatalf("SOA serial and minimum must be 1 and 60: %x", values)
	}
	ns := parse(Enums.DNS_RECORD_TYPE_NS).Answers[0]
	if name, _, _ := readName(ns.RData, 0); name != testNSName {
		t.Fatalf("NS %q", name)
	}
	a := parse(Enums.DNS_RECORD_TYPE_A).Answers[0]
	if !bytes.Equal(a.RData, []byte{192, 0, 2, 10}) {
		t.Fatalf("A %v", a.RData)
	}
}

func readName(data []byte, offset int) (string, int, error) {
	var name []byte
	for {
		length := int(data[offset])
		offset++
		if length == 0 {
			break
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, data[offset:offset+length]...)
		offset += length
	}
	return string(name), offset, nil
}

func TestDelegationCheckAnswersWithHMAC(t *testing.T) {
	server, _ := zoneTestServer(t)
	response := server.HandleQuery(resolverA, dnsQuery(t, "_mgchk-q7w8e9r0.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232), 0, true)
	parsed, err := DnsParser.ParsePacket(response)
	if err != nil || len(parsed.Answers) != 1 {
		t.Fatalf("no TXT answer: %v %+v", err, parsed)
	}
	key, _ := hex.DecodeString(testCheckKey)
	want := DelegationCheckAnswer(key, "q7w8e9r0")
	if got := string(parsed.Answers[0].RData[1:]); got != want || len(want) != 64 {
		t.Fatalf("TXT %q, want %q", got, want)
	}
	// 0x20 case randomisation must not change the answer.
	response = server.HandleQuery(resolverA, dnsQuery(t, "_MgChK-Q7w8E9r0.ExAmPlE.com", Enums.DNS_RECORD_TYPE_TXT, 1232), 0, true)
	parsed, err = DnsParser.ParsePacket(response)
	if err != nil || len(parsed.Answers) != 1 || string(parsed.Answers[0].RData[1:]) != want {
		t.Fatalf("a case-randomised query got a different answer: %v", err)
	}
}

func TestAnswerPreservesQuestionCaseAndIDAndCopiesNoOptions(t *testing.T) {
	server, credential := zoneTestServer(t)
	cipher, _ := sessionFor(t, server, credential)
	query := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 4096)
	// A resolver puts a client cookie in the OPT record it sends.
	cookieQuery := rewriteEDNS(t, query, 1232)
	cookieQuery = append(cookieQuery[:len(cookieQuery)-2], 0, 12)
	cookieQuery = append(cookieQuery, 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8)
	response := server.HandleQuery(resolverA, cookieQuery, 0, false)
	if len(response) == 0 || hasTC(response) {
		t.Fatalf("no answer to a query with a cookie (%d bytes)", len(response))
	}
	if !bytes.Equal(response[0:2], cookieQuery[0:2]) {
		t.Fatal("the answer must carry the query ID")
	}
	if bytes.Contains(response, []byte{0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("the client cookie was echoed")
	}
	parsed, err := DnsParser.ParsePacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Additional) != 1 || len(parsed.Additional[0].RData) != 0 {
		t.Fatalf("the OPT record of the answer must be empty: %+v", parsed.Additional)
	}
	if flagsOf(response)&0x0400 == 0 || flagsOf(response)&0x0080 != 0 {
		t.Fatal("tunnel answers are authoritative and not recursive")
	}
	if openFrame(t, cipher, response).PacketType != Enums.PACKET_PONG {
		t.Fatal("expected a PONG")
	}
}
