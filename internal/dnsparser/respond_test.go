package dnsparser

import (
	"bytes"
	"encoding/binary"
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

func queryWithOPT(t *testing.T, name string, qtype uint16, udpSize uint16, options []byte) []byte {
	t.Helper()
	query := buildDNSQuery(0x4321, name, qtype, false)
	binary.BigEndian.PutUint16(query[10:12], 1)
	query = append(query, 0, 0, 41, byte(udpSize>>8), byte(udpSize), 0, 0, 0, 0, byte(len(options)>>8), byte(len(options)))
	return append(query, options...)
}

func TestRequestEDNSAndUDPLimit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		query    []byte
		present  bool
		limit    int
		wantSize uint16
	}{
		{"no OPT means 512", buildDNSQuery(1, "a.example.com", Enums.DNS_RECORD_TYPE_TXT, false), false, 512, 0},
		{"OPT 1232", queryWithOPT(t, "a.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232, nil), true, 1232, 1232},
		{"OPT 4096 with a cookie", queryWithOPT(t, "a.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096, []byte{0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}), true, 4096, 4096},
		{"OPT below 512 counts as 512", queryWithOPT(t, "a.example.com", Enums.DNS_RECORD_TYPE_TXT, 100, nil), true, 512, 100},
	} {
		parsed, err := ParseDNSRequestLite(tc.query)
		if err != nil {
			t.Fatal(err)
		}
		edns := RequestEDNS(tc.query, parsed)
		if edns.Present != tc.present || edns.UDPSize != tc.wantSize || edns.UDPLimit() != tc.limit {
			t.Errorf("%s: %+v limit %d", tc.name, edns, edns.UDPLimit())
		}
	}
}

func TestBuildResponseWritesCompressedRecordsAndOwnOPT(t *testing.T) {
	query := queryWithOPT(t, "Probe.Example.COM", Enums.DNS_RECORD_TYPE_A, 4096, []byte{0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	parsed, err := ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	soa, err := SOAData("ns.example.net", "hostmaster.example.com", 1, 3600, 600, 86400, 60)
	if err != nil {
		t.Fatal(err)
	}
	apex, ok := SuffixPointer(query, parsed, "example.com")
	if !ok {
		t.Fatal("example.com is a suffix of the question")
	}
	response, err := BuildResponse(query, parsed, Response{
		Authoritative: true,
		Answers:       []Record{{Type: Enums.DNS_RECORD_TYPE_A, TTL: 300, Data: AData([4]byte{192, 0, 2, 1})}},
		Authority:     []Record{{Owner: apex, Type: Enums.DNS_RECORD_TYPE_SOA, TTL: 60, Data: soa}},
	})
	if err != nil {
		t.Fatal(err)
	}
	full, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("answer does not parse: %v", err)
	}
	if full.Answers[0].Name != "probe.example.com" || full.Authorities[0].Name != "example.com" {
		t.Fatalf("owners %q %q", full.Answers[0].Name, full.Authorities[0].Name)
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8400 != 0x8400 || flags&0x0080 != 0 {
		t.Fatalf("flags %#x: want QR and AA, no RA", flags)
	}
	if !bytes.Equal(response[0:2], query[0:2]) || !bytes.Equal(response[12:12+len(query)-12-11-12], query[12:len(query)-11-12]) {
		t.Fatal("ID and question must be copied byte for byte (case included)")
	}
	if len(full.Additional) != 1 || full.Additional[0].Class != AdvertisedUDPSize || len(full.Additional[0].RData) != 0 {
		t.Fatalf("expected one empty OPT of size %d, got %+v", AdvertisedUDPSize, full.Additional)
	}
	if bytes.Contains(response, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("the client cookie was echoed")
	}
	// Without an OPT record in the query there is none in the answer.
	plain := buildDNSQuery(2, "probe.example.com", Enums.DNS_RECORD_TYPE_A, false)
	plainParsed, _ := ParseDNSRequestLite(plain)
	answer, err := BuildResponse(plain, plainParsed, Response{Authoritative: true})
	if err != nil || binary.BigEndian.Uint16(answer[10:12]) != 0 || len(answer) != len(plain) {
		t.Fatalf("answer to a query without OPT: %v len %d vs %d", err, len(answer), len(plain))
	}
}

func TestBuildTruncatedIsNeverLongerThanTheQuery(t *testing.T) {
	for _, edns := range []uint16{0, 512, 1232, 4096} {
		var query []byte
		if edns == 0 {
			query = buildDNSQuery(7, "a.b.c.example.com", Enums.DNS_RECORD_TYPE_TXT, false)
		} else {
			query = queryWithOPT(t, "a.b.c.example.com", Enums.DNS_RECORD_TYPE_TXT, edns, []byte{0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})
		}
		parsed, err := ParseDNSRequestLite(query)
		if err != nil {
			t.Fatal(err)
		}
		truncated, err := BuildTruncated(query, parsed, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(truncated) > len(query) {
			t.Fatalf("edns %d: TC answer %d bytes for a query of %d", edns, len(truncated), len(query))
		}
		flags := binary.BigEndian.Uint16(truncated[2:4])
		if flags&0x0200 == 0 || flags&0x000F != 0 || binary.BigEndian.Uint16(truncated[6:8]) != 0 {
			t.Fatalf("edns %d: flags %#x", edns, flags)
		}
	}
}

func TestBuildResponseAnswersAnUnsupportedEDNSVersionWithBADVERS(t *testing.T) {
	query := queryWithOPT(t, "a.example.com", Enums.DNS_RECORD_TYPE_A, 1232, nil)
	query[len(query)-5] = 1 // EDNS version 1
	parsed, _ := ParseDNSRequestLite(query)
	response, err := BuildResponse(query, parsed, Response{})
	if err != nil {
		t.Fatal(err)
	}
	if response[len(response)-6] != 1 {
		t.Fatalf("the extended RCODE of the OPT record is %d, want 1 (BADVERS)", response[len(response)-6])
	}
}

func TestSuffixPointerOnlyMatchesWholeLabels(t *testing.T) {
	query := buildDNSQuery(1, "x.notexample.com", Enums.DNS_RECORD_TYPE_A, false)
	parsed, _ := ParseDNSRequestLite(query)
	if _, ok := SuffixPointer(query, parsed, "example.com"); ok {
		t.Fatal("example.com matched inside notexample.com")
	}
	pointer, ok := SuffixPointer(query, parsed, "NotExample.com")
	if !ok || pointer[0]&0xC0 != 0xC0 {
		t.Fatal("a case-insensitive whole-label match was not found")
	}
	offset := int(pointer[0]&0x3F)<<8 | int(pointer[1])
	if query[offset] != byte(len("notexample")) {
		t.Fatalf("the pointer %d does not point at a label", offset)
	}
}

func TestDNSRequestIDsAreNotACounter(t *testing.T) {
	const n = 2000
	seen := make(map[uint16]int, n)
	sequential := 0
	previous := nextDNSRequestID()
	for i := 0; i < n; i++ {
		id := nextDNSRequestID()
		seen[id]++
		if id == previous+1 {
			sequential++
		}
		previous = id
	}
	if sequential > 5 {
		t.Fatalf("%d of %d IDs follow their predecessor: the ID is still a counter", sequential, n)
	}
	if len(seen) < n*9/10 {
		t.Fatalf("only %d distinct IDs of %d", len(seen), n)
	}
}

func TestVPNResponseUsesOnePointerPerRecordAndFitsTheAnnouncedSize(t *testing.T) {
	query, err := BuildTunnelTXTQuestionPacket("v.example.com", bytes.Repeat([]byte("a"), 100), Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	frame := bytes.Repeat([]byte{0x5A}, 700)
	response, err := BuildVPNResponsePayload(query, frame, false)
	if err != nil {
		t.Fatal(err)
	}
	full, err := ParsePacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Answers) < 3 {
		t.Fatalf("a 700-byte frame must be chunked, got %d records", len(full.Answers))
	}
	// 12 header + question + per record (2 pointer + 10 + 1 length byte [+1 chunk number]) + frame + OPT 11
	questionLen := len(query) - 12 - 11
	want := 12 + questionLen + len(frame) + len(full.Answers)*(2+10+1+1) + 11 + 1
	if len(response) != want {
		t.Fatalf("answer is %d bytes, expected %d for %d records", len(response), want, len(full.Answers))
	}
	got, err := ExtractVPNResponsePayload(response, false)
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("the frame did not survive the TXT chunking: %v", err)
	}
}
