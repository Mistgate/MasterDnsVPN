package dnsparser

import (
	"bytes"
	"encoding/binary"
	"errors"

	Enums "masterdnsvpn-go/internal/enums"
)

const (
	// AdvertisedUDPSize is the UDP payload size every answer to an EDNS query
	// advertises in its own OPT record.
	AdvertisedUDPSize = 1232
	// MinUDPPayload is the UDP limit of a requester that sent no OPT record.
	MinUDPPayload = 512
)

// ownOPT is the only OPT record this server ever sends: root owner, type OPT,
// UDP payload size 1232, extended RCODE 0, version 0, no flags, no options.
// Nothing of the request's OPT (a client cookie, padding, ...) is echoed.
var ownOPT = []byte{0, 0, 41, byte(AdvertisedUDPSize >> 8), byte(AdvertisedUDPSize & 0xFF), 0, 0, 0, 0, 0, 0}

// OwnOPTSize is the size of the OPT record added to an answer.
func OwnOPTSize() int { return len(ownOPT) }

// EDNS describes the OPT record of a request.
type EDNS struct {
	Present bool
	UDPSize uint16
	Version uint8
}

// RequestEDNS reads the OPT record of a parsed request.
func RequestEDNS(request []byte, parsed LitePacket) EDNS {
	start, length := findOPTRecordRange(request, parsed.Header, parsed.QuestionEndOffset)
	if length < len(ownOPT) {
		return EDNS{}
	}
	record := request[start : start+length]
	if record[0] != 0 {
		return EDNS{}
	}
	return EDNS{
		Present: true,
		UDPSize: binary.BigEndian.Uint16(record[3:5]),
		Version: record[6],
	}
}

// UDPLimit is the largest UDP answer the requester accepts: its advertised
// payload size, at least 512, or 512 when it sent no OPT record.
func (e EDNS) UDPLimit() int {
	if !e.Present || e.UDPSize < MinUDPPayload {
		return MinUDPPayload
	}
	return int(e.UDPSize)
}

// Record is one resource record of an authoritative answer.
type Record struct {
	// Owner is a wire-format name or a two-byte compression pointer; nil means
	// the name of the question (pointer 0xC00C).
	Owner []byte
	Type  uint16
	TTL   uint32
	Data  []byte
}

// Response describes an answer built by BuildResponse.
type Response struct {
	RCode         uint8
	Authoritative bool
	Truncated     bool
	Answers       []Record
	Authority     []Record
}

var questionPointer = []byte{0xC0, 0x0C}

// BuildResponse builds the answer to a parsed request: the questions echoed
// verbatim, the records with compressed owner names, and an own OPT record
// when (and only when) the request carried one. RA is never set.
func BuildResponse(request []byte, parsed LitePacket, response Response) ([]byte, error) {
	if len(request) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}
	if !isLikelyDNSRequestHeader(parsed.Header) {
		return nil, ErrNotDNSRequest
	}
	questionLen := 0
	if parsed.QuestionEndOffset >= dnsHeaderSize && parsed.QuestionEndOffset <= len(request) {
		questionLen = parsed.QuestionEndOffset - dnsHeaderSize
	}
	edns := RequestEDNS(request, parsed)

	size := dnsHeaderSize + questionLen
	for _, record := range response.Answers {
		size += recordSize(record)
	}
	for _, record := range response.Authority {
		size += recordSize(record)
	}
	if edns.Present {
		size += len(ownOPT)
	}

	out := make([]byte, dnsHeaderSize, size)
	binary.BigEndian.PutUint16(out[0:2], parsed.Header.ID)
	binary.BigEndian.PutUint16(out[2:4], responseFlags(parsed.Header.Flags, response.RCode, response.Authoritative, response.Truncated))
	binary.BigEndian.PutUint16(out[4:6], parsed.Header.QDCount)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(response.Answers)))
	binary.BigEndian.PutUint16(out[8:10], uint16(len(response.Authority)))
	if edns.Present {
		binary.BigEndian.PutUint16(out[10:12], 1)
	}
	out = append(out, request[dnsHeaderSize:dnsHeaderSize+questionLen]...)
	for _, record := range response.Answers {
		out = appendRecord(out, record)
	}
	for _, record := range response.Authority {
		out = appendRecord(out, record)
	}
	if edns.Present {
		opt := append([]byte(nil), ownOPT...)
		if edns.Version != 0 {
			// Unsupported EDNS version: BADVERS, extended RCODE 1.
			opt[5] = 1
		}
		out = append(out, opt...)
	}
	return out, nil
}

// BuildTruncated is the answer that tells a UDP requester to retry over TCP:
// the questions and nothing else, TC set. It is never longer than the request.
func BuildTruncated(request []byte, parsed LitePacket, authoritative bool) ([]byte, error) {
	return BuildResponse(request, parsed, Response{Authoritative: authoritative, Truncated: true})
}

func recordSize(record Record) int {
	owner := len(record.Owner)
	if owner == 0 {
		owner = len(questionPointer)
	}
	return owner + 10 + len(record.Data)
}

func appendRecord(out []byte, record Record) []byte {
	if len(record.Owner) == 0 {
		out = append(out, questionPointer...)
	} else {
		out = append(out, record.Owner...)
	}
	out = binary.BigEndian.AppendUint16(out, record.Type)
	out = binary.BigEndian.AppendUint16(out, Enums.DNSQ_CLASS_IN)
	out = binary.BigEndian.AppendUint32(out, record.TTL)
	out = binary.BigEndian.AppendUint16(out, uint16(len(record.Data)))
	return append(out, record.Data...)
}

// WireName encodes a dotted name (no trailing dot required) in wire format.
func WireName(name string) ([]byte, error) { return encodeDNSNameStrict(name) }

// SuffixPointer returns a compression pointer to the place inside the first
// question where the labels of suffix start, so that an authority record owned
// by the zone apex costs two bytes. ok is false when suffix is not a suffix of
// the question name.
func SuffixPointer(request []byte, parsed LitePacket, suffix string) (pointer []byte, ok bool) {
	want, err := encodeDNSNameStrict(suffix)
	if err != nil || !parsed.HasQuestion {
		return nil, false
	}
	end := parsed.QuestionEndOffset - 4
	if end <= dnsHeaderSize || end > len(request) {
		return nil, false
	}
	name := request[dnsHeaderSize:end]
	for offset := 0; offset < len(name); {
		if len(name)-offset == len(want) && bytes.EqualFold(name[offset:], want) {
			position := dnsHeaderSize + offset
			if position > 0x3FFF {
				return nil, false
			}
			return []byte{0xC0 | byte(position>>8), byte(position)}, true
		}
		length := int(name[offset])
		if length == 0 || length > maxDNSLabelLen {
			return nil, false
		}
		offset += 1 + length
	}
	return nil, false
}

var errBadRData = errors.New("invalid record data")

// SOAData encodes the RDATA of an SOA record.
func SOAData(mname, rname string, serial, refresh, retry, expire, minimum uint32) ([]byte, error) {
	m, err := encodeDNSNameStrict(mname)
	if err != nil {
		return nil, err
	}
	r, err := encodeDNSNameStrict(rname)
	if err != nil {
		return nil, err
	}
	out := append(append([]byte(nil), m...), r...)
	for _, value := range []uint32{serial, refresh, retry, expire, minimum} {
		out = binary.BigEndian.AppendUint32(out, value)
	}
	return out, nil
}

// NSData encodes the RDATA of an NS record.
func NSData(name string) ([]byte, error) { return encodeDNSNameStrict(name) }

// AData encodes the RDATA of an A record.
func AData(address [4]byte) []byte { return append([]byte(nil), address[:]...) }

// TXTData encodes the RDATA of a TXT record holding one text of up to 255 bytes.
func TXTData(text string) ([]byte, error) {
	if len(text) > 255 {
		return nil, errBadRData
	}
	return append([]byte{byte(len(text))}, text...), nil
}
