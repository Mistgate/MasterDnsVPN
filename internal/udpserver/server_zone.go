package udpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
)

const (
	// DelegationCheckLabelPrefix starts the one name inside a zone that answers
	// a plain TXT query: _mgchk-<nonce>.<zone>.
	DelegationCheckLabelPrefix = "_mgchk-"

	zoneSOATTL      = 60
	zoneRecordTTL   = 300
	zoneSOARefresh  = 3600
	zoneSOARetry    = 600
	zoneSOAExpire   = 86400
	zoneSOAMinimum  = 60
	zoneSOASerial   = 1
	checkNonceMin   = 8
	checkNonceMax   = 32
	typeIXFR        = 251
	typeAXFR        = 252
	typeAnyQuestion = 255
)

// zoneResponder answers the few questions a resolver asks about a served zone
// that are not tunnel queries. It has no zone file: the apex has an SOA, an NS
// and an A record (when configured), the delegation check name has a TXT, and
// everything else inside the zone is an empty NOERROR answer. Names outside
// every zone are REFUSED.
type zoneResponder struct {
	nsName   string
	address  [4]byte
	hasAddr  bool
	checkKey []byte
}

func newZoneResponder(nsName, address, checkKeyHex string) *zoneResponder {
	z := &zoneResponder{nsName: strings.ToLower(strings.TrimSuffix(nsName, "."))}
	if addr, err := netip.ParseAddr(address); err == nil && addr.Is4() {
		z.address = addr.As4()
		z.hasAddr = true
	}
	if key, err := hex.DecodeString(checkKeyHex); err == nil && len(key) >= 16 {
		z.checkKey = key
	}
	return z
}

// DelegationCheckAnswer returns the text a node answers to _mgchk-<nonce>:
// hex(HMAC-SHA256(key, nonce)). A panel that knows the key proves that its
// query reached this node and not a stub or a rewriting resolver.
func DelegationCheckAnswer(key []byte, nonce string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// checkNonce extracts the nonce of a delegation check name: one label directly
// under the zone apex, _mgchk- followed by 8 to 32 characters of [a-z0-9].
func checkNonce(requestName, zone string) (string, bool) {
	suffix := "." + zone
	if !strings.HasSuffix(requestName, suffix) {
		return "", false
	}
	label := strings.TrimSuffix(requestName, suffix)
	if strings.Contains(label, ".") || !strings.HasPrefix(label, DelegationCheckLabelPrefix) {
		return "", false
	}
	nonce := label[len(DelegationCheckLabelPrefix):]
	if len(nonce) < checkNonceMin || len(nonce) > checkNonceMax {
		return "", false
	}
	for i := 0; i < len(nonce); i++ {
		c := nonce[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return "", false
		}
	}
	return nonce, true
}

func isDelegationCheckName(requestName, zone string) bool {
	suffix := "." + zone
	if !strings.HasSuffix(requestName, suffix) {
		return false
	}
	label := strings.TrimSuffix(requestName, suffix)
	return !strings.Contains(label, ".") && strings.HasPrefix(label, DelegationCheckLabelPrefix)
}

func (s *Server) answerZone(qc *queryContext, packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	qc.inZone = true
	z := s.zone
	if z == nil {
		z = &zoneResponder{}
	}
	zone := decision.BaseDomain
	qType := decision.QuestionType
	apex := decision.RequestName == zone

	build := func(response DnsParser.Response) []byte {
		out, err := DnsParser.BuildResponse(packet, parsed, response)
		if err != nil {
			return nil
		}
		return out
	}

	switch qType {
	case typeAXFR, typeIXFR:
		s.stats.refused.Add(1)
		return build(DnsParser.Response{RCode: Enums.DNSR_CODE_REFUSED})
	}

	soa := func() []DnsParser.Record {
		mname := z.nsName
		if mname == "" {
			mname = "ns." + zone
		}
		data, err := DnsParser.SOAData(mname, "hostmaster."+zone, zoneSOASerial, zoneSOARefresh, zoneSOARetry, zoneSOAExpire, zoneSOAMinimum)
		if err != nil {
			return nil
		}
		record := DnsParser.Record{Type: Enums.DNS_RECORD_TYPE_SOA, TTL: zoneSOATTL, Data: data}
		if !apex {
			if pointer, ok := DnsParser.SuffixPointer(packet, parsed, zone); ok {
				record.Owner = pointer
			} else if wire, err := DnsParser.WireName(zone); err == nil {
				record.Owner = wire
			}
		}
		return []DnsParser.Record{record}
	}

	if apex {
		switch qType {
		case Enums.DNS_RECORD_TYPE_SOA:
			return build(DnsParser.Response{Authoritative: true, Answers: soa()})
		case Enums.DNS_RECORD_TYPE_NS:
			if z.nsName != "" {
				if data, err := DnsParser.NSData(z.nsName); err == nil {
					return build(DnsParser.Response{Authoritative: true, Answers: []DnsParser.Record{{Type: Enums.DNS_RECORD_TYPE_NS, TTL: zoneRecordTTL, Data: data}}})
				}
			}
		case Enums.DNS_RECORD_TYPE_A:
			if z.hasAddr {
				return build(DnsParser.Response{Authoritative: true, Answers: []DnsParser.Record{{Type: Enums.DNS_RECORD_TYPE_A, TTL: zoneRecordTTL, Data: DnsParser.AData(z.address)}}})
			}
		}
	} else if qType == Enums.DNS_RECORD_TYPE_TXT && len(z.checkKey) > 0 {
		if nonce, ok := checkNonce(decision.RequestName, zone); ok {
			if data, err := DnsParser.TXTData(DelegationCheckAnswer(z.checkKey, nonce)); err == nil {
				return build(DnsParser.Response{Authoritative: true, Answers: []DnsParser.Record{{Type: Enums.DNS_RECORD_TYPE_TXT, Data: data}}})
			}
		}
	}

	// NODATA for everything else, never NXDOMAIN: a name below the apex may be
	// an empty non-terminal of a longer query name (QNAME minimisation), and an
	// NXDOMAIN there would cut the whole subtree off.
	withSOA := build(DnsParser.Response{Authoritative: true, Authority: soa()})
	if withSOA != nil && (qc.tcp || len(withSOA) <= qc.zoneLimit(packet)) {
		return withSOA
	}
	// The SOA would make the answer longer than the query: leave it out, an
	// answer without it is still a valid NODATA, only not cacheable by
	// resolvers for as long.
	return build(DnsParser.Response{Authoritative: true})
}
