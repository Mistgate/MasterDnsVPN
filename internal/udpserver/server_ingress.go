package udpserver

import (
	"errors"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
)

// handlePacket answers a packet without the size policy of HandleQuery. It is
// the entry point of the in-package tests.
func (s *Server) handlePacket(packet []byte) []byte {
	return s.handlePacketCtx(&queryContext{}, packet)
}

func (s *Server) handlePacketCtx(qc *queryContext, packet []byte) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}
	qc.parsed = parsed
	qc.hasParsed = true

	return s.handleParsedPacket(qc, packet, parsed)
}

func (s *Server) handleParsedPacket(qc *queryContext, packet []byte, parsed DnsParser.LitePacket) []byte {
	if parsed.Header.QR != 0 {
		return nil
	}

	if !parsed.HasQuestion || len(parsed.Questions) != 1 {
		return s.buildFormatErrorResponseLiteLogged(packet, parsed, "request-question-count")
	}
	if parsed.Header.OpCode != 0 {
		response, err := DnsParser.BuildNotImplementedResponseFromLite(packet, parsed)
		if err != nil {
			return nil
		}
		return response
	}

	decision := s.domainMatcher.Match(parsed)
	switch decision.Action {
	case domainMatcher.ActionProcess:
		if isDelegationCheckName(decision.RequestName, decision.BaseDomain) {
			return s.answerZone(qc, packet, parsed, decision)
		}
		qc.inZone = true
		response := s.handleTunnelCandidate(qc, packet, parsed, decision)
		if response != nil {
			return response
		}

		return s.buildInZoneNoData(packet, parsed)
	case domainMatcher.ActionFormatError:
		return s.buildFormatErrorResponseLiteLogged(packet, parsed, decision.Reason)
	case domainMatcher.ActionRefused:
		s.stats.refused.Add(1)
		response, err := DnsParser.BuildRefusedResponseFromLite(packet, parsed)
		if err != nil {
			return nil
		}
		return response
	case domainMatcher.ActionNoData:
		return s.answerZone(qc, packet, parsed, decision)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-unknown-action")
	}
}

func (s *Server) handleTunnelCandidate(qc *queryContext, packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	return s.handleSecureTunnelCandidate(qc, packet, parsed, decision)
}
