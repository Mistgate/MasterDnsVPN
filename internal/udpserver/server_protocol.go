package udpserver

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	maxInitCache = 1024
	// maxInitUDPAnswers bounds how often one INIT is answered over UDP with its
	// cached ACCEPT. A client retries and races the same INIT a handful of
	// times (three racing queries in each of three attempts); a captured INIT
	// replayed from a spoofed source would otherwise be answered for the whole
	// 120 s window. An ACCEPT is longer than its INIT
	// (the question is echoed in both, the ACCEPT adds its own record), so the
	// worst a captured INIT can reflect is maxInitUDPAnswers answers of about
	// 1.5 times the INIT each. TCP cannot be spoofed and has its own, larger
	// bound.
	maxInitUDPAnswers = 9
	maxInitTCPAnswers = 16
)

type initCacheKey struct {
	KID       [security.CredentialIDSize]byte
	Ephemeral [32]byte
}

type cachedInit struct {
	accept      []byte
	initMessage []byte
	responseB64 bool
	expires     time.Time
	udpAnswers  int
	tcpAnswers  int
	credential  string
}

func (s *Server) handleSecureTunnelCandidate(qc *queryContext, packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	wire, err := baseCodec.DecodeString(decision.Labels)
	if err != nil {
		return nil
	}

	// 1. A frame of an established session: sid | ctr | AEAD(...).
	if len(wire) >= security.FramePrefixSize+16+1 {
		sessionID := wire[0]
		if record, ok := s.sessions.Get(sessionID); ok && record != nil {
			if cipher := record.cipher(); cipher != nil {
				plain, counter, openErr := cipher.Open(wire)
				if errors.Is(openErr, security.ErrReplay) {
					return s.handleReplayedFrame(qc, packet, parsed, record, counter)
				}
				if openErr == nil {
					qc.authenticated = true
					qc.session = record
					qc.counter, qc.hasCounter = counter, true
					record.noteSource(qc.src.Addr())
					return s.handleAuthenticatedFrame(qc, packet, parsed, sessionID, plain)
				}
			}
		}
	}

	// 2. INIT and pre-session probes share their first byte (the version) with
	// session id 1, so they are tried after the session lookup and are answered
	// only when they authenticate.
	initLengthCandidate := len(wire) == security.SessionInitSize
	if initLengthCandidate && wire[0] == security.ProtocolVersion {
		if credential, init, err := security.OpenSessionInit(wire, s.credentialIndex, time.Now()); err == nil {
			// Keep rejected INITs silent rather than letting the generic DNS
			// fallback turn them into responses.
			qc.authenticated = true
			if response := s.handleSecureSessionInit(qc, packet, parsed, credential, init, wire); response != nil {
				return response
			}
			qc.authenticated = false
			return []byte{}
		}
	}

	if len(wire) >= 2 && wire[0] == security.ProtocolVersion && wire[1] == security.ProbeKindMTU {
		credential, probe, probeErr := security.OpenProbe(wire, s.credentialIndex)
		if probeErr != nil {
			return []byte{}
		}
		if !s.probeLimiter.Allow(credential.KID, probe.Nonce, time.Now()) {
			// Replayed, stale or over budget: a small answer without data.
			s.stats.probeLimited.Add(1)
			return s.buildInZoneNoData(packet, parsed)
		}
		vpnPacket, parseErr := VpnProto.Parse(probe.Payload)
		if parseErr != nil {
			return s.buildInZoneNoData(packet, parsed)
		}
		qc.authenticated = true
		return s.handleAuthenticatedMTUProbe(packet, parsed, credential, vpnPacket)
	}
	if initLengthCandidate {
		return []byte{}
	}
	return nil
}

// handleReplayedFrame answers a frame whose tag verified but whose counter the
// replay window already used: a resolver that asked again, or the TCP retry of
// an answer that came back truncated. The sealed answer of the first copy is
// repeated when the repeat is allowed (see answerCache); otherwise the answer
// is the usual empty one, no longer than the query.
func (s *Server) handleReplayedFrame(qc *queryContext, packet []byte, parsed DnsParser.LitePacket, record *sessionRecord, counter uint32) []byte {
	s.stats.replays.Add(1)
	if frame, ok := record.answers.get(counter, qc.src.Addr(), qc.tcp, time.Now()); ok {
		response, err := DnsParser.BuildVPNResponseFromLite(packet, parsed, frame, record.ResponseMode == mtuProbeModeBase64)
		if err == nil {
			s.stats.cacheServed.Add(1)
			qc.authenticated = true
			qc.session = record
			return response
		}
	}
	return s.buildInZoneNoData(packet, parsed)
}

func (s *Server) handleAuthenticatedFrame(qc *queryContext, packet []byte, parsed DnsParser.LitePacket, sessionID uint8, plain []byte) []byte {
	now := time.Now()
	if qc.session != nil && !qc.session.allowRequest(now, s.requestRate) {
		s.stats.rateLimited.Add(1)
		qc.authenticated = false
		return s.buildInZoneNoData(packet, parsed)
	}
	vpnPacket, parseErr := VpnProto.Parse(plain)
	if parseErr != nil {
		return s.buildInZoneNoData(packet, parsed)
	}
	vpnPacket.SessionID = sessionID

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, now)
		return s.buildInZoneNoData(packet, parsed)
	}
	validation := s.validatePostSessionPacket(vpnPacket)
	if !validation.ok {
		return s.buildInZoneNoData(packet, parsed)
	}
	if !s.handlePostSessionPacket(vpnPacket, validation.record) {
		return s.buildInZoneNoData(packet, parsed)
	}
	return s.serveQueuedOrPong(qc, packet, parsed, validation.record, time.Now())
}

// handleSecureSessionInit answers an authenticated INIT; nil means "stay silent".
// The ACCEPT for an INIT is built once and cached until the INIT leaves its
// timestamp window. A repeat returns the same bytes and never makes a second
// session or a second key schedule for the same INIT.
func (s *Server) handleSecureSessionInit(qc *queryContext, questionPacket []byte, parsed DnsParser.LitePacket, credential security.Credential, init security.SessionInit, message []byte) []byte {
	key := initCacheKey{KID: init.KID, Ephemeral: init.Ephemeral}
	now := time.Now()
	s.protocolMu.Lock()
	defer s.protocolMu.Unlock()
	s.purgeInitCacheLocked(now)
	if cached, ok := s.initCache[key]; ok {
		if qc.tcp {
			if cached.tcpAnswers >= maxInitTCPAnswers {
				return nil
			}
			cached.tcpAnswers++
		} else {
			if cached.udpAnswers >= maxInitUDPAnswers {
				return nil
			}
			cached.udpAnswers++
		}
		s.initCache[key] = cached
		if !bytes.Equal(cached.initMessage, message) {
			// ACCEPT authenticates the complete INIT transcript. Reusing the
			// same credential and ephemeral key with different INIT bytes cannot
			// be answered with the previous ACCEPT.
			return nil
		}
		response, buildErr := DnsParser.BuildVPNResponseFromLite(questionPacket, parsed, cached.accept, cached.responseB64)
		if buildErr != nil {
			return nil
		}
		return response
	}

	// Reject a low-order or otherwise unusable client key before a session slot
	// is taken for it.
	serverEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	clientPublic, err := ecdh.X25519().NewPublicKey(init.Ephemeral[:])
	if err != nil {
		return nil
	}
	if _, err := serverEphemeral.ECDH(clientPublic); err != nil {
		return nil
	}

	parameters := init.Parameters[:]
	signature := make([]byte, 0, security.CredentialIDSize+len(init.Ephemeral))
	signature = append(signature, init.KID[:]...)
	signature = append(signature, init.Ephemeral[:]...)
	s.enforceCredentialSessionLimit(credential.ID, signature)
	record, reused, err := s.sessions.findOrCreateWithSignature(
		parameters,
		signature,
		s.cfg.EffectiveMaxPacketsPerBatch(),
		s.cfg.ClientMaxUploadMTU,
		s.cfg.ClientMaxDownloadMTU,
	)
	if err != nil || record == nil {
		return nil
	}
	if reused {
		// The session exists but its ACCEPT is no longer cached. A second ACCEPT
		// would carry a new server key and desynchronise the client that already
		// holds the first one, so a replayed INIT must not produce one.
		return nil
	}

	policy := VpnProto.EncodeSessionAcceptV1Policy(VpnProto.SessionAcceptPayload{
		SessionID:  record.ID,
		VerifyCode: record.VerifyCode,
		ClientPolicy: VpnProto.SessionAcceptClientPolicy{
			MaxPacketDuplicationCount: s.cfg.ClientMaxPacketDuplicationCount,
			MaxSetupDuplicationCount:  s.cfg.ClientMaxSetupDuplicationCount,
			MaxUploadMTU:              s.cfg.ClientMaxUploadMTU,
			MaxDownloadMTU:            s.cfg.ClientMaxDownloadMTU,
			MaxRxTxWorkers:            s.cfg.ClientMaxRxTxWorkers,
			MinPingAggressiveInterval: s.cfg.ClientMinPingAggressiveInterval,
			MaxPacketsPerBatch:        s.cfg.ClientMaxPacketsPerBatch,
			MaxARQWindowSize:          s.cfg.ClientMaxARQWindowSize,
			MaxARQDataNackMaxGap:      s.cfg.ClientMaxARQDataNackMaxGap,
			MinARQInitialRTOSeconds:   s.cfg.ClientMinARQInitialRTOSeconds,
		},
		HasClientPolicySync: true,
	})
	accept, keys, err := security.BuildSessionAccept(credential, message, record.ID, policy, serverEphemeral)
	if err != nil {
		s.sessions.discardUnestablished(record)
		return nil
	}
	serverCipher, err := security.NewSessionCipher(record.ID, keys.ServerToClient, keys.ClientToServer)
	if err != nil {
		s.sessions.discardUnestablished(record)
		return nil
	}
	record.setCrypto(serverCipher, credential)
	responseBase64 := parameters[0] == mtuProbeModeBase64
	// An INIT is accepted while now.Unix() is within 120 s of its timestamp, so
	// it stays cached until the second after that window closes.
	cacheUntil := time.Unix(int64(init.Timestamp)+int64(security.InitTimestampWindow/time.Second)+1, 0)
	entry := cachedInit{
		accept:      append([]byte(nil), accept...),
		initMessage: append([]byte(nil), message...),
		responseB64: responseBase64,
		expires:     cacheUntil,
		credential:  credential.ID,
	}
	if qc.tcp {
		entry.tcpAnswers = 1
	} else {
		entry.udpAnswers = 1
	}
	s.initCache[key] = entry
	if len(s.initCache) > maxInitCache {
		s.evictOldestInitLocked()
	}
	response, err := DnsParser.BuildVPNResponseFromLite(questionPacket, parsed, accept, responseBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) purgeInitCacheLocked(now time.Time) {
	for key, value := range s.initCache {
		if !now.Before(value.expires) {
			delete(s.initCache, key)
		}
	}
}

// dropInitCacheForCredential forgets the cached ACCEPTs of a credential whose
// sessions were just closed, so that a repeated INIT cannot hand out the keys
// of a session that no longer exists.
func (s *Server) dropInitCacheForCredential(credentialID string) {
	s.protocolMu.Lock()
	defer s.protocolMu.Unlock()
	for key, value := range s.initCache {
		if value.credential == credentialID {
			delete(s.initCache, key)
		}
	}
}

func (s *Server) evictOldestInitLocked() {
	var oldest initCacheKey
	var expires time.Time
	first := true
	for key, value := range s.initCache {
		if first || value.expires.Before(expires) {
			oldest, expires, first = key, value.expires, false
		}
	}
	if !first {
		delete(s.initCache, oldest)
	}
}

func (s *Server) handleAuthenticatedMTUProbe(questionPacket []byte, parsed DnsParser.LitePacket, credential security.Credential, request VpnProto.Packet) []byte {
	var response VpnProto.Packet
	base64Reply := false
	switch request.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		if len(request.Payload) < mtuProbeUpMinSize {
			return nil
		}
		var ok bool
		base64Reply, ok = parseMTUProbeBaseEncoding(request.Payload[0])
		if !ok {
			return nil
		}
		payload := buildMTUProbeMetaPayload(request.Payload[1:mtuProbeUpMinSize], len(request.Payload))
		response = VpnProto.Packet{PacketType: Enums.PACKET_MTU_UP_RES, Payload: payload[:]}
	case Enums.PACKET_MTU_DOWN_REQ:
		if len(request.Payload) < mtuProbeDownMinSize {
			return nil
		}
		var ok bool
		base64Reply, ok = parseMTUProbeBaseEncoding(request.Payload[0])
		if !ok {
			return nil
		}
		downloadSize := int(binary.BigEndian.Uint16(request.Payload[mtuProbeUpMinSize:mtuProbeDownMinSize]))
		if downloadSize < mtuProbeMinDownSize || downloadSize > mtuProbeMaxDownSize {
			return nil
		}
		payload := make([]byte, downloadSize)
		copy(payload[:mtuProbeCodeLength], request.Payload[1:mtuProbeUpMinSize])
		binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(downloadSize))
		if downloadSize > mtuProbeMetaLength {
			fillMTUProbeBytes(payload[mtuProbeMetaLength:])
		}
		response = VpnProto.Packet{
			PacketType:     Enums.PACKET_MTU_DOWN_RES,
			StreamID:       request.StreamID,
			SequenceNum:    request.SequenceNum,
			FragmentID:     request.FragmentID,
			TotalFragments: request.TotalFragments,
			Payload:        payload,
		}
	default:
		return nil
	}
	raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		PacketType:     response.PacketType,
		StreamID:       response.StreamID,
		SequenceNum:    response.SequenceNum,
		FragmentID:     response.FragmentID,
		TotalFragments: response.TotalFragments,
		Payload:        response.Payload,
	})
	if err != nil {
		return nil
	}
	envelope, err := security.SealProbe(credential, raw, time.Now(), nil)
	if err != nil {
		return nil
	}
	answer, err := DnsParser.BuildVPNResponseFromLite(questionPacket, parsed, envelope, base64Reply)
	if err != nil {
		return nil
	}
	return answer
}
