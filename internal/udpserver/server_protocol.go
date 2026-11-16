package udpserver

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/compression"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	maxInitCache = 1024
	// maxInitAnswers bounds how often one INIT is answered with its cached ACCEPT.
	// A client retries and races the same INIT a handful of times; a captured INIT
	// replayed from a spoofed source would otherwise be answered for the whole
	// 120 s window with an answer larger than the request.
	maxInitAnswers = 16
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
	answers     int
}

func (s *Server) handleSecureTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	wire, err := baseCodec.DecodeString(decision.Labels)
	if err != nil {
		return nil
	}

	// 1. A frame of an established session: sid | ctr | AEAD(...).
	if len(wire) >= security.FramePrefixSize+16+1 {
		sessionID := wire[0]
		if record, ok := s.sessions.Get(sessionID); ok && record != nil {
			if cipher := record.cipher(); cipher != nil {
				plain, _, openErr := cipher.Open(wire)
				if errors.Is(openErr, security.ErrReplay) {
					return s.buildNoDataResponseLiteLogged(packet, parsed, "replayed-frame")
				}
				if openErr == nil {
					return s.handleAuthenticatedFrame(packet, parsed, decision, sessionID, plain)
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
			if response := s.handleSecureSessionInit(packet, decision.RequestName, credential, init, wire); response != nil {
				return response
			}
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
			return s.buildNoDataResponseLiteLogged(packet, parsed, "mtu-probe-rejected")
		}
		vpnPacket, parseErr := VpnProto.ParseInflated(probe.Payload)
		if parseErr != nil {
			return s.buildNoDataResponseLiteLogged(packet, parsed, "invalid-mtu-probe")
		}
		return s.handleAuthenticatedMTUProbe(packet, decision.RequestName, credential, vpnPacket)
	}
	if initLengthCandidate {
		return []byte{}
	}
	return nil
}

func (s *Server) handleAuthenticatedFrame(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision, sessionID uint8, plain []byte) []byte {
	vpnPacket, parseErr := VpnProto.ParseInflated(plain)
	if parseErr != nil {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "invalid-authenticated-frame")
	}
	vpnPacket.SessionID = sessionID

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return s.buildNoDataResponseLiteLogged(packet, parsed, "session-close-notice")
	}
	validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
	if !validation.ok {
		return validation.response
	}
	if !s.handlePostSessionPacket(vpnPacket, validation.record) {
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
	return s.serveQueuedOrPong(packet, decision.RequestName, validation.record, time.Now())
}

// handleSecureSessionInit answers an authenticated INIT; nil means "stay silent".
// The ACCEPT for an INIT is built once and cached until the INIT leaves its
// timestamp window. A repeat returns the same bytes and never makes a second
// session or a second key schedule for the same INIT.
func (s *Server) handleSecureSessionInit(questionPacket []byte, requestName string, credential security.Credential, init security.SessionInit, message []byte) []byte {
	key := initCacheKey{KID: init.KID, Ephemeral: init.Ephemeral}
	now := time.Now()
	s.protocolMu.Lock()
	defer s.protocolMu.Unlock()
	s.purgeInitCacheLocked(now)
	if cached, ok := s.initCache[key]; ok {
		if cached.answers >= maxInitAnswers {
			return nil
		}
		cached.answers++
		s.initCache[key] = cached
		if !bytes.Equal(cached.initMessage, message) {
			// ACCEPT authenticates the complete INIT transcript. Reusing the
			// same credential and ephemeral key with different INIT bytes cannot
			// be answered with the previous ACCEPT.
			return nil
		}
		response, buildErr := DnsParser.BuildVPNResponsePayload(questionPacket, requestName, cached.accept, cached.responseB64)
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
	requestedUpload, requestedDownload := compression.SplitPair(parameters[1])
	resolvedUpload := resolveCompressionType(requestedUpload, s.uploadCompressionMask)
	resolvedDownload := resolveCompressionType(requestedDownload, s.downloadCompressionMask)
	signature := make([]byte, 0, security.CredentialIDSize+len(init.Ephemeral))
	signature = append(signature, init.KID[:]...)
	signature = append(signature, init.Ephemeral[:]...)
	record, reused, err := s.sessions.findOrCreateWithSignature(
		parameters,
		signature,
		resolvedUpload,
		resolvedDownload,
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
		SessionID:       record.ID,
		CompressionPair: compression.PackPair(record.UploadCompression, record.DownloadCompression),
		VerifyCode:      record.VerifyCode,
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
			MinCompressionMinSize:     s.cfg.ClientMinCompressionMinSize,
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
	record.setCrypto(serverCipher, credential.ID)
	responseBase64 := parameters[0] == mtuProbeModeBase64
	// An INIT is accepted while now.Unix() is within 120 s of its timestamp, so
	// it stays cached until the second after that window closes.
	cacheUntil := time.Unix(int64(init.Timestamp)+int64(security.InitTimestampWindow/time.Second)+1, 0)
	s.initCache[key] = cachedInit{
		accept:      append([]byte(nil), accept...),
		initMessage: append([]byte(nil), message...),
		responseB64: responseBase64,
		expires:     cacheUntil,
		answers:     1,
	}
	if len(s.initCache) > maxInitCache {
		s.evictOldestInitLocked()
	}
	response, err := DnsParser.BuildVPNResponsePayload(questionPacket, requestName, accept, responseBase64)
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

func (s *Server) handleAuthenticatedMTUProbe(questionPacket []byte, requestName string, credential security.Credential, request VpnProto.Packet) []byte {
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
	raw, err := VpnProto.BuildRawAuto(VpnProto.BuildOptions{
		PacketType:      response.PacketType,
		StreamID:        response.StreamID,
		SequenceNum:     response.SequenceNum,
		FragmentID:      response.FragmentID,
		TotalFragments:  response.TotalFragments,
		CompressionType: response.CompressionType,
		Payload:         response.Payload,
	}, compression.DefaultMinSize)
	if err != nil {
		return nil
	}
	envelope, err := security.SealProbe(credential, raw, time.Now(), nil)
	if err != nil {
		return nil
	}
	return buildSecureProbeDNSResponse(questionPacket, requestName, envelope, base64Reply)
}

func buildSecureProbeDNSResponse(questionPacket []byte, requestName string, envelope []byte, base64Reply bool) []byte {
	response, err := DnsParser.BuildVPNResponsePayload(questionPacket, requestName, envelope, base64Reply)
	if err != nil {
		return nil
	}
	return response
}
