// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"time"

	"masterdnsvpn-go/internal/arq"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (s *Server) validatePostSessionPacket(vpnPacket VpnProto.Packet) postSessionValidation {
	now := time.Now()
	validation := s.sessions.ValidateAndTouch(vpnPacket.SessionID, now)
	if validation.Valid {
		return postSessionValidation{
			record: validation.Active,
			ok:     true,
		}
	}
	return postSessionValidation{}
}

func (s *Server) handleSessionCloseNotice(vpnPacket VpnProto.Packet, now time.Time) {
	if s == nil || vpnPacket.SessionID == 0 {
		return
	}

	lookup, known := s.sessions.Lookup(vpnPacket.SessionID)
	if !known || lookup.State != sessionLookupActive {
		return
	}

	record, ok := s.sessions.Close(vpnPacket.SessionID, now, s.cfg.ClosedSessionRetention())
	if !ok {
		return
	}

	s.cleanupClosedSession(vpnPacket.SessionID, record)
	if s.log != nil {
		s.log.Infof(
			"\U0001F6AA <green>Session Closed By Client, Session: <cyan>%d</cyan></green>",
			vpnPacket.SessionID,
		)
	}
}

func (s *Server) buildSessionVPNResponse(qc *queryContext, questionPacket []byte, parsed DnsParser.LitePacket, record *sessionRuntimeView, packet VpnProto.Packet) []byte {
	if record == nil || record.Crypto == nil {
		return nil
	}
	raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		PacketType:     packet.PacketType,
		StreamID:       packet.StreamID,
		SequenceNum:    packet.SequenceNum,
		FragmentID:     packet.FragmentID,
		TotalFragments: packet.TotalFragments,
		Payload:        packet.Payload,
	})
	if err != nil {
		return nil
	}
	frame, err := record.Crypto.Seal(raw)
	if err != nil {
		return nil
	}
	if qc != nil && qc.hasCounter && record.Answers != nil && packet.PacketType != Enums.PACKET_PONG {
		// The answer may be lost, or come back too big for UDP and be asked
		// again over TCP: keep the sealed frame for the repeat (see answerCache).
		record.Answers.put(qc.counter, frame, qc.src.Addr(), time.Now())
	}
	response, err := DnsParser.BuildVPNResponseFromLite(questionPacket, parsed, frame, record.ResponseBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) queueSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	record, ok := s.sessions.Get(sessionID)
	if !ok {
		return false
	}

	if packet.StreamID == 0 {
		record.ensureStream0(s.log)
		stream, exists := record.getStream(0)
		if !exists || stream == nil {
			return false
		}

		return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, 0, packet.Payload)
	}

	stream, exists := record.getStream(packet.StreamID)
	if !exists || stream == nil {
		return false
	}

	return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, 0, packet.Payload)
}

func (s *Server) streamARQConfig() arq.Config {
	return arq.Config{
		WindowSize:                  s.cfg.ARQWindowSize,
		RTO:                         s.cfg.ARQInitialRTOSeconds,
		MaxRTO:                      s.cfg.ARQMaxRTOSeconds,
		EnableControlReliability:    true,
		ControlRTO:                  s.cfg.ARQControlInitialRTOSeconds,
		ControlMaxRTO:               s.cfg.ARQControlMaxRTOSeconds,
		ControlMaxRetries:           s.cfg.ARQMaxControlRetries,
		InactivityTimeout:           s.cfg.ARQInactivityTimeoutSeconds,
		DataPacketTTL:               s.cfg.ARQDataPacketTTLSeconds,
		MaxDataRetries:              s.cfg.ARQMaxDataRetries,
		DataNackMaxGap:              s.cfg.ARQDataNackMaxGap,
		DataNackInitialDelaySeconds: s.cfg.ARQDataNackInitialDelaySeconds,
		DataNackRepeatSeconds:       s.cfg.ARQDataNackRepeatSeconds,
		ControlPacketTTL:            s.cfg.ARQControlPacketTTLSeconds,
		TerminalDrainTimeout:        s.cfg.ARQTerminalDrainTimeoutSec,
		TerminalAckWaitTimeout:      s.cfg.ARQTerminalAckWaitTimeoutSec,
	}
}

func (s *Server) queueMainSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	packet.StreamID = 0
	return s.queueSessionPacket(sessionID, packet)
}

func (s *Server) cleanupClosedSession(sessionID uint8, record *sessionRecord) {
	if s == nil || sessionID == 0 {
		return
	}
	s.clearDeferredPacketsForSession(sessionID)
	s.removeSOCKS5SynFragmentsForSession(sessionID)
	if record != nil {
		record.closeAllStreams("session closed cleanup")
	}
	s.cleanupDeferredSessionState(sessionID)
}

func (s *Server) cleanupDeferredSessionState(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	if s.deferredDNSSession != nil {
		s.deferredDNSSession.RemoveSession(sessionID)
	}
	if s.deferredConnectSession != nil {
		s.deferredConnectSession.RemoveSession(sessionID)
	}
	s.removeDNSQueryFragmentsForSession(sessionID)
}

func (s *Server) cleanupIdleDeferredSession(sessionID uint8, lastActivityNano int64, now time.Time) {
	if s == nil || sessionID == 0 {
		return
	}

	s.clearDeferredPacketsForSession(sessionID)
	s.removeSOCKS5SynFragmentsForSession(sessionID)
	s.cleanupDeferredSessionState(sessionID)
}

func (s *Server) cleanupStreamArtifacts(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.clearDeferredPacketsForStream(sessionID, streamID)
	s.removeSOCKS5SynFragmentsForStream(sessionID, streamID)
}

func (s *Server) finalizeStreamArtifacts(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.finalizeDeferredPacketsForStream(sessionID, streamID)
	s.removeSOCKS5SynFragmentsForStream(sessionID, streamID)
}

func (s *Server) serveQueuedOrPong(qc *queryContext, questionPacket []byte, parsed DnsParser.LitePacket, record *sessionRuntimeView, now time.Time) []byte {
	if record == nil {
		return nil
	}

	sessionID := record.ID

	if pkt, ok := s.dequeueSessionResponse(sessionID, now); ok {
		return s.buildSessionVPNResponse(qc, questionPacket, parsed, record, *pkt)
	}

	payload := s.nextPongPayload()
	return s.buildSessionVPNResponse(qc, questionPacket, parsed, record, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload[:],
	})
}

func (s *Server) dequeueSessionResponse(sessionID uint8, now time.Time) (*VpnProto.Packet, bool) {
	record, ok := s.sessions.Get(sessionID)
	if !ok {
		return nil, false
	}

	record.mu.Lock()
	if pkt, ok := s.dequeueDuplicatedPackedControlBlock(record); ok {
		record.mu.Unlock()
		return pkt, true
	}
	rrStreamID := record.RRStreamID
	record.mu.Unlock()

	readyIDs, readyStreams := record.activeStreamSnapshot()
	hasOrphan := record.OrphanQueue != nil && record.OrphanQueue.FastSize() > 0
	totalCandidates := len(readyIDs)

	if hasOrphan {
		totalCandidates++
	}

	if totalCandidates == 0 {
		return nil, false
	}

	startIdx := 0
	candidateAt := func(idx int) (int32, *Stream_server) {
		if hasOrphan {
			if idx == 0 {
				return -1, nil
			}
			idx--
		}
		if idx < 0 || idx >= len(readyIDs) {
			return 0, nil
		}
		return readyIDs[idx], readyStreams[idx]
	}

	for i := 0; i < totalCandidates; i++ {
		id, _ := candidateAt(i)
		if id >= rrStreamID {
			startIdx = i
			break
		}
	}

	for i := 0; i < totalCandidates; i++ {
		idx := (startIdx + i) % totalCandidates
		id, stream := candidateAt(idx)

		var item *serverStreamTXPacket
		var ok bool
		var selectedStreamID uint16

		if id == -1 {
			p, _, popOk := record.OrphanQueue.Pop()
			if popOk {
				item = &serverStreamTXPacket{
					PacketType:     p.PacketType,
					SequenceNum:    p.SequenceNum,
					FragmentID:     p.FragmentID,
					TotalFragments: p.TotalFragments,
					Payload:        p.Payload,
				}
				selectedStreamID = p.StreamID
				ok = true
			}
		} else {
			if stream == nil || stream.TXQueue == nil || stream.FastTXQueueSize() == 0 {
				continue
			}
			if stream.ARQ != nil && stream.ARQ.IsClosed() {
				stream.ClearTXQueue()
				record.deactivateStream(uint16(id))
				continue
			}
			var popped *serverStreamTXPacket
			popped, _, ok = stream.PopNextTXPacket()
			if ok {
				stream.NoteTXPacketDequeued(popped)
				if (popped.PacketType == Enums.PACKET_STREAM_DATA || popped.PacketType == Enums.PACKET_STREAM_RESEND) &&
					stream.ARQ != nil && !stream.ARQ.HasPendingSequence(popped.SequenceNum) {
					putTXPacketToPool(popped)
					continue
				}
				item = popped
				selectedStreamID = uint16(id)
			}
		}

		if ok && item != nil {
			record.mu.Lock()
			record.RRStreamID = id + 1
			if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && record.MaxPackedBlocks > 1 {
				pkt := s.packControlBlocks(record, item, id, selectedStreamID)
				s.cachePackedControlBlockDuplicate(record, pkt)
				record.mu.Unlock()
				return pkt, true
			}
			record.mu.Unlock()
			pkt := vpnPacketFromTX(item, selectedStreamID)
			if id != -1 {
				putTXPacketToPool(item)
			}
			return &pkt, true
		}
	}

	return nil, false
}

func cloneVPNPacket(packet *VpnProto.Packet) *VpnProto.Packet {
	if packet == nil {
		return nil
	}
	cloned := *packet
	if len(packet.Payload) > 0 {
		cloned.Payload = append([]byte(nil), packet.Payload...)
	}
	return &cloned
}

func (s *Server) dequeueDuplicatedPackedControlBlock(record *sessionRecord) (*VpnProto.Packet, bool) {
	if s == nil || record == nil || record.LastPackedControlBlock == nil || record.LastPackedControlBlockRemaining <= 0 {
		return nil, false
	}
	packet := cloneVPNPacket(record.LastPackedControlBlock)
	record.LastPackedControlBlockRemaining--
	if record.LastPackedControlBlockRemaining <= 0 {
		record.LastPackedControlBlock = nil
		record.LastPackedControlBlockRemaining = 0
	}
	return packet, packet != nil
}

func (s *Server) cachePackedControlBlockDuplicate(record *sessionRecord, packet *VpnProto.Packet) {
	if s == nil || record == nil {
		return
	}
	duplication := s.cfg.PacketBlockControlDuplication
	if duplication <= 1 || packet == nil || packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		record.LastPackedControlBlock = nil
		record.LastPackedControlBlockRemaining = 0
		return
	}
	record.LastPackedControlBlock = cloneVPNPacket(packet)
	record.LastPackedControlBlockRemaining = duplication - 1
}

func (s *Server) packControlBlocks(record *sessionRecord, first *serverStreamTXPacket, initialID int32, initialStreamID uint16) *VpnProto.Packet {
	limit := record.MaxPackedBlocks
	if limit <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		return &pkt
	}

	payload := make([]byte, 0, limit*VpnProto.PackedControlBlockSize)
	payload = VpnProto.AppendPackedControlBlock(payload, first.PacketType, initialStreamID, first.SequenceNum, first.FragmentID, first.TotalFragments)
	blocks := 1

	readyIDs, readyStreams := record.activeStreamSnapshot()
	hasOrphan := record.OrphanQueue != nil && record.OrphanQueue.FastSize() > 0

	processID := func(id int32, stream *Stream_server) bool {
		if blocks >= limit {
			return true
		}

		if id == -1 {
			for blocks < limit {
				if record.OrphanQueue == nil || record.OrphanQueue.FastSize() == 0 {
					return false
				}
				popped, ok := record.OrphanQueue.PopAnyIf(2, func(p VpnProto.Packet) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, 0)
				}, func(p VpnProto.Packet) uint64 {
					return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
				})
				if !ok {
					return false
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
			}
			return false
		}

		if stream == nil || stream.TXQueue == nil {
			return false
		}

		for blocks < limit {
			if stream.FastTXQueueSize() == 0 {
				return false
			}
			popped, ok := stream.PopAnyTXPacket(2, func(p *serverStreamTXPacket) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
			})
			if !ok {
				return false
			}
			stream.NoteTXPacketDequeued(popped)
			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(id), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
			blocks++
			putTXPacketToPool(popped)
		}
		return false
	}

	var initialStream *Stream_server
	var initialIndex int = -1
	if initialID != -1 {
		for i, id := range readyIDs {
			if id == initialID {
				initialIndex = i
				initialStream = readyStreams[i]
				break
			}
		}
	}
	if processID(initialID, initialStream) {
		goto buildResult
	}

	if hasOrphan && initialID != -1 {
		if processID(-1, nil) {
			goto buildResult
		}
	}

	if initialIndex >= 0 {
		for i := initialIndex + 1; i < len(readyIDs); i++ {
			if processID(readyIDs[i], readyStreams[i]) {
				goto buildResult
			}
		}
		for i := 0; i < initialIndex; i++ {
			if processID(readyIDs[i], readyStreams[i]) {
				goto buildResult
			}
		}
	} else {
		for i, id := range readyIDs {
			if processID(id, readyStreams[i]) {
				goto buildResult
			}
		}
	}

	if initialID == -1 && hasOrphan {
		for i, id := range readyIDs {
			if processID(id, readyStreams[i]) {
				goto buildResult
			}
		}
	}

buildResult:
	if blocks <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)

		if initialID != -1 {
			putTXPacketToPool(first)
		}
		return &pkt
	}

	if initialID != -1 {
		putTXPacketToPool(first)
	}

	return &VpnProto.Packet{
		PacketType:  Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Payload:     payload,
		StreamID:    0,
		HasStreamID: true,
	}
}

func vpnPacketFromTX(p *serverStreamTXPacket, streamID uint16) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:      p.PacketType,
		StreamID:        streamID,
		SequenceNum:     p.SequenceNum,
		FragmentID:      p.FragmentID,
		TotalFragments:  p.TotalFragments,
		Payload:         p.Payload,
		HasSequenceNum:  p.SequenceNum != 0,
		HasFragmentInfo: p.FragmentID != 0 || p.TotalFragments != 0,
		HasStreamID:     true,
	}
}

func (s *Server) nextPongPayload() [7]byte {
	var payload [7]byte
	payload[0] = 'P'
	payload[1] = 'O'
	payload[2] = ':'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:], nonce)
	return payload
}

func deferredSessionLaneForPacket(packet VpnProto.Packet) deferredSessionLane {
	return deferredSessionLane{
		sessionID: packet.SessionID,
		streamID:  packet.StreamID,
	}
}

func isDeferredPostSessionPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_DNS_QUERY_REQ,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_SOCKS5_SYN:
		return true
	default:
		return false
	}
}

func (s *Server) dispatchDeferredSessionPacket(packet VpnProto.Packet, run func(context.Context)) bool {
	if s == nil || !isDeferredPostSessionPacketType(packet.PacketType) {
		return false
	}
	var processor *deferredSessionProcessor
	switch packet.PacketType {
	case Enums.PACKET_DNS_QUERY_REQ:
		processor = s.deferredDNSSession
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
		processor = s.deferredConnectSession
	default:
		return false
	}
	if processor == nil {
		return false
	}
	return processor.Enqueue(deferredSessionLaneForPacket(packet), run)
}

func isPreSessionRequestType(packetType uint8) bool {
	return preSessionPacketTypes[packetType]
}

func buildPreSessionPacketTypes() [256]bool {
	var values [256]bool
	values[Enums.PACKET_SESSION_INIT] = true
	values[Enums.PACKET_MTU_UP_REQ] = true
	values[Enums.PACKET_MTU_DOWN_REQ] = true
	return values
}
