package udpserver

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestSessionInitPolicyMTULimitsAreAppliedToServerSession(t *testing.T) {
	store := newSessionStore(16, 32)
	payload := make([]byte, sessionInitDataSize)
	payload[0] = mtuProbeModeRaw
	binary.BigEndian.PutUint16(payload[1:3], 999)
	binary.BigEndian.PutUint16(payload[3:5], 9999)
	copy(payload[5:9], []byte{1, 2, 3, 4})

	record, reused, err := store.findOrCreate(payload, 10, 150, 2048)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}
	if reused {
		t.Fatal("expected first session init not to be reused")
	}
	if record.UploadMTU != 150 {
		t.Fatalf("unexpected upload mtu clamp: got=%d want=%d", record.UploadMTU, 150)
	}
	if record.DownloadMTU != 2048 {
		t.Fatalf("unexpected download mtu clamp: got=%d want=%d", record.DownloadMTU, 2048)
	}
}

func TestSessionStoreHonorsConfiguredActiveSessionLimit(t *testing.T) {
	store := newSessionStore(16, 32)
	store.maxActiveSessions = 1

	payloadA := make([]byte, sessionInitDataSize)
	payloadA[0] = mtuProbeModeRaw
	copy(payloadA[5:9], []byte{1, 2, 3, 4})

	record, reused, err := store.findOrCreate(payloadA, 10, 150, 2048)
	if err != nil {
		t.Fatalf("first findOrCreate returned error: %v", err)
	}
	if reused || record == nil {
		t.Fatal("expected first session to be created")
	}

	payloadB := make([]byte, sessionInitDataSize)
	payloadB[0] = mtuProbeModeRaw
	copy(payloadB[5:9], []byte{5, 6, 7, 8})

	record, reused, err = store.findOrCreate(payloadB, 10, 150, 2048)
	if err != ErrSessionTableFull {
		t.Fatalf("expected ErrSessionTableFull, got record=%v reused=%v err=%v", record != nil, reused, err)
	}
}

func TestHandleSecureSessionInitIncludesServerClientPolicy(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.ClientMaxPacketDuplicationCount = 5
	cfg.ClientMaxSetupDuplicationCount = 6
	cfg.ClientMaxUploadMTU = 150
	cfg.ClientMaxDownloadMTU = 4096
	cfg.ClientMaxRxTxWorkers = 64
	cfg.ClientMinPingAggressiveInterval = 0.10
	cfg.ClientMaxPacketsPerBatch = 20
	cfg.ClientMaxARQWindowSize = 6000
	cfg.ClientMaxARQDataNackMaxGap = 200
	cfg.ClientMinARQInitialRTOSeconds = 0.25

	s, credential := newProtocolTestServer(t, cfg, nil)

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	verifyCode := [4]byte{1, 2, 3, 4}
	var parameters [security.InitParametersSize]byte
	parameters[0] = mtuProbeModeRaw
	binary.BigEndian.PutUint16(parameters[1:3], 220)
	binary.BigEndian.PutUint16(parameters[3:5], 5000)
	copy(parameters[5:9], verifyCode[:])
	handshake, initMessage := makeProtocolTestInit(t, credential, parameters)
	response := callSecureInit(s, query, "x.v.example.com", initMessage)
	if response == nil {
		t.Fatal("expected session accept response")
	}
	acceptWire, err := DnsParser.ExtractVPNResponsePayload(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponsePayload returned error: %v", err)
	}
	if len(acceptWire) > len(initMessage) {
		t.Fatalf("accept response grew beyond init request: got=%d want<=%d", len(acceptWire), len(initMessage))
	}
	accepted, _, err := handshake.OpenAccept(acceptWire)
	if err != nil {
		t.Fatalf("OpenAccept returned error: %v", err)
	}
	accept, err := VpnProto.DecodeSessionAcceptV1Policy(accepted.SessionID, accepted.Policy)
	if err != nil {
		t.Fatalf("DecodeSessionAcceptV1Policy returned error: %v", err)
	}
	if !accept.HasClientPolicySync {
		t.Fatal("expected session accept to include client policy sync block")
	}
	if accept.VerifyCode != verifyCode {
		t.Fatalf("unexpected verify code: got=%v want=%v", accept.VerifyCode, verifyCode)
	}
	if accept.ClientPolicy.MaxPacketDuplicationCount != cfg.ClientMaxPacketDuplicationCount {
		t.Fatalf("unexpected max packet duplication: got=%d want=%d", accept.ClientPolicy.MaxPacketDuplicationCount, cfg.ClientMaxPacketDuplicationCount)
	}
	if accept.ClientPolicy.MaxSetupDuplicationCount != cfg.ClientMaxSetupDuplicationCount {
		t.Fatalf("unexpected max setup duplication: got=%d want=%d", accept.ClientPolicy.MaxSetupDuplicationCount, cfg.ClientMaxSetupDuplicationCount)
	}
	if accept.ClientPolicy.MaxUploadMTU != cfg.ClientMaxUploadMTU {
		t.Fatalf("unexpected max upload mtu: got=%d want=%d", accept.ClientPolicy.MaxUploadMTU, cfg.ClientMaxUploadMTU)
	}
	if accept.ClientPolicy.MaxDownloadMTU != cfg.ClientMaxDownloadMTU {
		t.Fatalf("unexpected max download mtu: got=%d want=%d", accept.ClientPolicy.MaxDownloadMTU, cfg.ClientMaxDownloadMTU)
	}
	if accept.ClientPolicy.MaxRxTxWorkers != cfg.ClientMaxRxTxWorkers {
		t.Fatalf("unexpected max rx/tx workers: got=%d want=%d", accept.ClientPolicy.MaxRxTxWorkers, cfg.ClientMaxRxTxWorkers)
	}
	if accept.ClientPolicy.MinPingAggressiveInterval < 0.095 || accept.ClientPolicy.MinPingAggressiveInterval > 0.105 {
		t.Fatalf("unexpected min ping aggressive interval: got=%f", accept.ClientPolicy.MinPingAggressiveInterval)
	}
	if accept.ClientPolicy.MaxPacketsPerBatch != cfg.ClientMaxPacketsPerBatch {
		t.Fatalf("unexpected max packets per batch: got=%d want=%d", accept.ClientPolicy.MaxPacketsPerBatch, cfg.ClientMaxPacketsPerBatch)
	}
	if accept.ClientPolicy.MaxARQWindowSize != cfg.ClientMaxARQWindowSize {
		t.Fatalf("unexpected max arq window size: got=%d want=%d", accept.ClientPolicy.MaxARQWindowSize, cfg.ClientMaxARQWindowSize)
	}
	if accept.ClientPolicy.MaxARQDataNackMaxGap != cfg.ClientMaxARQDataNackMaxGap {
		t.Fatalf("unexpected max arq data nack gap: got=%d want=%d", accept.ClientPolicy.MaxARQDataNackMaxGap, cfg.ClientMaxARQDataNackMaxGap)
	}
	if accept.ClientPolicy.MinARQInitialRTOSeconds < 0.245 || accept.ClientPolicy.MinARQInitialRTOSeconds > 0.255 {
		t.Fatalf("unexpected min arq initial rto: got=%f", accept.ClientPolicy.MinARQInitialRTOSeconds)
	}
}

func TestHandleSecureSessionInitConcurrentDuplicatesShareAccept(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.ClientMaxUploadMTU = 150
	cfg.ClientMaxDownloadMTU = 4096
	s, credential := newProtocolTestServer(t, cfg, nil)
	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	var parameters [security.InitParametersSize]byte
	parameters[0] = mtuProbeModeRaw
	binary.BigEndian.PutUint16(parameters[1:3], 120)
	binary.BigEndian.PutUint16(parameters[3:5], 400)
	copy(parameters[5:9], []byte{1, 2, 3, 4})
	handshake, initMessage := makeProtocolTestInit(t, credential, parameters)

	const duplicates = 4
	responses := make([][]byte, duplicates)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range duplicates {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			responses[i] = callSecureInit(s, query, "x.v.example.com", initMessage)
		}(i)
	}
	close(start)
	wg.Wait()

	var acceptWire []byte
	for i, response := range responses {
		if response == nil {
			t.Fatalf("expected session accept response for duplicate %d", i)
		}
		got, err := DnsParser.ExtractVPNResponsePayload(response, false)
		if err != nil {
			t.Fatalf("ExtractVPNResponsePayload returned error: %v", err)
		}
		if i == 0 {
			acceptWire = got
		} else if !bytes.Equal(got, acceptWire) {
			t.Fatalf("duplicate init returned a different accept: first=%x duplicate=%x", acceptWire, got)
		}
	}
	accepted, _, err := handshake.OpenAccept(acceptWire)
	if err != nil {
		t.Fatalf("OpenAccept returned error: %v", err)
	}
	record, ok := s.sessions.Get(accepted.SessionID)
	if !ok {
		t.Fatalf("expected session %d to exist", accepted.SessionID)
	}
	if record.streamCleanup == nil {
		t.Fatal("expected the session record to clean up stream artifacts")
	}
}

func TestHandleStreamSynRequestRejectsWhenActiveStreamLimitIsReached(t *testing.T) {
	store := newSessionStore(16, 32)
	store.maxActiveStreams = 1

	payload := make([]byte, sessionInitDataSize)
	payload[0] = mtuProbeModeRaw
	copy(payload[5:9], []byte{1, 2, 3, 4})

	record, reused, err := store.findOrCreate(payload, 10, 150, 2048)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}
	if reused || record == nil {
		t.Fatal("expected a fresh session record")
	}

	stream := record.getOrCreateStream(1, arq.Config{}, nil, nil)
	if stream == nil {
		t.Fatal("expected first user stream to be created")
	}

	s := &Server{sessions: store}
	packet := VpnProto.Packet{
		SessionID:      record.ID,
		PacketType:     Enums.PACKET_STREAM_SYN,
		StreamID:       2,
		HasStreamID:    true,
		SequenceNum:    77,
		HasSequenceNum: true,
	}

	if !s.handleStreamSynRequest(packet, &sessionRuntimeView{ID: record.ID}) {
		t.Fatal("expected stream syn over limit to be handled")
	}
	if _, exists := record.getStream(2); exists {
		t.Fatal("did not expect a new stream to be created when limit is reached")
	}

	orphan, _, ok := record.OrphanQueue.Pop()
	if !ok {
		t.Fatal("expected rejection packet in orphan queue")
	}
	if orphan.PacketType != Enums.PACKET_STREAM_CONNECT_FAIL {
		t.Fatalf("unexpected rejection packet type: got=%d want=%d", orphan.PacketType, Enums.PACKET_STREAM_CONNECT_FAIL)
	}
	if orphan.StreamID != 2 || orphan.SequenceNum != 77 {
		t.Fatalf("unexpected rejection packet identity: stream=%d seq=%d", orphan.StreamID, orphan.SequenceNum)
	}
}
