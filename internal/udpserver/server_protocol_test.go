package udpserver

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func buildSessionInitQuestion(t *testing.T, credential security.Credential, timestamp uint32, version ...byte) []byte {
	t.Helper()
	var parameters [security.InitParametersSize]byte
	return buildSessionInitQuestionWithParameters(t, credential, timestamp, parameters, protocolTestPrivateKey(t), version...)
}

func buildSessionInitQuestionWithParameters(
	t *testing.T,
	credential security.Credential,
	timestamp uint32,
	parameters [security.InitParametersSize]byte,
	private *ecdh.PrivateKey,
	version ...byte,
) []byte {
	t.Helper()
	initMessage, err := security.BuildSessionInit(credential, parameters, timestamp, private)
	if err != nil {
		t.Fatalf("BuildSessionInit failed: %v", err)
	}
	if len(version) > 0 {
		initMessage[0] = version[0]
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket("example.com", baseCodec.EncodeToBytes(initMessage), Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTunnelTXTQuestionPacket failed: %v", err)
	}
	return query
}

func TestSameEphemeralWithDifferentInitTranscriptIsSilentlyRejected(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{"example.com"}
	cfg.MinVPNLabelLength = 3
	server, credential := newProtocolTestServer(t, cfg, nil)
	timestamp := uint32(time.Now().Unix())
	private := protocolTestPrivateKey(t)
	var parameters [security.InitParametersSize]byte

	firstQuery := buildSessionInitQuestionWithParameters(t, credential, timestamp, parameters, private)
	firstResponse := server.HandlePacket(firstQuery)
	if len(firstResponse) == 0 {
		t.Fatal("expected first INIT to receive ACCEPT")
	}

	parameters[1] ^= 1
	changedQuery := buildSessionInitQuestionWithParameters(t, credential, timestamp, parameters, private)
	changedResponse := server.HandlePacket(changedQuery)
	if len(changedResponse) != 0 {
		t.Fatalf("different INIT transcript reused cached ACCEPT: response=%d bytes", len(changedResponse))
	}
}

func TestInvalidCredentialAndStaleInitGetNoAmplifyingAnswer(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{"example.com"}
	cfg.MinVPNLabelLength = 3
	server, credential := newProtocolTestServer(t, cfg, nil)
	now := uint32(time.Now().Unix())

	wrongKey := credential
	wrongKey.Key[0] ^= 0xff
	unknownKid := credential
	unknownKid.KID[0] ^= 0xff
	cases := []struct {
		name       string
		credential security.Credential
		timestamp  uint32
		version    byte
	}{
		{name: "wrong key", credential: wrongKey, timestamp: now},
		{name: "unknown kid", credential: unknownKid, timestamp: now},
		{name: "stale timestamp", credential: credential, timestamp: now - 121},
		{name: "unsupported version", credential: credential, timestamp: now, version: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var query []byte
			if tc.version == 0 {
				query = buildSessionInitQuestion(t, tc.credential, tc.timestamp)
			} else {
				query = buildSessionInitQuestion(t, tc.credential, tc.timestamp, tc.version)
			}
			response := server.HandlePacket(query)
			if len(response) > len(query) {
				t.Fatalf("rejected INIT amplified request: response=%d request=%d", len(response), len(query))
			}
			if len(response) != 0 {
				t.Fatalf("expected silent rejection, got %d response bytes", len(response))
			}
		})
	}
}

func TestReplayedSessionFrameGetsSmallNoDataAnswer(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{"example.com"}
	cfg.MinVPNLabelLength = 3
	server, credential := newProtocolTestServer(t, cfg, nil)

	var parameters [security.InitParametersSize]byte
	handshake, initMessage, err := security.NewClientHandshake(credential, parameters, time.Now(), rand.Reader)
	if err != nil {
		t.Fatalf("NewClientHandshake failed: %v", err)
	}
	initQuery, err := DnsParser.BuildTunnelTXTQuestionPacket("example.com", baseCodec.EncodeToBytes(initMessage), Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTunnelTXTQuestionPacket INIT failed: %v", err)
	}
	initResponse := server.HandlePacket(initQuery)
	acceptWire, err := DnsParser.ExtractVPNResponsePayload(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponsePayload ACCEPT failed: %v", err)
	}
	accepted, keys, err := handshake.OpenAccept(acceptWire)
	if err != nil {
		t.Fatalf("OpenAccept failed: %v", err)
	}
	clientCipher, err := security.NewSessionCipher(accepted.SessionID, keys.ClientToServer, keys.ServerToClient)
	if err != nil {
		t.Fatalf("NewSessionCipher failed: %v", err)
	}
	pingPlainSize := security.SessionInitSize - security.FramePrefixSize - 16
	pingHeader, err := VpnProto.BuildRaw(VpnProto.BuildOptions{PacketType: Enums.PACKET_PING})
	if err != nil {
		t.Fatalf("BuildRaw PING header failed: %v", err)
	}
	ping, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		PacketType: Enums.PACKET_PING,
		Payload:    make([]byte, pingPlainSize-len(pingHeader)),
	})
	if err != nil {
		t.Fatalf("BuildRaw padded PING failed: %v", err)
	}
	if accepted.SessionID != security.ProtocolVersion || len(ping)+security.FramePrefixSize+16 != security.SessionInitSize {
		t.Fatalf("expected session ID/secure frame to collide with INIT discriminator: sid=%d frame=%d init=%d", accepted.SessionID, len(ping)+security.FramePrefixSize+16, security.SessionInitSize)
	}
	frame, err := clientCipher.Seal(ping)
	if err != nil {
		t.Fatalf("Seal PING failed: %v", err)
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket("example.com", baseCodec.EncodeToBytes(frame), Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTunnelTXTQuestionPacket PING failed: %v", err)
	}

	firstResponse := server.HandlePacket(query)
	firstWire, err := DnsParser.ExtractVPNResponsePayload(firstResponse, false)
	if err != nil {
		t.Fatalf("expected encrypted PONG response, got: %v", err)
	}
	firstPlain, _, err := clientCipher.Open(firstWire)
	if err != nil {
		t.Fatalf("Open PONG failed: %v", err)
	}
	firstPacket, err := VpnProto.Parse(firstPlain)
	if err != nil || firstPacket.PacketType != Enums.PACKET_PONG {
		t.Fatalf("expected first PING to be handled, got packet=%+v err=%v", firstPacket, err)
	}

	replayResponse := server.HandlePacket(query)
	if len(replayResponse) == 0 || len(replayResponse) > len(query) {
		t.Fatalf("replayed frame answer must be small and no larger than request: answer=%d request=%d", len(replayResponse), len(query))
	}
	if _, err := DnsParser.ExtractVPNResponsePayload(replayResponse, false); !errors.Is(err, DnsParser.ErrTXTAnswerMissing) {
		t.Fatalf("replayed frame returned tunnel data: %v", err)
	}
}

func TestAuthenticatedProbeCanShareInitLengthAndVersionByte(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{"example.com"}
	cfg.MinVPNLabelLength = 3
	server, credential := newProtocolTestServer(t, cfg, nil)

	probePlainSize := security.SessionInitSize - security.ProbeHeaderSize - 16
	probePayload := make([]byte, probePlainSize-VpnProto.HeaderRawSize(Enums.PACKET_MTU_UP_REQ))
	probePayload[0] = mtuProbeModeRaw
	binary.BigEndian.PutUint32(probePayload[1:mtuProbeUpMinSize], 0x01020304)
	probeRaw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{PacketType: Enums.PACKET_MTU_UP_REQ, Payload: probePayload})
	if err != nil {
		t.Fatalf("BuildRaw MTU_UP_REQ failed: %v", err)
	}
	envelope, err := security.SealProbe(credential, probeRaw, time.Now(), bytes.NewReader([]byte("nonce-08")))
	if err != nil {
		t.Fatalf("SealProbe failed: %v", err)
	}
	if len(envelope) != security.SessionInitSize || envelope[0] != security.ProtocolVersion {
		t.Fatalf("expected probe/INIT discriminator collision: probe=%d init=%d version=%d", len(envelope), security.SessionInitSize, envelope[0])
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket("example.com", baseCodec.EncodeToBytes(envelope), Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTunnelTXTQuestionPacket failed: %v", err)
	}
	response := server.HandlePacket(query)
	wire, err := DnsParser.ExtractVPNResponsePayload(response, false)
	if err != nil {
		t.Fatalf("expected authenticated MTU probe response: %v", err)
	}
	probe, err := security.OpenProbeWithCredential(wire, credential)
	if err != nil {
		t.Fatalf("OpenProbeWithCredential failed: %v", err)
	}
	packet, err := VpnProto.Parse(probe.Payload)
	if err != nil || packet.PacketType != Enums.PACKET_MTU_UP_RES {
		t.Fatalf("expected MTU_UP_RES, got packet=%+v err=%v", packet, err)
	}
}

func TestIdlePongsHaveNoClearPOPlaintext(t *testing.T) {
	server, _ := newProtocolTestServer(t, config.DefaultServerConfig(), nil)
	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket failed: %v", err)
	}
	var key [security.CredentialKeySize]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	const sessionID = uint8(17)
	serverCipher, err := security.NewSessionCipher(sessionID, key, key)
	if err != nil {
		t.Fatal(err)
	}
	record := &sessionRuntimeView{ID: sessionID, Crypto: serverCipher}
	first := server.serveQueuedOrPong(query, "x.v.example.com", record, time.Now())
	second := server.serveQueuedOrPong(query, "x.v.example.com", record, time.Now())
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("expected two idle PONG DNS responses")
	}
	if bytes.Contains(first, []byte("PO:")) || bytes.Contains(second, []byte("PO:")) {
		t.Fatal("idle PONG marker leaked in cleartext")
	}
	if bytes.Equal(first, second) {
		t.Fatal("consecutive idle PONG frames should use distinct counters and ciphertext")
	}
	for _, response := range [][]byte{first, second} {
		wire, err := DnsParser.ExtractVPNResponsePayload(response, false)
		if err != nil {
			t.Fatalf("ExtractVPNResponsePayload failed: %v", err)
		}
		receiver, _ := security.NewSessionCipher(sessionID, key, key)
		plain, _, err := receiver.Open(wire)
		if err != nil {
			t.Fatalf("open idle PONG failed: %v", err)
		}
		packet, err := VpnProto.Parse(plain)
		if err != nil || packet.PacketType != Enums.PACKET_PONG {
			t.Fatalf("invalid idle PONG plaintext: packet=%+v err=%v", packet, err)
		}
	}
}

func protocolTestPrivateKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = 0x60 + byte(i)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw[:])
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	return key
}
