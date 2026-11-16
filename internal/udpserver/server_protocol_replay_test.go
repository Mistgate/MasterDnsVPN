package udpserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func replayTestServer(t *testing.T) (*Server, security.Credential) {
	t.Helper()
	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{"example.com"}
	cfg.MinVPNLabelLength = 3
	return newProtocolTestServer(t, cfg, nil)
}

func tunnelQuery(t *testing.T, wire []byte) []byte {
	t.Helper()
	query, err := DnsParser.BuildTunnelTXTQuestionPacket("example.com", baseCodec.EncodeToBytes(wire), Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTunnelTXTQuestionPacket failed: %v", err)
	}
	return query
}

// establish runs a real INIT/ACCEPT exchange against the server and returns the
// client's cipher together with the INIT query for replays.
func establish(t *testing.T, server *Server, credential security.Credential) (*security.SessionCipher, []byte, []byte) {
	t.Helper()
	var parameters [security.InitParametersSize]byte
	handshake, initMessage, err := security.NewClientHandshake(credential, parameters, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	query := tunnelQuery(t, initMessage)
	response := server.HandlePacket(query)
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
	return cipher, query, acceptWire
}

func pingFrameQuery(t *testing.T, cipher *security.SessionCipher) []byte {
	t.Helper()
	ping, err := VpnProto.BuildRaw(VpnProto.BuildOptions{PacketType: Enums.PACKET_PING, Payload: []byte("PING")})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := cipher.Seal(ping)
	if err != nil {
		t.Fatal(err)
	}
	return tunnelQuery(t, frame)
}

func pongFrame(t *testing.T, cipher *security.SessionCipher, response []byte) []byte {
	t.Helper()
	wire, err := DnsParser.ExtractVPNResponsePayload(response, false)
	if err != nil {
		t.Fatalf("expected an encrypted answer: %v", err)
	}
	return wire
}

func TestReplayedInitReturnsIdenticalAcceptAndNoSecondSession(t *testing.T) {
	server, credential := replayTestServer(t)
	_, query, firstAccept := establish(t, server, credential)
	before := server.sessions.activeCount
	for i := 0; i < 5; i++ {
		response := server.HandlePacket(query)
		got, err := DnsParser.ExtractVPNResponsePayload(response, false)
		if err != nil || !bytes.Equal(got, firstAccept) {
			t.Fatalf("replay %d did not return the identical ACCEPT (err=%v)", i, err)
		}
		if len(response) == 0 {
			t.Fatal("empty replay answer")
		}
	}
	if server.sessions.activeCount != before {
		t.Fatalf("replayed INITs created sessions: %d -> %d", before, server.sessions.activeCount)
	}
}

// If the cached ACCEPT is gone (evicted, expired) a replayed INIT must neither
// answer with a second server key nor disturb the session it already created.
func TestReplayedInitAfterCacheLossDoesNotRekeyTheSession(t *testing.T) {
	server, credential := replayTestServer(t)
	cipher, query, _ := establish(t, server, credential)

	server.protocolMu.Lock()
	clear(server.initCache)
	server.protocolMu.Unlock()

	if response := server.HandlePacket(query); len(response) != 0 {
		t.Fatalf("a replayed INIT without a cached ACCEPT must stay silent, got %d bytes", len(response))
	}
	response := server.HandlePacket(pingFrameQuery(t, cipher))
	wire := pongFrame(t, cipher, response)
	plain, _, err := cipher.Open(wire)
	if err != nil {
		t.Fatalf("the session no longer works after a replayed INIT: %v", err)
	}
	if packet, err := VpnProto.Parse(plain); err != nil || packet.PacketType != Enums.PACKET_PONG {
		t.Fatalf("expected PONG, got %+v %v", packet, err)
	}
}

func TestInitCacheOutlivesTheTimestampWindow(t *testing.T) {
	server, credential := replayTestServer(t)
	var parameters [security.InitParametersSize]byte
	ts := uint32(time.Now().Unix())
	private := protocolTestPrivateKey(t)
	initMessage, err := security.BuildSessionInit(credential, parameters, ts, private)
	if err != nil {
		t.Fatal(err)
	}
	if response := server.HandlePacket(tunnelQuery(t, initMessage)); len(response) == 0 {
		t.Fatal("INIT was not answered")
	}
	server.protocolMu.Lock()
	defer server.protocolMu.Unlock()
	if len(server.initCache) != 1 {
		t.Fatalf("expected one cached ACCEPT, got %d", len(server.initCache))
	}
	for _, cached := range server.initCache {
		// OpenSessionInit accepts now.Unix() <= ts+120, i.e. now < ts+121 s. The
		// cache must cover that whole span, including the final sub-second part.
		if want := time.Unix(int64(ts)+121, 0); !cached.expires.Equal(want) {
			t.Fatalf("cache expiry %v, want ts+121s = %v", cached.expires, want)
		}
	}
}

func TestLowOrderClientKeyGetsNoSessionAndNoAnswer(t *testing.T) {
	server, credential := replayTestServer(t)
	zero := make([]byte, 32)
	header := append([]byte{security.ProtocolVersion}, credential.KID[:]...)
	header = binary.BigEndian.AppendUint32(header, uint32(time.Now().Unix()))
	header = append(header, zero...)
	nonce := sha256Nonce12("masterdnsvpn-go/init/v1", header)
	aead, _ := chacha20poly1305.New(credential.Key[:])
	initMessage := aead.Seal(append([]byte(nil), header...), nonce, make([]byte, security.InitParametersSize), header)
	if len(initMessage) != security.SessionInitSize {
		t.Fatalf("test INIT has the wrong size %d", len(initMessage))
	}
	before := server.sessions.activeCount
	if response := server.HandlePacket(tunnelQuery(t, initMessage)); len(response) != 0 {
		t.Fatalf("an INIT with a low-order key was answered with %d bytes", len(response))
	}
	if server.sessions.activeCount != before {
		t.Fatal("an INIT with a low-order key took a session slot")
	}
}

func sha256Nonce12(label string, header []byte) []byte {
	sum := sha256.Sum256(append([]byte(label), header...))
	return sum[:12]
}

func mtuUpProbeQuery(t *testing.T, credential security.Credential, ts time.Time, random8 byte) []byte {
	t.Helper()
	payload := make([]byte, 1+4)
	payload[0] = mtuProbeModeRaw
	binary.BigEndian.PutUint32(payload[1:], 0x0a0b0c0d)
	raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{PacketType: Enums.PACKET_MTU_UP_REQ, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := security.SealProbe(credential, raw, ts, bytes.NewReader(bytes.Repeat([]byte{random8}, 8)))
	if err != nil {
		t.Fatal(err)
	}
	return tunnelQuery(t, envelope)
}

func hasTunnelAnswer(response []byte) bool {
	_, err := DnsParser.ExtractVPNResponsePayload(response, false)
	return err == nil
}

func TestPreSessionProbeIsFreshOneTimeAndBudgeted(t *testing.T) {
	server, credential := replayTestServer(t)
	now := time.Now()

	probe := mtuUpProbeQuery(t, credential, now, 1)
	first := server.HandlePacket(probe)
	if !hasTunnelAnswer(first) {
		t.Fatal("a fresh authenticated probe was not answered")
	}
	// Captured and replayed, right away or later: a small answer without data.
	for i := 0; i < 3; i++ {
		replay := server.HandlePacket(probe)
		if hasTunnelAnswer(replay) || len(replay) > len(probe) {
			t.Fatalf("replayed probe got data or an amplified answer (%d bytes for %d)", len(replay), len(probe))
		}
	}
	stale := server.HandlePacket(mtuUpProbeQuery(t, credential, now.Add(-130*time.Second), 2))
	if hasTunnelAnswer(stale) {
		t.Fatal("a probe older than the freshness window was answered")
	}
	future := server.HandlePacket(mtuUpProbeQuery(t, credential, now.Add(130*time.Second), 3))
	if hasTunnelAnswer(future) {
		t.Fatal("a probe from the future was answered")
	}

	answered := 1
	for i := 0; i < 80; i++ {
		if hasTunnelAnswer(server.HandlePacket(mtuUpProbeQuery(t, credential, time.Now(), byte(10+i)))) {
			answered++
		}
	}
	if answered != security.ProbeBudgetPerMinute {
		t.Fatalf("expected exactly %d probes answered per minute, got %d", security.ProbeBudgetPerMinute, answered)
	}
}

func TestProbeWithUnknownCredentialOrWrongKeyIsSilent(t *testing.T) {
	server, credential := replayTestServer(t)
	unknown := credential
	unknown.KID[0] ^= 0xff
	wrongKey := credential
	wrongKey.Key[5] ^= 0xff
	for name, c := range map[string]security.Credential{"unknown kid": unknown, "wrong key": wrongKey} {
		query := mtuUpProbeQuery(t, c, time.Now(), 9)
		if response := server.HandlePacket(query); len(response) != 0 {
			t.Errorf("%s: expected silence, got %d bytes", name, len(response))
		}
	}
}

// The downlink must not repeat any recognisable byte string: two idle answers to
// the same request share neither the PONG marker nor any run of bytes beyond the
// session id.
func TestDownlinkFramesShareNoRepeatingBytes(t *testing.T) {
	server, credential := replayTestServer(t)
	cipher, _, _ := establish(t, server, credential)
	var frames [][]byte
	for i := 0; i < 8; i++ {
		response := server.HandlePacket(pingFrameQuery(t, cipher))
		wire := pongFrame(t, cipher, response)
		if bytes.Contains(wire, []byte("PO:")) {
			t.Fatal("clear PONG marker in the downlink")
		}
		frames = append(frames, wire)
	}
	const run = 6
	for i := range frames {
		for j := i + 1; j < len(frames); j++ {
			a, b := frames[i], frames[j]
			if len(a) != len(b) {
				continue
			}
			for off := 1; off+run <= len(a); off++ { // byte 0 is the clear session id
				if bytes.Equal(a[off:off+run], b[off:off+run]) {
					t.Fatalf("frames %d and %d share %d identical bytes at offset %d:\n%x\n%x", i, j, run, off, a, b)
				}
			}
		}
	}
	if len(frames[0]) == 0 {
		t.Fatal("no frames")
	}
}

func TestCapturedInitIsAnsweredOnlyAFewTimes(t *testing.T) {
	server, credential := replayTestServer(t)
	_, query, firstAccept := establish(t, server, credential) // answer 1
	for i := 2; i <= maxInitAnswers; i++ {
		got, err := DnsParser.ExtractVPNResponsePayload(server.HandlePacket(query), false)
		if err != nil || !bytes.Equal(got, firstAccept) {
			t.Fatalf("answer %d of the same INIT was not the cached ACCEPT (err=%v)", i, err)
		}
	}
	if response := server.HandlePacket(query); len(response) != 0 {
		t.Fatalf("answer %d to one captured INIT: %d bytes, want silence", maxInitAnswers+1, len(response))
	}
}
