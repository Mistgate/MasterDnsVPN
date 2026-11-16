package client

import (
	"bytes"
	"strings"
	"testing"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestSessionInitIsRetriedIdempotentlyThenRebuiltBeforeTheServerWindowCloses(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a")

	if _, _, _, err := c.nextSessionInitAttempt(); err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), c.sessionInitMessage...)
	if len(first) != security.SessionInitSize {
		t.Fatalf("INIT has %d bytes, want %d", len(first), security.SessionInitSize)
	}
	if _, _, _, err := c.nextSessionInitAttempt(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, c.sessionInitMessage) {
		t.Fatal("a retry shortly after the first attempt must resend the same INIT (the server answers it idempotently)")
	}

	// The server only accepts a timestamp within 120 s. A retry loop that backs off
	// for longer must not keep resending an INIT the server will always refuse.
	c.sessionInitBuiltAt = time.Now().Add(-(sessionInitMaxAge + time.Second))
	if _, _, _, err := c.nextSessionInitAttempt(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, c.sessionInitMessage) {
		t.Fatal("an INIT older than sessionInitMaxAge was resent")
	}
	if sessionInitMaxAge >= security.InitTimestampWindow {
		t.Fatalf("sessionInitMaxAge %s must be well inside the %s server window", sessionInitMaxAge, security.InitTimestampWindow)
	}
}

func TestSilentDownlinkRestartsTheSession(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a")
	c.sessionReady = true
	c.lastAuthRxUnixNano.Store(time.Now().UnixNano())
	c.checkSessionHealth()
	if c.runtimeResetPending.Load() {
		t.Fatal("a session that just received a frame was restarted")
	}

	c.lastAuthRxUnixNano.Store(time.Now().Add(-(sessionLivenessTimeout + time.Second)).UnixNano())
	c.checkSessionHealth()
	if !c.runtimeResetPending.Load() {
		t.Fatal("a session whose downlink has been silent for longer than the liveness timeout was kept")
	}

	idle := buildTestClientWithResolvers(config.ClientConfig{}, "a")
	idle.checkSessionHealth()
	if idle.runtimeResetPending.Load() {
		t.Fatal("a client without a session must not request a restart")
	}
}

// The upload MTU discovered with pre-session probes must equal the payload a
// real session frame can carry in the same name, so the larger probe envelope
// does not cost the data path any capacity.
func TestDiscoveredUploadMTUEqualsSessionFramePayloadCapacity(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a")
	const domain = "t.example.com" // 13 characters: 236 name characters, 150 raw bytes
	capacity := c.maxUploadMTUPayload(domain)

	var key [security.CredentialKeySize]byte
	cipher, err := security.NewSessionCipher(1, key, key)
	if err != nil {
		t.Fatal(err)
	}
	build := func(payloadLen int) error {
		raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
			PacketType:      Enums.PACKET_STREAM_DATA,
			StreamID:        0xffff,
			SequenceNum:     0xffff,
			FragmentID:      0xff,
			TotalFragments:  0xff,
			CompressionType: 0xff,
			Payload:         make([]byte, payloadLen),
		})
		if err != nil {
			return err
		}
		frame, err := cipher.Seal(raw)
		if err != nil {
			return err
		}
		_, err = DnsParser.BuildTunnelQuestionName(domain, baseCodec.Encode(frame))
		return err
	}
	if err := build(capacity); err != nil {
		t.Fatalf("a STREAM_DATA frame carrying the discovered %d bytes does not fit the name: %v", capacity, err)
	}
	if err := build(capacity + 1); err == nil {
		t.Fatalf("a frame with %d bytes still fits: the probe envelope wastes capacity", capacity+1)
	}

	// Payload share of the 150-byte frame the 13-character zone allows:
	// 150 = 1 sid + 4 ctr + 16 tag + 8 inner header + payload.
	if capacity != 121 {
		t.Fatalf("expected 121 payload bytes in a 150-byte upstream frame, got %d", capacity)
	}
}

func TestBootstrapRefusesMissingOrMalformedCredential(t *testing.T) {
	for name, credential := range map[string]string{
		"empty":        "",
		"no dot":       "0102030405060708" + "00000000000000000000000000000000000000000000000000000000000000000",
		"short key":    "0102030405060708.00",
		"not hex":      "010203040506070z.0000000000000000000000000000000000000000000000000000000000000000",
		"old shared":   "0123456789abcdef0123456789abcdef",
		"extra field":  "0102030405060708.0000000000000000000000000000000000000000000000000000000000000000.00",
		"short kid":    "01020304.0000000000000000000000000000000000000000000000000000000000000000",
		"whitespace-x": "0102030405060708. 000000000000000000000000000000000000000000000000000000000000000",
	} {
		cfg := config.DefaultClientConfig()
		cfg.Domains = []string{"v.example.com"}
		cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: 5300}}
		cfg.DeviceCredential = credential
		if c, err := BootstrapLoadedConfig(cfg, ""); err == nil || c != nil {
			t.Errorf("%s: a client was built from the credential %q", name, credential)
		} else if credential != "" && strings.Contains(err.Error(), credential) {
			t.Errorf("%s: the error message repeats the credential", name)
		}
	}
}
