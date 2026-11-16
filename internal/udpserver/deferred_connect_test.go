package udpserver

import (
	"context"
	"encoding/binary"
	baseCodec "masterdnsvpn-go/internal/basecodec"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
)

func socksSynQuery(t testing.TB, cipher *security.SessionCipher, streamID uint16, host string, port uint16) []byte {
	t.Helper()
	target := append([]byte{3, byte(len(host))}, host...)
	target = binary.BigEndian.AppendUint16(target, port)
	return frameQueryFor(t, cipher, Enums.PACKET_SOCKS5_SYN, streamID, 1, target)
}

// frameQueryFor builds a frame of a stream packet (stream id, sequence).
func frameQueryFor(t testing.TB, cipher *security.SessionCipher, packetType uint8, streamID uint16, sequence uint16, payload []byte) []byte {
	t.Helper()
	return frameQueryOpts(t, cipher, packetType, streamID, sequence, 1, payload)
}

// pollFor sends PINGs until an answer carries a packet of wantType for the
// stream, or the timeout passes; it reports how long that took.
func pollFor(t testing.TB, server *Server, cipher *security.SessionCipher, streamID uint16, wantType uint8, timeout time.Duration) (time.Duration, bool) {
	t.Helper()
	started := time.Now()
	for time.Since(started) < timeout {
		answer := server.HandleQuery(resolverA, frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232), 0, false)
		if wire, err := extractOrNil(answer); err == nil {
			if plain, _, err := cipher.Open(wire); err == nil {
				if packet, err := parsePlain(plain); err == nil && packet.PacketType == wantType && packet.StreamID == streamID {
					return time.Since(started), true
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return time.Since(started), false
}

// Connects to a target that never answers must not hold up the connects that
// come after them (issue 202, hypothesis H3: a FIFO per worker meant the first
// few black holes blocked every later connect for up to the connect timeout).
func TestBlackHoleConnectsDoNotDelayOtherConnects(t *testing.T) {
	server, credential := zoneTestServer(t, func(cfg *config.ServerConfig) {
		cfg.SOCKSConnectTimeoutSecs = 20
	})
	var blackholes int
	setHooks := Hooks{Dial: func(ctx context.Context, credentialID, network, address string) (net.Conn, error) {
		if address == "blackhole.test:443" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		local, remote := net.Pipe()
		go func() { _, _ = remote.Read(make([]byte, 1)); remote.Close() }()
		return local, nil
	}}
	server.SetHooks(setHooks)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.Start(ctx)

	cipher, _ := sessionFor(t, server, credential)
	for i := 0; i < 10; i++ {
		blackholes++
		server.HandleQuery(resolverA, socksSynQuery(t, cipher, uint16(10+i), "blackhole.test", 443), 0, false)
	}
	time.Sleep(200 * time.Millisecond) // let the black-hole connects start
	server.HandleQuery(resolverA, socksSynQuery(t, cipher, 50, "ok.test", 80), 0, false)
	elapsed, ok := pollFor(t, server, cipher, 50, Enums.PACKET_SOCKS5_CONNECTED, 8*time.Second)
	if !ok {
		t.Fatalf("an ordinary connect was not answered within %s behind %d black holes", elapsed, blackholes)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("an ordinary connect took %s behind %d black holes, want at most 5 s", elapsed, blackholes)
	}
	t.Logf("ordinary connect answered after %s behind %d black holes", elapsed.Round(time.Millisecond), blackholes)
}

// The connect timeout ends a black-hole connect with TTL_EXPIRED, so a session
// is not left waiting for an answer that cannot come.
func TestBlackHoleConnectTimesOutWithTTLExpired(t *testing.T) {
	server, credential := zoneTestServer(t, func(cfg *config.ServerConfig) { cfg.SOCKSConnectTimeoutSecs = 1 })
	server.SetHooks(Hooks{Dial: func(ctx context.Context, credentialID, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.Start(ctx)
	cipher, _ := sessionFor(t, server, credential)
	server.HandleQuery(resolverA, socksSynQuery(t, cipher, 7, "blackhole.test", 443), 0, false)
	elapsed, ok := pollFor(t, server, cipher, 7, Enums.PACKET_SOCKS5_TTL_EXPIRED, 5*time.Second)
	if !ok || elapsed < 900*time.Millisecond {
		t.Fatalf("TTL_EXPIRED after %s (seen=%v), want about 1 s", elapsed, ok)
	}
}

func frameQueryOpts(t testing.TB, cipher *security.SessionCipher, packetType uint8, streamID uint16, sequence uint16, totalFragments uint8, payload []byte) []byte {
	t.Helper()
	raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		PacketType:     packetType,
		StreamID:       streamID,
		SequenceNum:    sequence,
		TotalFragments: totalFragments,
		Payload:        payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := cipher.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket(testZone, baseCodec.EncodeToBytes(frame), Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func parsePlain(plain []byte) (VpnProto.Packet, error) { return VpnProto.Parse(plain) }

func TestStandaloneDialerRefusesPrivateAddressesAfterResolution(t *testing.T) {
	for _, address := range []string{"127.0.0.1:80", "10.1.2.3:80", "169.254.169.254:80", "192.168.0.1:443", "[::1]:80", "[fe80::1]:80", "100.64.0.1:80", "198.18.0.1:80", "0.0.0.0:80"} {
		if err := controlBlockedAddress("tcp", address, nil); err == nil {
			t.Errorf("%s was not refused", address)
		}
	}
	for _, address := range []string{"198.51.100.7:443", "[2001:db8::1]:443"} {
		// documentation addresses are global unicast to Go and pass
		if err := controlBlockedAddress("tcp", address, nil); err != nil {
			t.Errorf("%s was refused: %v", address, err)
		}
	}
	// Without a Dial hook the server's own dialer applies the check to a real
	// connection attempt, whatever name led to the address.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, _ := zoneTestServer(t)
	if conn, err := server.dialTCPTargetContext(context.Background(), "", listener.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("the standalone dialer connected to a loopback address")
	}
	// A configured forward target is the operator's choice and may be local.
	if conn, err := server.dialForwardContext(context.Background(), "", listener.Addr().String()); err != nil {
		t.Fatalf("the forward target was refused: %v", err)
	} else {
		conn.Close()
	}
}
