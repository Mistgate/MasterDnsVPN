package mgdns_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mgdns "masterdnsvpn-go"
)

const (
	e2eZone       = "v.example.com"
	e2eCredential = "0102030405060708.000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	e2eBob        = "1112131415161718.101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
)

// relay stands in for the recursive resolvers between a client and the server.
// It receives the client's datagrams on a UDP socket, forwards them to
// Server.HandleQuery the way a resolver would (its own EDNS size, with the
// loss, duplication and retry of a real path) and sends the answers back.
type relay struct {
	t       *testing.T
	server  *mgdns.Server
	conn    *net.UDPConn
	lossPct atomic.Int32 // each direction
	dupPct  atomic.Int32 // queries sent twice to the server
	// retryPct: the answer is "lost" between server and resolver and the
	// resolver asks again with the same bytes.
	retryPct atomic.Int32
	// truncateEvery: every Nth query reaches the server with its EDNS size
	// cut to the 512 bytes of a resolver without EDNS.
	truncateEvery atomic.Int32
	// ednsSize is what the resolver advertises to the server.
	ednsSize atomic.Int32

	mu       sync.Mutex
	rng      *mrand.Rand
	queries  atomic.Int64
	dropped  atomic.Int64
	retried  atomic.Int64
	tcpAsked atomic.Int64
	wg       sync.WaitGroup
	src      netip.AddrPort
}

func newRelay(t *testing.T, server *mgdns.Server, src string) *relay {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{t: t, server: server, conn: conn, rng: mrand.New(mrand.NewSource(11)), src: netip.MustParseAddrPort(src)}
	r.ednsSize.Store(1232)
	r.wg.Add(1)
	go r.loop()
	t.Cleanup(func() {
		conn.Close()
		r.wg.Wait()
	})
	return r
}

func (r *relay) port() int { return r.conn.LocalAddr().(*net.UDPAddr).Port }

func (r *relay) roll(pct int32) bool {
	if pct <= 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rng.Int31n(100) < pct
}

func (r *relay) loop() {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, peer, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.serve(query, peer)
		}()
	}
}

func (r *relay) serve(query []byte, peer *net.UDPAddr) {
	count := r.queries.Add(1)
	if r.roll(r.lossPct.Load()) {
		r.dropped.Add(1)
		return
	}
	edns := uint16(r.ednsSize.Load())
	if every := int64(r.truncateEvery.Load()); every > 0 && count%every == 0 {
		edns = 0
	}
	forwarded := withEDNS(query, edns)
	copies := 1
	if r.roll(r.dupPct.Load()) {
		copies = 2
	}
	for i := 0; i < copies; i++ {
		answer := r.ask(forwarded)
		if len(answer) == 0 {
			continue
		}
		if r.roll(r.lossPct.Load()) {
			r.dropped.Add(1)
			continue
		}
		_, _ = r.conn.WriteToUDP(answer, peer)
	}
}

// ask is one resolver-to-server exchange, with the retry and TCP fallback of a
// real resolver.
func (r *relay) ask(query []byte) []byte {
	answer := r.server.HandleQuery(r.src, query, 0, false)
	if r.roll(r.retryPct.Load()) {
		r.retried.Add(1)
		// the answer never made it back: ask again with the same bytes
		answer = r.server.HandleQuery(r.src, query, 0, false)
	}
	if len(answer) >= 12 && answer[2]&0x02 != 0 { // TC
		r.tcpAsked.Add(1)
		return r.server.HandleQuery(r.src, query, 0, true)
	}
	return answer
}

// withEDNS rewrites the OPT record of a query the way a resolver does: its own
// size, or none at all when edns is 0.
func withEDNS(query []byte, edns uint16) []byte {
	// header 12, then the question: name, type, class
	offset := 12
	for offset < len(query) && query[offset] != 0 {
		offset += int(query[offset]) + 1
	}
	end := offset + 1 + 4
	if end > len(query) {
		return query
	}
	out := append([]byte(nil), query[:end]...)
	if edns == 0 {
		binary.BigEndian.PutUint16(out[10:12], 0)
		return out
	}
	binary.BigEndian.PutUint16(out[10:12], 1)
	return append(out, 0, 0, 41, byte(edns>>8), byte(edns), 0, 0, 0, 0, 0, 0)
}

type echoServer struct {
	listener net.Listener
	wg       sync.WaitGroup
}

func startEcho(t *testing.T) *echoServer {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &echoServer{listener: listener}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	t.Cleanup(func() { listener.Close(); e.wg.Wait() })
	return e
}

type e2eServer struct {
	server  *mgdns.Server
	dialed  atomic.Int64
	creds   sync.Map // credential ids that dialed
	resolve atomic.Int64
	cancel  context.CancelFunc
}

func startServer(t *testing.T, echo *echoServer, mutate func(*mgdns.ServerConfig)) *e2eServer {
	t.Helper()
	e := &e2eServer{}
	cfg := mgdns.ServerConfig{
		Domains:   []string{e2eZone},
		NSName:    "ns-k3x9ab.example.net",
		NSAddress: netip.MustParseAddr("192.0.2.10"),
		CheckKey:  []byte("0123456789abcdef"),
		Dial: func(ctx context.Context, credentialID, network, address string) (net.Conn, error) {
			e.dialed.Add(1)
			e.creds.Store(credentialID, true)
			switch address {
			case "echo.test:7007":
				return (&net.Dialer{}).DialContext(ctx, "tcp4", echo.listener.Addr().String())
			case "blackhole.test:443":
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("unexpected target %q", address)
		},
		ResolveDNS: func(ctx context.Context, credentialID string, query []byte) ([]byte, error) {
			e.resolve.Add(1)
			// a fixed answer: the query with QR set and one A record
			return fakeDNSAnswer(query), nil
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	server, err := mgdns.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.server = server
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	server.Start(ctx)
	t.Cleanup(cancel)
	return e
}

// fakeDNSAnswer answers any A query with 192.0.2.77.
func fakeDNSAnswer(query []byte) []byte {
	offset := 12
	for offset < len(query) && query[offset] != 0 {
		offset += int(query[offset]) + 1
	}
	end := offset + 5
	answer := append([]byte(nil), query[:end]...)
	answer[2], answer[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(answer[6:8], 1)
	binary.BigEndian.PutUint16(answer[8:10], 0)
	binary.BigEndian.PutUint16(answer[10:12], 0)
	answer = append(answer, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 77)
	return answer
}

func index(t *testing.T, secrets ...string) *mgdns.CredentialIndex {
	t.Helper()
	var credentials []mgdns.Credential
	for _, secret := range secrets {
		credential, err := mgdns.ParseCredential(secret)
		if err != nil {
			t.Fatal(err)
		}
		credentials = append(credentials, credential)
	}
	idx, err := mgdns.NewCredentialIndex(credentials...)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func startClient(t *testing.T, secret string, relays ...*relay) *mgdns.Client {
	t.Helper()
	return startClientWithLiveness(t, secret, 0, relays...)
}

// startClientWithLiveness starts a client that takes its session for lost after
// the server was silent for liveness (0: the default of 90 s).
func startClientWithLiveness(t *testing.T, secret string, liveness time.Duration, relays ...*relay) *mgdns.Client {
	t.Helper()
	var resolvers []netip.AddrPort
	for _, r := range relays {
		resolvers = append(resolvers, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(r.port())))
	}
	client, err := mgdns.NewClient(mgdns.ClientConfig{
		Domains:         []string{e2eZone},
		Credential:      secret,
		Resolvers:       resolvers,
		IdleTimeout:     -1,
		LivenessTimeout: liveness,
		SessionTimeout:  90 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
	})
	return client
}

func echoRoundTrip(t *testing.T, conn net.Conn, size int) time.Duration {
	t.Helper()
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	_ = conn.SetDeadline(time.Now().Add(4 * time.Minute))
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()
	got := make([]byte, size)
	started := time.Now()
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back failed after %s: %v", time.Since(started), err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != want || !bytes.Equal(got, payload) {
		t.Fatal("echoed bytes differ from the bytes sent")
	}
	return time.Since(started)
}

// TestFacadeEndToEnd runs the facade client and server against each other over
// loopback through a resolver stand-in: 1 MiB each way, with 10 % loss in each
// direction, duplicated and repeated queries, an EDNS size of 1232, and queries
// that reach the server with their EDNS size cut to 512 bytes, so that data
// answers come back truncated and are fetched over TCP.
func TestFacadeEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end transfer is slow")
	}
	echo := startEcho(t)
	s := startServer(t, echo, nil)
	s.server.SetCredentialIndex(index(t, e2eCredential))
	r := newRelay(t, s.server, "198.51.100.7:53000")
	client := startClient(t, e2eCredential, r)
	var peak atomic.Int64
	stopSampler := make(chan struct{})
	defer close(stopSampler)
	go func() {
		last := s.server.Stats().Queries
		for {
			select {
			case <-stopSampler:
				return
			case <-time.After(time.Second):
			}
			now := s.server.Stats().Queries
			if d := int64(now - last); d > peak.Load() {
				peak.Store(d)
			}
			last = now
		}
	}()

	if client.Ready() {
		t.Fatal("the session must be lazy: nothing is up before the first dial")
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := client.DialContext(dialCtx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if !client.Ready() {
		t.Fatal("the session is up after a dial, Ready must say so")
	}
	r.lossPct.Store(10)
	r.dupPct.Store(10)
	r.retryPct.Store(10)
	r.truncateEvery.Store(9)

	elapsed := echoRoundTrip(t, conn, 1<<20)
	stats := s.server.Stats()
	t.Logf("peak query rate at the server: %d per second", peak.Load())
	t.Logf("1 MiB each way in %s; resolver queries=%d dropped=%d retried=%d tcp=%d; server: queries=%d truncated=%d replays=%d cacheServed=%d rateLimited=%d",
		elapsed.Round(time.Millisecond), r.queries.Load(), r.dropped.Load(), r.retried.Load(), r.tcpAsked.Load(),
		stats.Queries, stats.Truncated, stats.Replays, stats.CacheServed, stats.RateLimited)
	if r.dropped.Load() == 0 || r.tcpAsked.Load() == 0 {
		t.Fatal("the scenario did not exercise loss and the TC-to-TCP fallback")
	}
	if stats.CacheServed == 0 {
		t.Fatal("no repeated query was answered from the answer cache")
	}
	if stats.RateLimited != 0 {
		t.Fatalf("%d queries of an ordinary transfer were rate limited", stats.RateLimited)
	}
	sessions := s.server.Sessions()
	if len(sessions) != 1 || sessions[0].CredentialID != "0102030405060708" || sessions[0].Resolver != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("sessions: %+v", sessions)
	}
	if _, ok := s.creds.Load("0102030405060708"); !ok {
		t.Fatal("the Dial hook did not receive the credential id")
	}
}

// In library mode the client opens no listener and writes no file: the SOCKS
// and DNS ports of the standalone defaults stay free and the working directory
// stays empty while a session is up.
func TestFacadeClientOpensNoListenerAndWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	echo := startEcho(t)
	s := startServer(t, echo, nil)
	s.server.SetCredentialIndex(index(t, e2eCredential))
	client := startClient(t, e2eCredential, newRelay(t, s.server, "198.51.100.7:53000"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatal(err)
	}
	echoRoundTrip(t, conn, 4<<10)
	if _, err := client.ResolveDNS(ctx, dnsQuery("example.org")); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"127.0.0.1:18000"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Errorf("%s is taken while the library client runs: %v", address, err)
			continue
		}
		listener.Close()
	}
	conn.Close()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the library client wrote files: %v", entries)
	}
}

func TestFacadeDialErrorsAndDNS(t *testing.T) {
	echo := startEcho(t)
	s := startServer(t, echo, func(cfg *mgdns.ServerConfig) { cfg.ConnectTimeout = 2 * time.Second })
	s.server.SetCredentialIndex(index(t, e2eCredential))
	r := newRelay(t, s.server, "198.51.100.7:53000")
	client := startClient(t, e2eCredential, r)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// A target the Dial hook cannot reach fails with an error, not a hang.
	if _, err := client.DialContext(ctx, "tcp", "elsewhere.test:80"); err == nil {
		t.Fatal("dialing an unknown target succeeded")
	}
	// A black hole ends with the connect timeout of the server.
	started := time.Now()
	if _, err := client.DialContext(ctx, "tcp", "blackhole.test:443"); err == nil {
		t.Fatal("dialing a black hole succeeded")
	}
	if took := time.Since(started); took > 15*time.Second {
		t.Fatalf("the black-hole dial took %s", took)
	}
	// A context that ends first ends the dial.
	short, cancelShort := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancelShort()
	if _, err := client.DialContext(short, "tcp", "blackhole.test:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a cancelled dial returned %v", err)
	}
	// An ordinary dial still works after the failures, and half-close works:
	// the peer sees EOF while the answer keeps coming.
	conn, err := client.DialContext(ctx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello through the tunnel")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("hello through the tunnel"))
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "hello through the tunnel" {
		t.Fatalf("echo %q %v", reply, err)
	}

	// DNS through the tunnel is resolved by the host's hook.
	query := dnsQuery("example.org")
	answer, err := client.ResolveDNS(ctx, query)
	if err != nil {
		t.Fatalf("ResolveDNS: %v", err)
	}
	if len(answer) < len(query)+16 || !bytes.Equal(answer[len(answer)-4:], []byte{192, 0, 2, 77}) {
		t.Fatalf("unexpected DNS answer %x", answer)
	}
	if s.resolve.Load() == 0 {
		t.Fatal("the ResolveDNS hook was not called")
	}
}

func dnsQuery(name string) []byte {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

// Kicking one credential does not touch another, and a kicked client comes back.
func TestFacadeKickDoesNotDisturbAnotherCredential(t *testing.T) {
	echo := startEcho(t)
	s := startServer(t, echo, nil)
	s.server.SetCredentialIndex(index(t, e2eCredential, e2eBob))
	// the kicked device learns that its session is gone by the silence of the
	// server: shorten the 90 s so that the test does not wait that long
	alice := startClientWithLiveness(t, e2eCredential, 12*time.Second, newRelay(t, s.server, "198.51.100.7:53000"))
	bob := startClient(t, e2eBob, newRelay(t, s.server, "203.0.113.9:41000"))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	aliceConn, err := alice.DialContext(ctx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	defer aliceConn.Close()
	bobConn, err := bob.DialContext(ctx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	defer bobConn.Close()
	if got := len(s.server.Sessions()); got != 2 {
		t.Fatalf("%d sessions, want 2", got)
	}

	if closed := s.server.CloseCredential("0102030405060708"); closed != 1 {
		t.Fatalf("closed %d sessions", closed)
	}
	started := time.Now()
	// Bob goes on.
	echoRoundTrip(t, bobConn, 64<<10)
	t.Logf("bob's round trip after the kick: %s", time.Since(started).Round(time.Millisecond))
	// Alice's connection is gone: it ends instead of hanging forever.
	_ = aliceConn.SetDeadline(time.Now().Add(2 * time.Minute))
	_, _ = aliceConn.Write([]byte("x"))
	_, readErr := aliceConn.Read(make([]byte, 1))
	t.Logf("alice's connection ended after %s: %v", time.Since(started).Round(time.Second), readErr)
	if readErr == nil {
		t.Fatal("alice's connection survived the kick")
	}
	// She can dial again: the client starts a new session by itself.
	again, err := alice.DialContext(ctx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatalf("alice after the kick: %v", err)
	}
	defer again.Close()
	echoRoundTrip(t, again, 16<<10)
}

func TestFacadeLazySessionEndsWhenIdle(t *testing.T) {
	echo := startEcho(t)
	s := startServer(t, echo, nil)
	s.server.SetCredentialIndex(index(t, e2eCredential))
	r := newRelay(t, s.server, "198.51.100.7:53000")
	var resolvers = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(r.port()))}
	saved := make(chan []netip.AddrPort, 8)
	client, err := mgdns.NewClient(mgdns.ClientConfig{
		Domains:     []string{e2eZone},
		Credential:  e2eCredential,
		Resolvers:   resolvers,
		IdleTimeout: 800 * time.Millisecond,
		SaveRanking: func(ranked []netip.AddrPort) { saved <- ranked },
		LoadRanking: func() []netip.AddrPort { return resolvers },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	dialCtx, cancelDial := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelDial()
	conn, err := client.DialContext(dialCtx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatal(err)
	}
	echoRoundTrip(t, conn, 8<<10)
	if !client.Ready() {
		t.Fatal("not ready after a dial")
	}
	conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	for client.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("the session did not end after the idle timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case ranked := <-saved:
		if len(ranked) == 0 {
			t.Fatal("an empty ranking was saved")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the resolver ranking was not saved when the session ended")
	}
	// A new dial brings the session up again.
	conn, err = client.DialContext(dialCtx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatalf("second session: %v", err)
	}
	defer conn.Close()
	echoRoundTrip(t, conn, 8<<10)
}

func TestFacadeInputValidation(t *testing.T) {
	if _, err := mgdns.NewClient(mgdns.ClientConfig{Credential: e2eCredential}); err == nil {
		t.Error("a client without domains and resolvers was accepted")
	}
	if _, err := mgdns.NewClient(mgdns.ClientConfig{Domains: []string{e2eZone}, Credential: "nonsense", Resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53")}}); err == nil {
		t.Error("a malformed credential was accepted")
	} else if strings.Contains(err.Error(), "nonsense") {
		t.Error("the error echoes the credential")
	}
	if _, err := mgdns.NewServer(mgdns.ServerConfig{}); err == nil {
		t.Error("a server without domains was accepted")
	}
	client, err := mgdns.NewClient(mgdns.ClientConfig{Domains: []string{e2eZone}, Credential: e2eCredential, Resolvers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DialContext(context.Background(), "tcp", "echo.test:7007"); err == nil {
		t.Error("a dial before Start succeeded")
	}
	if _, err := client.DialContext(context.Background(), "udp", "echo.test:7007"); err == nil {
		t.Error("udp is not supported and must say so")
	}
	if _, err := mgdns.ParseCredential("0102030405060708.zz"); err == nil {
		t.Error("a short key was accepted")
	}
}
