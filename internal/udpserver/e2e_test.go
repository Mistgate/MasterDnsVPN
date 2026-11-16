package udpserver

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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

// lossyForwarder stands in for a recursive resolver: it relays every datagram
// between one client socket and the server and drops a configurable share of
// them in each direction.
type lossyForwarder struct {
	conn     *net.UDPConn
	upstream *net.UDPConn
	lossPct  atomic.Int32
	dropped  atomic.Int64
	relayed  atomic.Int64
	done     sync.WaitGroup
	rng      *mrand.Rand
	rngMu    sync.Mutex
}

func startLossyForwarder(t *testing.T, serverAddr string) *lossyForwarder {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	f := &lossyForwarder{conn: conn, rng: mrand.New(mrand.NewSource(7))}
	var clientAddr atomic.Pointer[net.UDPAddr]
	// One upstream socket per forwarded query would mimic a resolver better, but a
	// single socket keeps the test small and still exercises reordering through the
	// goroutine scheduler.
	f.upstream, err = net.DialUDP("udp4", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	drop := func() bool {
		pct := int(f.lossPct.Load())
		if pct == 0 {
			return false
		}
		f.rngMu.Lock()
		defer f.rngMu.Unlock()
		if f.rng.Intn(100) < pct {
			f.dropped.Add(1)
			return true
		}
		return false
	}
	f.done.Add(2)
	go func() {
		defer f.done.Done()
		buf := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientAddr.Store(peer)
			if drop() {
				continue
			}
			f.relayed.Add(1)
			_, _ = f.upstream.Write(buf[:n])
		}
	}()
	go func() {
		defer f.done.Done()
		buf := make([]byte, 65535)
		for {
			n, err := f.upstream.Read(buf)
			if err != nil {
				return
			}
			peer := clientAddr.Load()
			if peer == nil || drop() {
				continue
			}
			f.relayed.Add(1)
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		f.upstream.Close()
		f.done.Wait()
	})
	return f
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func socks5Connect(t *testing.T, proxy string, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("SOCKS5 method selection failed: %v %v", reply, err)
	}
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, host...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("SOCKS5 CONNECT reply: %v", err)
	}
	if head[1] != 0 {
		t.Fatalf("SOCKS5 CONNECT refused with code %d", head[1])
	}
	var rest int
	switch head[3] {
	case 1:
		rest = 4 + 2
	case 4:
		rest = 16 + 2
	case 3:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		rest = int(l[0]) + 2
	}
	io.ReadFull(conn, make([]byte, rest))
	conn.SetDeadline(time.Time{})
	return conn
}

// TestEndToEndSocks5EchoOverLoopback runs the real client and the real server
// against each other over loopback UDP (through a relay that stands in for a
// recursive resolver) and moves 1 MiB through a SOCKS5 CONNECT in each
// direction, once on a clean path and once with 10 % packet loss each way.
func TestEndToEndSocks5EchoOverLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end transfer is slow")
	}
	for _, tc := range []struct {
		name    string
		lossPct int32
		size    int
	}{
		{name: "clean", lossPct: 0, size: 1 << 20},
		{name: "loss10", lossPct: 10, size: 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runEndToEnd(t, tc.lossPct, tc.size)
		})
	}
}

func runEndToEnd(t *testing.T, lossPct int32, size int) {
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var echoWG sync.WaitGroup
	echoWG.Add(1)
	go func() {
		defer echoWG.Done()
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	defer func() { echo.Close(); echoWG.Wait() }()
	echoAddr := echo.Addr().String()

	const domain = "v.example.com"
	credential := protocolTestCredential(t)
	serverPort := freeUDPPort(t)
	serverCfg := config.DefaultServerConfig()
	serverCfg.UDPHost, serverCfg.UDPPort = "127.0.0.1", serverPort
	serverCfg.UDPReaders, serverCfg.DNSRequestWorkers = 1, 4
	serverCfg.Domain = []string{domain}
	serverCfg.MinVPNLabelLength = 3
	server, _ := newProtocolTestServer(t, serverCfg, logger.New("e2e-server", "error"))
	// The hostname below is not an IP literal, so it passes the SSRF guard; the
	// hook then connects it to the local echo server instead of resolving it.
	server.dialStreamUpstreamFn = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address != net.JoinHostPort("echo.test", "7007") {
			return nil, fmt.Errorf("unexpected upstream %q", address)
		}
		return net.DialTimeout("tcp4", echoAddr, timeout)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx) }()
	defer func() {
		stopServer()
		if err := <-serverDone; err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}()
	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
	forwarder := startLossyForwarder(t, serverAddr)
	resolverPort := forwarder.conn.LocalAddr().(*net.UDPAddr).Port

	clientCfg := config.DefaultClientConfig()
	clientCfg.ProtocolType, clientCfg.ListenIP = "SOCKS5", "127.0.0.1"
	clientCfg.ListenPort = freeTCPPort(t)
	clientCfg.Domains = []string{domain}
	clientCfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: resolverPort}}
	clientCfg.ResolversFilePath = filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(clientCfg.ResolversFilePath, []byte(fmt.Sprintf("127.0.0.1:%d\n", resolverPort)), 0o600); err != nil {
		t.Fatal(err)
	}
	clientCfg.AutoSaveRankedResolvers = false
	clientCfg.RX_TX_Workers, clientCfg.MTUTestParallelism = 2, 1
	clientCfg.MinUploadMTU, clientCfg.MaxUploadMTU = 38, 150
	clientCfg.MinDownloadMTU, clientCfg.MaxDownloadMTU = 200, 600
	clientCfg.MTUTestRetries, clientCfg.MTUTestTimeout = 3, 0.5
	c := client.New(clientCfg, logger.New("e2e-client", "error"), credential)
	if err := c.BuildConnectionMap(); err != nil {
		t.Fatal(err)
	}
	runCtx, stopClient := context.WithCancel(context.Background())
	clientDone := make(chan error, 1)
	go func() { clientDone <- c.Run(runCtx) }()
	defer func() {
		stopClient()
		select {
		case <-clientDone:
		case <-time.After(10 * time.Second):
			t.Error("client did not stop")
		}
	}()

	// The client opens its SOCKS5 listener only once the session is up. (Polling
	// Client.SessionReady from another goroutine would be a data race: upstream
	// reads a plain bool there.)
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(clientCfg.ListenPort))
	deadline := time.Now().Add(90 * time.Second)
	for {
		probe, err := net.DialTimeout("tcp4", proxyAddr, time.Second)
		if err == nil {
			probe.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not establish a session")
		}
		time.Sleep(100 * time.Millisecond)
	}
	forwarder.lossPct.Store(lossPct)

	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)

	conn := socks5Connect(t, proxyAddr, "echo.test", 7007)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Minute))
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()
	got := make([]byte, size)
	started := time.Now()
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back failed after %s (dropped %d of %d datagrams): %v", time.Since(started), forwarder.dropped.Load(), forwarder.dropped.Load()+forwarder.relayed.Load(), err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != want || !bytes.Equal(got, payload) {
		t.Fatal("echoed bytes differ from the bytes sent")
	}
	t.Logf("1 MiB each way in %s, datagrams relayed=%d dropped=%d", time.Since(started).Round(time.Millisecond), forwarder.relayed.Load(), forwarder.dropped.Load())
	if lossPct > 0 && forwarder.dropped.Load() == 0 {
		t.Fatal("loss was configured but nothing was dropped")
	}
}
