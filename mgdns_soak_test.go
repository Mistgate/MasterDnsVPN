package mgdns_test

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mgdns "masterdnsvpn-go"
)

// TestFacadeSoak keeps one session busy for minutes over a lossy path, as issue
// 202 reports a tunnel that goes quiet after about three and a half minutes
// (the 120 s time to live of a SOCKS5_SYN plus the 90 s wait for the answer to
// its reset): a long-lived connection exchanges a short message every 250 ms
// and must never wait long for an answer; a fresh connection is opened every
// few seconds and must be connected within seconds; connects to a target that
// never answers come and go in between and must not hold the others up.
//
// It runs 5 minutes. MGDNS_SOAK_MINUTES sets another duration (30 for the full
// run); -short skips it.
func TestFacadeSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test")
	}
	duration := 5 * time.Minute
	if value := os.Getenv("MGDNS_SOAK_MINUTES"); value != "" {
		minutes, err := strconv.ParseFloat(value, 64)
		if err != nil || minutes <= 0 {
			t.Fatalf("MGDNS_SOAK_MINUTES=%q", value)
		}
		duration = time.Duration(minutes * float64(time.Minute))
	}

	echo := startEcho(t)
	s := startServer(t, echo, func(cfg *mgdns.ServerConfig) { cfg.ConnectTimeout = 5 * time.Second })
	s.server.SetCredentialIndex(index(t, e2eCredential))
	r := newRelay(t, s.server, "198.51.100.7:53000")
	r.lossPct.Store(3)
	r.dupPct.Store(3)
	r.retryPct.Store(3)
	client := startClient(t, e2eCredential, r)

	ctx, cancel := context.WithTimeout(context.Background(), duration+3*time.Minute)
	defer cancel()
	long, err := client.DialContext(ctx, "tcp", "echo.test:7007")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer long.Close()
	firstSession := s.server.Sessions()
	if len(firstSession) != 1 {
		t.Fatalf("%d sessions after the first dial", len(firstSession))
	}

	deadline := time.Now().Add(duration)
	var (
		wg           sync.WaitGroup
		longRounds   atomic.Int64
		maxStall     atomic.Int64 // nanoseconds
		freshOK      atomic.Int64
		freshSlowest atomic.Int64
		blackholes   atomic.Int64
	)
	fail := func(format string, args ...any) { t.Errorf(format, args...) }

	// the long-lived connection
	wg.Add(1)
	go func() {
		defer wg.Done()
		message := []byte("a short message that is echoed through the tunnel........")
		reply := make([]byte, len(message))
		last := time.Now()
		for time.Now().Before(deadline) {
			_ = long.SetDeadline(time.Now().Add(60 * time.Second))
			if _, err := long.Write(message); err != nil {
				fail("long connection write: %v", err)
				return
			}
			if _, err := io.ReadFull(long, reply); err != nil {
				fail("long connection read after %s: %v", time.Since(last).Round(time.Millisecond), err)
				return
			}
			now := time.Now()
			if stall := now.Sub(last).Nanoseconds(); stall > maxStall.Load() {
				maxStall.Store(stall)
			}
			if now.Sub(last) > 25*time.Second {
				fail("the long connection waited %s for one echo", now.Sub(last).Round(time.Millisecond))
			}
			last = now
			longRounds.Add(1)
			time.Sleep(250 * time.Millisecond)
		}
	}()

	// fresh connections
	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(deadline) {
			started := time.Now()
			dialCtx, cancelDial := context.WithTimeout(ctx, 40*time.Second)
			conn, err := client.DialContext(dialCtx, "tcp", "echo.test:7007")
			cancelDial()
			if err != nil {
				fail("a fresh connect failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
				time.Sleep(time.Second)
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(40 * time.Second))
			if _, err := conn.Write([]byte("fresh")); err == nil {
				buf := make([]byte, 5)
				_, err = io.ReadFull(conn, buf)
				if err != nil {
					fail("a fresh connection did not echo: %v", err)
				}
			}
			_ = conn.Close()
			took := time.Since(started)
			if took > 30*time.Second {
				fail("a fresh connect and echo took %s", took.Round(time.Millisecond))
			}
			if took.Nanoseconds() > freshSlowest.Load() {
				freshSlowest.Store(took.Nanoseconds())
			}
			freshOK.Add(1)
			time.Sleep(4 * time.Second)
		}
	}()

	// connects to a black hole
	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(deadline) {
			time.Sleep(11 * time.Second)
			dialCtx, cancelDial := context.WithTimeout(ctx, 40*time.Second)
			conn, err := client.DialContext(dialCtx, "tcp", "blackhole.test:443")
			cancelDial()
			if err == nil {
				_ = conn.Close()
				fail("a connect to a black hole succeeded")
				continue
			}
			var dialErr *mgdns.DialError
			if errors.As(err, &dialErr) {
				blackholes.Add(1)
			} else {
				fail("a connect to a black hole failed with %v, not with the server's answer", err)
			}
		}
	}()

	// progress and leak watch
	var warmGoroutines int
	progress := time.NewTicker(30 * time.Second)
	defer progress.Stop()
	started := time.Now()
	watching := true
	for watching {
		select {
		case <-progress.C:
			elapsed := time.Since(started)
			if warmGoroutines == 0 && elapsed >= 60*time.Second {
				warmGoroutines = runtime.NumGoroutine()
			}
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			stats := s.server.Stats()
			t.Logf("%s: long rounds=%d (max wait %s), fresh ok=%d (slowest %s), black holes=%d, goroutines=%d, heap=%d MiB, server queries=%d truncated=%d replays=%d cache=%d",
				elapsed.Round(time.Second), longRounds.Load(), time.Duration(maxStall.Load()).Round(time.Millisecond),
				freshOK.Load(), time.Duration(freshSlowest.Load()).Round(time.Millisecond), blackholes.Load(),
				runtime.NumGoroutine(), mem.HeapAlloc>>20, stats.Queries, stats.Truncated, stats.Replays, stats.CacheServed)
			if time.Now().After(deadline) {
				watching = false
			}
		case <-time.After(time.Until(deadline) + 2*time.Second):
			watching = false
		}
	}
	wg.Wait()

	final := runtime.NumGoroutine()
	t.Logf("done: long rounds=%d, longest wait for an echo %s, fresh connections=%d, black-hole connects=%d, goroutines %d -> %d",
		longRounds.Load(), time.Duration(maxStall.Load()).Round(time.Millisecond), freshOK.Load(), blackholes.Load(), warmGoroutines, final)
	if warmGoroutines > 0 && final > warmGoroutines*3/2+50 {
		t.Errorf("goroutines grew from %d to %d during the soak", warmGoroutines, final)
	}
	sessions := s.server.Sessions()
	if len(sessions) != 1 || sessions[0].ID != firstSession[0].ID {
		t.Errorf("the session was replaced during the soak: %+v then %+v", firstSession, sessions)
	}
	if freshOK.Load() == 0 || blackholes.Load() == 0 {
		t.Error("the soak did not exercise fresh and black-hole connects")
	}
}
