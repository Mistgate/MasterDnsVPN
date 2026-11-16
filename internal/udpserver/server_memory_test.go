package udpserver

import (
	"runtime"
	"testing"

	"masterdnsvpn-go/internal/config"
)

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// TestIdleSessionTableFootprint measures what 64 sessions with 8 open streams
// each hold when nothing flows. A stream that moves data additionally holds up
// to the ARQ window (512 packets) of the session's download MTU in its send
// buffer, which is what bounds the worst case documented in MISTGATE.md.
func TestIdleSessionTableFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("memory measurement")
	}
	const sessions, streams = 64, 8
	server, _ := zoneTestServer(t, func(cfg *config.ServerConfig) {
		cfg.MaxSessionsPerCredential = sessions
		cfg.MaxAllowedClientActiveSessions = sessions
	})
	credential := testCredential(t, 0x41)
	server.SetCredentialIndex(indexOf(t, credential))
	baseHeap, baseGoroutines := heapInUse(), runtime.NumGoroutine()
	for i := 0; i < sessions; i++ {
		_, id := sessionFor(t, server, credential)
		record, ok := server.sessions.Get(id)
		if !ok {
			t.Fatalf("session %d missing", id)
		}
		for stream := uint16(1); stream <= streams; stream++ {
			if record.getOrCreateStream(stream, server.streamARQConfig(), nil, nil) == nil {
				t.Fatal("stream not created")
			}
		}
	}
	grown := heapInUse() - baseHeap
	goroutines := runtime.NumGoroutine() - baseGoroutines
	t.Logf("%d sessions x %d streams idle: heap +%d KiB (%d KiB per session, %d KiB per stream), goroutines +%d (%d per stream)",
		sessions, streams, grown>>10, grown>>10/sessions, grown>>10/(sessions*streams), goroutines, goroutines/(sessions*streams))
	if len(server.Sessions()) != sessions {
		t.Fatalf("%d sessions", len(server.Sessions()))
	}
}
