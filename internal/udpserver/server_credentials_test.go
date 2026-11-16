package udpserver

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
)

func testCredential(t testing.TB, kid byte) security.Credential {
	t.Helper()
	var credential security.Credential
	for i := range credential.KID {
		credential.KID[i] = kid
	}
	for i := range credential.Key {
		credential.Key[i] = kid + byte(i)
	}
	credential.ID = hexKID(credential.KID)
	return credential
}

func hexKID(kid [security.CredentialIDSize]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(kid))
	for _, b := range kid {
		out = append(out, digits[b>>4], digits[b&15])
	}
	return string(out)
}

func indexOf(t testing.TB, credentials ...security.Credential) *security.MemoryCredentialIndex {
	t.Helper()
	index, err := security.NewMemoryCredentialIndex(credentials)
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func hasData(response []byte) bool {
	_, err := extractOrNil(response)
	return err == nil
}

func TestCloseCredentialClosesOnlyThatCredentialsSessions(t *testing.T) {
	server, _ := zoneTestServer(t)
	alice, bob := testCredential(t, 0x11), testCredential(t, 0x22)
	server.SetCredentialIndex(indexOf(t, alice, bob))
	aliceCipher, aliceSession := sessionFor(t, server, alice)
	bobCipher, _ := sessionFor(t, server, bob)

	if got := server.CloseCredential(alice.ID); got != 1 {
		t.Fatalf("closed %d sessions, want 1", got)
	}
	// The very next query of alice's session finds no session.
	response := server.HandleQuery(resolverA, frameQuery(t, aliceCipher, Enums.PACKET_PING, []byte("PING"), 1232), 0, false)
	if hasData(response) {
		t.Fatal("a kicked session still gets answers")
	}
	if _, ok := server.sessions.Get(aliceSession); ok {
		t.Fatal("the session is still in the table")
	}
	// Bob is untouched.
	response = server.HandleQuery(resolverB, frameQuery(t, bobCipher, Enums.PACKET_PING, []byte("PING"), 1232), 0, false)
	if openFrame(t, bobCipher, response).PacketType != Enums.PACKET_PONG {
		t.Fatal("bob's session was disturbed by kicking alice")
	}
	// Alice may connect again (a kick is not a ban): a new INIT works.
	if cipher, _ := sessionFor(t, server, alice); cipher == nil {
		t.Fatal("alice cannot reconnect")
	}
}

func TestCloseCredentialForgetsCachedAccepts(t *testing.T) {
	server, _ := zoneTestServer(t)
	alice := testCredential(t, 0x11)
	server.SetCredentialIndex(indexOf(t, alice))
	_, _ = sessionFor(t, server, alice)
	server.protocolMu.Lock()
	cached := len(server.initCache)
	server.protocolMu.Unlock()
	if cached != 1 {
		t.Fatalf("setup: %d cached ACCEPTs", cached)
	}
	server.CloseCredential(alice.ID)
	server.protocolMu.Lock()
	cached = len(server.initCache)
	server.protocolMu.Unlock()
	if cached != 0 {
		t.Fatal("a kicked credential keeps its cached ACCEPT, a repeated INIT would hand out dead keys")
	}
}

func TestReplacingTheCredentialIndexClosesRemovedAndRekeyedSessions(t *testing.T) {
	server, _ := zoneTestServer(t)
	alice, bob, carol := testCredential(t, 0x11), testCredential(t, 0x22), testCredential(t, 0x33)
	server.SetCredentialIndex(indexOf(t, alice, bob, carol))
	aliceCipher, _ := sessionFor(t, server, alice)
	bobCipher, _ := sessionFor(t, server, bob)
	carolCipher, _ := sessionFor(t, server, carol)

	rekeyed := carol
	rekeyed.Key[0] ^= 0xFF
	server.SetCredentialIndex(indexOf(t, bob, rekeyed)) // alice removed, carol's key changed

	for name, cipher := range map[string]*security.SessionCipher{"removed": aliceCipher, "rekeyed": carolCipher} {
		if hasData(server.HandleQuery(resolverA, frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232), 0, false)) {
			t.Fatalf("the session of the %s credential is still served", name)
		}
	}
	if openFrame(t, bobCipher, server.HandleQuery(resolverA, frameQuery(t, bobCipher, Enums.PACKET_PING, []byte("PING"), 1232), 0, false)).PacketType != Enums.PACKET_PONG {
		t.Fatal("bob's session did not survive the swap of the index")
	}
	if len(server.Sessions()) != 1 {
		t.Fatalf("%d sessions remain, want 1", len(server.Sessions()))
	}
	// Removing every credential closes everything.
	server.SetCredentialIndex(nil)
	if len(server.Sessions()) != 0 {
		t.Fatal("sessions survived an empty credential index")
	}
}

func TestSessionsPerCredentialAreCappedByClosingTheIdlest(t *testing.T) {
	server, _ := zoneTestServer(t, func(cfg *config.ServerConfig) { cfg.MaxSessionsPerCredential = 2 })
	alice, bob := testCredential(t, 0x11), testCredential(t, 0x22)
	server.SetCredentialIndex(indexOf(t, alice, bob))
	first, firstID := sessionFor(t, server, alice)
	second, _ := sessionFor(t, server, alice)
	bobCipher, _ := sessionFor(t, server, bob)
	// The second session was used more recently than the first.
	time.Sleep(5 * time.Millisecond)
	if !hasData(server.HandleQuery(resolverA, frameQuery(t, second, Enums.PACKET_PING, []byte("PING"), 1232), 0, false)) {
		t.Fatal("second session does not work")
	}
	third, _ := sessionFor(t, server, alice)

	if _, ok := server.sessions.Get(firstID); ok {
		t.Fatal("the idlest session of alice was not closed")
	}
	if hasData(server.HandleQuery(resolverA, frameQuery(t, first, Enums.PACKET_PING, []byte("PING"), 1232), 0, false)) {
		t.Fatal("the evicted session is still served")
	}
	for name, cipher := range map[string]*security.SessionCipher{"second": second, "third": third, "bob": bobCipher} {
		if !hasData(server.HandleQuery(resolverA, frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232), 0, false)) {
			t.Fatalf("session %s was closed", name)
		}
	}
	count := 0
	for _, info := range server.Sessions() {
		if info.CredentialID == alice.ID {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("alice holds %d sessions, want 2", count)
	}
}

func TestSessionsListsCredentialResolverAndCounters(t *testing.T) {
	server, _ := zoneTestServer(t)
	alice := testCredential(t, 0x11)
	server.SetCredentialIndex(indexOf(t, alice))
	cipher, sessionID := sessionFor(t, server, alice)
	query := frameQuery(t, cipher, Enums.PACKET_PING, []byte("PING"), 1232)
	answer := server.HandleQuery(resolverB, query, 0, false)
	infos := server.Sessions()
	if len(infos) != 1 {
		t.Fatalf("%d sessions listed", len(infos))
	}
	info := infos[0]
	if info.ID != sessionID || info.CredentialID != alice.ID {
		t.Fatalf("session %+v", info)
	}
	if info.Resolver != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("resolver %v is not the address that carried the query", info.Resolver)
	}
	if info.Queries != 1 || info.RxBytes != uint64(len(query)) || info.TxBytes != uint64(len(answer)) {
		t.Fatalf("counters %+v for query %d answer %d", info, len(query), len(answer))
	}
	if info.Age < 0 || info.LastActive.IsZero() {
		t.Fatalf("times %+v", info)
	}
}

func TestPreSessionProbesAreRefusedForARemovedCredential(t *testing.T) {
	server, _ := zoneTestServer(t)
	alice := testCredential(t, 0x11)
	server.SetCredentialIndex(indexOf(t, alice))
	server.SetCredentialIndex(nil)
	var parameters [security.InitParametersSize]byte
	binary.BigEndian.PutUint16(parameters[1:3], 100)
	_, initMessage, err := security.NewClientHandshake(alice, parameters, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response := server.HandleQuery(resolverA, tunnelQueryEDNS(t, initMessage, 1232), 0, false)
	if len(response) != 0 {
		t.Fatalf("an INIT of a removed credential got %d bytes", len(response))
	}
}
