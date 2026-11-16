package security

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const vectorTimestamp = uint32(0x65010203)

var (
	vectorParameters = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	vectorPolicy     = []byte{0x10, 0x20, 0x30}
)

func seq(first byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = first + byte(i)
	}
	return out
}

func vectorCredential() Credential {
	var credential Credential
	copy(credential.KID[:], seq(0, CredentialIDSize))
	copy(credential.Key[:], seq(0, CredentialKeySize))
	credential.ID = "0001020304050607"
	return credential
}

func vectorPrivateKey(t testing.TB, first byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(seq(first, 32))
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	return key
}

func vectorParametersArray() [InitParametersSize]byte {
	var parameters [InitParametersSize]byte
	copy(parameters[:], vectorParameters)
	return parameters
}

type vectorSet struct {
	init, accept     []byte
	keys             DirectionalKeys
	frame0, frame5   []byte
	frame5Plain      []byte
	clientCipher     *SessionCipher
	serverCipher     *SessionCipher
	credential       Credential
	index            *MemoryCredentialIndex
	clientHandshake  *ClientHandshake
	clientPrivateKey *ecdh.PrivateKey
}

func newVectorSet(t testing.TB) vectorSet {
	t.Helper()
	var v vectorSet
	v.credential = vectorCredential()
	var err error
	if v.index, err = NewMemoryCredentialIndex([]Credential{v.credential}); err != nil {
		t.Fatal(err)
	}
	v.clientPrivateKey = vectorPrivateKey(t, 0x20)
	if v.init, err = BuildSessionInit(v.credential, vectorParametersArray(), vectorTimestamp, v.clientPrivateKey); err != nil {
		t.Fatal(err)
	}
	if v.clientHandshake, err = newClientHandshakeWithPrivateKey(v.credential, v.init, v.clientPrivateKey); err != nil {
		t.Fatal(err)
	}
	if v.accept, v.keys, err = BuildSessionAccept(v.credential, v.init, 0x7e, vectorPolicy, vectorPrivateKey(t, 0x40)); err != nil {
		t.Fatal(err)
	}
	if v.serverCipher, err = NewSessionCipher(0x7e, v.keys.ServerToClient, v.keys.ClientToServer); err != nil {
		t.Fatal(err)
	}
	if v.clientCipher, err = NewSessionCipher(0x7e, v.keys.ClientToServer, v.keys.ServerToClient); err != nil {
		t.Fatal(err)
	}
	v.frame5Plain = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if v.frame0, err = v.clientCipher.Seal(v.frame5Plain); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 5; i++ {
		if _, err = v.clientCipher.Seal(v.frame5Plain); err != nil {
			t.Fatal(err)
		}
	}
	if v.frame5, err = v.clientCipher.Seal(v.frame5Plain); err != nil {
		t.Fatal(err)
	}
	return v
}

func newClientHandshakeWithPrivateKey(credential Credential, initMessage []byte, private *ecdh.PrivateKey) (*ClientHandshake, error) {
	if len(initMessage) != SessionInitSize || private == nil {
		return nil, ErrInvalidMessage
	}
	return &ClientHandshake{credential: credential, private: private, init: append([]byte(nil), initMessage...)}, nil
}

// Expected bytes for the fixed inputs above, pinned as literals. They were
// produced by the independent reference in reference_test.go (see
// TestReferenceImplementationMatchesPinnedVectors) and are the compatibility
// contract for every later client and server.
const (
	pinnedInit   = "01000102030405060765010203358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662549e20b10eab6df8e903063738d1f7e25b4d8c1a33000c0b450db2"
	pinnedAccept = "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a5127151ad99776a55c58d26faa472374a907100e"
	pinnedC2S    = "e65e010a1c0ab292b08eb5da5a0340ef6502d01880040a285e788dc822736626"
	pinnedS2C    = "d8c2c5531763b050b1146ea95585d530755e7c2604baf072146704cfea8f4383"
	pinnedFrame0 = "7e00000000b0335d8fdfc5324d1ef3d47cae4e7b7e31c91125be172d17"
	pinnedFrame5 = "7e00000005a03e581b56d07c3e50d8193002f09a4029a8b4ade0bfc7d5"
	pinnedProbe  = "015000010203040506076553f100909192939495969764006137bcfe9c5425f399d7e25252b57881e05237a483f9bef5822bf5"
)

const pinnedProbeTS = uint32(1_700_000_000)

func TestReferenceImplementationMatchesPinnedVectors(t *testing.T) {
	v := newVectorSet(t)
	credential := vectorCredential()
	clientPrivate := seq(0x20, 32)
	serverPrivate := seq(0x40, 32)

	wantInit := refInit(credential.KID[:], credential.Key[:], vectorTimestamp, clientPrivate, vectorParameters)
	if !bytes.Equal(v.init, wantInit) {
		t.Fatalf("INIT differs from the reference:\n got %x\nwant %x", v.init, wantInit)
	}
	if len(v.init) != 71 || SessionInitSize != 71 {
		t.Fatalf("INIT must be 1+8+4+32+10+16 = 71 bytes, got %d", len(v.init))
	}
	wantAccept, c2s, s2c := refAccept(credential.Key[:], wantInit, clientPrivate, serverPrivate, 0x7e, vectorPolicy)
	if !bytes.Equal(v.accept, wantAccept) {
		t.Fatalf("ACCEPT differs from the reference:\n got %x\nwant %x", v.accept, wantAccept)
	}
	if len(v.accept) != 32+1+len(vectorPolicy)+16 {
		t.Fatalf("ACCEPT must be e_s 32 + AEAD(sid, policy), got %d bytes", len(v.accept))
	}
	if !bytes.Equal(v.keys.ClientToServer[:], c2s) || !bytes.Equal(v.keys.ServerToClient[:], s2c) {
		t.Fatalf("directional keys differ from the reference")
	}
	if bytes.Equal(c2s, s2c) {
		t.Fatal("the two directions must have different keys")
	}
	if want := refFrame(c2s, 0x7e, 0, v.frame5Plain); !bytes.Equal(v.frame0, want) {
		t.Fatalf("frame 0 differs from the reference:\n got %x\nwant %x", v.frame0, want)
	}
	if want := refFrame(c2s, 0x7e, 5, v.frame5Plain); !bytes.Equal(v.frame5, want) {
		t.Fatalf("frame 5 differs from the reference:\n got %x\nwant %x", v.frame5, want)
	}
	if len(v.frame0) != FramePrefixSize+len(v.frame5Plain)+16 || v.frame0[0] != 0x7e || !bytes.Equal(v.frame0[1:5], []byte{0, 0, 0, 0}) || !bytes.Equal(v.frame5[1:5], []byte{0, 0, 0, 5}) {
		t.Fatalf("frame layout is sid | ctr(4, big endian) | ciphertext+tag: %x", v.frame5)
	}

	random8 := seq(0x90, 8)
	probe, err := SealProbe(credential, []byte("probe-payload"), time.Unix(int64(pinnedProbeTS), 0), bytes.NewReader(random8))
	if err != nil {
		t.Fatal(err)
	}
	if want := refProbe(credential.KID[:], credential.Key[:], pinnedProbeTS, random8, []byte("probe-payload")); !bytes.Equal(probe, want) {
		t.Fatalf("probe differs from the reference:\n got %x\nwant %x", probe, want)
	}

	for name, pair := range map[string][2]string{
		"init": {hex.EncodeToString(v.init), pinnedInit}, "accept": {hex.EncodeToString(v.accept), pinnedAccept},
		"c2s": {hex.EncodeToString(c2s), pinnedC2S}, "s2c": {hex.EncodeToString(s2c), pinnedS2C},
		"frame0": {hex.EncodeToString(v.frame0), pinnedFrame0}, "frame5": {hex.EncodeToString(v.frame5), pinnedFrame5},
		"probe": {hex.EncodeToString(probe), pinnedProbe},
	} {
		if pair[0] != pair[1] {
			t.Errorf("pinned %s vector changed:\n got %s\nwant %s", name, pair[0], pair[1])
		}
	}
}

func TestHandshakeEndToEndAgreesOnKeys(t *testing.T) {
	credential := vectorCredential()
	index, _ := NewMemoryCredentialIndex([]Credential{credential})
	now := time.Unix(1_700_000_000, 0)
	handshake, initMessage, err := NewClientHandshake(credential, vectorParametersArray(), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	gotCredential, init, err := OpenSessionInit(initMessage, index, now)
	if err != nil {
		t.Fatal(err)
	}
	if gotCredential.ID != credential.ID || !bytes.Equal(init.Parameters[:], vectorParameters) || init.Timestamp != uint32(now.Unix()) {
		t.Fatalf("server read different INIT contents: %+v", init)
	}
	serverPrivate, _ := ecdh.X25519().GenerateKey(rand.Reader)
	accept, serverKeys, err := BuildSessionAccept(gotCredential, initMessage, 9, vectorPolicy, serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	accepted, clientKeys, err := handshake.OpenAccept(accept)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.SessionID != 9 || !bytes.Equal(accepted.Policy, vectorPolicy) {
		t.Fatalf("client read different ACCEPT contents: %+v", accepted)
	}
	if clientKeys != serverKeys {
		t.Fatal("client and server derived different keys")
	}
	client, _ := NewSessionCipher(9, clientKeys.ClientToServer, clientKeys.ServerToClient)
	server, _ := NewSessionCipher(9, serverKeys.ServerToClient, serverKeys.ClientToServer)
	up, _ := client.Seal([]byte("up"))
	down, _ := server.Seal([]byte("down"))
	if plain, _, err := server.Open(up); err != nil || string(plain) != "up" {
		t.Fatalf("server could not open client frame: %q %v", plain, err)
	}
	if plain, _, err := client.Open(down); err != nil || string(plain) != "down" {
		t.Fatalf("client could not open server frame: %q %v", plain, err)
	}
	// Reflection: a direction's own frames do not open under the same direction's keys.
	if _, _, err := client.Open(up); err == nil {
		t.Fatal("client accepted its own uplink frame as downlink")
	}
	if _, _, err := server.Open(down); err == nil {
		t.Fatal("server accepted its own downlink frame as uplink")
	}
}

func TestEveryFlippedByteFailsAuthentication(t *testing.T) {
	v := newVectorSet(t)
	now := time.Unix(int64(vectorTimestamp), 0)
	for i := range v.init {
		mutated := append([]byte(nil), v.init...)
		mutated[i] ^= 1
		if _, _, err := OpenSessionInit(mutated, v.index, now); err == nil {
			t.Errorf("mutated INIT byte %d was accepted", i)
		}
	}
	for i := range v.accept {
		mutated := append([]byte(nil), v.accept...)
		mutated[i] ^= 1
		if _, _, err := v.clientHandshake.OpenAccept(mutated); err == nil {
			t.Errorf("mutated ACCEPT byte %d was accepted", i)
		}
	}
	for i := range v.frame0 {
		mutated := append([]byte(nil), v.frame0...)
		mutated[i] ^= 1
		receiver, err := NewSessionCipher(0x7e, v.keys.ServerToClient, v.keys.ClientToServer)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := receiver.Open(mutated); err == nil {
			t.Errorf("mutated frame byte %d was accepted", i)
		}
	}
	probe, err := SealProbe(v.credential, []byte("probe"), now, bytes.NewReader(seq(1, 8)))
	if err != nil {
		t.Fatal(err)
	}
	for i := range probe {
		mutated := append([]byte(nil), probe...)
		mutated[i] ^= 1
		if _, err := OpenProbeWithCredential(mutated, v.credential); err == nil {
			t.Errorf("mutated probe byte %d was accepted", i)
		}
	}
	// Truncation and extension are rejected as well.
	for _, size := range []int{0, 1, FramePrefixSize, len(v.frame0) - 1} {
		receiver, _ := NewSessionCipher(0x7e, v.keys.ServerToClient, v.keys.ClientToServer)
		if _, _, err := receiver.Open(v.frame0[:size]); err == nil {
			t.Errorf("frame truncated to %d bytes was accepted", size)
		}
	}
	if _, _, err := OpenSessionInit(append(append([]byte(nil), v.init...), 0), v.index, now); err == nil {
		t.Error("INIT with a trailing byte was accepted")
	}
}

// The frame AAD covers the protocol version in addition to sid and ctr: a frame
// sealed with an AAD of only sid||ctr (no version) must not open.
func TestFrameAADIncludesVersionSidAndCounter(t *testing.T) {
	v := newVectorSet(t)
	key := v.keys.ClientToServer[:]
	prefix := cat([]byte{0x7e}, be32(0))
	nonce := cat(make([]byte, 8), be32(0))
	withoutVersion := cat(prefix, refSeal(key, nonce, v.frame5Plain, prefix))
	receiver, _ := NewSessionCipher(0x7e, v.keys.ServerToClient, v.keys.ClientToServer)
	if _, _, err := receiver.Open(withoutVersion); err == nil {
		t.Fatal("frame whose AAD lacks the version byte was accepted")
	}
	receiver, _ = NewSessionCipher(0x7e, v.keys.ServerToClient, v.keys.ClientToServer)
	withVersionAAD := cat(prefix, refSeal(key, nonce, v.frame5Plain, cat([]byte{ProtocolVersion}, prefix)))
	if _, _, err := receiver.Open(withVersionAAD); err != nil {
		t.Fatalf("frame with the documented AAD was rejected: %v", err)
	}
	// Re-labelling the sid or counter of a valid frame fails (they are in the AAD).
	receiver, _ = NewSessionCipher(0x7e, v.keys.ServerToClient, v.keys.ClientToServer)
	other := append([]byte(nil), v.frame5...)
	other[4] ^= 0x01
	if _, _, err := receiver.Open(other); err == nil {
		t.Fatal("frame with an altered counter was accepted")
	}
}

func TestInitTimestampWindowEdgesAndCredentialFailures(t *testing.T) {
	credential := vectorCredential()
	index, err := NewMemoryCredentialIndex([]Credential{credential})
	if err != nil {
		t.Fatal(err)
	}
	const timestamp = uint32(1_700_000_000)
	message, err := BuildSessionInit(credential, vectorParametersArray(), timestamp, vectorPrivateKey(t, 0x20))
	if err != nil {
		t.Fatal(err)
	}
	for _, delta := range []int64{-120, -1, 0, 1, 120} {
		if _, _, err := OpenSessionInit(message, index, time.Unix(int64(timestamp)+delta, 0)); err != nil {
			t.Errorf("INIT %+d s from its timestamp must be accepted: %v", delta, err)
		}
	}
	for _, delta := range []int64{-121, 121, 3600, -3600} {
		if _, _, err := OpenSessionInit(message, index, time.Unix(int64(timestamp)+delta, 0)); !errors.Is(err, ErrTimestamp) {
			t.Errorf("INIT %+d s from its timestamp must be refused with ErrTimestamp, got %v", delta, err)
		}
	}

	wrongKey := credential
	wrongKey.Key[0] ^= 0xff
	wrongKeyIndex, _ := NewMemoryCredentialIndex([]Credential{wrongKey})
	if _, _, err := OpenSessionInit(message, wrongKeyIndex, time.Unix(int64(timestamp), 0)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected wrong-key authentication rejection, got %v", err)
	}
	unknown := credential
	unknown.KID[0] ^= 0xff
	unknownIndex, _ := NewMemoryCredentialIndex([]Credential{unknown})
	if _, _, err := OpenSessionInit(message, unknownIndex, time.Unix(int64(timestamp), 0)); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("expected unknown-kid rejection, got %v", err)
	}
	if _, _, err := OpenSessionInit(message, nil, time.Unix(int64(timestamp), 0)); err == nil {
		t.Fatal("a nil credential index must refuse everything")
	}
	var empty AtomicCredentialIndex
	if _, _, err := OpenSessionInit(message, &empty, time.Unix(int64(timestamp), 0)); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("an index that was never set must know no kid, got %v", err)
	}
	versioned := append([]byte(nil), message...)
	versioned[0] = 2
	if _, _, err := OpenSessionInit(versioned, index, time.Unix(int64(timestamp), 0)); err == nil {
		t.Fatal("unsupported protocol version was accepted")
	}
}

func TestAtomicCredentialIndexReplacesSetAtomically(t *testing.T) {
	credential := vectorCredential()
	first, _ := NewMemoryCredentialIndex([]Credential{credential})
	store := NewAtomicCredentialIndex(first)
	if _, ok := store.Lookup(credential.KID); !ok {
		t.Fatal("credential not found after Set")
	}
	store.Set(nil)
	if _, ok := store.Lookup(credential.KID); ok {
		t.Fatal("credential still found after the index was cleared")
	}
	other := credential
	other.KID[7] ^= 1
	second, _ := NewMemoryCredentialIndex([]Credential{other})
	store.Set(second)
	if _, ok := store.Lookup(credential.KID); ok {
		t.Fatal("old credential survived the swap")
	}
	if _, ok := store.Lookup(other.KID); !ok {
		t.Fatal("new credential missing after the swap")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				store.Lookup(credential.KID)
				store.Set(first)
				store.Set(second)
			}
		}()
	}
	wg.Wait()
}

func TestLowOrderKeysAreRefused(t *testing.T) {
	credential := vectorCredential()
	zero := make([]byte, 32)
	lowOrder, err := ecdh.X25519().NewPublicKey(zero)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vectorPrivateKey(t, 0x40).ECDH(lowOrder); err == nil {
		t.Skip("crypto/ecdh no longer rejects the all-zero shared secret")
	}

	// Client side: an INIT that carries a low-order e_c is built by a PSK holder
	// (the all-zero point). The server refuses to make an ACCEPT for it.
	header := cat([]byte{1}, credential.KID[:], be32(vectorTimestamp), zero)
	nonce := refHash12([]byte("masterdnsvpn-go/init/v1"), header)
	badInit := cat(header, refSeal(credential.Key[:], nonce, vectorParameters, header))
	index, _ := NewMemoryCredentialIndex([]Credential{credential})
	if _, _, err := OpenSessionInit(badInit, index, time.Unix(int64(vectorTimestamp), 0)); err != nil {
		t.Fatalf("INIT with a low-order key is authentic, only its use must fail: %v", err)
	}
	if _, _, err := BuildSessionAccept(credential, badInit, 1, vectorPolicy, vectorPrivateKey(t, 0x40)); err == nil {
		t.Fatal("ACCEPT was built for a low-order client key")
	}

	// Server side: an ACCEPT carrying e_s = 0, correctly sealed under the PSK.
	v := newVectorSet(t)
	acceptNonce := refHash12([]byte("masterdnsvpn-go/accept/v1"), v.init, zero)
	aad := cat([]byte("masterdnsvpn-go/accept-aad/v1"), v.init, zero)
	badAccept := cat(zero, refSeal(credential.Key[:], acceptNonce, cat([]byte{1}, vectorPolicy), aad))
	if _, _, err := v.clientHandshake.OpenAccept(badAccept); err == nil {
		t.Fatal("client accepted a low-order server key")
	}
}

func TestReplayedFrameIsRejectedAfterOneDelivery(t *testing.T) {
	var key [CredentialKeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x42}, len(key)))
	sender, _ := NewSessionCipher(7, key, key)
	receiver, _ := NewSessionCipher(7, key, key)
	frame, err := sender.Seal([]byte("packet"))
	if err != nil {
		t.Fatal(err)
	}
	plain, counter, err := receiver.Open(frame)
	if err != nil || string(plain) != "packet" || counter != 0 {
		t.Fatalf("first frame was not delivered: plain=%q counter=%d err=%v", plain, counter, err)
	}
	if _, _, err := receiver.Open(frame); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestReplayWindowEdgesAndCounterWrap(t *testing.T) {
	var window ReplayWindow
	if !window.Accept(5000) {
		t.Fatal("newest counter rejected")
	}
	for _, behind := range []uint32{2047, 2046, 1, 64, 63, 65} {
		if !window.Accept(5000 - behind) {
			t.Errorf("counter %d behind the newest was rejected, the window is 2048 wide", behind)
		}
	}
	for _, behind := range []uint32{2048, 2049, 4000} {
		if window.Accept(5000 - behind) {
			t.Errorf("counter %d behind the newest was accepted", behind)
		}
	}
	for _, behind := range []uint32{0, 2047, 64, 63, 65, 1} {
		if window.Accept(5000 - behind) {
			t.Errorf("duplicate of the counter %d behind the newest was accepted", behind)
		}
	}
	// The window slides with the newest counter: what was 2047 behind is now out.
	if !window.Accept(5001) {
		t.Fatal("next counter rejected")
	}
	if window.Accept(5000 - 2047) {
		t.Fatal("a counter that slid out of the window was accepted")
	}
	var sliding ReplayWindow
	sliding.Accept(10_000)
	sliding.Accept(10_001)
	if sliding.Accept(10_001-2048) || !sliding.Accept(10_001-2047) {
		t.Fatal("the window edge must be exactly 2047 behind the newest counter")
	}
	// A jump larger than the window clears everything older.
	if !window.Accept(1_000_000) || window.Accept(5001) || window.Accept(1_000_000-2048) {
		t.Fatal("a large forward jump must invalidate counters older than the window")
	}

	var wrapping ReplayWindow
	for _, counter := range []uint32{math.MaxUint32 - 1, math.MaxUint32, 0, 1} {
		if !wrapping.Accept(counter) {
			t.Fatalf("counter %d was rejected across uint32 wrap", counter)
		}
	}
	if wrapping.Accept(math.MaxUint32) || wrapping.Accept(0) {
		t.Fatal("wrapped replay window accepted a duplicate counter")
	}
	if !wrapping.Accept(math.MaxUint32 - 5) {
		t.Fatal("a fresh counter just before the wrap was rejected")
	}
}

func TestCounterExhaustionDoesNotReuseNonce(t *testing.T) {
	var key [CredentialKeySize]byte
	cipher, _ := NewSessionCipher(2, key, key)
	if cipher.NeedsRekey() {
		t.Fatal("a new session must not ask for a rekey")
	}
	cipher.txCounter = RekeyAfterFrames
	if !cipher.NeedsRekey() {
		t.Fatal("a session at the rekey threshold must ask for a new handshake")
	}
	cipher.txCounter = math.MaxUint32
	last, err := cipher.Seal([]byte{1})
	if err != nil {
		t.Fatalf("last counter should be usable: %v", err)
	}
	if !bytes.Equal(last[1:5], []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Fatalf("last frame must carry counter 2^32-1, got %x", last[1:5])
	}
	for i := 0; i < 3; i++ {
		if _, err := cipher.Seal([]byte{1}); !errors.Is(err, ErrCounterExhausted) {
			t.Fatalf("expected exhausted counter error, got %v", err)
		}
	}
}

func TestConcurrentSealsUseDistinctCounters(t *testing.T) {
	var key [CredentialKeySize]byte
	sender, _ := NewSessionCipher(3, key, key)
	receiver, _ := NewSessionCipher(3, key, key)
	const workers, each = 8, 500
	frames := make(chan []byte, workers*each)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				frame, err := sender.Seal([]byte{1, 2, 3})
				if err != nil {
					t.Error(err)
					return
				}
				frames <- frame
			}
		}()
	}
	wg.Wait()
	close(frames)
	seen := make(map[uint32]bool)
	for frame := range frames {
		_, counter, err := receiver.Open(frame)
		if err != nil && !errors.Is(err, ErrReplay) {
			t.Fatal(err)
		}
		if seen[counter] {
			t.Fatalf("counter %d was used twice", counter)
		}
		seen[counter] = true
	}
	if len(seen) != workers*each {
		t.Fatalf("expected %d distinct counters, got %d", workers*each, len(seen))
	}
}

func TestProbeRoundTripFreshnessReplayAndBudget(t *testing.T) {
	credential := vectorCredential()
	index, _ := NewMemoryCredentialIndex([]Credential{credential})
	now := time.Unix(1_700_000_000, 0)

	probe, err := SealProbe(credential, []byte("payload"), now, bytes.NewReader(seq(1, 8)))
	if err != nil {
		t.Fatal(err)
	}
	if len(probe) != ProbeHeaderSize+len("payload")+TagSize || ProbeHeaderSize != 22 {
		t.Fatalf("probe layout is 22 header bytes + payload + 16 tag, got header %d total %d", ProbeHeaderSize, len(probe))
	}
	gotCredential, opened, err := OpenProbe(probe, index)
	if err != nil || string(opened.Payload) != "payload" || gotCredential.ID != credential.ID || opened.Timestamp() != uint32(now.Unix()) {
		t.Fatalf("probe round trip failed: %+v %v", opened, err)
	}

	limiter := NewProbeLimiter()
	if !limiter.Allow(credential.KID, opened.Nonce, now) {
		t.Fatal("a fresh probe was refused")
	}
	// A captured probe cannot be replayed, not within the minute and not after it
	// (until its timestamp leaves the window it stays remembered).
	for _, later := range []time.Duration{0, 10 * time.Second, 61 * time.Second, 119 * time.Second, 120 * time.Second} {
		if limiter.Allow(credential.KID, opened.Nonce, now.Add(later)) {
			t.Errorf("replayed probe accepted %s later", later)
		}
	}
	// A stale or far-future probe is refused outright.
	stale, _ := SealProbe(credential, []byte("x"), now.Add(-121*time.Second), bytes.NewReader(seq(2, 8)))
	_, staleProbe, _ := OpenProbe(stale, index)
	if limiter.Allow(credential.KID, staleProbe.Nonce, now) {
		t.Fatal("a probe older than 120 s was accepted")
	}
	future, _ := SealProbe(credential, []byte("x"), now.Add(121*time.Second), bytes.NewReader(seq(3, 8)))
	_, futureProbe, _ := OpenProbe(future, index)
	if limiter.Allow(credential.KID, futureProbe.Nonce, now) {
		t.Fatal("a probe from more than 120 s in the future was accepted")
	}

	// 60 probes per minute per credential, the 61st is refused, the budget refills.
	other := NewProbeLimiter()
	for i := 0; i < ProbeBudgetPerMinute; i++ {
		p, _ := SealProbe(credential, []byte{1}, now, bytes.NewReader(seq(byte(10+i), 8)))
		_, m, _ := OpenProbe(p, index)
		if !other.Allow(credential.KID, m.Nonce, now) {
			t.Fatalf("probe %d of the budget was refused", i+1)
		}
	}
	p, _ := SealProbe(credential, []byte{1}, now, bytes.NewReader(seq(200, 8)))
	_, m, _ := OpenProbe(p, index)
	if other.Allow(credential.KID, m.Nonce, now) {
		t.Fatal("the 61st probe in a minute was accepted")
	}
	later := now.Add(time.Minute)
	p, _ = SealProbe(credential, []byte{1}, later, bytes.NewReader(seq(201, 8)))
	_, m, _ = OpenProbe(p, index)
	if !other.Allow(credential.KID, m.Nonce, later) {
		t.Fatal("the probe budget did not refill after a minute")
	}
	// Another credential has its own budget.
	second := credential
	second.KID[0] ^= 0x55
	if !other.Allow(second.KID, m.Nonce, later) {
		t.Fatal("budgets must be per credential")
	}
	if _, err := OpenProbeWithCredential(probe, second); err == nil {
		t.Fatal("a probe opened under another credential")
	}
}

func FuzzFrameParser(f *testing.F) {
	v := newVectorSet(f)
	f.Add(v.frame0)
	f.Add(v.frame5)
	f.Add([]byte{})
	f.Add([]byte{0x7e})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > MaxFrameSize {
			return
		}
		receiver, err := NewSessionCipher(0x7e, v.keys.ServerToClient, v.keys.ClientToServer)
		if err != nil {
			t.Fatal(err)
		}
		plain, _, err := receiver.Open(wire)
		if err == nil && !bytes.Equal(wire, v.frame0) && !bytes.Equal(wire, v.frame5) {
			t.Fatalf("a frame the fuzzer made up authenticated: %x -> %x", wire, plain)
		}
		if len(plain) > len(wire) {
			t.Fatalf("plaintext longer than the frame")
		}
	})
}

func FuzzSessionInit(f *testing.F) {
	v := newVectorSet(f)
	f.Add(v.init)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{1}, SessionInitSize))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > MaxHandshakeSize {
			return
		}
		_, init, err := OpenSessionInit(wire, v.index, time.Unix(int64(vectorTimestamp), 0))
		if err == nil && !bytes.Equal(wire, v.init) {
			t.Fatalf("an INIT the fuzzer made up authenticated: %x -> %+v", wire, init)
		}
	})
}

func FuzzSessionAccept(f *testing.F) {
	v := newVectorSet(f)
	f.Add(v.accept)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, SessionAcceptHeadSize+1+chacha20poly1305.Overhead))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > MaxHandshakeSize {
			return
		}
		accepted, _, err := v.clientHandshake.OpenAccept(wire)
		if err == nil && !bytes.Equal(wire, v.accept) {
			t.Fatalf("an ACCEPT the fuzzer made up authenticated: %x -> %+v", wire, accepted)
		}
	})
}

func FuzzProbe(f *testing.F) {
	credential := vectorCredential()
	seed, _ := SealProbe(credential, []byte("payload"), time.Unix(1_700_000_000, 0), bytes.NewReader(seq(1, 8)))
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > MaxHandshakeSize*4 {
			return
		}
		probe, err := OpenProbeWithCredential(wire, credential)
		if err == nil && !bytes.Equal(wire, seed) {
			t.Fatalf("a probe the fuzzer made up authenticated: %x -> %+v", wire, probe)
		}
	})
}

func TestParseCredentialAcceptsHexAndBase64URLKeys(t *testing.T) {
	const kid = "0001020304050607"
	hexKey := hex.EncodeToString(seq(0, 32))
	want := vectorCredential()
	for name, text := range map[string]string{
		"hex":          kid + "." + hexKey,
		"hex upper":    "0001020304050607." + strings.ToUpper(hexKey),
		"base64url":    kid + "." + base64.RawURLEncoding.EncodeToString(seq(0, 32)),
		"padded space": "  " + kid + "." + hexKey + "\n",
	} {
		got, err := ParseCredential(text)
		if err != nil || got.KID != want.KID || got.Key != want.Key || got.ID != want.ID {
			t.Errorf("%s: got %+v err=%v", name, got, err)
		}
	}
	// A key with the url-safe alphabet's two special characters round-trips.
	special := bytes.Repeat([]byte{0xfb, 0xff, 0xbe}, 11)[:32]
	got, err := ParseCredential(kid + "." + base64.RawURLEncoding.EncodeToString(special))
	if err != nil || !bytes.Equal(got.Key[:], special) {
		t.Errorf("base64url key with '-' and '_' not parsed: %v", err)
	}
	for name, text := range map[string]string{
		"empty": "", "no key": kid + ".", "no kid": "." + hexKey, "short hex": kid + "." + hexKey[:62],
		"padded base64": kid + "." + base64.URLEncoding.EncodeToString(seq(0, 32)),
		"std base64":    kid + "." + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, 16)),
		"three parts":   kid + "." + hexKey + ".x", "bad hex": kid + "." + strings.Repeat("g", 64),
		"short kid": "0001." + hexKey, "trailing bits": kid + "." + base64.RawURLEncoding.EncodeToString(seq(0, 32))[:42] + "B",
	} {
		if _, err := ParseCredential(text); err == nil {
			t.Errorf("%s: %q was accepted", name, text)
		}
	}
}
