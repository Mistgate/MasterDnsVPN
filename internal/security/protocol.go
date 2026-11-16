package security

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	ProtocolVersion       = byte(1)
	CredentialIDSize      = 8
	CredentialKeySize     = 32
	InitHeaderSize        = 1 + CredentialIDSize + 4 + 32
	InitParametersSize    = 9
	SessionInitSize       = InitHeaderSize + InitParametersSize + chacha20poly1305.Overhead
	SessionAcceptHeadSize = 32
	FramePrefixSize       = 1 + 4
	TagSize               = chacha20poly1305.Overhead
	ReplayWindowSize      = 2048
	ProbeKindMTU          = byte(0x50)
	ProbeHeaderSize       = 1 + 1 + CredentialIDSize + chacha20poly1305.NonceSize
	MaxHandshakeSize      = 1024
	MaxFramePlaintextSize = 65535
	MaxFrameSize          = FramePrefixSize + MaxFramePlaintextSize + chacha20poly1305.Overhead

	// MaxFrameCounter is the last counter value a direction may use. The 32-bit
	// counter is the AEAD nonce, so the cipher refuses to seal after it.
	MaxFrameCounter = math.MaxUint32
	// RekeyAfterFrames is where an endpoint should end the session and
	// handshake a new one, long before MaxFrameCounter is reachable.
	RekeyAfterFrames = 1 << 31

	// InitTimestampWindow is the accepted clock difference for INIT and probes.
	InitTimestampWindow = 120 * time.Second
)

var (
	ErrInvalidMessage   = errors.New("invalid protocol message")
	ErrUnknownKid       = errors.New("unknown credential id")
	ErrTimestamp        = errors.New("session init timestamp outside allowed window")
	ErrAuthentication   = errors.New("authentication failed")
	ErrReplay           = errors.New("replayed frame")
	ErrCounterExhausted = errors.New("frame counter exhausted; a new session is required")
)

type Credential struct {
	ID  string
	KID [CredentialIDSize]byte
	Key [CredentialKeySize]byte
}

// ParseCredential parses "<kid>.<key>": the kid is 16 hex characters and the key
// is either 64 hex characters (standalone configs) or 43 base64url characters
// without padding (the form the Mistgate panel issues). The two key forms cannot
// be confused: their lengths differ.
func ParseCredential(value string) (Credential, error) {
	var credential Credential
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 2 || len(parts[0]) != 2*CredentialIDSize {
		return Credential{}, ErrInvalidMessage
	}
	if _, err := hex.Decode(credential.KID[:], []byte(parts[0])); err != nil {
		return Credential{}, ErrInvalidMessage
	}
	switch len(parts[1]) {
	case 2 * CredentialKeySize:
		if _, err := hex.Decode(credential.Key[:], []byte(parts[1])); err != nil {
			return Credential{}, ErrInvalidMessage
		}
	case base64.RawURLEncoding.EncodedLen(CredentialKeySize):
		key, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
		if err != nil || len(key) != CredentialKeySize {
			return Credential{}, ErrInvalidMessage
		}
		copy(credential.Key[:], key)
	default:
		return Credential{}, ErrInvalidMessage
	}
	credential.ID = strings.ToLower(parts[0])
	return credential, nil
}

func LoadCredential(path string) (Credential, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Credential{}, err
	}
	credential, err := ParseCredential(string(contents))
	if err != nil {
		return Credential{}, fmt.Errorf("parse credential file %q: %w", path, err)
	}
	return credential, nil
}

// CredentialIndex resolves an eight-byte device identifier to its credential.
type CredentialIndex interface {
	Lookup(kid [CredentialIDSize]byte) (Credential, bool)
}

type MemoryCredentialIndex struct {
	credentials map[[CredentialIDSize]byte]Credential
}

func NewMemoryCredentialIndex(credentials []Credential) (*MemoryCredentialIndex, error) {
	idx := &MemoryCredentialIndex{credentials: make(map[[CredentialIDSize]byte]Credential, len(credentials))}
	for _, credential := range credentials {
		if credential.ID == "" {
			return nil, fmt.Errorf("credential id is required")
		}
		if _, exists := idx.credentials[credential.KID]; exists {
			return nil, fmt.Errorf("duplicate credential kid")
		}
		idx.credentials[credential.KID] = credential
	}
	return idx, nil
}

func (i *MemoryCredentialIndex) Lookup(kid [CredentialIDSize]byte) (Credential, bool) {
	if i == nil {
		return Credential{}, false
	}
	credential, ok := i.credentials[kid]
	return credential, ok
}

type credentialIndexHolder struct{ index CredentialIndex }

// AtomicCredentialIndex lets an embedding application replace credentials without
// racing packet handlers. Implementations installed with Set must be immutable.
type AtomicCredentialIndex struct {
	current atomic.Pointer[credentialIndexHolder]
}

func NewAtomicCredentialIndex(index CredentialIndex) *AtomicCredentialIndex {
	store := &AtomicCredentialIndex{}
	store.Set(index)
	return store
}

func (s *AtomicCredentialIndex) Set(index CredentialIndex) {
	if s == nil {
		return
	}
	if index == nil {
		s.current.Store(nil)
		return
	}
	s.current.Store(&credentialIndexHolder{index: index})
}

func (s *AtomicCredentialIndex) Lookup(kid [CredentialIDSize]byte) (Credential, bool) {
	if s == nil {
		return Credential{}, false
	}
	holder := s.current.Load()
	if holder == nil || holder.index == nil {
		return Credential{}, false
	}
	return holder.index.Lookup(kid)
}

type SessionInit struct {
	KID        [CredentialIDSize]byte
	Timestamp  uint32
	Ephemeral  [32]byte
	Parameters [InitParametersSize]byte
}

type ClientHandshake struct {
	credential Credential
	private    *ecdh.PrivateKey
	init       []byte
}

func NewClientHandshake(credential Credential, parameters [InitParametersSize]byte, now time.Time, random io.Reader) (*ClientHandshake, []byte, error) {
	if random == nil {
		random = rand.Reader
	}
	private, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return nil, nil, fmt.Errorf("generate X25519 client key: %w", err)
	}
	message, err := BuildSessionInit(credential, parameters, uint32(now.Unix()), private)
	if err != nil {
		return nil, nil, err
	}
	return &ClientHandshake{credential: credential, private: private, init: append([]byte(nil), message...)}, message, nil
}

func BuildSessionInit(credential Credential, parameters [InitParametersSize]byte, timestamp uint32, ephemeral *ecdh.PrivateKey) ([]byte, error) {
	if ephemeral == nil || len(ephemeral.PublicKey().Bytes()) != 32 {
		return nil, ErrInvalidMessage
	}
	aead, err := chacha20poly1305.New(credential.Key[:])
	if err != nil {
		return nil, err
	}
	message := make([]byte, SessionInitSize)
	message[0] = ProtocolVersion
	copy(message[1:1+CredentialIDSize], credential.KID[:])
	binary.BigEndian.PutUint32(message[9:13], timestamp)
	copy(message[13:InitHeaderSize], ephemeral.PublicKey().Bytes())
	nonce := initNonce(message[:InitHeaderSize])
	aead.Seal(message[:InitHeaderSize], nonce[:], parameters[:], message[:InitHeaderSize])
	return message, nil
}

func OpenSessionInit(message []byte, index CredentialIndex, now time.Time) (Credential, SessionInit, error) {
	if len(message) != SessionInitSize || message[0] != ProtocolVersion || index == nil {
		return Credential{}, SessionInit{}, ErrInvalidMessage
	}
	var kid [CredentialIDSize]byte
	copy(kid[:], message[1:9])
	credential, ok := index.Lookup(kid)
	if !ok {
		return Credential{}, SessionInit{}, ErrUnknownKid
	}
	timestamp := binary.BigEndian.Uint32(message[9:13])
	if !timestampInWindow(timestamp, now) {
		return Credential{}, SessionInit{}, ErrTimestamp
	}
	aead, err := chacha20poly1305.New(credential.Key[:])
	if err != nil {
		return Credential{}, SessionInit{}, err
	}
	nonce := initNonce(message[:InitHeaderSize])
	parameters, err := aead.Open(nil, nonce[:], message[InitHeaderSize:], message[:InitHeaderSize])
	if err != nil || len(parameters) != InitParametersSize {
		return Credential{}, SessionInit{}, ErrAuthentication
	}
	var init SessionInit
	init.KID = kid
	init.Timestamp = timestamp
	copy(init.Ephemeral[:], message[13:InitHeaderSize])
	copy(init.Parameters[:], parameters)
	return credential, init, nil
}

func timestampInWindow(timestamp uint32, now time.Time) bool {
	delta := now.Unix() - int64(timestamp)
	window := int64(InitTimestampWindow / time.Second)
	return delta >= -window && delta <= window
}

type SessionAccept struct {
	SessionID uint8
	Policy    []byte
	Ephemeral [32]byte
}

type DirectionalKeys struct {
	ClientToServer [CredentialKeySize]byte
	ServerToClient [CredentialKeySize]byte
}

func (h *ClientHandshake) OpenAccept(message []byte) (SessionAccept, DirectionalKeys, error) {
	if h == nil || h.private == nil || len(message) < SessionAcceptHeadSize+1+chacha20poly1305.Overhead || len(message) > MaxHandshakeSize {
		return SessionAccept{}, DirectionalKeys{}, ErrInvalidMessage
	}
	var serverPublic [32]byte
	copy(serverPublic[:], message[:SessionAcceptHeadSize])
	plain, err := openAcceptPSK(h.credential.Key, h.init, message)
	if err != nil || len(plain) < 1 {
		return SessionAccept{}, DirectionalKeys{}, ErrAuthentication
	}
	peer, err := ecdh.X25519().NewPublicKey(serverPublic[:])
	if err != nil {
		return SessionAccept{}, DirectionalKeys{}, ErrAuthentication
	}
	shared, err := h.private.ECDH(peer)
	if err != nil {
		return SessionAccept{}, DirectionalKeys{}, ErrAuthentication
	}
	keys, err := deriveDirectionalKeys(h.credential.Key, shared, h.init, message)
	if err != nil {
		return SessionAccept{}, DirectionalKeys{}, err
	}
	var accepted SessionAccept
	accepted.Ephemeral = serverPublic
	accepted.SessionID = plain[0]
	accepted.Policy = append([]byte(nil), plain[1:]...)
	return accepted, keys, nil
}

func BuildSessionAccept(credential Credential, initMessage []byte, sessionID uint8, policy []byte, ephemeral *ecdh.PrivateKey) ([]byte, DirectionalKeys, error) {
	if len(initMessage) != SessionInitSize || initMessage[0] != ProtocolVersion || ephemeral == nil || len(policy)+1+SessionAcceptHeadSize+chacha20poly1305.Overhead > MaxHandshakeSize {
		return nil, DirectionalKeys{}, ErrInvalidMessage
	}
	serverPublic := ephemeral.PublicKey().Bytes()
	message := make([]byte, SessionAcceptHeadSize)
	copy(message, serverPublic)
	plain := make([]byte, 1+len(policy))
	plain[0] = sessionID
	copy(plain[1:], policy)
	aead, err := chacha20poly1305.New(credential.Key[:])
	if err != nil {
		return nil, DirectionalKeys{}, err
	}
	nonce := acceptNonce(initMessage, serverPublic)
	message = aead.Seal(message, nonce[:], plain, acceptAAD(initMessage, serverPublic))
	clientPublic, err := ecdh.X25519().NewPublicKey(initMessage[13:InitHeaderSize])
	if err != nil {
		return nil, DirectionalKeys{}, err
	}
	shared, err := ephemeral.ECDH(clientPublic)
	if err != nil {
		return nil, DirectionalKeys{}, ErrAuthentication
	}
	keys, err := deriveDirectionalKeys(credential.Key, shared, initMessage, message)
	if err != nil {
		return nil, DirectionalKeys{}, err
	}
	return message, keys, nil
}

func openAcceptPSK(key [CredentialKeySize]byte, initMessage, message []byte) ([]byte, error) {
	if len(message) < SessionAcceptHeadSize+1+chacha20poly1305.Overhead || len(message) > MaxHandshakeSize || len(initMessage) != SessionInitSize {
		return nil, ErrInvalidMessage
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	public := message[:SessionAcceptHeadSize]
	nonce := acceptNonce(initMessage, public)
	plain, err := aead.Open(nil, nonce[:], message[SessionAcceptHeadSize:], acceptAAD(initMessage, public))
	if err != nil {
		return nil, ErrAuthentication
	}
	return plain, nil
}

// initNonce derives the INIT AEAD nonce from the whole INIT header (version,
// kid, timestamp, client ephemeral key). The ephemeral key is fresh for every
// INIT, so a (PSK, nonce) pair is never used for two different parameter sets.
func initNonce(header []byte) [chacha20poly1305.NonceSize]byte {
	h := sha256.New()
	h.Write([]byte("masterdnsvpn-go/init/v1"))
	h.Write(header)
	sum := h.Sum(nil)
	var nonce [chacha20poly1305.NonceSize]byte
	copy(nonce[:], sum[:len(nonce)])
	return nonce
}

func acceptNonce(initMessage, serverPublic []byte) [chacha20poly1305.NonceSize]byte {
	h := sha256.New()
	h.Write([]byte("masterdnsvpn-go/accept/v1"))
	h.Write(initMessage)
	h.Write(serverPublic)
	sum := h.Sum(nil)
	var nonce [chacha20poly1305.NonceSize]byte
	copy(nonce[:], sum[:len(nonce)])
	return nonce
}

func acceptAAD(initMessage, serverPublic []byte) []byte {
	aad := make([]byte, 0, len(initMessage)+len(serverPublic)+24)
	aad = append(aad, []byte("masterdnsvpn-go/accept-aad/v1")...)
	aad = append(aad, initMessage...)
	aad = append(aad, serverPublic...)
	return aad
}

func deriveDirectionalKeys(psk [CredentialKeySize]byte, shared, initMessage, acceptMessage []byte) (DirectionalKeys, error) {
	ikm := make([]byte, 0, len(psk)+len(shared))
	ikm = append(ikm, psk[:]...)
	ikm = append(ikm, shared...)
	transcript := make([]byte, 0, len(initMessage)+len(acceptMessage))
	transcript = append(transcript, initMessage...)
	transcript = append(transcript, acceptMessage...)
	salt := sha256.Sum256(transcript)
	var keys DirectionalKeys
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt[:], []byte("masterdnsvpn-go v1 client-to-server")), keys.ClientToServer[:]); err != nil {
		return DirectionalKeys{}, err
	}
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt[:], []byte("masterdnsvpn-go v1 server-to-client")), keys.ServerToClient[:]); err != nil {
		return DirectionalKeys{}, err
	}
	return keys, nil
}

type ReplayWindow struct {
	mu      sync.Mutex
	started bool
	highest uint32
	bitmap  [ReplayWindowSize / 64]uint64
}

// Accept reports whether counter is new and within the 2048-frame replay window.
// Serial arithmetic permits the window to move across uint32 wraparound.
func (w *ReplayWindow) Accept(counter uint32) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.started {
		w.started = true
		w.highest = counter
		w.bitmap[0] = 1
		return true
	}
	delta := int32(counter - w.highest)
	if delta > 0 {
		shift := uint32(delta)
		w.shift(shift)
		w.highest = counter
		w.bitmap[0] |= 1
		return true
	}
	behind := uint32(-int64(delta))
	if behind >= ReplayWindowSize {
		return false
	}
	word, bit := behind/64, behind%64
	mask := uint64(1) << bit
	if w.bitmap[word]&mask != 0 {
		return false
	}
	w.bitmap[word] |= mask
	return true
}

func (w *ReplayWindow) shift(amount uint32) {
	if amount >= ReplayWindowSize {
		clear(w.bitmap[:])
		return
	}
	words, bits := amount/64, amount%64
	var shifted [ReplayWindowSize / 64]uint64
	for dst := len(w.bitmap) - 1; dst >= 0; dst-- {
		src := dst - int(words)
		if src < 0 {
			continue
		}
		shifted[dst] |= w.bitmap[src] << bits
		if bits != 0 && src > 0 {
			shifted[dst] |= w.bitmap[src-1] >> (64 - bits)
		}
	}
	w.bitmap = shifted
}

type SessionCipher struct {
	sessionID uint8
	txAEAD    cipherAEAD
	rxAEAD    cipherAEAD
	txMu      sync.Mutex
	txCounter uint64
	rxWindow  ReplayWindow
}

type cipherAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func NewSessionCipher(sessionID uint8, sendKey, receiveKey [CredentialKeySize]byte) (*SessionCipher, error) {
	send, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		return nil, err
	}
	receive, err := chacha20poly1305.New(receiveKey[:])
	if err != nil {
		return nil, err
	}
	return &SessionCipher{sessionID: sessionID, txAEAD: send, rxAEAD: receive}, nil
}

func (c *SessionCipher) Seal(plaintext []byte) ([]byte, error) {
	if c == nil || c.txAEAD == nil || c.txAEAD.NonceSize() != chacha20poly1305.NonceSize || len(plaintext) > MaxFramePlaintextSize {
		return nil, ErrInvalidMessage
	}
	c.txMu.Lock()
	defer c.txMu.Unlock()
	if c.txCounter > MaxFrameCounter {
		return nil, ErrCounterExhausted
	}
	counter := uint32(c.txCounter)
	c.txCounter++
	return sealSessionFrame(c.sessionID, counter, plaintext, c.txAEAD), nil
}

// NeedsRekey reports that this direction has used RekeyAfterFrames counters and
// the session should be replaced by a fresh handshake.
func (c *SessionCipher) NeedsRekey() bool {
	if c == nil {
		return false
	}
	c.txMu.Lock()
	defer c.txMu.Unlock()
	return c.txCounter >= RekeyAfterFrames
}

func sealSessionFrame(sessionID uint8, counter uint32, plaintext []byte, aead cipherAEAD) []byte {
	frame := make([]byte, FramePrefixSize, FramePrefixSize+len(plaintext)+aead.Overhead())
	frame[0] = sessionID
	binary.BigEndian.PutUint32(frame[1:FramePrefixSize], counter)
	nonce := frameNonce(counter)
	aad := frameAAD(frame[:FramePrefixSize])
	return aead.Seal(frame, nonce[:], plaintext, aad[:])
}

// frameAAD authenticates the clear sid and counter together with the protocol
// version, which is implicit in the frame (it is negotiated by INIT).
func frameAAD(prefix []byte) [1 + FramePrefixSize]byte {
	var aad [1 + FramePrefixSize]byte
	aad[0] = ProtocolVersion
	copy(aad[1:], prefix)
	return aad
}

func (c *SessionCipher) Open(frame []byte) ([]byte, uint32, error) {
	if c == nil || c.rxAEAD == nil || len(frame) < FramePrefixSize+c.rxAEAD.Overhead()+1 || len(frame) > MaxFrameSize {
		return nil, 0, ErrInvalidMessage
	}
	if frame[0] != c.sessionID {
		return nil, 0, ErrAuthentication
	}
	counter := binary.BigEndian.Uint32(frame[1:FramePrefixSize])
	nonce := frameNonce(counter)
	aad := frameAAD(frame[:FramePrefixSize])
	plain, err := c.rxAEAD.Open(nil, nonce[:], frame[FramePrefixSize:], aad[:])
	if err != nil {
		return nil, 0, ErrAuthentication
	}
	if !c.rxWindow.Accept(counter) {
		return nil, counter, ErrReplay
	}
	return plain, counter, nil
}

func frameNonce(counter uint32) [chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint32(nonce[len(nonce)-4:], counter)
	return nonce
}

// ConstantTimeCredentialKeyEqual is useful to embedding indexes that perform
// credential checks outside MemoryCredentialIndex.
func ConstantTimeCredentialKeyEqual(a, b [CredentialKeySize]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

type ProbeMessage struct {
	KID     [CredentialIDSize]byte
	Nonce   [chacha20poly1305.NonceSize]byte
	Payload []byte
}

// Timestamp is the sender clock carried in the first four nonce bytes. The
// remaining eight nonce bytes are random.
func (p ProbeMessage) Timestamp() uint32 { return binary.BigEndian.Uint32(p.Nonce[:4]) }

// SealProbe builds a pre-session probe or probe answer:
// ver 1 | kind 1 | kid 8 | nonce 12 (ts 4 + random 8) | AEAD_psk(payload), AAD = header.
func SealProbe(credential Credential, payload []byte, now time.Time, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	if len(payload) > MaxHandshakeSize*4 {
		return nil, ErrInvalidMessage
	}
	aead, err := chacha20poly1305.New(credential.Key[:])
	if err != nil {
		return nil, err
	}
	message := make([]byte, ProbeHeaderSize)
	message[0] = ProtocolVersion
	message[1] = ProbeKindMTU
	copy(message[2:10], credential.KID[:])
	nonce := message[10:ProbeHeaderSize]
	binary.BigEndian.PutUint32(nonce[:4], uint32(now.Unix()))
	if _, err := io.ReadFull(random, nonce[4:]); err != nil {
		return nil, err
	}
	return aead.Seal(message, nonce, payload, message[:ProbeHeaderSize]), nil
}

func OpenProbe(message []byte, index CredentialIndex) (Credential, ProbeMessage, error) {
	if len(message) < ProbeHeaderSize+chacha20poly1305.Overhead || len(message) > MaxHandshakeSize*4 || message[0] != ProtocolVersion || message[1] != ProbeKindMTU || index == nil {
		return Credential{}, ProbeMessage{}, ErrInvalidMessage
	}
	var kid [CredentialIDSize]byte
	copy(kid[:], message[2:10])
	credential, ok := index.Lookup(kid)
	if !ok {
		return Credential{}, ProbeMessage{}, ErrUnknownKid
	}
	probe, err := OpenProbeWithCredential(message, credential)
	if err != nil {
		return Credential{}, ProbeMessage{}, err
	}
	return credential, probe, nil
}

// OpenProbeWithCredential authenticates a probe. It does not look at the clock:
// servers enforce freshness and uniqueness with ProbeLimiter, and clients only
// need the tag to check an answer to a probe they sent.
func OpenProbeWithCredential(message []byte, credential Credential) (ProbeMessage, error) {
	if len(message) < ProbeHeaderSize+chacha20poly1305.Overhead || len(message) > MaxHandshakeSize*4 || message[0] != ProtocolVersion || message[1] != ProbeKindMTU || subtle.ConstantTimeCompare(message[2:10], credential.KID[:]) != 1 {
		return ProbeMessage{}, ErrInvalidMessage
	}
	aead, err := chacha20poly1305.New(credential.Key[:])
	if err != nil {
		return ProbeMessage{}, err
	}
	plain, err := aead.Open(nil, message[10:ProbeHeaderSize], message[ProbeHeaderSize:], message[:ProbeHeaderSize])
	if err != nil {
		return ProbeMessage{}, ErrAuthentication
	}
	var probe ProbeMessage
	copy(probe.KID[:], message[2:10])
	copy(probe.Nonce[:], message[10:ProbeHeaderSize])
	probe.Payload = plain
	return probe, nil
}

const (
	// ProbeBudgetPerMinute is the number of pre-session probes one credential
	// may have answered per minute.
	ProbeBudgetPerMinute = 60
	maxProbeCredentials  = 4096
)

type probeBudget struct {
	windowStart time.Time
	count       int
	// seen holds the nonce of every accepted probe until its timestamp leaves
	// the freshness window, so a captured probe cannot be replayed.
	seen map[[chacha20poly1305.NonceSize]byte]int64
}

// ProbeLimiter admits each authenticated probe at most once, only while its
// timestamp is within InitTimestampWindow, and at most ProbeBudgetPerMinute
// times per minute per credential.
type ProbeLimiter struct {
	mu    sync.Mutex
	byKID map[[CredentialIDSize]byte]*probeBudget
}

func NewProbeLimiter() *ProbeLimiter {
	return &ProbeLimiter{byKID: make(map[[CredentialIDSize]byte]*probeBudget)}
}

func (l *ProbeLimiter) Allow(kid [CredentialIDSize]byte, nonce [chacha20poly1305.NonceSize]byte, now time.Time) bool {
	if l == nil {
		return false
	}
	timestamp := binary.BigEndian.Uint32(nonce[:4])
	if !timestampInWindow(timestamp, now) {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	budget := l.byKID[kid]
	if budget == nil {
		if len(l.byKID) >= maxProbeCredentials {
			return false
		}
		budget = &probeBudget{windowStart: now, seen: make(map[[chacha20poly1305.NonceSize]byte]int64)}
		l.byKID[kid] = budget
	}
	nowUnix := now.Unix()
	for old, expires := range budget.seen {
		if nowUnix > expires {
			delete(budget.seen, old)
		}
	}
	if now.Sub(budget.windowStart) >= time.Minute || now.Before(budget.windowStart) {
		budget.windowStart = now
		budget.count = 0
	}
	if _, replayed := budget.seen[nonce]; replayed || budget.count >= ProbeBudgetPerMinute {
		return false
	}
	budget.seen[nonce] = int64(timestamp) + int64(InitTimestampWindow/time.Second)
	budget.count++
	return true
}
