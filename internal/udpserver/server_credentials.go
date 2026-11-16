package udpserver

import (
	"encoding/hex"
	"net/netip"
	"time"

	"masterdnsvpn-go/internal/security"
)

// SessionInfo describes one live session for the embedding application.
type SessionInfo struct {
	ID           uint8
	CredentialID string
	// Resolver is the address of the resolver that last carried a query of the
	// session: the operator's resolver, not the user.
	Resolver   netip.Addr
	Created    time.Time
	LastActive time.Time
	Age        time.Duration
	Streams    int
	// Queries counts the authenticated queries of the session; RxBytes and
	// TxBytes count the DNS messages, in and out.
	Queries uint64
	RxBytes uint64
	TxBytes uint64
}

// SetCredentialIndex atomically replaces the credential set used for new
// handshakes and pre-session MTU probes. Sessions of a credential that is no
// longer in the set, or whose key changed, are closed at once.
func (s *Server) SetCredentialIndex(index security.CredentialIndex) {
	if s == nil || s.credentialIndex == nil {
		return
	}
	s.credentialIndex.Set(index)
	s.closeSessionsNotIn(index)
}

func (s *Server) closeSessionsNotIn(index security.CredentialIndex) {
	for _, record := range s.activeSessionRecords() {
		id := record.credentialID()
		if id == "" {
			continue
		}
		stale := index == nil
		if !stale {
			var kid [security.CredentialIDSize]byte
			if raw, err := hex.DecodeString(id); err != nil || len(raw) != len(kid) {
				stale = true
			} else {
				copy(kid[:], raw)
				credential, ok := index.Lookup(kid)
				record.mu.RLock()
				key := record.credentialKey
				record.mu.RUnlock()
				stale = !ok || !security.ConstantTimeCredentialKeyEqual(credential.Key, key)
			}
		}
		if stale {
			s.closeSessionRecord(record)
			s.dropInitCacheForCredential(id)
		}
	}
}

// CloseCredential closes every session of a credential at once: the next query
// of such a session finds no session and gets no answer with data. It returns
// the number of sessions closed.
func (s *Server) CloseCredential(credentialID string) int {
	if s == nil {
		return 0
	}
	closed := 0
	for _, record := range s.activeSessionRecords() {
		if record.credentialID() == credentialID {
			if s.closeSessionRecord(record) {
				closed++
			}
		}
	}
	s.dropInitCacheForCredential(credentialID)
	return closed
}

// Sessions lists the live sessions.
func (s *Server) Sessions() []SessionInfo {
	if s == nil {
		return nil
	}
	now := time.Now()
	records := s.activeSessionRecords()
	out := make([]SessionInfo, 0, len(records))
	for _, record := range records {
		if record.credentialID() == "" {
			continue
		}
		info := SessionInfo{
			ID:           record.ID,
			CredentialID: record.credentialID(),
			Created:      record.CreatedAt,
			Age:          now.Sub(record.CreatedAt),
			Queries:      record.rxQueries.Load(),
			RxBytes:      record.rxBytes.Load(),
			TxBytes:      record.txBytes.Load(),
		}
		if last := record.lastActivity(); last != 0 {
			info.LastActive = time.Unix(0, last)
		}
		if addr := record.lastSource.Load(); addr != nil {
			info.Resolver = *addr
		}
		record.StreamsMu.RLock()
		info.Streams = len(record.Streams)
		if _, ok := record.Streams[0]; ok {
			info.Streams--
		}
		record.StreamsMu.RUnlock()
		out = append(out, info)
	}
	return out
}

func (s *Server) activeSessionRecords() []*sessionRecord {
	s.sessions.mu.RLock()
	defer s.sessions.mu.RUnlock()
	out := make([]*sessionRecord, 0, s.sessions.activeCount)
	for _, record := range s.sessions.byID {
		if record != nil && !record.isClosed() {
			out = append(out, record)
		}
	}
	return out
}

// closeSessionRecord closes a session and everything it holds.
func (s *Server) closeSessionRecord(record *sessionRecord) bool {
	closed, ok := s.sessions.Close(record.ID, time.Now(), s.cfg.ClosedSessionRetention())
	if !ok || closed != record {
		return false
	}
	s.cleanupClosedSession(record.ID, closed)
	return true
}

// enforceCredentialSessionLimit makes room for one more session of a
// credential: while it holds MaxSessionsPerCredential sessions, the one that
// was idle longest is closed. A reconnecting client therefore never waits for
// its own stale session to time out. An INIT that only repeats a session that
// exists makes no room.
func (s *Server) enforceCredentialSessionLimit(credentialID string, signature []byte) {
	limit := s.cfg.MaxSessionsPerCredential
	if limit < 1 {
		return
	}
	if s.sessions.hasSignature(signature) {
		return
	}
	for {
		var oldest *sessionRecord
		count := 0
		for _, record := range s.activeSessionRecords() {
			if record.credentialID() != credentialID {
				continue
			}
			count++
			if oldest == nil || record.lastActivity() < oldest.lastActivity() {
				oldest = record
			}
		}
		if count < limit || oldest == nil {
			return
		}
		if !s.closeSessionRecord(oldest) {
			return
		}
	}
}

// sessionCredentialID is the credential of a live session, "" when there is none.
func (s *Server) sessionCredentialID(sessionID uint8) string {
	record, ok := s.sessions.Get(sessionID)
	if !ok || record == nil {
		return ""
	}
	return record.credentialID()
}
