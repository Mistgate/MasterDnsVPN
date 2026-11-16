package udpserver

import (
	"net/netip"
	"sync"
	"time"
)

const (
	answerCacheSize = 16
	answerCacheTTL  = 10 * time.Second
	// A resolver that lost our answer asks again with the same query; a query
	// that came back with TC=1 is repeated over TCP. Both carry the frame
	// counter of the first copy, which the replay window has already used, so
	// the sealed answer is kept for a few seconds and handed out again.
	maxUDPAnswerRepeats = 2
	maxTCPAnswerRepeats = 4
)

// answerCache keeps the last sealed answers of a session by the counter of the
// frame that asked for them.
//
// Repeats over UDP are served only to the source address that sent the first
// copy: a query copied by an on-path observer and sent from a victim's address
// gets the usual empty answer, so a captured query cannot be used to reflect
// data at a third party. Repeats over TCP need no such check, a TCP source
// cannot be spoofed.
type answerCache struct {
	mu      sync.Mutex
	entries [answerCacheSize]answerEntry
	next    int
}

type answerEntry struct {
	valid     bool
	counter   uint32
	frame     []byte
	at        time.Time
	source    netip.Addr
	udpServed int
	tcpServed int
}

func (c *answerCache) put(counter uint32, frame []byte, source netip.Addr, now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[c.next] = answerEntry{valid: true, counter: counter, frame: frame, at: now, source: source.Unmap()}
	c.next = (c.next + 1) % answerCacheSize
}

// get returns the sealed answer kept for counter, if the repeat is allowed.
func (c *answerCache) get(counter uint32, source netip.Addr, tcp bool, now time.Time) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.entries {
		entry := &c.entries[i]
		if !entry.valid || entry.counter != counter {
			continue
		}
		if now.Sub(entry.at) > answerCacheTTL {
			entry.valid = false
			entry.frame = nil
			return nil, false
		}
		if tcp {
			if entry.tcpServed >= maxTCPAnswerRepeats {
				return nil, false
			}
			entry.tcpServed++
			return entry.frame, true
		}
		if entry.udpServed >= maxUDPAnswerRepeats || !source.IsValid() || source.Unmap() != entry.source {
			return nil, false
		}
		entry.udpServed++
		return entry.frame, true
	}
	return nil, false
}
