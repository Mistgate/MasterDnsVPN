package mgdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

// ErrClosed is returned after Close.
var ErrClosed = errors.New("mgdns: client closed")

// DialError is the error of a dial that the server could not complete; Reply is
// the SOCKS5 reply code that says why (2 ruleset, 4 host unreachable, 5
// refused, 6 timed out, ...).
type DialError = client.DialError

// ClientConfig configures a Client; nothing is read from files or flags.
type ClientConfig struct {
	// Domains are the tunnel zones (normally one).
	Domains []string
	// Credential is "<kid>.<key>", see ParseCredential.
	Credential string
	// Resolvers are the resolvers the tunnel queries, as numbers: the client
	// does not resolve names and does not expand subnets. Best first, when the
	// order is known.
	Resolvers []netip.AddrPort
	// Control is called for every socket the client opens to a resolver, before
	// it is bound or connected: bind it to the physical interface, so that it
	// stays outside the host's own tunnel and kill switch.
	Control func(network, address string, c syscall.RawConn) error
	// LoadRanking returns the resolvers that carried the tunnel best last time;
	// they move to the front of Resolvers. SaveRanking receives the new order
	// whenever it changes and when the session ends. Both optional.
	LoadRanking func() []netip.AddrPort
	SaveRanking func(ranked []netip.AddrPort)

	// LivenessTimeout is how long the server may stay silent before the client
	// takes the session for lost and starts a new one (90 s). A server cannot
	// tell a client that its session is gone, silence is how the client learns.
	LivenessTimeout time.Duration
	// IdleTimeout ends the session after this long without an open stream; the
	// next DialContext starts it again (5 minutes; negative: never).
	IdleTimeout time.Duration
	// SessionTimeout bounds how long DialContext waits for a session to come up
	// when its context has no deadline (90 s).
	SessionTimeout time.Duration

	// LogLevel is "debug", "info", "warn" or "error" ("error"); LogWriter
	// receives the log lines (nil: discarded).
	LogLevel  string
	LogWriter io.Writer
}

// Client opens connections through the DNS tunnel. The session is lazy: it
// comes up at the first DialContext or ResolveDNS and ends after IdleTimeout
// without open streams, keeping the resolver ranking for the next time.
type Client struct {
	cfg     ClientConfig
	resolve []config.ResolverAddress

	mu       sync.Mutex
	started  bool
	closed   bool
	parent   context.Context
	cancel   context.CancelFunc
	current  *clientSession
	lastUsed time.Time
	busy     int // DialContext calls that are waiting for or opening a stream
	ready    atomic.Bool
	wg       sync.WaitGroup
}

type clientSession struct {
	inner  *client.Client
	cancel context.CancelFunc
	done   chan struct{}
}

// NewClient validates the configuration. Nothing runs until Start.
func NewClient(cfg ClientConfig) (*Client, error) {
	if len(cfg.Domains) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	if len(cfg.Resolvers) == 0 {
		return nil, errors.New("at least one resolver is required")
	}
	if _, err := security.ParseCredential(cfg.Credential); err != nil {
		return nil, errors.New("the credential is invalid")
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = 90 * time.Second
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "error"
	}
	c := &Client{cfg: cfg}
	for _, resolver := range cfg.Resolvers {
		if !resolver.IsValid() {
			return nil, fmt.Errorf("invalid resolver %v", resolver)
		}
		c.resolve = append(c.resolve, config.ResolverAddress{IP: resolver.Addr().Unmap().String(), Port: int(resolver.Port())})
	}
	if _, err := c.internalConfig(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) internalConfig() (config.ClientConfig, error) {
	internal := config.DefaultClientConfig()
	internal.LibraryMode = true
	internal.ProtocolType = "SOCKS5"
	internal.Domains = append([]string(nil), c.cfg.Domains...)
	internal.DeviceCredential = c.cfg.Credential
	internal.Resolvers = c.orderedResolvers()
	internal.Control = c.cfg.Control
	internal.LocalDNSEnabled = false
	internal.LocalDNSCachePersist = false
	internal.SaveMTUServersToFile = false
	internal.InteractiveStatsEnabled = false
	internal.AutoSaveRankedResolvers = c.cfg.SaveRanking != nil
	if c.cfg.SaveRanking != nil {
		save := c.cfg.SaveRanking
		internal.RankedSave = func(ranked []config.ResolverAddress) {
			addrs := make([]netip.AddrPort, 0, len(ranked))
			for _, resolver := range ranked {
				if addr, err := netip.ParseAddr(resolver.IP); err == nil {
					addrs = append(addrs, netip.AddrPortFrom(addr, uint16(resolver.Port)))
				}
			}
			save(addrs)
		}
	}
	internal.LogLevel = c.cfg.LogLevel
	if c.cfg.LivenessTimeout > 0 {
		internal.LivenessTimeoutSeconds = c.cfg.LivenessTimeout.Seconds()
	}
	// Resolvers reach this server with an EDNS size of 1232 or more: the probes
	// find the largest answer that fits, up to this.
	internal.MaxDownloadMTU = 1000
	return config.FinalizeClientConfig(internal)
}

// orderedResolvers puts the resolvers of the saved ranking first.
func (c *Client) orderedResolvers() []config.ResolverAddress {
	if c.cfg.LoadRanking == nil {
		return append([]config.ResolverAddress(nil), c.resolve...)
	}
	ordered := make([]config.ResolverAddress, 0, len(c.resolve))
	used := make(map[config.ResolverAddress]bool, len(c.resolve))
	configured := make(map[config.ResolverAddress]bool, len(c.resolve))
	for _, resolver := range c.resolve {
		configured[resolver] = true
	}
	for _, ranked := range c.cfg.LoadRanking() {
		resolver := config.ResolverAddress{IP: ranked.Addr().Unmap().String(), Port: int(ranked.Port())}
		if configured[resolver] && !used[resolver] {
			ordered = append(ordered, resolver)
			used[resolver] = true
		}
	}
	for _, resolver := range c.resolve {
		if !used[resolver] {
			ordered = append(ordered, resolver)
		}
	}
	return ordered
}

// Start lets the client work until ctx ends. It does not bring a session up:
// that happens at the first DialContext or ResolveDNS.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if c.started {
		return errors.New("mgdns: client already started")
	}
	c.started = true
	c.parent, c.cancel = context.WithCancel(ctx)
	c.lastUsed = time.Now()
	c.wg.Add(1)
	go c.idleLoop()
	return nil
}

// Ready reports whether a session is up right now. It may be called from any
// goroutine.
func (c *Client) Ready() bool { return c.ready.Load() }

// ActiveStreams is the number of open tunneled connections.
func (c *Client) ActiveStreams() int {
	c.mu.Lock()
	session := c.current
	c.mu.Unlock()
	if session == nil {
		return 0
	}
	return session.inner.ActiveStreams()
}

// DialContext opens a tunneled TCP connection to address ("host:port"). The
// host may be a name; the server resolves it. The session is brought up first
// when there is none.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("mgdns: network %q is not supported, only tcp", network)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("mgdns: invalid port in %q", address)
	}
	release := c.beginUse()
	defer release()
	for attempt := 0; ; attempt++ {
		session, err := c.ensureSession(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := session.inner.OpenStream(ctx, host, uint16(port))
		if errors.Is(err, client.ErrNoSession) && attempt == 0 {
			continue
		}
		return conn, err
	}
}

// ResolveDNS sends a DNS query through the tunnel and returns the answer.
func (c *Client) ResolveDNS(ctx context.Context, query []byte) ([]byte, error) {
	release := c.beginUse()
	defer release()
	session, err := c.ensureSession(ctx)
	if err != nil {
		return nil, err
	}
	return session.inner.ResolveDNS(ctx, query)
}

func (c *Client) beginUse() func() {
	c.mu.Lock()
	c.busy++
	c.lastUsed = time.Now()
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.busy--
		c.lastUsed = time.Now()
		c.mu.Unlock()
	}
}

// ensureSession returns a session that is up, starting one when needed.
func (c *Client) ensureSession(ctx context.Context) (*clientSession, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if !c.started {
		c.mu.Unlock()
		return nil, errors.New("mgdns: client not started")
	}
	if c.current == nil {
		session, err := c.startSessionLocked()
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.current = session
	}
	session := c.current
	c.mu.Unlock()

	waitCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, c.cfg.SessionTimeout)
		defer cancel()
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for !session.inner.SessionReady() {
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("mgdns: no session: %w", waitCtx.Err())
		case <-session.done:
			c.mu.Lock()
			if c.current == session {
				c.current = nil
				c.ready.Store(false)
			}
			c.mu.Unlock()
			return nil, errors.New("mgdns: the session ended")
		case <-ticker.C:
		}
	}
	c.ready.Store(true)
	return session, nil
}

func (c *Client) startSessionLocked() (*clientSession, error) {
	internal, err := c.internalConfig()
	if err != nil {
		return nil, err
	}
	credential, err := security.ParseCredential(c.cfg.Credential)
	if err != nil {
		return nil, err
	}
	inner := client.New(internal, logger.NewWithWriter("mgdns client", c.cfg.LogLevel, c.cfg.LogWriter), credential)
	if err := inner.BuildConnectionMap(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(c.parent)
	session := &clientSession{inner: inner, cancel: cancel, done: make(chan struct{})}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer close(session.done)
		_ = inner.Run(ctx)
	}()
	return session, nil
}

// idleLoop ends a session that has had no open stream for IdleTimeout.
func (c *Client) idleLoop() {
	defer c.wg.Done()
	interval := 5 * time.Second
	if c.cfg.IdleTimeout > 0 && c.cfg.IdleTimeout/4 < interval {
		interval = max(c.cfg.IdleTimeout/4, 10*time.Millisecond)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.parent.Done():
			c.stopSession()
			return
		case <-ticker.C:
		}
		if c.cfg.IdleTimeout < 0 {
			continue
		}
		c.mu.Lock()
		session := c.current
		idle := session != nil && c.busy == 0 && session.inner.ActiveStreams() == 0 && time.Since(c.lastUsed) >= c.cfg.IdleTimeout
		c.mu.Unlock()
		if idle {
			c.stopSession()
		}
	}
}

func (c *Client) stopSession() {
	c.mu.Lock()
	session := c.current
	c.current = nil
	c.ready.Store(false)
	c.mu.Unlock()
	if session == nil {
		return
	}
	session.cancel()
	select {
	case <-session.done:
	case <-time.After(10 * time.Second):
	}
}

// Close ends the session and everything the client runs.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.stopSession()
	c.wg.Wait()
	return nil
}
