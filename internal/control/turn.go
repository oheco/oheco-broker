package control

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v4"
)

// TURNConfig configures the standalone UDP TURN/STUN service. TCP/TLS relays are
// intentionally not enabled. PublicIP is a literal advertised relay IP; it need
// not be assigned locally (e.g. a server behind a static public NAT).
// Zero limits select bounded defaults, except byte rates, where zero is unlimited.
// RelayMinPort and RelayMaxPort must either both be zero (ephemeral) or define an
// inclusive range. AllowLoopbackPeers is only for isolated local tests.
type TURNConfig struct {
	Enabled                    bool          `json:"enabled"`
	ListenAddr                 string        `json:"listen_addr"`
	PublicIP                   string        `json:"public_ip"`
	Realm                      string        `json:"realm"`
	RelayMinPort               uint16        `json:"relay_min_port"`
	RelayMaxPort               uint16        `json:"relay_max_port"`
	AllowLoopbackPeers         bool          `json:"allow_loopback_peers"`
	MaxAllocations             int           `json:"max_allocations"`
	MaxAllocationsPerTenant    int           `json:"max_allocations_per_tenant"`
	MaxCredentials             int           `json:"max_credentials"`
	MaxCredentialsPerTenant    int           `json:"max_credentials_per_tenant"`
	MaxPeersPerAllocation      int           `json:"max_peers_per_allocation"`
	MaxChannelsPerAllocation   int           `json:"max_channels_per_allocation"`
	SocketBufferBytes          int           `json:"socket_buffer_bytes"`
	MaxBytesPerSecond          int64         `json:"max_bytes_per_second"`
	MaxBytesPerSecondPerTenant int64         `json:"max_bytes_per_second_per_tenant"`
	MaxCredentialTTL           time.Duration `json:"max_credential_ttl"`
}

// TURNCredentials are temporary, independently minted per-side credentials. The
// opaque username refers to immutable tenant/broker/session ownership server-side.
type TURNCredentials struct {
	URLs      []string  `json:"urls"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
}

type turnCredential struct {
	tenant, broker, session, username string
	key                               []byte
	expires                           time.Time
	gate                              sync.RWMutex // linearizes successful forwarding with revocation
	revoked                           bool
	timer                             *time.Timer
}

type turnTenant struct {
	credentials, allocations int
	window                   int64
	bytes                    int64
}

type turnManager struct {
	cfg       TURNConfig
	publicIP  net.IP
	bindIP    net.IP
	server    *turn.Server
	listener  *turnListener
	authorize func(tenant, broker, session string) bool
	usage     func(tenant, broker, session string, n int64)
	mu        sync.Mutex
	cond      *sync.Cond
	closed    bool
	creds     map[string]*turnCredential
	tenants   map[string]*turnTenant
	relays    map[string]*turnRelay // advertised relay address -> the actual socket
	clients   map[string]*turnRelay // client address -> allocation (one UDP listener)
	opening   int
	window    int64
	bytes     int64
	closeOnce sync.Once
	closeErr  error
}

var errTURNUnavailable = errors.New("TURN credential or allocation is unavailable")

func normalizeTURNConfig(cfg TURNConfig) (TURNConfig, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:3478"
	}
	if cfg.Realm == "" {
		cfg.Realm = "oheco-broker"
	}
	defaults := []struct {
		p *int
		n int
	}{
		{&cfg.MaxAllocations, 512}, {&cfg.MaxAllocationsPerTenant, 64},
		{&cfg.MaxCredentials, 4096}, {&cfg.MaxCredentialsPerTenant, 256},
		{&cfg.MaxPeersPerAllocation, 32}, {&cfg.MaxChannelsPerAllocation, 64},
		{&cfg.SocketBufferBytes, 64 * 1024},
	}
	for _, d := range defaults {
		if *d.p < 0 {
			return cfg, errors.New("TURN limits cannot be negative")
		}
		if *d.p == 0 {
			*d.p = d.n
		}
	}
	if cfg.MaxCredentialTTL == 0 {
		cfg.MaxCredentialTTL = time.Hour
	}
	if cfg.MaxCredentialTTL < 0 || cfg.MaxBytesPerSecond < 0 || cfg.MaxBytesPerSecondPerTenant < 0 {
		return cfg, errors.New("TURN TTL and rate limits cannot be negative")
	}
	if cfg.SocketBufferBytes > 4*1024*1024 {
		return cfg, errors.New("TURN socket buffer limit exceeds 4 MiB")
	}
	if (cfg.RelayMinPort == 0) != (cfg.RelayMaxPort == 0) || cfg.RelayMinPort > cfg.RelayMaxPort {
		return cfg, errors.New("invalid TURN relay port range")
	}
	return cfg, nil
}

func startTURN(cfg TURNConfig, authorize func(tenant, broker, session string) bool, usage func(tenant, broker, session string, n int64)) (*turnManager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if authorize == nil {
		return nil, errors.New("TURN requires an authorization callback")
	}
	var err error
	cfg, err = normalizeTURNConfig(cfg)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp4", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("TURN listen address: %w", err)
	}
	publicIP := net.ParseIP(cfg.PublicIP).To4()
	if cfg.PublicIP == "" {
		publicIP = addr.IP.To4()
	}
	if publicIP == nil || publicIP.IsUnspecified() || publicIP.IsMulticast() || publicIP.Equal(net.IPv4bcast) {
		return nil, errors.New("TURN requires a unicast IPv4 PublicIP (or a concrete IPv4 listen address)")
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	if err = tuneTURNSocket(conn, cfg.SocketBufferBytes); err != nil {
		conn.Close()
		return nil, err
	}
	m := &turnManager{cfg: cfg, publicIP: publicIP, bindIP: addr.IP, authorize: authorize, usage: usage,
		creds: make(map[string]*turnCredential), tenants: make(map[string]*turnTenant),
		relays: make(map[string]*turnRelay), clients: make(map[string]*turnRelay)}
	m.cond = sync.NewCond(&m.mu)
	m.listener = &turnListener{UDPConn: conn, manager: m, paused: make(chan struct{}), drained: make(chan struct{})}
	logger := logging.NewDefaultLoggerFactory()
	logger.DefaultLogLevel = logging.LogLevelError
	m.server, err = turn.NewServer(turn.ServerConfig{
		Realm: cfg.Realm, AuthHandler: m.auth, QuotaHandler: m.quota, LoggerFactory: logger,
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: m.listener, RelayAddressGenerator: m, PermissionHandler: m.permission}},
		EventHandler: turn.EventHandler{
			OnAllocationCreated: m.allocationCreated,
			OnAllocationDeleted: m.allocationDeleted,
			OnPermissionCreated: m.permissionCreated,
			OnPermissionDeleted: m.permissionDeleted,
			OnChannelCreated:    m.channelCreated,
			OnChannelDeleted:    m.channelDeleted,
		},
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return m, nil
}

func tuneTURNSocket(c *net.UDPConn, n int) error {
	if err := c.SetReadBuffer(n); err != nil {
		return err
	}
	return c.SetWriteBuffer(n)
}

func (m *turnManager) addr() string {
	if m == nil {
		return ""
	}
	return m.listener.LocalAddr().String()
}

func (m *turnManager) mint(tenant, broker, session string, expires time.Time) (TURNCredentials, error) {
	if m == nil || tenant == "" || broker == "" || session == "" {
		return TURNCredentials{}, errTURNUnavailable
	}
	now := time.Now()
	if !expires.After(now) || expires.Sub(now) > m.cfg.MaxCredentialTTL {
		return TURNCredentials{}, errors.New("invalid TURN credential expiry")
	}
	if !m.authorize(tenant, broker, session) {
		return TURNCredentials{}, errTURNUnavailable
	}
	var secret [48]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return TURNCredentials{}, err
	}
	username := base64.RawURLEncoding.EncodeToString(secret[:16])
	password := base64.RawURLEncoding.EncodeToString(secret[16:])
	c := &turnCredential{tenant: tenant, broker: broker, session: session, username: username,
		key: turn.GenerateAuthKey(username, m.cfg.Realm, password), expires: expires}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || !expires.After(time.Now()) {
		return TURNCredentials{}, errTURNUnavailable
	}
	t := m.tenants[tenant]
	if len(m.creds) >= m.cfg.MaxCredentials || (t != nil && t.credentials >= m.cfg.MaxCredentialsPerTenant) {
		return TURNCredentials{}, errors.New("TURN credential quota reached")
	}
	if t == nil {
		t = &turnTenant{}
		m.tenants[tenant] = t
	}
	t.credentials++
	m.creds[username] = c
	c.timer = time.AfterFunc(time.Until(expires), func() { m.expireCredential(c) })
	port := m.listener.LocalAddr().(*net.UDPAddr).Port
	return TURNCredentials{URLs: []string{"turn:" + net.JoinHostPort(m.publicIP.String(), strconv.Itoa(port)) + "?transport=udp"},
		Username: username, Password: password, ExpiresAt: expires}, nil
}

func (m *turnManager) credential(username string) *turnCredential {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	return m.creds[username]
}

// Callbacks run outside the manager map lock. authorize and usage may perform
// database work, but must not synchronously reenter the TURN manager.
func (m *turnManager) authorized(c *turnCredential) bool {
	// Authorization may involve a database call; do not let a slow callback
	// extend the credential lifetime while the expiry timer waits for gate.
	return c != nil && !c.revoked && time.Now().Before(c.expires) &&
		m.authorize(c.tenant, c.broker, c.session) && time.Now().Before(c.expires)
}

func (m *turnManager) auth(username, realm string, _ net.Addr) ([]byte, bool) {
	if realm != m.cfg.Realm {
		return nil, false
	}
	c := m.credential(username)
	if c == nil {
		return nil, false
	}
	c.gate.RLock()
	defer c.gate.RUnlock()
	if !m.authorized(c) {
		return nil, false
	}
	return c.key, true
}

func (m *turnManager) quota(username, _ string, src net.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.creds[username]
	if m.closed || c == nil || m.clients[src.String()] != nil {
		return false
	}
	t := m.tenants[c.tenant]
	return max(len(m.relays), len(m.clients))+m.opening < m.cfg.MaxAllocations && t != nil && t.allocations < m.cfg.MaxAllocationsPerTenant
}

// Validate and Allocate* implement Pion's RelayAddressGenerator. Ownership is
// deliberately NOT inferred here: this hook has no username argument. It is
// attached only by OnAllocationCreated, using the returned relay-address map.
func (m *turnManager) Validate() error { return nil }
func (m *turnManager) AllocateConn(string, int) (net.Conn, net.Addr, error) {
	return nil, nil, errors.New("TCP TURN relays are disabled")
}
func (m *turnManager) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	if network != "udp4" {
		return nil, nil, errors.New("only IPv4 UDP relays are enabled")
	}
	m.mu.Lock()
	if m.closed || max(len(m.relays), len(m.clients))+m.opening >= m.cfg.MaxAllocations {
		m.mu.Unlock()
		return nil, nil, errTURNUnavailable
	}
	m.opening++
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.opening--; m.cond.Broadcast(); m.mu.Unlock() }()
	lo, hi := int(m.cfg.RelayMinPort), int(m.cfg.RelayMaxPort)
	if requestedPort != 0 {
		if requestedPort < 1 || requestedPort > 65535 || (lo != 0 && (requestedPort < lo || requestedPort > hi)) {
			return nil, nil, errors.New("requested relay port outside configured range")
		}
		lo, hi = requestedPort, requestedPort
	}
	var conn *net.UDPConn
	var err error
	// Randomize the first port, then try each port once. No unbounded retries.
	start := lo
	if hi > lo {
		var b [2]byte
		if _, err = rand.Read(b[:]); err != nil {
			return nil, nil, err
		}
		start += int(binary.BigEndian.Uint16(b[:])) % (hi - lo + 1)
	}
	for i := 0; i <= hi-lo; i++ {
		p := lo
		if hi > lo {
			p = lo + (start-lo+i)%(hi-lo+1)
		}
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: m.bindIP, Port: p})
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if err = tuneTURNSocket(conn, m.cfg.SocketBufferBytes); err != nil {
		conn.Close()
		return nil, nil, err
	}
	advertised := &net.UDPAddr{IP: m.publicIP, Port: conn.LocalAddr().(*net.UDPAddr).Port}
	r := &turnRelay{UDPConn: conn, manager: m, advertised: advertised.String(), peers: make(map[string]bool), channels: make(map[uint16]bool)}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		conn.Close()
		return nil, nil, errTURNUnavailable
	}
	m.relays[r.advertised] = r
	m.mu.Unlock()
	return r, advertised, nil
}

func (m *turnManager) allocationCreated(src, _ net.Addr, _, username, _ string, addr net.Addr, _ int) {
	m.mu.Lock()
	r, c := m.relays[addr.String()], m.creds[username]
	if r == nil {
		m.mu.Unlock()
		return
	}
	r.credential = c
	r.client = src.String()
	m.clients[r.client] = r
	bad := m.closed || c == nil
	if c != nil {
		t := m.tenants[c.tenant]
		if t == nil {
			bad = true
		} else {
			t.allocations++
			bad = bad || t.allocations > m.cfg.MaxAllocationsPerTenant
		}
	}
	m.mu.Unlock()
	if bad {
		r.Close()
	}
}

func (m *turnManager) allocationDeleted(src, _ net.Addr, _, username, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.clients[src.String()]
	if r != nil && r.credential != nil && r.credential.username != username {
		return
	}
	if r != nil {
		delete(m.clients, src.String())
		if c := r.credential; c != nil {
			if t := m.tenants[c.tenant]; t != nil {
				t.allocations--
				m.cleanTenant(c.tenant, t)
			}
		}
	}
	m.cond.Broadcast()
}

func (m *turnManager) cleanTenant(id string, t *turnTenant) {
	if t.credentials == 0 && t.allocations == 0 {
		delete(m.tenants, id)
	}
}

func (m *turnManager) allowedPeer(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return m.cfg.AllowLoopbackPeers
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func (m *turnManager) permission(client net.Addr, ip net.IP) bool {
	if !m.allowedPeer(ip) {
		return false
	}
	m.mu.Lock()
	r := m.clients[client.String()]
	ok := !m.closed && r != nil && !r.closing.Load() && (r.peers[ip.String()] || len(r.peers) < m.cfg.MaxPeersPerAllocation)
	var c *turnCredential
	if r != nil {
		c = r.credential
	}
	m.mu.Unlock()
	if !ok || c == nil {
		return false
	}
	c.gate.RLock()
	defer c.gate.RUnlock()
	return m.authorized(c)
}
func (m *turnManager) permissionCreated(_, _ net.Addr, _, _, _ string, relay net.Addr, ip net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.relays[relay.String()]; r != nil {
		r.peers[ip.String()] = true
	}
}
func (m *turnManager) permissionDeleted(_, _ net.Addr, _, _, _ string, relay net.Addr, ip net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.relays[relay.String()]; r != nil {
		delete(r.peers, ip.String())
	}
}
func (m *turnManager) channelCreated(_, _ net.Addr, _, _, _ string, relay, _ net.Addr, channel uint16) {
	m.mu.Lock()
	r := m.relays[relay.String()]
	bad := false
	if r != nil {
		r.channels[channel] = true
		bad = len(r.channels) > m.cfg.MaxChannelsPerAllocation
	}
	m.mu.Unlock()
	if bad && r.closing.CompareAndSwap(false, true) {
		// Pion invokes this callback while holding its channel-binding lock.
		// Closing can wait for an incoming datagram which needs that same lock;
		// defer the drain until after the callback returns (once per allocation).
		go r.Close()
	}
}
func (m *turnManager) channelDeleted(_, _ net.Addr, _, _, _ string, relay, _ net.Addr, channel uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.relays[relay.String()]; r != nil {
		delete(r.channels, channel)
	}
}

// Rate limits count the combined payload in both directions. A saturated bucket
// drops immediately; no userspace byte queue is created. Kernel UDP buffers and
// Pion's fixed-size packet buffers are bounded separately.
func (m *turnManager) reserveBytes(c *turnCredential, n int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	t := m.tenants[c.tenant]
	if t == nil {
		return false
	}
	window := time.Now().Unix()
	if m.window != window {
		m.window, m.bytes = window, 0
	}
	if t.window != window {
		t.window, t.bytes = window, 0
	}
	bytes := int64(n)
	if (m.cfg.MaxBytesPerSecond > 0 && bytes > m.cfg.MaxBytesPerSecond-m.bytes) ||
		(m.cfg.MaxBytesPerSecondPerTenant > 0 && bytes > m.cfg.MaxBytesPerSecondPerTenant-t.bytes) {
		return false
	}
	// Failed network writes conservatively consume rate capacity, not usage.
	if m.cfg.MaxBytesPerSecond > 0 {
		m.bytes += bytes
	}
	if m.cfg.MaxBytesPerSecondPerTenant > 0 {
		t.bytes += bytes
	}
	return true
}

// renewSession extends existing temporary credentials without replacing their
// username/password or allocation. The caller invokes it after committing an
// approved session heartbeat. Empty/invalid, expired, revoked, unauthorized, or
// no-longer-managed credentials are never extended or recreated. No database
// callback runs under the manager lock, and each heartbeat is capped by the TTL.
func (m *turnManager) renewSession(session string, expires time.Time) {
	if m == nil || session == "" || !expires.After(time.Now()) {
		return
	}
	m.mu.Lock()
	var creds []*turnCredential
	if !m.closed {
		for _, c := range m.creds {
			if c.session == session {
				creds = append(creds, c)
			}
		}
	}
	m.mu.Unlock()
	for _, c := range creds {
		c.gate.Lock()
		if !m.authorized(c) {
			c.gate.Unlock()
			continue
		}
		m.mu.Lock()
		now := time.Now()
		deadline := expires
		if limit := now.Add(m.cfg.MaxCredentialTTL); deadline.After(limit) {
			deadline = limit
		}
		// Recheck expiry after acquiring the map lock too: even a delayed
		// heartbeat must not resurrect an already expired bearer.
		if !m.closed && m.creds[c.username] == c && now.Before(c.expires) && deadline.After(c.expires) {
			c.expires = deadline
			c.timer.Reset(time.Until(deadline))
		}
		m.mu.Unlock()
		c.gate.Unlock()
	}
}

// A Reset of an AfterFunc timer can leave its previous callback running. Check
// the CURRENT deadline while holding gate, rather than unconditionally revoke:
// a stale callback waiting behind a renewal must not kill the renewed lease.
func (m *turnManager) expireCredential(c *turnCredential) {
	c.gate.Lock()
	if c.revoked || time.Now().Before(c.expires) {
		c.gate.Unlock()
		return
	}
	c.revoked = true
	c.gate.Unlock()
	m.removeCredential(c)
}

func (m *turnManager) revokeCredential(c *turnCredential) {
	c.gate.Lock()
	c.revoked = true
	c.gate.Unlock()
	m.removeCredential(c)
}

func (m *turnManager) removeCredential(c *turnCredential) {
	m.mu.Lock()
	if m.creds[c.username] == c {
		delete(m.creds, c.username)
		c.timer.Stop()
		if t := m.tenants[c.tenant]; t != nil {
			t.credentials--
			m.cleanTenant(c.tenant, t)
		}
	}
	var relays []*turnRelay
	for _, r := range m.relays {
		if r.credential == c {
			relays = append(relays, r)
		}
	}
	m.mu.Unlock()
	for _, r := range relays {
		r.Close()
	}
}
func (m *turnManager) revoke(match func(*turnCredential) bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	var creds []*turnCredential
	for _, c := range m.creds {
		if match(c) {
			creds = append(creds, c)
		}
	}
	m.mu.Unlock()
	for _, c := range creds {
		m.revokeCredential(c)
	}
}
func (m *turnManager) revokeTenant(id string) {
	m.revoke(func(c *turnCredential) bool { return c.tenant == id })
}
func (m *turnManager) revokeBroker(id string) {
	m.revoke(func(c *turnCredential) bool { return c.broker == id })
}
func (m *turnManager) revokeSession(id string) {
	m.revoke(func(c *turnCredential) bool { return c.session == id })
}

func (m *turnManager) close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.mu.Unlock()
		// First park Pion's request reader BETWEEN requests. Drain relays before
		// letting its manager.Close run, avoiding concurrent Pion Allocation.Close.
		m.listener.quiesce()
		m.revoke(func(*turnCredential) bool { return true })
		m.mu.Lock()
		var relays []*turnRelay
		for _, r := range m.relays {
			relays = append(relays, r)
		}
		m.mu.Unlock()
		for _, r := range relays {
			r.Close()
		}
		m.mu.Lock()
		for len(m.clients) != 0 || m.opening != 0 {
			m.cond.Wait()
		}
		m.mu.Unlock()
		m.closeErr = m.server.Close()
	})
	return m.closeErr
}

type turnRelay struct {
	*net.UDPConn
	manager    *turnManager
	advertised string
	// The following fields are protected by manager.mu.
	credential *turnCredential
	client     string
	peers      map[string]bool
	channels   map[uint16]bool
	closeOnce  sync.Once
	incoming   sync.Mutex // pins the client->relay map while Pion handles one incoming datagram
	pending    atomic.Bool
	closing    atomic.Bool
}

func (r *turnRelay) finishIncoming() {
	if r.pending.CompareAndSwap(true, false) {
		r.incoming.Unlock()
	}
}

func (r *turnRelay) owner() *turnCredential {
	r.manager.mu.Lock()
	defer r.manager.mu.Unlock()
	return r.credential
}
func (r *turnRelay) ReadFrom(p []byte) (int, net.Addr, error) {
	// A packet Pion discarded (no permission) has no listener WriteTo. The
	// next read releases its pin before waiting for another datagram.
	r.finishIncoming()
	for {
		n, addr, err := r.UDPConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		udp, ok := addr.(*net.UDPAddr)
		if !ok || !r.manager.allowedPeer(udp.IP) {
			continue
		}
		c := r.owner()
		if c == nil {
			continue
		}
		c.gate.RLock()
		ok = r.manager.authorized(c)
		c.gate.RUnlock()
		if !ok {
			r.Close()
			return 0, nil, errTURNUnavailable
		}
		// Pin the mapping until the client write (or next read). Deletion waits
		// for this pin and quota rejects reuse of that client tuple meanwhile;
		// an old in-flight datagram cannot be billed to a replacement allocation.
		r.incoming.Lock()
		if r.closing.Load() {
			r.incoming.Unlock()
			return 0, nil, net.ErrClosed
		}
		r.pending.Store(true)
		// Do not charge here: Pion still has to check the permission/channel and
		// successfully write the encapsulated packet to the actual client.
		return n, addr, nil
	}
}
func (r *turnRelay) WriteTo(p []byte, addr net.Addr) (int, error) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || !r.manager.allowedPeer(udp.IP) {
		return 0, errTURNUnavailable
	}
	c := r.owner()
	if c == nil {
		return 0, errTURNUnavailable
	}
	c.gate.RLock()
	if r.closing.Load() || !r.manager.authorized(c) {
		c.gate.RUnlock()
		r.Close()
		return 0, errTURNUnavailable
	}
	if !r.manager.reserveBytes(c, len(p)) {
		c.gate.RUnlock()
		return 0, errTURNUnavailable
	}
	deadline := time.Now().Add(250 * time.Millisecond)
	if c.expires.Before(deadline) {
		deadline = c.expires
	}
	r.UDPConn.SetWriteDeadline(deadline)
	n, err := r.UDPConn.WriteTo(p, addr)
	if n > 0 && r.manager.usage != nil {
		r.manager.usage(c.tenant, c.broker, c.session, int64(n))
	}
	c.gate.RUnlock()
	return n, err
}
func (r *turnRelay) Close() error {
	var err error
	r.closeOnce.Do(func() {
		r.closing.Store(true)
		err = r.UDPConn.Close()
		r.incoming.Lock()
		r.incoming.Unlock()
		r.manager.mu.Lock()
		if r.manager.relays[r.advertised] == r {
			delete(r.manager.relays, r.advertised)
		}
		r.manager.cond.Broadcast()
		r.manager.mu.Unlock()
	})
	return err
}

type turnListener struct {
	*net.UDPConn
	manager              *turnManager
	stopping             atomic.Bool
	paused, drained      chan struct{}
	pauseOnce, closeOnce sync.Once
	writeMu              sync.Mutex // serialize short UDP writes/deadlines; at most one waiter per bounded allocation
}

func (l *turnListener) quiesce() {
	l.stopping.Store(true)
	l.UDPConn.SetReadDeadline(time.Now())
	<-l.paused
}
func (l *turnListener) ReadFrom(p []byte) (int, net.Addr, error) {
	if !l.stopping.Load() {
		n, addr, err := l.UDPConn.ReadFrom(p)
		if !l.stopping.Load() {
			return n, addr, err
		}
	}
	l.pauseOnce.Do(func() { close(l.paused) })
	<-l.drained
	return 0, nil, net.ErrClosed
}
func (l *turnListener) Close() error {
	var err error
	l.closeOnce.Do(func() { err = l.UDPConn.Close(); close(l.drained) })
	return err
}

// forwardedPayload recognizes only server->client ChannelData/Data indications.
// STUN control responses and framing bytes never contribute to relay usage.
func forwardedPayload(p []byte) (int, bool) {
	if len(p) >= 4 && p[0]&0xc0 == 0x40 {
		n := int(binary.BigEndian.Uint16(p[2:4]))
		return n, n <= len(p)-4
	}
	if !stun.IsMessage(p) {
		return 0, false
	}
	msg := &stun.Message{Raw: p}
	if msg.Decode() != nil || msg.Type != stun.NewType(stun.MethodData, stun.ClassIndication) {
		return 0, false
	}
	data, err := msg.Get(stun.AttrData)
	return len(data), err == nil
}
func (l *turnListener) writePacket(p []byte, addr net.Addr, expires time.Time) (int, error) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	deadline := time.Now().Add(250 * time.Millisecond)
	if !expires.IsZero() && expires.Before(deadline) {
		deadline = expires
	}
	if err := l.UDPConn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return l.UDPConn.WriteTo(p, addr)
}
func (l *turnListener) WriteTo(p []byte, addr net.Addr) (int, error) {
	payload, forwarded := forwardedPayload(p)
	if !forwarded {
		return l.writePacket(p, addr, time.Time{})
	}
	l.manager.mu.Lock()
	r := l.manager.clients[addr.String()]
	var c *turnCredential
	if r != nil {
		c = r.credential
	}
	l.manager.mu.Unlock()
	if r != nil {
		defer r.finishIncoming()
	}
	if c == nil {
		return 0, errTURNUnavailable
	}
	c.gate.RLock()
	if r.closing.Load() || !l.manager.authorized(c) {
		c.gate.RUnlock()
		r.finishIncoming()
		r.Close()
		return 0, errTURNUnavailable
	}
	if !l.manager.reserveBytes(c, payload) {
		c.gate.RUnlock()
		return 0, errTURNUnavailable
	}
	// Count only a successful payload write, not a socket read or TURN framing.
	n, err := l.writePacket(p, addr, c.expires)
	if err == nil && n == len(p) && payload > 0 && l.manager.usage != nil {
		l.manager.usage(c.tenant, c.broker, c.session, int64(payload))
	}
	c.gate.RUnlock()
	return n, err
}
