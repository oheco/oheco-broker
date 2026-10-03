package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

type turnTestUsage struct {
	mu     sync.Mutex
	bytes  map[string]int64
	owners map[string]int64
}

func (u *turnTestUsage) add(tenant, broker, session string, n int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.bytes[tenant] += n
	if u.owners == nil {
		u.owners = make(map[string]int64)
	}
	u.owners[tenant+"\x00"+broker+"\x00"+session] += n
}
func (u *turnTestUsage) getOwner(tenant, broker, session string) int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.owners[tenant+"\x00"+broker+"\x00"+session]
}
func (u *turnTestUsage) get(tenant string) int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.bytes[tenant]
}

type turnTestBase struct {
	*net.UDPConn
	channels atomic.Int64
}

func (c *turnTestBase) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) >= 4 && p[0]&0xc0 == 0x40 {
		c.channels.Add(1)
	}
	return c.UDPConn.WriteTo(p, addr)
}

type turnTestClient struct {
	client *turn.Client
	base   *turnTestBase
	relay  net.PacketConn
}

func turnTestConfig() TURNConfig {
	return TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true}
}
func turnTestManager(t *testing.T, cfg TURNConfig, auth func(string, string, string) bool, usage func(string, string, string, int64)) *turnManager {
	t.Helper()
	if auth == nil {
		auth = func(string, string, string) bool { return true }
	}
	m, err := startTURN(cfg, auth, usage)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.close(); err != nil {
			t.Errorf("TURN close: %v", err)
		}
	})
	return m
}
func turnTestMint(t *testing.T, m *turnManager, tenant, broker, session string, expires time.Time) TURNCredentials {
	t.Helper()
	c, err := m.mint(tenant, broker, session, expires)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func turnTestNewClient(t *testing.T, m *turnManager, creds TURNCredentials) *turnTestClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	base := &turnTestBase{UDPConn: conn}
	logger := logging.NewDefaultLoggerFactory()
	logger.DefaultLogLevel = logging.LogLevelError
	client, err := turn.NewClient(&turn.ClientConfig{Conn: base, STUNServerAddr: m.addr(), TURNServerAddr: m.addr(),
		Username: creds.Username, Password: creds.Password, Realm: m.cfg.Realm, RTO: 10 * time.Millisecond, LoggerFactory: logger})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err = client.Listen(); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	c := &turnTestClient{client: client, base: base}
	t.Cleanup(func() {
		if c.relay != nil {
			c.relay.Close()
		}
		client.Close()
		conn.Close()
	})
	return c
}
func turnTestAllocate(t *testing.T, c *turnTestClient) {
	t.Helper()
	var err error
	c.relay, err = c.client.Allocate()
	if err != nil {
		t.Fatal(err)
	}
}
func turnTestPeer(t *testing.T) *net.UDPConn {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	return peer
}
func turnTestExchange(c *turnTestClient, peer *net.UDPConn, outgoing, incoming []byte) error {
	if _, err := c.relay.WriteTo(outgoing, peer.LocalAddr()); err != nil {
		return err
	}
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	p := make([]byte, 2048)
	n, addr, err := peer.ReadFrom(p)
	if err != nil {
		return err
	}
	if !bytes.Equal(p[:n], outgoing) {
		return fmt.Errorf("relayed outgoing payload = %q, want %q", p[:n], outgoing)
	}
	if addr.String() != c.relay.LocalAddr().String() {
		return fmt.Errorf("peer source = %s, want actual relay %s", addr, c.relay.LocalAddr())
	}
	if _, err = peer.WriteTo(incoming, addr); err != nil {
		return err
	}
	c.relay.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addr, err = c.relay.ReadFrom(p)
	if err != nil {
		return err
	}
	if !bytes.Equal(p[:n], incoming) || addr.String() != peer.LocalAddr().String() {
		return fmt.Errorf("incoming %q from %s, want %q from %s", p[:n], addr, incoming, peer.LocalAddr())
	}
	return nil
}
func turnTestWait(t *testing.T, condition func() bool) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("TURN condition did not become true")
		}
	}
}
func turnTestDropped(t *testing.T, c *turnTestClient, peer *net.UDPConn) {
	t.Helper()
	// Existing permissions/channels are deliberately used: no new authenticated
	// Allocate/CreatePermission request is needed to try this traffic.
	c.relay.WriteTo([]byte("must not forward"), peer.LocalAddr())
	peer.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	p := make([]byte, 2048)
	if n, _, err := peer.ReadFrom(p); err == nil {
		t.Fatalf("forwarded %d bytes after disable/revoke", n)
	} else {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatal(err)
		}
	}
	peer.WriteTo([]byte("must not return"), c.relay.LocalAddr())
	c.relay.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if n, _, err := c.relay.ReadFrom(p); err == nil {
		t.Fatalf("returned %d bytes after disable/revoke", n)
	}
}

func TestTURNActualRelaySTUNAndTenantAttribution(t *testing.T) {
	u := &turnTestUsage{bytes: make(map[string]int64)}
	m := turnTestManager(t, turnTestConfig(), nil, u.add)
	const count = 6
	clients := make([]*turnTestClient, count)
	peers := make([]*net.UDPConn, count)
	expected := make([]int64, count)
	for i := range clients {
		tenant := fmt.Sprintf("tenant-%d", i/2)
		creds := turnTestMint(t, m, tenant, fmt.Sprintf("broker-%d", i), fmt.Sprintf("session-%d", i), time.Now().Add(time.Minute))
		if len(creds.URLs) != 1 || creds.Username == "" || creds.Password == "" || !creds.ExpiresAt.After(time.Now()) {
			t.Fatalf("bad credentials: %+v", creds)
		}
		clients[i] = turnTestNewClient(t, m, creds)
		mapped, err := clients[i].client.SendBindingRequest()
		if err != nil || mapped.String() != clients[i].base.LocalAddr().String() {
			t.Fatalf("standalone STUN = %v, %v", mapped, err)
		}
		peers[i] = turnTestPeer(t)
	}
	// Allocate concurrently with distinct credentials; a last-auth attribution
	// shortcut fails here (and in the concurrent payload exchange below).
	start := make(chan struct{})
	errs := make(chan error, count)
	for i := range clients {
		go func(i int) {
			<-start
			r, err := clients[i].client.Allocate()
			if err == nil {
				clients[i].relay = r
				err = clients[i].client.CreatePermission(peers[i].LocalAddr())
			}
			errs <- err
		}(i)
	}
	close(start)
	for range clients {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for i := range clients {
		go func(i int) {
			var err error
			for j := 0; j < 24; j++ {
				out := bytes.Repeat([]byte{byte(i + 1)}, 17+i*11+j)
				in := bytes.Repeat([]byte{byte(i + 101)}, 31+i*7+j)
				if err = turnTestExchange(clients[i], peers[i], out, in); err != nil {
					break
				}
				expected[i] += int64(len(out) + len(in))
			}
			errs <- err
		}(i)
	}
	for range clients {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	expectedTenants := make(map[string]int64)
	expectedOwners := make(map[string]int64)
	for i := range clients {
		tenant := fmt.Sprintf("tenant-%d", i/2)
		broker, session := fmt.Sprintf("broker-%d", i), fmt.Sprintf("session-%d", i)
		expectedTenants[tenant] += expected[i]
		expectedOwners[tenant+"\x00"+broker+"\x00"+session] = expected[i]
	}
	// A client can receive its final datagram before the server's successful
	// WriteTo invokes usage. Waiting for one owner is insufficient: its tenant
	// aggregate also contains another allocation whose callback may be pending.
	// Observe every exact total together, never a partially completed snapshot.
	turnTestWait(t, func() bool {
		u.mu.Lock()
		defer u.mu.Unlock()
		if len(u.bytes) != len(expectedTenants) || len(u.owners) != len(expectedOwners) {
			return false
		}
		for tenant, want := range expectedTenants {
			if u.bytes[tenant] != want {
				return false
			}
		}
		for owner, want := range expectedOwners {
			if u.owners[owner] != want {
				return false
			}
		}
		return true
	})
	for i := range clients {
		if clients[i].base.channels.Load() == 0 {
			t.Fatal("Pion client never used ChannelBind/ChannelData")
		}
	}
	m.close() // also exercise draining several active allocations without client cleanup first
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.clients) != 0 || len(m.relays) != 0 || len(m.creds) != 0 || len(m.tenants) != 0 {
		t.Fatal("TURN retained state after close")
	}
}

func TestTURNExistingAllocationDisableRevokeAndExpiry(t *testing.T) {
	for _, mode := range []string{"disable", "tenant", "broker", "session", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			var enabled atomic.Bool
			enabled.Store(true)
			u := &turnTestUsage{bytes: make(map[string]int64)}
			m := turnTestManager(t, turnTestConfig(), func(string, string, string) bool { return enabled.Load() }, u.add)
			expires := time.Now().Add(time.Minute)
			if mode == "expiry" {
				expires = time.Now().Add(400 * time.Millisecond)
			}
			creds := turnTestMint(t, m, "tenant", "broker", "session", expires)
			c := turnTestNewClient(t, m, creds)
			turnTestAllocate(t, c)
			peer := turnTestPeer(t)
			if err := c.client.CreatePermission(peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				if err := turnTestExchange(c, peer, []byte("before"), []byte("return")); err != nil {
					t.Fatal(err)
				}
			}
			turnTestWait(t, func() bool { return u.get("tenant") == 36 })
			switch mode {
			case "disable":
				enabled.Store(false)
			case "tenant":
				m.revokeTenant("tenant")
			case "broker":
				m.revokeBroker("broker")
			case "session":
				m.revokeSession("session")
			case "expiry":
				turnTestWait(t, func() bool { return !time.Now().Before(expires) })
			}
			turnTestDropped(t, c, peer)
			if got := u.get("tenant"); got != 36 {
				t.Fatalf("disabled traffic usage = %d, want 36", got)
			}
			if _, ok := m.auth(creds.Username, m.cfg.Realm, c.base.LocalAddr()); ok {
				t.Fatal("revoked/expired credential authenticated")
			}
			turnTestWait(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return len(m.clients) == 0 && len(m.relays) == 0 })
		})
	}
}

func TestTURNDefaultPeerPolicyAndNoUnpermittedUsage(t *testing.T) {
	u := &turnTestUsage{bytes: make(map[string]int64)}
	cfg := turnTestConfig()
	cfg.AllowLoopbackPeers = false
	m := turnTestManager(t, cfg, nil, u.add)
	creds := turnTestMint(t, m, "tenant", "broker", "session", time.Now().Add(time.Minute))
	c := turnTestNewClient(t, m, creds)
	turnTestAllocate(t, c)
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "fc00::1", "fe80::1"} {
		if m.allowedPeer(net.ParseIP(ip)) {
			t.Fatalf("default peer policy admitted %s", ip)
		}
		peer := &net.UDPAddr{IP: net.ParseIP(ip), Port: 12345}
		if peer.IP.To4() != nil {
			if err := c.client.CreatePermission(peer); err == nil {
				t.Fatalf("CreatePermission admitted %s", ip)
			}
		}
	}
	if !m.allowedPeer(net.ParseIP("8.8.8.8")) {
		t.Fatal("public unicast denied")
	}
	peer := turnTestPeer(t)
	if err := c.client.CreatePermission(peer.LocalAddr()); err == nil {
		t.Fatal("loopback permission admitted by default")
	}
	// Unpermitted inbound UDP arriving on a relay is received but NOT forwarded
	// or billed. This catches accounting raw socket reads rather than payloads.
	peer.WriteTo([]byte("unpermitted"), c.relay.LocalAddr())
	c.relay.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if n, _, err := c.relay.ReadFrom(make([]byte, 1024)); err == nil {
		t.Fatalf("unpermitted incoming %d bytes", n)
	}
	if u.get("tenant") != 0 {
		t.Fatal("control or unpermitted packets counted as usage")
	}
}

func TestTURNLimitsAndCredentialIsolation(t *testing.T) {
	cfg := turnTestConfig()
	cfg.MaxAllocations = 2
	cfg.MaxAllocationsPerTenant = 1
	cfg.MaxCredentials = 3
	cfg.MaxCredentialsPerTenant = 2
	m := turnTestManager(t, cfg, nil, nil)
	a := turnTestMint(t, m, "a", "b1", "s1", time.Now().Add(time.Minute))
	a2 := turnTestMint(t, m, "a", "b2", "s2", time.Now().Add(time.Minute))
	b := turnTestMint(t, m, "b", "b3", "s3", time.Now().Add(time.Minute))
	if a.Username == a2.Username || a.Password == a2.Password {
		t.Fatal("per-side credentials reused")
	}
	if _, err := m.mint("a", "b", "s", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("credential limit ignored")
	}
	ca := turnTestNewClient(t, m, a)
	turnTestAllocate(t, ca)
	ca2 := turnTestNewClient(t, m, a2)
	if relay, err := ca2.client.Allocate(); err == nil {
		relay.Close()
		t.Fatal("tenant allocation limit ignored")
	}
	cb := turnTestNewClient(t, m, b)
	turnTestAllocate(t, cb)
	m.revokeBroker("b1")
	if _, ok := m.auth(a.Username, m.cfg.Realm, ca.base.LocalAddr()); ok {
		t.Fatal("revoked broker credential allowed")
	}
	if _, ok := m.auth(a2.Username, m.cfg.Realm, ca2.base.LocalAddr()); !ok {
		t.Fatal("revocation crossed broker/session ownership")
	}
	if _, ok := m.auth(b.Username, m.cfg.Realm, cb.base.LocalAddr()); !ok {
		t.Fatal("revocation crossed tenant ownership")
	}
	if _, err := m.mint("b", "b", "s", time.Now().Add(-time.Second)); err == nil {
		t.Fatal("expired credential minted")
	}
	if _, err := m.mint("b", "b", "s", time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("overlong credential minted")
	}
}

func TestTURNBoundedRateDropsWithoutAccounting(t *testing.T) {
	for _, perTenant := range []bool{false, true} {
		t.Run(fmt.Sprintf("perTenant=%t", perTenant), func(t *testing.T) {
			cfg := turnTestConfig()
			if perTenant {
				cfg.MaxBytesPerSecondPerTenant = 4
			} else {
				cfg.MaxBytesPerSecond = 4
			}
			u := &turnTestUsage{bytes: make(map[string]int64)}
			m := turnTestManager(t, cfg, nil, u.add)
			creds := turnTestMint(t, m, "tenant", "b", "s", time.Now().Add(time.Minute))
			c := turnTestNewClient(t, m, creds)
			turnTestAllocate(t, c)
			peer := turnTestPeer(t)
			if err := c.client.CreatePermission(peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			c.relay.WriteTo([]byte("too many bytes"), peer.LocalAddr())
			peer.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
			if n, _, err := peer.ReadFrom(make([]byte, 1024)); err == nil {
				t.Fatalf("rate limit forwarded %d bytes", n)
			}
			peer.WriteTo([]byte("too many bytes"), c.relay.LocalAddr())
			c.relay.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
			if n, _, err := c.relay.ReadFrom(make([]byte, 1024)); err == nil {
				t.Fatalf("rate limit returned %d bytes", n)
			}
			if u.get("tenant") != 0 {
				t.Fatal("rate-dropped traffic charged")
			}
		})
	}
}

func TestTURNPeerChannelAndGlobalAllocationBounds(t *testing.T) {
	t.Run("global allocations", func(t *testing.T) {
		cfg := turnTestConfig()
		cfg.MaxAllocations = 1
		cfg.MaxAllocationsPerTenant = 2
		m := turnTestManager(t, cfg, nil, nil)
		for i := 0; i < 2; i++ {
			creds := turnTestMint(t, m, fmt.Sprintf("tenant-%d", i), "b", "s", time.Now().Add(time.Minute))
			c := turnTestNewClient(t, m, creds)
			if i == 0 {
				turnTestAllocate(t, c)
			} else if relay, err := c.client.Allocate(); err == nil {
				relay.Close()
				t.Fatal("global allocation limit ignored")
			}
		}
	})
	t.Run("peer IPs", func(t *testing.T) {
		cfg := turnTestConfig()
		cfg.MaxPeersPerAllocation = 1
		m := turnTestManager(t, cfg, nil, nil)
		creds := turnTestMint(t, m, "t", "b", "s", time.Now().Add(time.Minute))
		c := turnTestNewClient(t, m, creds)
		turnTestAllocate(t, c)
		if err := c.client.CreatePermission(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}); err != nil {
			t.Fatal(err)
		}
		if err := c.client.CreatePermission(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}); err == nil {
			t.Fatal("peer IP limit ignored")
		}
	})
	t.Run("channels", func(t *testing.T) {
		cfg := turnTestConfig()
		cfg.MaxChannelsPerAllocation = 1
		m := turnTestManager(t, cfg, nil, nil)
		creds := turnTestMint(t, m, "t", "b", "s", time.Now().Add(time.Minute))
		c := turnTestNewClient(t, m, creds)
		turnTestAllocate(t, c)
		first, second := turnTestPeer(t), turnTestPeer(t)
		if err := turnTestExchange(c, first, []byte("first"), []byte("return")); err != nil {
			t.Fatal(err)
		}
		turnTestWait(t, func() bool {
			m.mu.Lock()
			defer m.mu.Unlock()
			r := m.clients[c.base.LocalAddr().String()]
			return r != nil && len(r.channels) == 1
		})
		c.relay.WriteTo([]byte("second channel exceeds quota"), second.LocalAddr())
		turnTestWait(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return len(m.clients) == 0 && len(m.relays) == 0 })
	})
}

func TestTURNUnpermittedPubliclyAllowedPeerNotCharged(t *testing.T) {
	u := &turnTestUsage{bytes: make(map[string]int64)}
	m := turnTestManager(t, turnTestConfig(), nil, u.add)
	creds := turnTestMint(t, m, "t", "b", "s", time.Now().Add(time.Minute))
	c := turnTestNewClient(t, m, creds)
	turnTestAllocate(t, c)
	peer := turnTestPeer(t)
	peer.WriteTo([]byte("no permission yet"), c.relay.LocalAddr())
	c.relay.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if n, _, err := c.relay.ReadFrom(make([]byte, 1024)); err == nil {
		t.Fatalf("forwarded %d unpermitted bytes", n)
	}
	if u.get("t") != 0 {
		t.Fatal("unpermitted socket reads charged")
	}
	if err := c.client.CreatePermission(peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := turnTestExchange(c, peer, []byte("now allowed"), []byte("return")); err != nil {
		t.Fatal(err)
	}
	turnTestWait(t, func() bool { return u.getOwner("t", "b", "s") == 17 })
}

func TestTURNConcurrentTrafficRevocationAndClose(t *testing.T) {
	for round := 0; round < 8; round++ {
		t.Run(fmt.Sprintf("round-%d", round), func(t *testing.T) {
			m := turnTestManager(t, turnTestConfig(), nil, nil)
			const count = 4
			clients := make([]*turnTestClient, count)
			peers := make([]*net.UDPConn, count)
			for i := range clients {
				creds := turnTestMint(t, m, fmt.Sprintf("t-%d", i), "b", "s", time.Now().Add(time.Minute))
				clients[i] = turnTestNewClient(t, m, creds)
				turnTestAllocate(t, clients[i])
				peers[i] = turnTestPeer(t)
				if err := turnTestExchange(clients[i], peers[i], []byte("initialize"), []byte("channel")); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			var writers sync.WaitGroup
			for i := range clients {
				writers.Add(1)
				go func(i int) {
					defer writers.Done()
					<-start
					for j := 0; j < 128; j++ {
						peers[i].WriteTo([]byte("concurrent incoming"), clients[i].relay.LocalAddr())
						clients[i].relay.WriteTo([]byte("concurrent outgoing"), peers[i].LocalAddr())
					}
				}(i)
			}
			writers.Add(1)
			go func() {
				defer writers.Done()
				<-start
				for j := 0; j < 128; j++ {
					m.renewSession("s", time.Now().Add(time.Minute))
				}
			}()
			done := make(chan struct{})
			close(start)
			go func() { m.revokeTenant("t-0"); m.close(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("concurrent close did not drain")
			}
			writers.Wait()
			m.mu.Lock()
			remaining := len(m.clients) + len(m.relays) + len(m.creds) + len(m.tenants)
			m.mu.Unlock()
			if remaining != 0 {
				t.Fatal("concurrent close leaked allocation state")
			}
		})
	}
}

func TestTURNSessionRenewalKeepsExistingAllocation(t *testing.T) {
	for _, end := range []string{"expiry", "revocation"} {
		t.Run(end, func(t *testing.T) {
			u := &turnTestUsage{bytes: make(map[string]int64)}
			cfg := turnTestConfig()
			cfg.MaxCredentialTTL = 2 * time.Second
			m := turnTestManager(t, cfg, nil, u.add)
			originalExpiry := time.Now().Add(time.Second)
			creds := turnTestMint(t, m, "t", "b", "s", originalExpiry)
			other := turnTestMint(t, m, "t", "b", "other-session", originalExpiry)
			c := turnTestNewClient(t, m, creds)
			turnTestAllocate(t, c)
			peer := turnTestPeer(t)
			if err := turnTestExchange(c, peer, []byte("before"), []byte("return")); err != nil {
				t.Fatal(err)
			}
			allocationAddr := c.relay.LocalAddr().String()
			record, unrelated := m.credential(creds.Username), m.credential(other.Username)
			key := append([]byte(nil), record.key...)
			renewedExpiry := time.Now().Add(1500 * time.Millisecond)
			m.renewSession("s", renewedExpiry)
			record.gate.RLock()
			gotExpiry := record.expires
			record.gate.RUnlock()
			if !gotExpiry.Equal(renewedExpiry) {
				t.Fatalf("renewed expiry %s, want %s", gotExpiry, renewedExpiry)
			}
			unrelated.gate.RLock()
			otherExpiry := unrelated.expires
			unrelated.gate.RUnlock()
			if !otherExpiry.Equal(originalExpiry) {
				t.Fatal("renewal crossed session ownership")
			}
			turnTestWait(t, func() bool { return !time.Now().Before(originalExpiry) })
			// Model a previously dispatched timer callback that acquires gate
			// after renewal and the old deadline. It must see the current lease.
			m.expireCredential(record)
			if authKey, ok := m.auth(creds.Username, m.cfg.Realm, c.base.LocalAddr()); !ok || !bytes.Equal(authKey, key) {
				t.Fatal("renewal changed/revoked the existing username/auth key")
			}
			if err := c.client.CreatePermission(peer.LocalAddr()); err != nil {
				t.Fatalf("existing Pion credentials no longer authenticate: %v", err)
			}
			if err := turnTestExchange(c, peer, []byte("renewed"), []byte("working")); err != nil {
				t.Fatal(err)
			}
			if c.relay.LocalAddr().String() != allocationAddr {
				t.Fatal("renewal replaced the allocation")
			}
			turnTestWait(t, func() bool { return u.getOwner("t", "b", "s") == 26 })
			if end == "expiry" {
				turnTestWait(t, func() bool { return !time.Now().Before(renewedExpiry) })
			} else {
				m.revokeSession("s")
			}
			// Even a healthy-looking later heartbeat must not resurrect a bearer
			// that has already expired or been explicitly revoked.
			m.renewSession("s", time.Now().Add(time.Second))
			turnTestDropped(t, c, peer)
			if _, ok := m.auth(creds.Username, m.cfg.Realm, c.base.LocalAddr()); ok {
				t.Fatal("renewal resurrected an expired/revoked credential")
			}
			if u.getOwner("t", "b", "s") != 26 {
				t.Fatal("traffic after renewed lease ended was charged")
			}
		})
	}
}

func TestTURNSessionRenewalSafetyAndTimerRace(t *testing.T) {
	var approved atomic.Bool
	approved.Store(true)
	cfg := turnTestConfig()
	cfg.MaxCredentialTTL = time.Minute
	m := turnTestManager(t, cfg, func(string, string, string) bool { return approved.Load() }, nil)
	creds := turnTestMint(t, m, "t", "b", "s", time.Now().Add(10*time.Second))
	c := m.credential(creds.Username)
	before := time.Now()
	m.renewSession("s", before.Add(2*time.Hour))
	after := time.Now()
	c.gate.RLock()
	deadline := c.expires
	c.gate.RUnlock()
	if deadline.Before(before.Add(cfg.MaxCredentialTTL)) || deadline.After(after.Add(cfg.MaxCredentialTTL)) {
		t.Fatalf("renewed TTL was not capped: %s", deadline)
	}
	m.renewSession("s", time.Now().Add(time.Second))
	c.gate.RLock()
	shortened := c.expires
	c.gate.RUnlock()
	if !shortened.Equal(deadline) {
		t.Fatal("renewal shortened a live lease")
	}
	approved.Store(false)
	m.renewSession("s", time.Now().Add(2*time.Hour))
	c.gate.RLock()
	unauthorized := c.expires
	c.gate.RUnlock()
	if !unauthorized.Equal(deadline) {
		t.Fatal("unauthorized credential extended")
	}
	approved.Store(true)
	// Stop the timer to model a scheduler-delayed expiry callback: expiry must
	// be rejected from the timestamp itself, not only the revoked flag/map.
	c.gate.Lock()
	c.timer.Stop()
	expired := time.Now().Add(-time.Millisecond)
	c.expires = expired
	c.gate.Unlock()
	m.renewSession("s", time.Now().Add(time.Minute))
	c.gate.RLock()
	stillExpired, revoked := c.expires, c.revoked
	c.gate.RUnlock()
	if !stillExpired.Equal(expired) || revoked {
		t.Fatal("renewal resurrected a timestamp-expired credential")
	}
	m.expireCredential(c)
	if m.credential(creds.Username) != nil {
		t.Fatal("expired credential retained after callback")
	}

	// Concurrent stale timer callbacks, heartbeat extensions, and explicit
	// revocation must converge to revoked state without renewing it afterward.
	live := turnTestMint(t, m, "t", "b", "race-session", time.Now().Add(10*time.Second))
	r := m.credential(live.Username)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			for j := 0; j < 32; j++ {
				if i%2 == 0 {
					m.renewSession("race-session", time.Now().Add(time.Minute))
				} else {
					m.expireCredential(r)
				}
			}
		}(i)
	}
	close(start)
	m.revokeSession("race-session")
	wg.Wait()
	m.renewSession("race-session", time.Now().Add(time.Minute))
	r.gate.RLock()
	isRevoked := r.revoked
	r.gate.RUnlock()
	if !isRevoked || m.credential(live.Username) != nil {
		t.Fatal("concurrent renewal resurrected revoked bearer")
	}
	m.renewSession("unknown", time.Now().Add(time.Minute))
	(*turnManager)(nil).renewSession("unknown", time.Now().Add(time.Minute))
}

func TestTURNExpiryDuringAuthorizationCannotForward(t *testing.T) {
	var block atomic.Bool
	entered, release := make(chan struct{}, 4), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	u := &turnTestUsage{bytes: make(map[string]int64)}
	m := turnTestManager(t, turnTestConfig(), func(string, string, string) bool {
		if block.Load() {
			entered <- struct{}{}
			<-release
		}
		return true
	}, u.add)
	// Ensure test cleanup never leaves a callback blocked if an assertion fails.
	t.Cleanup(unblock)
	expires := time.Now().Add(500 * time.Millisecond)
	creds := turnTestMint(t, m, "t", "b", "s", expires)
	c := turnTestNewClient(t, m, creds)
	turnTestAllocate(t, c)
	peer := turnTestPeer(t)
	if err := turnTestExchange(c, peer, []byte("before"), []byte("return")); err != nil {
		t.Fatal(err)
	}
	// Pion starts ChannelBind asynchronously; wait for it before blocking auth.
	turnTestWait(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		r := m.clients[c.base.LocalAddr().String()]
		return r != nil && len(r.channels) == 1
	})
	block.Store(true)
	peer.WriteTo([]byte("expires while authorizing"), c.relay.LocalAddr())
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("incoming packet was not authorized")
	}
	turnTestWait(t, func() bool { return !time.Now().Before(expires) })
	unblock()
	c.relay.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if n, _, err := c.relay.ReadFrom(make([]byte, 1024)); err == nil {
		t.Fatalf("slow authorization extended expiry for %d bytes", n)
	}
	if got := u.get("t"); got != 12 {
		t.Fatalf("expired traffic charged: %d", got)
	}
}

func TestTURNAdvertisedAddressAndRelayPortRange(t *testing.T) {
	probe := turnTestPeer(t)
	port := probe.LocalAddr().(*net.UDPAddr).Port
	cfg := turnTestConfig()
	cfg.PublicIP = "198.51.100.17"
	cfg.RelayMinPort = uint16(port)
	cfg.RelayMaxPort = uint16(port)
	m := turnTestManager(t, cfg, nil, nil)
	creds := turnTestMint(t, m, "t", "b", "s", time.Now().Add(time.Minute))
	c := turnTestNewClient(t, m, creds)
	probe.Close()
	turnTestAllocate(t, c)
	addr := c.relay.LocalAddr().(*net.UDPAddr)
	if addr.Port != port || !addr.IP.Equal(net.ParseIP(cfg.PublicIP)) {
		t.Fatalf("advertised relay %s, want %s:%d", addr, cfg.PublicIP, port)
	}
	wantURL := fmt.Sprintf("turn:%s:%d?transport=udp", cfg.PublicIP, m.listener.LocalAddr().(*net.UDPAddr).Port)
	if len(creds.URLs) != 1 || creds.URLs[0] != wantURL {
		t.Fatalf("URLs = %v, want %s", creds.URLs, wantURL)
	}
	if conn, _, err := m.AllocatePacketConn("udp4", port); err == nil {
		conn.Close()
		t.Fatal("allocated an already occupied ranged port")
	}
	if conn, _, err := m.AllocatePacketConn("udp4", 1); err == nil {
		conn.Close()
		t.Fatal("allocated outside relay port range")
	}
}

func TestTURNConfigurationAndPayloadAccounting(t *testing.T) {
	if m, err := startTURN(TURNConfig{}, nil, nil); err != nil || m != nil {
		t.Fatalf("disabled TURN = %v, %v", m, err)
	}
	for _, modify := range []func(*TURNConfig){
		func(c *TURNConfig) { c.PublicIP = "invalid" }, func(c *TURNConfig) { c.RelayMinPort = 1000 },
		func(c *TURNConfig) { c.MaxAllocations = -1 }, func(c *TURNConfig) { c.SocketBufferBytes = 8 * 1024 * 1024 },
		func(c *TURNConfig) { c.MaxBytesPerSecond = -1 },
	} {
		cfg := turnTestConfig()
		modify(&cfg)
		if m, err := startTURN(cfg, func(string, string, string) bool { return true }, nil); err == nil {
			m.close()
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := startTURN(turnTestConfig(), nil, nil); err == nil {
		t.Fatal("nil authorization accepted")
	}
	p := []byte{0x40, 0, 0, 3, 'a', 'b', 'c', 0}
	if n, ok := forwardedPayload(p); !ok || n != 3 {
		t.Fatalf("channel payload = %d,%v", n, ok)
	}
	binary.BigEndian.PutUint16(p[2:4], 100)
	if _, ok := forwardedPayload(p); ok {
		t.Fatal("truncated channel payload admitted")
	}
	if _, ok := forwardedPayload([]byte("not a TURN packet")); ok {
		t.Fatal("non-TURN packet counted")
	}
}
