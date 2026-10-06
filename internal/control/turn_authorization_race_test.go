package control

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

// A manually driven cache makes the race deterministic: only the packet under
// test performs a cold read, without the scheduled worker consuming the barrier.
func manualTURNCache(t *testing.T, read func(context.Context, turnAuthorizationKey) (bool, int64)) *turnAuthorizationCache {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &turnAuthorizationCache{entries: make(map[turnAuthorizationKey]*turnAuthorizationEntry), limit: turnAuthorizationCacheLimit, started: time.Now(), ctx: ctx, cancel: cancel, stop: make(chan struct{}), done: make(chan struct{}), read: read}
	close(c.done)
	t.Cleanup(c.close)
	return c
}

func TestTURNAuthorizationMatchedColdReadRevalidates(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoked", true: "still-live"}[allowed], func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var reads atomic.Int64
			c := manualTURNCache(t, func(ctx context.Context, _ turnAuthorizationKey) (bool, int64) {
				if reads.Add(1) == 1 {
					close(started)
					select {
					case <-release:
						return true, timestamp(time.Now().Add(time.Minute))
					case <-ctx.Done():
						return false, 0
					}
				}
				return allowed, timestamp(time.Now().Add(time.Minute))
			})
			done := make(chan bool, 1)
			go func() { done <- c.authorize("t", "b", "s") }()
			<-started
			c.invalidateSession("s")
			close(release)
			if got := <-done; got != allowed || reads.Load() != 2 {
				t.Fatal("stale positive was not replaced with current authority", got, allowed, reads.Load())
			}
			c.mu.RLock()
			entry := c.entries[turnAuthorizationKey{"t", "b", "s"}]
			c.mu.RUnlock()
			if (entry != nil) != allowed {
				t.Fatal("revoked snapshot was published")
			}
		})
	}
}

func TestTURNAuthorizationUnrelatedInvalidationPreservesColdRead(t *testing.T) {
	for _, scope := range []string{"tenant", "broker", "session"} {
		t.Run(scope, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var reads atomic.Int64
			c := manualTURNCache(t, func(ctx context.Context, _ turnAuthorizationKey) (bool, int64) {
				reads.Add(1)
				close(started)
				select {
				case <-release:
					return true, timestamp(time.Now().Add(time.Minute))
				case <-ctx.Done():
					return false, 0
				}
			})
			done := make(chan bool, 1)
			go func() { done <- c.authorize("live-tenant", "live-broker", "live-session") }()
			<-started
			switch scope {
			case "tenant":
				c.invalidateTenant("other-tenant")
			case "broker":
				c.invalidateBroker("other-broker")
			case "session":
				c.invalidateSession("other-session")
			}
			close(release)
			if !<-done || reads.Load() != 1 {
				t.Fatal("unrelated invalidation denied or repeated a healthy read", reads.Load())
			}
		})
	}
}

func TestTURNAuthorizationUnrelatedInvalidationPreservesWorkerRefresh(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var reads atomic.Int64
	c := manualTURNCache(t, func(ctx context.Context, _ turnAuthorizationKey) (bool, int64) {
		if reads.Add(1) == 2 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return false, 0
			}
		}
		return true, timestamp(time.Now().Add(time.Minute))
	})
	if !c.authorize("t", "b", "s") {
		t.Fatal("initial permission denied")
	}
	c.mu.Lock()
	c.entries[turnAuthorizationKey{"t", "b", "s"}].checkedAt = time.Now().Add(-turnAuthorizationMaxAge)
	c.mu.Unlock()
	done := make(chan struct{})
	go func() { c.refresh(); close(done) }()
	<-started
	c.invalidateTenant("other-tenant")
	close(release)
	<-done
	if !c.authorize("t", "b", "s") || reads.Load() != 2 {
		t.Fatal("unrelated scope discarded a fresh worker snapshot", reads.Load())
	}
}

func TestTURNAuthorizationRepeatedInvalidationStopsOnCancellation(t *testing.T) {
	var reads atomic.Int64
	var c *turnAuthorizationCache
	c = manualTURNCache(t, func(context.Context, turnAuthorizationKey) (bool, int64) {
		c.invalidateSession("s")
		if reads.Add(1) == 3 {
			c.cancel()
		}
		return true, timestamp(time.Now().Add(time.Minute))
	})
	if c.authorize("t", "b", "s") || reads.Load() != 3 {
		t.Fatal("cancelled retry loop admitted or continued authority", reads.Load())
	}
}

func TestAuthRefreshLogoutPreservesConcurrentTURNAllocation(t *testing.T) {
	for _, scope := range []string{"same-tenant", "other-tenant", "matched-revalidation"} {
		t.Run(scope, func(t *testing.T) {
			a := refreshFixture(t, Config{TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true}})
			s := a.s
			tenant := a.tenant
			if scope == "other-tenant" {
				tenant = uuid()
				authExec(t, s, "INSERT INTO tenants(id,name,email,password_hash,status,relay_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", tenant, "other-race-fixture", "other@example.invalid", "unused", "active", 1, now(), now())
			}
			tx, err := s.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := s.issueAuthSession(tx, tenant, 1)
			if err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			broker, device := fixtureBroker(t, s, credentials.Token, "independent-host")
			b := connectionFixtureData{s, tenant, credentials.Token, broker, device}
			id := uuid()
			body := connectionBody(b, 0)
			body["relay_mode"] = "auto"
			sid := connectionOpen(t, b, id, body, 201)["session_id"].(string)
			apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 200)
			creds := apiCall(t, s, "POST", "/v1/sessions/"+sid+"/turn", body["session_token"].(string), nil, 200)

			// Install the controlled cache before creating the network client/allocation.
			s.turnAuthCache.close()
			key := turnAuthorizationKey{tenant, broker, sid}
			started, release := make(chan struct{}), make(chan struct{})
			var armed atomic.Bool
			var paused sync.Once
			var snapshots atomic.Int64
			cache := manualTURNCache(t, func(ctx context.Context, k turnAuthorizationKey) (bool, int64) {
				allowed, until := s.authorizeTURNIdentitySnapshotContext(ctx, k.tenant, k.broker, k.session)
				if armed.Load() && k == key {
					snapshots.Add(1)
					paused.Do(func() {
						close(started)
						select {
						case <-release:
						case <-ctx.Done():
						}
					})
				}
				return allowed, until
			})
			s.turnAuthCache = cache
			var unpause sync.Once
			defer unpause.Do(func() { close(release) })
			transport, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			logger := logging.NewDefaultLoggerFactory()
			logger.DefaultLogLevel = logging.LogLevelError
			client, err := turn.NewClient(&turn.ClientConfig{Conn: transport, TURNServerAddr: s.TURNAddr(), Username: creds["username"].(string), Password: creds["password"].(string), Realm: s.turn.cfg.Realm, LoggerFactory: logger, RTO: 100 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err = client.Listen(); err != nil {
				t.Fatal(err)
			}
			relay, err := client.Allocate()
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err = client.CreatePermission(peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			echo := func(payload []byte) {
				t.Helper()
				if _, err := relay.WriteTo(payload, peer.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 128)
				_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, addr, err := peer.ReadFrom(buf)
				if err != nil || !bytes.Equal(buf[:n], payload) {
					t.Fatal("same allocation lost outbound payload", err)
				}
				if _, err = peer.WriteTo(buf[:n], addr); err != nil {
					t.Fatal(err)
				}
				_ = relay.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _, err = relay.ReadFrom(buf)
				if err != nil || !bytes.Equal(buf[:n], payload) {
					t.Fatal("same allocation lost inbound payload", err)
				}
			}
			echo([]byte("before-family-logout"))
			original, _ := readConnection(s.db, id)
			cache.mu.Lock()
			delete(cache.entries, key)
			cache.mu.Unlock()
			armed.Store(true)
			payload := []byte("packet-during-other-family-logout")
			if _, err = relay.WriteTo(payload, peer.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("TURN packet missed cold-read barrier")
			}
			// The packet's positive authoritative SQL snapshot is now paused immediately
			// before cache publication, while another login's revocation commits.
			if scope == "matched-revalidation" {
				cache.invalidateTenant(tenant)
			}
			apiCall(t, s, "POST", "/v1/auth/logout", a.credentials.RefreshToken, nil, 200)
			apiCall(t, s, "GET", "/v1/me", credentials.Token, nil, 200)
			unpause.Do(func() { close(release) })
			buf := make([]byte, 128)
			_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := peer.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatal("unrelated logout closed existing allocation", err)
			}
			if _, err = peer.WriteTo(buf[:n], addr); err != nil {
				t.Fatal(err)
			}
			_ = relay.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err = relay.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatal("unrelated logout broke inbound allocation", err)
			}
			if scope == "matched-revalidation" && snapshots.Load() < 2 {
				t.Fatal("invalidated positive snapshot was not freshly revalidated")
			}
			echo([]byte("after-family-logout"))
			current, err := readConnection(s.db, id)
			if err != nil || current.Generation != original.Generation || current.Session != original.Session || current.Revoked != "" {
				t.Fatal("unrelated logout changed logical connection", current, err)
			}
		})
	}
}
