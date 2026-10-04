package control

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testTURNAuthorizationCache(t *testing.T, limit int, read func(context.Context, turnAuthorizationKey) (bool, int64), revoked func(turnAuthorizationKey)) *turnAuthorizationCache {
	t.Helper()
	c := startTURNAuthorizationCache(limit, read, revoked, nil)
	t.Cleanup(c.close)
	return c
}

func TestTURNAuthorizationCacheHitsWithoutDatabaseAccess(t *testing.T) {
	f := turnIdentityFixture(t, Config{})
	if !f.s.turnAuthCache.authorize(f.tenant, f.broker, f.session) {
		t.Fatal("permission was not admitted")
	}
	tx, err := f.s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	done := make(chan bool, 1)
	go func() {
		for i := 0; i < 1000; i++ {
			if !f.s.authorizeTURN(f.tenant, f.broker, f.session) {
				done <- false
				return
			}
		}
		done <- true
	}()
	select {
	case allowed := <-done:
		if !allowed {
			t.Fatal("cached permission changed while the DB was occupied")
		}
	case <-time.After(200 * time.Millisecond):
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		<-done
		t.Fatal("cache hits waited for the database connection")
	}
}

func TestTURNAuthorizationCacheSingleColdReadAndNoNegativeCache(t *testing.T) {
	var reads atomic.Int64
	release := make(chan struct{})
	c := testTURNAuthorizationCache(t, 4, func(ctx context.Context, key turnAuthorizationKey) (bool, int64) {
		reads.Add(1)
		select {
		case <-release:
			return true, timestamp(time.Now().Add(time.Minute))
		case <-ctx.Done():
			return false, 0
		}
	}, nil)
	const packets = 24
	started, done := make(chan struct{}, packets), make(chan bool, packets)
	for i := 0; i < packets; i++ {
		go func() {
			started <- struct{}{}
			done <- c.authorize("t", "b", "s")
		}()
	}
	for i := 0; i < packets; i++ {
		<-started
	}
	close(release)
	for i := 0; i < packets; i++ {
		if !<-done {
			t.Fatal("concurrent cold packet was denied")
		}
	}
	if reads.Load() != 1 {
		t.Fatal("concurrent misses duplicated the authority read", reads.Load())
	}
	var allowed atomic.Bool
	negative := testTURNAuthorizationCache(t, 4, func(context.Context, turnAuthorizationKey) (bool, int64) {
		return allowed.Load(), timestamp(time.Now().Add(time.Minute))
	}, nil)
	if negative.authorize("t", "b", "s") {
		t.Fatal("negative authority was cached as allowed")
	}
	allowed.Store(true)
	if !negative.authorize("t", "b", "s") {
		t.Fatal("negative caching delayed a new grant")
	}
}

func TestTURNAuthorizationCacheScopesAndBounds(t *testing.T) {
	for _, scope := range []string{"tenant", "broker", "session"} {
		t.Run(scope, func(t *testing.T) {
			c := testTURNAuthorizationCache(t, 3, func(context.Context, turnAuthorizationKey) (bool, int64) {
				return true, timestamp(time.Now().Add(time.Minute))
			}, nil)
			keys := []turnAuthorizationKey{{"t1", "b1", "s1"}, {"t1", "b2", "s2"}, {"t2", "b3", "s3"}}
			for _, key := range keys {
				if !c.authorize(key.tenant, key.broker, key.session) {
					t.Fatal("admission failed")
				}
			}
			switch scope {
			case "tenant":
				c.invalidateTenant("t1")
			case "broker":
				c.invalidateBroker("b1")
			case "session":
				c.invalidateSession("s1")
			}
			c.mu.RLock()
			first, unrelated := c.entries[keys[0]], c.entries[keys[2]]
			count := len(c.entries)
			c.mu.RUnlock()
			if first != nil || unrelated == nil || scope == "tenant" && count != 1 || scope != "tenant" && count != 2 {
				t.Fatal("scope invalidation removed the wrong permissions")
			}
			for i := 0; i < 10; i++ {
				if !c.authorize("new", "broker", string(rune('a'+i))) {
					t.Fatal("bounded cache could not admit a new permission")
				}
			}
			c.mu.RLock()
			count = len(c.entries)
			c.mu.RUnlock()
			if count > 3 {
				t.Fatal("cache exceeded its admission bound", count)
			}
		})
	}
}

func TestTURNAuthorizationCacheRejectsInvalidatedReads(t *testing.T) {
	for _, phase := range []string{"miss", "refresh"} {
		t.Run(phase, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var reads atomic.Int64
			var signal sync.Once
			c := testTURNAuthorizationCache(t, 4, func(ctx context.Context, key turnAuthorizationKey) (bool, int64) {
				n := reads.Add(1)
				if phase == "refresh" && n == 1 {
					return true, timestamp(time.Now().Add(time.Minute))
				}
				signal.Do(func() { close(started) })
				select {
				case <-release:
					return true, timestamp(time.Now().Add(time.Minute))
				case <-ctx.Done():
					return false, 0
				}
			}, nil)
			done := make(chan bool, 1)
			if phase == "refresh" {
				if !c.authorize("t", "b", "s") {
					t.Fatal("initial admission failed")
				}
				go func() { c.refresh(); done <- false }()
			} else {
				go func() { done <- c.authorize("t", "b", "s") }()
			}
			<-started
			c.invalidateSession("s")
			close(release)
			if <-done {
				t.Fatal("invalidated in-flight miss returned its old positive result")
			}
			c.mu.RLock()
			count := len(c.entries)
			c.mu.RUnlock()
			if count != 0 {
				t.Fatal("in-flight read republished a revoked permission")
			}
		})
	}
}

func TestTURNAuthorizationCacheExpiryStalenessAndLeaseRenewal(t *testing.T) {
	var reads atomic.Int64
	var deadline atomic.Int64
	deadline.Store(timestamp(time.Now().Add(time.Minute)))
	c := testTURNAuthorizationCache(t, 4, func(context.Context, turnAuthorizationKey) (bool, int64) {
		reads.Add(1)
		return true, deadline.Load()
	}, nil)
	key := turnAuthorizationKey{"t", "b", "s"}
	if !c.authorize(key.tenant, key.broker, key.session) {
		t.Fatal("initial admission failed")
	}
	c.mu.Lock()
	c.entries[key].checkedAt = time.Now().Add(-turnAuthorizationMaxAge)
	c.mu.Unlock()
	before := reads.Load()
	if c.authorize(key.tenant, key.broker, key.session) || reads.Load() != before {
		t.Fatal("stale cache entry was trusted or queried synchronously")
	}
	c.refresh()
	if !c.authorize(key.tenant, key.broker, key.session) {
		t.Fatal("background refresh did not restore a valid permission")
	}
	// An expired stored decision is not usable. A fresh authority read may
	// authorize an extended lease, while a truly expired authority must deny.
	c.mu.Lock()
	c.entries[key].until = now() - 1
	c.mu.Unlock()
	if !c.authorize(key.tenant, key.broker, key.session) || reads.Load() != before+2 {
		t.Fatal("renewed authority lease was not read on expiry")
	}
	deadline.Store(now() - 1)
	c.mu.Lock()
	c.entries[key].until = now() - 1
	c.mu.Unlock()
	if c.authorize(key.tenant, key.broker, key.session) {
		t.Fatal("expired credential deadline was authorized")
	}
}

func TestTURNAuthorizationCacheWorkerObservesTokenRevocation(t *testing.T) {
	for _, mutation := range []string{"delete", "early-expire"} {
		t.Run(mutation, func(t *testing.T) {
			f := turnIdentityFixture(t, Config{})
			if !f.s.turnAuthCache.authorize(f.tenant, f.broker, f.session) {
				t.Fatal("initial admission failed")
			}
			query := "DELETE FROM tokens WHERE hash=?"
			if mutation == "early-expire" {
				query = "UPDATE tokens SET expires_at=0 WHERE hash=?"
			}
			turnIdentityExec(t, f, query, tokenHash(f.token))
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			limit := time.NewTimer(2 * time.Second)
			defer limit.Stop()
			for {
				select {
				case <-ticker.C:
					c, err := readConnection(f.s.db, f.connection)
					if err != nil {
						t.Fatal(err)
					}
					if c.Revoked != "session_credential_revoked" {
						continue
					}
					if f.s.turnAuthCache.authorize(f.tenant, f.broker, f.session) {
						// The SQL tombstone can become visible just before the
						// worker removes the corresponding memory permission.
						continue
					}
					turnIdentityExec(t, f, "DELETE FROM sessions WHERE id=?", f.session)
					connectionOpen(t, f.connectionFixtureData, f.connection, map[string]any{"broker_id": f.broker, "relay_mode": "auto", "expected_generation": uint64(1), "request_id": uuid(), "session_token": randomSecret()}, 403)
					return
				case <-limit.C:
					t.Fatal("background refresh did not persist and evict token revocation")
				}
			}
		})
	}
}

func TestTURNAuthorizationCacheLocalRevocationAndIdleCleanup(t *testing.T) {
	f := turnIdentityFixture(t, Config{})
	if !f.s.turnAuthCache.authorize(f.tenant, f.broker, f.session) {
		t.Fatal("admission failed")
	}
	turnIdentityExec(t, f, "UPDATE tenants SET relay_enabled=0 WHERE id=?", f.tenant)
	f.s.revokeTURNTenant(f.tenant)
	if f.s.turnAuthCache.authorize(f.tenant, f.broker, f.session) {
		t.Fatal("local relay revocation retained a positive permission")
	}
	turnIdentityExec(t, f, "UPDATE tenants SET relay_enabled=1 WHERE id=?", f.tenant)
	if !f.s.turnAuthCache.authorize(f.tenant, f.broker, f.session) {
		t.Fatal("negative caching delayed relay reapproval")
	}
	key := turnAuthorizationKey{f.tenant, f.broker, f.session}
	f.s.turnAuthCache.mu.Lock()
	f.s.turnAuthCache.entries[key].lastUsed.Store(-int64(turnAuthorizationIdle))
	f.s.turnAuthCache.mu.Unlock()
	f.s.turnAuthCache.refresh()
	f.s.turnAuthCache.mu.RLock()
	entry := f.s.turnAuthCache.entries[key]
	f.s.turnAuthCache.mu.RUnlock()
	if entry != nil {
		t.Fatal("idle entry was retained")
	}
}

func TestTURNAuthorizationCacheCloseCancelsBlockedRefresh(t *testing.T) {
	f := turnIdentityFixture(t, Config{})
	if !f.s.turnAuthCache.authorize(f.tenant, f.broker, f.session) {
		t.Fatal("admission failed")
	}
	tx, err := f.s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// The worker's next scheduled query waits for this DB connection. Closing
	// must cancel that wait, without requiring the external transaction to end.
	timer := time.NewTimer(turnAuthorizationRefresh + 40*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	done := make(chan struct{})
	go func() { f.s.turnAuthCache.close(); close(done) }()
	select {
	case <-done:
		if f.s.turnAuthCache.authorize(f.tenant, f.broker, f.session) {
			t.Fatal("closed cache was authorized")
		}
	case <-time.After(time.Second):
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		<-done
		t.Fatal("cache close did not cancel the blocked SQL refresh")
	}
	f.s.turnAuthCache.close()
}

func TestTURNAuthorizationCacheChecksDeadlineAfterLockWait(t *testing.T) {
	deadline := timestamp(time.Now().Add(80 * time.Millisecond))
	c := testTURNAuthorizationCache(t, 4, func(context.Context, turnAuthorizationKey) (bool, int64) {
		return true, deadline
	}, nil)
	if !c.authorize("t", "b", "s") {
		t.Fatal("initial permission was not admitted")
	}
	c.mu.Lock()
	started, done := make(chan struct{}), make(chan bool, 1)
	go func() {
		close(started)
		done <- c.authorize("t", "b", "s")
	}()
	<-started
	timer := time.NewTimer(time.Until(fromTimestamp(deadline)) + 20*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	c.mu.Unlock()
	if <-done {
		t.Fatal("cache trusted a deadline that expired while waiting for its lock")
	}
}

func TestTURNAuthorizationSnapshotUsesEarliestDeadline(t *testing.T) {
	for _, field := range []string{"broker", "session", "account", "device", "token"} {
		t.Run(field, func(t *testing.T) {
			f := turnIdentityFixture(t, Config{})
			expires := timestamp(time.Now().Add(time.Second))
			switch field {
			case "broker":
				turnIdentityExec(t, f, "UPDATE brokers SET lease_expires_at=? WHERE id=?", expires, f.broker)
			case "session":
				turnIdentityExec(t, f, "UPDATE sessions SET expires_at=? WHERE id=?", expires, f.session)
			default:
				token := f.account
				if field == "device" {
					token = f.device
				} else if field == "token" {
					token = f.token
				}
				turnIdentityExec(t, f, "UPDATE tokens SET expires_at=? WHERE hash=?", expires, tokenHash(token))
			}
			allowed, until := f.s.authorizeTURNIdentitySnapshot(f.tenant, f.broker, f.session)
			if !allowed || until != expires {
				t.Fatal("snapshot did not return the earliest authority deadline", allowed, until, expires)
			}
		})
	}
}
