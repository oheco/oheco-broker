package control

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	turnAuthorizationCacheLimit = 4096
	turnAuthorizationRefresh    = 500 * time.Millisecond
	turnAuthorizationMaxAge     = 5 * time.Second
	turnAuthorizationIdle       = 2 * time.Minute
)

type turnAuthorizationKey struct {
	tenant, broker, session string
}

type turnAuthorizationEntry struct {
	until     int64
	checkedAt time.Time
	lastUsed  atomic.Int64 // Monotonic elapsed nanoseconds since cache creation.
}

// A cold read has no entry to remove yet. Only invalidations matching its key
// can make its in-flight authority snapshot obsolete.
type turnAuthorizationRead struct {
	key         turnAuthorizationKey
	invalidated bool
}

type turnAuthorizationCache struct {
	mu           sync.RWMutex
	missMu       sync.Mutex
	entries      map[turnAuthorizationKey]*turnAuthorizationEntry
	coldRead     *turnAuthorizationRead // protected by mu; missMu serializes cold reads
	closed       bool
	limit        int
	started      time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	stop, done   chan struct{}
	closeOnce    sync.Once
	read         func(context.Context, turnAuthorizationKey) (bool, int64)
	revoked      func(turnAuthorizationKey)
	refreshUsage func(context.Context)
}

func newTURNAuthorizationCache(s *Server) *turnAuthorizationCache {
	limit := s.cfg.TURN.MaxCredentials
	if limit <= 0 || limit > turnAuthorizationCacheLimit {
		limit = turnAuthorizationCacheLimit
	}
	return startTURNAuthorizationCache(limit,
		func(ctx context.Context, key turnAuthorizationKey) (bool, int64) {
			return s.authorizeTURNIdentitySnapshotContext(ctx, key.tenant, key.broker, key.session)
		},
		func(key turnAuthorizationKey) { s.revokeTURNSession(key.session) },
		func(ctx context.Context) { s.refreshTURNQuotaUsage(ctx) },
	)
}

func startTURNAuthorizationCache(limit int,
	read func(context.Context, turnAuthorizationKey) (bool, int64),
	revoked func(turnAuthorizationKey), refreshUsage func(context.Context),
) *turnAuthorizationCache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &turnAuthorizationCache{
		entries: make(map[turnAuthorizationKey]*turnAuthorizationEntry), limit: limit,
		started: time.Now(), ctx: ctx, cancel: cancel,
		stop: make(chan struct{}), done: make(chan struct{}),
		read: read, revoked: revoked, refreshUsage: refreshUsage,
	}
	go c.run()
	return c
}

// Hits only read memory and check the absolute authority deadline. Expired
// entries become misses so an already renewed authoritative lease can be read;
// stale entries fail closed until the background worker refreshes them.
func (c *turnAuthorizationCache) lookup(key turnAuthorizationKey) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return false, true
	}
	e := c.entries[key]
	if e == nil {
		return false, false
	}
	at := time.Now()
	if e.until <= timestamp(at) {
		return false, false
	}
	if at.Sub(e.checkedAt) >= turnAuthorizationMaxAge {
		return false, true
	}
	e.lastUsed.Store(at.Sub(c.started).Nanoseconds())
	return true, true
}

func (c *turnAuthorizationCache) authorize(tenant, broker, session string) bool {
	if c == nil {
		return false
	}
	key := turnAuthorizationKey{tenant, broker, session}
	if allowed, found := c.lookup(key); found {
		return allowed
	}
	// Only one cold read runs at a time. Concurrent packets for an admitted
	// session reuse its result rather than queueing duplicate database reads.
	c.missMu.Lock()
	defer c.missMu.Unlock()
	if allowed, found := c.lookup(key); found {
		return allowed
	}
	// A matching revocation may race a positive SQL read. Discard that result
	// and read current authority; unrelated scope changes must not terminate
	// healthy allocations. One deadline bounds all retries and database waits.
	ctx, cancel := context.WithTimeout(c.ctx, turnAuthorizationMaxAge)
	defer cancel()
	for {
		c.mu.Lock()
		if c.closed || ctx.Err() != nil {
			c.mu.Unlock()
			return false
		}
		delete(c.entries, key)
		attempt := &turnAuthorizationRead{key: key}
		c.coldRead = attempt
		c.mu.Unlock()
		checkedAt := time.Now()
		allowed, until := c.read(ctx, key)
		c.mu.Lock()
		c.coldRead = nil
		at := time.Now()
		if c.closed || ctx.Err() != nil {
			c.mu.Unlock()
			return false
		}
		if attempt.invalidated {
			c.mu.Unlock()
			continue
		}
		if !allowed || until <= timestamp(at) || at.Sub(checkedAt) >= turnAuthorizationMaxAge {
			c.mu.Unlock()
			return false
		}
		if len(c.entries) >= c.limit {
			var oldest turnAuthorizationKey
			oldestUsed := int64(1<<63 - 1)
			for candidate, entry := range c.entries {
				if used := entry.lastUsed.Load(); used < oldestUsed {
					oldest, oldestUsed = candidate, used
				}
			}
			delete(c.entries, oldest)
		}
		e := &turnAuthorizationEntry{until: until, checkedAt: checkedAt}
		e.lastUsed.Store(at.Sub(c.started).Nanoseconds())
		c.entries[key] = e
		c.mu.Unlock()
		return true
	}
}

func (c *turnAuthorizationCache) invalidate(tenant, broker, session string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	matches := func(key turnAuthorizationKey) bool {
		return (tenant == "" || key.tenant == tenant) && (broker == "" || key.broker == broker) && (session == "" || key.session == session)
	}
	if c.coldRead != nil && matches(c.coldRead.key) {
		c.coldRead.invalidated = true
	}
	for key := range c.entries {
		if matches(key) {
			delete(c.entries, key)
		}
	}
}

func (c *turnAuthorizationCache) invalidateTenant(id string)  { c.invalidate(id, "", "") }
func (c *turnAuthorizationCache) invalidateBroker(id string)  { c.invalidate("", id, "") }
func (c *turnAuthorizationCache) invalidateSession(id string) { c.invalidate("", "", id) }

func (c *turnAuthorizationCache) refresh() {
	if c.ctx.Err() != nil {
		return
	}
	if c.refreshUsage != nil {
		c.refreshUsage(c.ctx)
	}
	type candidate struct {
		key   turnAuthorizationKey
		entry *turnAuthorizationEntry
	}
	at := time.Now()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	keys := make([]candidate, 0, len(c.entries))
	for key, entry := range c.entries {
		if at.Sub(c.started).Nanoseconds()-entry.lastUsed.Load() >= int64(turnAuthorizationIdle) {
			delete(c.entries, key)
			continue
		}
		keys = append(keys, candidate{key, entry})
	}
	c.mu.Unlock()
	for _, item := range keys {
		if c.ctx.Err() != nil {
			return
		}
		c.mu.RLock()
		current := c.entries[item.key] == item.entry
		c.mu.RUnlock()
		if !current {
			continue
		}
		checkedAt := time.Now()
		allowed, until := c.read(c.ctx, item.key)
		if c.ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		at := time.Now()
		if c.closed || c.entries[item.key] != item.entry {
			c.mu.Unlock()
			continue
		}
		if allowed && until > timestamp(at) && at.Sub(checkedAt) < turnAuthorizationMaxAge {
			item.entry.until, item.entry.checkedAt = until, checkedAt
			c.mu.Unlock()
			continue
		}
		delete(c.entries, item.key)
		c.mu.Unlock()
		// No cache, database, or credential gate is held here. Revocation may
		// safely acquire the TURN credential gate and close existing relays.
		if c.revoked != nil {
			c.revoked(item.key)
		}
	}
}

func (c *turnAuthorizationCache) run() {
	defer close(c.done)
	ticker := time.NewTicker(turnAuthorizationRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.refresh()
		}
	}
}

func (c *turnAuthorizationCache) close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		clear(c.entries)
		c.mu.Unlock()
		close(c.stop)
		c.cancel()
		<-c.done
	})
}
