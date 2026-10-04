package control

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
)

const turnQuotaSnapshotMaxAge = 5 * time.Second

// All fields are protected by Server.usageMu, including during database refresh
// and flush. A flush moves pending bytes into SQLite without changing totals.
type turnQuotaCache struct {
	day      string
	loadedAt time.Time
	known    bool
	totals   map[string]int64
}

func newTURNQuotaCache() *turnQuotaCache {
	return &turnQuotaCache{totals: make(map[string]int64)}
}

// refreshTURNQuotaUsage is called at startup and by the existing authorization
// refresh worker, never by packet authorization. QueryContext lets shutdown
// cancel a refresh waiting for the single SQLite connection.
func (s *Server) refreshTURNQuotaUsage(ctx context.Context) error {
	if s.cfg.TenantDailyByteQuota == 0 {
		return nil
	}
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	if s.turnQuotaCache == nil {
		s.turnQuotaCache = newTURNQuotaCache()
	}
	cache := s.turnQuotaCache
	// A failed or canceled refresh must not continue authorizing from an older
	// successful snapshot. Publish known only after reading every durable row.
	cache.known = false
	day := time.Now().UTC().Format("2006-01-02")
	rows, err := s.db.QueryContext(ctx, "SELECT tenant_id,bytes FROM usage_daily WHERE day=?", day)
	if err != nil {
		return fmt.Errorf("TURN daily quota refresh: %w", err)
	}
	defer rows.Close()
	totals := make(map[string]int64)
	for rows.Next() {
		var tenant string
		var bytes int64
		if err = rows.Scan(&tenant, &bytes); err != nil {
			return fmt.Errorf("TURN daily quota refresh: %w", err)
		}
		totals[tenant] = bytes
	}
	if err = rows.Err(); err != nil {
		return fmt.Errorf("TURN daily quota refresh: %w", err)
	}
	for key, bytes := range s.pendingUsage {
		parts := strings.SplitN(key, "|", 3)
		if len(parts) != 3 || len(parts[2]) < 10 || bytes < 0 {
			return fmt.Errorf("TURN daily quota refresh: invalid pending usage bucket")
		}
		if parts[2][:10] == day {
			totals[parts[0]] = addTURNQuotaBytes(totals[parts[0]], bytes)
		}
	}
	cache.day = day
	cache.loadedAt = time.Now()
	cache.totals = totals
	cache.known = true
	return nil
}

// authorizeTURNQuota reads only memory, even on a cold, stale or expired cache.
// The complete daily snapshot makes an absent tenant equivalent to zero usage.
func (s *Server) authorizeTURNQuota(tenant string) bool {
	if s.cfg.TenantDailyByteQuota == 0 {
		return true
	}
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	cache := s.turnQuotaCache
	at := time.Now()
	return cache != nil && cache.known && cache.day == at.UTC().Format("2006-01-02") &&
		!at.Before(cache.loadedAt) && at.Sub(cache.loadedAt) < turnQuotaSnapshotMaxAge &&
		cache.totals[tenant] < s.cfg.TenantDailyByteQuota
}

// recordTURNQuotaUsageLocked is called under usageMu alongside pendingUsage.
// Counting bytes does not renew loadedAt: only a database refresh proves the
// durable baseline is fresh. Previous-day records do not change today's total.
func (s *Server) recordTURNQuotaUsageLocked(tenant, day string, n int64) {
	if s.cfg.TenantDailyByteQuota == 0 || n <= 0 {
		return
	}
	cache := s.turnQuotaCache
	if cache != nil && cache.known && cache.day == day {
		cache.totals[tenant] = addTURNQuotaBytes(cache.totals[tenant], n)
	}
}

func addTURNQuotaBytes(total, n int64) int64 {
	if n > 0 && total > math.MaxInt64-n {
		return math.MaxInt64
	}
	return total + n
}
