package control

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

const quotaCacheTenant = "quota-cache-tenant"

// No maintenance worker is started: a held SQLite transaction must test the
// quota hot path itself, without an unrelated periodic refresh taking usageMu.
func quotaCacheFixture(t *testing.T, quota int64) *Server {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	s := &Server{cfg: Config{RegistrationPolicy: "open", TenantDailyByteQuota: quota}, db: db,
		pendingUsage: map[string]int64{}, turnQuotaCache: newTURNQuotaCache()}
	if err = s.migrate(); err != nil {
		t.Fatal(err)
	}
	quotaCacheAddTenant(t, s, quotaCacheTenant)
	return s
}

func quotaCacheAddTenant(t *testing.T, s *Server, tenant string) {
	t.Helper()
	if _, err := s.db.Exec("INSERT INTO tenants(id,name,email,password_hash,status,relay_enabled,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
		tenant, tenant, tenant+"@example.invalid", "unused-fixture-hash", "active", 1, 1, now(), now()); err != nil {
		t.Fatal(err)
	}
}

func quotaCacheStore(t *testing.T, s *Server, tenant, day string, n any) {
	t.Helper()
	if _, err := s.db.Exec("INSERT INTO usage_daily(tenant_id,day,bytes) VALUES(?,?,?)", tenant, day, n); err != nil {
		t.Fatal(err)
	}
}

func quotaCacheRefresh(t *testing.T, s *Server) {
	t.Helper()
	if err := s.refreshTURNQuotaUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func quotaCacheTotal(s *Server, tenant string) int64 {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	return s.turnQuotaCache.totals[tenant]
}

func TestTURNQuotaCacheHotPathDoesNotQueryDatabase(t *testing.T) {
	s := quotaCacheFixture(t, 100)
	quotaCacheStore(t, s, quotaCacheTenant, time.Now().UTC().Format("2006-01-02"), 40)
	quotaCacheRefresh(t, s)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Confirm the transaction really monopolizes the one SQLite connection.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var n int
	if err = s.db.QueryRowContext(ctx, "SELECT 1").Scan(&n); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held transaction did not block SQL: %v", err)
	}
	done := make(chan bool, 1)
	go func() {
		for range 64 {
			if !s.authorizeTURNQuota(quotaCacheTenant) {
				done <- false
				return
			}
		}
		s.recordUsage(quotaCacheTenant, 60)
		done <- !s.authorizeTURNQuota(quotaCacheTenant)
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("hot quota decisions ignored known or newly recorded bytes")
		}
	case <-time.After(time.Second):
		_ = tx.Rollback()
		<-done
		t.Fatal("quota hot path waited for the database connection")
	}
	if len(s.pendingUsage) != 1 || quotaCacheTotal(s, quotaCacheTenant) != 100 {
		t.Fatal("quota did not deny exactly at the threshold before any persistence")
	}
}

func TestTURNQuotaCachePendingAndFlushAccounting(t *testing.T) {
	s := quotaCacheFixture(t, 100)
	quotaCacheStore(t, s, quotaCacheTenant, time.Now().UTC().Format("2006-01-02"), 20)
	s.recordUsage(quotaCacheTenant, 30)
	if s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("unknown initial snapshot authorized relay")
	}
	quotaCacheRefresh(t, s)
	if quotaCacheTotal(s, quotaCacheTenant) != 50 || !s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("initial snapshot did not combine stored and pending bytes")
	}
	s.recordUsage(quotaCacheTenant, 25)
	if err := s.flushUsage(); err != nil {
		t.Fatal(err)
	}
	if quotaCacheTotal(s, quotaCacheTenant) != 75 || len(s.pendingUsage) != 0 {
		t.Fatal("flush changed total instead of moving pending bytes into SQLite")
	}
	quotaCacheRefresh(t, s)
	if quotaCacheTotal(s, quotaCacheTenant) != 75 {
		t.Fatal("refresh double counted flushed bytes")
	}
	s.recordUsage(quotaCacheTenant, 25)
	if s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("pending bytes at the exact quota still authorized relay")
	}
	if err := s.flushUsage(); err != nil {
		t.Fatal(err)
	}
	quotaCacheRefresh(t, s)
	if quotaCacheTotal(s, quotaCacheTenant) != 100 || s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("threshold changed after flush/refresh")
	}
}

func TestTURNQuotaCacheRefreshExternalRowsAndAllPendingTenants(t *testing.T) {
	s := quotaCacheFixture(t, 100)
	other := "quota-cache-other"
	quotaCacheAddTenant(t, s, other)
	day := time.Now().UTC().Format("2006-01-02")
	quotaCacheStore(t, s, quotaCacheTenant, day, 20)
	quotaCacheStore(t, s, other, day, 90)
	quotaCacheStore(t, s, quotaCacheTenant, time.Now().UTC().Add(-24*time.Hour).Format("2006-01-02"), 1000000)
	quotaCacheRefresh(t, s)
	s.recordUsage(quotaCacheTenant, 7)
	s.recordUsage(other, 20)
	if _, err := s.db.Exec("UPDATE usage_daily SET bytes=? WHERE tenant_id=? AND day=?", 93, quotaCacheTenant, day); err != nil {
		t.Fatal(err)
	}
	if !s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("hot path unexpectedly queried the externally updated row")
	}
	quotaCacheRefresh(t, s)
	if quotaCacheTotal(s, quotaCacheTenant) != 100 || quotaCacheTotal(s, other) != 110 ||
		s.authorizeTURNQuota(quotaCacheTenant) || s.authorizeTURNQuota(other) {
		t.Fatal("refresh did not atomically combine all today's tenants and pending bytes")
	}
	if !s.authorizeTURNQuota("zero-usage-new-tenant") {
		t.Fatal("complete daily snapshot did not represent absent usage as zero")
	}
}

func TestTURNQuotaCacheDayAndFreshnessFailClosed(t *testing.T) {
	s := quotaCacheFixture(t, 100)
	day := time.Now().UTC().Format("2006-01-02")
	quotaCacheStore(t, s, quotaCacheTenant, day, 20)
	quotaCacheRefresh(t, s)
	s.usageMu.Lock()
	s.turnQuotaCache.day = time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	s.usageMu.Unlock()
	if s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("previous UTC day's snapshot authorized relay")
	}
	s.recordUsage(quotaCacheTenant, 5)
	quotaCacheRefresh(t, s)
	if quotaCacheTotal(s, quotaCacheTenant) != 25 || !s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("new-day refresh lost pending usage")
	}
	s.usageMu.Lock()
	loadedAt := time.Now().Add(-turnQuotaSnapshotMaxAge - time.Second)
	s.turnQuotaCache.loadedAt = loadedAt
	s.usageMu.Unlock()
	s.recordUsage(quotaCacheTenant, 1)
	s.usageMu.Lock()
	unchanged := s.turnQuotaCache.loadedAt.Equal(loadedAt)
	s.usageMu.Unlock()
	if !unchanged || s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("recording bytes refreshed an expired durable snapshot")
	}
	quotaCacheRefresh(t, s)
	if quotaCacheTotal(s, quotaCacheTenant) != 26 || !s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("fresh snapshot failed to restore valid quota")
	}
}

func TestTURNQuotaCacheRefreshErrorsInvalidateSnapshot(t *testing.T) {
	for _, mode := range []string{"invalid_integer", "missing_table", "closed_database"} {
		t.Run(mode, func(t *testing.T) {
			s := quotaCacheFixture(t, 100)
			day := time.Now().UTC().Format("2006-01-02")
			quotaCacheStore(t, s, quotaCacheTenant, day, 20)
			quotaCacheRefresh(t, s)
			switch mode {
			case "invalid_integer":
				_, err := s.db.Exec("UPDATE usage_daily SET bytes=? WHERE tenant_id=?", "invalid-counter", quotaCacheTenant)
				if err != nil {
					t.Fatal(err)
				}
			case "missing_table":
				if _, err := s.db.Exec("DROP TABLE usage_daily"); err != nil {
					t.Fatal(err)
				}
			case "closed_database":
				if err := s.db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.refreshTURNQuotaUsage(context.Background()); err == nil {
				t.Fatal("invalid SQL snapshot succeeded")
			}
			if s.authorizeTURNQuota(quotaCacheTenant) {
				t.Fatal("failed refresh retained an older authorizing snapshot")
			}
		})
	}
}

func TestTURNQuotaCacheCanceledRefreshJoins(t *testing.T) {
	s := quotaCacheFixture(t, 100)
	quotaCacheRefresh(t, s)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	waits := s.db.Stats().WaitCount
	go func() { done <- s.refreshTURNQuotaUsage(ctx) }()
	deadline := time.Now().Add(time.Second)
	for s.db.Stats().WaitCount == waits && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked refresh cancellation: %v", err)
		}
	case <-time.After(time.Second):
		_ = tx.Rollback()
		<-done
		t.Fatal("canceled refresh remained blocked on SQLite")
	}
	if s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("canceled refresh left quota usable")
	}
}

func TestTURNQuotaCacheUnlimitedAndOverflow(t *testing.T) {
	unlimited := &Server{}
	if !unlimited.authorizeTURNQuota(quotaCacheTenant) || unlimited.refreshTURNQuotaUsage(nil) != nil {
		t.Fatal("zero quota touched nonexistent database/cache")
	}
	unlimited.recordTURNQuotaUsageLocked(quotaCacheTenant, "", 1)
	if unlimited.turnQuotaCache != nil {
		t.Fatal("zero quota allocated a byte cache")
	}

	s := quotaCacheFixture(t, math.MaxInt64)
	quotaCacheStore(t, s, quotaCacheTenant, time.Now().UTC().Format("2006-01-02"), int64(math.MaxInt64-1))
	quotaCacheRefresh(t, s)
	s.recordUsage(quotaCacheTenant, 10)
	if quotaCacheTotal(s, quotaCacheTenant) != math.MaxInt64 || s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("quota counter overflow wrapped into an authorizing value")
	}
}

func TestTURNQuotaCacheConcurrentRecordingFlushAndRefresh(t *testing.T) {
	s := quotaCacheFixture(t, 101)
	quotaCacheRefresh(t, s)
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 25 {
				s.recordUsage(quotaCacheTenant, 1)
			}
		}()
	}
	errors := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for range 16 {
			if err := s.flushUsage(); err != nil {
				errors <- err
				return
			}
			if err := s.refreshTURNQuotaUsage(context.Background()); err != nil {
				errors <- err
				return
			}
		}
	}()
	workers.Wait()
	select {
	case err := <-errors:
		t.Fatal(err)
	default:
	}
	quotaCacheRefresh(t, s)
	if quotaCacheTotal(s, quotaCacheTenant) != 100 || !s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("concurrent flush/refresh lost or double-counted recorded bytes")
	}
	s.recordUsage(quotaCacheTenant, 1)
	if s.authorizeTURNQuota(quotaCacheTenant) {
		t.Fatal("final byte at quota was not rejected immediately")
	}
}
