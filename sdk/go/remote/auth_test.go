package remote

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testAuthSession = "bdb4e3bf-d91c-4e2c-8925-c17082e97645"

func authFixtureCredentials(ttl time.Duration) AuthCredentials {
	now := time.Now().UTC()
	return AuthCredentials{AuthSessionID: testAuthSession, Token: strings.Repeat("1", 64), RefreshToken: strings.Repeat("2", 64), Generation: 1,
		TokenExpiresAt: now.Add(ttl).Truncate(time.Millisecond), RefreshExpiresAt: now.Add(time.Hour).Truncate(time.Millisecond)}
}

type authFixture struct {
	mu                 sync.Mutex
	current            AuthCredentials
	predecessor        string
	pending            *AuthPending
	receipt            AuthCredentials
	ttl                time.Duration
	rotations, replays int
	dropFirst          bool
	badReceipt         bool
	refreshDelay       time.Duration
	server             *httptest.Server
}

func newAuthFixture(t *testing.T, ttl time.Duration) *authFixture {
	t.Helper()
	f := &authFixture{current: authFixtureCredentials(ttl), ttl: ttl}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}
func (f *authFixture) initial() AuthCredentials { f.mu.Lock(); defer f.mu.Unlock(); return f.current }
func (f *authFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/v1/auth/refresh" {
		if r.Header.Get("Authorization") != "Bearer "+f.current.Token {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error_code":"access_superseded"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}
	if f.refreshDelay > 0 {
		time.Sleep(f.refreshDelay)
	}
	var p AuthPending
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		w.WriteHeader(400)
		return
	}
	bearer := r.Header.Get("Authorization")
	var receipt AuthCredentials
	if f.pending != nil && bearer == "Bearer "+f.predecessor && p == *f.pending {
		f.replays++
		receipt = f.receipt
	} else {
		if bearer != "Bearer "+f.current.RefreshToken || p.AuthSessionID != f.current.AuthSessionID || p.ExpectedGeneration != f.current.Generation {
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"error_code":"auth_conflict"}`))
			return
		}
		f.predecessor = f.current.RefreshToken
		f.pending = &p
		f.current.Token = p.NextToken
		f.current.RefreshToken = p.NextRefreshToken
		f.current.Generation++
		f.current.TokenExpiresAt = time.Now().Add(f.ttl).UTC().Truncate(time.Millisecond)
		f.current.RefreshExpiresAt = time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
		f.rotations++
		f.receipt = f.current
		receipt = f.current
		if f.dropFirst {
			f.dropFirst = false
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
	}
	generation := receipt.Generation
	if f.badReceipt {
		generation += 2
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"auth_session_id": receipt.AuthSessionID, "generation": generation,
		"token_expires_at": receipt.TokenExpiresAt, "refresh_expires_at": receipt.RefreshExpiresAt})
}

type memoryAuthStore struct {
	mu                                    sync.Mutex
	credentials                           AuthCredentials
	pending                               *AuthPending
	beginError, prepareError, commitError error
	begins, ends, prepares, commits       int
}

func (s *memoryAuthStore) Begin() (AuthCredentials, *AuthPending, error) {
	s.mu.Lock()
	s.begins++
	var pending *AuthPending
	if s.pending != nil {
		p := *s.pending
		pending = &p
	}
	return s.credentials, pending, s.beginError
}
func (s *memoryAuthStore) Prepare(c AuthCredentials, p AuthPending) error {
	s.prepares++
	if s.prepareError != nil {
		return s.prepareError
	}
	s.pending = &p
	return nil
}
func (s *memoryAuthStore) Commit(c AuthCredentials, p AuthPending) error {
	s.commits++
	if s.commitError != nil {
		return s.commitError
	}
	s.credentials = c
	s.pending = nil
	return nil
}
func (s *memoryAuthStore) End() { s.ends++; s.mu.Unlock() }
func (s *memoryAuthStore) snapshot() (AuthCredentials, *AuthPending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var p *AuthPending
	if s.pending != nil {
		q := *s.pending
		p = &q
	}
	return s.credentials, p
}
func authClient(t *testing.T, f *authFixture, initial AuthCredentials, storage AuthStorage) *Client {
	t.Helper()
	client, err := NewWithAuth(Options{URL: f.server.URL, Timeout: time.Second}, AuthOptions{Credentials: initial, Storage: storage})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}
func TestAuthProactiveIdleAndCopiedBearer(t *testing.T) {
	f := newAuthFixture(t, 250*time.Millisecond)
	client := authClient(t, f, f.initial(), nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, err := client.AuthCredentials()
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Generation >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	snapshot, err := client.AuthCredentials()
	if err != nil || snapshot.Generation < 3 {
		t.Fatalf("idle refresh did not rotate repeatedly: generation=%d err=%v", snapshot.Generation, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := client.Request("GET", "/v1/me", nil, nil); err != nil {
				t.Errorf("concurrent refreshed request: %v", err)
			}
		}()
	}
	wg.Wait()
}
func TestAuthExpiredAccessWithLiveRefresh(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	initial := f.initial()
	initial.TokenExpiresAt = time.Now().Add(-time.Second)
	client := authClient(t, f, initial, nil)
	if _, err := client.Request("GET", "/v1/me", nil, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.AuthCredentials()
	if err != nil || snapshot.Generation != 2 {
		t.Fatalf("expired access not refreshed: generation=%d err=%v", snapshot.Generation, err)
	}
}
func TestAuthPendingReplayAfterPredecessorRefreshExpiry(t *testing.T) {
	for _, test := range []struct {
		name           string
		expiredReceipt bool
	}{
		{"live_receipt_access", false},
		{"expired_receipt_access", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAuthFixture(t, time.Hour)
			initial := f.initial()
			initial.TokenExpiresAt = time.Now().Add(100 * time.Millisecond).UTC().Truncate(time.Millisecond)
			initial.RefreshExpiresAt = time.Now().Add(250 * time.Millisecond).UTC().Truncate(time.Millisecond)
			f.mu.Lock()
			f.current = initial
			f.dropFirst = true
			f.mu.Unlock()
			pending := AuthPending{AuthSessionID: initial.AuthSessionID, ExpectedGeneration: initial.Generation,
				RequestID: "8c0f55b1-eb20-40c3-87b8-c480b6576e88", NextToken: strings.Repeat("3", 64), NextRefreshToken: strings.Repeat("4", 64)}
			// The journal was durable before RPC. Bootstrap deliberately has no
			// refresh timer, so a dropped reply deterministically represents a
			// crashed process without an in-process retry committing the journal.
			store := &memoryAuthStore{credentials: initial, pending: &pending}
			bootstrap, err := New(Options{URL: f.server.URL, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			_, err = bootstrap.Request("POST", "/v1/auth/refresh", &initial.RefreshToken, pending)
			if closeErr := bootstrap.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err == nil {
				t.Fatal("dropped committed response unexpectedly succeeded")
			}
			if test.expiredReceipt {
				f.mu.Lock()
				f.receipt.TokenExpiresAt = initial.TokenExpiresAt
				f.current.TokenExpiresAt = initial.TokenExpiresAt
				f.mu.Unlock()
			}
			if delay := time.Until(initial.RefreshExpiresAt) + 20*time.Millisecond; delay > 0 {
				time.Sleep(delay)
			}
			f.mu.Lock()
			childLive := f.current.RefreshExpiresAt.After(time.Now())
			f.mu.Unlock()
			if initial.RefreshExpiresAt.After(time.Now()) || !childLive {
				t.Fatal("fixture did not cross predecessor-only refresh expiry")
			}
			restarted := authClient(t, f, initial, store)
			if _, err := restarted.Request("GET", "/v1/me", nil, nil); err != nil {
				t.Fatal(err)
			}
			current, journal := store.snapshot()
			wantGeneration, wantRotations := uint64(2), 1
			if test.expiredReceipt {
				wantGeneration, wantRotations = 3, 2
			}
			f.mu.Lock()
			rotations, replays := f.rotations, f.replays
			f.mu.Unlock()
			if current.Generation != wantGeneration || rotations != wantRotations || replays != 1 || journal != nil || !current.RefreshExpiresAt.After(time.Now()) {
				t.Fatalf("pending expiry recovery: generation=%d rotations=%d replays=%d pending=%t", current.Generation, rotations, replays, journal != nil)
			}
		})
	}
}
func TestAuthExpiredRefreshWithoutPendingFailsClosed(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	initial := f.initial()
	initial.RefreshExpiresAt = time.Now().Add(-time.Second)
	client := authClient(t, f, initial, nil)
	if err := client.RefreshAuth(); err == nil {
		t.Fatal("expired refresh without pending unexpectedly accepted")
	}
	f.mu.Lock()
	rotations, replays := f.rotations, f.replays
	f.mu.Unlock()
	if rotations != 0 || replays != 0 {
		t.Fatal("expired refresh without pending sent an RPC")
	}
}

func TestAuthLostReplyExactPendingReplay(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.dropFirst = true
	initial := f.initial()
	store := &memoryAuthStore{credentials: initial}
	client := authClient(t, f, initial, store)
	if err := client.RefreshAuth(); err == nil {
		t.Fatal("lost response unexpectedly succeeded")
	}
	_, pending := store.snapshot()
	if pending == nil {
		t.Fatal("ambiguous refresh lost pending attempt")
	}
	if err := client.RefreshAuth(); err != nil {
		t.Fatal(err)
	}
	stored, pending := store.snapshot()
	if pending != nil || stored.Generation != 2 {
		t.Fatal("receipt did not commit pending attempt")
	}
	f.mu.Lock()
	rotations, replays := f.rotations, f.replays
	f.mu.Unlock()
	if rotations != 1 || replays != 1 {
		t.Fatalf("not exact-once rotation: rotations=%d replays=%d", rotations, replays)
	}
}
func TestAuthEarlyPendingRetriesWhileIdle(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.dropFirst = true
	client := authClient(t, f, f.initial(), nil)
	if err := client.RefreshAuth(); err == nil {
		t.Fatal("lost reply unexpectedly succeeded")
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		current, err := client.AuthCredentials()
		if err != nil {
			t.Fatal(err)
		}
		if current.Generation == 2 {
			f.mu.Lock()
			rotations, replays := f.rotations, f.replays
			f.mu.Unlock()
			if rotations != 1 || replays != 1 {
				t.Fatal("idle pending did not replay original receipt")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("pending retry waited for the old access deadline")
}
func TestAuthConcurrentRefreshSingleFlight(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.refreshDelay = 150 * time.Millisecond
	client := authClient(t, f, f.initial(), nil)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := client.RefreshAuth(); err != nil {
				t.Errorf("concurrent refresh: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	f.mu.Lock()
	rotations := f.rotations
	f.mu.Unlock()
	if rotations != 1 {
		t.Fatalf("refresh storm: %d rotations", rotations)
	}
}

func TestAuthExpiredReceiptThenFreshRotation(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.dropFirst = true
	initial := f.initial()
	store := &memoryAuthStore{credentials: initial}
	client := authClient(t, f, initial, store)
	if err := client.RefreshAuth(); err == nil {
		t.Fatal("lost reply unexpectedly succeeded")
	}
	f.mu.Lock()
	f.receipt.TokenExpiresAt = time.Now().Add(-time.Hour).UTC()
	f.current.TokenExpiresAt = f.receipt.TokenExpiresAt
	f.mu.Unlock()
	if err := client.RefreshAuth(); err != nil {
		t.Fatal(err)
	}
	current, err := client.AuthCredentials()
	if err != nil || current.Generation != 3 || !current.TokenExpiresAt.After(time.Now()) {
		t.Fatalf("expired receipt did not obtain fresh child credentials: generation=%d err=%v", current.Generation, err)
	}
	f.mu.Lock()
	rotations, replays := f.rotations, f.replays
	f.mu.Unlock()
	if rotations != 2 || replays != 1 {
		t.Fatal("expired receipt recovery was not one replay then one fresh rotation")
	}
}

func TestAuthStorageErrorsAlwaysEndAndKeepPending(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	initial := f.initial()
	sentinel := errors.New("fixture storage failure")
	store := &memoryAuthStore{credentials: initial, beginError: sentinel}
	client := authClient(t, f, initial, store)
	if err := client.RefreshAuth(); !errors.Is(err, sentinel) {
		t.Fatalf("Begin failure not propagated: %v", err)
	}
	store.mu.Lock()
	if store.begins != store.ends {
		t.Error("Begin failure skipped End")
	}
	store.beginError = nil
	store.commitError = sentinel
	store.mu.Unlock()
	if err := client.RefreshAuth(); !errors.Is(err, sentinel) {
		t.Fatalf("Commit failure not propagated: %v", err)
	}
	_, pending := store.snapshot()
	if pending == nil {
		t.Fatal("failed commit lost pending")
	}
	store.mu.Lock()
	store.commitError = nil
	store.mu.Unlock()
	if err := client.RefreshAuth(); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := store.snapshot()
	if snapshot.Generation != 2 {
		t.Fatal("commit recovery made a second rotation")
	}
}
func TestAuthAdoptsNewerSharedCredentials(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	initial := f.initial()
	store := &memoryAuthStore{credentials: initial}
	first := authClient(t, f, initial, store)
	second := authClient(t, f, initial, store)
	if err := first.RefreshAuth(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Request("GET", "/v1/me", nil, nil); err != nil {
		t.Fatal(err)
	}
	c, err := second.AuthCredentials()
	if err != nil || c.Generation != 2 {
		t.Fatal("second client failed to adopt committed generation")
	}
	f.mu.Lock()
	count := f.rotations
	f.mu.Unlock()
	if count != 1 {
		t.Fatal("shared profile caused extra rotation")
	}
}
func TestAuthNoBlindMutationReplay(t *testing.T) {
	initial := authFixtureCredentials(time.Hour)
	var mutations atomic.Int32
	var refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/auth/refresh" {
			refreshes.Add(1)
		} else {
			mutations.Add(1)
		}
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error_code":"refresh_revoked"}`))
	}))
	defer server.Close()
	client, err := NewWithAuth(Options{URL: server.URL}, AuthOptions{Credentials: initial})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Request("POST", "/v1/brokers", nil, map[string]any{"name": "test"}); err == nil {
		t.Fatal("mutation unexpectedly authorized")
	}
	if mutations.Load() != 1 || refreshes.Load() != 0 {
		t.Fatal("SDK replayed mutation or password-authenticated")
	}
	explicit := "scoped-device-token"
	if _, err := client.Request("GET", "/v1/brokers/id", &explicit, nil); err == nil {
		t.Fatal("scoped request unexpectedly authorized")
	}
	if refreshes.Load() != 0 {
		t.Fatal("explicit scoped bearer triggered account refresh")
	}
}
func TestAuthRejectsMalformedReceipt(t *testing.T) {
	f := newAuthFixture(t, time.Hour)
	f.badReceipt = true
	initial := f.initial()
	store := &memoryAuthStore{credentials: initial}
	client := authClient(t, f, initial, store)
	if err := client.RefreshAuth(); err == nil {
		t.Fatal("wrong-generation receipt accepted")
	}
	current, pending := store.snapshot()
	if current.Generation != 1 || pending == nil {
		t.Fatal("bad receipt committed or lost pending")
	}
}
func TestAuthCloseCancelsTransportAndJoinsCallbacks(t *testing.T) {
	initial := authFixtureCredentials(-time.Second)
	entered := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	client, err := NewWithAuth(Options{URL: server.URL}, AuthOptions{Credentials: initial})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		client.Close()
		t.Fatal("refresh did not enter transport")
	}
	var requests sync.WaitGroup
	for i := 0; i < 8; i++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			if _, err := client.Request("GET", "/v1/me", nil, nil); err == nil {
				t.Error("cancelled request unexpectedly succeeded")
			}
		}()
	}
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	requests.Wait()
	if time.Since(start) > 3*time.Second {
		t.Fatal("Close did not cancel refresh transport and single-flight waiters")
	}
}
