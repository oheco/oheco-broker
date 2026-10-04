package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"
	"golang.org/x/crypto/bcrypt"
)

// TestLocalHTTPFixture is opt-in, loopback-only, and exits gracefully on SIGTERM.
// It exposes a real HTTP+TURN endpoint to independently built native C fixtures.
func TestLocalHTTPFixture(t *testing.T) {
	dir := os.Getenv("CONTROL_FIXTURE_DIR")
	if dir == "" {
		t.Skip("opt-in native SDK fixture")
	}
	s := apiFixture(t, Config{DBPath: filepath.Join(dir, "control.sqlite"), TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true}})
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	h := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- h.Serve(l) }()
	fmt.Printf("CONTROL_FIXTURE_URL=http://%s\n", l.Addr())
	fmt.Printf("CONTROL_FIXTURE_TURN=%s\n", s.TURNAddr())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = h.Shutdown(closeCtx); e != nil {
		t.Error(e)
	}
	if e = <-errCh; e != http.ErrServerClosed {
		t.Error(e)
	}
}

const fixturePassword = "correct-horse-battery-staple"
const fixtureAdmin = "isolated-test-admin-never-production"

func apiFixture(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(t.TempDir(), "private", "control.sqlite")
	}
	if cfg.AdminToken == "" {
		cfg.AdminToken = fixtureAdmin
	}
	// Go TempDir uses 0777 for numbered children beneath a private root.
	// Tighten the fixture's actual database parent, not HOME or global settings.
	if cfg.DBPath != ":memory:" {
		if e := os.MkdirAll(filepath.Dir(cfg.DBPath), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(filepath.Dir(cfg.DBPath), 0700); e != nil {
			t.Fatal(e)
		}
	}
	s, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	})
	return s
}
func apiCall(t *testing.T, s *Server, method, path, token string, body any, status int) map[string]any {
	t.Helper()
	var b []byte
	if body != nil {
		var e error
		b, e = json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("%s %s status=%d want=%d response=%s", method, path, w.Code, status, w.Body.String())
	}
	var out map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatalf("response not JSON: %v", e)
	}
	return out
}
func awaitAPIUsage(t *testing.T, s *Server, path, token string, total int) map[string]any {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		u := apiCall(t, s, "GET", path, token, nil, 200)
		if u["lifetime"] == float64(total) {
			return u
		}
		select {
		case <-deadline.C:
			t.Fatalf("forwarded byte accounting did not settle: %v want=%d", u["lifetime"], total)
		case <-tick.C:
		}
	}
}
func fixtureRegister(t *testing.T, s *Server, name string) (string, string) {
	t.Helper()
	r := apiCall(t, s, "POST", "/v1/tenants/register", "", map[string]any{"name": name, "password": fixturePassword, "email": name + "@example.invalid"}, 201)
	tenant := r["tenant"].(map[string]any)
	if tenant["relay_enabled"] != false {
		t.Fatal("relay was enabled by default")
	}
	return tenant["id"].(string), r["token"].(string)
}
func fixtureBroker(t *testing.T, s *Server, token, name string) (string, string) {
	t.Helper()
	r := apiCall(t, s, "POST", "/v1/brokers", token, map[string]any{"name": name}, 201)
	return r["broker"].(map[string]any)["id"].(string), r["device_token"].(string)
}
func fixtureSession(t *testing.T, s *Server, token, broker string) (string, string) {
	t.Helper()
	r := apiCall(t, s, "POST", "/v1/sessions", token, map[string]any{"broker_id": broker, "relay_mode": "auto"}, 201)
	return r["session_id"].(string), r["session_token"].(string)
}

func TestAccountsPolicyPasswordsAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.sqlite")
	s := apiFixture(t, Config{DBPath: path})
	id, token := fixtureRegister(t, s, "alice")
	id2, _ := fixtureRegister(t, s, "bob")
	if len(id) != 36 || id == id2 {
		t.Fatal("tenant IDs are not independent UUIDs")
	}
	var h1, h2 string
	if e := s.db.QueryRow("SELECT password_hash FROM tenants WHERE id=?", id).Scan(&h1); e != nil {
		t.Fatal(e)
	}
	if e := s.db.QueryRow("SELECT password_hash FROM tenants WHERE id=?", id2).Scan(&h2); e != nil {
		t.Fatal(e)
	}
	if h1 == h2 || h1 == fixturePassword {
		t.Fatal("password hashes are not salted")
	}
	if c, e := bcrypt.Cost([]byte(h1)); e != nil || c != 12 {
		t.Fatal("wrong bcrypt cost")
	}
	apiCall(t, s, "POST", "/v1/tenants/register", "", map[string]any{"name": "ALICE", "password": fixturePassword}, 409)
	apiCall(t, s, "POST", "/v1/tenants/login", "", map[string]any{"name": "alice", "password": "wrong-password"}, 401)
	apiCall(t, s, "POST", "/v1/tenants/login", "", map[string]any{"name": "unknown", "password": "wrong-password"}, 401)
	me := apiCall(t, s, "GET", "/v1/me", token, nil, 200)
	encoded, _ := json.Marshal(me)
	if strings.Contains(string(encoded), "password") {
		t.Fatal("password material exposed")
	}
	fallback := apiCall(t, s, "POST", "/v1/tenants/register", "", map[string]any{}, 201)
	tenant := fallback["tenant"].(map[string]any)
	if tenant["name"] == "" || tenant["email"] == "" {
		t.Fatal("missing fallback identity")
	}
	if _, ok := fallback["password"]; ok {
		t.Fatal("generated password exposed")
	}
	apiCall(t, s, "PATCH", "/v1/admin/settings", fixtureAdmin, map[string]any{"registration_policy": "approval"}, 200)
	pending := apiCall(t, s, "POST", "/v1/tenants/register", "", map[string]any{"name": "pending", "password": fixturePassword}, 201)
	pid := pending["tenant"].(map[string]any)["id"].(string)
	pt := pending["token"].(string)
	apiCall(t, s, "GET", "/v1/me", pt, nil, 200)
	pc := apiCall(t, s, "GET", "/v1/capabilities", pt, nil, 200)
	if pc["status"] != "pending" {
		t.Fatal("pending status unreadable")
	}
	apiCall(t, s, "POST", "/v1/brokers", pt, map[string]any{"name": "forbidden"}, 403)
	apiCall(t, s, "POST", "/v1/me/password", pt, map[string]any{"password": fixturePassword}, 403)
	filtered := apiCall(t, s, "GET", "/v1/admin/tenants?status=pending", fixtureAdmin, nil, 200)
	if len(filtered["tenants"].([]any)) != 1 {
		t.Fatal("admin status filter ignored")
	}
	apiCall(t, s, "GET", "/v1/admin/tenants?status=bad", fixtureAdmin, nil, 400)
	apiCall(t, s, "POST", "/v1/admin/tenants/"+pid+"/approve", fixtureAdmin, nil, 200)
	apiCall(t, s, "POST", "/v1/tenants/login", "", map[string]any{"name": "pending", "password": fixturePassword}, 200)
	apiCall(t, s, "PATCH", "/v1/admin/settings", fixtureAdmin, map[string]any{"registration_policy": "closed"}, 200)
	apiCall(t, s, "POST", "/v1/tenants/register", "", map[string]any{}, 403)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened := apiFixture(t, Config{DBPath: path, RegistrationPolicy: "open"})
	apiCall(t, reopened, "POST", "/v1/tenants/register", "", map[string]any{}, 403)
	apiCall(t, reopened, "GET", "/v1/me", token, nil, 200)
}

func TestAccountUpdatesRevokeAllScopes(t *testing.T) {
	s := apiFixture(t, Config{})
	id, account := fixtureRegister(t, s, "updates")
	broker, device := fixtureBroker(t, s, account, "one")
	sid, session := fixtureSession(t, s, account, broker)
	r := apiCall(t, s, "PATCH", "/v1/me", account, map[string]any{"email": "new@example.invalid", "name": "renamed"}, 200)
	fresh := r["token"].(string)
	apiCall(t, s, "GET", "/v1/me", account, nil, 401)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/heartbeat", device, nil, 401)
	apiCall(t, s, "GET", "/v1/sessions/"+sid, session, nil, 401)
	rotated := apiCall(t, s, "POST", "/v1/brokers/"+broker+"/token", fresh, nil, 200)
	device = rotated["device_token"].(string)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/heartbeat", device, nil, 200)
	r = apiCall(t, s, "POST", "/v1/me/password", fresh, map[string]any{"password": "another-secure-password"}, 200)
	fresh2 := r["token"].(string)
	apiCall(t, s, "GET", "/v1/me", fresh, nil, 401)
	apiCall(t, s, "POST", "/v1/tenants/login", "", map[string]any{"name": "renamed", "password": fixturePassword}, 401)
	apiCall(t, s, "POST", "/v1/tenants/login", "", map[string]any{"name": "renamed", "password": "another-secure-password"}, 200)
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/disable", fixtureAdmin, nil, 200)
	apiCall(t, s, "GET", "/v1/me", fresh2, nil, 401)
	apiCall(t, s, "POST", "/v1/tenants/login", "", map[string]any{"name": "renamed", "password": "another-secure-password"}, 403)
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/enable", fixtureAdmin, nil, 200)
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/reset-password", fixtureAdmin, map[string]any{"password": "admin-reset-secure-password"}, 200)
	login := apiCall(t, s, "POST", "/v1/tenants/login", "", map[string]any{"name": "renamed", "password": "admin-reset-secure-password"}, 200)
	lt := login["token"].(string)
	apiCall(t, s, "POST", "/v1/tenants/logout", lt, nil, 200)
	apiCall(t, s, "GET", "/v1/me", lt, nil, 401)
}

func TestDirectionalMailboxesScopeBoundsAndLease(t *testing.T) {
	s := apiFixture(t, Config{MaxMessagesPerDirection: 3, MaxMessageBytes: 64})
	_, account := fixtureRegister(t, s, "signals")
	_, other := fixtureRegister(t, s, "other")
	broker, device := fixtureBroker(t, s, account, "host")
	second, device2 := fixtureBroker(t, s, account, "host2")
	apiCall(t, s, "POST", "/v1/brokers", account, map[string]any{"name": "host"}, 409)
	apiCall(t, s, "PATCH", "/v1/brokers/"+second, account, map[string]any{"name": "host"}, 409)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/token", account, nil, 409)
	apiCall(t, s, "GET", "/v1/brokers/"+broker, other, nil, 404)
	sid, session := fixtureSession(t, s, account, broker)
	sid2, session2 := fixtureSession(t, s, account, second)
	apiCall(t, s, "GET", "/v1/brokers/"+broker+"/sessions", device2, nil, 403)
	apiCall(t, s, "GET", "/v1/sessions/"+sid+"/messages", session2, nil, 403)
	apiCall(t, s, "GET", "/v1/sessions/"+sid+"/messages", account, nil, 403)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", session, map[string]any{"peer_authenticated": true, "relay": false}, 403)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": false, "relay": false}, 400)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": false}, 200)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", session, Message{1, "client PAKE opaque"}, 201)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", session, Message{1, "client PAKE opaque"}, 200)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", session, Message{1, "changed"}, 409)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", session, Message{3, "gap"}, 409)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", device, Message{1, "broker PAKE opaque"}, 201)
	clientRead := apiCall(t, s, "GET", "/v1/sessions/"+sid+"/messages?after=0", session, nil, 200)
	msgs := clientRead["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["data"] != "broker PAKE opaque" {
		t.Fatal("client read wrong direction")
	}
	brokerRead := apiCall(t, s, "GET", "/v1/sessions/"+sid+"/messages", device, nil, 200)
	if brokerRead["messages"].([]any)[0].(map[string]any)["data"] != "client PAKE opaque" {
		t.Fatal("broker read wrong direction")
	}
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", session, Message{2, strings.Repeat("x", 65)}, 400)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", session, Message{2, "next"}, 201)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", session, Message{3, "last"}, 201)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/messages", session, Message{4, "overflow"}, 400)
	apiCall(t, s, "GET", "/v1/sessions/"+sid+"/messages?after=-1", session, nil, 400)
	old, _ := s.session(sid)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/heartbeat", session, nil, 200)
	current, _ := s.session(sid)
	if current.ExpiresAt.Before(old.ExpiresAt) {
		t.Fatal("session lease shrank")
	}
	if _, e := s.db.Exec("UPDATE brokers SET lease_expires_at=0 WHERE id=?", broker); e != nil {
		t.Fatal(e)
	}
	apiCall(t, s, "GET", "/v1/sessions/"+sid, session, nil, 409)
	apiCall(t, s, "GET", "/v1/brokers/"+broker+"/sessions", device, nil, 409)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/heartbeat", device, nil, 200)
	apiCall(t, s, "GET", "/v1/sessions/"+sid+"/capabilities", session, nil, 200)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/offline", device, nil, 200)
	apiCall(t, s, "GET", "/v1/sessions/"+sid, session, nil, 401)
	rotated := apiCall(t, s, "POST", "/v1/brokers/"+broker+"/token", account, nil, 200)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/heartbeat", device, nil, 401)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/heartbeat", rotated["device_token"].(string), nil, 200)
	apiCall(t, s, "DELETE", "/v1/sessions/"+sid2, device2, nil, 200)
	apiCall(t, s, "GET", "/v1/sessions/"+sid2, session2, nil, 401)
	apiCall(t, s, "DELETE", "/v1/brokers/"+broker, account, nil, 200)
}

func TestExpiredSessionAndJSONStrictness(t *testing.T) {
	s := apiFixture(t, Config{})
	_, account := fixtureRegister(t, s, "expiry")
	broker, device := fixtureBroker(t, s, account, "host")
	sid, session := fixtureSession(t, s, account, broker)
	if _, e := s.db.Exec("UPDATE sessions SET expires_at=0 WHERE id=?", sid); e != nil {
		t.Fatal(e)
	}
	apiCall(t, s, "GET", "/v1/sessions/"+sid, session, nil, 410)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true}, 410)
	apiCall(t, s, "POST", "/v1/sessions", account, map[string]any{"broker_id": broker, "relay_mode": "force"}, 403)
	apiCall(t, s, "GET", "/v1/admin/tenants", account, nil, 401)
	for _, body := range []string{`{"name":"x"} trailing`, `{"name":"x"} {}`, `{"name":"x","unknown":1}`, strings.Repeat(" ", 65537) + `{}`} {
		r := httptest.NewRequest("POST", "/v1/brokers", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+account)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("bad JSON accepted: status=%d", w.Code)
		}
	}
}

func TestUsageRollingBucketsBrokerIsolationAndFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.sqlite")
	s := apiFixture(t, Config{DBPath: path})
	id, account := fixtureRegister(t, s, "usage")
	broker, _ := fixtureBroker(t, s, account, "host")
	other, _ := fixtureBroker(t, s, account, "other")
	s.recordRelayUsage(id, broker, "opaque-session", 100)
	s.recordRelayUsage(id, other, "other-session", 50)
	u := apiCall(t, s, "GET", "/v1/me/usage", account, nil, 200)
	if u["lifetime"] != float64(150) || u["days_1"] != float64(150) {
		t.Fatal("wrong batched tenant usage", u)
	}
	u = apiCall(t, s, "GET", "/v1/brokers/"+broker+"/usage", account, nil, 200)
	if u["lifetime"] != float64(100) {
		t.Fatal("broker attribution lost", u)
	}
	for _, v := range []struct {
		age time.Duration
		n   int64
	}{{48 * time.Hour, 200}, {10 * 24 * time.Hour, 300}, {40 * 24 * time.Hour, 400}} {
		bucket := time.Now().UTC().Add(-v.age).Truncate(time.Minute).Format(time.RFC3339)
		if _, e := s.db.Exec("INSERT INTO usage_buckets(tenant_id,bucket,bytes) VALUES(?,?,?)", id, bucket, v.n); e != nil {
			t.Fatal(e)
		}
		if _, e := s.db.Exec("INSERT INTO usage_daily(tenant_id,day,bytes) VALUES(?,?,?)", id, bucket[:10], v.n); e != nil {
			t.Fatal(e)
		}
	}
	u = apiCall(t, s, "GET", "/v1/usage", account, nil, 200)
	if u["days_1"] != float64(150) || u["days_7"] != float64(350) || u["days_30"] != float64(650) || u["lifetime"] != float64(1050) {
		t.Fatal("rolling totals incorrect", u)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened := apiFixture(t, Config{DBPath: path})
	u = apiCall(t, reopened, "GET", "/v1/admin/usage?tenant_id="+id+"&broker_id="+broker, fixtureAdmin, nil, 200)
	if u["lifetime"] != float64(100) {
		t.Fatal("usage not persistent", u)
	}
}

func TestAdminPaginationAllRecordsFiltersAndBounds(t *testing.T) {
	s := apiFixture(t, Config{})
	tx, e := s.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	statuses := []string{"active", "pending", "disabled"}
	expected := map[string]int{}
	firstTenant := ""
	// Seed rows directly: pagination is independent of bcrypt/login behavior.
	for i := 0; i < 1001; i++ {
		id := uuid()
		if i == 0 {
			firstTenant = id
		}
		status := statuses[i%3]
		expected[status]++
		name := fmt.Sprintf("paged-tenant-%04d", i)
		if _, e = tx.Exec("INSERT INTO tenants(id,name,email,password_hash,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", id, name, name+"@example.invalid", "not-used-for-login", status, int64(i+1), int64(i+1)); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec("INSERT INTO brokers(id,tenant_id,name,lease_expires_at,created_at) VALUES(?,?,?,?,?)", uuid(), id, fmt.Sprintf("broker-%04d", i), now()+60000, int64(i+1)); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	for _, resource := range []string{"tenants", "brokers"} {
		path := "/v1/admin/" + resource
		page := apiCall(t, s, "GET", path, fixtureAdmin, nil, 200)
		if len(page[resource].([]any)) != 100 || page["next_offset"] != float64(100) {
			t.Fatal("default admin page incorrect")
		}
		seen := map[string]bool{}
		offset := 0
		for {
			page = apiCall(t, s, "GET", fmt.Sprintf("%s?limit=1000&offset=%d", path, offset), fixtureAdmin, nil, 200)
			for _, row := range page[resource].([]any) {
				id := row.(map[string]any)["id"].(string)
				if seen[id] {
					t.Fatal("pagination repeated a record")
				}
				seen[id] = true
			}
			next := page["next_offset"]
			if next == nil {
				break
			}
			offset = int(next.(float64))
		}
		if len(seen) != 1001 {
			t.Fatalf("%s pagination omitted records: %d", resource, len(seen))
		}
		empty := apiCall(t, s, "GET", path+"?limit=1&offset=1001", fixtureAdmin, nil, 200)
		if len(empty[resource].([]any)) != 0 || empty["next_offset"] != nil {
			t.Fatal("empty page has invalid cursor")
		}
		for _, query := range []string{"limit=-1", "limit=0", "limit=1001", "limit=abc", "limit=", "limit=1&limit=2", "offset=-1", "offset=1000000001", "offset=abc", "offset=", "offset=1&offset=2"} {
			apiCall(t, s, "GET", path+"?"+query, fixtureAdmin, nil, 400)
		}
	}
	for _, status := range statuses {
		page := apiCall(t, s, "GET", "/v1/admin/tenants?limit=1000&status="+status, fixtureAdmin, nil, 200)
		rows := page["tenants"].([]any)
		if len(rows) != expected[status] || page["next_offset"] != nil {
			t.Fatal("status filter page incorrect")
		}
		for _, row := range rows {
			if row.(map[string]any)["status"] != status {
				t.Fatal("inactive status filter leaked another status")
			}
		}
	}
	p := apiCall(t, s, "GET", "/v1/admin/tenants?status=pending&limit=200", fixtureAdmin, nil, 200)
	if len(p["tenants"].([]any)) != 200 || p["next_offset"] != float64(200) {
		t.Fatal("filtered page cursor incorrect")
	}
	p = apiCall(t, s, "GET", "/v1/admin/tenants?status=pending&limit=200&offset=200", fixtureAdmin, nil, 200)
	if len(p["tenants"].([]any)) != expected["pending"]-200 || p["next_offset"] != nil {
		t.Fatal("filtered final page incorrect")
	}
	p = apiCall(t, s, "GET", "/v1/admin/brokers?tenant_id="+firstTenant+"&limit=1", fixtureAdmin, nil, 200)
	if len(p["brokers"].([]any)) != 1 || p["next_offset"] != nil {
		t.Fatal("broker tenant filter/pagination incorrect")
	}
}

// Seeds only the identity row so race instrumentation need not spend minutes in bcrypt.
// Password/login behavior is covered by separate real cost-12 tests.
func TestRESTConcurrentIdempotencyUsageAndRevocation(t *testing.T) {
	s := apiFixture(t, Config{UsageFlushInterval: 5 * time.Millisecond})
	id := uuid()
	if _, e := s.db.Exec("INSERT INTO tenants(id,name,email,password_hash,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", id, "concurrent", "concurrent@example.invalid", "$2a$12$vVG.VB.BErnxNdgqbKkb2e.nPiwzgutIUvdmgSlOBNAUzAhGVKgde", "active", now(), now()); e != nil {
		t.Fatal(e)
	}
	account, e := s.accountToken(id, 1)
	if e != nil {
		t.Fatal(e)
	}
	broker, device := fixtureBroker(t, s, account, "host")
	sid, session := fixtureSession(t, s, account, broker)
	start := make(chan struct{})
	statuses := make(chan int, 16)
	for i := 0; i < 16; i++ {
		go func() {
			<-start
			r := httptest.NewRequest("POST", "/v1/sessions/"+sid+"/messages", strings.NewReader(`{"sequence":1,"data":"immutable"}`))
			r.Header.Set("Authorization", "Bearer "+session)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			statuses <- w.Code
		}()
	}
	close(start)
	created := 0
	for i := 0; i < 16; i++ {
		code := <-statuses
		if code == 201 {
			created++
		} else if code != 200 {
			t.Fatalf("concurrent idempotent write status=%d", code)
		}
	}
	if created != 1 {
		t.Fatal("immutable sequence created more than once")
	}
	poll := apiCall(t, s, "GET", "/v1/sessions/"+sid+"/messages", device, nil, 200)
	if len(poll["messages"].([]any)) != 1 {
		t.Fatal("duplicate mailbox rows")
	}
	done := make(chan struct{}, 16)
	for i := 0; i < 16; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				s.recordRelayUsage(id, broker, sid, 1)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 16; i++ {
		<-done
	}
	u := apiCall(t, s, "GET", "/v1/me/usage", account, nil, 200)
	if u["lifetime"] != float64(1600) {
		t.Fatal("concurrent persistence lost bytes", u)
	}
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/relay", fixtureAdmin, map[string]any{"enabled": true}, 200)
	stale, version, e := s.tenant(id)
	if e != nil {
		t.Fatal(e)
	}
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/relay", fixtureAdmin, map[string]any{"enabled": false}, 200)
	stale.Email = "race-safe@example.invalid"
	if account, e = s.updateAccount(stale, nil, true, version, false, false); e != nil {
		t.Fatal(e)
	}
	current, _, e := s.tenant(id)
	if e != nil || current.RelayEnabled {
		t.Fatal("stale account snapshot restored revoked relay permission")
	}
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/disable", fixtureAdmin, nil, 200)
	apiCall(t, s, "GET", "/v1/sessions/"+sid+"/messages", session, nil, 401)
	apiCall(t, s, "GET", "/v1/brokers/"+broker+"/sessions", device, nil, 401)
}

func TestDailyQuotaIncludesPendingAndUTCReset(t *testing.T) {
	s := apiFixture(t, Config{TenantDailyByteQuota: 64, TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true}})
	id, account := fixtureRegister(t, s, "quota")
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/relay", fixtureAdmin, map[string]any{"enabled": true}, 200)
	broker, device := fixtureBroker(t, s, account, "host")
	sid, session := fixtureSession(t, s, account, broker)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 200)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/turn", session, nil, 200)
	s.recordRelayUsage(id, broker, sid, 64)
	if s.authorizeTURN(id, broker, sid) {
		t.Fatal("daily quota ignored pending persistence batch")
	}
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/turn", session, nil, 403)
	u := apiCall(t, s, "GET", "/v1/me/usage", account, nil, 200)
	if u["lifetime"] != float64(64) {
		t.Fatal("quota bytes not persisted")
	}
	if _, e := s.db.Exec("UPDATE usage_daily SET day=? WHERE tenant_id=?", time.Now().UTC().Add(-24*time.Hour).Format("2006-01-02"), id); e != nil {
		t.Fatal(e)
	}
	// The background refresh observes changes made outside usage accounting.
	if e := s.refreshTURNQuotaUsage(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !s.authorizeTURN(id, broker, sid) {
		t.Fatal("daily quota did not reset for a new UTC day")
	}
}

func TestPrivateDatabasePermissionAndStaleVersion(t *testing.T) {
	for _, path := range []string{"file:test.sqlite", filepath.Join(t.TempDir(), "driver.sqlite?_foreign_keys=off")} {
		if _, e := New(Config{DBPath: path, AdminToken: fixtureAdmin}); e == nil {
			t.Fatal("SQLite URI/DSN bypass accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "insecure.sqlite")
	if e := os.WriteFile(path, nil, 0660); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0660); e != nil {
		t.Fatal(e)
	}
	if _, e := New(Config{DBPath: path, AdminToken: fixtureAdmin}); e == nil {
		t.Fatal("insecure file accepted")
	}
	parent := filepath.Join(t.TempDir(), "group-writable")
	if e := os.Mkdir(parent, 0770); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(parent, 0770); e != nil {
		t.Fatal(e)
	}
	if _, e := New(Config{DBPath: filepath.Join(parent, "control.sqlite"), AdminToken: fixtureAdmin}); e == nil {
		t.Fatal("group-writable database parent accepted")
	}
	s := apiFixture(t, Config{})
	id, account := fixtureRegister(t, s, "versions")
	tenant, version, e := s.tenant(id)
	if e != nil {
		t.Fatal(e)
	}
	apiCall(t, s, "PATCH", "/v1/me", account, map[string]any{"email": "version-new@example.invalid"}, 200)
	if _, e = s.updateAccount(tenant, nil, true, version, false, false); e == nil {
		t.Fatal("stale already-authenticated principal minted replacement after revocation")
	}
}

func TestSessionHeartbeatRenewsExistingTURNAllocation(t *testing.T) {
	s := apiFixture(t, Config{TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true, Realm: "renew-fixture", MaxCredentialTTL: 250 * time.Millisecond}})
	id := uuid()
	if _, e := s.db.Exec("INSERT INTO tenants(id,name,email,password_hash,status,relay_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", id, "renew", "renew@example.invalid", "unused-no-login", "active", 1, now(), now()); e != nil {
		t.Fatal(e)
	}
	account, e := s.accountToken(id, 1)
	if e != nil {
		t.Fatal(e)
	}
	broker, device := fixtureBroker(t, s, account, "host")
	created := apiCall(t, s, "POST", "/v1/sessions", account, map[string]any{"broker_id": broker, "relay_mode": "force"}, 201)
	sid := created["session_id"].(string)
	session := created["session_token"].(string)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/heartbeat", session, nil, 200) // no credentials/approval yet is normal
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 200)
	creds := apiCall(t, s, "POST", "/v1/sessions/"+sid+"/turn", session, nil, 200)
	initialExpiry, e := time.Parse(time.RFC3339Nano, creds["expires_at"].(string))
	if e != nil {
		t.Fatal(e)
	}
	transport, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer transport.Close()
	logger := logging.NewDefaultLoggerFactory()
	logger.DefaultLogLevel = logging.LogLevelError
	client, e := turn.NewClient(&turn.ClientConfig{Conn: transport, TURNServerAddr: s.TURNAddr(), Username: creds["username"].(string), Password: creds["password"].(string), Realm: "renew-fixture", LoggerFactory: logger, RTO: 100 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if e = client.Listen(); e != nil {
		t.Fatal(e)
	}
	relay, e := client.Allocate()
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	peer, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	if e = client.CreatePermission(peer.LocalAddr()); e != nil {
		t.Fatal(e)
	}
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	buf := make([]byte, 128)
	payload := []byte("healthy-renewed-allocation")
	total := 0
	for i := 0; i < 5; i++ {
		<-ticker.C
		bearer := session
		if i%2 == 1 {
			bearer = device
		}
		status := apiCall(t, s, "POST", "/v1/sessions/"+sid+"/heartbeat", bearer, nil, 200)
		if status["turn_credential_renewal"] != "session-heartbeat" {
			t.Fatal("renewal contract not advertised")
		}
		if _, e = relay.WriteTo(payload, peer.LocalAddr()); e != nil {
			t.Fatal(e)
		}
		_ = peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, addr, e := peer.ReadFrom(buf)
		if e != nil {
			t.Fatal("same allocation expired despite heartbeat", e)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatal("renewed relay corrupted data")
		}
		if _, e = peer.WriteTo(buf[:n], addr); e != nil {
			t.Fatal(e)
		}
		_ = relay.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		if _, _, e = relay.ReadFrom(buf); e != nil {
			t.Fatal("renewed inbound allocation failed", e)
		}
		total += 2 * len(payload)
	}
	if !time.Now().After(initialExpiry) {
		t.Fatal("fixture did not cross original credential expiration")
	}
	awaitAPIUsage(t, s, "/v1/me/usage", account, total)
	// Once heartbeat stops, the bounded credential timer closes the allocation.
	expired := time.NewTimer(300 * time.Millisecond)
	defer expired.Stop()
	<-expired.C
	// A later healthy session heartbeat must NOT revive an expired secret/allocation.
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/heartbeat", session, nil, 200)
	_, _ = relay.WriteTo([]byte("must-not-resurrect"), peer.LocalAddr())
	_ = peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, e = peer.ReadFrom(buf); e == nil {
		t.Fatal("expired allocation resurrected by heartbeat")
	}
	awaitAPIUsage(t, s, "/v1/me/usage", account, total)
}

func TestControlTURNApprovalRealRelayUsageAndRevocation(t *testing.T) {
	s := apiFixture(t, Config{TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true, Realm: "fixture"}})
	id, account := fixtureRegister(t, s, "relay")
	broker, device := fixtureBroker(t, s, account, "host")
	sid, session := fixtureSession(t, s, account, broker)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 403)
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/relay", fixtureAdmin, map[string]any{"enabled": true}, 200)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/heartbeat", device, nil, 200)
	apiCall(t, s, "GET", "/v1/sessions/"+sid, session, nil, 200)
	caps := apiCall(t, s, "GET", "/v1/capabilities", account, nil, 200)
	if caps["stun_address"] != s.AdvertisedTURNAddr() {
		t.Fatal("missing STUN endpoint")
	}
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/turn", session, nil, 403)
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 200)
	credentials := apiCall(t, s, "POST", "/v1/sessions/"+sid+"/turn", session, nil, 200)
	transport, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer transport.Close()
	logger := logging.NewDefaultLoggerFactory()
	logger.DefaultLogLevel = logging.LogLevelError
	client, e := turn.NewClient(&turn.ClientConfig{Conn: transport, STUNServerAddr: s.TURNAddr(), TURNServerAddr: s.TURNAddr(), Username: credentials["username"].(string), Password: credentials["password"].(string), Realm: "fixture", LoggerFactory: logger, RTO: 100 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if e = client.Listen(); e != nil {
		t.Fatal(e)
	}
	if _, e = client.SendBindingRequest(); e != nil {
		t.Fatal("STUN binding:", e)
	}
	relay, e := client.Allocate()
	if e != nil {
		t.Fatal("TURN allocation:", e)
	}
	defer relay.Close()
	peer, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	if e = client.CreatePermission(peer.LocalAddr()); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 128)
	total := 0
	for i := 0; i < 3; i++ {
		payload := []byte(fmt.Sprintf("real-forwarded-QUIC-opaque-%d", i))
		if _, e = relay.WriteTo(payload, peer.LocalAddr()); e != nil {
			t.Fatal(e)
		}
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, e := peer.ReadFrom(buf)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatal("relay corrupted packet")
		}
		if _, e = peer.WriteTo(buf[:n], addr); e != nil {
			t.Fatal(e)
		}
		_ = relay.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, e = relay.ReadFrom(buf)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatal("inbound relay corrupted packet")
		}
		total += 2 * len(payload)
	}
	usage := awaitAPIUsage(t, s, "/v1/me/usage", account, total)
	if usage["lifetime"] != float64(total) {
		t.Fatalf("real forwarded usage=%v want=%d", usage["lifetime"], total)
	}
	usage = apiCall(t, s, "GET", "/v1/brokers/"+broker+"/usage", account, nil, 200)
	if usage["lifetime"] != float64(total) {
		t.Fatal("real broker attribution missing")
	}
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/relay", fixtureAdmin, map[string]any{"enabled": false}, 200)
	apiCall(t, s, "GET", "/v1/me", account, nil, 200)
	apiCall(t, s, "POST", "/v1/brokers/"+broker+"/heartbeat", device, nil, 200)
	status := apiCall(t, s, "GET", "/v1/sessions/"+sid, session, nil, 200)
	if status["relay_approved"] != false {
		t.Fatal("approval survived relay disable")
	}
	apiCall(t, s, "POST", "/v1/sessions/"+sid+"/turn", session, nil, 403)
	// Existing allocations must not keep forwarding after disabling relay capability.
	_, _ = relay.WriteTo([]byte("must-be-revoked"), peer.LocalAddr())
	_ = peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, e = peer.ReadFrom(buf); e == nil {
		t.Fatal("revoked TURN allocation forwarded")
	}
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/relay", fixtureAdmin, map[string]any{"enabled": true}, 200)
	force := apiCall(t, s, "POST", "/v1/sessions", account, map[string]any{"broker_id": broker, "relay_mode": "force"}, 201)
	fsid := force["session_id"].(string)
	ftoken := force["session_token"].(string)
	apiCall(t, s, "POST", "/v1/sessions/"+fsid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": false}, 409)
	apiCall(t, s, "POST", "/v1/sessions/"+fsid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 200)
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/relay", fixtureAdmin, map[string]any{"enabled": false}, 200)
	apiCall(t, s, "GET", "/v1/sessions/"+fsid, ftoken, nil, 401)
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/disable", fixtureAdmin, nil, 200)
	apiCall(t, s, "GET", "/v1/sessions/"+sid, session, nil, 401)
}
