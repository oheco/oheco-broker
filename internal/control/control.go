// Package control implements the embeddable SQLite management and WS/REST signaling plane.
// It deliberately does not terminate native peer authentication or QUIC.
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Config contains no global process settings. The caller owns its HTTP listener.
// Put DBPath on a private-permission filesystem, not HarmonyOS HOME/hmdfs.
type Config struct {
	ListenAddr string
	DBPath     string
	AdminToken string
	// Initial defaults only; persisted settings take precedence on subsequent starts.
	RegistrationPolicy       string // open (default), approval, closed
	RegistrationRelayEnabled bool   // enable relay for newly registered tenants; default false
	TURN                     TURNConfig
	AccountTokenTTL          time.Duration
	AuthRefreshTTL           time.Duration // idle lifetime; zero defaults to 30 days
	AuthAbsoluteTTL          time.Duration // zero permits continuously refreshed sessions
	AuthAccessOverlap        time.Duration // zero defaults to two minutes
	SessionTTL               time.Duration
	BrokerLease              time.Duration
	UsageFlushInterval       time.Duration
	// Zero means unlimited. Measured forwarded payload bytes, both directions.
	TenantDailyByteQuota    int64
	MaxSessionsPerTenant    int
	MaxMessagesPerDirection int
	MaxMessageBytes         int
	// Optional embedder-only fault/admission hook; nil in production adapters.
	// Role is "broker" (watcher) or "session". The context is canceled when
	// the socket or server closes. Never hold SQLite transactions in this hook.
	BeforeWebSocketRequest func(context.Context, string, string) error
}

type Server struct {
	cfg            Config
	db             *sql.DB
	turnAuthStmt   *sql.Stmt
	turnAuthCache  *turnAuthorizationCache
	turnQuotaCache *turnQuotaCache
	mux            *http.ServeMux
	turn           *turnManager
	ws             *wsHub
	stop           chan struct{}
	done           chan struct{}
	closeOnce      sync.Once
	closeErr       error
	usageMu        sync.Mutex
	pendingUsage   map[string]int64 // tenant UUID + UTC minute bucket
}

type Tenant struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	Status       string    `json:"status"`
	RelayEnabled bool      `json:"relay_enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type Broker struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Name           string    `json:"name"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	Online         bool      `json:"online"`
	CreatedAt      time.Time `json:"created_at"`
}
type Session struct {
	ID                string    `json:"session_id"`
	TenantID          string    `json:"tenant_id"`
	BrokerID          string    `json:"broker_id"`
	RelayMode         string    `json:"relay_mode"`
	PeerAuthenticated bool      `json:"peer_authenticated"`
	RelayApproved     bool      `json:"relay_approved"`
	ExpiresAt         time.Time `json:"expires_at"`
	ConnectionID      string    `json:"connection_id,omitempty"`
	Generation        uint64    `json:"generation,omitempty"`
	AuthSession       string    `json:"-"`
}
type Message struct {
	Sequence int64  `json:"sequence"`
	Data     string `json:"data"`
}

type apiError struct {
	code       int
	message    string
	reason     string
	generation uint64
}

func (e *apiError) Error() string         { return e.message }
func fail(code int, message string) error { return &apiError{code: code, message: message} }
func apiErrorBody(a *apiError) map[string]any {
	body := map[string]any{"error": a.message}
	if a.reason != "" {
		body["error_code"] = a.reason
	}
	if a.generation != 0 {
		body["generation"] = a.generation
	}
	return body
}

// New opens/migrates SQLite and optionally starts the embedded UDP TURN listener.
// Handler can be mounted on the caller's HTTP server; ListenAddr is informational.
func New(cfg Config) (*Server, error) {
	if cfg.DBPath == "" {
		return nil, errors.New("control: DBPath is required")
	}
	if cfg.AdminToken == "" {
		return nil, errors.New("control: AdminToken is required")
	}
	if cfg.RegistrationPolicy == "" {
		cfg.RegistrationPolicy = "open"
	}
	if !validPolicy(cfg.RegistrationPolicy) {
		return nil, errors.New("control: invalid registration policy")
	}
	if cfg.AccountTokenTTL < 0 || cfg.AuthRefreshTTL < 0 || cfg.AuthAbsoluteTTL < 0 || cfg.AuthAccessOverlap < 0 || cfg.SessionTTL < 0 || cfg.BrokerLease < 0 || cfg.UsageFlushInterval < 0 || cfg.TenantDailyByteQuota < 0 || cfg.MaxSessionsPerTenant < 0 || cfg.MaxMessagesPerDirection < 0 || cfg.MaxMessageBytes < 0 {
		return nil, errors.New("control: durations, quotas and limits cannot be negative")
	}
	if cfg.MaxSessionsPerTenant > 10000 || cfg.MaxMessagesPerDirection > 1024 {
		return nil, errors.New("control: session/message limits exceed safety ceiling")
	}
	if cfg.AccountTokenTTL <= 0 {
		cfg.AccountTokenTTL = 24 * time.Hour
	}
	if cfg.AuthRefreshTTL == 0 {
		cfg.AuthRefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.AuthAccessOverlap == 0 {
		cfg.AuthAccessOverlap = 2 * time.Minute
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 10 * time.Minute
	}
	if cfg.SessionTTL > time.Hour {
		return nil, errors.New("control: SessionTTL exceeds one hour")
	}
	if cfg.BrokerLease <= 0 {
		cfg.BrokerLease = 90 * time.Second
	}
	if cfg.UsageFlushInterval <= 0 {
		cfg.UsageFlushInterval = time.Second
	}
	if cfg.MaxSessionsPerTenant <= 0 {
		cfg.MaxSessionsPerTenant = 128
	}
	if cfg.MaxMessagesPerDirection <= 0 {
		cfg.MaxMessagesPerDirection = 256
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 32768
	}
	if cfg.MaxMessageBytes > 32768 {
		return nil, errors.New("control: MaxMessageBytes exceeds 32768")
	}
	if cfg.DBPath != ":memory:" {
		if strings.ContainsAny(cfg.DBPath, "?\x00") || strings.HasPrefix(cfg.DBPath, "file:") {
			return nil, errors.New("control: DBPath must be a plain filesystem path, not a SQLite URI/DSN")
		}
		if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0700); err != nil {
			return nil, err
		}
		dirInfo, e := os.Stat(filepath.Dir(cfg.DBPath))
		if e != nil {
			return nil, e
		}
		if dirInfo.Mode().Perm()&0022 != 0 {
			return nil, errors.New("control: database parent directory must not be group/other writable")
		}
		f, err := os.OpenFile(cfg.DBPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		info, statErr := f.Stat()
		_ = f.Close()
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("control: DBPath must have private 0600 permissions on a permissions-capable filesystem (HarmonyOS HOME is unsuitable)")
		}
	}
	db, err := sql.Open("sqlite3", cfg.DBPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Server{cfg: cfg, db: db, mux: http.NewServeMux(), ws: newWSHub(), stop: make(chan struct{}), done: make(chan struct{}), pendingUsage: map[string]int64{}}
	if err = s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Reuse the authorization query plan, while reading current rows for every
	// packet. Preparing this joined query per packet dominates TURN CPU cost.
	s.turnAuthStmt, err = db.Prepare(turnAuthorizationIdentitySQL)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.turnQuotaCache = newTURNQuotaCache()
	if err = s.refreshTURNQuotaUsage(context.Background()); err != nil {
		_ = s.turnAuthStmt.Close()
		_ = db.Close()
		return nil, err
	}
	s.turnAuthCache = newTURNAuthorizationCache(s)
	if cfg.TURN.Enabled {
		s.turn, err = startTURN(cfg.TURN, s.authorizeTURN, s.recordRelayUsage)
		if err != nil {
			s.turnAuthCache.close()
			_ = s.turnAuthStmt.Close()
			_ = db.Close()
			return nil, err
		}
	}
	s.routes()
	go s.maintenance()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

// TURNAddr returns the actual bound UDP endpoint (including a random test port).
func (s *Server) TURNAddr() string {
	if s.turn == nil {
		return ""
	}
	return s.turn.addr()
}

// AdvertisedTURNAddr is also the STUN endpoint; capability does not authorize relay.
func (s *Server) AdvertisedTURNAddr() string {
	a := s.TURNAddr()
	if a == "" {
		return ""
	}
	if s.cfg.TURN.PublicIP != "" {
		_, p, e := net.SplitHostPort(a)
		if e == nil {
			return net.JoinHostPort(s.cfg.TURN.PublicIP, p)
		}
	}
	return a
}
func (s *Server) turnRenewalMode() string {
	if s.turn != nil {
		return "session-heartbeat"
	}
	return "none"
}
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
		s.turnAuthCache.close()
		// HTTP Shutdown does not own hijacked connections. Join all WS readers,
		// writers and scope loops while their SQLite authorization is still live.
		s.ws.close()
		if s.turn != nil {
			s.closeErr = s.turn.close()
		}
		<-s.done
		if err := s.flushUsage(); err != nil && s.closeErr == nil {
			s.closeErr = err
		}
		if err := s.turnAuthStmt.Close(); err != nil && s.closeErr == nil {
			s.closeErr = err
		}
		if err := s.db.Close(); err != nil && s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}
func validPolicy(p string) bool { return p == "open" || p == "approval" || p == "closed" }
func uuid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func randomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func tokenHash(v string) string       { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func timestamp(t time.Time) int64     { return t.UTC().UnixMilli() }
func fromTimestamp(n int64) time.Time { return time.UnixMilli(n).UTC() }
func now() int64                      { return timestamp(time.Now()) }
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func validName(v string) bool {
	return strings.TrimSpace(v) == v && len(v) > 0 && len(v) <= 64 && !strings.ContainsAny(v, "\x00\r\n")
}
func validEmail(v string) bool {
	if len(v) > 254 {
		return false
	}
	a, e := mail.ParseAddress(v)
	return e == nil && a.Address == v
}
func passwordHash(p string) (string, error) {
	if len(p) < 12 || len(p) > 72 {
		return "", fail(400, "password must contain 12 to 72 bytes")
	}
	b, e := bcrypt.GenerateFromPassword([]byte(p), 12)
	return string(b), e
}

func (s *Server) migrate() error {
	// Keep SQL portable: no rowid identities, JSON operators or vendor-specific UPSERT.
	// SQLite transaction/foreign-key behavior is part of the documented D1 contract.
	_, err := s.db.Exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
 CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
 INSERT INTO schema_version(version) SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
 CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY,name TEXT NOT NULL COLLATE NOCASE UNIQUE,email TEXT NOT NULL,password_hash TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('active','pending','disabled')),relay_enabled INTEGER NOT NULL DEFAULT 0,version INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY,kind TEXT NOT NULL,tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,broker_id TEXT,session_id TEXT,version INTEGER NOT NULL,expires_at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS tokens_tenant ON tokens(tenant_id);
 CREATE TABLE IF NOT EXISTS brokers(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,name TEXT NOT NULL,lease_expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,UNIQUE(tenant_id,name));
 CREATE INDEX IF NOT EXISTS brokers_tenant ON brokers(tenant_id);
 CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,broker_id TEXT NOT NULL REFERENCES brokers(id) ON DELETE CASCADE,relay_mode TEXT NOT NULL,peer_authenticated INTEGER NOT NULL DEFAULT 0,relay_approved INTEGER NOT NULL DEFAULT 0,expires_at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS sessions_broker ON sessions(broker_id,expires_at);
 CREATE TABLE IF NOT EXISTS messages(session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,side TEXT NOT NULL,sequence INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(session_id,side,sequence));
 CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS usage_daily(tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,day TEXT NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(tenant_id,day));
 CREATE TABLE IF NOT EXISTS usage_buckets(tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,bucket TEXT NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(tenant_id,bucket));
 CREATE TABLE IF NOT EXISTS broker_usage_daily(tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,broker_id TEXT NOT NULL,day TEXT NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(tenant_id,broker_id,day));
 CREATE TABLE IF NOT EXISTS broker_usage_buckets(tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,broker_id TEXT NOT NULL,bucket TEXT NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(tenant_id,broker_id,bucket));`)
	if err != nil {
		return fmt.Errorf("control migration: %w", err)
	}
	var v int
	if err = s.db.QueryRow("SELECT version FROM schema_version").Scan(&v); err != nil {
		return err
	}
	if v != 1 && v != 2 && v != 3 {
		return fmt.Errorf("control: unsupported schema version %d", v)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,broker_id TEXT NOT NULL REFERENCES brokers(id) ON DELETE CASCADE,relay_mode TEXT NOT NULL,account_hash TEXT NOT NULL,device_hash TEXT NOT NULL,tenant_version INTEGER NOT NULL,generation INTEGER NOT NULL,current_session_id TEXT NOT NULL,request_id TEXT NOT NULL,prior_generation INTEGER NOT NULL,session_token_hash TEXT NOT NULL,revoked_reason TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS connections_tenant ON connections(tenant_id);
 CREATE INDEX IF NOT EXISTS connections_broker ON connections(broker_id);
 CREATE TABLE IF NOT EXISTS connection_sessions(session_id TEXT PRIMARY KEY,connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,generation INTEGER NOT NULL,request_id TEXT NOT NULL,prior_generation INTEGER NOT NULL,token_hash TEXT NOT NULL UNIQUE,created_at INTEGER NOT NULL,UNIQUE(connection_id,generation),UNIQUE(connection_id,request_id));
 CREATE INDEX IF NOT EXISTS connection_sessions_connection ON connection_sessions(connection_id,generation);
 UPDATE schema_version SET version=2;`)
	if err != nil {
		return err
	}
	if err = s.migrateAuth(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT OR IGNORE INTO settings(key,value) VALUES('registration_policy',?),('registration_relay_enabled',?)", s.cfg.RegistrationPolicy, strconv.FormatBool(s.cfg.RegistrationRelayEnabled))
	return err
}

func (s *Server) write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) endpoint(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		select {
		case <-s.stop:
			s.write(w, 503, map[string]string{"error": "server closed"})
			return
		default:
		}
		if err := fn(w, r); err != nil {
			err = s.persistObservedRevocation(err)
			var a *apiError
			if errors.As(err, &a) {
				s.write(w, a.code, apiErrorBody(a))
			} else {
				s.write(w, 500, map[string]string{"error": "internal server error"})
			}
		}
	}
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	limit := int64(65536)
	if _, internal := r.Context().Value(wsAuthKey{}).(string); internal {
		// WS strict parsing already enforced its complete 256 KiB envelope.
		// A valid 32 KiB string may expand six-fold under JSON escaping.
		limit = wsMaxFrame
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fail(400, "invalid JSON body")
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return fail(400, "trailing JSON data")
	}
	return nil
}

func (s *Server) tenant(id string) (Tenant, int, error) {
	var t Tenant
	var version int
	var relay int
	var created, updated int64
	err := s.db.QueryRow("SELECT id,name,email,status,relay_enabled,version,created_at,updated_at FROM tenants WHERE id=?", id).Scan(&t.ID, &t.Name, &t.Email, &t.Status, &relay, &version, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return t, 0, fail(404, "tenant not found")
	}
	t.RelayEnabled = relay != 0
	t.CreatedAt = fromTimestamp(created)
	t.UpdatedAt = fromTimestamp(updated)
	return t, version, err
}
func (s *Server) broker(id string) (Broker, error) {
	var b Broker
	var lease, created int64
	e := s.db.QueryRow("SELECT id,tenant_id,name,lease_expires_at,created_at FROM brokers WHERE id=?", id).Scan(&b.ID, &b.TenantID, &b.Name, &lease, &created)
	if errors.Is(e, sql.ErrNoRows) {
		return b, fail(404, "broker not found")
	}
	b.LeaseExpiresAt = fromTimestamp(lease)
	b.CreatedAt = fromTimestamp(created)
	b.Online = lease > now()
	return b, e
}
func (s *Server) session(id string) (Session, error) {
	var v Session
	var peer, relay int
	var expiry int64
	e := s.db.QueryRow("SELECT s.id,s.tenant_id,s.broker_id,s.relay_mode,s.peer_authenticated,s.relay_approved,s.expires_at,COALESCE(c.connection_id,''),COALESCE(c.generation,0),COALESCE(s.auth_session_id,'') FROM sessions s LEFT JOIN connection_sessions c ON c.session_id=s.id WHERE s.id=?", id).Scan(&v.ID, &v.TenantID, &v.BrokerID, &v.RelayMode, &peer, &relay, &expiry, &v.ConnectionID, &v.Generation, &v.AuthSession)
	if errors.Is(e, sql.ErrNoRows) {
		return v, fail(404, "session not found")
	}
	v.PeerAuthenticated = peer != 0
	v.RelayApproved = relay != 0
	v.ExpiresAt = fromTimestamp(expiry)
	return v, e
}

type principal struct {
	kind, tenant, broker, session string
	authSession                   string
	version                       int
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}
func (s *Server) auth(r *http.Request, kinds ...string) (principal, error) {
	return s.authWithPending(r, false, kinds...)
}
func (s *Server) readAccount(r *http.Request) (principal, error) {
	return s.authWithPending(r, true, "account")
}
func (s *Server) authWithPending(r *http.Request, allowPending bool, kinds ...string) (principal, error) {
	var p principal
	var expiry int64
	hash, internal := r.Context().Value(wsAuthKey{}).(string)
	if !internal {
		token := bearer(r)
		if token == "" {
			return p, fail(401, "bearer required")
		}
		hash = tokenHash(token)
	}
	e := s.db.QueryRow("SELECT kind,tenant_id,COALESCE(broker_id,''),COALESCE(session_id,''),version,expires_at,COALESCE(auth_session_id,'') FROM tokens WHERE hash=?", hash).Scan(&p.kind, &p.tenant, &p.broker, &p.session, &p.version, &expiry, &p.authSession)
	if errors.Is(e, sql.ErrNoRows) {
		return p, fail(401, "invalid bearer")
	}
	if e != nil {
		return p, e
	}
	if expiry <= now() {
		if p.authSession != "" && p.kind == "account" {
			return p, authFailure(401, "account_token_expired")
		}
		return p, fail(401, "expired bearer")
	}
	if p.authSession != "" {
		if _, e = authAuthority(s.db, p.authSession, p.tenant, p.version, true); e != nil {
			return p, e
		}
	}
	accepted := false
	for _, kind := range kinds {
		if p.kind == kind {
			accepted = true
		}
	}
	if !accepted {
		return p, fail(403, "bearer scope denied")
	}
	t, v, e := s.tenant(p.tenant)
	if e != nil {
		return p, e
	}
	if v != p.version {
		return p, fail(401, "revoked bearer")
	}
	if t.Status != "active" && !(allowPending && t.Status == "pending") {
		return p, fail(403, "tenant is not active")
	}
	return p, nil
}
func (s *Server) admin(r *http.Request) error {
	a := sha256.Sum256([]byte(bearer(r)))
	b := sha256.Sum256([]byte(s.cfg.AdminToken))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return fail(401, "admin bearer required")
	}
	return nil
}
func issue(tx *sql.Tx, kind, tenant, broker, session string, version int, expiry time.Time) (string, error) {
	t := randomSecret()
	_, e := tx.Exec("INSERT INTO tokens(hash,kind,tenant_id,broker_id,session_id,version,expires_at) VALUES(?,?,?,?,?,?,?)", tokenHash(t), kind, tenant, broker, session, version, timestamp(expiry))
	return t, e
}
func txActive(tx *sql.Tx, p principal) error {
	var v int
	var status string
	if e := tx.QueryRow("SELECT version,status FROM tenants WHERE id=?", p.tenant).Scan(&v, &status); e != nil {
		return e
	}
	if v != p.version {
		return fail(401, "revoked bearer")
	}
	if status != "active" {
		return fail(403, "tenant is not active")
	}
	return nil
}

// txPrincipal closes the authentication-to-mutation race on the single SQLite
// owner. Device rotation may delete a token without changing tenant version.
func txPrincipal(tx *sql.Tx, r *http.Request, p principal) error {
	if p.authSession != "" && p.kind == "account" {
		return txAuthPrincipal(tx, p)
	}
	hash, internal := r.Context().Value(wsAuthKey{}).(string)
	if !internal {
		hash = tokenHash(bearer(r))
	}
	var current principal
	var expiry int64
	err := tx.QueryRow("SELECT kind,tenant_id,COALESCE(broker_id,''),COALESCE(session_id,''),version,expires_at,COALESCE(auth_session_id,'') FROM tokens WHERE hash=?", hash).Scan(&current.kind, &current.tenant, &current.broker, &current.session, &current.version, &expiry, &current.authSession)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(401, "revoked bearer")
	}
	if err != nil {
		return err
	}
	if current != p || expiry <= now() {
		return fail(401, "expired or changed bearer")
	}
	if p.authSession != "" {
		if err = txAuthPrincipal(tx, p); err != nil {
			return err
		}
	}
	return txActive(tx, p)
}
func txSessionLive(tx *sql.Tx, v Session) error {
	if err := checkSessionAuth(tx, v); err != nil {
		return err
	}
	if err := txManagedSession(tx, v); err != nil {
		return err
	}
	var expiry, lease int64
	err := tx.QueryRow("SELECT sessions.expires_at,brokers.lease_expires_at FROM sessions JOIN brokers ON brokers.id=sessions.broker_id WHERE sessions.id=? AND sessions.tenant_id=? AND sessions.broker_id=?", v.ID, v.TenantID, v.BrokerID).Scan(&expiry, &lease)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(404, "session not found")
	}
	if err != nil {
		return err
	}
	if expiry <= now() {
		return fail(410, "session expired")
	}
	if lease <= now() {
		return fail(409, "broker lease expired; heartbeat required")
	}
	return nil
}
func (s *Server) accountToken(id string, v int) (string, error) {
	tx, e := s.db.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	t, e := issue(tx, "account", id, "", "", v, time.Now().Add(s.cfg.AccountTokenTTL))
	if e != nil {
		return "", e
	}
	return t, tx.Commit()
}
func (s *Server) revokeTenant(id string) {
	s.revokeTURNTenant(id)
	s.notifyWSTenant(id)
}
func (s *Server) revokeTURNTenant(id string) {
	s.turnAuthCache.invalidateTenant(id)
	if s.turn != nil {
		s.turn.revokeTenant(id)
	}
}
func (s *Server) revokeBroker(id string) {
	s.turnAuthCache.invalidateBroker(id)
	if s.turn != nil {
		s.turn.revokeBroker(id)
	}
	s.notifyWSBroker(id)
}
func (s *Server) revokeSession(id string) {
	s.revokeTURNSession(id)
	s.notifyWSSession(id)
}
func (s *Server) revokeTURNSession(id string) {
	s.turnAuthCache.invalidateSession(id)
	if s.turn != nil {
		s.turn.revokeSession(id)
	}
}

func (s *Server) maintenance() {
	defer close(s.done)
	t := time.NewTicker(s.cfg.UsageFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			_ = s.flushUsage()
			// Session DELETE cascades bounded mailboxes. Expired tokens never authorize.
			if result, err := s.db.Exec("DELETE FROM sessions WHERE expires_at<=?", now()); err == nil {
				if n, err := result.RowsAffected(); err == nil && n > 0 {
					s.ws.wake(func(*wsPeer) bool { return true })
				}
			}
			_, _ = s.db.Exec("DELETE FROM tokens WHERE expires_at<=? OR (kind='session' AND NOT EXISTS(SELECT 1 FROM sessions WHERE sessions.id=tokens.session_id)) OR (kind='device' AND NOT EXISTS(SELECT 1 FROM brokers WHERE brokers.id=tokens.broker_id))", now())
			// Unknown lineages fail closed. Never discard an authorized idle
			// connection merely because its transport lease naturally expired.
			_ = s.pruneConnections()
			_, _ = s.db.Exec("DELETE FROM auth_sessions WHERE (revoked_reason<>'' OR refresh_expires_at<=?) AND NOT EXISTS(SELECT 1 FROM tokens WHERE tokens.auth_session_id=auth_sessions.id) AND NOT EXISTS(SELECT 1 FROM connections WHERE connections.auth_session_id=auth_sessions.id) AND NOT EXISTS(SELECT 1 FROM sessions WHERE sessions.auth_session_id=auth_sessions.id)", now())
		}
	}
}
func (s *Server) recordUsage(tenant string, n int64) { s.recordRelayUsage(tenant, "", "", n) }
func (s *Server) recordRelayUsage(tenant, broker, session string, n int64) {
	if n <= 0 {
		return
	}
	bucket := time.Now().UTC().Truncate(time.Minute).Format(time.RFC3339)
	key := tenant + "|" + broker + "|" + bucket
	s.usageMu.Lock()
	s.pendingUsage[key] += n
	s.recordTURNQuotaUsageLocked(tenant, bucket[:10], n)
	s.usageMu.Unlock()
}
func (s *Server) flushUsage() error {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	if len(s.pendingUsage) == 0 {
		return nil
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for key, n := range s.pendingUsage {
		parts := strings.SplitN(key, "|", 3)
		broker := parts[1]
		bucket := parts[2]
		day := bucket[:10]
		res, e := tx.Exec("UPDATE usage_daily SET bytes=bytes+? WHERE tenant_id=? AND day=?", n, parts[0], day)
		if e != nil {
			return e
		}
		count, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if count == 0 {
			if _, e = tx.Exec("INSERT INTO usage_daily(tenant_id,day,bytes) VALUES(?,?,?)", parts[0], day, n); e != nil {
				return e
			}
		}
		res, e = tx.Exec("UPDATE usage_buckets SET bytes=bytes+? WHERE tenant_id=? AND bucket=?", n, parts[0], bucket)
		if e != nil {
			return e
		}
		count, e = res.RowsAffected()
		if e != nil {
			return e
		}
		if count == 0 {
			if _, e = tx.Exec("INSERT INTO usage_buckets(tenant_id,bucket,bytes) VALUES(?,?,?)", parts[0], bucket, n); e != nil {
				return e
			}
		}
		if broker != "" {
			for _, period := range []string{"day", "bucket"} {
				table := "broker_usage_daily"
				value := day
				if period == "bucket" {
					table = "broker_usage_buckets"
					value = bucket
				}
				res, e = tx.Exec("UPDATE "+table+" SET bytes=bytes+? WHERE tenant_id=? AND broker_id=? AND "+period+"=?", n, parts[0], broker, value)
				if e != nil {
					return e
				}
				count, e = res.RowsAffected()
				if e != nil {
					return e
				}
				if count == 0 {
					if _, e = tx.Exec("INSERT INTO "+table+"(tenant_id,broker_id,"+period+",bytes) VALUES(?,?,?,?)", parts[0], broker, value, n); e != nil {
						return e
					}
				}
			}
		}
	}
	for _, table := range []string{"usage_buckets", "broker_usage_buckets"} {
		if _, e = tx.Exec("DELETE FROM "+table+" WHERE bucket<?", time.Now().UTC().Add(-31*24*time.Hour).Format(time.RFC3339)); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	clear(s.pendingUsage)
	return nil
}
func (s *Server) authorizeTURN(tenant, broker, session string) bool {
	return s.turnAuthCache.authorize(tenant, broker, session) && s.authorizeTURNQuota(tenant)
}

// Serve runs an HTTP server using Config.ListenAddr. Embedders can instead use Handler.
// The caller must provide TLS or a trusted local reverse proxy for bearer secrecy.
func (s *Server) Serve(ctx context.Context) error {
	if s.cfg.ListenAddr == "" {
		return errors.New("control: ListenAddr is required by Serve")
	}
	h := &http.Server{Addr: s.cfg.ListenAddr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = h.Shutdown(c)
		case <-done:
		}
	}()
	err := h.ListenAndServe()
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
