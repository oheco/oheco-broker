package control

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"github.com/pion/logging"
	"github.com/pion/turn/v4"
	"net"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type authFixtureData struct {
	connectionFixtureData
	credentials authCredentials
}

func refreshFixture(t *testing.T, cfg Config) authFixtureData {
	t.Helper()
	cfg.DBPath = ":memory:"
	cfg.UsageFlushInterval = time.Hour
	s := apiFixture(t, cfg)
	tenant := uuid()
	if _, err := s.db.Exec("INSERT INTO tenants(id,name,email,password_hash,status,relay_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", tenant, "auth-fixture", "auth@example.invalid", "unused", "active", 1, now(), now()); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.issueAuthSession(tx, tenant, 1)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	broker, device := fixtureBroker(t, s, c.Token, "auth-host")
	return authFixtureData{connectionFixtureData{s, tenant, c.Token, broker, device}, c}
}
func refreshBody(c authCredentials) map[string]any {
	return map[string]any{"auth_session_id": c.AuthSessionID, "expected_generation": c.Generation, "request_id": uuid(), "next_token": randomSecret(), "next_refresh_token": randomSecret()}
}
func rotateFixture(t *testing.T, f *authFixtureData) map[string]any {
	t.Helper()
	body := refreshBody(f.credentials)
	out := apiCall(t, f.s, "POST", "/v1/auth/refresh", f.credentials.RefreshToken, body, 200)
	tokenExpiry, err := time.Parse(time.RFC3339Nano, out["token_expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	refreshExpiry, err := time.Parse(time.RFC3339Nano, out["refresh_expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	f.credentials = authCredentials{body["next_token"].(string), body["next_refresh_token"].(string), f.credentials.AuthSessionID, uint64(out["generation"].(float64)), tokenExpiry, refreshExpiry}
	f.account = f.credentials.Token
	return out
}
func authExec(t *testing.T, s *Server, query string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestAuthRefreshWireRegisterLoginAndPending(t *testing.T) {
	s := apiFixture(t, Config{DBPath: ":memory:", RegistrationPolicy: "approval", UsageFlushInterval: time.Hour})
	out := apiCall(t, s, "POST", "/v1/auth/register", "", map[string]any{"name": "fresh-auth", "password": fixturePassword}, 201)
	id := out["tenant"].(map[string]any)["id"].(string)
	token := out["token"].(string)
	c := authCredentials{Token: token, RefreshToken: out["refresh_token"].(string), AuthSessionID: out["auth_session_id"].(string), Generation: 1}
	if !validAuthID(c.AuthSessionID) || !validConnectionToken(token) || !validConnectionToken(c.RefreshToken) || token == c.RefreshToken {
		t.Fatal("invalid generated auth credentials")
	}
	apiCall(t, s, "GET", "/v1/me", token, nil, 200)
	apiCall(t, s, "POST", "/v1/brokers", token, map[string]any{"name": "denied-pending"}, 403)
	apiCall(t, s, "POST", "/v1/auth/refresh", c.RefreshToken, refreshBody(c), 200)
	apiCall(t, s, "POST", "/v1/auth/login", "", map[string]any{"name": "fresh-auth", "password": fixturePassword}, 403)
	apiCall(t, s, "POST", "/v1/admin/tenants/"+id+"/approve", fixtureAdmin, map[string]any{}, 200)
	logged := apiCall(t, s, "POST", "/v1/auth/login", "", map[string]any{"name": "fresh-auth", "password": fixturePassword}, 200)
	if logged["generation"] != float64(1) || logged["auth_session_id"] == c.AuthSessionID {
		t.Fatal("login must create its own stable authority")
	}
	apiCall(t, s, "GET", "/v1/me", logged["token"].(string), nil, 200)
	apiCall(t, s, "GET", "/v1/me", logged["refresh_token"].(string), nil, 401)
	status := apiCall(t, s, "GET", "/v1/status", "", nil, 200)
	if status["account_refresh_protocol"] != "refresh-v1" {
		t.Fatal(status)
	}
}

func TestAuthRefreshExactReceiptReplayAndStaleConflict(t *testing.T) {
	f := refreshFixture(t, Config{})
	old := f.credentials
	body := refreshBody(old)
	first := apiCall(t, f.s, "POST", "/v1/auth/refresh", old.RefreshToken, body, 200)
	replay := apiCall(t, f.s, "POST", "/v1/auth/refresh", old.RefreshToken, body, 200)
	if !reflect.DeepEqual(first, replay) || first["token"] != nil || first["refresh_token"] != nil {
		t.Fatal("receipt must replay exact metadata without secrets")
	}
	other := refreshBody(old)
	conflict := apiCall(t, f.s, "POST", "/v1/auth/refresh", old.RefreshToken, other, 409)
	if conflict["error_code"] != "auth_conflict" {
		t.Fatal(conflict)
	}
	apiCall(t, f.s, "GET", "/v1/me", body["next_token"].(string), nil, 200)
	// An old receipt cannot extend the authority, including after idle/absolute expiry.
	a, err := readAuthSession(f.s.db, old.AuthSessionID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Generation != 2 || a.RefreshExpiry != a.ReceiptRefreshExpiry || a.TokenExpiry != a.ReceiptTokenExpiry {
		t.Fatal("receipt changed authority deadlines")
	}
	current := authCredentials{AuthSessionID: old.AuthSessionID, Generation: 2, RefreshToken: body["next_refresh_token"].(string)}
	next := refreshBody(current)
	apiCall(t, f.s, "POST", "/v1/auth/refresh", current.RefreshToken, next, 200)
	apiCall(t, f.s, "POST", "/v1/auth/refresh", old.RefreshToken, body, 401)
	authExec(t, f.s, "UPDATE auth_sessions SET revoked_reason='fixture-revoke' WHERE id=?", old.AuthSessionID)
	apiCall(t, f.s, "POST", "/v1/auth/refresh", current.RefreshToken, next, 401)
	// All persisted values are hashes; actual candidate/proof strings appear nowhere.
	rows, err := f.s.db.Query("SELECT refresh_hash,token_hash,previous_refresh_hash,next_token_hash,next_refresh_hash FROM auth_sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var values [5]string
		if err = rows.Scan(&values[0], &values[1], &values[2], &values[3], &values[4]); err != nil {
			t.Fatal(err)
		}
		for _, v := range values {
			if v == old.Token || v == old.RefreshToken || v == body["next_token"] || v == body["next_refresh_token"] {
				t.Fatal("plaintext credential persisted")
			}
		}
	}
}

func TestAuthRefreshAccessExpiryAndAbsoluteLifetime(t *testing.T) {
	f := refreshFixture(t, Config{AccountTokenTTL: time.Hour, AuthRefreshTTL: time.Hour, AuthAbsoluteTTL: 20 * time.Minute})
	if f.credentials.RefreshExpiresAt.Sub(time.Now()) > 20*time.Minute || f.credentials.TokenExpiresAt.After(f.credentials.RefreshExpiresAt) {
		t.Fatal("absolute lifetime was not enforced")
	}
	authExec(t, f.s, "UPDATE tokens SET expires_at=0 WHERE hash=?", tokenHash(f.account))
	apiCall(t, f.s, "GET", "/v1/me", f.account, nil, 401)
	rotateFixture(t, &f)
	apiCall(t, f.s, "GET", "/v1/me", f.account, nil, 200)
	authExec(t, f.s, "UPDATE auth_sessions SET absolute_expires_at=1 WHERE id=?", f.credentials.AuthSessionID)
	out := apiCall(t, f.s, "POST", "/v1/auth/refresh", f.credentials.RefreshToken, refreshBody(f.credentials), 401)
	if out["error_code"] != "refresh_expired" {
		t.Fatal(out)
	}
}

func TestAuthRefreshStableConnectionTURNAndWSS(t *testing.T) {
	f := refreshFixture(t, Config{TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true}})
	id := uuid()
	body := connectionBody(f.connectionFixtureData, 0)
	body["relay_mode"] = "auto"
	sid := connectionOpen(t, f.connectionFixtureData, id, body, 201)["session_id"].(string)
	apiCall(t, f.s, "POST", "/v1/sessions/"+sid+"/approve", f.device, map[string]any{"peer_authenticated": true, "relay": true}, 200)
	h := httptest.NewServer(f.s.Handler())
	defer h.Close()
	watcher := wsConnect(t, h, "/v1/ws/brokers/"+f.broker, f.device)
	wsUntil(t, watcher, "sessions")
	caller := wsConnect(t, h, "/v1/ws/sessions/"+sid, body["session_token"].(string))
	wsUntil(t, caller, "capabilities")
	creds := apiCall(t, f.s, "POST", "/v1/sessions/"+sid+"/turn", body["session_token"].(string), nil, 200)
	transport, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	logger := logging.NewDefaultLoggerFactory()
	logger.DefaultLogLevel = logging.LogLevelError
	client, err := turn.NewClient(&turn.ClientConfig{Conn: transport, TURNServerAddr: f.s.TURNAddr(), Username: creds["username"].(string), Password: creds["password"].(string), Realm: f.s.turn.cfg.Realm, LoggerFactory: logger, RTO: 100 * time.Millisecond})
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
	original, _ := readConnection(f.s.db, id)
	for i := 0; i < 3; i++ {
		rotateFixture(t, &f)
		// Force the old account admission rows out of storage, without changing the live authority.
		authExec(t, f.s, "DELETE FROM tokens WHERE kind='account' AND auth_session_id=? AND hash<>?", f.credentials.AuthSessionID, tokenHash(f.account))
		if err := f.s.pruneConnections(); err != nil {
			t.Fatal(err)
		}
		c, err := readConnection(f.s.db, id)
		if err != nil || c.Generation != original.Generation || c.Session != original.Session || c.AuthSession != f.credentials.AuthSessionID {
			t.Fatal("refresh recreated or pruned connection", c, err)
		}
		if !f.s.authorizeTURNIdentity(f.tenant, f.broker, sid) {
			t.Fatal("TURN authority lost after access rotation")
		}
		wsRequest(t, watcher, int64(i+1), "heartbeat", nil, 200)
		wsRequest(t, caller, int64(i+1), "heartbeat", nil, 200)
		payload := []byte("same-allocation-through-auth-rotation")
		if _, err = relay.WriteTo(payload, peer.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 128)
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := peer.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatal("outbound TURN broke during refresh", err)
		}
		if _, err = peer.WriteTo(buf[:n], addr); err != nil {
			t.Fatal(err)
		}
		_ = relay.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err = relay.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatal("inbound TURN broke during refresh", err)
		}

	}
	// Recovery with the refreshed access token remains in the same logical connection.
	recovery := connectionBody(f.connectionFixtureData, 1)
	recovery["relay_mode"] = "auto"
	connectionOpen(t, f.connectionFixtureData, id, recovery, 201)
	apiCall(t, f.s, "POST", "/v1/auth/logout", f.credentials.RefreshToken, map[string]any{}, 200)
	apiCall(t, f.s, "POST", "/v1/auth/refresh", f.credentials.RefreshToken, refreshBody(f.credentials), 401)
	wsClosed(t, watcher)
}

func TestAuthRefreshDeviceSameSecretRenewalAndExpiredDenial(t *testing.T) {
	f := refreshFixture(t, Config{AuthRefreshTTL: time.Hour})
	var original int64
	if err := f.s.db.QueryRow("SELECT expires_at FROM tokens WHERE hash=?", tokenHash(f.device)).Scan(&original); err != nil {
		t.Fatal(err)
	}
	authExec(t, f.s, "UPDATE tokens SET expires_at=? WHERE hash=?", now()+10000, tokenHash(f.device))
	rotateFixture(t, &f)
	apiCall(t, f.s, "POST", "/v1/brokers/"+f.broker+"/heartbeat", f.device, map[string]any{}, 200)
	var renewed int64
	if err := f.s.db.QueryRow("SELECT expires_at FROM tokens WHERE hash=?", tokenHash(f.device)).Scan(&renewed); err != nil || renewed <= original {
		t.Fatal("same device grant was not renewed", renewed, original, err)
	}
	a, _ := readAuthSession(f.s.db, f.credentials.AuthSessionID)
	if renewed > a.RefreshExpiry {
		t.Fatal("device exceeded authority deadline")
	}
	authExec(t, f.s, "UPDATE tokens SET expires_at=0 WHERE hash=?", tokenHash(f.device))
	apiCall(t, f.s, "POST", "/v1/brokers/"+f.broker+"/heartbeat", f.device, map[string]any{}, 401)
}

func TestAuthRefreshAdmittedLongRequestAndRevocation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "rotation", true: "revocation"}[revoke], func(t *testing.T) {
			f := refreshFixture(t, Config{})
			old := f.account
			payload, _ := json.Marshal(map[string]any{"name": "long-admitted"})
			reader := &connectionDecodeFault{source: bytes.NewReader(payload), revoke: func() {
				if revoke {
					apiCall(t, f.s, "POST", "/v1/auth/logout", f.credentials.RefreshToken, map[string]any{}, 200)
				} else {
					rotateFixture(t, &f)
					authExec(t, f.s, "DELETE FROM tokens WHERE hash=?", tokenHash(old))
				}
			}}
			r := httptest.NewRequest("POST", "/v1/brokers", reader)
			r.Header.Set("Authorization", "Bearer "+old)
			w := httptest.NewRecorder()
			f.s.Handler().ServeHTTP(w, r)
			want := 201
			if revoke {
				want = 401
			}
			if w.Code != want {
				t.Fatal("admitted request authority incorrect", w.Code, w.Body.String())
			}
		})
	}
}

func TestAuthRefreshAccountMutationReturnsReplacementSession(t *testing.T) {
	for _, route := range []string{"/v1/me", "/v1/me/password"} {
		t.Run(route, func(t *testing.T) {
			f := refreshFixture(t, Config{})
			old := f.credentials
			method, body := "PATCH", map[string]any{"email": "changed@example.invalid"}
			if strings.HasSuffix(route, "password") {
				method = "POST"
				body = map[string]any{"password": fixturePassword}
			}
			out := apiCall(t, f.s, method, route, old.Token, body, 200)
			if out["auth_session_id"] == old.AuthSessionID || out["refresh_token"] == nil || out["generation"] != float64(1) {
				t.Fatal("identity mutation lost renewable credentials")
			}
			apiCall(t, f.s, "POST", "/v1/auth/refresh", old.RefreshToken, refreshBody(old), 401)
			apiCall(t, f.s, "GET", "/v1/me", out["token"].(string), nil, 200)
		})
	}
}

func TestAuthRefreshRevokeScopeAndLegacyCompatibility(t *testing.T) {
	f := refreshFixture(t, Config{})
	old := f.credentials
	tx, _ := f.s.db.Begin()
	other, err := f.s.issueAuthSession(tx, f.tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	apiCall(t, f.s, "DELETE", "/v1/auth/sessions/"+old.AuthSessionID, other.Token, nil, 200)
	apiCall(t, f.s, "GET", "/v1/me", old.Token, nil, 401)
	apiCall(t, f.s, "GET", "/v1/me", other.Token, nil, 200)
	apiCall(t, f.s, "POST", "/v1/auth/logout", old.RefreshToken, map[string]any{}, 200)
	legacy, err := f.s.accountToken(f.tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	var association any
	if err = f.s.db.QueryRow("SELECT auth_session_id FROM tokens WHERE hash=?", tokenHash(legacy)).Scan(&association); err != nil || association != nil {
		t.Fatal("legacy token was implicitly upgraded")
	}
	apiCall(t, f.s, "GET", "/v1/me", legacy, nil, 200)
	apiCall(t, f.s, "POST", "/v1/tenants/logout", other.Token, map[string]any{}, 200)
	apiCall(t, f.s, "GET", "/v1/me", legacy, nil, 200)
}

func TestAuthRefreshSchemaTwoMigrationPreservesLegacyGrants(t *testing.T) {
	s := apiFixture(t, Config{UsageFlushInterval: time.Hour})
	tenant := uuid()
	authExec(t, s, "INSERT INTO tenants(id,name,email,password_hash,status,relay_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", tenant, "migration-auth", "migration@example.invalid", "unused", "active", 1, now(), now())
	token, err := s.accountToken(tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	broker, device := fixtureBroker(t, s, token, "legacy-host")
	cfg := s.cfg
	path := cfg.DBPath
	var expiry int64
	if err = s.db.QueryRow("SELECT expires_at FROM tokens WHERE hash=?", tokenHash(token)).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	// Physically restore the original schema-two tables, not just its version label.
	_, err = db.Exec("DROP INDEX tokens_auth_session; DROP INDEX connections_auth_session; ALTER TABLE tokens DROP COLUMN auth_session_id; ALTER TABLE connections DROP COLUMN auth_session_id; ALTER TABLE sessions DROP COLUMN auth_session_id; DROP TABLE auth_sessions; UPDATE schema_version SET version=2;")
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	migrated := apiFixture(t, cfg)
	apiCall(t, migrated, "GET", "/v1/me", token, nil, 200)
	apiCall(t, migrated, "POST", "/v1/brokers/"+broker+"/heartbeat", device, nil, 200)
	var got int64
	var association any
	if err = migrated.db.QueryRow("SELECT expires_at,auth_session_id FROM tokens WHERE hash=?", tokenHash(token)).Scan(&got, &association); err != nil || got != expiry || association != nil {
		t.Fatal("migration altered legacy authority", got, expiry, association, err)
	}
	var version int
	if err = migrated.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 3 {
		t.Fatal(version, err)
	}
}

func TestAuthRefreshReceiptSurvivesServerRestart(t *testing.T) {
	s := apiFixture(t, Config{RegistrationPolicy: "open", UsageFlushInterval: time.Hour})
	out := apiCall(t, s, "POST", "/v1/auth/register", "", map[string]any{"name": "restart-refresh", "password": fixturePassword}, 201)
	c := authCredentials{AuthSessionID: out["auth_session_id"].(string), RefreshToken: out["refresh_token"].(string), Generation: 1}
	body := refreshBody(c)
	first := apiCall(t, s, "POST", "/v1/auth/refresh", c.RefreshToken, body, 200)
	cfg := s.cfg
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := apiFixture(t, cfg)
	second := apiCall(t, restarted, "POST", "/v1/auth/refresh", c.RefreshToken, body, 200)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("restart lost exact durable receipt")
	}
	apiCall(t, restarted, "GET", "/v1/me", body["next_token"].(string), nil, 200)
}

func TestAuthRefreshSessionAdmissionAndLegacyEvictionIsolation(t *testing.T) {
	f := refreshFixture(t, Config{})
	h, err := passwordHash(fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	authExec(t, f.s, "UPDATE tenants SET password_hash=? WHERE id=?", h, f.tenant)
	for i := 0; i < 16; i++ {
		if _, err = f.s.accountToken(f.tenant, 1); err != nil {
			t.Fatal(err)
		}
	}
	login := map[string]any{"name": "auth-fixture", "password": fixturePassword}
	apiCall(t, f.s, "POST", "/v1/auth/login", "", login, 200)
	var legacy int
	if err = f.s.db.QueryRow("SELECT COUNT(*) FROM tokens WHERE kind='account' AND auth_session_id IS NULL").Scan(&legacy); err != nil || legacy != 16 {
		t.Fatal("refresh login evicted legacy grants", legacy, err)
	}
	for i := 0; i < 20; i++ {
		rotateFixture(t, &f)
	}
	apiCall(t, f.s, "POST", "/v1/tenants/login", "", login, 200)
	apiCall(t, f.s, "GET", "/v1/me", f.account, nil, 200)
	var associated int
	if err = f.s.db.QueryRow("SELECT COUNT(*) FROM tokens WHERE auth_session_id=? AND kind='account'", f.credentials.AuthSessionID).Scan(&associated); err != nil || associated > 2 {
		t.Fatal("rotation accumulated access rows", associated, err)
	}
	for i := 0; i < 14; i++ {
		tx, _ := f.s.db.Begin()
		_, err = f.s.issueAuthSession(tx, f.tenant, 1)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	out := apiCall(t, f.s, "POST", "/v1/auth/login", "", login, 429)
	if out["error_code"] != "auth_session_limit" {
		t.Fatal(out)
	}
	rotateFixture(t, &f)
}

func TestAuthRefreshUnmanagedSessionChecksCallerAuthority(t *testing.T) {
	f := refreshFixture(t, Config{TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true}})
	legacy, err := f.s.accountToken(f.tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	broker, device := fixtureBroker(t, f.s, legacy, "independent-legacy-host")
	out := apiCall(t, f.s, "POST", "/v1/sessions", f.account, map[string]any{"broker_id": broker, "relay_mode": "force"}, 201)
	sid := out["session_id"].(string)
	apiCall(t, f.s, "POST", "/v1/sessions/"+sid+"/approve", device, map[string]any{"peer_authenticated": true, "relay": true}, 200)
	if !f.s.authorizeTURNIdentity(f.tenant, broker, sid) {
		t.Fatal("healthy session denied")
	}
	authExec(t, f.s, "UPDATE auth_sessions SET refresh_expires_at=0 WHERE id=?", f.credentials.AuthSessionID)
	apiCall(t, f.s, "POST", "/v1/sessions/"+sid+"/heartbeat", device, nil, 401)
	if f.s.authorizeTURNIdentity(f.tenant, broker, sid) {
		t.Fatal("legacy device continued expired login's session")
	}
	apiCall(t, f.s, "POST", "/v1/auth/logout", f.credentials.RefreshToken, nil, 200)
	var count int
	if err = f.s.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sid).Scan(&count); err != nil || count != 0 {
		t.Fatal("logout left unmanaged session", count, err)
	}
	apiCall(t, f.s, "POST", "/v1/brokers/"+broker+"/heartbeat", device, nil, 200)
}

func TestAuthRefreshDeviceRotationCannotReviveRevokedConnection(t *testing.T) {
	f := refreshFixture(t, Config{})
	id := uuid()
	body := connectionBody(f.connectionFixtureData, 0)
	connectionOpen(t, f.connectionFixtureData, id, body, 201)
	apiCall(t, f.s, "POST", "/v1/brokers/"+f.broker+"/offline", f.device, nil, 200)
	rotated := apiCall(t, f.s, "POST", "/v1/brokers/"+f.broker+"/token", f.account, nil, 200)
	f.device = rotated["device_token"].(string)
	if err := f.s.pruneConnections(); err != nil {
		t.Fatal(err)
	}
	rotateFixture(t, &f)
	connectionOpen(t, f.connectionFixtureData, id, body, 403)
	fresh := uuid()
	connectionOpen(t, f.connectionFixtureData, fresh, connectionBody(f.connectionFixtureData, 0), 201)
}

func TestAuthRefreshUnknownProofAndDisableFailClosed(t *testing.T) {
	f := refreshFixture(t, Config{})
	body := refreshBody(f.credentials)
	out := apiCall(t, f.s, "POST", "/v1/auth/refresh", randomSecret(), body, 401)
	if out["error_code"] != "refresh_invalid" {
		t.Fatal(out)
	}
	apiCall(t, f.s, "GET", "/v1/me", f.account, nil, 200)
	apiCall(t, f.s, "POST", "/v1/admin/tenants/"+f.tenant+"/disable", fixtureAdmin, map[string]any{}, 200)
	out = apiCall(t, f.s, "POST", "/v1/auth/refresh", f.credentials.RefreshToken, body, 401)
	if out["error_code"] != "refresh_revoked" {
		t.Fatal(out)
	}
}
