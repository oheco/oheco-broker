package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type connectionDecodeFault struct {
	source io.Reader
	once   sync.Once
	revoke func()
}

func (r *connectionDecodeFault) Read(data []byte) (int, error) {
	r.once.Do(r.revoke)
	return r.source.Read(data)
}

func TestConnectionRecoveryRevalidatesAfterRequestDecoding(t *testing.T) {
	for _, kind := range []string{"account", "device"} {
		t.Run(kind, func(t *testing.T) {
			f := connectionFixture(t, Config{})
			id := uuid()
			connectionOpen(t, f, id, connectionBody(f, 0), 201)
			raw, _ := json.Marshal(connectionBody(f, 1))
			token := f.account
			if kind == "device" {
				token = f.device
			}
			reader := &connectionDecodeFault{source: bytes.NewReader(raw), revoke: func() {
				if _, err := f.s.db.Exec("DELETE FROM tokens WHERE hash=?", tokenHash(token)); err != nil {
					t.Fatal(err)
				}
			}}
			r := httptest.NewRequest("POST", "/v1/connections/"+id+"/session", reader)
			r.Header.Set("Authorization", "Bearer "+f.account)
			w := httptest.NewRecorder()
			f.s.Handler().ServeHTTP(w, r)
			want := 401
			if kind == "device" {
				want = 403
			}
			if w.Code != want {
				t.Fatal("stale pre-decode authorization", w.Code, w.Body.String())
			}
			c, err := readConnection(f.s.db, id)
			if err != nil || c.Generation != 1 {
				t.Fatal("revocation race minted a session", c, err)
			}
		})
	}
}

func TestConnectionRecoveryHistoryRemainsBoundedBeyond256Generations(t *testing.T) {
	f := connectionFixture(t, Config{})
	id := uuid()
	for generation := uint64(0); generation < 270; generation++ {
		connectionOpen(t, f, id, connectionBody(f, generation), 201)
	}
	var count int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM connection_sessions WHERE connection_id=?", id).Scan(&count); err != nil || count > 257 {
		t.Fatal("unbounded history", count, err)
	}
	out := connectionOpen(t, f, id, connectionBody(f, 270), 201)
	if out["generation"] != float64(271) {
		t.Fatal("history imposed a connection lifetime limit", out)
	}
	apiCall(t, f.s, "DELETE", "/v1/connections/"+id, f.account, nil, 200)
	connectionOpen(t, f, id, connectionBody(f, 271), 403)
}

func TestConnectionRecoveryRacesHistoricalRevocation(t *testing.T) {
	f := connectionFixture(t, Config{})
	id := uuid()
	body := connectionBody(f, 0)
	oldSID := connectionOpen(t, f, id, body, 201)["session_id"].(string)
	start := make(chan struct{})
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		raw, _ := json.Marshal(connectionBody(f, 1))
		r := httptest.NewRequest("POST", "/v1/connections/"+id+"/session", bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+f.account)
		w := httptest.NewRecorder()
		f.s.Handler().ServeHTTP(w, r)
		codes <- w.Code
	}()
	go func() {
		defer wg.Done()
		<-start
		r := httptest.NewRequest("DELETE", "/v1/sessions/"+oldSID, nil)
		r.Header.Set("Authorization", "Bearer "+f.device)
		w := httptest.NewRecorder()
		f.s.Handler().ServeHTTP(w, r)
		codes <- w.Code
	}()
	close(start)
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 && code != 201 && code != 403 {
			t.Fatal("unexpected racing result", code)
		}
	}
	connectionOpen(t, f, id, connectionBody(f, 1), 403)
	var count int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil || count != 0 {
		t.Fatal("revocation lost to recovery", count, err)
	}
}

type connectionFixtureData struct {
	s                               *Server
	tenant, account, broker, device string
}

func connectionFixture(t *testing.T, cfg Config) connectionFixtureData {
	t.Helper()
	cfg.DBPath = ":memory:"
	cfg.UsageFlushInterval = time.Hour
	s := apiFixture(t, cfg)
	tenant := uuid()
	if _, err := s.db.Exec("INSERT INTO tenants(id,name,email,password_hash,status,relay_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", tenant, "connection-fixture", "fixture@example.invalid", "unused-no-password-login", "active", 1, now(), now()); err != nil {
		t.Fatal(err)
	}
	account, err := s.accountToken(tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	out := apiCall(t, s, "POST", "/v1/brokers", account, map[string]any{"name": "connection-broker"}, 201)
	return connectionFixtureData{s, tenant, account, out["broker"].(map[string]any)["id"].(string), out["device_token"].(string)}
}
func connectionBody(f connectionFixtureData, generation uint64) map[string]any {
	return map[string]any{"broker_id": f.broker, "relay_mode": "never", "expected_generation": generation, "request_id": uuid(), "session_token": randomSecret()}
}
func connectionOpen(t *testing.T, f connectionFixtureData, id string, body map[string]any, status int) map[string]any {
	t.Helper()
	return apiCall(t, f.s, "POST", "/v1/connections/"+id+"/session", f.account, body, status)
}

func TestConnectionRecoveryReplaysAndFreshAuthorization(t *testing.T) {
	f := connectionFixture(t, Config{})
	id := uuid()
	body := connectionBody(f, 0)
	created := connectionOpen(t, f, id, body, 201)
	if created["connection_id"] != id || created["generation"] != float64(1) || created["session_token"] != nil {
		t.Fatal("bad initial response", created)
	}
	sid := created["session_id"].(string)
	replay := connectionOpen(t, f, id, body, 200)
	if replay["session_id"] != sid || replay["generation"] != created["generation"] || replay["expires_at"] != created["expires_at"] {
		t.Fatal("lost reply replay changed grant", replay)
	}
	apiCall(t, f.s, "POST", "/v1/sessions/"+sid+"/approve", f.device, map[string]any{"peer_authenticated": true, "relay": false}, 200)
	status := apiCall(t, f.s, "GET", "/v1/sessions/"+sid, body["session_token"].(string), nil, 200)
	if status["peer_authenticated"] != true || status["connection_id"] != id || status["generation"] != float64(1) {
		t.Fatal(status)
	}
	if _, err := f.s.db.Exec("INSERT INTO messages(session_id,side,sequence,data) VALUES(?,'client',1,'old-authenticated-envelope')", sid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("DELETE FROM tokens WHERE session_id=?", sid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("DELETE FROM sessions WHERE id=?", sid); err != nil {
		t.Fatal(err)
	}
	// Natural expiry/GC is recoverable without reusing the old session/token.
	fresh := connectionBody(f, 1)
	resumed := connectionOpen(t, f, id, fresh, 201)
	newSID := resumed["session_id"].(string)
	if newSID == sid || resumed["generation"] != float64(2) {
		t.Fatal("not a fresh transport generation", resumed)
	}
	status = apiCall(t, f.s, "GET", "/v1/sessions/"+newSID, fresh["session_token"].(string), nil, 200)
	if status["peer_authenticated"] != false || status["relay_approved"] != false {
		t.Fatal("authorization proof was inherited", status)
	}
	apiCall(t, f.s, "GET", "/v1/sessions/"+sid, body["session_token"].(string), nil, 401)
	var count int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count); err != nil || count != 0 {
		t.Fatal("old mailbox survived", count, err)
	}
	connectionOpen(t, f, id, fresh, 200)
	conflict := connectionOpen(t, f, id, connectionBody(f, 1), 409)
	if conflict["error_code"] != "connection_conflict" || conflict["generation"] != float64(2) {
		t.Fatal(conflict)
	}
}

func TestConnectionExplicitRevocationNeverRecovers(t *testing.T) {
	for _, mode := range []string{"expired-session-delete", "old-generation-delete", "connection-delete", "offline", "rotation", "device-token-delete", "account-token-delete", "session-token-delete", "session-token-expire", "tenant-disable-enable", "tenant-version", "logout"} {
		t.Run(mode, func(t *testing.T) {
			f := connectionFixture(t, Config{})
			id := uuid()
			body := connectionBody(f, 0)
			out := connectionOpen(t, f, id, body, 201)
			sid := out["session_id"].(string)
			generation := uint64(1)
			switch mode {
			case "expired-session-delete":
				if _, err := f.s.db.Exec("UPDATE sessions SET expires_at=0 WHERE id=?", sid); err != nil {
					t.Fatal(err)
				}
				apiCall(t, f.s, "DELETE", "/v1/sessions/"+sid, f.device, nil, 200)
			case "old-generation-delete":
				connectionOpen(t, f, id, connectionBody(f, 1), 201)
				generation = 2
				apiCall(t, f.s, "DELETE", "/v1/sessions/"+sid, f.account, nil, 200)
			case "connection-delete":
				apiCall(t, f.s, "DELETE", "/v1/connections/"+id, f.device, nil, 200)
			case "offline":
				apiCall(t, f.s, "POST", "/v1/brokers/"+f.broker+"/offline", f.device, nil, 200)
				apiCall(t, f.s, "POST", "/v1/brokers/"+f.broker+"/heartbeat", f.device, nil, 200)
			case "rotation":
				if _, err := f.s.db.Exec("UPDATE brokers SET lease_expires_at=0 WHERE id=?", f.broker); err != nil {
					t.Fatal(err)
				}
				apiCall(t, f.s, "POST", "/v1/brokers/"+f.broker+"/token", f.account, nil, 200)
			case "device-token-delete":
				if _, err := f.s.db.Exec("DELETE FROM tokens WHERE hash=?", tokenHash(f.device)); err != nil {
					t.Fatal(err)
				}
			case "account-token-delete":
				if _, err := f.s.db.Exec("DELETE FROM tokens WHERE hash=?", tokenHash(f.account)); err != nil {
					t.Fatal(err)
				}
			case "session-token-delete":
				if _, err := f.s.db.Exec("DELETE FROM tokens WHERE hash=?", tokenHash(body["session_token"].(string))); err != nil {
					t.Fatal(err)
				}
			case "session-token-expire":
				if _, err := f.s.db.Exec("UPDATE tokens SET expires_at=0 WHERE hash=?", tokenHash(body["session_token"].(string))); err != nil {
					t.Fatal(err)
				}
			case "tenant-disable-enable":
				if _, err := f.s.db.Exec("UPDATE tenants SET status='disabled' WHERE id=?", f.tenant); err != nil {
					t.Fatal(err)
				}
				tenant, version, err := f.s.tenant(f.tenant)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.s.updateCapabilities(tenant, true, false, version); err != nil {
					t.Fatal(err)
				}
				if _, err = f.s.db.Exec("UPDATE tenants SET status='active' WHERE id=?", f.tenant); err != nil {
					t.Fatal(err)
				}
			case "tenant-version":
				if _, err := f.s.db.Exec("UPDATE tenants SET version=version+1 WHERE id=?", f.tenant); err != nil {
					t.Fatal(err)
				}
			case "logout":
				apiCall(t, f.s, "POST", "/v1/tenants/logout", f.account, nil, 200)
			}
			want := 403
			if mode == "account-token-delete" || mode == "tenant-version" || mode == "logout" {
				want = 401
			}
			connectionOpen(t, f, id, connectionBody(f, generation), want)
			// Replaying a successfully returned request must revalidate revoke.
			connectionOpen(t, f, id, body, want)
		})
	}
}

func TestConnectionBrokerLeaseRecoveryAndUnknownLineage(t *testing.T) {
	f := connectionFixture(t, Config{})
	id := uuid()
	connectionOpen(t, f, id, connectionBody(f, 0), 201)
	if _, err := f.s.db.Exec("UPDATE brokers SET lease_expires_at=0 WHERE id=?", f.broker); err != nil {
		t.Fatal(err)
	}
	out := connectionOpen(t, f, id, connectionBody(f, 1), 409)
	if out["error_code"] != "broker_offline" {
		t.Fatal(out)
	}
	apiCall(t, f.s, "POST", "/v1/brokers/"+f.broker+"/heartbeat", f.device, nil, 200)
	connectionOpen(t, f, id, connectionBody(f, 1), 201)
	out = connectionOpen(t, f, uuid(), connectionBody(f, 1), 404)
	if out["error_code"] != "connection_unknown" {
		t.Fatal(out)
	}
}

func TestConnectionExpiredLostReplyReturnsEpoch(t *testing.T) {
	f := connectionFixture(t, Config{})
	id := uuid()
	body := connectionBody(f, 0)
	out := connectionOpen(t, f, id, body, 201)
	if _, err := f.s.db.Exec("DELETE FROM tokens WHERE session_id=?", out["session_id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec("DELETE FROM sessions WHERE id=?", out["session_id"]); err != nil {
		t.Fatal(err)
	}
	out = connectionOpen(t, f, id, body, 410)
	if out["error_code"] != "session_expired" || out["generation"] != float64(1) {
		t.Fatal(out)
	}
	connectionOpen(t, f, id, connectionBody(f, 1), 201)
}

func TestConnectionRecoveryConcurrentCASAndDelete(t *testing.T) {
	f := connectionFixture(t, Config{})
	id := uuid()
	first := connectionBody(f, 0)
	out := connectionOpen(t, f, id, first, 201)
	oldSID := out["session_id"].(string)
	var wg sync.WaitGroup
	codes := make(chan int, 16)
	for i := 0; i < 16; i++ {
		body := connectionBody(f, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, _ := json.Marshal(body)
			r := httptest.NewRequest("POST", "/v1/connections/"+id+"/session", bytes.NewReader(raw))
			r.Header.Set("Authorization", "Bearer "+f.account)
			w := httptest.NewRecorder()
			f.s.Handler().ServeHTTP(w, r)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	created, conflicts := 0, 0
	for code := range codes {
		if code == 201 {
			created++
		} else if code == 409 {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent status %d", code)
		}
	}
	if created != 1 || conflicts != 15 {
		t.Fatal(created, conflicts)
	}
	apiCall(t, f.s, "DELETE", "/v1/sessions/"+oldSID, f.device, nil, 200)
	connectionOpen(t, f, id, connectionBody(f, 2), 403)
	var count int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil || count != 0 {
		t.Fatal("old SID revocation left a replacement", count, err)
	}
}

func TestConnectionWebSocketRevocationClassificationAfterTransportDeletion(t *testing.T) {
	for _, mode := range []string{"explicit-delete", "historical-delete", "natural-expiry", "replacement", "account-gc", "device-revoke"} {
		t.Run(mode, func(t *testing.T) {
			f := connectionFixture(t, Config{})
			id := uuid()
			body := connectionBody(f, 0)
			sid := connectionOpen(t, f, id, body, 201)["session_id"].(string)
			oldSID := sid
			if mode == "historical-delete" {
				body = connectionBody(f, 1)
				sid = connectionOpen(t, f, id, body, 201)["session_id"].(string)
			}
			h := httptest.NewServer(f.s.Handler())
			defer h.Close()
			client := wsConnect(t, h, "/v1/ws/sessions/"+sid, body["session_token"].(string))
			defer client.Close()
			server := wsConnect(t, h, "/v1/ws/sessions/"+sid, f.device)
			defer server.Close()
			wsUntil(t, client, "capabilities")
			wsUntil(t, server, "capabilities")
			code, status := "connection_revoked", float64(403)
			switch mode {
			case "explicit-delete":
				apiCall(t, f.s, "DELETE", "/v1/connections/"+id, f.account, nil, 200)
			case "historical-delete":
				apiCall(t, f.s, "DELETE", "/v1/sessions/"+oldSID, f.device, nil, 200)
			case "natural-expiry":
				if _, err := f.s.db.Exec("UPDATE sessions SET expires_at=0 WHERE id=?", sid); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.db.Exec("DELETE FROM tokens WHERE session_id=?", sid); err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.db.Exec("DELETE FROM sessions WHERE id=?", sid); err != nil {
					t.Fatal(err)
				}
				f.s.notifyWSSession(sid)
				code, status = "session_expired", 410
			case "replacement":
				connectionOpen(t, f, id, connectionBody(f, 1), 201)
				code, status = "session_replaced", 409
			case "account-gc":
				if _, err := f.s.db.Exec("DELETE FROM tokens WHERE hash=?", tokenHash(f.account)); err != nil {
					t.Fatal(err)
				}
				if err := f.s.pruneConnections(); err != nil {
					t.Fatal(err)
				}
				code = "credential_revoked"
			case "device-revoke":
				if _, err := f.s.db.Exec("DELETE FROM tokens WHERE hash=?", tokenHash(f.device)); err != nil {
					t.Fatal(err)
				}
				f.s.notifyWSSession(sid)
				code = "credential_revoked"
			}
			for _, revoked := range []map[string]any{wsUntil(t, client, "revoked"), wsUntil(t, server, "revoked")} {
				if revoked["status"] != status || revoked["body"].(map[string]any)["error_code"] != code {
					t.Fatalf("%s lost authorization classification: %v", mode, revoked)
				}
			}
			if mode == "natural-expiry" || mode == "replacement" {
				generation := uint64(1)
				if mode == "replacement" {
					generation = 2
				}
				connectionOpen(t, f, id, connectionBody(f, generation), 201)
			} else {
				connectionOpen(t, f, id, connectionBody(f, 1), map[string]int{"explicit-delete": 403, "historical-delete": 403, "account-gc": 401, "device-revoke": 403}[mode])
			}
		})
	}
}

func TestConnectionDiscoveryWebSocketSnapshotsAndTokenRevoke(t *testing.T) {
	f := connectionFixture(t, Config{})
	id := uuid()
	body := connectionBody(f, 0)
	out := connectionOpen(t, f, id, body, 201)
	sid := out["session_id"].(string)
	status := apiCall(t, f.s, "GET", "/v1/status", "", nil, 200)
	if status["connection_recovery_version"] != float64(1) {
		t.Fatal(status)
	}
	h := httptest.NewServer(f.s.Handler())
	defer h.Close()
	watch := wsConnect(t, h, "/v1/ws/brokers/"+f.broker, f.device)
	defer watch.Close()
	snapshot := wsUntil(t, watch, "sessions")["body"].(map[string]any)["sessions"].([]any)
	if len(snapshot) != 1 || snapshot[0].(map[string]any)["connection_id"] != id || snapshot[0].(map[string]any)["generation"] != float64(1) {
		t.Fatal(snapshot)
	}
	client := wsConnect(t, h, "/v1/ws/sessions/"+sid, body["session_token"].(string))
	defer client.Close()
	caps := wsUntil(t, client, "capabilities")["body"].(map[string]any)
	if caps["connection_id"] != id {
		t.Fatal(caps)
	}
	if _, err := f.s.db.Exec("DELETE FROM tokens WHERE hash=?", tokenHash(f.account)); err != nil {
		t.Fatal(err)
	}
	f.s.notifyWSTenant(f.tenant)
	revoked := wsUntil(t, client, "revoked")["body"].(map[string]any)
	if revoked["error_code"] != "credential_revoked" {
		t.Fatal(revoked)
	}
	if err := f.s.pruneConnections(); err != nil {
		t.Fatal(err)
	}
	// Credential GC cannot strip metadata and accidentally turn a v2 grant
	// into an unbound legacy session.
	apiCall(t, f.s, "GET", "/v1/sessions/"+sid, body["session_token"].(string), nil, 401)
}

func TestConnectionScopeBoundsAndUsedSecrets(t *testing.T) {
	f := connectionFixture(t, Config{MaxSessionsPerTenant: 1})
	id := uuid()
	body := connectionBody(f, 0)
	connectionOpen(t, f, id, body, 201)
	connectionOpen(t, f, uuid(), connectionBody(f, 0), 429)
	replay := connectionBody(f, 1)
	replay["session_token"] = body["session_token"]
	connectionOpen(t, f, id, replay, 409)
	if _, err := f.s.db.Exec("UPDATE tokens SET expires_at=0 WHERE hash=?", tokenHash(f.device)); err != nil {
		t.Fatal(err)
	}
	connectionOpen(t, f, id, connectionBody(f, 1), 403)
	if err := f.s.pruneConnections(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count); err != nil || count != 1 {
		t.Fatal("lost creation retries still require the revoked ID tombstone", count, err)
	}
	connectionOpen(t, f, id, body, 403)
	if _, err := f.s.db.Exec("UPDATE tokens SET expires_at=0 WHERE hash=?", tokenHash(f.account)); err != nil {
		t.Fatal(err)
	}
	if err := f.s.pruneConnections(); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count); err != nil || count != 0 {
		t.Fatal("dead caller authority should release tombstones", count, err)
	}
}

func TestConnectionObservedSessionCredentialRevocationSurvivesTransportGC(t *testing.T) {
	for _, mode := range []string{"delete", "early-expire", "database-observer"} {
		t.Run(mode, func(t *testing.T) {
			f := connectionFixture(t, Config{})
			id := uuid()
			body := connectionBody(f, 0)
			sid := connectionOpen(t, f, id, body, 201)["session_id"].(string)
			query := "DELETE FROM tokens WHERE hash=?"
			if mode == "early-expire" {
				query = "UPDATE tokens SET expires_at=0 WHERE hash=?"
			}
			if _, err := f.s.db.Exec(query, tokenHash(body["session_token"].(string))); err != nil {
				t.Fatal(err)
			}
			if mode == "database-observer" {
				apiCall(t, f.s, "GET", "/v1/sessions/"+sid, f.device, nil, 403)
			} else {
				connectionOpen(t, f, id, connectionBody(f, 1), 403)
			}
			var revoked string
			if err := f.s.db.QueryRow("SELECT revoked_reason FROM connections WHERE id=?", id).Scan(&revoked); err != nil || revoked == "" {
				t.Fatal("observed revocation was not committed outside failed transaction", revoked, err)
			}
			if _, err := f.s.db.Exec("UPDATE sessions SET expires_at=0 WHERE id=?", sid); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.db.Exec("DELETE FROM tokens WHERE session_id=?", sid); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.db.Exec("DELETE FROM sessions WHERE id=?", sid); err != nil {
				t.Fatal(err)
			}
			out := connectionOpen(t, f, id, connectionBody(f, 1), 403)
			if out["error_code"] != "connection_revoked" {
				t.Fatal(out)
			}
			connectionOpen(t, f, id, body, 403)
			var count int
			if err := f.s.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count); err != nil || count != 0 {
				t.Fatal("observed revocation minted successor after expiry/GC", count, err)
			}
		})
	}
}

func TestConnectionActiveQuotaFreesOnCloseWithoutDiscardingTombstones(t *testing.T) {
	f := connectionFixture(t, Config{MaxSessionsPerTenant: 1})
	for iteration := 0; iteration < 6; iteration++ {
		id := uuid()
		first := connectionBody(f, 0)
		connectionOpen(t, f, id, first, 201)
		connectionOpen(t, f, id, first, 200)
		recovery := connectionBody(f, 1)
		connectionOpen(t, f, id, recovery, 201)
		connectionOpen(t, f, id, recovery, 200)
		connectionOpen(t, f, uuid(), connectionBody(f, 0), 429)
		apiCall(t, f.s, "DELETE", "/v1/connections/"+id, f.account, nil, 200)
		// A lost initial response cannot recreate this explicitly closed ID.
		connectionOpen(t, f, id, first, 403)
	}
	var total, active int
	if err := f.s.db.QueryRow("SELECT COUNT(*),COALESCE(SUM(revoked_reason=''),0) FROM connections").Scan(&total, &active); err != nil || total != 6 || active != 0 {
		t.Fatal("active quota or retained tombstones incorrect", total, active, err)
	}
	connectionOpen(t, f, uuid(), connectionBody(f, 0), 201)
}

func TestConnectionSchemaMigrationPersistsLegacyData(t *testing.T) {
	f := connectionFixture(t, Config{})
	if _, err := f.s.db.Exec("DROP TABLE connection_sessions; DROP TABLE connections; UPDATE schema_version SET version=1;"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.migrate(); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := f.s.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 3 {
		t.Fatal(version, err)
	}
	apiCall(t, f.s, "GET", "/v1/brokers/"+f.broker, f.account, nil, 200)
	connectionOpen(t, f, uuid(), connectionBody(f, 0), 201)
	legacy := apiCall(t, f.s, "POST", "/v1/sessions", f.account, map[string]any{"broker_id": f.broker}, 201)
	status := apiCall(t, f.s, "GET", "/v1/sessions/"+legacy["session_id"].(string), legacy["session_token"].(string), nil, 200)
	if status["connection_id"] != nil || status["generation"] != nil {
		t.Fatal("legacy response changed", status)
	}
}
