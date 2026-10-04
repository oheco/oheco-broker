package control

import (
	"testing"
	"time"
)

type turnIdentityFixtureData struct {
	connectionFixtureData
	connection, session, token string
}

func turnIdentityFixture(t *testing.T, cfg Config) turnIdentityFixtureData {
	t.Helper()
	f := connectionFixture(t, cfg)
	id := uuid()
	body := connectionBody(f, 0)
	body["relay_mode"] = "auto"
	out := connectionOpen(t, f, id, body, 201)
	v := turnIdentityFixtureData{f, id, out["session_id"].(string), body["session_token"].(string)}
	turnIdentityExec(t, v, "UPDATE sessions SET peer_authenticated=1,relay_approved=1 WHERE id=?", v.session)
	if !f.s.authorizeTURNIdentity(f.tenant, f.broker, v.session) {
		t.Fatal("healthy managed fixture was not authorized")
	}
	return v
}

func turnIdentityExec(t *testing.T, f turnIdentityFixtureData, query string, args ...any) {
	t.Helper()
	if _, err := f.s.db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

// Keep an independent oracle for the previous identity checks. Calling the
// public wrapper here would compare the joined helper with itself after wiring.
func turnIdentityReference(s *Server, tenant, broker, session string) bool {
	t, _, err := s.tenant(tenant)
	if err != nil || t.Status != "active" || !t.RelayEnabled {
		return false
	}
	b, err := s.broker(broker)
	if err != nil || b.TenantID != tenant || !b.Online {
		return false
	}
	v, err := s.session(session)
	return err == nil && s.managedSession(v) == nil && v.TenantID == tenant && v.BrokerID == broker &&
		v.PeerAuthenticated && v.RelayApproved && v.RelayMode != "never" && v.ExpiresAt.After(time.Now())
}

func TestTURNAuthorizationIdentityMatchesExistingChecks(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, turnIdentityFixtureData)
		allow  bool
	}{
		{"healthy", func(t *testing.T, f turnIdentityFixtureData) {}, true},
		{"account_null_broker", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE tokens SET broker_id=NULL WHERE hash=?", tokenHash(f.account))
		}, true},
		{"account_empty_broker", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE tokens SET broker_id='' WHERE hash=?", tokenHash(f.account))
		}, true},
		{"session_token_scope_unchanged", func(t *testing.T, f turnIdentityFixtureData) {
			// checkConnection binds the session token by hash, kind, session and
			// version; it does not add an account/device broker scope to it.
			turnIdentityExec(t, f, "UPDATE tokens SET broker_id='different' WHERE hash=?", tokenHash(f.token))
		}, true},
		{"relay_nonzero", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE tenants SET relay_enabled=2 WHERE id=?", f.tenant)
		}, true},
		{"tenant_disabled", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE tenants SET status='disabled' WHERE id=?", f.tenant)
		}, false},
		{"relay_disabled", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE tenants SET relay_enabled=0 WHERE id=?", f.tenant)
		}, false},
		{"tenant_version", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE tenants SET version=version+1 WHERE id=?", f.tenant)
		}, false},
		{"broker_offline", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE brokers SET lease_expires_at=0 WHERE id=?", f.broker)
		}, false},
		{"session_unauthenticated", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE sessions SET peer_authenticated=0 WHERE id=?", f.session)
		}, false},
		{"session_unapproved", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE sessions SET relay_approved=0 WHERE id=?", f.session)
		}, false},
		{"session_relay_never", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE sessions SET relay_mode='never' WHERE id=?", f.session)
		}, false},
		{"session_expired", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE sessions SET expires_at=0 WHERE id=?", f.session)
		}, false},
		{"connection_revoked", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE connections SET revoked_reason='explicit' WHERE id=?", f.connection)
		}, false},
		{"connection_missing", func(t *testing.T, f turnIdentityFixtureData) {
			// Retain the transport but remove its lineage, as a missing JOIN row
			// must never be treated as an authorized managed connection.
			turnIdentityExec(t, f, "PRAGMA foreign_keys=OFF")
			turnIdentityExec(t, f, "DELETE FROM connections WHERE id=?", f.connection)
		}, false},
		{"generation_replaced", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE connections SET generation=generation+1 WHERE id=?", f.connection)
		}, false},
		{"current_session_replaced", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE connections SET current_session_id=? WHERE id=?", uuid(), f.connection)
		}, false},
		{"invalid_generation_type", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE connection_sessions SET generation=-1 WHERE session_id=?", f.session)
			turnIdentityExec(t, f, "UPDATE connections SET generation=-1 WHERE id=?", f.connection)
		}, false},
		{"invalid_version_type", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE tenants SET version='invalid' WHERE id=?", f.tenant)
			turnIdentityExec(t, f, "UPDATE connections SET tenant_version='invalid' WHERE id=?", f.connection)
			turnIdentityExec(t, f, "UPDATE tokens SET version='invalid' WHERE tenant_id=?", f.tenant)
		}, false},
		{"invalid_relay_type", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE tenants SET relay_enabled='invalid' WHERE id=?", f.tenant)
		}, false},
		{"invalid_authenticated_type", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE sessions SET peer_authenticated='invalid' WHERE id=?", f.session)
		}, false},
		{"invalid_approved_type", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE sessions SET relay_approved='invalid' WHERE id=?", f.session)
		}, false},
		{"invalid_approved_fraction", func(t *testing.T, f turnIdentityFixtureData) {
			turnIdentityExec(t, f, "UPDATE sessions SET relay_approved=0.5 WHERE id=?", f.session)
		}, false},
	}
	for _, credential := range []string{"account", "device", "session"} {
		for _, mutation := range []string{"delete", "expire", "kind", "version", "scope", "tenant"} {
			if credential == "session" && (mutation == "scope" || mutation == "tenant") {
				continue
			}
			cases = append(cases, struct {
				name   string
				mutate func(*testing.T, turnIdentityFixtureData)
				allow  bool
			}{credential + "_" + mutation, func(t *testing.T, f turnIdentityFixtureData) {
				token := f.account
				if credential == "device" {
					token = f.device
				} else if credential == "session" {
					token = f.token
				}
				query := "DELETE FROM tokens WHERE hash=?"
				args := []any{tokenHash(token)}
				switch mutation {
				case "expire":
					query = "UPDATE tokens SET expires_at=0 WHERE hash=?"
				case "kind":
					query = "UPDATE tokens SET kind='wrong' WHERE hash=?"
				case "version":
					query = "UPDATE tokens SET version=version+1 WHERE hash=?"
				case "scope":
					query = "UPDATE tokens SET broker_id='wrong' WHERE hash=?"
				case "tenant":
					other := uuid()
					turnIdentityExec(t, f, "INSERT INTO tenants(id,name,email,password_hash,status,relay_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", other, "other-tenant", "other@example.invalid", "unused", "active", 1, now(), now())
					query = "UPDATE tokens SET tenant_id=? WHERE hash=?"
					args = []any{other, tokenHash(token)}
				}
				turnIdentityExec(t, f, query, args...)
				if credential == "account" {
					// Another live account token cannot replace the original hash.
					if _, err := f.s.accountToken(f.tenant, 1); err != nil {
						t.Fatal(err)
					}
				} else if credential == "device" {
					// A replacement device credential also cannot satisfy the
					// original lineage's exact device hash.
					turnIdentityExec(t, f, "INSERT INTO tokens(hash,kind,tenant_id,broker_id,version,expires_at) VALUES(?,?,?,?,?,?)", tokenHash(randomSecret()), "device", f.tenant, f.broker, 1, timestamp(time.Now().Add(time.Minute)))
				}
			}, false})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := turnIdentityFixture(t, Config{})
			tc.mutate(t, f)
			got := f.s.authorizeTURNIdentity(f.tenant, f.broker, f.session)
			want := turnIdentityReference(f.s, f.tenant, f.broker, f.session)
			if got != tc.allow || got != want {
				t.Fatalf("joined authorization=%v reference=%v expected=%v", got, want, tc.allow)
			}
		})
	}
}

func TestTURNAuthorizationLegacyScopeAndMissingRows(t *testing.T) {
	f := connectionFixture(t, Config{})
	sid, token := fixtureSession(t, f.s, f.account, f.broker)
	v := turnIdentityFixtureData{f, "", sid, token}
	turnIdentityExec(t, v, "UPDATE sessions SET peer_authenticated=1,relay_approved=1,relay_mode='auto' WHERE id=?", sid)
	turnIdentityExec(t, v, "DELETE FROM tokens WHERE hash=?", tokenHash(token))
	if !f.s.authorizeTURNIdentity(f.tenant, f.broker, sid) || !turnIdentityReference(f.s, f.tenant, f.broker, sid) {
		t.Fatal("legacy identity acquired a new session-token requirement")
	}
	for _, args := range [][3]string{{uuid(), f.broker, sid}, {f.tenant, uuid(), sid}, {f.tenant, f.broker, uuid()}} {
		if f.s.authorizeTURNIdentity(args[0], args[1], args[2]) {
			t.Fatal("missing identity row was authorized")
		}
	}
	other := apiCall(t, f.s, "POST", "/v1/brokers", f.account, map[string]any{"name": "other-broker"}, 201)
	if f.s.authorizeTURNIdentity(f.tenant, other["broker"].(map[string]any)["id"].(string), sid) {
		t.Fatal("session was authorized under another broker")
	}
	turnIdentityExec(t, v, "UPDATE tenants SET version='invalid' WHERE id=?", f.tenant)
	if f.s.authorizeTURNIdentity(f.tenant, f.broker, sid) || turnIdentityReference(f.s, f.tenant, f.broker, sid) {
		t.Fatal("malformed legacy tenant version was authorized")
	}
}

func TestTURNAuthorizationObservedRevocationUnderCredentialGate(t *testing.T) {
	for _, mode := range []string{"delete", "early-expire"} {
		t.Run(mode, func(t *testing.T) {
			f := turnIdentityFixture(t, Config{TURN: TURNConfig{Enabled: true, ListenAddr: "127.0.0.1:0", PublicIP: "127.0.0.1", AllowLoopbackPeers: true}})
			creds, err := f.s.turn.mint(f.tenant, f.broker, f.session, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			credential := f.s.turn.credential(creds.Username)
			if credential == nil {
				t.Fatal("missing registered TURN credential")
			}
			query := "DELETE FROM tokens WHERE hash=?"
			if mode == "early-expire" {
				query = "UPDATE tokens SET expires_at=0 WHERE hash=?"
			}
			turnIdentityExec(t, f, query, tokenHash(f.token))
			// Force the cold authorization path here; asynchronous observation
			// of a warmed permission is covered by the cache worker tests.
			f.s.turnAuthCache.invalidateSession(f.session)
			// Hold the actual registered credential's gate, as the TURN packet
			// path does. Owning it here permits releasing it even on a failure,
			// so an accidental callback reentry cannot hang fixture cleanup.
			credential.gate.RLock()
			done := make(chan bool, 1)
			go func() { done <- f.s.turn.authorized(credential) }()
			select {
			case allowed := <-done:
				credential.gate.RUnlock()
				if allowed {
					t.Fatal("revoked token was authorized")
				}
			case <-time.After(2 * time.Second):
				credential.gate.RUnlock()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
				}
				t.Fatal("authorization tried to reenter the held TURN credential gate")
			}
			c, err := readConnection(f.s.db, f.connection)
			if err != nil || c.Revoked != "session_credential_revoked" {
				t.Fatal("TURN observation did not persist revocation", err)
			}
			turnIdentityExec(t, f, "DELETE FROM sessions WHERE id=?", f.session)
			connectionOpen(t, f.connectionFixtureData, f.connection, map[string]any{"broker_id": f.broker, "relay_mode": "auto", "expected_generation": uint64(1), "request_id": uuid(), "session_token": randomSecret()}, 403)
		})
	}
}

func TestTURNAuthorizationRevocationObservationOrder(t *testing.T) {
	for _, mode := range []string{"natural-expiry", "account-missing", "relay-disabled", "historical-session"} {
		t.Run(mode, func(t *testing.T) {
			f := turnIdentityFixture(t, Config{})
			session := f.session
			if mode == "historical-session" {
				body := connectionBody(f.connectionFixtureData, 1)
				body["relay_mode"] = "auto"
				current := connectionOpen(t, f.connectionFixtureData, f.connection, body, 201)["session_id"].(string)
				turnIdentityExec(t, f, "UPDATE sessions SET peer_authenticated=1,relay_approved=1 WHERE id=?", current)
				// Keep an expired historical transport to exercise the existing
				// check order: observe the live current token before rejecting the
				// historical generation or its expired transport lease.
				turnIdentityExec(t, f, "INSERT INTO sessions(id,tenant_id,broker_id,relay_mode,peer_authenticated,relay_approved,expires_at) VALUES(?,?,?,?,1,1,0)", session, f.tenant, f.broker, "auto")
				turnIdentityExec(t, f, "DELETE FROM tokens WHERE hash=?", tokenHash(body["session_token"].(string)))
			} else {
				turnIdentityExec(t, f, "DELETE FROM tokens WHERE hash=?", tokenHash(f.token))
				switch mode {
				case "natural-expiry":
					turnIdentityExec(t, f, "UPDATE sessions SET expires_at=0 WHERE id=?", session)
				case "account-missing":
					turnIdentityExec(t, f, "DELETE FROM tokens WHERE hash=?", tokenHash(f.account))
				case "relay-disabled":
					turnIdentityExec(t, f, "UPDATE tenants SET relay_enabled=0 WHERE id=?", f.tenant)
				}
			}
			if f.s.authorizeTURNIdentity(f.tenant, f.broker, session) {
				t.Fatal("invalid transport was authorized")
			}
			c, err := readConnection(f.s.db, f.connection)
			if err != nil {
				t.Fatal(err)
			}
			if (c.Revoked != "") != (mode == "historical-session") {
				t.Fatal("authorization changed the revocation observation order")
			}
		})
	}
}

func TestTURNAuthorizationDatabaseErrorDenies(t *testing.T) {
	f := turnIdentityFixture(t, Config{})
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	if f.s.authorizeTURNIdentity(f.tenant, f.broker, f.session) {
		t.Fatal("database error was authorized")
	}
}

func TestTURNAuthorizationChecksTimeAfterDatabaseWait(t *testing.T) {
	f := turnIdentityFixture(t, Config{})
	tx, err := f.s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	expires := timestamp(time.Now().Add(80 * time.Millisecond))
	if _, err := tx.Exec("UPDATE brokers SET lease_expires_at=? WHERE id=?", expires, f.broker); err != nil {
		t.Fatal(err)
	}
	started, done := make(chan struct{}), make(chan bool, 1)
	go func() {
		close(started)
		done <- f.s.authorizeTURNIdentity(f.tenant, f.broker, f.session)
	}()
	<-started
	timer := time.NewTimer(time.Until(fromTimestamp(expires)) + 20*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case allowed := <-done:
		if allowed {
			t.Fatal("lease expired while waiting for the DB but was authorized")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authorization did not finish after releasing the database connection")
	}
}
