package control

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/ws/brokers/{id}", s.endpoint(s.websocketBroker))
	s.mux.HandleFunc("GET /v1/ws/sessions/{id}", s.endpoint(s.websocketSession))
	s.mux.HandleFunc("POST /v1/tenants/register", s.endpoint(s.register))
	s.mux.HandleFunc("POST /v1/tenants/login", s.endpoint(s.login))
	s.mux.HandleFunc("POST /v1/tenants/logout", s.endpoint(s.logout))
	s.mux.HandleFunc("GET /v1/me", s.endpoint(s.me))
	s.mux.HandleFunc("GET /v1/me/capabilities", s.endpoint(s.capabilities))
	s.mux.HandleFunc("GET /v1/capabilities", s.endpoint(s.capabilities))
	s.mux.HandleFunc("GET /v1/usage", s.endpoint(s.myUsage))
	s.mux.HandleFunc("PATCH /v1/me", s.endpoint(s.updateMe))
	s.mux.HandleFunc("POST /v1/me/password", s.endpoint(s.changePassword))
	s.mux.HandleFunc("GET /v1/me/usage", s.endpoint(s.myUsage))
	s.mux.HandleFunc("GET /v1/brokers", s.endpoint(s.listBrokers))
	s.mux.HandleFunc("POST /v1/brokers", s.endpoint(s.registerBroker))
	s.mux.HandleFunc("GET /v1/brokers/{id}", s.endpoint(s.getBroker))
	s.mux.HandleFunc("GET /v1/brokers/{id}/usage", s.endpoint(s.brokerUsage))
	s.mux.HandleFunc("PATCH /v1/brokers/{id}", s.endpoint(s.renameBroker))
	s.mux.HandleFunc("DELETE /v1/brokers/{id}", s.endpoint(s.deleteBroker))
	s.mux.HandleFunc("POST /v1/brokers/{id}/token", s.endpoint(s.rotateDevice))
	s.mux.HandleFunc("POST /v1/brokers/{id}/heartbeat", s.endpoint(s.heartbeat))
	s.mux.HandleFunc("POST /v1/brokers/{id}/offline", s.endpoint(s.offlineBroker))
	s.mux.HandleFunc("GET /v1/brokers/{id}/sessions", s.endpoint(s.pollSessions))
	s.mux.HandleFunc("POST /v1/sessions", s.endpoint(s.createSession))
	s.mux.HandleFunc("GET /v1/sessions/{id}", s.endpoint(s.getSession))
	s.mux.HandleFunc("GET /v1/sessions/{id}/capabilities", s.endpoint(s.getSession))
	s.mux.HandleFunc("POST /v1/sessions/{id}/heartbeat", s.endpoint(s.sessionHeartbeat))
	s.mux.HandleFunc("DELETE /v1/sessions/{id}", s.endpoint(s.deleteSession))
	s.mux.HandleFunc("POST /v1/sessions/{id}/messages", s.endpoint(s.sendMessage))
	s.mux.HandleFunc("GET /v1/sessions/{id}/messages", s.endpoint(s.pollMessages))
	s.mux.HandleFunc("POST /v1/sessions/{id}/approve", s.endpoint(s.approveSession))
	s.mux.HandleFunc("POST /v1/sessions/{id}/turn", s.endpoint(s.sessionTURN))
	s.mux.HandleFunc("GET /v1/admin/tenants", s.endpoint(s.adminTenants))
	s.mux.HandleFunc("GET /v1/admin/tenants/{id}", s.endpoint(s.adminTenant))
	s.mux.HandleFunc("PATCH /v1/admin/tenants/{id}", s.endpoint(s.adminUpdateTenant))
	s.mux.HandleFunc("POST /v1/admin/tenants/{id}/{action}", s.endpoint(s.adminAction))
	s.mux.HandleFunc("GET /v1/admin/settings", s.endpoint(s.adminSettings))
	s.mux.HandleFunc("PATCH /v1/admin/settings", s.endpoint(s.adminSetSettings))
	s.mux.HandleFunc("GET /v1/admin/brokers", s.endpoint(s.adminBrokers))
	s.mux.HandleFunc("GET /v1/admin/brokers/{id}", s.endpoint(s.adminBroker))
	s.mux.HandleFunc("GET /v1/admin/usage", s.endpoint(s.adminUsage))
	s.mux.HandleFunc("GET /v1/admin/info", s.endpoint(s.adminInfo))
}

type registrationSettings struct {
	Policy       string `json:"registration_policy"`
	RelayEnabled bool   `json:"registration_relay_enabled"`
}

// Both settings come from one SQL snapshot, including when called inside a PATCH transaction.
func readRegistrationSettings(q interface {
	QueryRow(string, ...any) *sql.Row
}) (registrationSettings, error) {
	var settings registrationSettings
	var relay string
	err := q.QueryRow(`SELECT policy.value, relay.value FROM settings AS policy CROSS JOIN settings AS relay
		WHERE policy.key='registration_policy' AND relay.key='registration_relay_enabled'`).Scan(&settings.Policy, &relay)
	if err != nil {
		return settings, err
	}
	if !validPolicy(settings.Policy) {
		return settings, errors.New("control: invalid persisted registration policy")
	}
	settings.RelayEnabled, err = strconv.ParseBool(relay)
	return settings, err
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) error {
	settings, e := readRegistrationSettings(s.db)
	if e != nil {
		return e
	}
	if settings.Policy == "closed" {
		return fail(403, "registration closed")
	}
	var b struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if e = decode(w, r, &b); e != nil {
		return e
	}
	if b.Name == "" {
		b.Name = "tenant-" + randomSecret()[:12]
	}
	if b.Password == "" {
		b.Password = randomSecret()
	}
	if b.Email == "" {
		b.Email = "tenant-" + randomSecret()[:12] + "@example.invalid"
	}
	if !validName(b.Name) || !validEmail(b.Email) {
		return fail(400, "invalid name or email")
	}
	hash, e := passwordHash(b.Password)
	if e != nil {
		return e
	}
	status := "active"
	if settings.Policy == "approval" {
		status = "pending"
	}
	id := uuid()
	n := now()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var existing int
	e = tx.QueryRow("SELECT COUNT(*) FROM tenants WHERE name=?", b.Name).Scan(&existing)
	if e != nil {
		return e
	}
	if existing != 0 {
		return fail(409, "name already exists")
	}
	if _, e = tx.Exec("INSERT INTO tenants(id,name,email,password_hash,status,relay_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", id, b.Name, b.Email, hash, status, boolInt(settings.RelayEnabled), n, n); e != nil {
		return e
	}
	token, e := issue(tx, "account", id, "", "", 1, time.Now().Add(s.cfg.AccountTokenTTL))
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	t, _, e := s.tenant(id)
	if e != nil {
		return e
	}
	s.write(w, 201, map[string]any{"tenant": t, "token": token})
	return nil
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	var id, hash, status string
	var version int
	e := s.db.QueryRow("SELECT id,password_hash,status,version FROM tenants WHERE name=?", b.Name).Scan(&id, &hash, &status, &version)
	// Always perform the same expensive password operation, including unknown names.
	if errors.Is(e, sql.ErrNoRows) {
		hash = "$2a$12$vVG.VB.BErnxNdgqbKkb2e.nPiwzgutIUvdmgSlOBNAUzAhGVKgde"
	} else if e != nil {
		return e
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(b.Password)) != nil || id == "" {
		return fail(401, "invalid login")
	}
	if status != "active" {
		return fail(403, "tenant is not active")
	}
	// Account sessions are bounded. Oldest expiry is evicted only at the limit.
	_, e = s.db.Exec("DELETE FROM tokens WHERE hash IN (SELECT hash FROM tokens WHERE tenant_id=? AND kind='account' ORDER BY expires_at ASC LIMIT MAX(0,(SELECT COUNT(*) FROM tokens WHERE tenant_id=? AND kind='account')-15))", id, id)
	if e != nil {
		return e
	}
	token, e := s.accountToken(id, version)
	if e != nil {
		return e
	}
	t, _, e := s.tenant(id)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"tenant": t, "token": token})
	return nil
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) error {
	token := bearer(r)
	if token == "" {
		return fail(401, "bearer required")
	}
	if _, e := s.db.Exec("DELETE FROM tokens WHERE hash=? AND kind='account'", tokenHash(token)); e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"logged_out": true})
	return nil
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) error {
	p, e := s.readAccount(r)
	if e != nil {
		return e
	}
	t, _, e := s.tenant(p.tenant)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"tenant": t})
	return nil
}
func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) error {
	p, e := s.readAccount(r)
	if e != nil {
		return e
	}
	t, _, e := s.tenant(p.tenant)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"status": t.Status, "relay_enabled": t.RelayEnabled, "turn_available": s.turn != nil, "stun_address": s.AdvertisedTURNAddr(), "turn_address": s.AdvertisedTURNAddr(), "turn_credential_renewal": s.turnRenewalMode(), "signaling": wsProtocol, "session_ttl_seconds": int(s.cfg.SessionTTL.Seconds()), "broker_lease_seconds": int(s.cfg.BrokerLease.Seconds()), "max_message_bytes": s.cfg.MaxMessageBytes, "max_messages_per_direction": s.cfg.MaxMessagesPerDirection, "tenant_daily_byte_quota": s.cfg.TenantDailyByteQuota})
	return nil
}
func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) error {
	p, e := s.auth(r, "account")
	if e != nil {
		return e
	}
	var b struct {
		Name  *string `json:"name"`
		Email *string `json:"email"`
	}
	if e = decode(w, r, &b); e != nil {
		return e
	}
	if b.Name == nil && b.Email == nil {
		return fail(400, "no account changes")
	}
	t, _, e := s.tenant(p.tenant)
	if e != nil {
		return e
	}
	if b.Name != nil {
		t.Name = *b.Name
	}
	if b.Email != nil {
		t.Email = *b.Email
	}
	if !validName(t.Name) || !validEmail(t.Email) {
		return fail(400, "invalid name or email")
	}
	token, e := s.updateAccount(t, nil, true, p.version, false, false)
	if e != nil {
		return e
	}
	t, _, e = s.tenant(t.ID)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"tenant": t, "token": token})
	return nil
}
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) error {
	p, e := s.auth(r, "account")
	if e != nil {
		return e
	}
	var b struct {
		Password string `json:"password"`
	}
	if e = decode(w, r, &b); e != nil {
		return e
	}
	h, e := passwordHash(b.Password)
	if e != nil {
		return e
	}
	t, _, e := s.tenant(p.tenant)
	if e != nil {
		return e
	}
	token, e := s.updateAccount(t, &h, true, p.version, false, false)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"token": token})
	return nil
}

// Account changes are one atomic version bump + token deletion + replacement token.
func (s *Server) updateAccount(t Tenant, hash *string, replacement bool, expectedVersion int, updateStatus, updateRelay bool) (string, error) {
	tx, e := s.db.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var v, relay int
	var status string
	if e = tx.QueryRow("SELECT version,status,relay_enabled FROM tenants WHERE id=?", t.ID).Scan(&v, &status, &relay); e != nil {
		return "", e
	}
	if !updateStatus {
		t.Status = status
	}
	if !updateRelay {
		t.RelayEnabled = relay != 0
	}
	if expectedVersion >= 0 && v != expectedVersion {
		if !replacement {
			return "", fail(409, "tenant concurrently changed")
		}
		return "", fail(401, "revoked bearer")
	}
	var conflict int
	if e = tx.QueryRow("SELECT COUNT(*) FROM tenants WHERE name=? AND id<>?", t.Name, t.ID).Scan(&conflict); e != nil {
		return "", e
	}
	if conflict != 0 {
		return "", fail(409, "name already exists")
	}
	if _, e = tx.Exec("UPDATE tenants SET name=?,email=?,status=?,relay_enabled=?,version=version+1,updated_at=? WHERE id=?", t.Name, t.Email, t.Status, boolInt(t.RelayEnabled), now(), t.ID); e != nil {
		return "", e
	}
	if hash != nil {
		if _, e = tx.Exec("UPDATE tenants SET password_hash=? WHERE id=?", *hash, t.ID); e != nil {
			return "", e
		}
	}
	if _, e = tx.Exec("DELETE FROM tokens WHERE tenant_id=?", t.ID); e != nil {
		return "", e
	}
	if _, e = tx.Exec("DELETE FROM sessions WHERE tenant_id=?", t.ID); e != nil {
		return "", e
	}
	if _, e = tx.Exec("UPDATE brokers SET lease_expires_at=0 WHERE tenant_id=?", t.ID); e != nil {
		return "", e
	}
	token := ""
	if replacement {
		token, e = issue(tx, "account", t.ID, "", "", v+1, time.Now().Add(s.cfg.AccountTokenTTL))
		if e != nil {
			return "", e
		}
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	s.revokeTenant(t.ID)
	return token, nil
}
func adminPage(r *http.Request) (limit, offset int, err error) {
	limit = 100
	parse := func(key string, fallback, max int) (int, error) {
		values, present := r.URL.Query()[key]
		if !present {
			return fallback, nil
		}
		if len(values) != 1 || values[0] == "" {
			return 0, fail(400, "invalid "+key)
		}
		n, e := strconv.ParseInt(values[0], 10, 32)
		if e != nil || n < 0 || n > int64(max) {
			return 0, fail(400, "invalid "+key)
		}
		return int(n), nil
	}
	limit, err = parse("limit", 100, 1000)
	if err != nil {
		return
	}
	if limit < 1 {
		return 0, 0, fail(400, "limit must be 1 to 1000")
	}
	offset, err = parse("offset", 0, 1000000000)
	return
}
func pagedIDs(ids []string, limit, offset int) ([]string, any) {
	if len(ids) > limit {
		return ids[:limit], offset + limit
	}
	return ids, nil
}
func (s *Server) adminTenants(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	limit, offset, e := adminPage(r)
	if e != nil {
		return e
	}
	query := "SELECT id FROM tenants"
	args := []any{}
	if status := r.URL.Query().Get("status"); status != "" {
		if !validStatus(status) {
			return fail(400, "invalid status filter")
		}
		query += " WHERE status=?"
		args = append(args, status)
	}
	query += " ORDER BY created_at,id LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)
	ids, e := s.listIDs(query, args...)
	if e != nil {
		return e
	}
	ids, next := pagedIDs(ids, limit, offset)
	out := make([]Tenant, 0, len(ids))
	for _, id := range ids {
		t, _, e := s.tenant(id)
		if e != nil {
			return e
		}
		out = append(out, t)
	}
	s.write(w, 200, map[string]any{"tenants": out, "next_offset": next})
	return nil
}
func (s *Server) listIDs(query string, args ...any) ([]string, error) {
	rows, e := s.db.Query(query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *Server) adminTenant(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	t, _, e := s.tenant(r.PathValue("id"))
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"tenant": t})
	return nil
}
func validStatus(v string) bool { return v == "active" || v == "pending" || v == "disabled" }
func (s *Server) adminUpdateTenant(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	var b struct {
		Name   *string `json:"name"`
		Email  *string `json:"email"`
		Status *string `json:"status"`
		Relay  *bool   `json:"relay_enabled"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	t, version, e := s.tenant(r.PathValue("id"))
	if e != nil {
		return e
	}
	if b.Name != nil {
		t.Name = *b.Name
	}
	if b.Email != nil {
		t.Email = *b.Email
	}
	if b.Status != nil {
		t.Status = *b.Status
	}
	if b.Relay != nil {
		t.RelayEnabled = *b.Relay
	}
	if !validName(t.Name) || !validEmail(t.Email) || !validStatus(t.Status) {
		return fail(400, "invalid tenant update")
	}
	if b.Name != nil || b.Email != nil || t.Status != "active" {
		_, e = s.updateAccount(t, nil, false, version, b.Status != nil, b.Relay != nil)
	} else {
		e = s.updateCapabilities(t, b.Status != nil, b.Relay != nil, version)
	}
	if e != nil {
		return e
	}
	t, _, e = s.tenant(t.ID)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"tenant": t})
	return nil
}
func (s *Server) adminAction(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	t, version, e := s.tenant(r.PathValue("id"))
	if e != nil {
		return e
	}
	var hash *string
	switch r.PathValue("action") {
	case "approve":
		if t.Status != "pending" {
			return fail(409, "tenant is not pending")
		}
		t.Status = "active"
	case "enable":
		t.Status = "active"
	case "disable":
		t.Status = "disabled"
	case "relay":
		var b struct {
			Enabled *bool `json:"enabled"`
		}
		if e = decode(w, r, &b); e != nil {
			return e
		}
		if b.Enabled == nil {
			return fail(400, "enabled required")
		}
		t.RelayEnabled = *b.Enabled
	case "reset-password":
		var b struct {
			Password string `json:"password"`
		}
		if e = decode(w, r, &b); e != nil {
			return e
		}
		if b.Password == "" {
			return fail(400, "password required; generate it client-side")
		}
		h, e := passwordHash(b.Password)
		if e != nil {
			return e
		}
		hash = &h
	default:
		return fail(404, "unknown admin action")
	}
	if r.PathValue("action") == "disable" || hash != nil {
		_, e = s.updateAccount(t, hash, false, version, r.PathValue("action") == "disable", false)
	} else {
		e = s.updateCapabilities(t, r.PathValue("action") != "relay", r.PathValue("action") == "relay", version)
	}
	if e != nil {
		return e
	}
	t, _, e = s.tenant(t.ID)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"tenant": t})
	return nil
}

// Capability toggles do not rotate account/device secrets or kill direct sessions.
// Relay disable closes existing TURN allocations, clears approvals and deletes force sessions.
func (s *Server) updateCapabilities(t Tenant, setStatus, setRelay bool, expectedVersion int) error {
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var status string
	var relay, version int
	if e = tx.QueryRow("SELECT status,relay_enabled,version FROM tenants WHERE id=?", t.ID).Scan(&status, &relay, &version); e != nil {
		return e
	}
	if version != expectedVersion {
		return fail(409, "tenant concurrently changed")
	}
	if !setStatus {
		t.Status = status
	}
	if !setRelay {
		t.RelayEnabled = relay != 0
	}
	if _, e = tx.Exec("UPDATE tenants SET status=?,relay_enabled=?,updated_at=? WHERE id=?", t.Status, boolInt(t.RelayEnabled), now(), t.ID); e != nil {
		return e
	}
	if !t.RelayEnabled {
		if _, e = tx.Exec("DELETE FROM tokens WHERE kind='session' AND session_id IN (SELECT id FROM sessions WHERE tenant_id=? AND relay_mode='force')", t.ID); e != nil {
			return e
		}
		if _, e = tx.Exec("DELETE FROM sessions WHERE tenant_id=? AND relay_mode='force'", t.ID); e != nil {
			return e
		}
		if _, e = tx.Exec("UPDATE sessions SET relay_approved=0 WHERE tenant_id=?", t.ID); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if !t.RelayEnabled {
		// Capability-only revocation must not kill authenticated direct sockets.
		s.revokeTURNTenant(t.ID)
	}
	s.notifyWSTenant(t.ID)
	return nil
}
func (s *Server) adminSettings(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	settings, e := readRegistrationSettings(s.db)
	if e != nil {
		return e
	}
	s.write(w, 200, settings)
	return nil
}
func (s *Server) adminSetSettings(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	var b struct {
		Policy       json.RawMessage `json:"registration_policy"`
		RelayEnabled json.RawMessage `json:"registration_relay_enabled"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if b.Policy == nil && b.RelayEnabled == nil {
		return fail(400, "no settings changes")
	}
	// Distinguish omission from explicit null so an invalid field rejects the whole PATCH.
	var policy *string
	if b.Policy != nil {
		if e := json.Unmarshal(b.Policy, &policy); e != nil || policy == nil || !validPolicy(*policy) {
			return fail(400, "invalid registration policy")
		}
	}
	var relayEnabled *bool
	if b.RelayEnabled != nil {
		if e := json.Unmarshal(b.RelayEnabled, &relayEnabled); e != nil || relayEnabled == nil {
			return fail(400, "invalid registration relay setting")
		}
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if policy != nil {
		if _, e = tx.Exec("UPDATE settings SET value=? WHERE key='registration_policy'", *policy); e != nil {
			return e
		}
	}
	if relayEnabled != nil {
		if _, e = tx.Exec("UPDATE settings SET value=? WHERE key='registration_relay_enabled'", strconv.FormatBool(*relayEnabled)); e != nil {
			return e
		}
	}
	settings, e := readRegistrationSettings(tx)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.write(w, 200, settings)
	return nil
}
func (s *Server) adminInfo(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	counts := map[string]int{}
	for _, table := range []string{"tenants", "brokers", "sessions"} {
		var n int
		if e := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); e != nil {
			return e
		}
		counts[table] = n
	}
	s.write(w, 200, map[string]any{"schema_version": 1, "listen_addr": s.cfg.ListenAddr, "turn_addr": s.TURNAddr(), "counts": counts, "signaling": wsProtocol, "storage": "sqlite3", "quic_termination": false})
	return nil
}
func (s *Server) myUsage(w http.ResponseWriter, r *http.Request) error {
	p, e := s.auth(r, "account")
	if e != nil {
		return e
	}
	broker := r.URL.Query().Get("broker_id")
	if broker != "" {
		b, e := s.broker(broker)
		if e != nil {
			return e
		}
		if b.TenantID != p.tenant {
			return fail(404, "broker not found")
		}
	}
	u, e := s.usage(p.tenant, broker)
	if e != nil {
		return e
	}
	s.write(w, 200, u)
	return nil
}
func (s *Server) adminUsage(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	id := r.URL.Query().Get("tenant_id")
	if id != "" {
		if _, _, e := s.tenant(id); e != nil {
			return e
		}
	}
	broker := r.URL.Query().Get("broker_id")
	if broker != "" {
		b, e := s.broker(broker)
		if e != nil {
			return e
		}
		if id != "" && b.TenantID != id {
			return fail(404, "broker not found")
		}
		id = b.TenantID
	}
	u, e := s.usage(id, broker)
	if e != nil {
		return e
	}
	s.write(w, 200, u)
	return nil
}
func (s *Server) brokerUsage(w http.ResponseWriter, r *http.Request) error {
	p, b, e := s.ownedBroker(r)
	if e != nil {
		return e
	}
	u, e := s.usage(p.tenant, b.ID)
	if e != nil {
		return e
	}
	s.write(w, 200, u)
	return nil
}
func (s *Server) usage(id, broker string) (map[string]any, error) {
	if e := s.flushUsage(); e != nil {
		return nil, e
	}
	out := map[string]any{"tenant_id": id, "broker_id": broker, "unit": "forwarded_payload_bytes", "lifetime": int64(0), "days_1": int64(0), "days_7": int64(0), "days_30": int64(0)}
	for _, key := range []string{"lifetime", "days_1", "days_7", "days_30"} {
		table := "usage_buckets"
		if key == "lifetime" {
			table = "usage_daily"
		}
		if broker != "" {
			table = "broker_" + table
		}
		query := "SELECT COALESCE(SUM(bytes),0) FROM " + table + " WHERE 1=1"
		args := []any{}
		if id != "" {
			query += " AND tenant_id=?"
			args = append(args, id)
		}
		if broker != "" {
			query += " AND broker_id=?"
			args = append(args, broker)
		}
		if key != "lifetime" {
			days := 1
			switch key {
			case "days_7":
				days = 7
			case "days_30":
				days = 30
			}
			query += " AND bucket>=?"
			args = append(args, time.Now().UTC().Add(-time.Duration(days)*24*time.Hour).Truncate(time.Minute).Format(time.RFC3339))
		}
		var n int64
		if e := s.db.QueryRow(query, args...).Scan(&n); e != nil {
			return nil, e
		}
		out[key] = n
	}
	out["window"] = "rolling 24/168/720 hours, one-minute bucket resolution"
	return out, nil
}
