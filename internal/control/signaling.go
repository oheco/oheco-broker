package control

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) ownedBroker(r *http.Request) (principal, Broker, error) {
	p, e := s.auth(r, "account")
	if e != nil {
		return p, Broker{}, e
	}
	b, e := s.broker(r.PathValue("id"))
	if e != nil {
		return p, b, e
	}
	if b.TenantID != p.tenant {
		return p, b, fail(404, "broker not found")
	}
	return p, b, nil
}
func (s *Server) listBrokerRecords(tenant string) ([]Broker, error) {
	q := "SELECT id FROM brokers"
	args := []any{}
	if tenant != "" {
		q += " WHERE tenant_id=?"
		args = append(args, tenant)
	}
	q += " ORDER BY created_at,id LIMIT 1001"
	ids, e := s.listIDs(q, args...)
	if e != nil {
		return nil, e
	}
	if len(ids) > 1000 {
		return nil, fail(409, "broker list exceeds 1000")
	}
	out := make([]Broker, 0, len(ids))
	for _, id := range ids {
		b, e := s.broker(id)
		if e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, nil
}
func (s *Server) listBrokers(w http.ResponseWriter, r *http.Request) error {
	p, e := s.auth(r, "account")
	if e != nil {
		return e
	}
	out, e := s.listBrokerRecords(p.tenant)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"brokers": out})
	return nil
}
func (s *Server) registerBroker(w http.ResponseWriter, r *http.Request) error {
	p, e := s.auth(r, "account")
	if e != nil {
		return e
	}
	var body struct {
		Name string `json:"name"`
	}
	if e = decode(w, r, &body); e != nil {
		return e
	}
	if body.Name == "" {
		body.Name = "broker-" + randomSecret()[:12]
	}
	if !validName(body.Name) {
		return fail(400, "invalid broker name")
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	var count int
	if e = tx.QueryRow("SELECT COUNT(*) FROM brokers WHERE tenant_id=? AND name=?", p.tenant, body.Name).Scan(&count); e != nil {
		return e
	}
	if count > 0 {
		return fail(409, "broker name already exists")
	}
	if e = tx.QueryRow("SELECT COUNT(*) FROM brokers WHERE tenant_id=?", p.tenant).Scan(&count); e != nil {
		return e
	}
	if count >= 128 {
		return fail(429, "tenant broker limit reached")
	}
	id := uuid()
	lease := time.Now().Add(s.cfg.BrokerLease)
	if _, e = tx.Exec("INSERT INTO brokers(id,tenant_id,name,lease_expires_at,created_at) VALUES(?,?,?,?,?)", id, p.tenant, body.Name, timestamp(lease), now()); e != nil {
		return e
	}
	token, e := issue(tx, "device", p.tenant, id, "", p.version, time.Now().Add(365*24*time.Hour))
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	b, e := s.broker(id)
	if e != nil {
		return e
	}
	s.write(w, 201, map[string]any{"broker": b, "device_token": token})
	return nil
}
func (s *Server) getBroker(w http.ResponseWriter, r *http.Request) error {
	_, b, e := s.ownedBroker(r)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"broker": b})
	return nil
}
func (s *Server) renameBroker(w http.ResponseWriter, r *http.Request) error {
	p, b, e := s.ownedBroker(r)
	if e != nil {
		return e
	}
	var body struct {
		Name string `json:"name"`
	}
	if e = decode(w, r, &body); e != nil {
		return e
	}
	if !validName(body.Name) {
		return fail(400, "invalid broker name")
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRow("SELECT COUNT(*) FROM brokers WHERE tenant_id=? AND name=? AND id<>?", b.TenantID, body.Name, b.ID).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return fail(409, "broker name already exists")
	}
	if _, e = tx.Exec("UPDATE brokers SET name=? WHERE id=?", body.Name, b.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	b.Name = body.Name
	s.write(w, 200, map[string]any{"broker": b})
	return nil
}
func (s *Server) deleteBroker(w http.ResponseWriter, r *http.Request) error {
	p, b, e := s.ownedBroker(r)
	if e != nil {
		return e
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	if e = revokeConnections(tx, "broker_id=?", "broker_deleted", b.ID); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM tokens WHERE broker_id=?", b.ID); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM brokers WHERE id=?", b.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.revokeBroker(b.ID)
	s.write(w, 200, map[string]any{"deleted": true})
	return nil
}
func (s *Server) rotateDevice(w http.ResponseWriter, r *http.Request) error {
	p, b, e := s.ownedBroker(r)
	if e != nil {
		return e
	}
	if b.Online {
		return fail(409, "broker is online; wait for lease expiry or send offline")
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	var currentLease int64
	if e = tx.QueryRow("SELECT lease_expires_at FROM brokers WHERE id=? AND tenant_id=?", b.ID, p.tenant).Scan(&currentLease); e != nil {
		return e
	}
	if currentLease > now() {
		return fail(409, "broker is online; wait for lease expiry or send offline")
	}
	if e = revokeConnections(tx, "broker_id=?", "broker_revoked", b.ID); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM tokens WHERE kind='session' AND broker_id=?", b.ID); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM sessions WHERE broker_id=?", b.ID); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM tokens WHERE kind='device' AND broker_id=?", b.ID); e != nil {
		return e
	}
	token, e := issue(tx, "device", p.tenant, b.ID, "", p.version, time.Now().Add(365*24*time.Hour))
	if e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE brokers SET lease_expires_at=? WHERE id=?", timestamp(time.Now().Add(s.cfg.BrokerLease)), b.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.revokeBroker(b.ID)
	s.write(w, 200, map[string]any{"device_token": token})
	return nil
}
func (s *Server) deviceBroker(r *http.Request, requireOnline bool) (principal, Broker, error) {
	p, e := s.auth(r, "device")
	if e != nil {
		return p, Broker{}, e
	}
	if p.broker != r.PathValue("id") {
		return p, Broker{}, fail(403, "device broker scope denied")
	}
	b, e := s.broker(p.broker)
	if e != nil {
		return p, b, e
	}
	if b.TenantID != p.tenant {
		return p, b, fail(403, "device tenant scope denied")
	}
	if requireOnline && !b.Online {
		return p, b, fail(409, "broker lease expired; heartbeat required")
	}
	return p, b, nil
}
func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) error {
	p, b, e := s.deviceBroker(r, false)
	if e != nil {
		return e
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE brokers SET lease_expires_at=? WHERE id=?", timestamp(time.Now().Add(s.cfg.BrokerLease)), b.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.notifyWSBroker(b.ID)
	b, e = s.broker(b.ID)
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"broker": b})
	return nil
}
func (s *Server) offlineBroker(w http.ResponseWriter, r *http.Request) error {
	p, b, e := s.deviceBroker(r, false)
	if e != nil {
		return e
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE brokers SET lease_expires_at=0 WHERE id=?", b.ID); e != nil {
		return e
	}
	if e = revokeConnections(tx, "broker_id=?", "broker_revoked", b.ID); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM tokens WHERE kind='session' AND broker_id=?", b.ID); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM sessions WHERE broker_id=?", b.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.revokeBroker(b.ID)
	s.offlineWSBroker(b.ID)
	s.write(w, 200, map[string]any{"offline": true})
	return nil
}
func (s *Server) pollSessions(w http.ResponseWriter, r *http.Request) error {
	_, b, e := s.deviceBroker(r, true)
	if e != nil {
		return e
	}
	ids, e := s.listIDs("SELECT id FROM sessions WHERE broker_id=? AND expires_at>? ORDER BY expires_at,id LIMIT 128", b.ID, now())
	if e != nil {
		return e
	}
	out := make([]Session, 0, len(ids))
	for _, id := range ids {
		v, e := s.session(id)
		if e != nil {
			return e
		}
		out = append(out, v)
	}
	s.write(w, 200, map[string]any{"sessions": out})
	return nil
}
func (s *Server) createSession(w http.ResponseWriter, r *http.Request) error {
	p, e := s.auth(r, "account")
	if e != nil {
		return e
	}
	var body struct {
		BrokerID  string `json:"broker_id"`
		RelayMode string `json:"relay_mode"`
	}
	if e = decode(w, r, &body); e != nil {
		return e
	}
	if body.RelayMode == "" {
		body.RelayMode = "auto"
	}
	if body.RelayMode != "auto" && body.RelayMode != "never" && body.RelayMode != "force" {
		return fail(400, "invalid relay mode")
	}
	b, e := s.broker(body.BrokerID)
	if e != nil {
		return e
	}
	if b.TenantID != p.tenant {
		return fail(404, "broker not found")
	}
	if !b.Online {
		return fail(409, "broker offline")
	}
	t, _, e := s.tenant(p.tenant)
	if e != nil {
		return e
	}
	if body.RelayMode == "force" && (!t.RelayEnabled || s.turn == nil) {
		return fail(403, "forced relay unavailable")
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	var n int
	var lease int64
	if e = tx.QueryRow("SELECT lease_expires_at FROM brokers WHERE id=? AND tenant_id=?", b.ID, p.tenant).Scan(&lease); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return fail(404, "broker not found")
		}
		return e
	}
	if lease <= now() {
		return fail(409, "broker offline")
	}
	if body.RelayMode == "force" {
		var relay int
		if e = tx.QueryRow("SELECT relay_enabled FROM tenants WHERE id=?", p.tenant).Scan(&relay); e != nil {
			return e
		}
		if relay == 0 {
			return fail(403, "forced relay unavailable")
		}
	}
	if e = tx.QueryRow("SELECT COUNT(*) FROM sessions WHERE tenant_id=? AND expires_at>?", p.tenant, now()).Scan(&n); e != nil {
		return e
	}
	if n >= s.cfg.MaxSessionsPerTenant {
		return fail(429, "tenant session limit reached")
	}
	if e = tx.QueryRow("SELECT COUNT(*) FROM sessions WHERE expires_at>?", now()).Scan(&n); e != nil {
		return e
	}
	if n >= 10000 {
		return fail(429, "global session limit reached")
	}
	id := uuid()
	expiry := time.Now().Add(s.cfg.SessionTTL)
	if _, e = tx.Exec("INSERT INTO sessions(id,tenant_id,broker_id,relay_mode,expires_at) VALUES(?,?,?,?,?)", id, p.tenant, b.ID, body.RelayMode, timestamp(expiry)); e != nil {
		return e
	}
	token, e := issue(tx, "session", p.tenant, b.ID, id, p.version, expiry)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.notifyWSBroker(b.ID)
	s.write(w, 201, map[string]any{"session_id": id, "session_token": token, "expires_at": expiry.UTC()})
	return nil
}
func (s *Server) sessionPrincipal(r *http.Request) (principal, Session, string, error) {
	p, e := s.auth(r, "session", "device")
	if e != nil {
		return p, Session{}, "", e
	}
	v, e := s.session(r.PathValue("id"))
	if e != nil {
		return p, v, "", e
	}
	if e = s.managedSession(v); e != nil {
		return p, v, "", e
	}
	if v.TenantID != p.tenant || v.BrokerID != p.broker {
		return p, v, "", fail(403, "session scope denied")
	}
	if p.kind == "session" && p.session != v.ID {
		return p, v, "", fail(403, "session scope denied")
	}
	if !v.ExpiresAt.After(time.Now()) {
		return p, v, "", fail(410, "session expired")
	}
	b, e := s.broker(v.BrokerID)
	if e != nil {
		return p, v, "", e
	}
	if !b.Online {
		return p, v, "", fail(409, "broker lease expired; heartbeat required")
	}
	side := "client"
	if p.kind == "device" {
		side = "broker"
	}
	return p, v, side, nil
}
func (s *Server) sessionStatus(v Session) (map[string]any, error) {
	b, e := s.broker(v.BrokerID)
	if e != nil {
		return nil, e
	}
	out := map[string]any{"session_id": v.ID, "broker_id": v.BrokerID, "tenant_id": v.TenantID, "relay_mode": v.RelayMode, "peer_authenticated": v.PeerAuthenticated, "relay_approved": v.RelayApproved, "expires_at": v.ExpiresAt, "broker_lease_expires_at": b.LeaseExpiresAt, "lease_seconds": int(s.cfg.BrokerLease.Seconds()), "stun_address": s.AdvertisedTURNAddr(), "turn_address": s.AdvertisedTURNAddr(), "turn_credential_renewal": s.turnRenewalMode()}
	if v.ConnectionID != "" {
		out["connection_id"] = v.ConnectionID
		out["generation"] = v.Generation
	}
	return out, nil
}
func (s *Server) getSession(w http.ResponseWriter, r *http.Request) error {
	_, v, _, e := s.sessionPrincipal(r)
	if e != nil {
		return e
	}
	out, e := s.sessionStatus(v)
	if e != nil {
		return e
	}
	s.write(w, 200, out)
	return nil
}
func (s *Server) sessionHeartbeat(w http.ResponseWriter, r *http.Request) error {
	p, v, _, e := s.sessionPrincipal(r)
	if e != nil {
		return e
	}
	expiry := time.Now().Add(s.cfg.SessionTTL)
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	if e = txManagedSession(tx, v); e != nil {
		return e
	}
	var lease int64
	if e = tx.QueryRow("SELECT lease_expires_at FROM brokers WHERE id=?", v.BrokerID).Scan(&lease); e != nil {
		return e
	}
	if lease <= now() {
		return fail(409, "broker lease expired; heartbeat required")
	}
	expiry = time.Now().Add(s.cfg.SessionTTL)
	res, e := tx.Exec("UPDATE sessions SET expires_at=? WHERE id=? AND expires_at>?", timestamp(expiry), v.ID, now())
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return fail(410, "session expired")
	}

	if _, e = tx.Exec("UPDATE tokens SET expires_at=? WHERE kind='session' AND session_id=?", timestamp(expiry), v.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	v.ExpiresAt = expiry.UTC()
	s.notifyWSBroker(v.BrokerID)
	// DB transaction must be released before TURN calls its authorization callback.
	// Renewal never mints new secrets or revives expired/revoked credentials.
	if s.turn != nil && v.PeerAuthenticated && v.RelayApproved && s.authorizeTURN(v.TenantID, v.BrokerID, v.ID) {
		s.turn.renewSession(v.ID, expiry)
	}
	out, e := s.sessionStatus(v)
	if e != nil {
		return e
	}
	s.write(w, 200, out)
	return nil
}
func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) error {
	if handled, e := s.deleteSessionLineage(r); handled || e != nil {
		if e != nil {
			return e
		}
		s.write(w, 200, map[string]bool{"deleted": true})
		return nil
	}
	p, v, _, e := s.sessionPrincipal(r)
	if e != nil {
		return e
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM tokens WHERE session_id=?", v.ID); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM sessions WHERE id=?", v.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.revokeSession(v.ID)
	s.notifyWSBroker(v.BrokerID)
	s.write(w, 200, map[string]any{"deleted": true})
	return nil
}
func (s *Server) sendMessage(w http.ResponseWriter, r *http.Request) error {
	p, v, side, e := s.sessionPrincipal(r)
	if e != nil {
		return e
	}
	var body Message
	if e = decode(w, r, &body); e != nil {
		return e
	}
	if body.Sequence < 1 || body.Sequence > int64(s.cfg.MaxMessagesPerDirection) || len(body.Data) > s.cfg.MaxMessageBytes {
		return fail(400, "message bounds exceeded")
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	if e = txSessionLive(tx, v); e != nil {
		return e
	}
	var current int64
	if e = tx.QueryRow("SELECT COALESCE(MAX(sequence),0) FROM messages WHERE session_id=? AND side=?", v.ID, side).Scan(&current); e != nil {
		return e
	}
	if body.Sequence <= current {
		var data string
		e = tx.QueryRow("SELECT data FROM messages WHERE session_id=? AND side=? AND sequence=?", v.ID, side, body.Sequence).Scan(&data)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e != nil || data != body.Data {
			return fail(409, "sequence already used with different data")
		}
		s.write(w, 200, map[string]any{"sequence": body.Sequence, "duplicate": true})
		return nil
	}
	if body.Sequence != current+1 {
		return fail(409, "sequence must be next directional sequence")
	}
	if _, e = tx.Exec("INSERT INTO messages(session_id,side,sequence,data) VALUES(?,?,?,?)", v.ID, side, body.Sequence, body.Data); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.notifyWSSession(v.ID)
	s.write(w, 201, map[string]any{"sequence": body.Sequence})
	return nil
}
func (s *Server) pollMessages(w http.ResponseWriter, r *http.Request) error {
	_, v, side, e := s.sessionPrincipal(r)
	if e != nil {
		return e
	}
	after := int64(0)
	if q := r.URL.Query().Get("after"); q != "" {
		after, e = strconv.ParseInt(q, 10, 64)
		if e != nil || after < 0 || after > int64(s.cfg.MaxMessagesPerDirection) {
			return fail(400, "invalid after cursor")
		}
	}
	opposite := "broker"
	if side == "broker" {
		opposite = "client"
	}
	rows, e := s.db.Query("SELECT sequence,data FROM messages WHERE session_id=? AND side=? AND sequence>? ORDER BY sequence LIMIT 16", v.ID, opposite, after)
	if e != nil {
		return e
	}
	defer rows.Close()
	out := []Message{}
	next := after
	for rows.Next() {
		var m Message
		if e = rows.Scan(&m.Sequence, &m.Data); e != nil {
			return e
		}
		out = append(out, m)
		next = m.Sequence
	}
	if e = rows.Err(); e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"messages": out, "next": next})
	return nil
}
func (s *Server) approveSession(w http.ResponseWriter, r *http.Request) error {
	p, v, _, e := s.sessionPrincipal(r)
	if e != nil {
		return e
	}
	if p.kind != "device" {
		return fail(403, "only broker device may approve")
	}
	var body struct {
		PeerAuthenticated bool `json:"peer_authenticated"`
		Relay             bool `json:"relay"`
	}
	if e = decode(w, r, &body); e != nil {
		return e
	}
	if !body.PeerAuthenticated {
		return fail(400, "broker must report peer authentication success")
	}
	if body.Relay {
		t, _, e := s.tenant(p.tenant)
		if e != nil {
			return e
		}
		if !t.RelayEnabled || s.turn == nil || v.RelayMode == "never" {
			return fail(403, "relay unavailable or forbidden")
		}
	}
	if v.RelayMode == "force" && !body.Relay {
		return fail(409, "force mode requires relay approval")
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = txPrincipal(tx, r, p); e != nil {
		return e
	}
	if e = txSessionLive(tx, v); e != nil {
		return e
	}
	if body.Relay {
		var relay int
		if e = tx.QueryRow("SELECT relay_enabled FROM tenants WHERE id=?", p.tenant).Scan(&relay); e != nil {
			return e
		}
		if relay == 0 {
			return fail(403, "relay unavailable or forbidden")
		}
	}
	if _, e = tx.Exec("UPDATE sessions SET peer_authenticated=1,relay_approved=? WHERE id=?", boolInt(body.Relay), v.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if !body.Relay {
		s.revokeTURNSession(v.ID)
	}
	s.notifyWSBroker(v.BrokerID)
	v.PeerAuthenticated = true
	v.RelayApproved = body.Relay
	s.write(w, 200, map[string]any{"session": v})
	return nil
}
func (s *Server) sessionTURN(w http.ResponseWriter, r *http.Request) error {
	_, v, _, e := s.sessionPrincipal(r)
	if e != nil {
		return e
	}
	if s.turn == nil {
		return fail(503, "TURN disabled")
	}
	if !s.authorizeTURN(v.TenantID, v.BrokerID, v.ID) {
		return fail(403, "relay approval, tenant capability, or quota denied")
	}
	expiry := v.ExpiresAt
	limit := time.Now().Add(s.turn.cfg.MaxCredentialTTL)
	if expiry.After(limit) {
		expiry = limit
	}
	c, e := s.turn.mint(v.TenantID, v.BrokerID, v.ID, expiry)
	if e != nil {
		return fail(429, "TURN credential limit reached")
	}
	s.write(w, 200, c)
	return nil
}
func (s *Server) adminBrokers(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	limit, offset, e := adminPage(r)
	if e != nil {
		return e
	}
	query := "SELECT id FROM brokers"
	args := []any{}
	if tenant := r.URL.Query().Get("tenant_id"); tenant != "" {
		query += " WHERE tenant_id=?"
		args = append(args, tenant)
	}
	query += " ORDER BY created_at,id LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)
	ids, e := s.listIDs(query, args...)
	if e != nil {
		return e
	}
	ids, next := pagedIDs(ids, limit, offset)
	out := make([]Broker, 0, len(ids))
	for _, id := range ids {
		b, e := s.broker(id)
		if e != nil {
			return e
		}
		out = append(out, b)
	}
	s.write(w, 200, map[string]any{"brokers": out, "next_offset": next})
	return nil
}
func (s *Server) adminBroker(w http.ResponseWriter, r *http.Request) error {
	if e := s.admin(r); e != nil {
		return e
	}
	b, e := s.broker(r.PathValue("id"))
	if e != nil {
		return e
	}
	s.write(w, 200, map[string]any{"broker": b})
	return nil
}
