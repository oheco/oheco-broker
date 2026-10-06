package control

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

// The login session is durable authority. Access rows admit new requests; their
// rotation must not change the identity of an already authorized connection.
type authCredentials struct {
	Token            string    `json:"token"`
	RefreshToken     string    `json:"refresh_token"`
	AuthSessionID    string    `json:"auth_session_id"`
	Generation       uint64    `json:"generation"`
	TokenExpiresAt   time.Time `json:"token_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}
type authReceipt struct {
	AuthSessionID    string    `json:"auth_session_id"`
	Generation       uint64    `json:"generation"`
	TokenExpiresAt   time.Time `json:"token_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}
type authSession struct {
	ID, Tenant, RefreshHash, TokenHash, Revoked      string
	Version                                          int
	Generation                                       uint64
	TokenExpiry, RefreshExpiry, AbsoluteExpiry       int64
	PreviousRefresh, Request, NextToken, NextRefresh string
	ExpectedGeneration                               uint64
	ReceiptTokenExpiry, ReceiptRefreshExpiry         int64
}
type authQuerier interface{ QueryRow(string, ...any) *sql.Row }

func authFailure(code int, reason string) error {
	return &apiError{code: code, reason: reason, message: strings.ReplaceAll(reason, "_", " ")}
}
func validAuthID(id string) bool {
	return validConnectionID(id) && id[14] == '4' && strings.ContainsRune("89ab", rune(id[19]))
}
func readAuthSession(q authQuerier, id string) (authSession, error) {
	var a authSession
	err := q.QueryRow(`SELECT id,tenant_id,version,generation,refresh_hash,token_hash,token_expires_at,refresh_expires_at,absolute_expires_at,revoked_reason,previous_refresh_hash,request_id,expected_generation,next_token_hash,next_refresh_hash,receipt_token_expires_at,receipt_refresh_expires_at FROM auth_sessions WHERE id=?`, id).Scan(&a.ID, &a.Tenant, &a.Version, &a.Generation, &a.RefreshHash, &a.TokenHash, &a.TokenExpiry, &a.RefreshExpiry, &a.AbsoluteExpiry, &a.Revoked, &a.PreviousRefresh, &a.Request, &a.ExpectedGeneration, &a.NextToken, &a.NextRefresh, &a.ReceiptTokenExpiry, &a.ReceiptRefreshExpiry)
	return a, err
}
func checkAuthSession(q authQuerier, a authSession, pending bool) error {
	if a.Revoked != "" {
		return authFailure(401, "refresh_revoked")
	}
	if a.RefreshExpiry <= now() || a.AbsoluteExpiry != 0 && a.AbsoluteExpiry <= now() {
		return authFailure(401, "refresh_expired")
	}
	var version int
	var status string
	err := q.QueryRow("SELECT version,status FROM tenants WHERE id=?", a.Tenant).Scan(&version, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return authFailure(401, "refresh_revoked")
	}
	if err != nil {
		return err
	}
	if version != a.Version || status != "active" && !(pending && status == "pending") {
		return authFailure(401, "refresh_revoked")
	}
	return nil
}
func authAuthority(q authQuerier, id, tenant string, version int, pending bool) (authSession, error) {
	a, err := readAuthSession(q, id)
	if errors.Is(err, sql.ErrNoRows) {
		return a, authFailure(401, "refresh_revoked")
	}
	if err != nil {
		return a, err
	}
	if a.Tenant != tenant || a.Version != version {
		return a, authFailure(401, "refresh_revoked")
	}
	return a, checkAuthSession(q, a, pending)
}
func (s *Server) migrateAuth(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS auth_sessions(
 id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,version INTEGER NOT NULL,generation INTEGER NOT NULL,
 refresh_hash TEXT NOT NULL UNIQUE,token_hash TEXT NOT NULL,token_expires_at INTEGER NOT NULL,refresh_expires_at INTEGER NOT NULL,absolute_expires_at INTEGER NOT NULL DEFAULT 0,revoked_reason TEXT NOT NULL DEFAULT '',
 previous_refresh_hash TEXT NOT NULL DEFAULT '',request_id TEXT NOT NULL DEFAULT '',expected_generation INTEGER NOT NULL DEFAULT 0,next_token_hash TEXT NOT NULL DEFAULT '',next_refresh_hash TEXT NOT NULL DEFAULT '',receipt_token_expires_at INTEGER NOT NULL DEFAULT 0,receipt_refresh_expires_at INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS auth_sessions_tenant ON auth_sessions(tenant_id);`); err != nil {
		return err
	}
	for _, table := range []string{"tokens", "connections", "sessions"} {
		rows, err := tx.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ string
			var def any
			if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
				rows.Close()
				return err
			}
			found = found || name == "auth_session_id"
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !found {
			if _, err = tx.Exec("ALTER TABLE " + table + " ADD COLUMN auth_session_id TEXT REFERENCES auth_sessions(id)"); err != nil {
				return err
			}
		}
	}
	_, err := tx.Exec("CREATE INDEX IF NOT EXISTS tokens_auth_session ON tokens(auth_session_id); CREATE INDEX IF NOT EXISTS connections_auth_session ON connections(auth_session_id); UPDATE schema_version SET version=3")
	return err
}
func (s *Server) issueAuthSession(tx *sql.Tx, tenant string, version int) (authCredentials, error) {
	var c authCredentials
	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM auth_sessions WHERE tenant_id=? AND revoked_reason='' AND refresh_expires_at>? AND (absolute_expires_at=0 OR absolute_expires_at>?)", tenant, now(), now()).Scan(&count); err != nil {
		return c, err
	}
	if count >= 16 {
		return c, authFailure(429, "auth_session_limit")
	}
	c.AuthSessionID, c.Token, c.RefreshToken, c.Generation = uuid(), randomSecret(), randomSecret(), 1
	at := time.Now()
	refresh := at.Add(s.cfg.AuthRefreshTTL)
	absolute := int64(0)
	if s.cfg.AuthAbsoluteTTL > 0 {
		absolute = timestamp(at.Add(s.cfg.AuthAbsoluteTTL))
		if timestamp(refresh) > absolute {
			refresh = fromTimestamp(absolute)
		}
	}
	c.RefreshExpiresAt = fromTimestamp(timestamp(refresh))
	c.TokenExpiresAt = fromTimestamp(min(timestamp(at.Add(s.cfg.AccountTokenTTL)), timestamp(refresh)))
	_, err := tx.Exec(`INSERT INTO auth_sessions(id,tenant_id,version,generation,refresh_hash,token_hash,token_expires_at,refresh_expires_at,absolute_expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, c.AuthSessionID, tenant, version, 1, tokenHash(c.RefreshToken), tokenHash(c.Token), timestamp(c.TokenExpiresAt), timestamp(c.RefreshExpiresAt), absolute, timestamp(at), timestamp(at))
	if err != nil {
		return c, err
	}
	_, err = tx.Exec("INSERT INTO tokens(hash,kind,tenant_id,version,expires_at,auth_session_id) VALUES(?,'account',?,?,?,?)", tokenHash(c.Token), tenant, version, timestamp(c.TokenExpiresAt), c.AuthSessionID)
	return c, err
}
func authResponse(t Tenant, c authCredentials) map[string]any {
	return map[string]any{"tenant": t, "token": c.Token, "refresh_token": c.RefreshToken, "auth_session_id": c.AuthSessionID, "generation": c.Generation, "token_expires_at": c.TokenExpiresAt, "refresh_expires_at": c.RefreshExpiresAt}
}
func (s *Server) refreshAuth(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		AuthSessionID      string  `json:"auth_session_id"`
		ExpectedGeneration *uint64 `json:"expected_generation"`
		RequestID          string  `json:"request_id"`
		NextToken          string  `json:"next_token"`
		NextRefreshToken   string  `json:"next_refresh_token"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	proof := bearer(r)
	if !validAuthID(body.AuthSessionID) || !validAuthID(body.RequestID) || body.ExpectedGeneration == nil || *body.ExpectedGeneration == 0 || !validConnectionToken(body.NextToken) || !validConnectionToken(body.NextRefreshToken) || body.NextToken == body.NextRefreshToken || body.NextToken == proof || body.NextRefreshToken == proof {
		return fail(400, "invalid refresh request")
	}
	if !validConnectionToken(proof) {
		return authFailure(401, "refresh_invalid")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a, err := readAuthSession(tx, body.AuthSessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return authFailure(401, "refresh_invalid")
	}
	if err != nil {
		return err
	}
	hash, next, nextRefresh := tokenHash(proof), tokenHash(body.NextToken), tokenHash(body.NextRefreshToken)
	// Unknown proofs cannot inspect or affect an unrelated authority.
	if hash != a.RefreshHash && hash != a.PreviousRefresh {
		return authFailure(401, "refresh_invalid")
	}
	if err = checkAuthSession(tx, a, true); err != nil {
		return err
	}
	if hash == a.PreviousRefresh {
		if body.RequestID != a.Request || *body.ExpectedGeneration != a.ExpectedGeneration || next != a.NextToken || nextRefresh != a.NextRefresh || a.Generation != a.ExpectedGeneration+1 {
			return authFailure(409, "auth_conflict")
		}
		s.write(w, 200, authReceipt{a.ID, a.Generation, fromTimestamp(a.ReceiptTokenExpiry), fromTimestamp(a.ReceiptRefreshExpiry)})
		return nil
	}
	if *body.ExpectedGeneration != a.Generation || body.RequestID == a.Request {
		return authFailure(409, "auth_conflict")
	}
	if a.Generation >= 2147483647 {
		return authFailure(409, "auth_conflict")
	}
	var used int
	if err = tx.QueryRow(`SELECT (SELECT COUNT(*) FROM tokens WHERE hash IN (?,?))+(SELECT COUNT(*) FROM auth_sessions WHERE refresh_hash IN (?,?) OR previous_refresh_hash IN (?,?) OR token_hash IN (?,?))`, next, nextRefresh, next, nextRefresh, next, nextRefresh, next, nextRefresh).Scan(&used); err != nil {
		return err
	}
	if used != 0 {
		return fail(400, "refresh candidates must be fresh")
	}
	at := time.Now()
	refreshExpiry := timestamp(at.Add(s.cfg.AuthRefreshTTL))
	if a.AbsoluteExpiry != 0 {
		refreshExpiry = min(refreshExpiry, a.AbsoluteExpiry)
	}
	tokenExpiry := min(timestamp(at.Add(s.cfg.AccountTokenTTL)), refreshExpiry)
	overlap := min(a.TokenExpiry, timestamp(at.Add(s.cfg.AuthAccessOverlap)))
	// Only current + predecessor admission rows are retained; live connections
	// now refer to the authority, never to these transient admission rows.
	if _, err = tx.Exec("DELETE FROM tokens WHERE kind='account' AND auth_session_id=? AND hash<>?", a.ID, a.TokenHash); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE tokens SET expires_at=? WHERE hash=? AND kind='account'", overlap, a.TokenHash); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO tokens(hash,kind,tenant_id,version,expires_at,auth_session_id) VALUES(?,'account',?,?,?,?)", next, a.Tenant, a.Version, tokenExpiry, a.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE auth_sessions SET generation=generation+1,refresh_hash=?,token_hash=?,token_expires_at=?,refresh_expires_at=?,previous_refresh_hash=?,request_id=?,expected_generation=?,next_token_hash=?,next_refresh_hash=?,receipt_token_expires_at=?,receipt_refresh_expires_at=?,updated_at=? WHERE id=?`, nextRefresh, next, tokenExpiry, refreshExpiry, hash, body.RequestID, a.Generation, next, nextRefresh, tokenExpiry, refreshExpiry, timestamp(at), a.ID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	// Ordinary rotation only extends unchanged authority. Cache snapshots expire
	// naturally; advancing revocation epochs here could close an in-flight relay.
	s.notifyWSTenant(a.Tenant)
	s.write(w, 200, authReceipt{a.ID, a.Generation + 1, fromTimestamp(tokenExpiry), fromTimestamp(refreshExpiry)})
	return nil
}

type authRevocation struct {
	tenant            string
	sessions, brokers []string
}

func revokeAuthSession(tx *sql.Tx, a authSession) (authRevocation, error) {
	out := authRevocation{tenant: a.Tenant}
	if _, err := tx.Exec("UPDATE auth_sessions SET revoked_reason='logout',updated_at=? WHERE id=? AND revoked_reason=''", now(), a.ID); err != nil {
		return out, err
	}
	scope := "auth_session_id=? OR device_hash IN (SELECT hash FROM tokens WHERE kind='device' AND auth_session_id=?)"
	rows, err := tx.Query("SELECT id FROM sessions WHERE id IN (SELECT current_session_id FROM connections WHERE "+scope+") OR id IN (SELECT session_id FROM tokens WHERE kind='session' AND auth_session_id=?) OR broker_id IN (SELECT broker_id FROM tokens WHERE kind='device' AND auth_session_id=?)", a.ID, a.ID, a.ID, a.ID)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return out, err
		}
		out.sessions = append(out.sessions, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.Query("SELECT broker_id FROM tokens WHERE kind='device' AND auth_session_id=?", a.ID)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return out, err
		}
		out.brokers = append(out.brokers, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = revokeConnections(tx, scope, "account_logout", a.ID, a.ID); err != nil {
		return out, err
	}
	// Materialized session IDs also include non-managed sessions belonging to
	// this caller or broker. Deleting token rows cannot erase the selector for
	// the later session deletion, and unrelated login sessions remain live.
	for _, id := range out.sessions {
		if _, err = tx.Exec("DELETE FROM tokens WHERE kind='session' AND session_id=?", id); err != nil {
			return out, err
		}
		if _, err = tx.Exec("DELETE FROM sessions WHERE id=?", id); err != nil {
			return out, err
		}
	}
	if _, err = tx.Exec("UPDATE brokers SET lease_expires_at=0 WHERE id IN (SELECT broker_id FROM tokens WHERE kind='device' AND auth_session_id=?)", a.ID); err != nil {
		return out, err
	}
	_, err = tx.Exec("DELETE FROM tokens WHERE auth_session_id=?", a.ID)
	return out, err
}
func (s *Server) applyAuthRevocation(v authRevocation) {
	// The transaction materialized every affected session and device broker.
	// Their revoke helpers invalidate those scopes; other families stay cached.
	for _, id := range v.sessions {
		s.revokeSession(id)
	}
	for _, id := range v.brokers {
		s.revokeBroker(id)
	}
	s.notifyWSTenant(v.tenant)
}
func (s *Server) logoutAuth(w http.ResponseWriter, r *http.Request) error {
	proof := bearer(r)
	if proof == "" {
		return authFailure(401, "refresh_invalid")
	}
	hash := tokenHash(proof)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRow(`SELECT id FROM auth_sessions WHERE token_hash=? OR refresh_hash=? OR previous_refresh_hash=? OR id IN (SELECT auth_session_id FROM tokens WHERE hash=? AND kind='account')`, hash, hash, hash, hash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return authFailure(401, "refresh_invalid")
	}
	if err != nil {
		return err
	}
	a, err := readAuthSession(tx, id)
	if err != nil {
		return err
	}
	// Retained proof hashes allow harmless repeat logout without resurrecting any
	// token. No unknown proof can enter this path.
	v, err := revokeAuthSession(tx, a)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.applyAuthRevocation(v)
	s.write(w, 200, map[string]any{"logged_out": true})
	return nil
}
func (s *Server) deleteAuthSession(w http.ResponseWriter, r *http.Request) error {
	p, err := s.auth(r, "account")
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = txPrincipal(tx, r, p); err != nil {
		return err
	}
	a, err := readAuthSession(tx, r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		return fail(404, "auth session not found")
	}
	if err != nil {
		return err
	}
	if a.Tenant != p.tenant {
		return fail(403, "auth session scope denied")
	}
	v, err := revokeAuthSession(tx, a)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.applyAuthRevocation(v)
	s.write(w, 200, map[string]any{"deleted": true})
	return nil
}

// Admission must be current; an already admitted account request may complete
// after access rotation, but never after authority revocation or tenant change.
func txAuthPrincipal(tx *sql.Tx, p principal) error {
	_, err := authAuthority(tx, p.authSession, p.tenant, p.version, false)
	return err
}
func (s *Server) issueDevice(tx *sql.Tx, p principal, broker string) (string, error) {
	expiry := time.Now().Add(365 * 24 * time.Hour)
	if p.authSession != "" {
		a, err := authAuthority(tx, p.authSession, p.tenant, p.version, false)
		if err != nil {
			return "", err
		}
		expiry = fromTimestamp(min(timestamp(expiry), a.RefreshExpiry))
	}
	token, err := issue(tx, "device", p.tenant, broker, "", p.version, expiry)
	if err == nil && p.authSession != "" {
		_, err = tx.Exec("UPDATE tokens SET auth_session_id=? WHERE hash=?", p.authSession, tokenHash(token))
	}
	return token, err
}

func nullAuthSession(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func checkSessionAuth(q authQuerier, v Session) error {
	if v.AuthSession == "" {
		return nil
	}
	a, err := readAuthSession(q, v.AuthSession)
	if errors.Is(err, sql.ErrNoRows) {
		return authFailure(401, "refresh_revoked")
	}
	if err != nil {
		return err
	}
	if a.Tenant != v.TenantID {
		return authFailure(401, "refresh_revoked")
	}
	return checkAuthSession(q, a, false)
}
