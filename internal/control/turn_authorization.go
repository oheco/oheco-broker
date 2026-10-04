package control

import "context"

// Read the complete authorization lineage in one database snapshot. Token
// deadlines are checked after Scan, so waiting for the single DB connection
// cannot authorize an already expired lease. The joins intentionally retain
// the credential scopes used by checkConnection, including legacy sessions
// without a managed connection and nullable account broker IDs.
const turnAuthorizationIdentitySQL = `SELECT
 CASE WHEN t.status='active' AND t.relay_enabled<>0 AND b.tenant_id=t.id THEN 1 ELSE 0 END,
 b.lease_expires_at,
 CASE WHEN v.tenant_id=t.id AND v.broker_id=b.id AND v.peer_authenticated<>0 AND v.relay_approved<>0 AND v.relay_mode<>'never' THEN 1 ELSE 0 END,
 v.expires_at,COALESCE(cs.connection_id,''),COALESCE(cs.generation,0),
 CASE WHEN c.id IS NOT NULL AND c.revoked_reason='' AND ct.status='active' AND ct.version=c.tenant_version AND a.hash IS NOT NULL AND d.hash IS NOT NULL THEN 1 ELSE 0 END,
 COALESCE(a.expires_at,0),COALESCE(d.expires_at,0),
 COALESCE(cur.expires_at,0),COALESCE(st.expires_at,0),
 CASE WHEN c.current_session_id=v.id AND c.generation=cs.generation THEN 1 ELSE 0 END,
 COALESCE(c.id,''),COALESCE(c.broker_id,''),COALESCE(c.current_session_id,''),
 COALESCE(c.generation,0),COALESCE(c.session_token_hash,''),COALESCE(c.tenant_version,0),
 t.version,t.relay_enabled,v.peer_authenticated,v.relay_approved
FROM tenants t
JOIN brokers b ON b.id=?
JOIN sessions v ON v.id=?
LEFT JOIN connection_sessions cs ON cs.session_id=v.id
LEFT JOIN connections c ON c.id=cs.connection_id
LEFT JOIN tenants ct ON ct.id=c.tenant_id
LEFT JOIN tokens a ON a.hash=c.account_hash AND a.kind='account' AND a.tenant_id=c.tenant_id AND a.version=c.tenant_version AND COALESCE(a.broker_id,'')=''
LEFT JOIN tokens d ON d.hash=c.device_hash AND d.kind='device' AND d.tenant_id=c.tenant_id AND d.version=c.tenant_version AND COALESCE(d.broker_id,'')=c.broker_id
LEFT JOIN sessions cur ON cur.id=c.current_session_id
LEFT JOIN tokens st ON st.hash=c.session_token_hash AND st.kind='session' AND st.session_id=cur.id AND st.version=c.tenant_version
WHERE t.id=?`

func (s *Server) authorizeTURNIdentity(tenant, broker, session string) bool {
	allowed, _ := s.authorizeTURNIdentitySnapshot(tenant, broker, session)
	return allowed
}

func (s *Server) authorizeTURNIdentitySnapshot(tenant, broker, session string) (bool, int64) {
	return s.authorizeTURNIdentitySnapshotContext(context.Background(), tenant, broker, session)
}

func (s *Server) authorizeTURNIdentitySnapshotContext(ctx context.Context, tenant, broker, session string) (bool, int64) {
	var baseAllowed, sessionAllowed, lineageAllowed, currentGeneration int
	var brokerExpiry, sessionExpiry, accountExpiry, deviceExpiry, currentExpiry, tokenExpiry int64
	var connectionID string
	var sessionGeneration uint64
	var c connectionRecord
	var integerFields struct {
		tenantVersion, relayEnabled, peerAuthenticated, relayApproved int
	}
	// Retain typed scans for authorization fields: malformed stored integers
	// must deny authorization just as the previous typed query helpers did.
	err := s.turnAuthStmt.QueryRowContext(ctx, broker, session, tenant).Scan(
		&baseAllowed, &brokerExpiry, &sessionAllowed, &sessionExpiry, &connectionID, &sessionGeneration,
		&lineageAllowed, &accountExpiry, &deviceExpiry, &currentExpiry, &tokenExpiry, &currentGeneration,
		&c.ID, &c.Broker, &c.Session, &c.Generation, &c.TokenHash, &c.Version,
		&integerFields.tenantVersion, &integerFields.relayEnabled, &integerFields.peerAuthenticated, &integerFields.relayApproved,
	)
	if err != nil {
		return false, 0
	}
	at := now()
	if baseAllowed != 1 || brokerExpiry <= at {
		return false, 0
	}
	validUntil := min(brokerExpiry, sessionExpiry)
	if connectionID != "" {
		if lineageAllowed != 1 || accountExpiry <= at || deviceExpiry <= at {
			return false, 0
		}
		// Observe the current lineage before rejecting a historical generation,
		// just as managedSession does. Natural transport expiry is recoverable;
		// a missing or prematurely expired token for a live session is not.
		if currentExpiry > at && tokenExpiry <= at {
			s.persistTURNObservedRevocationContext(ctx, c)
			return false, 0
		}
		if currentGeneration != 1 {
			return false, 0
		}
		validUntil = min(validUntil, accountExpiry, deviceExpiry, currentExpiry, tokenExpiry)
	}
	if sessionAllowed != 1 || sessionExpiry <= at {
		return false, 0
	}
	return true, validUntil
}

func (s *Server) persistTURNObservedRevocation(c connectionRecord) {
	s.persistTURNObservedRevocationContext(context.Background(), c)
}

func (s *Server) persistTURNObservedRevocationContext(ctx context.Context, c connectionRecord) {
	result, err := s.db.ExecContext(ctx, "UPDATE connections SET revoked_reason='session_credential_revoked',updated_at=? WHERE id=? AND generation=? AND current_session_id=? AND session_token_hash=? AND revoked_reason=''", now(), c.ID, c.Generation, c.Session, c.TokenHash)
	if err != nil {
		return
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return
	}
	// TURN invokes authorization while holding the credential gate. Reentering
	// TURN revocation here would acquire that same gate exclusively and hang.
	// Persist before denying; the packet caller releases its gate and closes
	// the allocation. These wakes only enqueue control-owner notifications.
	s.notifyWSSession(c.Session)
	s.notifyWSBroker(c.Broker)
}
