# Account credential refresh in 0.5.0

The CLI and opt-in C/Go authentication manager rotate account credentials while the same peers, mappings, TCP sockets and TURN allocations continue running. Access TTL defaults to 24 hours (also for legacy login), refresh idle lifetime to 30 days, refresh lead to 10 minutes with small jitter, superseded access admission overlap to 2 minutes. Absolute login-session lifetime is optional and defaults to unlimited; idle expiry and explicit revocation always apply. All token material is 32 CSPRNG bytes encoded as 64 lowercase hexadecimal characters. Persist hashes only on the server.

## Wire contract

Additive discovery field: `account_refresh_protocol: "refresh-v1"` in `GET /v1/status`. Legacy endpoints continue their existing static-bearer contract. New endpoints:

- `POST /v1/auth/register`: same name/password/email request as tenant registration; same registration policy.
- `POST /v1/auth/login`: same name/password request as tenant login.
- Both return `{tenant,token,refresh_token,auth_session_id,generation,token_expires_at,refresh_expires_at}`. Generation begins at 1. Timestamps are UTC RFC3339Nano. Pending registration may retain refresh authority but must not gain active tenant permissions.
- `POST /v1/auth/refresh`: authenticate with refresh bearer; body `{auth_session_id,expected_generation,request_id,next_token,next_refresh_token}`. Session/request IDs are UUIDv4; candidates are fresh distinct 256-bit secrets. Response is ONLY `{auth_session_id,generation,token_expires_at,refresh_expires_at}`; client already owns the candidate secrets. A successful ordinary rotation increments credential generation by one and extends idle expiry, bounded by optional absolute lifetime. It never increments tenant/connection generation or creates a new broker.
- `POST /v1/auth/logout`: revoke current login session using its access/refresh proof; safe retries may acknowledge already revoked authority without granting permission.
- `DELETE /v1/auth/sessions/{id}`: an authenticated account can revoke its own specified login session.

One transaction validates tenant status/version, session idle/absolute expiry and nonrevocation, rotates hashes, admits prior access for at most the overlap (clamped to its old expiry), and records ONE predecessor receipt: old refresh hash, request ID, expected generation, both candidate hashes, committed generation/deadlines. Exact predecessor replay returns the original metadata only while the authority is alive and that commit remains current; it never extends deadlines. A different stale attempt returns HTTP409 `auth_conflict`, without automatically revoking the whole family. Invalid/expired/revoked refresh gets typed HTTP401 errors such as `refresh_invalid`, `refresh_expired`, `refresh_revoked`. Always validate authority BEFORE receipt replay. Unknown/bad secrets cannot revoke someone else's family. Retain current predecessor receipt until the next rotation/session expiry, allowing long interrupted-commit recovery with bounded storage.

Access tokens remain kind `account`, with nullable login-session association. Refresh proofs do not grant general account API access. Account session admission counts stable sessions (bound 16 per tenant), not rotated access rows; legacy login token eviction must not evict refresh-enabled sessions. Schema 3 preserves all legacy rows. Never mint refresh authority from an expired or revoked old bearer. Password/identity changes, disable/delete, logout and explicit connection/device revocation retain their effective revocation behavior.

## Stable authorization

New managed connections bind to stable caller login session and scoped device authority. Update connection create/recovery/check/pruning, session checks, TURN joined authorization/minimum deadline/cache invalidation, WS principal checks, and logout selection together. Legacy rows remain bound to original hashes/deadlines. A freshly admitted request needs a valid current/overlap access bearer; its mutation-time check revalidates stable live authority/version, allowing already-admitted long requests to complete after rotation. Continuing WSS checks live stable authority rather than expired initial access hash. Never revive explicitly revoked lineages.

New login-associated device tokens are renewed IN PLACE by an authenticated heartbeat, bounded by live login-session authority/version. Do not use existing offline-only device rotation for routine renewal; explicit rotation keeps its revocation semantics. Legacy device/connection rows do not gain new indefinite authority implicitly.

## Native SDK ABI and storage

Preserve legacy immutable/concurrent `ob_api_options` and constructors. Add opaque opt-in auth manager, versioned/size-tagged new option structs and a new client constructor; do not append fields to old public structs. The manager owns immutable credential snapshots with safe lifetimes, one refresh operation at a time and an independent bounded refresh transport. Requests obtain a current copied account bearer; explicit device/session bearers retain their scopes. Manager runs throughout serve/connect lifetime, even when no account RPC is made. Do not blindly replay arbitrary modifying HTTP operations after a refresh: only a known pre-mutation authentication failure or an operation with its own idempotence contract may replay.

Include `ob_auth.h` for `ob_auth_manager`, `ob_auth_credentials`, `ob_auth_pending`, `ob_auth_options` and `ob_api_client_create_with_auth`. Initialize the new options with `struct_size = sizeof(ob_auth_options)` and `version = 1`. C credentials hold the session ID, access/refresh secrets, generation and UTC epoch-millisecond deadlines. A pending request holds the session ID, expected generation, request ID and next secrets. `ob_auth_credentials_parse` reads a successful login response; clear the response and credentials when finished. `ob_auth_manager_snapshot` copies a credential snapshot, while `ob_auth_manager_refresh` coordinates explicit rotation. The client owns its borrowed manager; close peers and mappings before destroying the client.

Storage callbacks run outside client/peer locks:
1. Begin: coordinate persistence (e.g. acquire profile lock), reload credentials and any pending attempt into working snapshots.
2. Prepare: durably persist exact candidate request BEFORE network.
3. Commit: atomically persist confirmed credentials AFTER receipt verification.
4. End: release coordination unconditionally after success/failure. Ambiguous outcomes keep pending data.

After Begin, newer credentials from the SAME authority may avoid network. A different API/tenant/login session is not silently adopted. Pending receipt replay may yield an already-expired access credential while refresh remains valid: persist confirmation, then perform a fresh rotation as needed. Never overwrite a newer profile generation with stale receipt data. In-memory-only mode is supported without filesystem writes; callers own storage callbacks.

Go wrapper integration:

```go
type AuthCredentials struct {
    AuthSessionID string `json:"auth_session_id"`
    Token string `json:"token"`
    RefreshToken string `json:"refresh_token"`
    Generation uint64 `json:"generation"`
    TokenExpiresAt time.Time `json:"token_expires_at"`
    RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}
type AuthPending struct {
    AuthSessionID string `json:"auth_session_id"`
    ExpectedGeneration uint64 `json:"expected_generation"`
    RequestID string `json:"request_id"`
    NextToken string `json:"next_token"`
    NextRefreshToken string `json:"next_refresh_token"`
}
type AuthStorage interface {
    Begin() (AuthCredentials, *AuthPending, error)
    Prepare(AuthCredentials, AuthPending) error
    Commit(AuthCredentials, AuthPending) error
    End()
}
type AuthOptions struct {
    Credentials AuthCredentials
    Storage AuthStorage // nil: memory-only
    RefreshBefore time.Duration // 0: default10min, clamped for short TTLs
}
func NewWithAuth(options Options, auth AuthOptions) (*Client, error)
```

Native auth state/status callbacks must redact credentials. Go storage bridge must keep callback context alive until manager threads and all clients/peers are joined; never retain unsafe Go pointers in C.

## CLI configuration

New private version2 account profiles retain the ordinary API/CA/account identity and access token in `account.token`, with refresh token, session ID, generation and expiry metadata in `auth`. They contain no stored account password. Registration against a refresh-enabled server requires a password through interactive input or `--password-stdin`; the CLI does not create a password that would be discarded. Explicit `--legacy-auth` register/login creates a version1 profile for older clients. Read version1 for legacy operation/migration. One explicit `tenant login` uses old saved password only if same account/API, calls new endpoint after discovery, and creates v2 profile. Do not silently password-login upon generic 401. New profile is intentionally not readable by legacy strict CLI; mixed versions use separate `--config`.

Use ORIGINAL profile's persistent `.lock` inode. Refresh pending filename is `.refresh-pending` appended to profile (different from registration `.pending`). Under lock reread current profile, recover exact pending transaction before a new attempt, or adopt a newer committed SAME-session generation. File+directory fsync before RPC; atomic profile rename+directory fsync before pending unlink+directory fsync. Release lock on all paths and keep pending data on ambiguity. Other processes adopt next generation without peer close/rebind. Do not adopt different account/API/session after explicit login/logout. Redact new credential fields from all JSON/log/state output.

The `tenant refresh` command requests rotation and prints only the login-session ID, generation and deadlines. Routine `serve`, `connect` and account commands refresh automatically. The client never retries an arbitrary modifying RPC after HTTP401; GET requests may refresh/adopt shared credentials and retry once. Logout, password and identity changes stop the old authentication worker before replacing the local profile. Password and identity changes return a new login session and revoke the previous authority according to the tenant-version policy.

Server options are `--account-token-ttl` (24h), `--auth-refresh-ttl` (720h), `--auth-absolute-ttl` (0) and `--auth-access-overlap` (2m). Refresh deadlines slide only after successful rotation. Offline clients can recover an expired access token while the refresh authority remains valid; explicit login is required after idle expiry or revocation.

```sh
# Upgrade an existing version1 profile once; its saved password may be reused.
oheco-broker --api https://example.org:3478 tenant login
# Thereafter long-running peers renew credentials automatically.
oheco-broker tenant serve --name desktop --password-stdin \
  --allow tcp@127.0.0.1:8080 < /private/path/peer-password
# Optional diagnostic rotation; no token is printed.
oheco-broker tenant refresh
```

## Acceptance

Use short configurable lifetimes in isolated permission-correct fixtures to test multiple refreshes while SAME TCP socket and TCP/UDP maps carry payloads; confirm no listener rebinding, peer recreation or connection-generation increment. Cover access expiry with live refresh, proactive idle timer, multi-process shared profile, lost reply, process restart, persistence failure, long-call admission, revocation/disabled/password cases, cache/TURN/WSS correctness, schema2 migration preserving legacy rows and old0.3/0.4 protocols. Native HarmonyOS build/sign/run before release. Publish immutable0.5.0 runtime+SDK+source artifacts, package index/Pages and real installation validation, then backup/migrate production image and localCLI with post-upgrade scoped native acceptance.
