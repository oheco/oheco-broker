#ifndef OB_AUTH_H
#define OB_AUTH_H
#include "ob_api.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Opt-in account refresh. Legacy ob_api_options and constructors retain their
 * immutable bearer contract. Credentials are copied; SDK never writes files. */
typedef struct ob_auth_manager ob_auth_manager;
typedef struct {
    char auth_session_id[37];
    char token[65], refresh_token[65];
    uint64_t generation;
    int64_t token_expires_at_ms, refresh_expires_at_ms;
} ob_auth_credentials;
typedef struct {
    char auth_session_id[37], request_id[37];
    uint64_t expected_generation;
    char next_token[65], next_refresh_token[65];
} ob_auth_pending;

/* Begin fills credentials and optionally pending; has_pending is initially 0.
 * End is called after EVERY Begin invocation, including failed Begin. Callbacks
 * must be bounded/cancellation-aware, must not recursively refresh/destroy the
 * client or close borrowed peers/servers, and run without client/peer/state locks
 * (serialized refresh operation). Snapshot inspection is permitted.
 * Prepare MUST durably save the exact pending attempt before returning success.
 * Commit MUST durably save credentials before clearing pending. Ambiguous or
 * failed outcomes retain pending. Return 0 on success, nonzero on storage error.
 * User/context remains alive until client destruction has joined its worker. */
typedef int (*ob_auth_begin_fn)(void *, ob_auth_credentials *, ob_auth_pending *, int *has_pending);
typedef int (*ob_auth_prepare_fn)(void *, const ob_auth_credentials *, const ob_auth_pending *);
typedef int (*ob_auth_commit_fn)(void *, const ob_auth_credentials *, const ob_auth_pending *);
typedef void (*ob_auth_end_fn)(void *);
typedef struct {
    uint32_t struct_size, version; /* sizeof(ob_auth_options), 1 */
    ob_auth_credentials credentials;
    int64_t refresh_before_ms; /* 0: 10min, clamped to a fifth of short remaining TTL */
    long refresh_timeout_ms; /* 0: 10s; 1..30000, independent refresh transport */
    void *user;
    ob_auth_begin_fn begin;
    ob_auth_prepare_fn prepare;
    ob_auth_commit_fn commit;
    ob_auth_end_fn end;
} ob_auth_options;

ob_api_client *ob_api_client_create_with_auth(const ob_api_options *, const ob_auth_options *, ob_api_error *);
/* Borrowed manager; client must outlive all calls, peers and mappings. */
ob_auth_manager *ob_api_client_auth_manager(ob_api_client *);
int ob_auth_manager_snapshot(ob_auth_manager *, ob_auth_credentials *, ob_api_error *);
/* force=0 checks freshness/adopts shared credentials; force=1 requests rotation.
 * Arbitrary account mutations are never automatically replayed. Managed
 * connection proposals may reuse their own idempotent CAS/request identity. */
int ob_auth_manager_refresh(ob_auth_manager *, int force, ob_api_error *);
/* Stop future refresh and interrupt its transport; destroy joins the worker. */
void ob_auth_manager_cancel(ob_auth_manager *);
/* Decode the additive /v1/auth/login or register response; no disk writes. */
int ob_auth_credentials_parse(const char *json, ob_auth_credentials *, ob_api_error *);
void ob_auth_credentials_clear(ob_auth_credentials *);
void ob_auth_pending_clear(ob_auth_pending *);
#ifdef __cplusplus
}
#endif
#endif
