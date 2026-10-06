#include "internal.h"
#include "crypto.h"
#include "../ob_api_internal.h"
#include <openssl/rand.h>
#include <openssl/mem.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

static const char *text(cJSON *j, const char *key)
{ cJSON *v = cJSON_GetObjectItemCaseSensitive(j, key); return cJSON_IsString(v) ? v->valuestring : NULL; }
static int integer(cJSON *j, const char *key, uint64_t *out)
{
    cJSON *v = cJSON_GetObjectItemCaseSensitive(j, key);
    if (!cJSON_IsNumber(v) || v->valuedouble < 0 || v->valuedouble > 9007199254740991.0) return -1;
    uint64_t n = (uint64_t)v->valuedouble;
    if ((double)n != v->valuedouble) return -1;
    *out = n; return 0;
}
static int uuid(char out[37])
{
    unsigned char bytes[16]; char raw[33];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) return -1;
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    ob_hex(bytes, sizeof(bytes), raw);
    snprintf(out, 37, "%.8s-%.4s-%.4s-%.4s-%.12s", raw, raw+8, raw+12, raw+16, raw+20);
    OPENSSL_cleanse(bytes, sizeof(bytes)); return 0;
}
static void wait_locked(ob_remote_peer *p, unsigned milliseconds)
{
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += (long)milliseconds * 1000000;
    ts.tv_sec += ts.tv_nsec / 1000000000; ts.tv_nsec %= 1000000000;
    pthread_cond_timedwait(&p->cv, &p->mu, &ts);
}
static int request_cancel(void *data)
{
    ob_remote_peer *p = data;
    return atomic_load(&p->stop) || ob_now_us() >= p->deadline_us;
}
static int api_failure(ob_remote_error *error, const ob_api_error *api)
{
    int code = api->code == OB_API_NOMEM ? OB_REMOTE_ENOMEM :
        api->code == OB_API_JSON ? OB_REMOTE_EPROTOCOL :
        api->code == OB_API_LIMIT ? OB_REMOTE_ELIMIT :
        api->code == OB_API_INVALID ? OB_REMOTE_EINVAL :
        api->code == OB_API_CRYPTO ? OB_REMOTE_EAUTH : OB_REMOTE_EHTTP;
    return ob_error(error, code, (int)api->http_status, api->message);
}
static int retryable(const ob_remote_error *e)
{
    if (e->code == OB_REMOTE_EICE || e->code == OB_REMOTE_EQUIC ||
        e->code == OB_REMOTE_ETIMEOUT || e->code == OB_REMOTE_EIO) return 1;
    return e->code == OB_REMOTE_EHTTP &&
        (!e->http_status || e->http_status == 409 || e->http_status == 429 || e->http_status >= 500);
}
/* Network requests belong to this coordinator. A managed request's identifiers
 * and proposed token are generated before sending and survive ambiguous errors. */
static int open_session(ob_remote_peer *p, ob_remote_error *error)
{
    p->control_retryable = 0;
    if (!p->control_discovered) {
        char *status_text = NULL; ob_api_error status_error = {0};
        int api_rc = ob_api_request_cancelled(p->api, "GET", "/v1/status", NULL, NULL,
                       &status_text, &status_error, request_cancel, p);
        cJSON *status = status_text && *status_text ? ob_peer_json_parse(status_text) : NULL;
        ob_api_response_free(status_text);
        int rc = api_rc ? api_failure(error, &status_error) : 0;
        if (rc && error->http_status != 404) { cJSON_Delete(status); return rc; }
        uint64_t version = 0;
        if (!rc && !integer(status, "connection_recovery_version", &version) && version == 1)
            p->control_managed = 1;
        cJSON_Delete(status); p->control_discovered = 1;
    }
    if (p->control_managed && !p->connection_id[0] && uuid(p->connection_id))
        return ob_error(error, OB_REMOTE_EAUTH, 0, "Cannot generate logical connection identity");
    if (p->control_managed && !p->request_pending) {
        unsigned char token[32];
        if (uuid(p->request_id) || RAND_bytes(token, sizeof(token)) != 1)
            return ob_error(error, OB_REMOTE_EAUTH, 0, "Cannot generate connection request credentials");
        ob_hex(token, sizeof(token), p->requested_session_token);
        OPENSSL_cleanse(token, sizeof(token)); p->request_pending = 1;
    }
    cJSON *body = cJSON_CreateObject();
    if (!body) return ob_error(error, OB_REMOTE_ENOMEM, 0, NULL);
    cJSON_AddStringToObject(body, "broker_id", p->broker_id);
    cJSON_AddStringToObject(body, "relay_mode", p->relay == OB_REMOTE_RELAY_FORCE ? "force" :
                            p->relay == OB_REMOTE_RELAY_NEVER ? "never" : "auto");
    char path[160];
    if (p->control_managed) {
        snprintf(path, sizeof(path), "/v1/connections/%s/session", p->connection_id);
        cJSON_AddNumberToObject(body, "expected_generation", (double)p->control_generation);
        cJSON_AddStringToObject(body, "request_id", p->request_id);
        cJSON_AddStringToObject(body, "session_token", p->requested_session_token);
    } else snprintf(path, sizeof(path), "/v1/sessions");
    char *payload = cJSON_PrintUnformatted(body), *response_text = NULL;
    cJSON_Delete(body);
    if (!payload) return ob_error(error, OB_REMOTE_ENOMEM, 0, NULL);
    ob_api_error ae = {0};
    int rc = ob_api_request_cancelled(p->api, "POST", path, NULL, payload, &response_text,
                                       &ae, request_cancel, p);
    /* This managed session proposal has its own persisted-in-handle CAS/request
     * identity. Retry only that exact idempotent transaction after refreshing an
     * account 401; generic mutation RPCs retain their no-replay behavior. */
    if (rc && p->control_managed && p->api->auth && ae.http_status == 401 && !request_cancel(p)) {
        ob_api_error refresh_error = {0};
        if (!ob_auth_manager_refresh_cancelled(p->api->auth, 1, &refresh_error, request_cancel, p)) {
            ob_api_response_free(response_text); response_text = NULL;
            rc = ob_api_request_cancelled(p->api, "POST", path, NULL, payload, &response_text,
                                           &ae, request_cancel, p);
        }
    }
    OPENSSL_cleanse(payload, strlen(payload)); free(payload);
    cJSON *response = response_text && *response_text ? ob_peer_json_parse(response_text) : NULL;
    ob_api_response_free(response_text);
    if (rc) {
        const char *reason = text(response, "error_code"); uint64_t generation = 0;
        /* A committed request may have expired before its result arrived.
         * The authenticated server reports its CAS generation; the next request
         * then proposes a fresh token rather than replaying the expired grant. */
        if (p->control_managed && (ae.http_status == 409 || ae.http_status == 410) &&
            reason && (!strcmp(reason, "session_expired") || !strcmp(reason, "connection_conflict")) &&
            !integer(response, "generation", &generation) && generation >= p->control_generation) {
            p->control_generation = generation; p->request_pending = 0;
            p->control_retryable = 1;
        }
        cJSON_Delete(response);
        return api_failure(error, &ae);
    }
    const char *sid = text(response, "session_id");
    const char *token = p->control_managed ? p->requested_session_token : text(response, "session_token");
    uint64_t generation = 0;
    const char *connection = text(response, "connection_id");
    if (!ob_valid_id(sid) || !token || !*token ||
        (p->control_managed && (!connection || strcmp(connection, p->connection_id) ||
        integer(response, "generation", &generation) || generation <= p->control_generation))) {
        cJSON_Delete(response); return ob_error(error, OB_REMOTE_EPROTOCOL, 0, "Invalid connection session grant");
    }
    char *new_sid = strdup(sid), *new_token = strdup(token);
    cJSON_Delete(response);
    if (!new_sid || !new_token) {
        free(new_sid); if (new_token) { OPENSSL_cleanse(new_token, strlen(new_token)); free(new_token); }
        return ob_error(error, OB_REMOTE_ENOMEM, 0, NULL);
    }
    free(p->session_id); p->session_id = new_sid;
    if (p->bearer) { OPENSSL_cleanse(p->bearer, strlen(p->bearer)); free(p->bearer); }
    p->bearer = new_token;
    if (p->control_managed) { p->control_generation = generation; p->request_pending = 0; }
    return 0;
}
static void retire_attempt(ob_remote_peer *p)
{
    if (p->setup_started) { pthread_join(p->setup_thread, NULL); p->setup_started = 0; }
    pthread_mutex_lock(&p->mu);
    while (!p->transport_detached) wait_locked(p, 50);
    pthread_mutex_unlock(&p->mu);
    /* libjuice joins its callbacks before return. Only then discard queued old
     * ciphertext and prepare new keys, cert and transport on the same handle. */
    juice_agent_t *ice = atomic_exchange(&p->ice, NULL);
    if (ice) juice_destroy(ice);
    pthread_mutex_lock(&p->qmu);
    struct ob_packet *packet = p->qhead; p->qhead = p->qtail = NULL; p->qcount = 0;
    pthread_mutex_unlock(&p->qmu);
    while (packet) { struct ob_packet *next = packet->next; free(packet); packet = next; }
    ob_certificate_cleanup(p);
    memset(p->cert_dir, 0, sizeof(p->cert_dir)); memset(p->cert_path, 0, sizeof(p->cert_path));
    memset(p->key_path, 0, sizeof(p->key_path));
}
static int schedule(ob_remote_peer *p)
{
    pthread_mutex_lock(&p->mu);
    struct ob_recovery *r = &p->recovery;
    int manual = 0;
    for (;;) {
        if (atomic_load(&p->stop)) { pthread_mutex_unlock(&p->mu); return -1; }
        uint64_t now = ob_now_us();
        if (atomic_exchange(&r->requested, 0)) {
            r->info.attempts = 0; r->outage_us = now; r->retry_us = 0; manual = 1;
        }
        int exhausted = (r->policy.disabled && p->transport_generation && !manual) ||
            r->info.attempts >= r->policy.max_attempts ||
            (r->outage_us && now - r->outage_us >= (uint64_t)r->policy.retry_budget_ms * 1000);
        if (exhausted) {
            if (r->info.state != OB_REMOTE_STATE_PAUSED)
                ob_recovery_set_locked(r, OB_REMOTE_STATE_PAUSED, &p->attempt_error);
            pthread_mutex_unlock(&p->mu); ob_recovery_deliver(r, &p->mu);
            pthread_mutex_lock(&p->mu); wait_locked(p, 50); continue;
        }
        if (!r->retry_us || now >= r->retry_us) break;
        if (r->info.state != OB_REMOTE_STATE_RETRY_WAIT)
            ob_recovery_set_locked(r, OB_REMOTE_STATE_RETRY_WAIT, &p->attempt_error);
        pthread_mutex_unlock(&p->mu); ob_recovery_deliver(r, &p->mu);
        pthread_mutex_lock(&p->mu); wait_locked(p, 50);
    }
    ++r->info.attempts; ++p->transport_generation;
    r->info.generation = p->transport_generation;
    ob_recovery_set_locked(r, p->ever_ready ? OB_REMOTE_STATE_RECONNECTING : OB_REMOTE_STATE_CONNECTING, NULL);
    pthread_mutex_unlock(&p->mu); ob_recovery_deliver(r, &p->mu); return 0;
}
static void delay_next(ob_remote_peer *p)
{
    pthread_mutex_lock(&p->mu); struct ob_recovery *r = &p->recovery;
    if (!r->outage_us) r->outage_us = ob_now_us();
    if (!r->info.attempts) { r->retry_us = 0; pthread_mutex_unlock(&p->mu); return; }
    uint64_t delay = r->policy.initial_delay_ms;
    for (uint32_t i = 1; i < r->info.attempts && delay < r->policy.max_delay_ms; ++i) delay *= 2;
    if (delay > r->policy.max_delay_ms) delay = r->policy.max_delay_ms;
    unsigned jitter = 0; if (RAND_bytes((unsigned char *)&jitter, sizeof(jitter)) != 1) jitter = (unsigned)ob_now_us();
    delay += jitter % (delay / 4 + 1);
    if (delay > r->policy.max_delay_ms) delay = r->policy.max_delay_ms;
    r->retry_us = ob_now_us() + delay * 1000;
    pthread_mutex_unlock(&p->mu);
}
static int server_session(ob_remote_peer *p)
{
    pthread_mutex_lock(&p->mu);
    while (!p->pending_session_id && !atomic_load(&p->stop)) {
        if (p->recovery.info.state != OB_REMOTE_STATE_RETRY_WAIT)
            ob_recovery_set_locked(&p->recovery, OB_REMOTE_STATE_RETRY_WAIT, NULL);
        pthread_mutex_unlock(&p->mu); ob_recovery_deliver(&p->recovery, &p->mu);
        pthread_mutex_lock(&p->mu); wait_locked(p, 50);
    }
    if (atomic_load(&p->stop)) { pthread_mutex_unlock(&p->mu); return -1; }
    char *sid = p->pending_session_id; p->pending_session_id = NULL;
    free(p->session_id); p->session_id = sid;
    p->control_generation = p->pending_control_generation;
    pthread_mutex_unlock(&p->mu); return 0;
}
void *ob_peer_coordinator(void *data)
{
    ob_remote_peer *p = data; int first = 1;
    while (!atomic_load(&p->stop)) {
        if (p->is_server && !first && server_session(p)) break;
        if (!p->is_server && schedule(p)) break;
        pthread_mutex_lock(&p->mu);
        p->attempt_result = 0; memset(&p->attempt_error, 0, sizeof(p->attempt_error));
        p->ready = p->tls_ready = p->proof_ready = 0; p->transport_available = 0;
        p->lease_deadline_set = p->approved = p->control_cleanup = 0;
        p->tx_sequence = p->rx_sequence = p->heartbeat_id = 0;
        p->heartbeat_due_us = p->heartbeat_sent_us = p->reconnect_us = 0;
        p->reconnect_backoff = 0; p->next_timer_us = 0;
        p->deadline_us = ob_now_us() + (uint64_t)p->timeout_ms * 1000;
        if (!p->is_server && p->recovery.outage_us) {
            uint64_t budget = p->recovery.outage_us + (uint64_t)p->recovery.policy.retry_budget_ms * 1000;
            if (budget < p->deadline_us) p->deadline_us = budget;
        }
        atomic_store(&p->ice_ready, 0); atomic_store(&p->gathered, 0); atomic_store(&p->ice_failed, 0);
        atomic_store(&p->attempt_stop, 0);
        if (p->is_server) {
            ++p->transport_generation; p->recovery.info.generation = p->transport_generation;
            ob_recovery_set_locked(&p->recovery, p->ever_ready ? OB_REMOTE_STATE_RECONNECTING : OB_REMOTE_STATE_CONNECTING, NULL);
        }
        pthread_mutex_unlock(&p->mu);
        ob_remote_error error = {0};
        int rc = p->is_server ? 0 : open_session(p, &error);
        first = 0;
        if (rc) {
            pthread_mutex_lock(&p->mu);
            if ((retryable(&error) || p->control_retryable) &&
                (p->control_managed || !p->control_discovered)) {
                ob_peer_transport_fail_locked(p, rc, error.message); p->attempt_error = error;
            } else { p->error = error; ob_peer_fail_locked(p, rc, error.message); }
            pthread_mutex_unlock(&p->mu);
        } else if (pthread_create(&p->setup_thread, NULL, ob_setup_worker, p)) {
            ob_peer_transport_fail(p, OB_REMOTE_EIO, "Cannot start connection setup worker");
        } else {
            p->setup_started = 1;
            pthread_mutex_lock(&p->mu);
            while (!atomic_load(&p->stop) && !atomic_load(&p->attempt_stop)) {
                uint64_t now = ob_now_us();
                if (p->ready && p->recovery.stable_us &&
                    now - p->recovery.stable_us >= (uint64_t)p->recovery.policy.stable_reset_ms * 1000) {
                    p->recovery.info.attempts = 0; p->recovery.outage_us = 0;
                }
                wait_locked(p, 50);
                pthread_mutex_unlock(&p->mu); ob_recovery_deliver(&p->recovery, &p->mu);
                pthread_mutex_lock(&p->mu);
            }
            pthread_mutex_unlock(&p->mu);
        }
        retire_attempt(p);
        if (atomic_load(&p->stop)) break;
        if (!p->control_managed && p->control_discovered) { ob_peer_fail(p, OB_REMOTE_ECLOSED, "Transport recovery requires a managed control connection"); break; }
        if (!p->is_server) delay_next(p);
    }
    /* Server-side context retirement must not revoke an otherwise authorized
     * client lineage; broker offline/rotation performs explicit global revoke. */
    if (!p->is_server) ob_control_close_connection(p);
    ob_recovery_deliver(&p->recovery, &p->mu); return NULL;
}
int ob_peer_start(ob_remote_peer *p, ob_remote_error *error)
{
    if (pthread_create(&p->io_thread, NULL, ob_engine_worker, p))
        return ob_error(error, OB_REMOTE_EIO, 0, "Cannot start peer I/O owner");
    p->io_started = 1;
    if (pthread_create(&p->coordinator_thread, NULL, ob_peer_coordinator, p)) {
        atomic_store(&p->stop, 1); ob_wake(p);
        return ob_error(error, OB_REMOTE_EIO, 0, "Cannot start connection coordinator");
    }
    p->coordinator_started = 1; return 0;
}
