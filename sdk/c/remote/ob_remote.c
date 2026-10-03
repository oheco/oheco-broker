#include "peer/internal.h"
#include "peer/crypto.h"
#include <openssl/mem.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

uint64_t ob_now_us(void)
{ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (uint64_t)ts.tv_sec*1000000+ts.tv_nsec/1000; }
uint64_t ob_realtime_us(void)
{ struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); return (uint64_t)ts.tv_sec*1000000+ts.tv_nsec/1000; }
const char *ob_remote_strerror(int r)
{
    switch (r) {
    case 0: return "success"; case OB_REMOTE_EINVAL: return "invalid argument";
    case OB_REMOTE_ENOMEM: return "allocation failed"; case OB_REMOTE_EHTTP: return "control request failed";
    case OB_REMOTE_EAUTH: return "peer authentication failed"; case OB_REMOTE_ETIMEOUT: return "timeout";
    case OB_REMOTE_EICE: return "ICE transport failed"; case OB_REMOTE_EQUIC: return "QUIC transport failed";
    case OB_REMOTE_EACL: return "target denied"; case OB_REMOTE_EIO: return "socket I/O failed";
    case OB_REMOTE_ECLOSED: return "peer closed or revoked"; case OB_REMOTE_ELIMIT: return "resource limit";
    case OB_REMOTE_EPROTOCOL: return "invalid peer protocol"; default: return "unknown remote error";
    }
}
int ob_error(ob_remote_error *e, int code, int http, const char *message)
{
    if (e) { memset(e, 0, sizeof(*e)); e->code = code; e->http_status = http;
        snprintf(e->message, sizeof(e->message), "%s", message ? message : ob_remote_strerror(code)); }
    return code;
}
void ob_wake(ob_remote_peer *p)
{ if (p->wake[1] >= 0) { const unsigned char c = 1; (void)write(p->wake[1], &c, 1); } }
void ob_peer_fail_locked(ob_remote_peer *p, int code, const char *message)
{
    if (!p->result) {
        p->result = code;
        if (code != OB_REMOTE_EHTTP || p->error.code != OB_REMOTE_EHTTP)
            ob_error(&p->error, code, 0, message);
    }
    atomic_store(&p->stop, 1); pthread_cond_broadcast(&p->cv); ob_wake(p);
}
void ob_peer_fail(ob_remote_peer *p, int code, const char *message)
{ pthread_mutex_lock(&p->mu); ob_peer_fail_locked(p, code, message); pthread_mutex_unlock(&p->mu); }
void ob_peer_mark_ready(ob_remote_peer *p)
{ p->proof_ready = p->ready = 1; pthread_cond_broadcast(&p->cv); }
int ob_valid_id(const char *s)
{
    if (!s || strlen(s) != 36) return 0;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    }
    return 1;
}
static const char *str(cJSON *obj, const char *name)
{ cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, name); return cJSON_IsString(v) ? v->valuestring : NULL; }
static uint32_t def(uint32_t value, uint32_t fallback) { return value ? value : fallback; }
static pthread_once_t native_once = PTHREAD_ONCE_INIT;
static void native_initialize(void)
{
    /* Upstream debug/warning messages can include ICE credentials. */
    juice_set_log_level(JUICE_LOG_LEVEL_NONE);
}
ob_remote_peer *ob_peer_alloc(ob_api_client *api, const char *broker_id,
                              const char *password, const ob_remote_connect_options *o)
{
    pthread_once(&native_once, native_initialize);
    ob_remote_peer *p = calloc(1, sizeof(*p)); if (!p) return NULL;
    p->api = api; p->wake[0] = p->wake[1] = -1;
    pthread_mutex_init(&p->mu, NULL); pthread_mutex_init(&p->qmu, NULL); pthread_cond_init(&p->cv, NULL);
    p->broker_id = strdup(broker_id); p->password = strdup(password);
    if (o && o->stun_server) p->stun = strdup(o->stun_server);
    p->relay = o ? o->relay_mode : OB_REMOTE_RELAY_AUTO;
    p->stun_port = o && o->stun_port ? o->stun_port : 3478;
    p->timeout_ms = def(o ? o->timeout_ms : 0, 30000);
    p->max_maps = def(o ? o->max_maps : 0, 32); p->max_flows = def(o ? o->max_flows : 0, 128);
    p->udp_idle_ms = def(o ? o->udp_idle_timeout_ms : 0, 60000);
    p->deadline_us = ob_now_us() + (uint64_t)p->timeout_ms*1000;
    p->lease_deadline_us = p->deadline_us; p->next_flow_id = 1;
    p->logical_local.sin_family = p->logical_peer.sin_family = AF_INET;
    p->logical_local.sin_addr.s_addr = p->logical_peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    p->logical_local.sin_port = htons(30001); p->logical_peer.sin_port = htons(30002);
    if (!p->broker_id || !p->password || (o && o->stun_server && !p->stun) || pipe(p->wake)) {
        ob_peer_destroy(p); return NULL;
    }
    for (int i = 0; i < 2; ++i) { fcntl(p->wake[i], F_SETFL, O_NONBLOCK); fcntl(p->wake[i], F_SETFD, FD_CLOEXEC); }
    return p;
}
void ob_peer_destroy(ob_remote_peer *p)
{
    if (!p) return;
    atomic_store(&p->stop, 1); ob_wake(p);
    if (p->setup_started) pthread_join(p->setup_thread, NULL);
    if (p->io_started) pthread_join(p->io_thread, NULL);
    if (p->ice) juice_destroy(p->ice);
    struct ob_packet *packet = p->qhead;
    while (packet) { struct ob_packet *next = packet->next; free(packet); packet = next; }
    ob_mapping_cleanup(p);
    ob_certificate_cleanup(p);
    if (p->password) { OPENSSL_cleanse(p->password, strlen(p->password)); free(p->password); }
    if (p->bearer) { OPENSSL_cleanse(p->bearer, strlen(p->bearer)); free(p->bearer); }
    free(p->session_id); free(p->broker_id); free(p->stun);
    for (int i = 0; i < 2; ++i) if (p->wake[i] >= 0) close(p->wake[i]);
    pthread_cond_destroy(&p->cv); pthread_mutex_destroy(&p->mu); pthread_mutex_destroy(&p->qmu);
    OPENSSL_cleanse(p, sizeof(*p)); free(p);
}
int ob_remote_connect(ob_api_client *api, const char *broker_id, const char *password,
                      const ob_remote_connect_options *options, ob_remote_peer **out, ob_remote_error *error)
{
    if (out) *out = NULL;
    if (!api || !out || !ob_valid_id(broker_id) || !password || !*password || strlen(password) > 1024
        || (options && (options->relay_mode < 0 || options->relay_mode > OB_REMOTE_RELAY_FORCE
            || options->max_maps > 128 || options->max_flows > 512 || options->timeout_ms > 300000
            || (options->stun_server && !ob_valid_host(options->stun_server, 0)))))
        return ob_error(error, OB_REMOTE_EINVAL, 0, NULL);
    ob_remote_peer *p = ob_peer_alloc(api, broker_id, password, options);
    if (!p) return ob_error(error, OB_REMOTE_ENOMEM, 0, NULL);
    cJSON *body = cJSON_CreateObject(), *response = NULL;
    cJSON_AddStringToObject(body, "broker_id", broker_id);
    cJSON_AddStringToObject(body, "relay_mode", p->relay == OB_REMOTE_RELAY_FORCE ? "force"
        : p->relay == OB_REMOTE_RELAY_NEVER ? "never" : "auto");
    int rc = ob_control_request(api, "POST", "/v1/sessions", NULL, body, &response, error); cJSON_Delete(body);
    const char *sid = str(response, "session_id"), *token = str(response, "session_token");
    if (!rc && (!ob_valid_id(sid) || !token)) rc = ob_error(error, OB_REMOTE_EPROTOCOL, 0, "Invalid control session response");
    if (!rc) { p->session_id = strdup(sid); p->bearer = strdup(token);
        if (!p->session_id || !p->bearer) rc = ob_error(error, OB_REMOTE_ENOMEM, 0, NULL); }
    cJSON_Delete(response);
    if (!rc && pthread_create(&p->setup_thread, NULL, ob_setup_worker, p))
        rc = ob_error(error, OB_REMOTE_EIO, 0, "Cannot start peer setup worker");
    if (rc) { ob_peer_destroy(p); return rc; }
    p->setup_started = 1;
    pthread_mutex_lock(&p->mu);
    while (!p->ready && !p->result) {
        uint64_t now = ob_now_us();
        if (now >= p->deadline_us) { ob_peer_fail_locked(p, OB_REMOTE_ETIMEOUT, "Peer setup timed out"); break; }
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_nsec += 100000000;
        if (ts.tv_nsec >= 1000000000) { ++ts.tv_sec; ts.tv_nsec -= 1000000000; }
        pthread_cond_timedwait(&p->cv, &p->mu, &ts);
    }
    rc = p->result;
    if (rc && error) *error = p->error;
    pthread_mutex_unlock(&p->mu);
    if (rc) { ob_peer_destroy(p); return rc; }
    *out = p; return ob_error(error, 0, 0, NULL);
}
int ob_remote_peer_status(ob_remote_peer *p, ob_remote_error *error)
{
    if (!p) return ob_error(error, OB_REMOTE_EINVAL, 0, NULL);
    pthread_mutex_lock(&p->mu); int rc = p->result;
    if (error) *error = p->error;
    pthread_mutex_unlock(&p->mu); return rc;
}
void ob_remote_peer_close(ob_remote_peer *p)
{
    if (!p) return;
    ob_peer_fail(p, OB_REMOTE_ECLOSED, "Peer closed by caller");
    ob_peer_destroy(p);
}
static void server_free(ob_remote_server *s)
{
    for (size_t i = 0; i < s->rule_count; ++i) free((char *)s->rules[i].host);
    free(s->rules); free(s->broker_id); free(s->stun);
    if (s->device_token) { OPENSSL_cleanse(s->device_token, strlen(s->device_token)); free(s->device_token); }
    if (s->password) { OPENSSL_cleanse(s->password, strlen(s->password)); free(s->password); }
    while (s->seen_sessions) { struct ob_seen_session *seen = s->seen_sessions; s->seen_sessions = seen->next; free(seen); }
    pthread_cond_destroy(&s->cv); pthread_mutex_destroy(&s->mu); free(s);
}
int ob_remote_serve(ob_api_client *api, const char *name, const char *password,
                    const ob_remote_serve_options *o, ob_remote_server **out, ob_remote_error *error)
{
    if (out) *out = NULL;
    if (!api || !out || !name || !*name || strlen(name) > 128 || !password || !*password || strlen(password) > 1024
        || (o && (o->allow_rule_count > OB_MAX_ACL || (o->allow_rule_count && !o->allow_rules)
            || o->max_peers > 128 || o->max_maps_per_peer > 128 || o->max_flows_per_peer > 512
            || o->setup_timeout_ms > 300000 || (o->stun_server && !ob_valid_host(o->stun_server, 0)))))
        return ob_error(error, OB_REMOTE_EINVAL, 0, NULL);
    ob_remote_server *s = calloc(1, sizeof(*s));
    if (!s) return ob_error(error, OB_REMOTE_ENOMEM, 0, NULL);
    pthread_mutex_init(&s->mu, NULL); pthread_cond_init(&s->cv, NULL);
    s->api = api; s->password = strdup(password);
    if (o) s->options = *o;
    s->options.max_peers = def(s->options.max_peers, 16);
    s->options.setup_timeout_ms = def(s->options.setup_timeout_ms, 30000);
    if (o && o->stun_server) s->stun = strdup(o->stun_server);
    if (!s->password || (o && o->stun_server && !s->stun)) goto nomem;
    if (o && o->allow_rule_count) {
        s->rules = calloc(o->allow_rule_count, sizeof(*s->rules)); if (!s->rules) goto nomem;
        for (size_t i = 0; i < o->allow_rule_count; ++i) {
            const ob_remote_allow_rule *r = &o->allow_rules[i];
            if (!ob_valid_host(r->host, 1) || !r->port_first || r->port_first > r->port_last
                || (r->protocol != OB_REMOTE_TCP && r->protocol != OB_REMOTE_UDP)) {
                server_free(s); return ob_error(error, OB_REMOTE_EINVAL, 0, "Invalid target allow rule");
            }
            s->rules[i] = *r; s->rules[i].host = strdup(r->host); ++s->rule_count;
            if (!s->rules[i].host) goto nomem;
        }
    }
    cJSON *response = NULL;
    int rc = ob_control_request(api, "GET", "/v1/brokers", NULL, NULL, &response, error);
    if (rc) { server_free(s); cJSON_Delete(response); return rc; }
    cJSON *list = cJSON_GetObjectItemCaseSensitive(response, "brokers"), *item;
    cJSON_ArrayForEach(item, list) {
        const char *existing_name = str(item, "name"), *id = str(item, "id");
        if (existing_name && !strcmp(existing_name, name) && ob_valid_id(id)) {
            if (cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(item, "online"))) {
                cJSON_Delete(response); server_free(s);
                return ob_error(error, OB_REMOTE_EHTTP, 409, "Broker name is already online");
            }
            s->broker_id = strdup(id); break;
        }
    }
    cJSON_Delete(response); response = NULL;
    if (s->broker_id) {
        char path[128]; snprintf(path, sizeof(path), "/v1/brokers/%s/token", s->broker_id);
        rc = ob_control_request(api, "POST", path, NULL, NULL, &response, error);
    } else {
        cJSON *body = cJSON_CreateObject(); cJSON_AddStringToObject(body, "name", name);
        rc = ob_control_request(api, "POST", "/v1/brokers", NULL, body, &response, error); cJSON_Delete(body);
        const char *id = str(cJSON_GetObjectItemCaseSensitive(response, "broker"), "id");
        if (!rc && ob_valid_id(id)) s->broker_id = strdup(id);
    }
    const char *token = str(response, "device_token");
    if (!rc && token) s->device_token = strdup(token);
    cJSON_Delete(response);
    if (!rc && (!s->broker_id || !s->device_token)) rc = ob_error(error, OB_REMOTE_EPROTOCOL, 0, "Invalid broker registration response");
    s->start_deadline_us = ob_now_us() + 15000000;
    if (!rc && pthread_create(&s->worker, NULL, ob_server_worker, s))
        rc = ob_error(error, OB_REMOTE_EIO, 0, "Cannot start broker control worker");
    if (rc) { server_free(s); return rc; }
    s->worker_started = 1;
    /* Registration remains REST; first online authorization is a WS RPC on
     * the control owner, before exposing a usable broker to the caller. */
    pthread_mutex_lock(&s->mu);
    while (!s->initialized && !s->result) {
        if (ob_now_us() >= s->start_deadline_us) {
            s->result = ob_error(&s->error, OB_REMOTE_ETIMEOUT, 0, "Broker WebSocket startup timed out");
            atomic_store(&s->stop, 1); break;
        }
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_nsec += 100000000;
        if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
        pthread_cond_timedwait(&s->cv, &s->mu, &ts);
    }
    rc = s->result; if (rc && error) *error = s->error;
    pthread_mutex_unlock(&s->mu);
    if (rc) { ob_remote_server_close(s); return rc; }
    *out = s; return ob_error(error, 0, 0, NULL);
nomem:
    server_free(s); return ob_error(error, OB_REMOTE_ENOMEM, 0, NULL);
}
const char *ob_remote_server_id(const ob_remote_server *s) { return s ? s->broker_id : NULL; }
int ob_remote_server_status(ob_remote_server *s, ob_remote_error *error)
{
    if (!s) return ob_error(error, OB_REMOTE_EINVAL, 0, NULL);
    pthread_mutex_lock(&s->mu); int rc = s->result; if (error) *error = s->error;
    pthread_mutex_unlock(&s->mu); return rc;
}
void ob_remote_server_close(ob_remote_server *s)
{
    if (!s) return;
    atomic_store(&s->caller_close, 1); atomic_store(&s->stop, 1);
    if (s->worker_started) pthread_join(s->worker, NULL);
    ob_remote_peer *p = s->peers;
    while (p) { ob_remote_peer *next = p->next; ob_peer_destroy(p); p = next; }
    server_free(s);
}
