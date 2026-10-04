#include "internal.h"
#include "crypto.h"
#include "../ob_json.h"
#include "../ob_api_internal.h"
#include <openssl/rand.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

static const char *string(cJSON *o, const char *name)
{ cJSON *v = cJSON_GetObjectItemCaseSensitive(o, name); return cJSON_IsString(v) ? v->valuestring : NULL; }
cJSON *ob_peer_json_parse(const char *text)
{
    if (!text) return NULL;
    /* cJSON does not expose decoded string lengths. Reject actual U+0000
     * escapes before decoding, while preserving literal escaped backslashes
     * such as JSON "\\\\u0000". All other JSON syntax is checked by cJSON. */
    int in_string = 0;
    for (const char *c = text; *c; ++c) {
        if (!in_string) { if (*c == '"') in_string = 1; continue; }
        if (*c == '"') { in_string = 0; continue; }
        if (*c == '\\') {
            if (c[1] == 'u' && !strncmp(c+2, "0000", 4)) return NULL;
            if (!c[1]) return NULL;
            ++c;
        }
    }
    return ob_json_parse_complete(text, strlen(text));
}
int ob_control_request(ob_api_client *api, const char *method, const char *path,
                        const char *bearer, cJSON *body, cJSON **out, ob_remote_error *error)
{
    char *text = body ? cJSON_PrintUnformatted(body) : NULL, *response = NULL;
    ob_api_error ae = {0}; if (out) *out = NULL;
    if (body && !text) return ob_error(error, OB_REMOTE_ENOMEM, 0, NULL);
    int rc = ob_api_request(api, method, path, bearer, text, &response, &ae);
    free(text);
    if (rc) {
        ob_api_response_free(response);
        return ob_error(error, OB_REMOTE_EHTTP, (int)ae.http_status, ae.message);
    }
    cJSON *json = response && *response ? ob_peer_json_parse(response) : cJSON_CreateObject();
    ob_api_response_free(response);
    if (!json) return ob_error(error, OB_REMOTE_EPROTOCOL, 0, "Invalid control JSON response");
    if (out) *out = json; else cJSON_Delete(json);
    return 0;
}
static void pause_ms(unsigned ms)
{ struct timespec ts = {(time_t)(ms/1000), (long)(ms%1000)*1000000}; while (nanosleep(&ts, &ts) && errno == EINTR) {} }
static int alive(ob_remote_peer *p)
{
    if (atomic_load(&p->stop) || atomic_load(&p->attempt_stop)) return 0;
    pthread_mutex_lock(&p->mu);
    int ready = p->ready, expired = p->lease_deadline_set && ob_now_us() >= p->lease_deadline_us;
    pthread_mutex_unlock(&p->mu);
    if (expired) {
        if (p->control_managed) ob_peer_transport_fail(p, OB_REMOTE_ECLOSED, "Control authorization lease expired");
        else ob_peer_fail(p, OB_REMOTE_ECLOSED, "Control authorization lease expired");
        return 0;
    }
    if (!ready && ob_now_us() >= p->deadline_us) { ob_peer_transport_fail(p, OB_REMOTE_ETIMEOUT, "Peer setup timed out"); return 0; }
    return 1;
}
static uint64_t expiry(const char *text)
{
    int y, m, d, h, min, sec;
    if (!text || sscanf(text, "%d-%d-%dT%d:%d:%d", &y,&m,&d,&h,&min,&sec) != 6
        || y < 2020 || m < 1 || m > 12 || d < 1 || d > 31 || h > 23 || min > 59 || sec > 60) return 0;
    struct tm tm = {0}; tm.tm_year = y-1900; tm.tm_mon = m-1; tm.tm_mday = d;
    tm.tm_hour = h; tm.tm_min = min; tm.tm_sec = sec;
    time_t t = timegm(&tm); return t > 0 ? (uint64_t)t*1000000 : 0;
}
static int set_lease(ob_remote_peer *p, cJSON *response)
{
    uint64_t session = expiry(string(response, "expires_at"));
    uint64_t broker = expiry(string(response, "broker_lease_expires_at"));
    uint64_t realtime = ob_realtime_us(), now = ob_now_us();
    if (!session || !broker || session <= realtime || broker <= realtime) return -1;
    uint64_t remaining = (session < broker ? session : broker) - realtime;
    if (remaining > 120000000) remaining = 120000000;
    pthread_mutex_lock(&p->mu);
    /* Never resurrect a lease that expired while DNS/TLS/RPC was blocked. */
    if (p->lease_deadline_set && now >= p->lease_deadline_us) {
        pthread_mutex_unlock(&p->mu); return -1;
    }
    p->lease_deadline_us = now + remaining; p->lease_deadline_set = 1;
    pthread_mutex_unlock(&p->mu); return 0;
}
static int discover_stun(ob_remote_peer *p, cJSON *response)
{
    if (p->stun || p->ice) return 0;
    const char *address = string(response, "stun_address");
    if (!address || !*address) return 0;
    if (strlen(address) > 270) return -1;
    const char *begin = address, *end, *port;
    if (*begin == '[') {
        ++begin; end = strchr(begin, ']');
        if (!end || end[1] != ':') return -1;
        port = end+2;
    } else {
        end = strrchr(begin, ':'); if (!end || memchr(begin, ':', (size_t)(end-begin))) return -1;
        port = end+1;
    }
    size_t n = (size_t)(end-begin); if (!n || n > OB_MAX_HOST) return -1;
    char host[OB_MAX_HOST+1]; memcpy(host, begin, n); host[n] = 0;
    if (!ob_valid_host(host, 0)) return -1;
    char *tail; unsigned long number = strtoul(port, &tail, 10);
    if (tail == port || *tail || number < 1 || number > 65535) return -1;
    p->stun = strdup(host); if (!p->stun) return -1;
    p->stun_port = (uint16_t)number; return 0;
}
#include "ws_control.inc"
static int send_signal(ob_remote_peer *p, const char *type, const char *payload, int authenticated)
{
    uint64_t seq = p->tx_sequence+1;
    cJSON *envelope = cJSON_CreateObject();
    if (!envelope) return OB_REMOTE_ENOMEM;
    cJSON_AddNumberToObject(envelope, "v", 1); cJSON_AddStringToObject(envelope, "sid", p->session_id);
    cJSON_AddNumberToObject(envelope, "seq", (double)seq); cJSON_AddStringToObject(envelope, "t", type);
    cJSON_AddStringToObject(envelope, "payload", payload);
    if (authenticated) {
        unsigned char mac[32]; char encoded[65];
        if (ob_signal_mac(p->tx_key, seq, type, payload, mac)) { cJSON_Delete(envelope); return OB_REMOTE_EAUTH; }
        ob_hex(mac, 32, encoded); cJSON_AddStringToObject(envelope, "mac", encoded);
    }
    char *data = cJSON_PrintUnformatted(envelope); cJSON_Delete(envelope);
    if (!data) return OB_REMOTE_ENOMEM;
    cJSON *body = cJSON_CreateObject(); cJSON_AddNumberToObject(body, "sequence", (double)seq);
    cJSON_AddStringToObject(body, "data", data); free(data);
    ob_remote_error e = {0};
    /* Construct once: lost result retries identical sequence/data. */
    int rc = peer_rpc(p, "send", body, NULL, &e); cJSON_Delete(body);
    if (!rc) p->tx_sequence = seq;
    else { pthread_mutex_lock(&p->mu); if (!p->result) p->error = e; pthread_mutex_unlock(&p->mu); }
    if (rc && authenticated && (e.http_status == 401 || e.http_status == 403
        || e.http_status == 404 || e.http_status == 410)) return OB_REMOTE_EAUTH;
    return rc;
}
int ob_decode_signal(ob_remote_peer *p, const char *data, double rest_sequence,
                      const char *type, int authenticated, char **out)
{
    if (!p || !out || !type) return OB_REMOTE_EINVAL;
    *out = NULL;
    if (p->rx_sequence >= UINT64_C(9007199254740991)) return OB_REMOTE_EPROTOCOL;
    uint64_t want = p->rx_sequence+1;
    cJSON *envelope = data && strlen(data) <= 16384 ? ob_peer_json_parse(data) : NULL;
    const char *sid = string(envelope, "sid"), *kind = string(envelope, "t"), *payload = string(envelope, "payload");
    cJSON *version = cJSON_GetObjectItemCaseSensitive(envelope, "v");
    cJSON *seq = cJSON_GetObjectItemCaseSensitive(envelope, "seq");
    unsigned seen = 0; int fields_ok = cJSON_IsObject(envelope); cJSON *field;
    static const char *names[] = {"v", "sid", "seq", "t", "payload", "mac"};
    cJSON_ArrayForEach(field, envelope) {
        unsigned i;
        for (i = 0; i < 6; ++i) if (field->string && !strcmp(field->string, names[i])) break;
        if (i == 6 || (seen & (1u << i))) { fields_ok = 0; break; }
        seen |= 1u << i;
    }
    if (seen != (authenticated ? 63u : 31u)) fields_ok = 0;
    int valid = fields_ok && cJSON_IsNumber(version) && version->valuedouble == 1
        && ob_json_uint_field(data, strlen(data), "v", 1, 1, NULL)
        && ob_json_uint_field(data, strlen(data), "seq", want, want, NULL)
        && rest_sequence == (double)want && cJSON_IsNumber(seq) && seq->valuedouble == (double)want
        && sid && p->session_id && !strcmp(sid, p->session_id)
        && kind && !strcmp(kind, type) && payload;
    if (valid && authenticated) {
        unsigned char mac[32], claimed[32];
        valid = !ob_unhex(string(envelope, "mac"), claimed, 32)
            && !ob_signal_mac(p->rx_key, want, kind, payload, mac)
            && !CRYPTO_memcmp(mac, claimed, 32);
    }
    if (valid) *out = strdup(payload);
    cJSON_Delete(envelope);
    if (!valid) return authenticated ? OB_REMOTE_EAUTH : OB_REMOTE_EPROTOCOL;
    if (!*out) return OB_REMOTE_ENOMEM;
    p->rx_sequence = want; return 0;
}
static int receive_signal(ob_remote_peer *p, const char *type, int authenticated, char **out)
{
    *out = NULL;
    while (alive(p)) {
        int rc = peer_tick(p, 20); if (rc) return rc;
        cJSON *message = ob_ws_pop(p->ws, "message"); if (!message) continue;
        cJSON *sequence = cJSON_GetObjectItemCaseSensitive(message, "sequence");
        if (sequence->valuedouble <= (double)p->rx_sequence) { cJSON_Delete(message); continue; }
        rc = ob_decode_signal(p, string(message, "data"), sequence->valuedouble, type, authenticated, out);
        cJSON_Delete(message);
        if (!rc) {
            /* ACK the actual validated/consumed cursor, never raw receipt. */
            ob_api_error e = {0};
            if (ob_ws_connected(p->ws) && ob_ws_ack(p->ws, p->rx_sequence, &e)) {
                int fatal = peer_transport_error(p, &e); if (fatal) { free(*out); *out = NULL; return fatal; }
            }
        }
        return rc;
    }
    return OB_REMOTE_ECLOSED;
}
static int pake(ob_remote_peer *p)
{
    char client[256], server[256];
    snprintf(client, sizeof(client), "ob-peer-v1/client/%s/%s", p->broker_id, p->session_id);
    snprintf(server, sizeof(server), "ob-peer-v1/server/%s/%s", p->broker_id, p->session_id);
    SPAKE2_CTX *ctx = SPAKE2_CTX_new(p->is_server ? spake2_role_bob : spake2_role_alice,
        (const unsigned char *)(p->is_server ? server : client), strlen(p->is_server ? server : client),
        (const unsigned char *)(p->is_server ? client : server), strlen(p->is_server ? client : server));
    if (!ctx) return OB_REMOTE_EAUTH;
    unsigned char mine[SPAKE2_MAX_MSG_SIZE], theirs[SPAKE2_MAX_MSG_SIZE]; size_t n = 0;
    char encoded[SPAKE2_MAX_MSG_SIZE*2+1], *remote = NULL; int rc = OB_REMOTE_EAUTH;
    if (!SPAKE2_generate_msg(ctx, mine, &n, sizeof(mine), (const unsigned char *)p->password,
                            strlen(p->password)) || n != SPAKE2_MAX_MSG_SIZE) goto end;
    ob_hex(mine, n, encoded);
    rc = send_signal(p, "pake", encoded, 0); if (rc) goto end;
    rc = receive_signal(p, "pake", 0, &remote); if (rc) goto end;
    rc = OB_REMOTE_EAUTH;
    if (ob_unhex(remote, theirs, sizeof(theirs)) || !SPAKE2_process_msg(ctx, p->shared,
            &p->shared_len, sizeof(p->shared), theirs, sizeof(theirs))
        || p->shared_len != SPAKE2_MAX_KEY_SIZE) goto end;
    if (ob_derive_keys(p, p->is_server ? theirs : mine, p->is_server ? mine : theirs)) goto end;
    /* Two-way explicit key confirmation. Keys bind suite, identities, PAKE
     * transcript; MAC includes sequence and distinct directional context. */
    rc = send_signal(p, "confirm", "ob-peer-v1 key confirmation", 1); if (rc) goto end;
    free(remote); remote = NULL;
    rc = receive_signal(p, "confirm", 1, &remote);
    if (!rc && strcmp(remote, "ob-peer-v1 key confirmation")) rc = OB_REMOTE_EAUTH;
end:
    free(remote); SPAKE2_CTX_free(ctx); OPENSSL_cleanse(mine, sizeof(mine));
    /* Fresh transport attempts repeat PAKE. The owned password is retained in
     * memory only and cleansed with all recovery keys on logical handle close. */
    if (!rc && ob_resume_key_derive(p)) rc = OB_REMOTE_EAUTH;
    return rc;
}
static int turn_config(cJSON *response, juice_turn_server_t *turn, char host[256])
{
    cJSON *urls = cJSON_GetObjectItemCaseSensitive(response, "urls");
    const char *url = cJSON_IsString(urls) ? urls->valuestring : NULL;
    if (!url) { cJSON *first = cJSON_GetArrayItem(urls, 0); if (cJSON_IsString(first)) url = first->valuestring; }
    const char *user = string(response, "username"), *password = string(response, "password");
    if (!url || strncmp(url, "turn:", 5) || !user || !password) return -1;
    const char *begin = url+5; if (!strncmp(begin, "//", 2)) begin += 2;
    const char *end = strchr(begin, '?'); if (!end) end = begin+strlen(begin);
    if (*end && strcmp(end, "?transport=udp")) return -1;
    const char *port = NULL;
    if (*begin == '[') { ++begin; const char *bracket = memchr(begin, ']', (size_t)(end-begin));
        if (!bracket) return -1; if (bracket+1 < end && bracket[1] == ':') port = bracket+2; end = bracket;
    } else { const char *colon = memchr(begin, ':', (size_t)(end-begin)); if (colon) { port = colon+1; end = colon; } }
    size_t len = (size_t)(end-begin); if (!len || len > 253) return -1;
    memcpy(host, begin, len); host[len] = 0; if (!ob_valid_host(host, 0)) return -1;
    unsigned long number = 3478;
    if (port) { char *tail; number = strtoul(port, &tail, 10); if (tail == port || (*tail && *tail != '?') || number < 1 || number > 65535) return -1; }
    memset(turn, 0, sizeof(*turn)); turn->host = host; turn->port = (uint16_t)number;
    turn->username = user; turn->password = password; return 0;
}
static int ice_space(unsigned char c)
{ return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
static int ice_token(const char *s, size_t n, const char *want)
{
    if (n != strlen(want)) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 'A' && c <= 'Z') c += 'a'-'A';
        if (c != (unsigned char)want[i]) return 0;
    }
    return 1;
}
int ob_relay_candidate(const char *line, size_t len)
{
    if (!line || len < 12 || len >= JUICE_MAX_CANDIDATE_SDP_STRING_LEN
        || memcmp(line, "a=candidate:", 12)) return 0;
    const char *tokens[8]; size_t sizes[8], at = 12;
    for (unsigned i = 0; i < 8; ++i) {
        while (at < len && ice_space((unsigned char)line[at])) ++at;
        size_t begin = at;
        while (at < len && !ice_space((unsigned char)line[at])) ++at;
        if (begin == at) return 0;
        tokens[i] = line+begin; sizes[i] = at-begin;
    }
    /* RFC 5245 section 15.1: component, transport, and candidate type are
     * fixed fields. A relay-looking extension or 'relayed' is not evidence. */
    return sizes[0] <= 32 && sizes[1] == 1 && tokens[1][0] == '1'
        && ice_token(tokens[2], sizes[2], "udp")
        && sizes[6] == 3 && !memcmp(tokens[6], "typ", 3)
        && ice_token(tokens[7], sizes[7], "relay");
}
int ob_filter_relay_description(const char *source, char out[JUICE_MAX_SDP_STRING_LEN])
{
    if (!source || !out) return -1;
    size_t used = 0; int relays = 0;
    for (const char *line = source; *line;) {
        const char *end = strchr(line, '\n'); size_t n = end ? (size_t)(end-line)+1 : strlen(line);
        /* Upstream removes CR anywhere before parsing. Reject embedded CR
         * so 'a=\\rcandidate:' cannot evade this filter then become a candidate. */
        for (size_t i = 0; i < n; ++i)
            if (line[i] == '\r' && (i+1 >= n || line[i+1] != '\n')) return -1;
        int candidate = n >= 12 && !memcmp(line, "a=candidate:", 12);
        int relay = candidate && ob_relay_candidate(line, n);
        if (!candidate || relay) {
            if (used+n >= JUICE_MAX_SDP_STRING_LEN) return -1;
            memcpy(out+used, line, n); used += n; if (relay) ++relays;
        }
        line += n;
    }
    out[used] = 0; return relays ? 0 : -1;
}
static int establish_ice(ob_remote_peer *p)
{
    if (p->is_server) {
        cJSON *body = cJSON_CreateObject(); cJSON_AddBoolToObject(body, "peer_authenticated", 1);
        cJSON_AddBoolToObject(body, "relay", p->relay != OB_REMOTE_RELAY_NEVER);
        ob_remote_error e; int rc = peer_rpc(p, "approve", body, NULL, &e);
        if (rc && p->relay == OB_REMOTE_RELAY_AUTO && (e.http_status == 403 || e.http_status == 503)) {
            cJSON_ReplaceItemInObjectCaseSensitive(body, "relay", cJSON_CreateBool(0));
            rc = peer_rpc(p, "approve", body, NULL, &e);
        }
        cJSON_Delete(body); if (rc) return rc;
        if (ob_make_certificate(p)) return OB_REMOTE_EAUTH;
    }
    int rc = capabilities(p, !p->is_server); if (rc) return rc;
    juice_config_t config = {0}; ob_ice_callbacks(&config, p);
    config.stun_server_host = p->stun; config.stun_server_port = p->stun_port;
    cJSON *turn_response = NULL; juice_turn_server_t turn; char turn_host[256];
    if (p->relay != OB_REMOTE_RELAY_NEVER) {
        ob_remote_error e;
        rc = peer_rpc(p, "turn", NULL, &turn_response, &e);
        if (!rc && !turn_config(turn_response, &turn, turn_host)) {
            config.turn_servers = &turn; config.turn_servers_count = 1;
        } else if (rc && !e.http_status) { cJSON_Delete(turn_response); return rc; }
        else if (p->relay == OB_REMOTE_RELAY_FORCE) { cJSON_Delete(turn_response); return OB_REMOTE_EICE; }
    }
    /* This pinned libjuice extension is required, never an optional fallback. */
    config.relay_only = p->relay == OB_REMOTE_RELAY_FORCE;
    p->ice = juice_create(&config); cJSON_Delete(turn_response);
    if (!p->ice || juice_gather_candidates(p->ice)) return OB_REMOTE_EICE;
    while (alive(p) && !atomic_load(&p->gathered) && !atomic_load(&p->ice_failed)) { rc = peer_tick(p, 10); if (rc) return rc; }
    if (!atomic_load(&p->gathered) || atomic_load(&p->ice_failed)) return OB_REMOTE_EICE;
    char local[JUICE_MAX_SDP_STRING_LEN], filtered[JUICE_MAX_SDP_STRING_LEN];
    if (juice_get_local_description(p->ice, local, sizeof(local))) return OB_REMOTE_EICE;
    const char *sdp = local;
    if (p->relay == OB_REMOTE_RELAY_FORCE) { if (ob_filter_relay_description(local, filtered)) return OB_REMOTE_EICE; sdp = filtered; }
    cJSON *body = cJSON_CreateObject(); cJSON_AddStringToObject(body, "sdp", sdp);
    cJSON_AddNumberToObject(body, "mapping_version", 2);
    if (p->resume_key_set) {
        unsigned char proof[32]; char encoded[65];
        if (ob_resume_proof(p, p->is_server, proof)) { cJSON_Delete(body); return OB_REMOTE_EAUTH; }
        ob_hex(proof, sizeof(proof), encoded);
        cJSON_AddStringToObject(body, "resume_proof", encoded);
        OPENSSL_cleanse(proof, sizeof(proof));
    }
    if (p->is_server) { char fp[65]; ob_hex(p->fingerprint, 32, fp); cJSON_AddStringToObject(body, "cert_sha256", fp); }
    char *payload = cJSON_PrintUnformatted(body); cJSON_Delete(body);
    if (!payload) return OB_REMOTE_ENOMEM;
    rc = send_signal(p, "ice", payload, 1); free(payload); if (rc) return rc;
    char *remote = NULL; rc = receive_signal(p, "ice", 1, &remote); if (rc) return rc;
    cJSON *remote_json = ob_peer_json_parse(remote); free(remote);
    const char *remote_sdp = string(remote_json, "sdp");
    cJSON *version = cJSON_GetObjectItemCaseSensitive(remote_json, "mapping_version");
    if (version && (!cJSON_IsNumber(version) ||
        (version->valuedouble != 1 && version->valuedouble != 2))) rc = OB_REMOTE_EPROTOCOL;
    p->wire_version = version && cJSON_IsNumber(version) && version->valuedouble == 2 ? 2 : 1;
    p->resume_context_available = 0;
    if (!rc && p->wire_version == 2 && p->resume_key_set) {
        unsigned char expected[32], received[32];
        if (!ob_resume_proof(p, !p->is_server, expected) &&
            !ob_unhex(string(remote_json, "resume_proof"), received, sizeof(received)) &&
            CRYPTO_memcmp(expected, received, sizeof(expected)) == 0)
            p->resume_context_available = p->ever_ready;
        OPENSSL_cleanse(expected, sizeof(expected)); OPENSSL_cleanse(received, sizeof(received));
    }
    if (!remote_sdp || strlen(remote_sdp) >= JUICE_MAX_SDP_STRING_LEN) rc = OB_REMOTE_EPROTOCOL;
    if (!rc && !p->is_server && ob_unhex(string(remote_json, "cert_sha256"), p->fingerprint, 32)) rc = OB_REMOTE_EAUTH;
    if (!rc && p->relay == OB_REMOTE_RELAY_FORCE) {
        if (ob_filter_relay_description(remote_sdp, filtered)) rc = OB_REMOTE_EICE;
        else remote_sdp = filtered;
    }
    /* Verify the MAC first, then apply local policy to authenticated SDP;
     * no unauthenticated or FORCE non-relay candidate is installed. */
    if (!rc && juice_set_remote_description(p->ice, remote_sdp)) rc = OB_REMOTE_EICE;
    cJSON_Delete(remote_json); if (rc) return rc;
    juice_set_remote_gathering_done(p->ice);
    while (alive(p) && !atomic_load(&p->ice_ready) && !atomic_load(&p->ice_failed)) { rc = peer_tick(p, 10); if (rc) return rc; }
    if (!atomic_load(&p->ice_ready) || atomic_load(&p->ice_failed)) return OB_REMOTE_EICE;
    pthread_mutex_lock(&p->mu);
    if (!atomic_load(&p->stop) && !atomic_load(&p->attempt_stop)) {
        p->transport_detached = 0; p->transport_available = 1;
        pthread_cond_broadcast(&p->cv); ob_wake(p);
    }
    pthread_mutex_unlock(&p->mu);
    /* The I/O owner was started with the logical handle and stays alive while
     * transport attempts are suspended. */
    return 0;
}
/* Close RPC is bounded and best-effort. REST is a single cleanup attempt only
 * if no usable WS exists; it is never a polling/recovery transport. */
static int close_rpc(ob_ws *ws, const char *op)
{
    ob_api_error e = {0}; uint64_t id = 0, until = ob_now_us()+300000;
    if (!ob_ws_connected(ws) || ob_ws_begin(ws, op, NULL, &id, 100, &e)) return -1;
    while (ob_now_us() < until) {
        int status; cJSON *body = NULL;
        if (ob_ws_result(ws, id, &status, &body)) { cJSON_Delete(body); return status >= 200 && status < 300 ? 0 : -1; }
        if (ob_ws_pump(ws, 10, &e)) return -1;
    }
    return -1;
}
static void cleanup_rest(ob_api_client *api, const char *method, const char *path, const char *bearer)
{
    ob_api_client bounded = *api; bounded.timeout_ms = 300;
    ob_remote_error e; (void)ob_control_request(&bounded, method, path, bearer, NULL, NULL, &e);
}
static void cancel_session(ob_remote_peer *p)
{
    if (!p->session_id || !p->bearer) return;
    p->control_cleanup = 1;
    int closed = ob_ws_connected(p->ws) && !close_rpc(p->ws, "delete");
    if (!closed) {
        /* A failed/timed-out close leaves no usable socket. One idempotent
         * cleanup attempt is allowed; this is not signaling recovery/polling. */
        ob_ws_disconnect(p->ws);
        char path[128]; snprintf(path, sizeof(path), "/v1/sessions/%s", p->session_id);
        cleanup_rest(p->api, "DELETE", path, p->bearer);
    }
}
void ob_control_close_connection(ob_remote_peer *p)
{
    if (!p->control_managed || !ob_valid_id(p->connection_id)) return;
    char path[128]; snprintf(path, sizeof(path), "/v1/connections/%s", p->connection_id);
    cleanup_rest(p->api, "DELETE", path, p->is_server ? p->bearer : NULL);
}
void *ob_setup_worker(void *data)
{
    ob_remote_peer *p = data;
    p->ws = ob_ws_create(p->api, 0, p->session_id, p->bearer, peer_cancel, p);
    int rc = p->ws ? capabilities(p, 0) : OB_REMOTE_ENOMEM;
    if (!rc) rc = pake(p);
    if (!rc && alive(p)) rc = establish_ice(p);
    if (rc && !atomic_load(&p->stop) && !atomic_load(&p->attempt_stop)) {
        /* Cancellation after a transient failure/replacement retires only this
         * attempt. Its ECLOSED result must not terminate the logical peer. */
        if (rc == OB_REMOTE_EICE || rc == OB_REMOTE_EQUIC || rc == OB_REMOTE_ETIMEOUT ||
            rc == OB_REMOTE_EIO || (rc == OB_REMOTE_EHTTP && p->control_managed))
            ob_peer_transport_fail(p, rc, ob_remote_strerror(rc));
        else ob_peer_fail(p, rc, ob_remote_strerror(rc));
    }
    while (alive(p)) {
        rc = peer_tick(p, 50); if (rc) break;
        /* After ICE, only already-consumed replay is legal. Future unexpected
         * envelopes cannot be silently acknowledged without semantic checks. */
        cJSON *message;
        while ((message = ob_ws_pop(p->ws, "message"))) {
            cJSON *seq = cJSON_GetObjectItemCaseSensitive(message, "sequence");
            int unexpected = seq->valuedouble > (double)p->rx_sequence;
            cJSON_Delete(message);
            if (unexpected) { ob_peer_fail(p, OB_REMOTE_EPROTOCOL, "Unexpected post-setup signal"); break; }
        }
    }
    if (atomic_load(&p->stop) && !p->control_managed) cancel_session(p);
    ob_ws_destroy(p->ws); p->ws = NULL; return NULL;
}
#include "ws_server.inc"
