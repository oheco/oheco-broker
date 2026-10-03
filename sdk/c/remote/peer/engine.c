#include "internal.h"
#include "crypto.h"
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/mem.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

static void ice_state(juice_agent_t *agent, juice_state_t state, void *data)
{
    (void)agent; ob_remote_peer *p = data;
    atomic_store(&p->ice_ready, state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED);
    if (state == JUICE_STATE_FAILED) atomic_store(&p->ice_failed, 1);
    ob_wake(p);
}
static void ice_gathered(juice_agent_t *agent, void *data)
{
    (void)agent; ob_remote_peer *p = data;
    atomic_store(&p->gathered, 1); ob_wake(p);
}
static void ice_receive(juice_agent_t *agent, const char *bytes, size_t size, void *data)
{
    (void)agent; ob_remote_peer *p = data;
    if (atomic_load(&p->stop) || size > OB_PACKET_SIZE || !size) return;
    struct ob_packet *packet = malloc(sizeof(*packet)+size);
    if (!packet) return;
    packet->next = NULL; packet->len = size; memcpy(packet->data, bytes, size);
    pthread_mutex_lock(&p->qmu);
    if (p->qcount >= OB_PACKET_LIMIT) { pthread_mutex_unlock(&p->qmu); free(packet); return; }
    if (p->qtail) p->qtail->next = packet; else p->qhead = packet;
    p->qtail = packet; ++p->qcount;
    pthread_mutex_unlock(&p->qmu); ob_wake(p);
}
void ob_ice_callbacks(juice_config_t *config, ob_remote_peer *p)
{
    config->concurrency_mode = JUICE_CONCURRENCY_MODE_THREAD;
    config->cb_state_changed = ice_state; config->cb_gathering_done = ice_gathered;
    config->cb_recv = ice_receive; config->user_ptr = p;
}
int ob_force_path(ob_remote_peer *p)
{
    if (p->relay != OB_REMOTE_RELAY_FORCE) return 1;
    char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN], remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
    /* The LOCAL selected relay was gathered from our own TURN allocation.
     * A remote relay label is only a peer assertion; remote prflx can still
     * be a genuine physical relay path when our local transport is relayed.
     * The retained libjuice policy also enforces this atomically at send. */
    return p->ice && !juice_get_selected_candidates(p->ice, local, sizeof(local), remote, sizeof(remote))
        && ob_relay_candidate(local, strlen(local));
}
static ssize_t write_socket(const unsigned char *buf, size_t size,
                            const struct sockaddr *addr, socklen_t len, void *data)
{
    (void)addr; (void)len; ob_remote_peer *p = data;
    if (!p || atomic_load(&p->stop) || !ob_force_path(p)) return XQC_SOCKET_ERROR;
    int rc = juice_send(p->ice, (const char *)buf, size);
    return rc == JUICE_ERR_SUCCESS ? (ssize_t)size
        : rc == JUICE_ERR_AGAIN ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
}
static void set_timer(xqc_usec_t after, void *data)
{
    ob_remote_peer *p = data; p->next_timer_us = ob_now_us() + after;
}
static void quiet_log(xqc_log_level_t level, const void *buf, size_t size, void *data)
{ (void)level; (void)buf; (void)size; (void)data; }
static void save_token(const unsigned char *buf, uint32_t n, void *data)
{ (void)buf; (void)n; (void)data; }
static void save_string(const char *buf, size_t n, void *data)
{ (void)buf; (void)n; (void)data; }
static void update_cid(xqc_connection_t *conn, const xqc_cid_t *old,
                       const xqc_cid_t *next, void *data)
{ (void)conn; (void)old; ob_remote_peer *p = data; p->cid = *next; }
static int verify_cert(const unsigned char *certs[], const size_t lens[], size_t n, void *data)
{
    ob_remote_peer *p = data;
    return n && ob_certificate_matches(p, certs[0], lens[0]) ? 0 : -1;
}
static int accept_conn(xqc_engine_t *engine, xqc_connection_t *conn,
                       const xqc_cid_t *cid, void *data)
{
    (void)engine; ob_remote_peer *p = data;
    if (p->conn || atomic_load(&p->stop)) return -1;
    p->conn = conn; p->cid = *cid; xqc_conn_set_transport_user_data(conn, p);
    xqc_datagram_set_user_data(conn, p); return 0;
}
static void refuse_conn(xqc_engine_t *engine, xqc_connection_t *conn,
                        const xqc_cid_t *cid, void *data)
{ (void)engine; (void)cid; ob_remote_peer *p = data; if (p->conn == conn) p->conn = NULL; }
static int conn_create(xqc_connection_t *conn, const xqc_cid_t *cid, void *data, void *proto)
{
    (void)proto; ob_remote_peer *p = data; p->conn = conn; p->cid = *cid;
    xqc_conn_set_alp_user_data(conn, p); xqc_datagram_set_user_data(conn, p); return 0;
}
static int conn_close(xqc_connection_t *conn, const xqc_cid_t *cid, void *data, void *proto)
{
    (void)conn; (void)cid; (void)proto; ob_remote_peer *p = data;
    p->conn = NULL; ob_peer_fail_locked(p, OB_REMOTE_ECLOSED, "QUIC connection closed"); return 0;
}
static xqc_int_t conn_closing(xqc_connection_t *conn, const xqc_cid_t *cid,
                              xqc_int_t code, void *data)
{
    (void)conn; (void)cid; (void)code;
    ob_peer_fail_locked(data, OB_REMOTE_ECLOSED, "QUIC connection closing"); return 0;
}
void ob_peer_handshake(xqc_connection_t *conn, void *data, void *proto)
{
    (void)proto; ob_remote_peer *p = data;
    if (atomic_load(&p->stop)) return;
    /* Both roles gate the actual authenticated peer transport parameters.
     * Never emit the exporter proof or enable any application traffic first. */
    if (!ob_connection_encrypted(conn)) {
        ob_peer_fail_locked(p, OB_REMOTE_EAUTH, "QUIC peer application encryption policy failed");
        return;
    }
    if (!p->is_server) {
        SSL *ssl = xqc_conn_get_ssl(conn); X509 *cert = ssl ? SSL_get_peer_certificate(ssl) : NULL;
        unsigned char hash[32]; unsigned int len = 0;
        int ok = cert && X509_digest(cert, EVP_sha256(), hash, &len) && len == 32
            && !CRYPTO_memcmp(hash, p->fingerprint, 32);
        X509_free(cert);
        if (!ok) { ob_peer_fail_locked(p, OB_REMOTE_EAUTH, "QUIC certificate pin mismatch"); return; }
    }
    p->tls_ready = 1; ob_mapping_handshake(p);
}
static int engine_init(ob_remote_peer *p)
{
    xqc_config_t config;
    xqc_engine_type_t type = p->is_server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;
    if (xqc_engine_get_default_config(&config, type)) return -1;
    config.conns_hash_bucket_size = 16; config.streams_hash_bucket_size = 128;
    config.conns_active_pq_capacity = 16; config.conns_wakeup_pq_capacity = 16;
    config.cfg_log_level = XQC_LOG_ERROR;
    xqc_engine_ssl_config_t tls = {0};
    if (p->is_server) { tls.cert_file = p->cert_path; tls.private_key_file = p->key_path; }
    xqc_engine_callback_t cbs = {0}; cbs.set_event_timer = set_timer;
    cbs.monotonic_ts = ob_now_us; cbs.realtime_ts = ob_realtime_us;
    cbs.log_callbacks.xqc_log_write_err = quiet_log;
    cbs.log_callbacks.xqc_log_write_stat = quiet_log;
    xqc_transport_callbacks_t transport = {0};
    transport.write_socket = write_socket; transport.conn_send_packet_before_accept = write_socket;
    transport.server_accept = accept_conn; transport.server_refuse = refuse_conn;
    transport.conn_update_cid_notify = update_cid; transport.save_token = save_token;
    transport.save_session_cb = save_string; transport.save_tp_cb = save_string;
    transport.cert_verify_cb = verify_cert; transport.conn_closing = conn_closing;
    p->engine = xqc_engine_create(type, &config, &tls, &cbs, &transport, p);
    if (!p->engine) return -1;
    xqc_app_proto_callbacks_t app = {0}; ob_mapping_callbacks(&app);
    app.conn_cbs.conn_create_notify = conn_create; app.conn_cbs.conn_close_notify = conn_close;
    app.conn_cbs.conn_handshake_finished = ob_peer_handshake;
    /* xquic OWNS and frees alp_ctx during engine destruction. The peer is
     * caller-owned, so never hand it over as an ALPN allocation context. */
    if (xqc_engine_register_alpn(p->engine, OB_ALPN, strlen(OB_ALPN), &app, NULL)) return -1;
    xqc_conn_settings_t settings = {0}; settings.ping_on = 1;
    settings.proto_version = XQC_VERSION_V1; settings.init_idle_time_out = p->timeout_ms;
    settings.idle_time_out = 90000; settings.max_datagram_frame_size = 65535;
    settings.max_pkt_out_size = 1350; settings.max_streams_bidi = p->max_flows + 1;
    /* xquic interprets zero stream limits as defaults. Advertise at most one
     * unidirectional stream; the application rejects even that first stream. */
    settings.max_streams_uni = 1; settings.sndq_packets_used_max = 1024;
    settings.enable_stream_rate_limit = 1;
    settings.init_recv_window = OB_STREAM_BUFFER;
    /* Without receive-rate control xquic sums all advertised stream windows
     * into a potentially enormous connection window. This sets a bounded
     * ~1MiB initial aggregate window, growing only to xquic's 16MiB cap. */
    settings.recv_rate_bytes_per_sec = 16 * 1024 * 1024;
    if (p->is_server) xqc_server_set_conn_settings(p->engine, &settings);
    else {
        xqc_conn_ssl_config_t ssl = {0};
        ssl.cert_verify_flag = XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
        const xqc_cid_t *cid = xqc_connect(p->engine, &settings, NULL, 0,
            "ob-peer-ephemeral", 0, &ssl, (struct sockaddr *)&p->logical_peer,
            sizeof(p->logical_peer), OB_ALPN, p);
        if (!cid) return -1;
        p->cid = *cid;
        p->conn = xqc_engine_get_conn_by_scid(p->engine, &p->cid);
        if (!p->conn) return -1;
        xqc_datagram_set_user_data(p->conn, p);
    }
    return 0;
}
void *ob_engine_worker(void *data)
{
    ob_remote_peer *p = data;
    pthread_mutex_lock(&p->mu);
    if (engine_init(p)) ob_peer_fail_locked(p, OB_REMOTE_EQUIC, "QUIC engine initialization failed");
    pthread_mutex_unlock(&p->mu);
    while (!atomic_load(&p->stop)) {
        /* Honor xquic's scheduled wakeup with a 1ms timer quantum, while
         * polling application sockets at least once every 10ms. */
        int wait_ms = 10; uint64_t before_poll = ob_now_us();
        if (p->next_timer_us) {
            uint64_t delay = p->next_timer_us > before_poll
                ? (p->next_timer_us-before_poll+999)/1000 : 1;
            if (!delay) delay = 1;
            if (delay < 10) wait_ms = (int)delay;
        }
        struct pollfd fd = {p->wake[0], POLLIN, 0}; poll(&fd, 1, wait_ms);
        unsigned char bytes[64]; while (read(p->wake[0], bytes, sizeof(bytes)) > 0) {}
        pthread_mutex_lock(&p->mu);
        uint64_t now = ob_now_us();
        if (p->is_server && p->server && atomic_load(&p->server->stop))
            ob_peer_fail_locked(p, OB_REMOTE_ECLOSED, "Broker stopped or revoked");
        if (atomic_load(&p->ice_failed) || !atomic_load(&p->ice_ready) || !ob_force_path(p))
            ob_peer_fail_locked(p, OB_REMOTE_EICE, "ICE association lost or relay policy failed");
        if (!p->ready && now >= p->deadline_us)
            ob_peer_fail_locked(p, OB_REMOTE_ETIMEOUT, "Peer setup timed out");
        if (p->lease_deadline_set && now >= p->lease_deadline_us)
            ob_peer_fail_locked(p, OB_REMOTE_ECLOSED, "Control authorization lease expired");
        pthread_mutex_lock(&p->qmu);
        struct ob_packet *packet = p->qhead; p->qhead = p->qtail = NULL; p->qcount = 0;
        pthread_mutex_unlock(&p->qmu);
        while (packet) {
            struct ob_packet *next = packet->next;
            if (!atomic_load(&p->stop)) xqc_engine_packet_process(p->engine, packet->data,
                packet->len, (struct sockaddr *)&p->logical_local, sizeof(p->logical_local),
                (struct sockaddr *)&p->logical_peer, sizeof(p->logical_peer), now, p);
            free(packet); packet = next;
        }
        if (!atomic_load(&p->stop)) {
            xqc_engine_finish_recv(p->engine); ob_mapping_tick(p);
            /* Application writes outside receive callbacks can activate a
             * connection without changing the old wakeup timer. Drain that
             * work now, while also servicing due transport timers. */
            xqc_engine_main_logic(p->engine);
            if (p->conn && !atomic_load(&p->stop)) xqc_conn_continue_send(p->engine, &p->cid);
        }
        pthread_mutex_unlock(&p->mu);
    }
    pthread_mutex_lock(&p->mu);
    /* stop is already set. The stop branch aborts every flow and closes its
     * socket immediately, before any control or DNS worker can delay joins. */
    ob_mapping_tick(p);
    if (p->conn) xqc_conn_close_with_error(p->conn, 1);
    if (p->engine) { xqc_engine_destroy(p->engine); p->engine = NULL; p->conn = NULL; }
    /* Listener handles remain valid after asynchronous revocation until the
     * caller closes them or destroys the peer. Stop forwarding immediately. */
    for (ob_remote_map *map = p->maps; map; map = map->next) {
        if (map->fd >= 0) { close(map->fd); map->fd = -1; }
        map->closed = 1;
    }
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu); return NULL;
}
