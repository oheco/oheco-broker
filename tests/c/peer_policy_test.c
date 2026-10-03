/* Included by remote_peer_test.c: SDK-owned policy tests, no upstream probe.
 * Network fixture uses pristine xquic client/server plus BoringSSL's real QUIC
 * transport parameter extension and getter. No mocked SSL/cipher inspection. */
#include <openssl/ssl.h>
#include <fcntl.h>

/* Test-only pinned xquic 1.9.7 encoder entry point. Production needs no private
 * header/symbol: it only parses BoringSSL's public raw peer TP getter. */
extern xqc_int_t xqc_conn_encode_local_tp(xqc_connection_t *, uint8_t *, size_t, size_t *);
struct policy_endpoint {
    ob_remote_peer policy;
    xqc_engine_t *engine;
    xqc_connection_t *conn;
    xqc_cid_t cid;
    struct sockaddr_in address, other;
    int fd, server, enforce, inject, handshakes, saw_rejection, cipher_present;
    unsigned sent, received;
    int closing_code;
    char cipher_name[64], last_error[512];
};
static void policy_timer(xqc_usec_t after, void *data) { (void)after; (void)data; }
static void policy_log(xqc_log_level_t level, const void *buf, size_t n, void *data)
{
    (void)level; struct policy_endpoint *e = data;
    if (!e) return;
    if (n >= sizeof(e->last_error)) n = sizeof(e->last_error)-1;
    memcpy(e->last_error, buf, n); e->last_error[n] = 0;
}
static ssize_t policy_write(const unsigned char *bytes, size_t n,
                            const struct sockaddr *addr, socklen_t len, void *data)
{
    (void)addr; (void)len; struct policy_endpoint *e = data;
    ssize_t result = sendto(e->fd, bytes, n, 0, (struct sockaddr *)&e->other, sizeof(e->other));
    if (result > 0) ++e->sent; return result;
}
static int policy_verify(const unsigned char *certs[], const size_t lens[], size_t n, void *data)
{ (void)certs; (void)lens; (void)n; (void)data; return 0; }
static int policy_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                         const xqc_cid_t *cid, void *data)
{
    (void)engine; struct policy_endpoint *e = data;
    e->conn = conn; e->policy.conn = conn; e->cid = *cid;
    xqc_conn_set_transport_user_data(conn, e);
    if (e->inject) {
        unsigned char tp[2048]; size_t n = 0;
        if (xqc_conn_encode_local_tp(conn, tp, sizeof(tp)-4, &n)) return -1;
        /* Append private ID 0x1000, one-byte varint length and value, to the
         * upstream-generated COMPLETE parameters (including CID bindings). */
        tp[n++] = 0x50; tp[n++] = 0; tp[n++] = 1; tp[n++] = (unsigned char)e->inject;
        if (!SSL_set_quic_transport_params(xqc_conn_get_ssl(conn), tp, n)) return -1;
    }
    return 0;
}
static int policy_create(xqc_connection_t *conn, const xqc_cid_t *cid, void *data, void *proto)
{
    (void)cid; (void)proto; struct policy_endpoint *e = data;
    e->conn = conn; e->policy.conn = conn; return 0;
}
static int policy_close(xqc_connection_t *conn, const xqc_cid_t *cid, void *data, void *proto)
{ (void)conn; (void)cid; (void)proto; ((struct policy_endpoint *)data)->conn = NULL; return 0; }
static xqc_int_t policy_closing(xqc_connection_t *conn, const xqc_cid_t *cid, xqc_int_t code, void *data)
{ (void)conn; (void)cid; ((struct policy_endpoint *)data)->closing_code = code; return 0; }
static void policy_handshake(xqc_connection_t *conn, void *data, void *proto)
{
    struct policy_endpoint *e = data; ++e->handshakes;
    const SSL_CIPHER *cipher = SSL_get_current_cipher(xqc_conn_get_ssl(conn));
    e->cipher_present = cipher != NULL;
    snprintf(e->cipher_name, sizeof(e->cipher_name), "%s", cipher ? SSL_CIPHER_get_name(cipher) : "none");
    int encrypted = ob_connection_encrypted(conn);
    if (e->enforce && !encrypted) {
        /* Run the EXACT SDK callback. It must stop before proof creation. */
        ob_peer_handshake(conn, &e->policy, proto);
        unsigned char proof[32];
        e->saw_rejection = e->policy.result == OB_REMOTE_EAUTH
            && !strcmp(e->policy.error.message, "QUIC peer application encryption policy failed")
            && atomic_load(&e->policy.stop) && !e->policy.tls_ready
            && !e->policy.proof_ready && !e->policy.ready
            && !e->policy.mapping_private && !e->policy.flows
            && ob_connection_proof(&e->policy, e->server, proof) != 0;
    } else if (e->enforce) {
        /* Positive network check stays raw: ordinary SDK proof/traffic is
         * exercised by the direct and actual Pion TURN integration tests. */
        e->policy.tls_ready = encrypted;
    }
}
static int policy_socket(struct policy_endpoint *e)
{
    e->fd = socket(AF_INET, SOCK_DGRAM, 0);
    e->address.sin_family = AF_INET; e->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t n = sizeof(e->address);
    if (e->fd < 0 || bind(e->fd, (struct sockaddr *)&e->address, sizeof(e->address))
        || getsockname(e->fd, (struct sockaddr *)&e->address, &n)
        || fcntl(e->fd, F_SETFL, O_NONBLOCK)) return -1;
    return 0;
}
static int policy_engine(struct policy_endpoint *e, const ob_remote_peer *cert)
{
    xqc_config_t config; xqc_engine_type_t type = e->server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;
    if (xqc_engine_get_default_config(&config, type)) return -1;
    config.cfg_log_level = XQC_LOG_ERROR;
    xqc_engine_ssl_config_t ssl = {0};
    if (e->server) { ssl.cert_file = (char *)cert->cert_path; ssl.private_key_file = (char *)cert->key_path; }
    xqc_engine_callback_t cb = {0}; cb.set_event_timer = policy_timer;
    cb.monotonic_ts = ob_now_us; cb.realtime_ts = ob_realtime_us;
    cb.log_callbacks.xqc_log_write_err = policy_log; cb.log_callbacks.xqc_log_write_stat = policy_log;
    xqc_transport_callbacks_t transport = {0}; transport.write_socket = policy_write;
    transport.conn_send_packet_before_accept = policy_write;
    transport.server_accept = policy_accept; transport.cert_verify_cb = policy_verify;
    transport.conn_closing = policy_closing;
    e->engine = xqc_engine_create(type, &config, &ssl, &cb, &transport, e);
    if (!e->engine) return -1;
    xqc_app_proto_callbacks_t app = {0};
    app.conn_cbs.conn_create_notify = policy_create; app.conn_cbs.conn_close_notify = policy_close;
    app.conn_cbs.conn_handshake_finished = policy_handshake;
    if (xqc_engine_register_alpn(e->engine, OB_ALPN, strlen(OB_ALPN), &app, NULL)) return -1;
    xqc_conn_settings_t settings = {0}; settings.proto_version = XQC_VERSION_V1;
    settings.init_idle_time_out = settings.idle_time_out = 5000;
    settings.max_streams_bidi = 2; settings.max_datagram_frame_size = 65535;
    if (e->server) xqc_server_set_conn_settings(e->engine, &settings);
    else {
        xqc_conn_ssl_config_t tls = {0};
        tls.cert_verify_flag = XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
        const xqc_cid_t *cid = xqc_connect(e->engine, &settings, NULL, 0,
            "ob-peer-ephemeral", e->inject, &tls, (struct sockaddr *)&e->other,
            sizeof(e->other), OB_ALPN, e);
        if (!cid) return -1;
        e->cid = *cid;
        e->conn = xqc_engine_get_conn_by_scid(e->engine, cid); e->policy.conn = e->conn;
    }
    return 0;
}
static int policy_network_case(int hostile_server, int no_crypto)
{
    struct policy_endpoint ends[2] = {{0}}; ob_remote_peer cert = {0}; int ok = 0;
    for (unsigned i = 0; i < 2; ++i) {
        ends[i].fd = -1; ends[i].server = i; ends[i].policy.is_server = i;
        ends[i].policy.wake[0] = ends[i].policy.wake[1] = -1;
        pthread_cond_init(&ends[i].policy.cv, NULL);
        ends[i].enforce = (int)i != hostile_server;
        ends[i].inject = (int)i == hostile_server ? no_crypto : 0;
    }
    if (ob_make_certificate(&cert) || policy_socket(&ends[0]) || policy_socket(&ends[1])) goto done;
    /* A hostile password-holder can provide the CORRECT certificate pin.
     * Seed it so missing TP validation cannot pass by unrelated pin failure. */
    for (unsigned i = 0; i < 2; ++i) {
        memcpy(ends[i].policy.fingerprint, cert.fingerprint, sizeof(cert.fingerprint));
        ends[i].policy.session_id = "00000000-0000-0000-0000-000000000001";
        ends[i].policy.shared_len = SPAKE2_MAX_KEY_SIZE;
        memset(ends[i].policy.shared, 7, sizeof(ends[i].policy.shared));
    }
    ends[0].other = ends[1].address; ends[1].other = ends[0].address;
    if (policy_engine(&ends[1], &cert) || policy_engine(&ends[0], &cert)) goto done;
    uint64_t until = ob_now_us() + 5000000;
    while (ob_now_us() < until) {
        for (unsigned i = 0; i < 2; ++i) {
            struct policy_endpoint *e = &ends[i]; unsigned char bytes[2048]; ssize_t n;
            while ((n = recv(e->fd, bytes, sizeof(bytes), 0)) > 0) {
                ++e->received;
                xqc_engine_packet_process(e->engine, bytes, (size_t)n,
                    (struct sockaddr *)&e->address, sizeof(e->address),
                    (struct sockaddr *)&e->other, sizeof(e->other), ob_now_us(), e);
            }
            xqc_engine_finish_recv(e->engine); xqc_engine_main_logic(e->engine);
            if (e->conn) xqc_conn_continue_send(e->engine, &e->cid);
        }
        struct policy_endpoint *enforced = &ends[!hostile_server];
        if (enforced->handshakes) {
            ok = enforced->cipher_present && (no_crypto ? enforced->saw_rejection : enforced->policy.tls_ready);
            break;
        }
        struct pollfd fds[2] = {{ends[0].fd, POLLIN, 0}, {ends[1].fd, POLLIN, 0}};
        poll(fds, 2, 2);
    }
    if (ok) printf("PASS network TP policy receiver=%s peer_no_crypto=%d TLS=%s before-proof=%s\n",
        hostile_server ? "client" : "server", no_crypto, ends[!hostile_server].cipher_name,
        no_crypto ? "rejected" : "normal");
    if (!ok) fprintf(stderr, "FAIL real xquic policy hostile_server=%d no_crypto=%d hsk=%d/%d results=%d/%d tx=%u/%u rx=%u/%u\n",
        hostile_server, no_crypto, ends[0].handshakes, ends[1].handshakes,
        ends[0].policy.result, ends[1].policy.result, ends[0].sent, ends[1].sent,
        ends[0].received, ends[1].received);
    if (!ok) fprintf(stderr, "TLS closing=%d/%d last error=%s / %s\n",
        ends[0].closing_code, ends[1].closing_code, ends[0].last_error, ends[1].last_error);
done:
    for (unsigned i = 0; i < 2; ++i) {
        ob_mapping_cleanup(&ends[i].policy);
        if (ends[i].engine) xqc_engine_destroy(ends[i].engine);
        ends[i].policy.conn = NULL;
        if (ends[i].fd >= 0) close(ends[i].fd);
        OPENSSL_cleanse(ends[i].policy.shared, sizeof(ends[i].policy.shared));
        pthread_cond_destroy(&ends[i].policy.cv);
    }
    ob_certificate_cleanup(&cert); return ok ? 0 : -1;
}
static int policy_relay_tests(void)
{
    const char *relay = "a=candidate:r 1 UDP 123 127.0.0.1 40000 typ relay\r\n";
    const char *host = "a=candidate:h 1 UDP 124 127.0.0.1 40001 typ host\r\n";
    const char *spoof = "a=candidate:h 1 UDP 124 127.0.0.1 40001 typ host note typ relay\r\n";
    const char *suffix = "a=candidate:r 1 UDP 123 127.0.0.1 40000 typ relayed\r\n";
    const char *tcp = "a=candidate:r 1 TCP 123 127.0.0.1 40000 typ relay tcptype passive\r\n";
    const char *mixed_case = "a=candidate:r 1 udp 123 127.0.0.1 40000 typ RELAY\n";
    char mixed[JUICE_MAX_SDP_STRING_LEN], filtered[JUICE_MAX_SDP_STRING_LEN];
    snprintf(mixed, sizeof(mixed), "a=ice-ufrag:test\r\na=ice-pwd:password\r\n%s%s%s%s", host, spoof, suffix, relay);
    if (!ob_relay_candidate(relay, strlen(relay)) || !ob_relay_candidate(mixed_case, strlen(mixed_case))
        || ob_relay_candidate(host, strlen(host)) || ob_relay_candidate(spoof, strlen(spoof))
        || ob_relay_candidate(suffix, strlen(suffix)) || ob_relay_candidate(tcp, strlen(tcp))
        || ob_filter_relay_description(mixed, filtered) || strstr(filtered, "typ host")
        || strstr(filtered, "typ relayed") || !strstr(filtered, relay)
        || !ob_filter_relay_description(host, filtered)
        || !ob_filter_relay_description("a=\rcandidate:h 1 UDP 124 127.0.0.1 40001 typ host\n", filtered)) return -1;
    printf("PASS SDK relay SDP fixed tokens, mixed candidates filtered, spoof/suffix/TCP/embedded-CR rejection\n");
    ob_remote_peer ends[2] = {{0}}; int ok = 0;
    for (unsigned i = 0; i < 2; ++i) {
        ends[i].wake[0] = ends[i].wake[1] = -1;
        pthread_mutex_init(&ends[i].qmu, NULL);
        juice_config_t config = {0}; ob_ice_callbacks(&config, &ends[i]);
        config.bind_address = "127.0.0.1";
        /* Deliberately use DEFAULT libjuice configuration (not relay_only):
         * SDK FORCE gate must reject the actual selected direct pair itself. */
        ends[i].ice = juice_create(&config);
    }
    if (!ends[0].ice || !ends[1].ice || juice_gather_candidates(ends[0].ice)
        || juice_gather_candidates(ends[1].ice)) goto done;
    uint64_t until = ob_now_us() + 3000000;
    while (ob_now_us() < until && (!atomic_load(&ends[0].gathered) || !atomic_load(&ends[1].gathered))) {
        struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
    }
    char descriptions[2][JUICE_MAX_SDP_STRING_LEN];
    if (!atomic_load(&ends[0].gathered) || !atomic_load(&ends[1].gathered)
        || juice_get_local_description(ends[0].ice, descriptions[0], sizeof(descriptions[0]))
        || juice_get_local_description(ends[1].ice, descriptions[1], sizeof(descriptions[1]))
        || juice_set_remote_description(ends[0].ice, descriptions[1])
        || juice_set_remote_description(ends[1].ice, descriptions[0])) goto done;
    juice_set_remote_gathering_done(ends[0].ice); juice_set_remote_gathering_done(ends[1].ice);
    until = ob_now_us() + 3000000;
    while (ob_now_us() < until && (!atomic_load(&ends[0].ice_ready) || !atomic_load(&ends[1].ice_ready))) {
        struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
    }
    if (!atomic_load(&ends[0].ice_ready) || !atomic_load(&ends[1].ice_ready)) goto done;
    for (unsigned i = 0; i < 2; ++i) {
        char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN], remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
        if (juice_get_selected_candidates(ends[i].ice, local, sizeof(local), remote, sizeof(remote))
            || ob_relay_candidate(local, strlen(local))) goto done;
        ends[i].relay = OB_REMOTE_RELAY_AUTO; if (!ob_force_path(&ends[i])) goto done;
        ends[i].relay = OB_REMOTE_RELAY_FORCE; if (ob_force_path(&ends[i])) goto done;
    }
    ok = 1;
done:
    for (unsigned i = 0; i < 2; ++i) {
        if (ends[i].ice) juice_destroy(ends[i].ice);
        struct ob_packet *packet = ends[i].qhead;
        while (packet) { struct ob_packet *next = packet->next; free(packet); packet = next; }
        pthread_mutex_destroy(&ends[i].qmu);
    }
    if (!ok) fprintf(stderr, "FAIL actual libjuice selected direct-pair policy gate\n");
    else printf("PASS actual libjuice selected direct pair accepted in AUTO, refused in FORCE\n");
    return ok ? 0 : -1;
}
static int ob_peer_policy_tests(void)
{
    /* RFC 9000 sections 16/18 allow non-minimal varints, unknown parameters;
     * only exact TLV boundaries may identify xquic's private parameter. */
    static const unsigned char absent[] = {1, 1, 30};
    static const unsigned char zero[] = {1, 1, 30, 0x50, 0, 1, 0};
    static const unsigned char one[] = {1, 1, 30, 0x50, 0, 1, 1};
    static const unsigned char two[] = {1, 1, 30, 0x50, 0, 1, 2};
    static const unsigned char large[] = {0x50, 0, 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const unsigned char hidden[] = {0x40, 0x3f, 4, 0x50, 0, 1, 1};
    static const unsigned char duplicate[] = {0x50, 0, 1, 0, 0x50, 0, 1, 0};
    static const unsigned char bad_value[] = {0x50, 0, 2, 0, 0};
    static const unsigned char empty_value[] = {0x50, 0, 0};
    static const unsigned char truncated[] = {1, 8, 0};
    static const unsigned char wide_id[] = {0x80, 0, 0x10, 0, 1, 1};
    static const unsigned char wide_zero[] = {0x50, 0, 2, 0x40, 0};
    if (!ob_transport_params_encrypted(absent, sizeof(absent))
        || !ob_transport_params_encrypted(zero, sizeof(zero))
        || !ob_transport_params_encrypted(hidden, sizeof(hidden))
        || !ob_transport_params_encrypted(wide_zero, sizeof(wide_zero))
        || ob_transport_params_encrypted(one, sizeof(one))
        || ob_transport_params_encrypted(two, sizeof(two))
        || ob_transport_params_encrypted(large, sizeof(large))
        || ob_transport_params_encrypted(duplicate, sizeof(duplicate))
        || ob_transport_params_encrypted(bad_value, sizeof(bad_value))
        || ob_transport_params_encrypted(empty_value, sizeof(empty_value))
        || ob_transport_params_encrypted(truncated, sizeof(truncated))
        || ob_transport_params_encrypted(wide_id, sizeof(wide_id))
        || ob_transport_params_encrypted(NULL, 0) || ob_connection_encrypted(NULL)) return -1;
    for (size_t i = 0; i < sizeof(zero); ++i)
        if (i != sizeof(absent) && ob_transport_params_encrypted(zero, i)) return -1;
    printf("PASS SDK complete QUIC TP traversal: zero/absent, any nonzero, malformed/duplicate/unknown/wide varints\n");
    if (policy_relay_tests() || policy_network_case(0, 0) || policy_network_case(1, 0)
        || policy_network_case(0, 1) || policy_network_case(1, 1)
        || policy_network_case(1, 2)) return -1;
    printf("PASS pristine xquic UDP/TLS handshake: hostile client/server no_crypto rejected before proof/ready, TLS cipher still present\n");
    return 0;
}
