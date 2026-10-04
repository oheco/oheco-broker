#ifndef OB_PEER_INTERNAL_H
#define OB_PEER_INTERNAL_H
#include "../ob_remote.h"
#include "../ob_api.h"
#include "../ob_ws.h"
#include <pthread.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <juice/juice.h>
#include <xquic/xquic.h>
#include <openssl/curve25519.h>
#include <cjson/cJSON.h>
#define OB_ALPN "ob-peer-v1"
#define OB_MAX_HOST 253
#define OB_PACKET_LIMIT 256
#define OB_PACKET_SIZE 2048
#define OB_STREAM_BUFFER 65536
#define OB_MAX_ACL 128
struct ob_packet { struct ob_packet *next; size_t len; unsigned char data[]; };
struct ob_flow;
struct ob_seen_session { struct ob_seen_session *next; char id[37]; };
struct ob_remote_map {
    struct ob_remote_map *next;
    ob_remote_peer *peer;
    int fd, closed, udp_draining;
    uint16_t local_port, target_port;
    ob_remote_protocol protocol;
    char target_host[OB_MAX_HOST + 1];
};
/* The enclosing handle's mutex protects policy/info/callback and deadlines.
 * Only its coordinator delivers callbacks; callbacks never run under that mutex. */
struct ob_recovery {
    ob_remote_reconnect_policy policy;
    ob_remote_connection_info info;
    ob_remote_state_callback callback;
    void *callback_data;
    atomic_int requested;
    int callback_pending;
    uint64_t outage_us, stable_us, retry_us;
};
struct ob_remote_server {
    ob_api_client *api;
    char *password, *broker_id, *device_token, *stun;
    ob_remote_allow_rule *rules;
    size_t rule_count;
    ob_remote_serve_options options;
    pthread_mutex_t mu;
    pthread_t worker;
    pthread_cond_t cv;
    int worker_started, initialized, manual_attempt;
    atomic_int stop, caller_close;
    struct ob_recovery recovery;
    int result;
    ob_remote_error error;
    ob_remote_peer *peers;
    struct ob_seen_session *seen_sessions;
    size_t seen_count;
    int control_cleanup;
    uint64_t start_deadline_us;
};
struct ob_remote_peer {
    ob_remote_peer *next;
    ob_api_client *api;
    ob_remote_server *server;
    char *password, *session_id, *bearer, *broker_id, *stun;
    int is_server;
    ob_remote_relay_mode relay;
    uint16_t stun_port;
    uint32_t timeout_ms, max_maps, max_flows, udp_idle_ms;
    pthread_mutex_t mu, qmu;
    pthread_cond_t cv;
    pthread_t setup_thread, io_thread, coordinator_thread;
    int setup_started, io_started, coordinator_started;
    /* stop terminates the logical handle; attempt_stop only retires transport. */
    atomic_int stop, attempt_stop;
    int managed, attempt_result;
    ob_remote_error attempt_error;
    struct ob_recovery recovery;
    int result, ready, tls_ready, proof_ready;
    atomic_int ice_ready, gathered, ice_failed;
    ob_remote_error error;
    uint64_t deadline_us, lease_deadline_us, next_timer_us;
    uint64_t transport_generation, recovery_deadline_us, next_ping_us;
    uint32_t transport_idle_ms;
    int transport_available, transport_detached, transport_detaching;
    int wire_version, resume_context_available, ever_ready;
    char connection_id[37], request_id[37], requested_session_token[65];
    uint64_t control_generation;
    int request_pending, control_managed, control_discovered, control_retryable;
    int lease_deadline_set;
    /* Setup worker owns every WS field. I/O only reads lease under mu and
     * atomic stop; it never waits for curl, TLS, DNS or control RPCs. */
    ob_ws *ws;
    int control_cleanup, approved;
    uint64_t heartbeat_id, heartbeat_due_us, heartbeat_sent_us, reconnect_us;
    unsigned reconnect_backoff;
    uint64_t tx_sequence, rx_sequence;
    unsigned char shared[64], tx_key[32], rx_key[32], fingerprint[32];
    unsigned char resume_key[32], fresh_resume_key[32];
    int resume_key_set;
    char *pending_session_id;
    uint64_t pending_control_generation;
    size_t shared_len;
    _Atomic(juice_agent_t *) ice;
    struct ob_packet *qhead, *qtail;
    size_t qcount;
    int wake[2];
    xqc_engine_t *engine;
    xqc_connection_t *conn;
    xqc_cid_t cid;
    struct sockaddr_in logical_local, logical_peer;
    char cert_dir[1024], cert_path[1100], key_path[1100];
    ob_remote_map *maps;
    struct ob_flow *flows;
    size_t map_count, flow_count;
    uint64_t next_flow_id;
    void *mapping_private;
};
uint64_t ob_now_us(void);
uint64_t ob_realtime_us(void);
void ob_ice_callbacks(juice_config_t *config, ob_remote_peer *p);
int ob_relay_candidate(const char *line, size_t len);
int ob_filter_relay_description(const char *source, char out[JUICE_MAX_SDP_STRING_LEN]);
int ob_force_path(ob_remote_peer *p);
void *ob_engine_worker(void *data);
int ob_error(ob_remote_error *e, int code, int http, const char *message);
void ob_peer_fail(ob_remote_peer *p, int code, const char *message);
void ob_peer_fail_locked(ob_remote_peer *p, int code, const char *message);
/* Retryable failure retires only the current transport and stops forwarding.
 * Explicit authorization/protocol failures must use the terminal fail helper. */
void ob_peer_transport_fail_locked(ob_remote_peer *p, int code, const char *message);
void ob_peer_transport_fail(ob_remote_peer *p, int code, const char *message);
void ob_recovery_init(struct ob_recovery *recovery);
/* Caller holds the enclosing handle's mutex and supplies a normalized policy.
 * Retained retry deadlines may move earlier; outage/grace/budget ages are kept. */
void ob_recovery_apply_policy_locked(struct ob_recovery *recovery,
                                     const ob_remote_reconnect_policy *policy);
void ob_recovery_set_locked(struct ob_recovery *recovery,
                            ob_remote_connection_state state,
                            const ob_remote_error *error);
void ob_recovery_deliver(struct ob_recovery *recovery, pthread_mutex_t *mutex);
void ob_wake(ob_remote_peer *p);
/* All mapping hooks run on engine owner thread with p->mu held.
 * mapping API may take p->mu; no xquic API on caller/control threads. */
void ob_mapping_callbacks(xqc_app_proto_callbacks_t *callbacks);
void ob_mapping_tick(ob_remote_peer *p);
void ob_mapping_cleanup(ob_remote_peer *p);
void ob_mapping_transport_suspend(ob_remote_peer *p, int preserve_tcp,
                                   uint64_t deadline_us);
void ob_mapping_transport_ready(ob_remote_peer *p, int wire_version,
                                 int resume_context_available);
void ob_mapping_recovery_tick(ob_remote_peer *p, uint64_t now_us);
void ob_mapping_forget_flows(ob_remote_peer *p);
/* Called after TLS handshake; mappings implement first proof stream using
 * ob_connection_proof. No OPEN accepted before proof_ready/ready. */
int ob_connection_proof(ob_remote_peer *p, int sender_server, unsigned char out[32]);
void ob_mapping_handshake(ob_remote_peer *p);
void ob_peer_mark_ready(ob_remote_peer *p);
int ob_valid_id(const char *id);
int ob_valid_host(const char *host, int cidr);
void *ob_setup_worker(void *data);
void ob_control_close_connection(ob_remote_peer *peer);
void *ob_peer_coordinator(void *data);
int ob_peer_start(ob_remote_peer *peer, ob_remote_error *error);
void *ob_server_worker(void *data);
ob_remote_peer *ob_peer_alloc(ob_api_client *api, const char *broker_id,
                              const char *password, const ob_remote_connect_options *options);
void ob_peer_destroy(ob_remote_peer *p);
cJSON *ob_peer_json_parse(const char *text);
int ob_decode_signal(ob_remote_peer *p, const char *data, double rest_sequence,
                      const char *type, int authenticated, char **payload);
int ob_control_request(ob_api_client *api, const char *method, const char *path,
                        const char *bearer, cJSON *body, cJSON **out, ob_remote_error *error);
int ob_target_resolve(ob_remote_peer *p, const char *host, uint16_t port,
                      ob_remote_protocol protocol, struct sockaddr_storage *out,
                      socklen_t *outlen);
#endif
