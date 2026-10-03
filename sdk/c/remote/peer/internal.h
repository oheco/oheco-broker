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
    int fd, closed;
    uint16_t local_port, target_port;
    ob_remote_protocol protocol;
    char target_host[OB_MAX_HOST + 1];
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
    int worker_started, initialized;
    atomic_int stop, caller_close;
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
    pthread_t setup_thread, io_thread;
    int setup_started, io_started;
    atomic_int stop;
    int result, ready, tls_ready, proof_ready;
    atomic_int ice_ready, gathered, ice_failed;
    ob_remote_error error;
    uint64_t deadline_us, lease_deadline_us, next_timer_us;
    int lease_deadline_set;
    /* Setup worker owns every WS field. I/O only reads lease under mu and
     * atomic stop; it never waits for curl, TLS, DNS or control RPCs. */
    ob_ws *ws;
    int control_cleanup, approved;
    uint64_t heartbeat_id, heartbeat_due_us, heartbeat_sent_us, reconnect_us;
    unsigned reconnect_backoff;
    uint64_t tx_sequence, rx_sequence;
    unsigned char shared[64], tx_key[32], rx_key[32], fingerprint[32];
    size_t shared_len;
    juice_agent_t *ice;
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
void ob_wake(ob_remote_peer *p);
/* All mapping hooks run on engine owner thread with p->mu held.
 * mapping API may take p->mu; no xquic API on caller/control threads. */
void ob_mapping_callbacks(xqc_app_proto_callbacks_t *callbacks);
void ob_mapping_tick(ob_remote_peer *p);
void ob_mapping_cleanup(ob_remote_peer *p);
/* Called after TLS handshake; mappings implement first proof stream using
 * ob_connection_proof. No OPEN accepted before proof_ready/ready. */
int ob_connection_proof(ob_remote_peer *p, int sender_server, unsigned char out[32]);
void ob_mapping_handshake(ob_remote_peer *p);
void ob_peer_mark_ready(ob_remote_peer *p);
int ob_valid_id(const char *id);
int ob_valid_host(const char *host, int cidr);
void *ob_setup_worker(void *data);
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
