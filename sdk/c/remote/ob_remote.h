#ifndef OB_REMOTE_H
#define OB_REMOTE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* ob_api_client must remain alive until all servers/peers are closed. */
typedef struct ob_api_client ob_api_client;
typedef struct ob_remote_server ob_remote_server;
typedef struct ob_remote_peer ob_remote_peer;
typedef struct ob_remote_map ob_remote_map;

typedef enum {
    OB_REMOTE_OK = 0,
    OB_REMOTE_EINVAL = -1,
    OB_REMOTE_ENOMEM = -2,
    OB_REMOTE_EHTTP = -3,
    OB_REMOTE_EAUTH = -4,
    OB_REMOTE_ETIMEOUT = -5,
    OB_REMOTE_EICE = -6,
    OB_REMOTE_EQUIC = -7,
    OB_REMOTE_EACL = -8,
    OB_REMOTE_EIO = -9,
    OB_REMOTE_ECLOSED = -10,
    OB_REMOTE_ELIMIT = -11,
    OB_REMOTE_EPROTOCOL = -12
} ob_remote_result;
typedef enum { OB_REMOTE_RELAY_AUTO = 0, OB_REMOTE_RELAY_NEVER = 1,
               OB_REMOTE_RELAY_FORCE = 2 } ob_remote_relay_mode;
typedef enum { OB_REMOTE_TCP = 1, OB_REMOTE_UDP = 2 } ob_remote_protocol;
typedef struct {
    int code;
    int http_status;
    char message[256];
} ob_remote_error;
/* Exact DNS name, numeric IP, or numeric CIDR. No wildcard or shell syntax.
 * A DNS rule authorizes that name's resolved IP, selected once for connect.
 * port_first=port_last for one port; protocol is TCP or UDP. */
typedef struct {
    const char *host;
    uint16_t port_first;
    uint16_t port_last;
    ob_remote_protocol protocol;
} ob_remote_allow_rule;
typedef struct {
    const ob_remote_allow_rule *allow_rules;
    size_t allow_rule_count;          /* zero means deny every target */
    const char *stun_server;           /* optional hostname, no scheme */
    uint16_t stun_port;               /* zero defaults to 3478 */
    uint32_t setup_timeout_ms;        /* zero defaults to 30000 */
    uint32_t max_peers;               /* zero defaults to 16 */
    uint32_t max_maps_per_peer;       /* zero defaults to 32 */
    uint32_t max_flows_per_peer;      /* zero defaults to 128 */
    uint32_t udp_idle_timeout_ms;     /* zero defaults to 60000 */
} ob_remote_serve_options;
typedef struct {
    ob_remote_relay_mode relay_mode;
    uint32_t timeout_ms;              /* zero defaults to 30000 */
    const char *stun_server;
    uint16_t stun_port;
    uint32_t max_maps;                /* zero defaults to 32 */
    uint32_t max_flows;               /* zero defaults to 128 */
    uint32_t udp_idle_timeout_ms;     /* zero defaults to 60000 */
} ob_remote_connect_options;
/* Connection handles and local mapping ports survive recoverable transport
 * failures. State callbacks are optional, run without SDK locks, and must not
 * close/destroy their handle; enqueue that action on the caller's thread.
 * Explicit close must still be serialized with all calls on the same handle. */
typedef enum {
    OB_REMOTE_STATE_CONNECTING = 0,
    OB_REMOTE_STATE_CONNECTED = 1,
    OB_REMOTE_STATE_RECONNECTING = 2,
    OB_REMOTE_STATE_RETRY_WAIT = 3,
    OB_REMOTE_STATE_PAUSED = 4,
    OB_REMOTE_STATE_FAILED = 5,
    OB_REMOTE_STATE_CLOSED = 6
} ob_remote_connection_state;
typedef struct {
    uint32_t struct_size;            /* sizeof(ob_remote_reconnect_policy) */
    uint32_t disabled;               /* zero enables automatic recovery */
    uint32_t max_attempts;           /* zero defaults to 8 */
    uint32_t initial_delay_ms;       /* zero defaults to 1000 */
    uint32_t max_delay_ms;           /* zero defaults to 15000 */
    uint32_t retry_budget_ms;        /* zero defaults to 60000 */
    uint32_t flow_grace_ms;          /* zero defaults to 120000 */
    uint32_t stable_reset_ms;        /* zero defaults to 30000 */
    uint32_t transport_timeout_ms;   /* v2 loss detection; zero defaults to 15000 */
} ob_remote_reconnect_policy;
typedef struct {
    ob_remote_connection_state state;
    uint32_t attempts;
    uint64_t generation;
    uint64_t next_retry_ms;          /* relative delay; zero if not waiting */
    ob_remote_error last_error;
} ob_remote_connection_info;
typedef void (*ob_remote_state_callback)(const ob_remote_connection_info *info,
                                         void *user_data);
void ob_remote_reconnect_policy_init(ob_remote_reconnect_policy *policy);
int ob_remote_peer_set_reconnect_policy(ob_remote_peer *peer,
                         const ob_remote_reconnect_policy *policy,
                         ob_remote_error *error);
int ob_remote_server_set_reconnect_policy(ob_remote_server *server,
                         const ob_remote_reconnect_policy *policy,
                         ob_remote_error *error);
int ob_remote_peer_get_state(ob_remote_peer *peer, ob_remote_connection_info *info);
int ob_remote_server_get_state(ob_remote_server *server, ob_remote_connection_info *info);
int ob_remote_peer_set_state_callback(ob_remote_peer *peer,
                         ob_remote_state_callback callback, void *user_data);
int ob_remote_server_set_state_callback(ob_remote_server *server,
                         ob_remote_state_callback callback, void *user_data);
/* Nonblocking: success means accepted, not connected. Repeated requests are
 * coalesced. A connected handle is left intact. Authorization is revalidated;
 * retrying cannot override an explicit revocation or authentication failure. */
int ob_remote_peer_reconnect(ob_remote_peer *peer, ob_remote_error *error);
int ob_remote_server_reconnect(ob_remote_server *server, ob_remote_error *error);
/* Returns a live handle before network setup finishes, so an initial connection
 * failure can also be retried manually. Invalid input/allocation still fails. */
int ob_remote_connect_async(ob_api_client *api, const char *broker_id,
                           const char *peer_password,
                           const ob_remote_connect_options *options,
                           ob_remote_peer **out, ob_remote_error *error);

/* Copies password/options/rules. Registers broker and starts background
 * control and native I/O workers. Password is NEVER an HTTP credential/body.
 * Caller serializes close with other operations on the same handle. */
int ob_remote_serve(ob_api_client *api, const char *broker_name,
                    const char *peer_password,
                    const ob_remote_serve_options *options,
                    ob_remote_server **out, ob_remote_error *error);
const char *ob_remote_server_id(const ob_remote_server *server);
int ob_remote_server_status(ob_remote_server *server, ob_remote_error *error);
void ob_remote_server_close(ob_remote_server *server);
/* Blocks until PAKE, ICE, pinned QUIC TLS and connection proof finish. */
int ob_remote_connect(ob_api_client *api, const char *broker_id,
                      const char *peer_password,
                      const ob_remote_connect_options *options,
                      ob_remote_peer **out, ob_remote_error *error);
int ob_remote_peer_status(ob_remote_peer *peer, ob_remote_error *error);
void ob_remote_peer_close(ob_remote_peer *peer);
/* local_host NULL/empty is 127.0.0.1; local_port 0 chooses a free port.
 * Mapping is fixed-target. TCP target errors appear as closed accepted sockets;
 * UDP target errors drop that flow. No local-listener authentication. */
int ob_remote_portmap_tcp(ob_remote_peer *peer, const char *local_host,
                         uint16_t local_port, const char *target_host,
                         uint16_t target_port, ob_remote_map **out,
                         ob_remote_error *error);
int ob_remote_portmap_udp(ob_remote_peer *peer, const char *local_host,
                         uint16_t local_port, const char *target_host,
                         uint16_t target_port, ob_remote_map **out,
                         ob_remote_error *error);
uint16_t ob_remote_map_local_port(const ob_remote_map *map);
void ob_remote_map_close(ob_remote_map *map);
const char *ob_remote_strerror(int result);
#ifdef __cplusplus
}
#endif
#endif
