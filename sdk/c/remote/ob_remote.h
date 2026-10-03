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
