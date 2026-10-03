/* Bounded public-test consumer of the frozen native C SDK; no Go runtime. */
#define _GNU_SOURCE
#include "ob_api.h"
#include "ob_remote.h"
#ifdef OB_PUBLIC_PEER_FIXED_ICE_PORTS
#include <juice/juice.h>
#endif
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef OB_PUBLIC_PEER_FIXED_ICE_PORTS
/* Temporary Linux acceptance consumer link adaptation, enabled with GNU --wrap.
 * Copy the public libjuice configuration to constrain both runtime roles' ICE
 * sockets below the production TURN pool. The SDK and libjuice stay unchanged. */
extern juice_agent_t *__real_juice_create(const juice_config_t *config);
juice_agent_t *__wrap_juice_create(const juice_config_t *config)
{
    if (!config) return __real_juice_create(config);
    juice_config_t bounded = *config;
    bounded.local_port_range_begin = 50000;
    bounded.local_port_range_end = 52999;
    return __real_juice_create(&bounded);
}
#endif

#define ECHO_TCP_PORT 41081
#define ECHO_UDP_PORT 41082
#define MAX_CLIENTS 16
#define MAX_LIFETIME_SECONDS 1200
static volatile sig_atomic_t interrupted;
struct echo { int fd, udp, started; pthread_t thread; atomic_int stop; };
static void on_signal(int value) { interrupted = value; }
static void clear_free(char *value)
{ if (value) { OPENSSL_cleanse(value, strlen(value)); free(value); } }
static int error_json(const char *stage, int code, long http)
{
    /* stage is always a hardcoded literal. Never print SDK messages/responses. */
    fprintf(stderr, "{\"event\":\"peer_error\",\"stage\":\"%s\",\"code\":%d,\"http_status\":%ld}\n", stage, code, http);
    fflush(stderr); return 1;
}
static char *private_value(const char *path, size_t maximum)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != getuid()
        || (st.st_mode & 077) || st.st_nlink != 1 || st.st_size < 1
        || (uintmax_t)st.st_size > maximum + 2) { close(fd); return NULL; }
    size_t size = (size_t)st.st_size, used = 0;
    char *value = calloc(size + 1, 1);
    if (!value) { close(fd); return NULL; }
    while (used < size) {
        ssize_t n = read(fd, value + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { OPENSSL_cleanse(value, size); free(value); close(fd); return NULL; }
        used += (size_t)n;
    }
    char extra;
    ssize_t tail;
    do { tail = read(fd, &extra, 1); } while (tail < 0 && errno == EINTR);
    close(fd);
    if (tail != 0 || memchr(value, 0, size)) { OPENSSL_cleanse(value, size); free(value); return NULL; }
    if (used && value[used - 1] == '\n') value[--used] = 0;
    if (used && value[used - 1] == '\r') value[--used] = 0;
    if (!used || used > maximum) { OPENSSL_cleanse(value, size); free(value); return NULL; }
    for (size_t i = 0; i < used; ++i)
        if ((unsigned char)value[i] < 32 || (unsigned char)value[i] == 127) {
            OPENSSL_cleanse(value, size); free(value); return NULL;
        }
    return value;
}
static int valid_id(const char *id)
{
    if (!id || strlen(id) != 36) return 0;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (id[i] != '-') return 0; }
        else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return 0;
    }
    return 1;
}
static int send_all(int fd, const unsigned char *data, size_t size)
{
    size_t pos = 0;
    while (pos < size) {
        ssize_t n = send(fd, data + pos, size - pos, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        pos += (size_t)n;
    }
    return 0;
}
static void *echo_worker(void *arg)
{
    struct echo *e = arg;
    unsigned char buffer[65536];
    int clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; ++i) clients[i] = -1;
    while (!atomic_load(&e->stop)) {
        struct pollfd fds[MAX_CLIENTS + 1];
        fds[0] = (struct pollfd){e->fd, POLLIN, 0};
        for (int i = 0; i < MAX_CLIENTS; ++i) fds[i + 1] = (struct pollfd){clients[i], POLLIN, 0};
        int ready = poll(fds, e->udp ? 1 : MAX_CLIENTS + 1, 100);
        if (ready <= 0) continue;
        if (fds[0].revents & POLLIN) {
            if (e->udp) {
                struct sockaddr_storage addr; socklen_t length = sizeof(addr);
                ssize_t n = recvfrom(e->fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &length);
                if (n >= 0) (void)sendto(e->fd, buffer, (size_t)n, 0, (struct sockaddr *)&addr, length);
            } else {
                int fd = accept4(e->fd, NULL, NULL, SOCK_CLOEXEC);
                if (fd >= 0) {
                    struct timeval timeout = {1, 0};
                    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                    int slot;
                    for (slot = 0; slot < MAX_CLIENTS && clients[slot] >= 0; ++slot) {}
                    if (slot == MAX_CLIENTS) close(fd); else clients[slot] = fd;
                }
            }
        }
        if (!e->udp) for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i] < 0 || !fds[i + 1].revents) continue;
            ssize_t n = recv(clients[i], buffer, sizeof(buffer), 0);
            if (n <= 0 || send_all(clients[i], buffer, (size_t)n)) { close(clients[i]); clients[i] = -1; }
        }
    }
    for (int i = 0; i < MAX_CLIENTS; ++i) if (clients[i] >= 0) close(clients[i]);
    return NULL;
}
static int echo_start(struct echo *e, int udp, uint16_t port)
{
    memset(e, 0, sizeof(*e)); e->fd = -1; e->udp = udp;
    atomic_init(&e->stop, 0);
    e->fd = socket(AF_INET, (udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_CLOEXEC, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(port);
    if (e->fd < 0 || bind(e->fd, (struct sockaddr *)&addr, sizeof(addr)) || (!udp && listen(e->fd, MAX_CLIENTS))) {
        if (e->fd >= 0) close(e->fd);
        e->fd = -1; return -1;
    }
    if (pthread_create(&e->thread, NULL, echo_worker, e)) { close(e->fd); e->fd = -1; return -1; }
    e->started = 1; return 0;
}
static void echo_close(struct echo *e)
{
    if (e->started) { atomic_store(&e->stop, 1); pthread_join(e->thread, NULL); }
    if (e->fd >= 0) close(e->fd);
}
static void usage(void)
{
    puts("public-peer serve|connect --api HTTPS_ORIGIN --ca-file PEM --tenant-token-file PRIVATE_FILE --peer-password-file PRIVATE_FILE --broker NAME_OR_ID [--relay auto|never|force]\n"
         "public-peer --version\n"
         "Secrets must be owner-only regular files, never argv values.\n"
         "Serve targets: loopback TCP 41081, UDP 41082. Connect maps use random loopback ports.\n"
         "STUN is discovered from server capabilities.stun_address. Connect relay defaults to auto; --relay is connect-only.\n"
         "SIGINT/SIGTERM closes; maximum lifetime 1200 seconds.");
}
int main(int argc, char **argv)
{
    struct rlimit no_core = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &no_core);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        const curl_version_info_data *curl = curl_version_info(CURLVERSION_NOW);
        printf("{\"event\":\"peer_version\",\"version\":1,\"sdk\":\"native-c\",\"curl\":\"%s\",\"tls\":\"BoringSSL\",\"runtime\":\"GNU-libstdc++\",\"tcp_target\":%d,\"udp_target\":%d,\"max_lifetime_seconds\":%d}\n",
               curl ? curl->version : "unknown", ECHO_TCP_PORT, ECHO_UDP_PORT, MAX_LIFETIME_SECONDS);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--help")) { usage(); return 0; }
    if (argc < 2 || (strcmp(argv[1], "serve") && strcmp(argv[1], "connect"))) { usage(); return 2; }
    int serving = !strcmp(argv[1], "serve");
    const char *api_url = NULL, *ca = NULL, *token_path = NULL, *password_path = NULL, *broker = NULL, *relay = NULL;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) return error_json("arguments", -1, 0);
        const char **dest = NULL;
        if (!strcmp(argv[i], "--api")) dest = &api_url;
        else if (!strcmp(argv[i], "--ca-file")) dest = &ca;
        else if (!strcmp(argv[i], "--tenant-token-file")) dest = &token_path;
        else if (!strcmp(argv[i], "--peer-password-file")) dest = &password_path;
        else if (!strcmp(argv[i], "--broker")) dest = &broker;
        else if (!strcmp(argv[i], "--relay") && !serving) dest = &relay;
        else return error_json("arguments", -1, 0);
        if (*dest || !*argv[i + 1]) return error_json("arguments", -1, 0);
        *dest = argv[i + 1];
    }
    if (!api_url || strncmp(api_url, "https://", 8) || !ca || !token_path || !password_path || !broker
        || (serving ? strlen(broker) > 128 : !valid_id(broker))) return error_json("arguments", -1, 0);
    if (!relay) relay = "auto";
    if (strcmp(relay, "auto") && strcmp(relay, "never") && strcmp(relay, "force")) return error_json("arguments", -1, 0);
    ob_remote_relay_mode relay_mode = !strcmp(relay, "force") ? OB_REMOTE_RELAY_FORCE
        : !strcmp(relay, "never") ? OB_REMOTE_RELAY_NEVER : OB_REMOTE_RELAY_AUTO;
    struct sigaction action = {0}; action.sa_handler = on_signal; sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL); sigaction(SIGTERM, &action, NULL); signal(SIGPIPE, SIG_IGN);
    char *token = private_value(token_path, 8192), *password = private_value(password_path, 1024);
    if (!token || !password) { clear_free(token); clear_free(password); return error_json("private_files", -1, 0); }
    ob_api_error ae = {0}; ob_remote_error re = {0};
    ob_api_options ao = {.base_url = api_url, .tenant_token = token, .ca_file = ca, .timeout_ms = 15000};
    ob_api_client *api = ob_api_client_create(&ao, &ae);
    clear_free(token); token = NULL;
    if (!api) { clear_free(password); return error_json("api_initialize", ae.code, ae.http_status); }
    struct echo tcp_echo = {.fd = -1}, udp_echo = {.fd = -1};
    ob_remote_server *server = NULL; ob_remote_peer *peer = NULL;
    ob_remote_map *tcp_map = NULL, *udp_map = NULL;
    int rc = 1;
    if (serving) {
        if (echo_start(&tcp_echo, 0, ECHO_TCP_PORT) || echo_start(&udp_echo, 1, ECHO_UDP_PORT)) {
            error_json("echo_bind", -1, 0); goto done;
        }
        ob_remote_allow_rule rules[] = {{"127.0.0.1", ECHO_TCP_PORT, ECHO_TCP_PORT, OB_REMOTE_TCP},
                                        {"127.0.0.1", ECHO_UDP_PORT, ECHO_UDP_PORT, OB_REMOTE_UDP}};
        ob_remote_serve_options options = {.allow_rules = rules, .allow_rule_count = 2,
            .setup_timeout_ms = 60000,
            .max_peers = 4, .max_maps_per_peer = 8, .max_flows_per_peer = 32};
        int status = ob_remote_serve(api, broker, password, &options, &server, &re);
        clear_free(password); password = NULL;
        if (status) { error_json("serve", status, re.http_status); goto done; }
        const char *id = ob_remote_server_id(server);
        if (!valid_id(id)) { error_json("broker_id", -1, 0); goto done; }
        printf("{\"event\":\"peer_ready\",\"role\":\"serve\",\"broker_id\":\"%s\",\"tcp_target\":%d,\"udp_target\":%d}\n", id, ECHO_TCP_PORT, ECHO_UDP_PORT);
    } else {
        char *response = NULL;
        int status = ob_api_broker_get(api, broker, &response, &ae);
        ob_api_response_free(response);
        if (status) { error_json("broker_query", status, ae.http_status); goto done; }
        ob_remote_connect_options options = {.relay_mode = relay_mode,
            .timeout_ms = 60000, .max_maps = 8, .max_flows = 32};
        status = ob_remote_connect(api, broker, password, &options, &peer, &re);
        clear_free(password); password = NULL;
        if (status) { error_json("connect", status, re.http_status); goto done; }
        status = ob_remote_portmap_tcp(peer, "127.0.0.1", 0, "127.0.0.1", ECHO_TCP_PORT, &tcp_map, &re);
        if (!status) status = ob_remote_portmap_udp(peer, "127.0.0.1", 0, "127.0.0.1", ECHO_UDP_PORT, &udp_map, &re);
        if (status) { error_json("portmap", status, re.http_status); goto done; }
        printf("{\"event\":\"peer_ready\",\"role\":\"connect\",\"broker_id\":\"%s\",\"tcp_port\":%u,\"udp_port\":%u,\"relay_mode\":\"%s\"}\n",
               broker, ob_remote_map_local_port(tcp_map), ob_remote_map_local_port(udp_map), relay);
    }
    fflush(stdout);
    struct timespec start; clock_gettime(CLOCK_MONOTONIC, &start);
    while (!interrupted) {
        int status = serving ? ob_remote_server_status(server, &re) : ob_remote_peer_status(peer, &re);
        if (status) { error_json("status", status, re.http_status); goto done; }
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= MAX_LIFETIME_SECONDS) { error_json("lifetime_limit", -1, 0); goto done; }
        struct timespec pause = {0, 200000000};
        (void)nanosleep(&pause, NULL);
    }
    rc = 0;
    printf("{\"event\":\"peer_stopped\",\"signal\":%d}\n", (int)interrupted);
done:
    clear_free(password);
    if (udp_map) ob_remote_map_close(udp_map);
    if (tcp_map) ob_remote_map_close(tcp_map);
    if (peer) ob_remote_peer_close(peer);
    if (server) ob_remote_server_close(server);
    echo_close(&udp_echo); echo_close(&tcp_echo);
    ob_api_client_destroy(api);
    return rc;
}
