/* Test-only IPv4 control socket redirection; TLS still verifies the real API.
 * The native SDK intentionally disables environment proxies. Redirect its exact
 * configured TCP destination to an own loopback gate, which forwards via SOCKS5.
 * Refuse other public destinations so this opt-in smoke cannot silently bypass
 * the proxy. This library is never part of the product runtime.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>

static int (*next_connect)(int, const struct sockaddr *, socklen_t);
static struct in_addr destination;
static unsigned short destination_port, gate_port;
static int configured;

__attribute__((constructor)) static void configure(void) {
    const char *ip = getenv("OHECO_SMOKE_API_IP");
    const char *port = getenv("OHECO_SMOKE_API_PORT");
    const char *gate = getenv("OHECO_SMOKE_GATE_PORT");
    unsigned long p = port ? strtoul(port, NULL, 10) : 0;
    unsigned long g = gate ? strtoul(gate, NULL, 10) : 0;
    *(void **)(&next_connect) = dlsym(RTLD_NEXT, "connect");
    configured = ip && inet_pton(AF_INET, ip, &destination) == 1 && p > 0 && p <= 65535 && g > 0 && g <= 65535;
    destination_port = htons((unsigned short)p);
    gate_port = htons((unsigned short)g);
}

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (!next_connect || !configured) {
        errno = EINVAL;
        return -1;
    }
    if (address && address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        if ((ntohl(ipv4->sin_addr.s_addr) >> 24) == 127)
            return next_connect(fd, address, length);
        int type = 0;
        socklen_t type_length = sizeof(type);
        if (ipv4->sin_addr.s_addr == destination.s_addr && ipv4->sin_port == destination_port &&
            getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 && type == SOCK_STREAM) {
            struct sockaddr_in redirected = *ipv4;
            redirected.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            redirected.sin_port = gate_port;
            return next_connect(fd, (const struct sockaddr *)&redirected, sizeof(redirected));
        }
        errno = EHOSTUNREACH;
        return -1;
    }
    if (address && address->sa_family == AF_INET6) {
        errno = EHOSTUNREACH;
        return -1;
    }
    return next_connect(fd, address, length);
}
