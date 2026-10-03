#include "internal.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

int ob_valid_host(const char *host, int cidr)
{
    if (!host || !*host || strlen(host) > OB_MAX_HOST) return 0;
    for (const unsigned char *c = (const unsigned char *)host; *c; ++c)
        if (!(isalnum(*c) || *c == '-' || *c == '.' || *c == ':' || (cidr && *c == '/'))) return 0;
    return 1;
}
static int ip_matches(const char *rule, const struct sockaddr *addr)
{
    char text[OB_MAX_HOST+1]; unsigned char network[16];
    snprintf(text, sizeof(text), "%s", rule);
    char *slash = strchr(text, '/'); int bits = addr->sa_family == AF_INET ? 32 : 128;
    if (slash) {
        *slash++ = 0; char *end; long n = strtol(slash, &end, 10);
        if (!*slash || *end || n < 0 || n > bits) return 0;
        bits = (int)n;
    }
    if (inet_pton(addr->sa_family, text, network) != 1) return 0;
    const unsigned char *chosen = addr->sa_family == AF_INET
        ? (const unsigned char *)&((const struct sockaddr_in *)addr)->sin_addr
        : (const unsigned char *)&((const struct sockaddr_in6 *)addr)->sin6_addr;
    if (memcmp(network, chosen, (size_t)bits/8)) return 0;
    return !(bits%8) || ((network[bits/8]^chosen[bits/8]) & (0xff << (8-bits%8))) == 0;
}
int ob_target_resolve(ob_remote_peer *p, const char *host, uint16_t port,
                      ob_remote_protocol protocol, struct sockaddr_storage *out,
                      socklen_t *outlen)
{
    if (!p || !p->is_server || !p->server || !p->ready || !port || !ob_valid_host(host, 0))
        return OB_REMOTE_EACL;
    /* Do not perform even a DNS query for a default-denied target or an
     * entirely unauthorized protocol/port. Address rules still authorize the
     * exact chosen answer below, with no second lookup. */
    int possible = 0;
    for (size_t i = 0; i < p->server->rule_count; ++i) {
        const ob_remote_allow_rule *rule = &p->server->rules[i];
        if (rule->protocol == protocol && port >= rule->port_first && port <= rule->port_last) {
            possible = 1; break;
        }
    }
    if (!possible) return OB_REMOTE_EACL;
    /* Resolve once, authorize the exact chosen address, connect that sockaddr.
     * Explicit DNS rules authorize their answers; numeric rules/CIDR can also
     * constrain any hostname to permitted addresses. No second DNS lookup. */
    struct addrinfo hints = {0}, *list = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = protocol == OB_REMOTE_TCP ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_protocol = protocol == OB_REMOTE_TCP ? IPPROTO_TCP : IPPROTO_UDP;
    char service[6]; snprintf(service, sizeof(service), "%u", port);
    if (getaddrinfo(host, service, &hints, &list)) return OB_REMOTE_EIO;
    int result = OB_REMOTE_EACL;
    for (struct addrinfo *ai = list; ai; ai = ai->ai_next) {
        if ((ai->ai_family != AF_INET && ai->ai_family != AF_INET6) || ai->ai_addrlen > sizeof(*out)) continue;
        for (size_t i = 0; i < p->server->rule_count; ++i) {
            const ob_remote_allow_rule *rule = &p->server->rules[i];
            if (rule->protocol != protocol || port < rule->port_first || port > rule->port_last) continue;
            if (!strcasecmp(rule->host, host) || ip_matches(rule->host, ai->ai_addr)) {
                memset(out, 0, sizeof(*out)); memcpy(out, ai->ai_addr, ai->ai_addrlen);
                *outlen = (socklen_t)ai->ai_addrlen; result = 0; goto end;
            }
        }
    }
end:
    freeaddrinfo(list); return result;
}
