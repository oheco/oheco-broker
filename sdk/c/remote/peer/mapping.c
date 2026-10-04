#include "internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/mem.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef OB_MAPPING_TRACE
#include <stdio.h>
#define M_TRACE(...) fprintf(stderr, __VA_ARGS__)
#else
#define M_TRACE(...) ((void)0)
#endif
#ifdef OB_UDP_TRACE
#include <stdio.h>
#include <stdatomic.h>
#define U_TRACE_ROWS 2048U
#define U_TRACE_WIDTH 320U
static char ob_udp_trace_rows[2][U_TRACE_ROWS][U_TRACE_WIDTH];
static atomic_uint ob_udp_trace_counts[2];
/* Reserve a unique row without allocation or I/O. The diagnostic caller dumps
 * only after every peer owner has joined, so row readers cannot race writers. */
#define U_TRACE(format, role, ...) do { \
    int ob_trace_errno = errno; \
    unsigned int ob_trace_role = (unsigned int)(role); \
    if (ob_trace_role < 2U) { \
        unsigned int ob_trace_row = atomic_fetch_add_explicit(&ob_udp_trace_counts[ob_trace_role], 1U, memory_order_relaxed); \
        if (ob_trace_row < U_TRACE_ROWS) \
            (void)snprintf(ob_udp_trace_rows[ob_trace_role][ob_trace_row], U_TRACE_WIDTH, format, (int)ob_trace_role, __VA_ARGS__); \
    } \
    errno = ob_trace_errno; \
} while (0)
void ob_mapping_udp_trace_dump(void)
{
    int saved_errno = errno;
    for (unsigned int role = 0; role < 2U; ++role) {
        unsigned int count = atomic_load_explicit(&ob_udp_trace_counts[role], memory_order_relaxed);
        unsigned int rows = count < U_TRACE_ROWS ? count : U_TRACE_ROWS;
        fprintf(stderr, "udp buffered-summary role=%u rows=%u dropped_rows=%u\n", role, rows, count - rows);
        for (unsigned int row = 0; row < rows; ++row) fputs(ob_udp_trace_rows[role][row], stderr);
    }
    errno = saved_errno;
}
#else
#define U_TRACE(...) ((void)0)
#endif

/* Application wire protocol (all integers big endian):
 * OBM1, kind:u8, protocol:u8, size:u16, flow:u64, payload.
 * PROOF=1 has 32 bytes and flow/protocol zero; OPEN=2 has port:u16
 * followed by a non-NUL host; ACK=3 has result:u32. TCP bytes follow ACK.
 * UDP's reliable stream stays open solely to own the logical flow.
 * OBD1, flow:u64, packet:u64, total:u16, offset:u16, size:u16, zero:u16,
 * followed by exactly size bytes. Fixed 512-byte fragments support every
 * UDP payload through 65507, including empty packets, with at most 128
 * fragments. DATAGRAM MSS must be >=540. RFC 9221 section 5: lost DATAGRAMs
 * are never retransmitted. A lost fragment expires the whole packet.
 * All hooks and callbacks require the engine owner to hold peer->mu.
 */
#define M_HEADER 16U
#define M_CTRL (M_HEADER + OB_MAX_HOST + 2U)
#define M_PROOF 1U
#define M_OPEN 2U
#define M_ACK 3U
#define M_RESUME 4U
#define M_RESUME_ACK 5U
#define M_RESUME_SIZE 40U
#define M_V2_HEADER 24U
#define M_V2_DATA 1U
#define M_V2_ACK 2U
#define M_V2_FIN 3U
#define M_DHEADER 28U
#define M_FRAGMENT 512U
#define M_UDP_MAX 65507U
#define M_UDP_QUEUE 4U
#define M_REASSEMBLY 4U
#define M_MEMORY (16U * 1024U * 1024U)
#define M_MAPS 128U
#define M_FLOWS 512U
#define M_SETUP_US UINT64_C(10000000)
#define M_PACKET_US UINT64_C(2000000)
#define M_PACKET_TTL_US UINT64_C(1000000)
#define M_IO_BUDGET 16384U

#ifdef OB_UDP_COUNTERS
#include <stdio.h>
#include <stdatomic.h>
struct ob_udp_counters {
    atomic_uint_fast64_t enq_ok, enq_denied, send_flow, send_packet;
    atomic_uint_fast64_t target_reads, target_n, send_attempts, admitted, eagain, negative, mss_drop;
    atomic_int_fast64_t last_rc;
    atomic_uint_fast64_t sent_bits[2], sent_ids[128];
    atomic_uint_fast64_t ttl_expired, ttl_offset, recv_flow, recv_packet, recv_fragments, recv_bytes, recv_bits[2];
    atomic_uint_fast64_t incomplete_drops, drop_received, drop_bits[2], deliveries;
    atomic_int_fast64_t delivery_n;
    atomic_uint_fast64_t delivery_errno, lost_count, lost_ids[128];
};
static struct ob_udp_counters ob_udp_counters[2];
_Static_assert(sizeof(ob_udp_counters) <= 8192U, "UDP diagnostic counters must stay within 8KiB BSS");
#define UC_GET(p) (&ob_udp_counters[(p)->is_server ? 1U : 0U])
#define UC_ADD(p, field, value) ((void)atomic_fetch_add_explicit(&UC_GET(p)->field, (value), memory_order_relaxed))
#define UC_SET(p, field, value) atomic_store_explicit(&UC_GET(p)->field, (value), memory_order_relaxed)
#define UC_OR(p, field, word, value) ((void)atomic_fetch_or_explicit(&UC_GET(p)->field[(word)], (value), memory_order_relaxed))
#define UC_LOAD(s, field) atomic_load_explicit(&(s)->field, memory_order_relaxed)
/* All collection hooks below perform integer/atomic operations only. The
 * diagnostic caller dumps after every peer owner has stopped and joined. */
void ob_mapping_udp_counters_dump(void)
{
    int saved_errno = errno;
    for (unsigned int role = 0; role < 2U; ++role) {
        struct ob_udp_counters *s = &ob_udp_counters[role];
        fprintf(stderr, "udp counters role=%u bss=%zu enq_ok=%llu enq_denied=%llu send_flow=%llu send_packet=%llu target_reads=%llu target_n=%llu send_attempts=%llu admitted=%llu eagain=%llu negative=%llu mss_drop=%llu last_rc=%lld sent_bits=%016llx/%016llx ttl_expired=%llu ttl_offset=%llu recv_flow=%llu recv_packet=%llu recv_fragments=%llu recv_bytes=%llu recv_bits=%016llx/%016llx incomplete_drops=%llu drop_received=%llu drop_bits=%016llx/%016llx deliveries=%llu delivery_n=%lld delivery_errno=%llu lost_count=%llu\n",
            role, sizeof(ob_udp_counters),
            (unsigned long long)UC_LOAD(s, enq_ok), (unsigned long long)UC_LOAD(s, enq_denied),
            (unsigned long long)UC_LOAD(s, send_flow), (unsigned long long)UC_LOAD(s, send_packet),
            (unsigned long long)UC_LOAD(s, target_reads), (unsigned long long)UC_LOAD(s, target_n),
            (unsigned long long)UC_LOAD(s, send_attempts), (unsigned long long)UC_LOAD(s, admitted),
            (unsigned long long)UC_LOAD(s, eagain), (unsigned long long)UC_LOAD(s, negative),
            (unsigned long long)UC_LOAD(s, mss_drop), (long long)UC_LOAD(s, last_rc),
            (unsigned long long)UC_LOAD(s, sent_bits[0]), (unsigned long long)UC_LOAD(s, sent_bits[1]),
            (unsigned long long)UC_LOAD(s, ttl_expired), (unsigned long long)UC_LOAD(s, ttl_offset),
            (unsigned long long)UC_LOAD(s, recv_flow), (unsigned long long)UC_LOAD(s, recv_packet),
            (unsigned long long)UC_LOAD(s, recv_fragments), (unsigned long long)UC_LOAD(s, recv_bytes),
            (unsigned long long)UC_LOAD(s, recv_bits[0]), (unsigned long long)UC_LOAD(s, recv_bits[1]),
            (unsigned long long)UC_LOAD(s, incomplete_drops), (unsigned long long)UC_LOAD(s, drop_received),
            (unsigned long long)UC_LOAD(s, drop_bits[0]), (unsigned long long)UC_LOAD(s, drop_bits[1]),
            (unsigned long long)UC_LOAD(s, deliveries), (long long)UC_LOAD(s, delivery_n),
            (unsigned long long)UC_LOAD(s, delivery_errno), (unsigned long long)UC_LOAD(s, lost_count));
        for (unsigned int fragment = 0; fragment < 128U; ++fragment)
            if (UC_LOAD(s, sent_bits[fragment / 64U]) & (UINT64_C(1) << (fragment % 64U)))
                fprintf(stderr, "udp admitted-id role=%u fragment=%u offset=%u dgram=%llu\n", role, fragment, fragment * M_FRAGMENT, (unsigned long long)UC_LOAD(s, sent_ids[fragment]));
        uint64_t lost = UC_LOAD(s, lost_count);
        for (unsigned int index = 0; index < 128U && index < lost; ++index)
            fprintf(stderr, "udp lost-id role=%u index=%u dgram=%llu\n", role, index, (unsigned long long)UC_LOAD(s, lost_ids[index]));
        fprintf(stderr, "udp lost-overflow role=%u count=%llu\n", role, (unsigned long long)(lost > 128U ? lost - 128U : 0U));
    }
    errno = saved_errno;
}
#endif

enum m_phase { M_CONTROL, M_RESOLVING, M_CONNECTING, M_REPLY, M_ACTIVE, M_DEAD };
struct m_resolve {
    struct m_resolve *next;
    ob_remote_server *server;
    int is_server, state, detached, result;
    uint16_t port;
    ob_remote_protocol protocol;
    char host[OB_MAX_HOST + 1];
    struct sockaddr_storage address;
    socklen_t address_len;
};
struct m_udp_packet {
    struct m_udp_packet *next;
    uint64_t id, created;
    size_t len, offset;
    unsigned char data[];
};
struct m_assembly {
    uint64_t id, updated, bits[2];
    unsigned char *data;
    size_t total, received;
};
struct ob_flow {
    struct ob_flow *next;
    ob_remote_peer *peer;
    ob_remote_map *map;
    xqc_stream_t *stream;
    uint64_t id, created, last_io, next_packet, receive_high, delivered;
    int fd, local, proof, close_requested, close_sent;
    int socket_eof, stream_eof, sent_fin, socket_shutdown;
    int acked, reject_after_reply, proof_reply_ready;
    ob_remote_protocol protocol;
    enum m_phase phase;
    struct sockaddr_storage source;
    socklen_t source_len;
    unsigned char control[M_CTRL], reply[M_CTRL];
    size_t control_len, control_need, reply_len, reply_pos;
#ifdef OB_MAPPING_TRACE
    unsigned int trace_send, trace_read;
    uint64_t trace_tick_us;
    ssize_t trace_last_send, trace_last_recv;
#endif
    unsigned char *tx, *rx;
    size_t tx_len, tx_pos, rx_len, rx_pos;
    /* V2 retains tx until cumulative delivery to the other real socket.
     * stream_generation is an attachment, never the logical flow identity. */
    uint64_t stream_generation, grace_deadline_us, tx_base, tx_sent_high, rx_commit, rx_next;
    uint64_t tx_final, rx_final;
    int wire_version, transient, suspended, pending_open, waiting_resume, resuming;
    int rx_fin, rx_fin_applied, tx_fin_acked, ack_dirty;
    unsigned char in_frame[M_V2_HEADER], out_frame[M_V2_HEADER];
    size_t in_have, in_size, in_pos, out_pos;
    uint64_t in_offset, out_offset, out_end;
    unsigned int in_kind, in_flags, out_kind, out_flags;
    struct m_udp_packet *udp_head, *udp_tail;
    unsigned int udp_count;
    struct m_assembly assembly[M_REASSEMBLY];
    struct m_resolve *resolve;
};
struct m_state {
    size_t memory;
    int proof_started, resolver_stop;
    pthread_mutex_t resolver_mu;
    pthread_cond_t resolver_cv;
    pthread_t resolver_threads[2];
    unsigned int resolver_count, job_count;
    size_t map_rotation, udp_rotation;
    struct m_resolve *jobs;
    unsigned char udp[M_UDP_MAX + 1U];
};

static void m_stop_io(ob_remote_peer *p);
static int m_v2_control_done(struct ob_flow *f);
static void m_v2_read(struct ob_flow *f);
static void m_v2_write(struct ob_flow *f);
static void m_v2_tick(struct ob_flow *f);
static int m_resume_open(struct ob_flow *f);

/* A tick's timestamp can precede flows/packets created later in that same
 * tick, including timestamps written by synchronous xquic callbacks. Never
 * interpret unsigned underflow as an expired setup, packet, or idle flow. */
static int m_expired(uint64_t now, uint64_t timestamp, uint64_t limit)
{
    return now >= timestamp && now - timestamp > limit;
}
static unsigned int m_limit(unsigned int configured, unsigned int def,
                            unsigned int hard)
{
    return configured ? (configured < hard ? configured : hard) : def;
}
static struct m_state *m_state_get(ob_remote_peer *p)
{
    if (!p->mapping_private) {
        struct m_state *s = calloc(1, sizeof(*s));
        if (!s) return NULL;
        if (pthread_mutex_init(&s->resolver_mu, NULL)) { free(s); return NULL; }
        if (pthread_cond_init(&s->resolver_cv, NULL)) {
            pthread_mutex_destroy(&s->resolver_mu); free(s); return NULL;
        }
        p->mapping_private = s;
    }
    return p->mapping_private;
}
static void *m_control_alloc(ob_remote_peer *p, size_t n)
{
    struct m_state *s = m_state_get(p);
    if (!s || n > M_MEMORY || s->memory > M_MEMORY - n) return NULL;
    void *v = calloc(1, n);
    if (v) s->memory += n;
    return v;
}
static void *m_alloc(ob_remote_peer *p, size_t n)
{
    struct m_state *s = m_state_get(p);
    /* Retained payload must leave room for every admitted flow's incoming
     * RESUME parser and channel proof, even when xquic receives a whole batch
     * before the regular tick can rebind and free placeholders. The reserve is
     * inside the same hard budget, not an additional allocation allowance. */
    size_t reserve = ((size_t)m_limit(p->max_flows, 128U, M_FLOWS) + 2U) * sizeof(struct ob_flow);
    size_t limit = M_MEMORY - reserve;
    if (!s || n > limit || s->memory > limit - n) return NULL;
    return m_control_alloc(p, n);
}
static void m_free(ob_remote_peer *p, void *v, size_t n)
{
    if (!v) return;
    struct m_state *s = p->mapping_private;
    if (s) s->memory -= n;
    free(v);
}
/* DNS/ACL resolution may block in libc. A bounded pool does it away from
 * the engine; workers never reference a flow or take peer->mu. The core helper
 * only needs the immutable server ACL and authenticated role snapshot. */
static void *m_resolver_worker(void *data)
{
    struct m_state *s = data;
    for (;;) {
        pthread_mutex_lock(&s->resolver_mu);
        struct m_resolve *job = NULL;
        while (!s->resolver_stop) {
            for (job = s->jobs; job; job = job->next)
                if (!job->state) break;
            if (job) break;
            pthread_cond_wait(&s->resolver_cv, &s->resolver_mu);
        }
        if (s->resolver_stop) { pthread_mutex_unlock(&s->resolver_mu); return NULL; }
        job->state = 1;
        pthread_mutex_unlock(&s->resolver_mu);
        ob_remote_peer snapshot;
        memset(&snapshot, 0, sizeof(snapshot));
        snapshot.is_server = job->is_server; snapshot.server = job->server;
        snapshot.ready = snapshot.proof_ready = 1;
        struct sockaddr_storage address;
        socklen_t address_len = sizeof(address);
        int result = ob_target_resolve(&snapshot, job->host, job->port,
                                       job->protocol, &address, &address_len);
        pthread_mutex_lock(&s->resolver_mu);
        job->result = result;
        if (!result) { job->address = address; job->address_len = address_len; }
        job->state = 2;
        pthread_mutex_unlock(&s->resolver_mu);
    }
}
static int m_resolve_start(struct ob_flow *f, const char *host, uint16_t port)
{
    struct m_state *s = m_state_get(f->peer);
    if (!s) return OB_REMOTE_ENOMEM;
    if (!s->resolver_count) {
        for (unsigned int i = 0; i < 2; ++i) {
            if (pthread_create(&s->resolver_threads[i], NULL, m_resolver_worker, s)) break;
            ++s->resolver_count;
        }
        if (!s->resolver_count) return OB_REMOTE_EIO;
    }
    pthread_mutex_lock(&s->resolver_mu);
    if (s->job_count >= 32) { pthread_mutex_unlock(&s->resolver_mu); return OB_REMOTE_ELIMIT; }
    struct m_resolve *job = m_alloc(f->peer, sizeof(*job));
    if (!job) { pthread_mutex_unlock(&s->resolver_mu); return OB_REMOTE_ENOMEM; }
    job->server = f->peer->server; job->is_server = f->peer->is_server;
    job->protocol = f->protocol; job->port = port;
    memcpy(job->host, host, strlen(host) + 1);
    job->next = s->jobs; s->jobs = job; ++s->job_count;
    f->resolve = job; f->phase = M_RESOLVING;
    pthread_cond_signal(&s->resolver_cv);
    pthread_mutex_unlock(&s->resolver_mu); return 0;
}
static void m_resolve_detach(struct ob_flow *f)
{
    if (!f->resolve) return;
    struct m_state *s = f->peer->mapping_private;
    pthread_mutex_lock(&s->resolver_mu);
    f->resolve->detached = 1; f->resolve = NULL;
    pthread_mutex_unlock(&s->resolver_mu);
}
static void m_resolve_reap(ob_remote_peer *p)
{
    struct m_state *s = p->mapping_private;
    pthread_mutex_lock(&s->resolver_mu);
    struct m_resolve **at = &s->jobs;
    while (*at) {
        struct m_resolve *job = *at;
        if (job->detached && job->state != 1) {
            *at = job->next; --s->job_count;
            m_free(p, job, sizeof(*job));
        } else at = &job->next;
    }
    pthread_mutex_unlock(&s->resolver_mu);
}
static uint16_t m_u16(const unsigned char *v)
{
    return (uint16_t)(((uint16_t)v[0] << 8) | v[1]);
}
static uint64_t m_u64(const unsigned char *v)
{
    uint64_t n = 0;
    for (unsigned int i = 0; i < 8; ++i) n = (n << 8) | v[i];
    return n;
}
static void m_put16(unsigned char *v, size_t n)
{
    v[0] = (unsigned char)(n >> 8); v[1] = (unsigned char)n;
}
static void m_put64(unsigned char *v, uint64_t n)
{
    for (unsigned int i = 0; i < 8; ++i) { v[7U - i] = (unsigned char)n; n >>= 8; }
}
static void m_header(unsigned char *v, unsigned int kind,
                     unsigned int protocol, size_t size, uint64_t id)
{
    memcpy(v, "OBM1", 4); v[4] = (unsigned char)kind;
    v[5] = (unsigned char)protocol; m_put16(v + 6, size); m_put64(v + 8, id);
}
static int m_nonblock(int fd)
{
    int f = fcntl(fd, F_GETFL, 0), d = fcntl(fd, F_GETFD, 0);
    return f < 0 || d < 0 || fcntl(fd, F_SETFL, f | O_NONBLOCK) < 0 ||
           fcntl(fd, F_SETFD, d | FD_CLOEXEC) < 0 ? -1 : 0;
}
static int m_socket(int family, int type)
{
    int fd = socket(family, type, 0);
    if (fd >= 0 && m_nonblock(fd) < 0) { close(fd); fd = -1; }
    return fd;
}
static int m_again(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
static int m_host_valid(const char *host, size_t len)
{
    if (!len || len > OB_MAX_HOST) return 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':' ||
              c == '_' || c == '%')) return 0;
    }
    return 1;
}
static void m_drop_udp(struct ob_flow *f)
{
    while (f->udp_head) {
        struct m_udp_packet *q = f->udp_head;
        f->udp_head = q->next;
        m_free(f->peer, q, sizeof(*q) + q->len);
    }
    f->udp_tail = NULL; f->udp_count = 0;
    for (unsigned int i = 0; i < M_REASSEMBLY; ++i) {
        struct m_assembly *a = &f->assembly[i];
        m_free(f->peer, a->data, a->total ? a->total : 1U);
        memset(a, 0, sizeof(*a));
    }
}
static void m_release_io(struct ob_flow *f)
{
    m_resolve_detach(f);
    if (f->fd >= 0) { close(f->fd); f->fd = -1; }
    m_free(f->peer, f->tx, OB_STREAM_BUFFER); f->tx = NULL;
    m_free(f->peer, f->rx, OB_STREAM_BUFFER); f->rx = NULL;
    m_drop_udp(f);
}
static void m_abort_at(struct ob_flow *f, const char *file, int line)
{
    (void)file; (void)line;
    M_TRACE("mapping abort role=%d gen=%llu flow=%llu fd=%d phase=%d location=%s:%d ack=%d suspended=%d resuming=%d\n",
            f->peer->is_server, (unsigned long long)f->peer->transport_generation,
            (unsigned long long)f->id, f->fd, f->phase, file, line, f->acked,
            f->suspended, f->resuming);
    f->phase = M_DEAD;
    m_release_io(f);
    if (f->stream && !f->close_sent) {
        f->close_sent = 1;
        (void)xqc_stream_close(f->stream);
    }
}
#define m_abort(f) m_abort_at((f), __FILE__, __LINE__)
static void m_fail(ob_remote_peer *p, int code, const char *message)
{
    if (code == OB_REMOTE_EQUIC || code == OB_REMOTE_EICE || code == OB_REMOTE_ETIMEOUT)
        ob_peer_transport_fail_locked(p, code, message);
    else ob_peer_fail_locked(p, code, message);
}
static struct ob_flow *m_flow_new(ob_remote_peer *p)
{
    /* Incoming RESUME headers temporarily coexist with the retained logical
     * flow. Both allocations count against M_MEMORY, with a separate hard cap. */
    if (p->flow_count >= 2U * m_limit(p->max_flows, 128U, M_FLOWS) + 2U) return NULL;
    struct ob_flow *f = m_control_alloc(p, sizeof(*f));
    if (!f) return NULL;
    f->peer = p; f->fd = -1; f->phase = M_CONTROL;
    f->created = f->last_io = ob_now_us(); f->control_need = M_HEADER;
    f->next = p->flows; p->flows = f; ++p->flow_count;
    return f;
}
static void m_flow_free(struct ob_flow *f)
{
    ob_remote_peer *p = f->peer;
    struct ob_flow **at = &p->flows;
    while (*at && *at != f) at = &(*at)->next;
    if (*at) { *at = f->next; --p->flow_count; }
    m_release_io(f); m_free(p, f, sizeof(*f));
}
static size_t m_data_flow_count(ob_remote_peer *p)
{
    size_t count = 0;
    for (struct ob_flow *f = p->flows; f; f = f->next)
        if (!f->proof && !f->transient && f->phase != M_DEAD) ++count;
    return count;
}
static struct ob_flow *m_find(ob_remote_peer *p, uint64_t id)
{
    for (struct ob_flow *f = p->flows; f; f = f->next)
        if (!f->proof && !f->transient && f->phase != M_DEAD && f->id == id) return f;
    return NULL;
}
static int m_tcp_buffers(struct ob_flow *f)
{
    f->tx = m_alloc(f->peer, OB_STREAM_BUFFER);
    f->rx = m_alloc(f->peer, OB_STREAM_BUFFER);
    if (!f->tx || !f->rx) { m_release_io(f); return -1; }
    return 0;
}
static int m_stream_open(struct ob_flow *f)
{
    if (!f->peer->conn || atomic_load(&f->peer->stop)
        || atomic_load(&f->peer->attempt_stop)) return -1;
    f->stream_generation = f->peer->transport_generation;
    f->stream = xqc_stream_create_with_direction(f->peer->conn,
                                                 XQC_STREAM_BIDI, f);
    return f->stream ? 0 : -1;
}
static void m_ack(struct ob_flow *f, int code)
{
    M_TRACE("mapping ack role=%d flow=%llu result=%d\n", f->peer->is_server,
            (unsigned long long)f->id, code);
    uint32_t wire = (uint32_t)(code < 0 ? -code : code);
    m_header(f->reply, M_ACK, (unsigned int)f->protocol, 4, f->id);
    f->reply[16] = (unsigned char)(wire >> 24); f->reply[17] = (unsigned char)(wire >> 16);
    f->reply[18] = (unsigned char)(wire >> 8); f->reply[19] = (unsigned char)wire;
    f->reply_len = 20; f->reply_pos = 0; f->phase = M_REPLY;
    f->reject_after_reply = code != 0;
}
static void m_reply_flush(struct ob_flow *f)
{
    if (!f->stream || f->close_requested || f->phase == M_DEAD ||
        !f->reply_len) return;
    if (f->reply_pos < f->reply_len) {
        ssize_t n = xqc_stream_send(f->stream, f->reply + f->reply_pos,
                                    f->reply_len - f->reply_pos, 0);
#ifdef OB_MAPPING_TRACE
        if (f->trace_send++ < 16)
            M_TRACE("mapping control-send role=%d flow=%llu kind=%u phase=%d pos=%zu len=%zu n=%zd\n",
                    f->peer->is_server, (unsigned long long)f->id,
                    f->reply[4], f->phase, f->reply_pos, f->reply_len, n);
#endif
        if (n == -XQC_EAGAIN) return;
        if (n < 0) {
            M_TRACE("mapping reply-send error=%zd\n", n);
            if (f->wire_version == 2 && f->protocol == OB_REMOTE_TCP)
                ob_peer_transport_fail_locked(f->peer, OB_REMOTE_EQUIC, "TCP control send failed");
            else m_abort(f);
            return;
        }
        if (!f->stream || f->close_requested) return;
        f->reply_pos += (size_t)n;
        if (f->reply_pos < f->reply_len) return;
    }
    if (f->proof) {
        if (!f->sent_fin) {
            ssize_t n = xqc_stream_send(f->stream, f->reply, 0, 1);
            if (n == -XQC_EAGAIN) return;
            if (n < 0) { m_fail(f->peer, OB_REMOTE_EQUIC, "proof stream send failed"); m_abort(f); return; }
            f->sent_fin = 1;
        }
        if (f->proof_reply_ready && f->peer->is_server) {
            f->phase = M_ACTIVE;
            if (!f->peer->ready) ob_peer_mark_ready(f->peer);
        }
    } else if (f->phase == M_REPLY) {
        if (f->reject_after_reply) { m_abort(f); return; }
        f->acked = 1; f->phase = M_ACTIVE;
    }
}
static int m_header_check(struct ob_flow *f)
{
    unsigned char *v = f->control;
    size_t size = m_u16(v + 6);
    if (memcmp(v, "OBM1", 4) || size > OB_MAX_HOST + 2U) return -1;
    if (f->proof) {
        if (v[4] != M_PROOF || v[5] || size != 32 || m_u64(v + 8)) return -1;
    } else if (f->local) {
        unsigned int kind = f->waiting_resume ? M_RESUME_ACK : M_ACK;
        size_t expected = f->waiting_resume ? M_RESUME_SIZE : 4;
        if (v[4] != kind || v[5] != (unsigned int)f->protocol ||
            size != expected || m_u64(v + 8) != f->id) return -1;
    } else {
        if (!f->peer->ready || !f->peer->proof_ready ||
            (v[4] != M_OPEN && v[4] != M_RESUME) ||
            (v[5] != OB_REMOTE_TCP && v[5] != OB_REMOTE_UDP) || size < 3) return -1;
        uint64_t id = m_u64(v + 8);
        if (!id || (id & 1U) != (unsigned int)(f->peer->is_server != 0)) return -1;
        if (v[4] == M_RESUME) {
            if (f->peer->wire_version != 2 || v[5] != OB_REMOTE_TCP || size != M_RESUME_SIZE)
                return -1;
        } else {
            if (m_find(f->peer, id) ||
                m_data_flow_count(f->peer) >= m_limit(f->peer->max_flows, 128U, M_FLOWS)) return -1;
            f->transient = 0;
        }
        f->id = id; f->protocol = (ob_remote_protocol)v[5];
        f->wire_version = f->peer->wire_version;
    }
    f->control_need = M_HEADER + size;
    return 0;
}
static int m_control_done(struct ob_flow *f)
{
    ob_remote_peer *p = f->peer;
    if (f->proof) {
        unsigned char expected[32];
        if (ob_connection_proof(p, !p->is_server, expected) ||
            CRYPTO_memcmp(expected, f->control + M_HEADER, 32)) {
            m_fail(p, OB_REMOTE_EAUTH, "connection channel proof mismatch"); return -1;
        }
        if (p->is_server) {
            m_header(f->reply, M_PROOF, 0, 32, 0);
            if (ob_connection_proof(p, 1, f->reply + M_HEADER)) {
                m_fail(p, OB_REMOTE_EAUTH, "connection channel proof unavailable"); return -1;
            }
            f->reply_len = M_HEADER + 32; f->reply_pos = 0;
            f->proof_reply_ready = 1; f->phase = M_REPLY;
        } else {
            f->proof_reply_ready = 1; f->phase = M_ACTIVE;
            ob_peer_mark_ready(p);
        }
        return 0;
    }
    if (f->control[4] == M_RESUME || f->control[4] == M_RESUME_ACK)
        return m_v2_control_done(f);
    if (f->local) {
        const unsigned char *r = f->control + M_HEADER;
        if (r[0] || r[1] || r[2] || r[3]) return -1;
        f->acked = 1; f->phase = M_ACTIVE; f->last_io = ob_now_us(); return 0;
    }
    char host[OB_MAX_HOST + 1];
    size_t len = f->control_need - M_HEADER - 2;
    uint16_t port = m_u16(f->control + M_HEADER);
    memcpy(host, f->control + M_HEADER + 2, len); host[len] = '\0';
    if (!port || !m_host_valid(host, len)) return -1;
    int rc = m_resolve_start(f, host, port);
    if (rc) m_ack(f, rc);
    return 0;
}
static void m_resolve_tick(struct ob_flow *f)
{
    struct m_state *s = f->peer->mapping_private;
    struct m_resolve *job = f->resolve;
    if (!job) { m_abort(f); return; }
    pthread_mutex_lock(&s->resolver_mu);
    if (job->state != 2) { pthread_mutex_unlock(&s->resolver_mu); return; }
    int rc = job->result;
    struct sockaddr_storage target = job->address;
    socklen_t target_len = job->address_len;
    job->detached = 1; f->resolve = NULL;
    pthread_mutex_unlock(&s->resolver_mu);
    if (rc) { m_ack(f, rc); return; }
    if ((target.ss_family != AF_INET && target.ss_family != AF_INET6) ||
        target_len > sizeof(target)) { m_ack(f, OB_REMOTE_EIO); return; }
    if (f->protocol == OB_REMOTE_TCP && m_tcp_buffers(f)) { m_ack(f, OB_REMOTE_ENOMEM); return; }
    f->fd = m_socket(target.ss_family, f->protocol == OB_REMOTE_TCP ? SOCK_STREAM : SOCK_DGRAM);
    if (f->fd < 0) { m_ack(f, OB_REMOTE_EIO); return; }
    rc = connect(f->fd, (const struct sockaddr *)&target, target_len);
    if (rc == 0) m_ack(f, 0);
    else if (errno == EINPROGRESS && f->protocol == OB_REMOTE_TCP) f->phase = M_CONNECTING;
    else m_ack(f, OB_REMOTE_EIO);
}
static void m_stream_read(struct ob_flow *f)
{
    if (!f || !f->stream || f->phase == M_DEAD || f->close_requested) return;
    if (f->phase == M_CONTROL) {
        for (unsigned int step = 0; step < 2; ++step) {
            uint8_t fin = 0;
            ssize_t n = xqc_stream_recv(f->stream, f->control + f->control_len,
                                        f->control_need - f->control_len, &fin);
#ifdef OB_MAPPING_TRACE
            if (f->trace_read++ < 16)
                M_TRACE("mapping control-read role=%d flow=%llu phase=%d pos=%zu need=%zu n=%zd fin=%u\n",
                        f->peer->is_server, (unsigned long long)f->id,
                        f->phase, f->control_len, f->control_need, n, fin);
#endif
            if (n == -XQC_EAGAIN) return;
            if (n < 0) { M_TRACE("mapping control-read error=%zd\n", n); m_abort(f); return; }
            f->control_len += (size_t)n;
            if (f->control_len == M_HEADER && f->control_need == M_HEADER && m_header_check(f)) {
                if (f->proof) m_fail(f->peer, OB_REMOTE_EPROTOCOL, "invalid connection proof frame");
                m_abort(f); return;
            }
            if (fin && f->control_len != f->control_need) { m_abort(f); return; }
            if (f->control_len == f->control_need) {
                if (m_control_done(f)) { m_abort(f); return; }
                if (fin) f->stream_eof = 1;
                /* A target may immediately half-close its write side. Its
                 * successful TCP ACK can share the final stream frame; this
                 * FIN must not reset the still-usable client write direction. */
                if (fin && !f->proof &&
                    !(f->local && f->protocol == OB_REMOTE_TCP && f->acked)) {
                    m_abort(f); return;
                }
                m_reply_flush(f); break;
            }
            if (fin || n == 0) return;
        }
    }
    if (f->phase != M_ACTIVE) return;
    if (!f->proof && f->protocol == OB_REMOTE_TCP && f->wire_version == 2) {
        m_v2_read(f); return;
    }
    if (f->stream_eof) return;
    if (f->proof || f->protocol == OB_REMOTE_UDP) {
        unsigned char extra;
        uint8_t fin = 0;
        ssize_t n = xqc_stream_recv(f->stream, &extra, 1, &fin);
        if (n == -XQC_EAGAIN) return;
        if (n < 0 || n > 0) {
            if (f->proof) m_fail(f->peer, OB_REMOTE_EPROTOCOL, "unexpected proof stream payload");
            m_abort(f); return;
        }
        if (fin) { f->stream_eof = 1; if (!f->proof) m_abort(f); }
        return;
    }
    if (f->rx_pos == f->rx_len) f->rx_pos = f->rx_len = 0;
    else if (f->rx_pos && f->rx_len == OB_STREAM_BUFFER) {
        memmove(f->rx, f->rx + f->rx_pos, f->rx_len - f->rx_pos);
        f->rx_len -= f->rx_pos; f->rx_pos = 0;
    }
    size_t room = OB_STREAM_BUFFER - f->rx_len;
    if (!room) return;
    if (room > M_IO_BUDGET) room = M_IO_BUDGET;
    uint8_t fin = 0;
    ssize_t n = xqc_stream_recv(f->stream, f->rx + f->rx_len, room, &fin);
    if (n == -XQC_EAGAIN) return;
    if (n < 0) { m_abort(f); return; }
    f->rx_len += (size_t)n;
    if (n) f->last_io = ob_now_us();
    if (fin) f->stream_eof = 1;
}
static void m_tcp_write(struct ob_flow *f)
{
    if (f->wire_version == 2) { m_v2_write(f); return; }
    if (!f->stream || f->close_requested || f->phase != M_ACTIVE ||
        !f->acked) return;
    if (f->tx_pos < f->tx_len) {
        size_t count = f->tx_len - f->tx_pos;
        if (count > M_IO_BUDGET) count = M_IO_BUDGET;
        ssize_t n = xqc_stream_send(f->stream, f->tx + f->tx_pos, count, 0);
        if (n == -XQC_EAGAIN) return;
        if (n < 0) { m_abort(f); return; }
        if (!f->stream || f->close_requested) return;
        f->tx_pos += (size_t)n;
    }
    if (f->tx_pos == f->tx_len) {
        f->tx_pos = f->tx_len = 0;
        if (f->socket_eof && !f->sent_fin && f->stream) {
            f->sent_fin = 1;
            ssize_t n = xqc_stream_send(f->stream, f->control, 0, 1);
            if (n == -XQC_EAGAIN) { f->sent_fin = 0; return; }
            if (n < 0) { f->sent_fin = 0; m_abort(f); return; }
        }
    }
}
static void m_tcp_tick(struct ob_flow *f)
{
    if (f->wire_version == 2) { m_v2_tick(f); return; }
    if (f->phase != M_ACTIVE || !f->acked || f->fd < 0) return;
    struct pollfd pollfd = { .fd = f->fd, .events = 0, .revents = 0 };
    if (!f->socket_eof && f->tx_len < OB_STREAM_BUFFER) pollfd.events |= POLLIN;
    if (f->rx_pos < f->rx_len) pollfd.events |= POLLOUT;
    int rc = poll(&pollfd, 1, 0);
    if (rc < 0 && errno != EINTR) { m_abort(f); return; }
    if (pollfd.revents & (POLLERR | POLLNVAL)) { m_abort(f); return; }
    if ((pollfd.revents & POLLOUT) && f->rx_pos < f->rx_len) {
        size_t count = f->rx_len - f->rx_pos;
        if (count > M_IO_BUDGET) count = M_IO_BUDGET;
        ssize_t n = send(f->fd, f->rx + f->rx_pos, count, MSG_NOSIGNAL);
        if (n < 0 && !m_again()) { m_abort(f); return; }
        if (n > 0) { f->rx_pos += (size_t)n; f->last_io = ob_now_us(); }
        if (f->rx_pos == f->rx_len) f->rx_pos = f->rx_len = 0;
    }
    if (f->stream_eof && f->rx_pos == f->rx_len && !f->socket_shutdown) {
        (void)shutdown(f->fd, SHUT_WR); f->socket_shutdown = 1;
    }
    if ((pollfd.revents & (POLLIN | POLLHUP)) && !f->socket_eof) {
        if (f->tx_pos == f->tx_len) f->tx_pos = f->tx_len = 0;
        else if (f->tx_pos && f->tx_len == OB_STREAM_BUFFER) {
            memmove(f->tx, f->tx + f->tx_pos, f->tx_len - f->tx_pos);
            f->tx_len -= f->tx_pos; f->tx_pos = 0;
        }
        size_t room = OB_STREAM_BUFFER - f->tx_len;
        if (room > M_IO_BUDGET) room = M_IO_BUDGET;
        if (room) {
            ssize_t n = recv(f->fd, f->tx + f->tx_len, room, 0);
            if (n < 0 && !m_again()) { m_abort(f); return; }
            if (n == 0) f->socket_eof = 1;
            if (n > 0) { f->tx_len += (size_t)n; f->last_io = ob_now_us(); }
        }
    }
    m_tcp_write(f);
    if (f->stream_eof && f->socket_eof && f->sent_fin && f->rx_pos == f->rx_len && f->fd >= 0) {
        close(f->fd); f->fd = -1;
    }
}
#include "mapping_v2.inc"

static void m_udp_enqueue(struct ob_flow *f, const unsigned char *data, size_t len)
{
    if ((len && !data) || len > M_UDP_MAX || f->udp_count >= M_UDP_QUEUE ||
        f->next_packet == UINT64_MAX) {
        if (len == M_UDP_MAX) U_TRACE("udp enqueue-filter role=%d flow=%llu len=%zu queue=%u sequence=%llu\n", f->peer->is_server, (unsigned long long)f->id, len, f->udp_count, (unsigned long long)f->next_packet);
#ifdef OB_UDP_COUNTERS
        if (len == M_UDP_MAX) UC_ADD(f->peer, enq_denied, 1U);
#endif
        return;
    }
    struct m_udp_packet *q = m_alloc(f->peer, sizeof(*q) + len);
    if (!q) {
        U_TRACE("udp enqueue-denied role=%d flow=%llu len=%zu queue=%u\n", f->peer->is_server, (unsigned long long)f->id, len, f->udp_count);
#ifdef OB_UDP_COUNTERS
        if (len == M_UDP_MAX) UC_ADD(f->peer, enq_denied, 1U);
#endif
        return;
    }
    q->id = ++f->next_packet; q->created = ob_now_us(); q->len = len;
    if (len) memcpy(q->data, data, len);
    if (f->udp_tail) f->udp_tail->next = q; else f->udp_head = q;
    f->udp_tail = q; ++f->udp_count; f->last_io = q->created;
#ifdef OB_UDP_COUNTERS
    if (len == M_UDP_MAX) {
        UC_ADD(f->peer, enq_ok, 1U); UC_SET(f->peer, send_flow, f->id); UC_SET(f->peer, send_packet, q->id);
    }
#endif
    if (len == M_UDP_MAX) U_TRACE("udp enqueue role=%d flow=%llu packet=%llu len=%zu queue=%u time=%llu\n", f->peer->is_server, (unsigned long long)f->id, (unsigned long long)q->id, len, f->udp_count, (unsigned long long)q->created);
}
static void m_udp_pop(struct ob_flow *f)
{
    struct m_udp_packet *q = f->udp_head;
    f->udp_head = q->next;
    if (!f->udp_head) f->udp_tail = NULL;
    --f->udp_count; m_free(f->peer, q, sizeof(*q) + q->len);
}
static void m_udp_flush(struct ob_flow *f, unsigned int *budget)
{
    if (f->phase != M_ACTIVE || f->close_requested || !f->stream ||
        !f->acked || !f->peer->ready) return;
    unsigned int per_flow = 8;
    while (f->udp_head && *budget && per_flow) {
        struct m_udp_packet *q = f->udp_head;
        if (m_expired(ob_now_us(), q->created, M_PACKET_TTL_US)) {
#ifdef OB_UDP_COUNTERS
            if (q->len == M_UDP_MAX) { UC_ADD(f->peer, ttl_expired, 1U); UC_SET(f->peer, ttl_offset, q->offset); }
#endif
            if (q->len == M_UDP_MAX) U_TRACE("udp expire role=%d flow=%llu packet=%llu offset=%zu total=%zu age_us=%llu\n", f->peer->is_server, (unsigned long long)f->id, (unsigned long long)q->id, q->offset, q->len, (unsigned long long)(ob_now_us() - q->created));
            m_udp_pop(f); continue;
        }
        if (xqc_datagram_get_mss(f->peer->conn) < M_DHEADER + M_FRAGMENT) {
#ifdef OB_UDP_COUNTERS
            if (q->len == M_UDP_MAX) UC_ADD(f->peer, mss_drop, 1U);
#endif
            m_udp_pop(f); continue;
        }
        unsigned char wire[M_DHEADER + M_FRAGMENT];
        size_t len = q->len - q->offset;
        if (len > M_FRAGMENT) len = M_FRAGMENT;
        memcpy(wire, "OBD1", 4); m_put64(wire + 4, f->id); m_put64(wire + 12, q->id);
        m_put16(wire + 20, q->len); m_put16(wire + 22, q->offset);
        m_put16(wire + 24, len); m_put16(wire + 26, 0);
        if (len) memcpy(wire + M_DHEADER, q->data + q->offset, len);
        uint64_t dgram_id = 0;
        int rc = xqc_datagram_send(f->peer->conn, wire, M_DHEADER + len,
                                   &dgram_id, XQC_DATA_QOS_NORMAL);
#ifdef OB_UDP_COUNTERS
        if (q->len == M_UDP_MAX) {
            UC_ADD(f->peer, send_attempts, 1U); UC_SET(f->peer, last_rc, rc);
            if (rc >= 0) {
                unsigned int fragment = (unsigned int)(q->offset / M_FRAGMENT);
                UC_ADD(f->peer, admitted, 1U);
                UC_OR(f->peer, sent_bits, fragment / 64U, UINT64_C(1) << (fragment % 64U));
                UC_SET(f->peer, sent_ids[fragment], dgram_id);
            } else if (rc == -XQC_EAGAIN) UC_ADD(f->peer, eagain, 1U);
            else UC_ADD(f->peer, negative, 1U);
        }
#endif
        if (q->len == M_UDP_MAX) U_TRACE("udp send role=%d flow=%llu packet=%llu offset=%zu size=%zu age_us=%llu rc=%d dgram=%llu\n", f->peer->is_server, (unsigned long long)f->id, (unsigned long long)q->id, q->offset, len, (unsigned long long)(ob_now_us() - q->created), rc, (unsigned long long)dgram_id);
        if (f->close_requested || !f->stream) return;
        if (rc == -XQC_EAGAIN) return;
        --*budget; --per_flow;
        if (rc < 0) { m_udp_pop(f); continue; }
        q->offset += len;
        if (q->offset == q->len) m_udp_pop(f);
    }
}
static void m_udp_target_read(struct ob_flow *f)
{
    if (f->local || f->fd < 0 || f->phase != M_ACTIVE) return;
    struct m_state *s = f->peer->mapping_private;
    if (!s) return;
    for (unsigned int i = 0; i < 4; ++i) {
        ssize_t n = recv(f->fd, s->udp, sizeof(s->udp), 0);
        if (n < 0) { if (!m_again()) m_abort(f); return; }
#ifdef OB_UDP_COUNTERS
        if ((size_t)n == M_UDP_MAX) { UC_ADD(f->peer, target_reads, 1U); UC_SET(f->peer, target_n, (uint64_t)n); }
#endif
        if ((size_t)n <= M_UDP_MAX) m_udp_enqueue(f, s->udp, (size_t)n);
    }
}
static int m_source_equal(const struct sockaddr_storage *a,
                           const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)a, *y = (const struct sockaddr_in *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a, *y = (const struct sockaddr_in6 *)b;
        return x->sin6_port == y->sin6_port && x->sin6_scope_id == y->sin6_scope_id &&
               memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0;
    }
    return 0;
}
static struct ob_flow *m_local_flow(ob_remote_map *map, int fd,
                                    const struct sockaddr_storage *source,
                                    socklen_t source_len)
{
    ob_remote_peer *p = map->peer;
    if (m_data_flow_count(p) >= m_limit(p->max_flows, 128U, M_FLOWS)) return NULL;
    struct ob_flow *f = m_flow_new(p);
    if (!f) return NULL;
    f->local = 1; f->protocol = map->protocol; f->map = map;
    f->wire_version = p->wire_version;
    if (p->next_flow_id >= UINT64_MAX / 2U) { m_flow_free(f); return NULL; }
    f->id = (++p->next_flow_id << 1) | (uint64_t)!p->is_server;
    if (source) { f->source = *source; f->source_len = source_len; }
    if (f->protocol == OB_REMOTE_TCP && m_tcp_buffers(f)) { m_flow_free(f); return NULL; }
    if (f->protocol == OB_REMOTE_TCP && (!p->ready || !p->proof_ready ||
        atomic_load(&p->attempt_stop) || !p->conn)) {
        f->pending_open = f->suspended = 1; f->phase = M_ACTIVE;
        f->grace_deadline_us = ob_now_us() + (uint64_t)p->timeout_ms * 1000;
        f->fd = fd;
        return f;
    }
    /* The caller retains fd ownership until allocation and stream creation succeed. */
    size_t len = strlen(map->target_host);
    m_header(f->reply, M_OPEN, (unsigned int)f->protocol, len + 2, f->id);
    m_put16(f->reply + M_HEADER, map->target_port);
    memcpy(f->reply + M_HEADER + 2, map->target_host, len);
    f->reply_len = M_HEADER + 2 + len;
    if (m_stream_open(f)) { m_flow_free(f); return NULL; }
    f->fd = fd;
    M_TRACE("mapping local-open role=%d flow=%llu sid=%llu replylen=%zu protocol=%d\n",
            p->is_server, (unsigned long long)f->id,
            (unsigned long long)xqc_stream_id(f->stream), f->reply_len, f->protocol);
    m_reply_flush(f);
    return f;
}
static void m_map_tick(ob_remote_map *map, unsigned int *budget)
{
    if (map->closed || map->fd < 0) return;
    if (map->protocol == OB_REMOTE_TCP) {
        for (unsigned int i = 0; i < 16 && *budget; ++i) {
            int fd = accept(map->fd, NULL, NULL);
            if (fd < 0) return;
            --*budget;
            if (m_nonblock(fd) || !m_local_flow(map, fd, NULL, 0)) close(fd);
        }
        return;
    }
    struct m_state *s = map->peer->mapping_private;
    for (unsigned int i = 0; i < 16 && *budget; ++i) {
        struct sockaddr_storage source;
        socklen_t len = sizeof(source);
        memset(&source, 0, sizeof(source));
        ssize_t n = recvfrom(map->fd, s->udp, sizeof(s->udp), 0, (struct sockaddr *)&source, &len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) map->udp_draining = 0;
            return;
        }
        --*budget;
        if (map->udp_draining) continue;
        if ((size_t)n > M_UDP_MAX || len > sizeof(source) ||
            (source.ss_family != AF_INET && source.ss_family != AF_INET6)) continue;
        struct ob_flow *f;
        for (f = map->peer->flows; f; f = f->next)
            if (f->map == map && f->protocol == OB_REMOTE_UDP && f->phase != M_DEAD &&
                m_source_equal(&f->source, &source)) break;
        if (!f) f = m_local_flow(map, -1, &source, len);
        if (f && f->phase != M_DEAD) m_udp_enqueue(f, s->udp, (size_t)n);
    }
}
static void m_assembly_drop(struct ob_flow *f, struct m_assembly *a)
{
#ifdef OB_UDP_COUNTERS
    if (a->total == M_UDP_MAX && a->received != a->total) {
        UC_ADD(f->peer, incomplete_drops, 1U); UC_SET(f->peer, drop_received, a->received);
        UC_SET(f->peer, drop_bits[0], a->bits[0]); UC_SET(f->peer, drop_bits[1], a->bits[1]);
    }
#endif
    if (a->total == M_UDP_MAX) U_TRACE("udp assembly-drop role=%d flow=%llu packet=%llu received=%zu total=%zu bits=%016llx/%016llx gap_us=%llu\n", f->peer->is_server, (unsigned long long)f->id, (unsigned long long)a->id, a->received, a->total, (unsigned long long)a->bits[0], (unsigned long long)a->bits[1], (unsigned long long)(ob_now_us() - a->updated));
    m_free(f->peer, a->data, a->total ? a->total : 1U); memset(a, 0, sizeof(*a));
}
static void m_udp_read(xqc_connection_t *conn, void *data_user,
                        const void *data, size_t len, uint64_t timestamp)
{
    (void)conn; (void)timestamp;
    ob_remote_peer *p = data_user;
    if (!p || p->conn != conn || !p->ready || !p->proof_ready ||
        atomic_load(&p->attempt_stop) || p->transport_detaching || len < M_DHEADER) return;
    const unsigned char *v = data;
    if (memcmp(v, "OBD1", 4) || m_u16(v + 26)) return;
    uint64_t id = m_u64(v + 4), packet = m_u64(v + 12);
    size_t total = m_u16(v + 20), offset = m_u16(v + 22), size = m_u16(v + 24);
    if (!id || !packet || total > M_UDP_MAX || offset > total ||
        size > M_FRAGMENT || size != len - M_DHEADER || offset % M_FRAGMENT ||
        size != (total - offset > M_FRAGMENT ? M_FRAGMENT : total - offset) ||
        (total && offset == total)) return;
    struct ob_flow *f = m_find(p, id);
    if (!f || f->phase != M_ACTIVE || !f->acked || f->close_requested ||
        f->protocol != OB_REMOTE_UDP || (f->local && !f->map)) return;
    if (packet > f->receive_high) {
        uint64_t shift = packet - f->receive_high;
        f->delivered = shift >= 64 ? 0 : f->delivered << shift;
        f->receive_high = packet;
    }
    uint64_t behind = f->receive_high - packet;
    if (behind >= 64 || (f->delivered & (UINT64_C(1) << behind))) return;
    struct m_assembly *a = NULL, *empty = NULL;
    uint64_t now = ob_now_us();
    for (unsigned int i = 0; i < M_REASSEMBLY; ++i) {
        struct m_assembly *slot = &f->assembly[i];
        if (slot->data && (m_expired(now, slot->updated, M_PACKET_US) ||
            (slot->id <= f->receive_high && f->receive_high - slot->id >= 64))) m_assembly_drop(f, slot);
        if (slot->data && slot->id == packet) a = slot;
        if (!slot->data && !empty) empty = slot;
    }
    if (!a) {
        if (!empty) return;
        a = empty; a->data = m_alloc(p, total ? total : 1U);
        if (!a->data) return;
        a->id = packet; a->total = total;
    }
    if (a->total != total) { m_assembly_drop(f, a); f->delivered |= UINT64_C(1) << behind; return; }
    unsigned int fragment = (unsigned int)(offset / M_FRAGMENT);
    unsigned int word = fragment / 64U;
    uint64_t bit = UINT64_C(1) << (fragment % 64U);
    if (a->bits[word] & bit) {
        if (size && memcmp(a->data + offset, v + M_DHEADER, size)) {
            m_assembly_drop(f, a); f->delivered |= UINT64_C(1) << behind;
        }
        return;
    }
    if (size) memcpy(a->data + offset, v + M_DHEADER, size);
    a->bits[word] |= bit; a->received += size; a->updated = now;
#ifdef OB_UDP_COUNTERS
    if (total == M_UDP_MAX) {
        UC_SET(p, recv_flow, f->id); UC_SET(p, recv_packet, packet); UC_ADD(p, recv_fragments, 1U);
        UC_ADD(p, recv_bytes, size); UC_OR(p, recv_bits, word, bit);
    }
#endif
    if (total == M_UDP_MAX) U_TRACE("udp recv role=%d flow=%llu packet=%llu offset=%zu size=%zu received=%zu bits=%016llx/%016llx time=%llu\n", p->is_server, (unsigned long long)f->id, (unsigned long long)packet, offset, size, a->received, (unsigned long long)a->bits[0], (unsigned long long)a->bits[1], (unsigned long long)now);
    if (a->received != total) return;
    /* Only a complete packet reaches a real socket, exactly once. Socket
     * EAGAIN and ICMP errors drop UDP; they never cause reliable retransmit. */
    ssize_t n;
    if (f->local) n = sendto(f->map->fd, a->data, total, MSG_NOSIGNAL,
                              (const struct sockaddr *)&f->source, f->source_len);
    else n = send(f->fd, a->data, total, MSG_NOSIGNAL);
#ifdef OB_UDP_COUNTERS
    if (total == M_UDP_MAX) {
        UC_ADD(p, deliveries, 1U); UC_SET(p, delivery_n, n); UC_SET(p, delivery_errno, n < 0 ? errno : 0);
    }
#endif
    if (total == M_UDP_MAX) U_TRACE("udp deliver role=%d flow=%llu packet=%llu total=%zu n=%zd errno=%d time=%llu\n", p->is_server, (unsigned long long)f->id, (unsigned long long)packet, total, n, n < 0 ? errno : 0, (unsigned long long)now);
    if (n >= 0) f->last_io = now;
    else if (!m_again() && !f->local) f->close_requested = 1;
    f->delivered |= UINT64_C(1) << behind;
    m_assembly_drop(f, a);
}
static xqc_int_t m_create(xqc_stream_t *stream, void *data)
{
    if (data) {
        struct ob_flow *f = data;
        f->stream = stream; f->stream_generation = f->peer->transport_generation;
        return 0;
    }
    ob_remote_peer *p = xqc_get_conn_user_data_by_stream(stream);
    if (!p || atomic_load(&p->stop) || atomic_load(&p->attempt_stop) ||
        p->transport_detaching) return -1;
    int proof = !p->ready;
    M_TRACE("mapping incoming role=%d sid=%llu proof=%d tls=%d\n", p->is_server,
            (unsigned long long)xqc_stream_id(stream), proof, p->tls_ready);
    if (xqc_stream_get_direction(stream) != XQC_STREAM_BIDI ||
        (proof && (!p->is_server || !p->tls_ready || xqc_stream_id(stream) != 0))) {
        if (proof) m_fail(p, OB_REMOTE_EPROTOCOL, "first stream must carry client channel proof");
        return -1;
    }
    struct m_state *s = m_state_get(p);
    if (!s || (proof && s->proof_started)) return -1;
    /* The extra context allowance belongs to authentication, never an extra
     * forwarding socket after the proof stream has been reclaimed. */
    struct ob_flow *f = m_flow_new(p);
    if (!f) return -1;
    f->proof = proof; f->stream = stream; f->transient = !proof;
    f->stream_generation = p->transport_generation;
    if (proof) s->proof_started = 1;
    xqc_stream_set_user_data(stream, f); return 0;
}
static xqc_int_t m_read(xqc_stream_t *stream, void *data)
{
    (void)stream; (void)data;
    /* xqc_stream_send can synchronously run engine callbacks. Only the
     * regular tick advances application state, after that API has returned. */
    return 0;
}
static xqc_int_t m_write(xqc_stream_t *stream, void *data)
{
    (void)stream; (void)data;
    return 0;
}
static xqc_int_t m_close(xqc_stream_t *stream, void *data)
{
    (void)stream;
    struct ob_flow *f = data;
    if (!f || f->stream != stream ||
        f->stream_generation != f->peer->transport_generation) return 0;
    M_TRACE("mapping close role=%d flow=%llu phase=%d eof=%d/%d fin=%d stop=%d\n",
            f->peer->is_server, (unsigned long long)f->id, f->phase,
            f->socket_eof, f->stream_eof, f->sent_fin, atomic_load(&f->peer->stop));
    f->stream = NULL;
    if (f->peer->transport_detaching || atomic_load(&f->peer->attempt_stop)) return 0;
    if (f->proof && !f->peer->ready && !f->proof_reply_ready &&
        !atomic_load(&f->peer->stop))
        m_fail(f->peer, OB_REMOTE_EAUTH, "connection proof stream closed prematurely");
    /* QUIC can finish before the nonblocking local socket drains its last
     * bytes. Keep this bounded context until those bytes and FIN are applied. */
    if (!f->proof && f->protocol == OB_REMOTE_TCP && f->phase == M_ACTIVE &&
        f->stream_eof && f->sent_fin && !f->close_requested &&
        !atomic_load(&f->peer->stop)) return 0;
    /* Do not free here: xqc_stream_send/datagram_send may have invoked this
     * callback while the engine tick still holds this context or its next
     * list entry. Reclamation belongs to the next regular tick/cleanup. */
    f->close_requested = 1;
    return 0;
}
static void m_reset(xqc_stream_t *stream, xqc_int_t error, void *data)
{
    (void)stream; (void)error;
    struct ob_flow *f = data;
    if (!f || f->stream != stream ||
        f->stream_generation != f->peer->transport_generation ||
        f->peer->transport_detaching || atomic_load(&f->peer->attempt_stop)) return;
    M_TRACE("mapping reset role=%d flow=%llu error=%d\n", f->peer->is_server,
            (unsigned long long)f->id, error);
    if (f->proof && !f->peer->ready) m_fail(f->peer, OB_REMOTE_EAUTH, "connection proof stream reset");
    f->close_requested = 1;
}
static void m_udp_write(xqc_connection_t *conn, void *data)
{
    (void)conn; (void)data;
    /* The regular engine tick applies the global DATAGRAM work budget. */
}
static xqc_int_t m_udp_lost(xqc_connection_t *conn, uint64_t id, void *data)
{
    (void)conn; (void)id; (void)data;
#if defined(OB_UDP_TRACE) || defined(OB_UDP_COUNTERS)
    ob_remote_peer *p = data;
#endif
#ifdef OB_UDP_TRACE
    if (p) U_TRACE("udp lost role=%d dgram=%llu time=%llu\n", p->is_server, (unsigned long long)id, (unsigned long long)ob_now_us());
#endif
#ifdef OB_UDP_COUNTERS
    if (p) {
        uint64_t index = atomic_fetch_add_explicit(&UC_GET(p)->lost_count, 1U, memory_order_relaxed);
        if (index < 128U) UC_SET(p, lost_ids[index], id);
    }
#endif
    return 0;
}
void ob_mapping_callbacks(xqc_app_proto_callbacks_t *callbacks)
{
    memset(&callbacks->stream_cbs, 0, sizeof(callbacks->stream_cbs));
    memset(&callbacks->dgram_cbs, 0, sizeof(callbacks->dgram_cbs));
    callbacks->stream_cbs.stream_create_notify = m_create;
    callbacks->stream_cbs.stream_read_notify = m_read;
    callbacks->stream_cbs.stream_write_notify = m_write;
    callbacks->stream_cbs.stream_close_notify = m_close;
    callbacks->stream_cbs.stream_closing_notify = m_reset;
    callbacks->dgram_cbs.datagram_read_notify = m_udp_read;
    callbacks->dgram_cbs.datagram_write_notify = m_udp_write;
    callbacks->dgram_cbs.datagram_lost_notify = m_udp_lost;
}
void ob_mapping_handshake(ob_remote_peer *p)
{
    if (!p->conn || !p->tls_ready) return;
    xqc_datagram_set_user_data(p->conn, p);
    struct m_state *s = m_state_get(p);
    if (!s) { m_fail(p, OB_REMOTE_ENOMEM, "mapping state allocation failed"); return; }
    if (p->is_server || s->proof_started) return;
    struct ob_flow *f = m_flow_new(p);
    if (!f) { m_fail(p, OB_REMOTE_ENOMEM, "proof stream allocation failed"); return; }
    f->local = f->proof = 1; s->proof_started = 1;
    m_header(f->reply, M_PROOF, 0, 32, 0);
    if (ob_connection_proof(p, 0, f->reply + M_HEADER) || m_stream_open(f)) {
        m_fail(p, OB_REMOTE_EAUTH, "connection proof unavailable"); m_flow_free(f); return;
    }
    if (xqc_stream_id(f->stream) != 0) {
        m_fail(p, OB_REMOTE_EPROTOCOL, "proof must be the first QUIC stream"); m_abort(f); return;
    }
    f->reply_len = M_HEADER + 32; m_reply_flush(f);
}
void ob_mapping_tick(ob_remote_peer *p)
{
    if (atomic_load(&p->stop)) { m_stop_io(p); return; }
    if (atomic_load(&p->attempt_stop)) return;
    ob_mapping_recovery_tick(p, ob_now_us());
    struct m_state *s = m_state_get(p);
    if (!s) return;
    uint64_t now = ob_now_us();
    if (p->ready && !atomic_load(&p->stop) && p->maps) {
        unsigned int packet_budget = 128;
        size_t start = s->map_rotation % p->map_count;
        s->map_rotation += 8;
        ob_remote_map *map = p->maps;
        for (size_t i = 0; i < start; ++i) map = map->next;
        for (size_t i = 0; i < p->map_count && packet_budget; ++i) {
            m_map_tick(map, &packet_budget);
            map = map->next ? map->next : p->maps;
        }
    }
    for (struct ob_flow *f = p->flows, *next; f; f = next) {
        next = f->next;
        if (atomic_load(&p->attempt_stop)) return;
        if (f->close_requested || atomic_load(&p->stop)) {
            m_abort(f);
            if (!f->stream) m_flow_free(f);
            continue;
        }
        if (f->phase == M_DEAD) {
            if (!f->stream) m_flow_free(f);
            continue;
        }
        if (f->suspended && !f->waiting_resume) continue;
        if (!f->proof && f->phase != M_ACTIVE && m_expired(now, f->created, M_SETUP_US)) {
            if (f->waiting_resume) {
                ob_peer_transport_fail_locked(p, OB_REMOTE_ETIMEOUT, "TCP resume handshake timed out");
                return;
            }
            m_abort(f); continue;
        }
        if (f->phase == M_RESOLVING) m_resolve_tick(f);
        if (f->phase == M_CONNECTING) {
            struct pollfd fd = { .fd = f->fd, .events = POLLOUT, .revents = 0 };
            if (poll(&fd, 1, 0) > 0 && fd.revents) {
                int error = 0; socklen_t len = sizeof(error);
                if (getsockopt(f->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) m_ack(f, OB_REMOTE_EIO);
                else m_ack(f, 0);
            }
        }
        m_reply_flush(f);
        m_stream_read(f);
        if (f->proof || f->phase == M_DEAD) continue;
        if (f->protocol == OB_REMOTE_TCP) {
            m_tcp_tick(f);
            if (!f->stream && f->fd < 0) m_flow_free(f);
        } else if (f->protocol == OB_REMOTE_UDP) {
            uint64_t idle = (uint64_t)(p->udp_idle_ms ? p->udp_idle_ms : 60000U) * 1000U;
            if (m_expired(now, f->last_io, idle)) { m_abort(f); continue; }
            for (unsigned int i = 0; i < M_REASSEMBLY; ++i)
                if (f->assembly[i].data &&
                    m_expired(now, f->assembly[i].updated, M_PACKET_US))
                    m_assembly_drop(f, &f->assembly[i]);
            m_udp_target_read(f);
        }
    }
    /* Rotate scheduling, not flow IDs: a busy newer UDP source must not starve
     * an older mapping/source indefinitely. No reliable fallback is used. */
    if (p->ready && !atomic_load(&p->stop) && p->flows) {
        unsigned int datagram_budget = 128;
        size_t start = s->udp_rotation % p->flow_count;
        s->udp_rotation += 16;
        struct ob_flow *f = p->flows;
        for (size_t i = 0; i < start; ++i) f = f->next;
        for (size_t i = 0; i < p->flow_count && datagram_budget; ++i) {
            if (f->protocol == OB_REMOTE_UDP) m_udp_flush(f, &datagram_budget);
            f = f->next ? f->next : p->flows;
        }
    }
    m_resolve_reap(p);
}
#include "mapping_recovery.inc"

/* Engine-owned immediate revocation: no resolver/HTTP joins and no freeing
 * public map handles. Final cleanup follows after the QUIC engine exits. */
static void m_stop_io(ob_remote_peer *p)
{
    for (ob_remote_map *map = p->maps; map; map = map->next) {
        if (map->fd >= 0) { close(map->fd); map->fd = -1; }
        map->closed = 1;
    }
    for (struct ob_flow *f = p->flows; f; f = f->next) {
        f->close_requested = 1; f->phase = M_DEAD;
        m_release_io(f);
    }
}
void ob_mapping_cleanup(ob_remote_peer *p)
{
    struct m_state *s = p->mapping_private;
    if (s) {
        pthread_mutex_lock(&s->resolver_mu);
        s->resolver_stop = 1; pthread_cond_broadcast(&s->resolver_cv);
        pthread_mutex_unlock(&s->resolver_mu);
        /* No worker takes peer->mu. Shutdown can wait for libc DNS, but the
         * live QUIC engine never waits for a resolver. ACL storage is owned by
         * the server and must outlive this final peer cleanup. */
        for (unsigned int i = 0; i < s->resolver_count; ++i)
            pthread_join(s->resolver_threads[i], NULL);
    }
    while (p->flows) {
        struct ob_flow *f = p->flows;
        p->flows = f->next; --p->flow_count;
        if (f->stream) { xqc_stream_set_user_data(f->stream, NULL); f->stream = NULL; }
        m_release_io(f); m_free(p, f, sizeof(*f));
    }
    while (p->maps) {
        ob_remote_map *map = p->maps; p->maps = map->next;
        if (map->fd >= 0) close(map->fd);
        free(map);
    }
    p->map_count = 0;
    if (s) {
        while (s->jobs) {
            struct m_resolve *job = s->jobs; s->jobs = job->next;
            m_free(p, job, sizeof(*job));
        }
        pthread_cond_destroy(&s->resolver_cv);
        pthread_mutex_destroy(&s->resolver_mu);
    }
    free(s); p->mapping_private = NULL;
}
static int m_portmap(ob_remote_peer *p, const char *local_host,
                      uint16_t local_port, const char *target_host,
                      uint16_t target_port, ob_remote_protocol protocol,
                      ob_remote_map **out, ob_remote_error *error)
{
    if (out) *out = NULL;
    size_t target_len = target_host ? strnlen(target_host, OB_MAX_HOST + 1U) : 0;
    if (!p || !out || !target_host || !target_port ||
        !m_host_valid(target_host, target_len))
        return ob_error(error, OB_REMOTE_EINVAL, 0, "invalid fixed mapping target");
    if (!local_host || !*local_host) local_host = "127.0.0.1";
    struct sockaddr_storage address;
    memset(&address, 0, sizeof(address));
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
    socklen_t address_len;
    if (inet_pton(AF_INET, local_host, &ipv4->sin_addr) == 1) {
        ipv4->sin_family = AF_INET; ipv4->sin_port = htons(local_port); address_len = sizeof(*ipv4);
    } else if (inet_pton(AF_INET6, local_host, &ipv6->sin6_addr) == 1) {
        ipv6->sin6_family = AF_INET6; ipv6->sin6_port = htons(local_port); address_len = sizeof(*ipv6);
    } else return ob_error(error, OB_REMOTE_EINVAL, 0, "local interface must be a numeric IPv4 or IPv6 address");
    pthread_mutex_lock(&p->mu);
    if (atomic_load(&p->stop) || (!p->managed && (!p->ready || !p->proof_ready))) {
        pthread_mutex_unlock(&p->mu);
        return ob_error(error, OB_REMOTE_ECLOSED, 0, "peer is not authenticated and ready");
    }
    if (p->map_count >= m_limit(p->max_maps, 32U, M_MAPS)) {
        pthread_mutex_unlock(&p->mu);
        return ob_error(error, OB_REMOTE_ELIMIT, 0, "mapping limit reached");
    }
    ob_remote_map *map = calloc(1, sizeof(*map));
    if (!map) { pthread_mutex_unlock(&p->mu); return ob_error(error, OB_REMOTE_ENOMEM, 0, "mapping allocation failed"); }
    map->fd = m_socket(address.ss_family, protocol == OB_REMOTE_TCP ? SOCK_STREAM : SOCK_DGRAM);
    int one = 1;
    if (map->fd >= 0 && address.ss_family == AF_INET6)
        (void)setsockopt(map->fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    if (map->fd < 0 || bind(map->fd, (const struct sockaddr *)&address, address_len) < 0 ||
        (protocol == OB_REMOTE_TCP && listen(map->fd, 64) < 0) ||
        getsockname(map->fd, (struct sockaddr *)&address, &address_len) < 0) {
        if (map->fd >= 0) close(map->fd);
        free(map); pthread_mutex_unlock(&p->mu);
        return ob_error(error, OB_REMOTE_EIO, 0, "cannot bind requested local interface and port");
    }
    map->peer = p; map->protocol = protocol; map->target_port = target_port;
    map->local_port = ntohs(address.ss_family == AF_INET ? ipv4->sin_port : ipv6->sin6_port);
    memcpy(map->target_host, target_host, target_len + 1);
    map->next = p->maps; p->maps = map; ++p->map_count; *out = map;
    pthread_mutex_unlock(&p->mu); ob_wake(p);
    if (error) memset(error, 0, sizeof(*error));
    return OB_REMOTE_OK;
}
int ob_remote_portmap_tcp(ob_remote_peer *p, const char *local_host,
                         uint16_t local_port, const char *target_host,
                         uint16_t target_port, ob_remote_map **out,
                         ob_remote_error *error)
{
    return m_portmap(p, local_host, local_port, target_host, target_port, OB_REMOTE_TCP, out, error);
}
int ob_remote_portmap_udp(ob_remote_peer *p, const char *local_host,
                         uint16_t local_port, const char *target_host,
                         uint16_t target_port, ob_remote_map **out,
                         ob_remote_error *error)
{
    return m_portmap(p, local_host, local_port, target_host, target_port, OB_REMOTE_UDP, out, error);
}
uint16_t ob_remote_map_local_port(const ob_remote_map *map)
{
    return map ? map->local_port : 0;
}
void ob_remote_map_close(ob_remote_map *map)
{
    if (!map) return;
    ob_remote_peer *p = map->peer;
    pthread_mutex_lock(&p->mu);
    ob_remote_map **at = &p->maps;
    while (*at && *at != map) at = &(*at)->next;
    if (*at) { *at = map->next; --p->map_count; }
    map->closed = 1;
    if (map->fd >= 0) { close(map->fd); map->fd = -1; }
    for (struct ob_flow *f = p->flows; f; f = f->next)
        if (f->map == map) { f->map = NULL; f->close_requested = 1; }
    free(map);
    pthread_mutex_unlock(&p->mu); ob_wake(p);
}
