/* Mapping version 2 is negotiated inside the PAKE-authenticated ICE envelope.
 * OPEN/ACK and channel proof retain the v1 encoding. Established TCP uses
 * OBM2, kind:u8, flags:u8, length:u16, flow:u64, offset:u64, payload.
 * DATA's offset is the first byte; ACK's offset is cumulative delivery to the
 * real socket (not QUIC receipt). FIN names the immutable final byte offset.
 * Stream FIN cannot stand in for application FIN after a transport restart.
 * All state and xquic calls below belong to the engine owner under peer->mu. */
static uint32_t m_u32(const unsigned char *v)
{
    return (uint32_t)v[0] << 24 | (uint32_t)v[1] << 16 |
           (uint32_t)v[2] << 8 | (uint32_t)v[3];
}
static void m_put32(unsigned char *v, uint32_t n)
{
    v[0] = (unsigned char)(n >> 24); v[1] = (unsigned char)(n >> 16);
    v[2] = (unsigned char)(n >> 8); v[3] = (unsigned char)n;
}
static uint64_t m_tx_next(const struct ob_flow *f)
{
    return f->tx_base + f->tx_len;
}
static int m_v2_ack(struct ob_flow *f, uint64_t offset, unsigned int flags)
{
    if (flags & ~1U || offset > m_tx_next(f) || offset > f->tx_sent_high) return -1;
    if (flags && (!f->socket_eof || offset != f->tx_final)) return -1;
    if (offset > f->tx_base) {
        size_t consumed = (size_t)(offset - f->tx_base);
        if (consumed > f->tx_pos) return -1;
        memmove(f->tx, f->tx + consumed, f->tx_len - consumed);
        f->tx_len -= consumed; f->tx_pos -= consumed; f->tx_base = offset;
    }
    if (flags) f->tx_fin_acked = 1;
    return 0;
}
static void m_resume_snapshot(struct ob_flow *f, unsigned char out[M_RESUME_SIZE], int result)
{
    memset(out, 0, M_RESUME_SIZE);
    m_put32(out, result < 0 ? (uint32_t)-result : (uint32_t)result);
    m_put32(out + 4, (f->socket_eof ? 1U : 0U) | (f->rx_fin_applied ? 2U : 0U));
    m_put64(out + 8, f->rx_commit); m_put64(out + 16, f->tx_base);
    m_put64(out + 24, m_tx_next(f)); m_put64(out + 32, f->tx_final);
}
static int m_resume_apply(struct ob_flow *f, const unsigned char in[M_RESUME_SIZE])
{
    uint32_t flags = m_u32(in + 4);
    uint64_t delivered = m_u64(in + 8), base = m_u64(in + 16);
    uint64_t next = m_u64(in + 24), final = m_u64(in + 32);
    M_TRACE("mapping resume-apply role=%d gen=%llu flow=%llu status=%u flags=%u remote_rx=%llu remote_tx=%llu/%llu remote_fin=%llu own_tx=%llu/%llu sent=%llu rx=%llu fin=%d/%d\n",
            f->peer->is_server, (unsigned long long)f->peer->transport_generation,
            (unsigned long long)f->id, m_u32(in), flags, (unsigned long long)delivered,
            (unsigned long long)base, (unsigned long long)next, (unsigned long long)final,
            (unsigned long long)f->tx_base, (unsigned long long)m_tx_next(f),
            (unsigned long long)f->tx_sent_high, (unsigned long long)f->rx_commit,
            f->socket_eof, f->rx_fin);
    if (m_u32(in) || flags & ~3U || base > next || base > f->rx_commit ||
        next < f->rx_commit || delivered < f->tx_base || delivered > m_tx_next(f) ||
        ((flags & 1U) && final != next) || (!(flags & 1U) && final) ||
        ((flags & 2U) && (!f->socket_eof || delivered != f->tx_final)) ||
        (f->rx_fin && (!(flags & 1U) || final != f->rx_final))) return -1;
    /* Fresh transport can acknowledge bytes sent on the previous attempt.
     * Validate the retained range before allowing the normal ACK helper. */
    f->tx_pos = f->tx_len;
    if (m_v2_ack(f, delivered, (flags & 2U) ? 1U : 0U)) return -1;
    f->tx_pos = 0;
    f->in_have = f->in_size = f->in_pos = f->out_pos = 0;
    f->out_kind = 0; f->rx_next = f->rx_commit;
    f->rx_len = f->rx_pos = 0;
    if (flags & 1U) { f->rx_fin = 1; f->rx_final = final; }
    f->sent_fin = f->tx_fin_acked; f->ack_dirty = 1;
    return 0;
}
static int m_v2_control_done(struct ob_flow *f)
{
    const unsigned char *body = f->control + M_HEADER;
    if (f->local) {
        if (m_resume_apply(f, body)) return -1;
        f->waiting_resume = f->suspended = 0; f->grace_deadline_us = 0;
        f->acked = 1; f->phase = M_ACTIVE; f->last_io = ob_now_us();
        return 0;
    }
    struct ob_flow *old = m_find(f->peer, f->id);
    int result = OB_REMOTE_ECLOSED;
    if (old && !old->local && old->suspended && old->wire_version == 2 &&
        old->protocol == OB_REMOTE_TCP && old->fd >= 0 &&
        old->grace_deadline_us > ob_now_us()) {
        if (m_resume_apply(old, body)) result = OB_REMOTE_EPROTOCOL;
        else result = 0;
    }
    M_TRACE("mapping resume-result role=%d gen=%llu flow=%llu result=%d old=%p fd=%d suspended=%d grace=%llu\n",
            f->peer->is_server, (unsigned long long)f->peer->transport_generation,
            (unsigned long long)f->id, result, (void *)old, old ? old->fd : -1,
            old ? old->suspended : -1, (unsigned long long)(old ? old->grace_deadline_us : 0));
    if (result) {
        m_header(f->reply, M_RESUME_ACK, OB_REMOTE_TCP, M_RESUME_SIZE, f->id);
        memset(f->reply + M_HEADER, 0, M_RESUME_SIZE);
        m_put32(f->reply + M_HEADER, (uint32_t)-result);
        f->reply_len = M_HEADER + M_RESUME_SIZE; f->reply_pos = 0;
        f->reject_after_reply = 1; f->phase = M_REPLY;
        return 0;
    }
    /* Rebind only after fresh connection proof and validated resume offsets.
     * The parsing placeholder stays allocated until the next regular tick. */
    old->stream = f->stream; old->stream_generation = f->stream_generation;
    xqc_stream_set_user_data(old->stream, old);
    f->stream = NULL; f->phase = M_DEAD; f->close_requested = 1;
    old->suspended = old->waiting_resume = 0; old->resuming = 1;
    old->close_requested = old->close_sent = 0; old->acked = 0;
    old->created = ob_now_us();
    old->control_len = 0; old->control_need = M_HEADER;
    m_header(old->reply, M_RESUME_ACK, OB_REMOTE_TCP, M_RESUME_SIZE, old->id);
    m_resume_snapshot(old, old->reply + M_HEADER, 0);
    old->reply_len = M_HEADER + M_RESUME_SIZE; old->reply_pos = 0; old->phase = M_REPLY;
    return 0;
}
static int m_resume_open(struct ob_flow *f)
{
    f->waiting_resume = 1; f->phase = M_CONTROL; f->created = ob_now_us();
    f->control_len = 0; f->control_need = M_HEADER;
    f->reply_pos = 0; f->acked = 0; f->close_sent = 0;
    m_header(f->reply, M_RESUME, OB_REMOTE_TCP, M_RESUME_SIZE, f->id);
    m_resume_snapshot(f, f->reply + M_HEADER, 0);
    f->reply_len = M_HEADER + M_RESUME_SIZE;
    if (m_stream_open(f)) return -1;
    m_reply_flush(f);
    return 0;
}
static void m_v2_frame(struct ob_flow *f, unsigned int kind, unsigned int flags,
                       size_t length, uint64_t offset)
{
    memcpy(f->out_frame, "OBM2", 4); f->out_frame[4] = (unsigned char)kind;
    f->out_frame[5] = (unsigned char)flags; m_put16(f->out_frame + 6, length);
    m_put64(f->out_frame + 8, f->id); m_put64(f->out_frame + 16, offset);
    f->out_kind = kind; f->out_flags = flags; f->out_pos = 0;
    f->out_offset = offset; f->out_end = offset + length;
}
static void m_v2_write(struct ob_flow *f)
{
    if (!f->stream || f->phase != M_ACTIVE || !f->acked || f->suspended ||
        f->close_requested || atomic_load(&f->peer->attempt_stop)) return;
    if (!f->out_kind) {
        if (f->ack_dirty) m_v2_frame(f, M_V2_ACK, f->rx_fin_applied ? 1U : 0U, 0, f->rx_commit);
        else if (f->tx_pos < f->tx_len) {
            size_t n = f->tx_len - f->tx_pos;
            if (n > M_IO_BUDGET) n = M_IO_BUDGET;
            m_v2_frame(f, M_V2_DATA, 0, n, f->tx_base + f->tx_pos);
        } else if (f->socket_eof && !f->sent_fin)
            m_v2_frame(f, M_V2_FIN, 0, 0, f->tx_final);
        else return;
    }
    if (f->out_pos < M_V2_HEADER) {
        ssize_t n = xqc_stream_send(f->stream, f->out_frame + f->out_pos,
                                    M_V2_HEADER - f->out_pos, 0);
#ifdef OB_MAPPING_TRACE
        f->trace_last_send = n;
#endif
        if (n == -XQC_EAGAIN) return;
        if (n < 0) {
            ob_peer_transport_fail_locked(f->peer, OB_REMOTE_EQUIC, "TCP frame send failed"); return;
        }
        if (!f->stream || atomic_load(&f->peer->attempt_stop)) return;
        f->out_pos += (size_t)n;
        if (f->out_pos < M_V2_HEADER) return;
    }
    if (f->out_kind == M_V2_DATA && f->out_offset < f->out_end) {
        if (f->out_offset < f->tx_base || f->out_end > m_tx_next(f)) {
            m_fail(f->peer, OB_REMOTE_EPROTOCOL, "TCP replay range is invalid"); return;
        }
        size_t offset = (size_t)(f->out_offset - f->tx_base);
        ssize_t n = xqc_stream_send(f->stream, f->tx + offset,
                                    (size_t)(f->out_end - f->out_offset), 0);
#ifdef OB_MAPPING_TRACE
        f->trace_last_send = n;
#endif
        if (n == -XQC_EAGAIN) return;
        if (n < 0) {
            ob_peer_transport_fail_locked(f->peer, OB_REMOTE_EQUIC, "TCP payload send failed"); return;
        }
        if (!f->stream || atomic_load(&f->peer->attempt_stop)) return;
        f->out_offset += (size_t)n; f->tx_pos = (size_t)(f->out_offset - f->tx_base);
        if (f->out_offset > f->tx_sent_high) f->tx_sent_high = f->out_offset;
        if (f->out_offset < f->out_end) return;
    }
    unsigned int completed = f->out_kind;
    if (completed == M_V2_ACK) {
        if (f->out_offset == f->rx_commit && f->out_flags == (unsigned int)f->rx_fin_applied)
            f->ack_dirty = 0;
    } else if (completed == M_V2_FIN) f->sent_fin = 1;
    f->out_kind = 0; f->out_pos = 0;
    /* One delivery ACK plus one payload frame per tick prevents a sustained
     * upload from starving the opposite TCP direction. No socket writes run
     * in xquic callbacks, so a complete ACK clears dirty before this tail call. */
    if (completed == M_V2_ACK && !f->ack_dirty && f->tx_pos < f->tx_len)
        m_v2_write(f);
}
static int m_v2_header(struct ob_flow *f)
{
    const unsigned char *h = f->in_frame;
    unsigned int kind = h[4], flags = h[5]; size_t size = m_u16(h + 6);
    uint64_t offset = m_u64(h + 16);
    if (memcmp(h, "OBM2", 4) || m_u64(h + 8) != f->id ||
        (kind != M_V2_DATA && kind != M_V2_ACK && kind != M_V2_FIN) ||
        (kind == M_V2_DATA && (!size || size > M_IO_BUDGET || flags ||
                              offset > UINT64_MAX - size)) ||
        (kind != M_V2_DATA && size) || (kind == M_V2_FIN && flags) ||
        (kind == M_V2_ACK && flags & ~1U)) return -1;
    f->in_kind = kind; f->in_flags = flags; f->in_size = size;
    f->in_offset = offset; f->in_pos = 0;
    if (kind == M_V2_ACK && m_v2_ack(f, offset, flags)) return -1;
    if (kind == M_V2_FIN) {
        if (offset != f->rx_next || (f->rx_fin && offset != f->rx_final)) return -1;
        f->rx_fin = 1; f->rx_final = offset;
    } else if (kind == M_V2_DATA &&
               (offset > f->rx_next || (f->rx_fin && offset + size > f->rx_final))) return -1;
    if (f->resuming) { f->resuming = 0; f->grace_deadline_us = 0; }
    return 0;
}
static void m_v2_read(struct ob_flow *f)
{
    if (!f->stream || f->suspended || atomic_load(&f->peer->attempt_stop)) return;
    for (unsigned int step = 0; step < 32; ++step) {
        uint8_t fin = 0;
        if (f->in_have < M_V2_HEADER) {
            ssize_t n = xqc_stream_recv(f->stream, f->in_frame + f->in_have,
                                        M_V2_HEADER - f->in_have, &fin);
#ifdef OB_MAPPING_TRACE
            f->trace_last_recv = n;
#endif
            if (n == -XQC_EAGAIN) return;
            if (n < 0 || fin) {
                M_TRACE("mapping v2-read-close role=%d gen=%llu flow=%llu n=%zd fin=%u have=%zu size=%zu pos=%zu attempt_stop=%d\n",
                        f->peer->is_server, (unsigned long long)f->peer->transport_generation,
                        (unsigned long long)f->id, n, fin, f->in_have, f->in_size, f->in_pos,
                        atomic_load(&f->peer->attempt_stop));
                m_abort(f); return;
            }
            f->in_have += (size_t)n;
            if (f->in_have < M_V2_HEADER) return;
            if (m_v2_header(f)) {
                M_TRACE("mapping invalid-v2-frame role=%d gen=%llu flow=%llu kind=%u flags=%u len=%u id=%llu offset=%llu tx=%llu/%llu pos=%zu sent=%llu rx=%llu/%llu fin=%d\n",
                        f->peer->is_server, (unsigned long long)f->peer->transport_generation,
                        (unsigned long long)f->id, f->in_frame[4], f->in_frame[5],
                        (unsigned int)m_u16(f->in_frame + 6),
                        (unsigned long long)m_u64(f->in_frame + 8),
                        (unsigned long long)m_u64(f->in_frame + 16),
                        (unsigned long long)f->tx_base, (unsigned long long)m_tx_next(f),
                        f->tx_pos, (unsigned long long)f->tx_sent_high,
                        (unsigned long long)f->rx_commit, (unsigned long long)f->rx_next, f->rx_fin);
                m_fail(f->peer, OB_REMOTE_EPROTOCOL, "Invalid TCP delivery frame"); m_abort(f); return;
            }
            if (f->in_kind != M_V2_DATA) { f->in_have = 0; continue; }
        }
        uint64_t at = f->in_offset + f->in_pos;
        size_t remaining = f->in_size - f->in_pos;
        unsigned char duplicate[512]; unsigned char *destination;
        int fresh = at == f->rx_next;
        if (at > f->rx_next) {
            m_fail(f->peer, OB_REMOTE_EPROTOCOL, "TCP delivery offset gap"); m_abort(f); return;
        }
        if (fresh) {
            if (f->rx_pos && f->rx_len == OB_STREAM_BUFFER) {
                memmove(f->rx, f->rx + f->rx_pos, f->rx_len - f->rx_pos);
                f->rx_len -= f->rx_pos; f->rx_pos = 0;
            }
            size_t room = OB_STREAM_BUFFER - f->rx_len;
            if (!room) return;
            if (remaining > room) remaining = room;
            destination = f->rx + f->rx_len;
        } else {
            if (remaining > sizeof(duplicate)) remaining = sizeof(duplicate);
            uint64_t boundary = at < f->rx_commit ? f->rx_commit : f->rx_next;
            if ((uint64_t)remaining > boundary - at) remaining = (size_t)(boundary - at);
            destination = duplicate;
        }
        ssize_t n = xqc_stream_recv(f->stream, destination, remaining, &fin);
#ifdef OB_MAPPING_TRACE
        f->trace_last_recv = n;
#endif
        if (n == -XQC_EAGAIN) return;
        if (n < 0 || fin) {
            M_TRACE("mapping v2-payload-close role=%d gen=%llu flow=%llu n=%zd fin=%u have=%zu size=%zu pos=%zu attempt_stop=%d\n",
                    f->peer->is_server, (unsigned long long)f->peer->transport_generation,
                    (unsigned long long)f->id, n, fin, f->in_have, f->in_size, f->in_pos,
                    atomic_load(&f->peer->attempt_stop));
            m_abort(f); return;
        }
        if (!n) return;
        if (fresh) { f->rx_len += (size_t)n; f->rx_next += (size_t)n; }
        else if (at >= f->rx_commit && memcmp(duplicate,
                  f->rx + f->rx_pos + (size_t)(at - f->rx_commit), (size_t)n)) {
            m_fail(f->peer, OB_REMOTE_EPROTOCOL, "TCP replay bytes changed"); m_abort(f); return;
        } else f->ack_dirty = 1;
        f->in_pos += (size_t)n; f->last_io = ob_now_us();
        if (f->in_pos == f->in_size) { f->in_have = f->in_size = f->in_pos = 0; }
    }
}
static void m_v2_tick(struct ob_flow *f)
{
    if (f->phase != M_ACTIVE || !f->acked || f->fd < 0 || f->suspended ||
        !f->peer->ready || !f->peer->proof_ready || atomic_load(&f->peer->attempt_stop)) return;
    struct pollfd descriptor = { .fd = f->fd, .events = 0, .revents = 0 };
    if (!f->socket_eof && f->tx_len < OB_STREAM_BUFFER) descriptor.events |= POLLIN;
    if (f->rx_pos < f->rx_len) descriptor.events |= POLLOUT;
    int polled = poll(&descriptor, 1, 0);
#ifdef OB_MAPPING_TRACE
    uint64_t trace_now = ob_now_us();
    if (trace_now - f->trace_tick_us >= UINT64_C(2000000)) {
        f->trace_tick_us = trace_now;
        M_TRACE("mapping window role=%d gen=%llu flow=%llu at=%llu fd=%d poll=%d/%d tx=%llu+%zu pos=%zu high=%llu out=%u/%zu/%llu/%llu rx=%llu/%llu cache=%zu/%zu in=%u/%zu/%zu/%zu ack=%d quic=%zd/%zd\n",
                f->peer->is_server, (unsigned long long)f->peer->transport_generation,
                (unsigned long long)f->id, (unsigned long long)trace_now, f->fd,
                descriptor.events, descriptor.revents, (unsigned long long)f->tx_base,
                f->tx_len, f->tx_pos, (unsigned long long)f->tx_sent_high,
                f->out_kind, f->out_pos, (unsigned long long)f->out_offset,
                (unsigned long long)f->out_end, (unsigned long long)f->rx_commit,
                (unsigned long long)f->rx_next, f->rx_len, f->rx_pos,
                f->in_kind, f->in_have, f->in_size, f->in_pos, f->ack_dirty,
                f->trace_last_send, f->trace_last_recv);
    }
#endif
    if ((polled < 0 && errno != EINTR) || descriptor.revents & (POLLERR | POLLNVAL)) {
        m_abort(f); return;
    }
    if (descriptor.revents & POLLOUT && f->rx_pos < f->rx_len) {
        size_t count = f->rx_len - f->rx_pos;
        if (count > M_IO_BUDGET) count = M_IO_BUDGET;
        ssize_t n = send(f->fd, f->rx + f->rx_pos, count, MSG_NOSIGNAL);
        if (n < 0 && !m_again()) { m_abort(f); return; }
        if (n > 0) {
            f->rx_pos += (size_t)n; f->rx_commit += (size_t)n;
            f->last_io = ob_now_us(); f->ack_dirty = 1;
        }
        if (f->rx_pos == f->rx_len) f->rx_pos = f->rx_len = 0;
    }
    if (f->rx_fin && f->rx_commit == f->rx_final && !f->rx_fin_applied) {
        if (shutdown(f->fd, SHUT_WR) < 0 && errno != ENOTCONN) { m_abort(f); return; }
        f->rx_fin_applied = f->socket_shutdown = 1; f->ack_dirty = 1;
    }
    if (descriptor.revents & (POLLIN | POLLHUP) && !f->socket_eof) {
        size_t room = OB_STREAM_BUFFER - f->tx_len;
        if (room > M_IO_BUDGET) room = M_IO_BUDGET;
        if (room) {
            ssize_t n = recv(f->fd, f->tx + f->tx_len, room, 0);
            if (n < 0 && !m_again()) { m_abort(f); return; }
            if (!n) { f->socket_eof = 1; f->tx_final = m_tx_next(f); }
            if (n > 0) {
                if (m_tx_next(f) > UINT64_MAX - (size_t)n) {
                    m_fail(f->peer, OB_REMOTE_ELIMIT, "TCP byte counter exhausted"); m_abort(f); return;
                }
                f->tx_len += (size_t)n; f->last_io = ob_now_us();
            }
        }
    }
    m_v2_write(f);
    if (f->socket_eof && f->rx_fin_applied && f->tx_fin_acked && !f->tx_len &&
        !f->ack_dirty && !f->out_kind) m_abort(f);
}
