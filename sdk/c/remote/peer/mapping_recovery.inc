/* Recoverable transport retirement never owns a public map's lifetime.
 * All hooks require peer->mu and the persistent engine owner. */
void ob_mapping_transport_suspend(ob_remote_peer *p, int preserve_tcp,
                                  uint64_t deadline_us)
{
    struct m_state *s = p->mapping_private;
    if (s) s->proof_started = 0;
    uint64_t now = ob_now_us();
    if (!deadline_us) deadline_us = now + (uint64_t)p->recovery.policy.flow_grace_ms * 1000;
    if (deadline_us <= now) preserve_tcp = 0;
    for (struct ob_flow *f = p->flows; f; f = f->next) {
        if (f->stream) xqc_stream_set_user_data(f->stream, NULL);
        f->stream = NULL;
        /* acked belongs to the current stream. A retained target socket remains
         * established when another attempt dies before its RESUME_ACK flush. */
        int keep = !f->proof && !f->transient && f->protocol == OB_REMOTE_TCP &&
            f->fd >= 0 && (!f->local || f->map) && !f->reject_after_reply &&
            (f->pending_open || (preserve_tcp && f->wire_version == 2 &&
             (f->local || f->acked || f->phase == M_REPLY ||
              f->suspended || f->resuming)));
        M_TRACE("mapping suspend role=%d gen=%llu flow=%llu fd=%d keep=%d phase=%d acked=%d suspended=%d resuming=%d grace=%llu\n",
                p->is_server, (unsigned long long)p->transport_generation,
                (unsigned long long)f->id, f->fd, keep, f->phase, f->acked,
                f->suspended, f->resuming, (unsigned long long)f->grace_deadline_us);
        if (!keep) { f->phase = M_DEAD; f->close_requested = 1; m_release_io(f); continue; }
        f->suspended = 1; f->waiting_resume = f->resuming = 0;
        f->close_requested = f->close_sent = 0; f->phase = M_ACTIVE;
        if (!f->grace_deadline_us || f->grace_deadline_us > deadline_us)
            f->grace_deadline_us = deadline_us;
        /* Uncommitted receive bytes may be safely discarded: the sender still
         * owns them. rx_commit alone survives and prevents duplicate delivery. */
        f->rx_len = f->rx_pos = 0; f->rx_next = f->rx_commit;
        f->in_have = f->in_size = f->in_pos = f->out_pos = 0; f->out_kind = 0;
        f->tx_pos = 0; f->sent_fin = f->tx_fin_acked;
        f->control_len = 0; f->control_need = M_HEADER;
        f->reply_len = f->reply_pos = 0; m_drop_udp(f);
    }
    for (ob_remote_map *map = p->maps; map; map = map->next)
        if (map->protocol == OB_REMOTE_UDP) map->udp_draining = 1;
}
void ob_mapping_forget_flows(ob_remote_peer *p)
{
    for (struct ob_flow *f = p->flows; f; f = f->next)
        if (!f->proof && !f->transient && !f->pending_open) m_abort(f);
}
static int m_pending_open(struct ob_flow *f)
{
    if (!f->map || f->map->closed) return -1;
    size_t len = strlen(f->map->target_host);
    f->wire_version = f->peer->wire_version;
    f->pending_open = f->suspended = 0; f->grace_deadline_us = 0;
    f->phase = M_CONTROL; f->created = ob_now_us(); f->control_len = 0;
    f->control_need = M_HEADER; f->reply_pos = 0;
    m_header(f->reply, M_OPEN, (unsigned int)f->protocol, len + 2, f->id);
    m_put16(f->reply + M_HEADER, f->map->target_port);
    memcpy(f->reply + M_HEADER + 2, f->map->target_host, len);
    f->reply_len = M_HEADER + len + 2;
    if (m_stream_open(f)) return -1;
    m_reply_flush(f);
    return 0;
}
void ob_mapping_transport_ready(ob_remote_peer *p, int wire_version,
                                int resume_context_available)
{
    uint64_t now = ob_now_us();
    M_TRACE("mapping ready role=%d gen=%llu version=%d context=%d now=%llu\n", p->is_server,
            (unsigned long long)p->transport_generation, wire_version, resume_context_available,
            (unsigned long long)now);
    for (struct ob_flow *f = p->flows; f; f = f->next) {
        if (f->proof || !f->suspended || f->phase == M_DEAD) continue;
        M_TRACE("mapping ready-flow role=%d flow=%llu fd=%d pending=%d grace=%llu tx=%llu/%llu sent=%llu rx=%llu\n",
                p->is_server, (unsigned long long)f->id, f->fd, f->pending_open,
                (unsigned long long)f->grace_deadline_us, (unsigned long long)f->tx_base,
                (unsigned long long)m_tx_next(f), (unsigned long long)f->tx_sent_high,
                (unsigned long long)f->rx_commit);
        if (f->grace_deadline_us <= now || (f->local && !f->map)) { m_abort(f); continue; }
        if (f->pending_open) {
            if (m_pending_open(f))
                ob_peer_transport_fail_locked(p, OB_REMOTE_EQUIC, "Pending TCP open failed");
        } else if (wire_version != 2 || !resume_context_available) m_abort(f);
        else if (f->local) {
            if (m_resume_open(f))
                ob_peer_transport_fail_locked(p, OB_REMOTE_EQUIC, "TCP resume stream failed");
        }
        if (atomic_load(&p->stop) || atomic_load(&p->attempt_stop)) break;
    }
}
static void m_udp_discard(ob_remote_map *map, struct m_state *s, unsigned int *budget)
{
    while (*budget) {
        ssize_t n = recv(map->fd, s->udp, sizeof(s->udp), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) map->udp_draining = 0;
            return;
        }
        --*budget;
    }
}
void ob_mapping_recovery_tick(ob_remote_peer *p, uint64_t now)
{
    for (struct ob_flow *f = p->flows, *next; f; f = next) {
        next = f->next;
        if (((f->suspended || f->resuming) && f->grace_deadline_us <= now) ||
            f->close_requested) m_abort(f);
        if (f->phase == M_DEAD && !f->stream) m_flow_free(f);
    }
    struct m_state *s = m_state_get(p);
    if (!s) return;
    if (!p->ready || !p->proof_ready || atomic_load(&p->attempt_stop)) {
        unsigned int budget = 128;
        for (ob_remote_map *map = p->maps; map && budget; map = map->next) {
            if (map->closed || map->fd < 0) continue;
            if (map->protocol == OB_REMOTE_TCP) m_map_tick(map, &budget);
            else { map->udp_draining = 1; m_udp_discard(map, s, &budget); }
        }
    }
    m_resolve_reap(p);
}
