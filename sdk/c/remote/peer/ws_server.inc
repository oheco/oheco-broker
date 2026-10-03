/* Broker control worker, one curl owner and pushed complete snapshots. */
static void server_fail(ob_remote_server *s, int code, const ob_remote_error *e)
{
    pthread_mutex_lock(&s->mu);
    if (!s->result) { s->result = code;
        if (e) { s->error = *e; s->error.code = code; }
        else ob_error(&s->error, code, 0, NULL);
    }
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu); atomic_store(&s->stop, 1);
}
static int server_cancel(void *arg)
{
    ob_remote_server *s = arg;
    return !s->control_cleanup && (atomic_load(&s->stop)
        || (!s->initialized && ob_now_us() >= s->start_deadline_us));
}
static void server_snapshot(ob_remote_server *s, cJSON *response)
{
    cJSON *sessions = cJSON_GetObjectItemCaseSensitive(response, "sessions"), *item;
    if (!cJSON_IsArray(sessions)) { server_fail(s, OB_REMOTE_EPROTOCOL, NULL); return; }
    cJSON_ArrayForEach(item, sessions) {
        const char *sid = string(item, "session_id"), *mode = string(item, "relay_mode");
        if (!ob_valid_id(sid)) { server_fail(s, OB_REMOTE_EPROTOCOL, NULL); return; }
        size_t count = 0; int exists = 0;
        for (struct ob_seen_session *seen = s->seen_sessions; seen; seen = seen->next)
            if (!strcmp(seen->id, sid)) { exists = 1; break; }
        for (ob_remote_peer *p = s->peers; p; p = p->next) ++count;
        if (exists || count >= s->options.max_peers) continue;
        ob_remote_connect_options options = {0};
        options.relay_mode = mode && !strcmp(mode, "force") ? OB_REMOTE_RELAY_FORCE
            : mode && !strcmp(mode, "never") ? OB_REMOTE_RELAY_NEVER : OB_REMOTE_RELAY_AUTO;
        options.timeout_ms = s->options.setup_timeout_ms; options.stun_server = s->stun;
        options.stun_port = s->options.stun_port; options.max_maps = s->options.max_maps_per_peer;
        options.max_flows = s->options.max_flows_per_peer; options.udp_idle_timeout_ms = s->options.udp_idle_timeout_ms;
        ob_remote_peer *p = ob_peer_alloc(s->api, s->broker_id, s->password, &options);
        if (!p) continue;
        p->is_server = 1; p->server = s;
        p->logical_local.sin_port = htons(30002); p->logical_peer.sin_port = htons(30001);
        p->session_id = strdup(sid); p->bearer = strdup(s->device_token);
        /* Tombstones are pruned only after durable snapshots no longer contain
         * the session, so an expired forwarding peer cannot be resurrected. */
        struct ob_seen_session *seen = calloc(1, sizeof(*seen));
        if (!seen || s->seen_count >= 4096) {
            free(seen); ob_peer_destroy(p); server_fail(s, OB_REMOTE_ELIMIT, NULL); return;
        }
        if (!p->session_id || !p->bearer || pthread_create(&p->setup_thread, NULL, ob_setup_worker, p)) {
            free(seen); ob_peer_destroy(p); continue;
        }
        strcpy(seen->id, sid); seen->next = s->seen_sessions; s->seen_sessions = seen; s->seen_count++;
        p->setup_started = 1; p->next = s->peers; s->peers = p;
    }
    struct ob_seen_session **link = &s->seen_sessions;
    while (*link) {
        int present = 0, active = 0;
        cJSON_ArrayForEach(item, sessions) { const char *sid = string(item,"session_id"); if (sid && !strcmp(sid,(*link)->id)) { present = 1; break; } }
        for (ob_remote_peer *p = s->peers; p; p = p->next) if (!strcmp(p->session_id,(*link)->id)) { active = 1; break; }
        if (!present && !active) { struct ob_seen_session *seen = *link; *link = seen->next; free(seen); s->seen_count--; }
        else link = &(*link)->next;
    }
}
void *ob_server_worker(void *data)
{
    ob_remote_server *s = data;
    ob_ws *ws = ob_ws_create(s->api, 1, s->broker_id, s->device_token, server_cancel, s);
    if (!ws) { server_fail(s, OB_REMOTE_ENOMEM, NULL); return NULL; }
    uint64_t heartbeat = 0, heartbeat_id = 0, heartbeat_sent = 0;
    uint64_t lease_deadline = 0, reconnect = 0;
    unsigned backoff = 100; int lease_was_expired = 0;
    cJSON *snapshot = NULL;
    while (!atomic_load(&s->stop)) {
        uint64_t now = ob_now_us(); ob_api_error e = {0}; int rc = 0;
        if (!s->initialized && now >= s->start_deadline_us) { server_fail(s, OB_REMOTE_ETIMEOUT, NULL); break; }
        if (lease_deadline && now >= lease_deadline && !lease_was_expired) {
            for (ob_remote_peer *p = s->peers; p; p = p->next)
                ob_peer_fail(p, OB_REMOTE_ECLOSED, "Broker authorization lease expired");
            lease_was_expired = 1;
        }
        if (!ob_ws_connected(ws) && now >= reconnect) {
            long timeout = 1500;
            if (!s->initialized && s->start_deadline_us > now && (s->start_deadline_us-now)/1000 < 1500)
                timeout = (long)((s->start_deadline_us-now+999)/1000);
            rc = ob_ws_connect(ws, 0, timeout, &e);
            heartbeat_id = 0;
            if (!rc) { heartbeat = 0; backoff = 100; reconnect = 0; }
        }
        if (!rc && ob_ws_connected(ws)) rc = ob_ws_pump(ws, 50, &e);
        if (rc) {
            if (fatal_status((int)e.http_status)) {
                ob_remote_error re; ob_error(&re, OB_REMOTE_ECLOSED, (int)e.http_status, e.message);
                server_fail(s, OB_REMOTE_ECLOSED, &re); break;
            }
            if (e.code == OB_API_JSON || e.code == OB_API_LIMIT || e.code == OB_API_NOMEM) {
                server_fail(s, OB_REMOTE_EPROTOCOL, NULL); break;
            }
            heartbeat_id = 0; reconnect = ob_now_us()+(uint64_t)jitter(backoff)*1000;
            backoff = backoff < 2000 ? backoff*2 : 2000;
        }
        cJSON *j;
        if ((j = ob_ws_pop(ws, "revoked"))) {
            int status = cJSON_GetObjectItemCaseSensitive(j, "status")->valueint; cJSON_Delete(j);
            if (fatal_status(status)) { server_fail(s, OB_REMOTE_ECLOSED, NULL); break; }
            if (status == 409) {
                /* Offline requires a new watch, and can never restore old data
                 * peers when its idempotent heartbeat restores this UUID. */
                for (ob_remote_peer *p = s->peers; p; p = p->next)
                    ob_peer_fail(p, OB_REMOTE_ECLOSED, "Broker offline; new authorization required");
                lease_was_expired = 1;
            }
            ob_ws_disconnect(ws); heartbeat_id = 0;
            reconnect = ob_now_us()+(uint64_t)jitter(backoff)*1000;
            backoff = backoff < 2000 ? backoff*2 : 2000;
        }
        while ((j = ob_ws_pop(ws, "sessions"))) {
            cJSON_Delete(snapshot); snapshot = cJSON_DetachItemFromObjectCaseSensitive(j,"body"); cJSON_Delete(j);
        }
        if (heartbeat_id) {
            int status; cJSON *body = NULL;
            if (ob_ws_result(ws, heartbeat_id, &status, &body)) {
                heartbeat_id = 0;
                if (status >= 200 && status < 300) {
                    uint64_t expires = expiry(string(cJSON_GetObjectItemCaseSensitive(body, "broker"), "lease_expires_at"));
                    uint64_t realtime = ob_realtime_us();
                    if (expires <= realtime) { cJSON_Delete(body); server_fail(s, OB_REMOTE_EPROTOCOL, NULL); break; }
                    uint64_t remaining = expires-realtime; if (remaining > 120000000) remaining = 120000000;
                    lease_deadline = ob_now_us()+remaining; heartbeat = ob_now_us()+heartbeat_interval(remaining);
                    lease_was_expired = 0;
                    pthread_mutex_lock(&s->mu); s->initialized = 1; pthread_cond_broadcast(&s->cv); pthread_mutex_unlock(&s->mu);
                } else if (fatal_status(status)) {
                    cJSON_Delete(body); server_fail(s, OB_REMOTE_ECLOSED, NULL); break;
                } else heartbeat = ob_now_us()+200000;
                cJSON_Delete(body);
            } else if (ob_now_us()-heartbeat_sent >= (uint64_t)s->api->timeout_ms*1000) {
                ob_ws_disconnect(ws); heartbeat_id = 0;
            }
        }
        if (!heartbeat_id && ob_ws_connected(ws) && ob_now_us() >= heartbeat) {
            if (ob_ws_begin(ws, "heartbeat", NULL, &heartbeat_id, 500, &e)) {
                heartbeat_id = 0; reconnect = ob_now_us()+(uint64_t)jitter(backoff)*1000;
            } else heartbeat_sent = ob_now_us();
        }
        if (snapshot && s->initialized && !lease_was_expired && !atomic_load(&s->stop)) {
            server_snapshot(s, snapshot); cJSON_Delete(snapshot); snapshot = NULL;
        }
        ob_remote_peer **link = &s->peers;
        while (*link) {
            ob_remote_peer *p = *link;
            if (atomic_load(&p->stop)) { *link = p->next; ob_peer_destroy(p); }
            else link = &p->next;
        }
        if (!ob_ws_connected(ws)) pause_ms(50);
    }
    for (ob_remote_peer *p = s->peers; p; p = p->next) ob_peer_fail(p, OB_REMOTE_ECLOSED, "Broker stopped or revoked");
    if (atomic_load(&s->caller_close)) {
        s->control_cleanup = 1;
        int closed = ob_ws_connected(ws) && !close_rpc(ws, "offline");
        if (!closed) {
            ob_ws_disconnect(ws);
            char path[128]; snprintf(path,sizeof(path),"/v1/brokers/%s/offline",s->broker_id);
            cleanup_rest(s->api,"POST",path,s->device_token);
        }
    }
    cJSON_Delete(snapshot); ob_ws_destroy(ws); return NULL;
}
