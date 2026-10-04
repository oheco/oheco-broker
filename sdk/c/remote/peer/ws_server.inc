/* Broker control worker, one curl owner and pushed complete snapshots. */
static void server_fail(ob_remote_server *s, int code, const ob_remote_error *e)
{
    pthread_mutex_lock(&s->mu);
    if (atomic_load(&s->caller_close)) { pthread_mutex_unlock(&s->mu); return; }
    if (!s->result) { s->result = code;
        if (e) { s->error = *e; s->error.code = code; }
        else ob_error(&s->error, code, 0, NULL);
    }
    ob_recovery_set_locked(&s->recovery, OB_REMOTE_STATE_FAILED, &s->error);
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
        const char *connection = string(item, "connection_id");
        cJSON *epoch = cJSON_GetObjectItemCaseSensitive(item, "generation");
        uint64_t generation = 0;
        if (!ob_valid_id(sid) || (connection && (!ob_valid_id(connection) ||
            !cJSON_IsNumber(epoch) || epoch->valuedouble < 1 || epoch->valuedouble > 2147483647.0 ||
            epoch->valuedouble != (double)(uint64_t)epoch->valuedouble))) {
            server_fail(s, OB_REMOTE_EPROTOCOL, NULL); return;
        }
        if (connection) generation = (uint64_t)epoch->valuedouble;
        size_t count = 0; int exists = 0; ob_remote_peer *logical = NULL;
        for (struct ob_seen_session *seen = s->seen_sessions; seen; seen = seen->next)
            if (!strcmp(seen->id, sid)) { exists = 1; break; }
        for (ob_remote_peer *p = s->peers; p; p = p->next) {
            ++count;
            if (connection && !strcmp(p->connection_id, connection) && !atomic_load(&p->stop)) logical = p;
        }
        if (exists) continue;
        struct ob_seen_session *seen = calloc(1, sizeof(*seen));
        if (!seen || s->seen_count >= 4096) {
            free(seen); server_fail(s, OB_REMOTE_ELIMIT, NULL); return;
        }
        if (logical) {
            char *pending = strdup(sid);
            if (!pending) { free(seen); continue; }
            pthread_mutex_lock(&logical->mu);
            if (generation > logical->control_generation && generation > logical->pending_control_generation) {
                free(logical->pending_session_id); logical->pending_session_id = pending; pending = NULL;
                logical->pending_control_generation = generation;
                ob_peer_transport_fail_locked(logical, OB_REMOTE_ECLOSED, "A fresh control session replaced the transport");
            }
            pthread_mutex_unlock(&logical->mu); free(pending);
        } else {
            if (count >= s->options.max_peers) { free(seen); continue; }
            ob_remote_connect_options options = {0};
            options.relay_mode = mode && !strcmp(mode, "force") ? OB_REMOTE_RELAY_FORCE
                : mode && !strcmp(mode, "never") ? OB_REMOTE_RELAY_NEVER : OB_REMOTE_RELAY_AUTO;
            options.timeout_ms = s->options.setup_timeout_ms; options.stun_server = s->stun;
            options.stun_port = s->options.stun_port; options.max_maps = s->options.max_maps_per_peer;
            options.max_flows = s->options.max_flows_per_peer; options.udp_idle_timeout_ms = s->options.udp_idle_timeout_ms;
            ob_remote_peer *p = ob_peer_alloc(s->api, s->broker_id, s->password, &options);
            if (!p) { free(seen); continue; }
            p->is_server = 1; p->server = s; p->control_discovered = 1;
            pthread_mutex_lock(&s->mu); ob_remote_reconnect_policy policy = s->recovery.policy; pthread_mutex_unlock(&s->mu);
            pthread_mutex_lock(&p->mu); ob_recovery_apply_policy_locked(&p->recovery, &policy); pthread_mutex_unlock(&p->mu);
            if (connection) {
                memcpy(p->connection_id, connection, 37); p->control_managed = 1; p->control_generation = generation;
            }
            p->logical_local.sin_port = htons(30002); p->logical_peer.sin_port = htons(30001);
            p->session_id = strdup(sid); p->bearer = strdup(s->device_token);
            ob_remote_error error;
            if (!p->session_id || !p->bearer || ob_peer_start(p, &error)) {
                free(seen); ob_peer_destroy(p); continue;
            }
            p->next = s->peers; s->peers = p;
        }
        strcpy(seen->id, sid); seen->next = s->seen_sessions; s->seen_sessions = seen; s->seen_count++;
    }
    struct ob_seen_session **link = &s->seen_sessions;
    while (*link) {
        int present = 0, active = 0;
        cJSON_ArrayForEach(item, sessions) { const char *sid = string(item, "session_id"); if (sid && !strcmp(sid, (*link)->id)) { present = 1; break; } }
        for (ob_remote_peer *p = s->peers; p; p = p->next) {
            pthread_mutex_lock(&p->mu);
            if (p->session_id && !strcmp(p->session_id, (*link)->id)) active = 1;
            pthread_mutex_unlock(&p->mu);
        }
        if (!present && !active) { struct ob_seen_session *seen = *link; *link = seen->next; free(seen); s->seen_count--; }
        else link = &(*link)->next;
    }
}
static void server_suspend_peers(ob_remote_server *s, const char *reason)
{
    for (ob_remote_peer *p = s->peers; p; p = p->next) {
        if (p->control_managed) ob_peer_transport_fail(p, OB_REMOTE_ECLOSED, reason);
        else ob_peer_fail(p, OB_REMOTE_ECLOSED, reason);
    }
}
static int server_retry_allowed(ob_remote_server *s, int connected, uint64_t now,
                                 uint64_t *reconnect)
{
    pthread_mutex_lock(&s->mu); struct ob_recovery *r = &s->recovery;
    if (atomic_exchange(&r->requested, 0)) {
        r->info.attempts = 0; r->outage_us = now; r->retry_us = 0; *reconnect = 0;
        s->manual_attempt = 1;
    }
    /* Policy changes clamp the authoritative deadline on the caller thread. */
    *reconnect = r->retry_us;
    if (connected && r->stable_us && now - r->stable_us >= (uint64_t)r->policy.stable_reset_ms * 1000) {
        r->info.attempts = 0; r->outage_us = 0;
    }
    int exhausted = !connected && s->initialized && !s->manual_attempt &&
        (r->policy.disabled || r->info.attempts >= r->policy.max_attempts ||
        (r->outage_us && now-r->outage_us >= (uint64_t)r->policy.retry_budget_ms * 1000));
    if (exhausted && r->info.state != OB_REMOTE_STATE_PAUSED)
        ob_recovery_set_locked(r, OB_REMOTE_STATE_PAUSED, NULL);
    pthread_mutex_unlock(&s->mu); return !exhausted;
}
static void server_retry_delay(ob_remote_server *s, const ob_api_error *error,
                               uint64_t *reconnect)
{
    pthread_mutex_lock(&s->mu); struct ob_recovery *r = &s->recovery;
    if (atomic_load(&s->stop)) { pthread_mutex_unlock(&s->mu); return; }
    if (!r->outage_us) r->outage_us = ob_now_us();
    uint64_t delay = r->info.attempts ? r->policy.initial_delay_ms : 0;
    for (uint32_t i = 1; i < r->info.attempts && delay < r->policy.max_delay_ms; ++i) delay *= 2;
    if (delay > r->policy.max_delay_ms) delay = r->policy.max_delay_ms;
    delay = jitter((unsigned)delay);
    if (delay > r->policy.max_delay_ms) delay = r->policy.max_delay_ms;
    r->retry_us = *reconnect = ob_now_us() + delay*1000;
    ob_remote_error remote; ob_error(&remote, OB_REMOTE_EHTTP,
                                    error ? (int)error->http_status : 0,
                                    error ? error->message : "Broker control transport disconnected");
    ob_recovery_set_locked(r, OB_REMOTE_STATE_RETRY_WAIT, &remote);
    pthread_mutex_unlock(&s->mu);
}
void *ob_server_worker(void *data)
{
    ob_remote_server *s = data;
    ob_ws *ws = ob_ws_create(s->api, 1, s->broker_id, s->device_token, server_cancel, s);
    if (!ws) { server_fail(s, OB_REMOTE_ENOMEM, NULL); return NULL; }
    uint64_t heartbeat = 0, heartbeat_id = 0, heartbeat_sent = 0;
    uint64_t lease_deadline = 0, reconnect = 0;
    int lease_was_expired = 0;
    cJSON *snapshot = NULL;
    while (!atomic_load(&s->stop)) {
        uint64_t now = ob_now_us(); ob_api_error e = {0}; int rc = 0;
        if (!s->initialized && now >= s->start_deadline_us) { server_fail(s, OB_REMOTE_ETIMEOUT, NULL); break; }
        if (lease_deadline && now >= lease_deadline && !lease_was_expired) {
            server_suspend_peers(s, "Broker authorization lease expired");
            lease_was_expired = 1;
        }
        int retry_allowed = server_retry_allowed(s, ob_ws_connected(ws), now, &reconnect);
        if (!ob_ws_connected(ws) && retry_allowed && now >= reconnect) {
            pthread_mutex_lock(&s->mu);
            ++s->recovery.info.attempts; s->manual_attempt = 0;
            ob_recovery_set_locked(&s->recovery, s->initialized ? OB_REMOTE_STATE_RECONNECTING : OB_REMOTE_STATE_CONNECTING, NULL);
            pthread_mutex_unlock(&s->mu);
            long timeout = 1500;
            if (!s->initialized && s->start_deadline_us > now && (s->start_deadline_us-now)/1000 < 1500)
                timeout = (long)((s->start_deadline_us-now+999)/1000);
            rc = ob_ws_connect(ws, 0, timeout, &e);
            heartbeat_id = 0;
            if (!rc) {
                heartbeat = 0; reconnect = 0;
                pthread_mutex_lock(&s->mu); ++s->recovery.info.generation;
                s->recovery.retry_us = 0; pthread_mutex_unlock(&s->mu);
            }
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
            heartbeat_id = 0; server_retry_delay(s, &e, &reconnect);
        }
        cJSON *j;
        if ((j = ob_ws_pop(ws, "revoked"))) {
            int status = cJSON_GetObjectItemCaseSensitive(j, "status")->valueint; cJSON_Delete(j);
            if (fatal_status(status)) { server_fail(s, OB_REMOTE_ECLOSED, NULL); break; }
            if (status == 409) {
                /* All forwarding stops. Retained flows require a separately
                 * authorized successor session, never this heartbeat alone. */
                server_suspend_peers(s, "Broker offline; new authorization required");
                lease_was_expired = 1;
            }
            ob_ws_disconnect(ws); heartbeat_id = 0;
            server_retry_delay(s, NULL, &reconnect);
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
                    pthread_mutex_lock(&s->mu);
                    if (!s->initialized) { s->recovery.info.attempts = 0; s->recovery.outage_us = 0; }
                    s->initialized = 1;
                    if (s->recovery.info.state != OB_REMOTE_STATE_CONNECTED) {
                        s->recovery.stable_us = ob_now_us();
                        ob_recovery_set_locked(&s->recovery, OB_REMOTE_STATE_CONNECTED, NULL);
                    }
                    s->recovery.retry_us = 0; atomic_store(&s->recovery.requested, 0);
                    pthread_cond_broadcast(&s->cv); pthread_mutex_unlock(&s->mu);
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
                heartbeat_id = 0; server_retry_delay(s, &e, &reconnect);
            } else heartbeat_sent = ob_now_us();
        }
        if (snapshot && s->initialized && !lease_was_expired && !atomic_load(&s->stop)) {
            server_snapshot(s, snapshot); cJSON_Delete(snapshot); snapshot = NULL;
        }
        ob_remote_peer **link = &s->peers;
        while (*link) {
            ob_remote_peer *p = *link;
            pthread_mutex_lock(&s->mu); ob_remote_reconnect_policy policy = s->recovery.policy; pthread_mutex_unlock(&s->mu);
            pthread_mutex_lock(&p->mu); ob_recovery_apply_policy_locked(&p->recovery, &policy);
            uint64_t deadline = p->recovery_deadline_us ? p->recovery_deadline_us
                : p->deadline_us + (uint64_t)policy.flow_grace_ms * 1000;
            if (p->control_managed && !p->transport_available && p->flow_count == 0 && now >= deadline)
                ob_peer_fail_locked(p, OB_REMOTE_ECLOSED, "Idle recovery context expired");
            pthread_mutex_unlock(&p->mu);
            if (atomic_load(&p->stop)) { *link = p->next; ob_peer_destroy(p); }
            else link = &p->next;
        }
        ob_recovery_deliver(&s->recovery, &s->mu);
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
    cJSON_Delete(snapshot); ob_ws_destroy(ws);
    ob_recovery_deliver(&s->recovery, &s->mu); return NULL;
}
