/* Included by control.c, after lease/STUN parsing helpers. */
static int fatal_status(int status)
{ return status == 401 || status == 403 || status == 404 || status == 410; }
static unsigned jitter(unsigned n)
{ unsigned r = 0; if (RAND_bytes((unsigned char *)&r, sizeof(r)) != 1) r = (unsigned)ob_now_us(); return n + r % (n/4 + 1); }
static uint64_t heartbeat_interval(uint64_t remaining)
{ uint64_t interval = remaining/3; if (interval > 10000000) interval = 10000000; if (interval < 50000) interval = 50000; return interval; }
static int peer_cancel(void *arg)
{
    ob_remote_peer *p = arg; if (p->control_cleanup) return 0;
    if (atomic_load(&p->stop) || atomic_load(&p->attempt_stop)) return 1;
    pthread_mutex_lock(&p->mu);
    int cancel = (p->lease_deadline_set && ob_now_us() >= p->lease_deadline_us)
        || (!p->ready && ob_now_us() >= p->deadline_us);
    pthread_mutex_unlock(&p->mu); return cancel;
}
static int apply_capabilities(ob_remote_peer *p, cJSON *response)
{
    if (!cJSON_IsObject(response) || discover_stun(p, response)) {
        ob_peer_fail(p, OB_REMOTE_EPROTOCOL, "Invalid pushed capabilities/STUN endpoint"); return OB_REMOTE_EPROTOCOL;
    }
    if (set_lease(p, response)) {
        if (p->control_managed) ob_peer_transport_fail(p, OB_REMOTE_ECLOSED, "Control authorization lease expired");
        else ob_peer_fail(p, OB_REMOTE_ECLOSED, "Control authorization lease expired");
        return OB_REMOTE_ECLOSED;
    }
    p->approved = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(response, "peer_authenticated"));
    return 0;
}
static int peer_authorization_error(ob_remote_peer *p, cJSON *body)
{
    const char *reason = string(body, "error_code");
    int terminal = reason && (!strcmp(reason, "connection_revoked") ||
                              !strcmp(reason, "credential_revoked"));
    if (!p->control_managed || terminal)
        ob_peer_fail(p, OB_REMOTE_ECLOSED, "Control authorization was explicitly revoked");
    else ob_peer_transport_fail(p, OB_REMOTE_ECLOSED, "Control session requires fresh authorization");
    return OB_REMOTE_ECLOSED;
}
static int peer_transport_error(ob_remote_peer *p, const ob_api_error *e)
{
    if (fatal_status((int)e->http_status)) {
        if (p->control_managed) ob_peer_transport_fail(p, OB_REMOTE_ECLOSED, "Control session requires fresh authorization");
        else ob_peer_fail(p, OB_REMOTE_ECLOSED, "Control session revoked");
        return OB_REMOTE_ECLOSED;
    }
    if (e->code == OB_API_JSON || e->code == OB_API_LIMIT || e->code == OB_API_NOMEM) {
        int rc = e->code == OB_API_NOMEM ? OB_REMOTE_ENOMEM : OB_REMOTE_EPROTOCOL;
        ob_peer_fail(p, rc, e->message); return rc;
    }
    p->heartbeat_id = 0;
    unsigned backoff = p->reconnect_backoff ? p->reconnect_backoff : 100;
    p->reconnect_us = ob_now_us() + (uint64_t)jitter(backoff)*1000;
    p->reconnect_backoff = backoff < 2000 ? backoff*2 : 2000;
    return 0;
}
/* Pump through PAKE, approval, ICE gathering and ready. Only this owner calls
 * curl. Heartbeat may overlap one foreground RPC, correlated by IDs. */
static int peer_tick(ob_remote_peer *p, unsigned wait_ms)
{
    if (!alive(p)) return OB_REMOTE_ECLOSED;
    ob_api_error e = {0};
    if (!ob_ws_connected(p->ws)) {
        if (ob_now_us() < p->reconnect_us) { pause_ms(wait_ms ? wait_ms : 10); return 0; }
        pthread_mutex_lock(&p->mu);
        uint64_t deadline = p->lease_deadline_set ? p->lease_deadline_us : p->deadline_us;
        pthread_mutex_unlock(&p->mu);
        uint64_t now = ob_now_us(); long timeout = deadline > now ? (long)((deadline-now+999)/1000) : 1;
        if (timeout > 1500) timeout = 1500;
        int rc = ob_ws_connect(p->ws, p->rx_sequence, timeout, &e);
        if (rc) return peer_transport_error(p, &e);
        p->heartbeat_id = 0; p->heartbeat_due_us = 0;
        p->reconnect_backoff = 100; p->reconnect_us = 0;
    }
    int rc = ob_ws_pump(p->ws, wait_ms, &e);
    if (rc) return peer_transport_error(p, &e);
    cJSON *j;
    while ((j = ob_ws_pop(p->ws, "revoked"))) {
        int status = cJSON_GetObjectItemCaseSensitive(j, "status")->valueint;
        cJSON *body = cJSON_GetObjectItemCaseSensitive(j, "body");
        if (status >= 500) {
            cJSON_Delete(j);
            /* Unavailable authorization is not a fresh grant or proof of
             * invalid identity. Preserve only the old deadline while retrying. */
            ob_ws_disconnect(p->ws); e.code = OB_API_TRANSPORT; e.http_status = status;
            return peer_transport_error(p, &e);
        }
        int authorization = peer_authorization_error(p, body); cJSON_Delete(j);
        return authorization;
    }
    while ((j = ob_ws_pop(p->ws, "capabilities"))) {
        rc = apply_capabilities(p, cJSON_GetObjectItemCaseSensitive(j, "body")); cJSON_Delete(j); if (rc) return rc;
    }
    if (p->heartbeat_id) {
        int status; cJSON *body = NULL;
        if (ob_ws_result(p->ws, p->heartbeat_id, &status, &body)) {
            p->heartbeat_id = 0;
            if (status >= 200 && status < 300) rc = apply_capabilities(p, body);
            else if (fatal_status(status) || (p->control_managed && status == 409))
                rc = peer_authorization_error(p, body);
            cJSON_Delete(body); if (rc) return rc;
            pthread_mutex_lock(&p->mu); uint64_t lease = p->lease_deadline_us; pthread_mutex_unlock(&p->mu);
            uint64_t now = ob_now_us(); p->heartbeat_due_us = now + heartbeat_interval(lease > now ? lease-now : 0);
        } else if (ob_now_us()-p->heartbeat_sent_us >= (uint64_t)p->api->timeout_ms*1000) {
            ob_ws_disconnect(p->ws); p->heartbeat_id = 0; return 0;
        }
    }
    if (!p->heartbeat_id && ob_now_us() >= p->heartbeat_due_us && ob_ws_connected(p->ws)) {
        rc = ob_ws_begin(p->ws, "heartbeat", NULL, &p->heartbeat_id, 500, &e);
        p->heartbeat_sent_us = ob_now_us(); if (rc) return peer_transport_error(p, &e);
    }
    return 0;
}
static int peer_rpc(ob_remote_peer *p, const char *op, cJSON *body, cJSON **out, ob_remote_error *error)
{
    if (out) *out = NULL;
    uint64_t id = 0, end = ob_now_us() + (uint64_t)p->api->timeout_ms*1000;
    int attempted = 0, repeatable = strcmp(op, "turn") != 0;
    while (alive(p) && ob_now_us() < end) {
        /* Detect loss before reconnect: request IDs do not survive sockets. */
        if (id && !ob_ws_connected(p->ws)) {
            if (!repeatable) return ob_error(error, OB_REMOTE_EHTTP, 0, "TURN outcome lost; setup must restart");
            id = 0;
        }
        int rc = peer_tick(p, 20); if (rc) return ob_error(error, rc, 0, NULL);
        if (!ob_ws_connected(p->ws)) {
            if (attempted && !repeatable) return ob_error(error, OB_REMOTE_EHTTP, 0, "TURN outcome lost; setup must restart");
            id = 0; continue;
        }
        if (!id) {
            ob_api_error ae = {0}; attempted = 1;
            rc = ob_ws_begin(p->ws, op, body, &id, 500, &ae);
            if (rc) {
                int fatal = peer_transport_error(p, &ae); if (fatal) return ob_error(error, fatal, (int)ae.http_status, ae.message);
                id = 0; if (!repeatable) return ob_error(error, OB_REMOTE_EHTTP, 0, "TURN outcome lost; setup must restart");
                continue;
            }
        }
        int status; cJSON *response = NULL;
        if (ob_ws_result(p->ws, id, &status, &response)) {
            if (status < 200 || status >= 300) {
                cJSON_Delete(response); return ob_error(error, OB_REMOTE_EHTTP, status, "Control WebSocket RPC failed");
            }
            if (out) *out = response; else cJSON_Delete(response); return 0;
        }
    }
    ob_ws_disconnect(p->ws); p->heartbeat_id = 0;
    return ob_error(error, atomic_load(&p->stop) ? OB_REMOTE_ECLOSED : OB_REMOTE_ETIMEOUT, 0, "Control WebSocket RPC timed out");
}
static int capabilities(ob_remote_peer *p, int wait_approved)
{
    while (alive(p)) {
        int rc = peer_tick(p, 20); if (rc) return rc;
        if (p->lease_deadline_set && (!wait_approved || p->approved)) return 0;
    }
    return OB_REMOTE_ECLOSED;
}
