#include "internal.h"
#include <string.h>

void ob_remote_reconnect_policy_init(ob_remote_reconnect_policy *p)
{
    if (!p) return;
    memset(p, 0, sizeof(*p)); p->struct_size = sizeof(*p);
    p->max_attempts = 8; p->initial_delay_ms = 1000; p->max_delay_ms = 15000;
    p->retry_budget_ms = 60000; p->flow_grace_ms = 120000; p->stable_reset_ms = 30000;
    p->transport_timeout_ms = 15000;
}
static int normalize(const ob_remote_reconnect_policy *in, ob_remote_reconnect_policy *out)
{
    ob_remote_reconnect_policy_init(out);
    if (!in) return 0;
    if ((in->struct_size && in->struct_size != sizeof(*in)) || in->disabled > 1)
        return OB_REMOTE_EINVAL;
    out->disabled = in->disabled;
#define COPY_DEFAULT(field) do { if (in->field) out->field = in->field; } while (0)
    COPY_DEFAULT(max_attempts); COPY_DEFAULT(initial_delay_ms); COPY_DEFAULT(max_delay_ms);
    COPY_DEFAULT(retry_budget_ms); COPY_DEFAULT(flow_grace_ms); COPY_DEFAULT(stable_reset_ms);
    COPY_DEFAULT(transport_timeout_ms);
#undef COPY_DEFAULT
    if (out->max_attempts > 10000 || out->initial_delay_ms > out->max_delay_ms ||
        out->max_delay_ms > 300000 || out->retry_budget_ms > 3600000 ||
        out->flow_grace_ms > 3600000 || out->stable_reset_ms > 3600000 ||
        out->transport_timeout_ms < 1000 || out->transport_timeout_ms > 300000)
        return OB_REMOTE_EINVAL;
    return 0;
}
void ob_recovery_init(struct ob_recovery *r)
{
    memset(r, 0, sizeof(*r)); ob_remote_reconnect_policy_init(&r->policy);
    atomic_init(&r->requested, 0); r->info.state = OB_REMOTE_STATE_CONNECTING;
}
void ob_recovery_set_locked(struct ob_recovery *r, ob_remote_connection_state state,
                            const ob_remote_error *error)
{
    r->info.state = state;
    if (error) r->info.last_error = *error;
    r->callback_pending = 1;
}
static ob_remote_connection_info snapshot(struct ob_recovery *r)
{
    ob_remote_connection_info info = r->info;
    uint64_t now = ob_now_us();
    info.next_retry_ms = r->retry_us > now ? (r->retry_us - now + 999) / 1000 : 0;
    return info;
}
void ob_recovery_deliver(struct ob_recovery *r, pthread_mutex_t *mu)
{
    pthread_mutex_lock(mu);
    ob_remote_state_callback callback = r->callback_pending ? r->callback : NULL;
    void *data = r->callback_data;
    ob_remote_connection_info info = snapshot(r);
    r->callback_pending = 0;
    pthread_mutex_unlock(mu);
    if (callback) callback(&info, data);
}
int ob_remote_peer_set_reconnect_policy(ob_remote_peer *p,
                         const ob_remote_reconnect_policy *policy, ob_remote_error *error)
{
    ob_remote_reconnect_policy normalized;
    if (!p || normalize(policy, &normalized)) return ob_error(error, OB_REMOTE_EINVAL, 0, NULL);
    pthread_mutex_lock(&p->mu); p->recovery.policy = normalized;
    pthread_cond_broadcast(&p->cv); pthread_mutex_unlock(&p->mu); ob_wake(p);
    return ob_error(error, 0, 0, NULL);
}
int ob_remote_server_set_reconnect_policy(ob_remote_server *s,
                         const ob_remote_reconnect_policy *policy, ob_remote_error *error)
{
    ob_remote_reconnect_policy normalized;
    if (!s || normalize(policy, &normalized)) return ob_error(error, OB_REMOTE_EINVAL, 0, NULL);
    pthread_mutex_lock(&s->mu); s->recovery.policy = normalized;
    pthread_cond_broadcast(&s->cv); pthread_mutex_unlock(&s->mu);
    return ob_error(error, 0, 0, NULL);
}
int ob_remote_peer_get_state(ob_remote_peer *p, ob_remote_connection_info *info)
{
    if (!p || !info) return OB_REMOTE_EINVAL;
    pthread_mutex_lock(&p->mu); *info = snapshot(&p->recovery); pthread_mutex_unlock(&p->mu);
    return 0;
}
int ob_remote_server_get_state(ob_remote_server *s, ob_remote_connection_info *info)
{
    if (!s || !info) return OB_REMOTE_EINVAL;
    pthread_mutex_lock(&s->mu); *info = snapshot(&s->recovery); pthread_mutex_unlock(&s->mu);
    return 0;
}
int ob_remote_peer_set_state_callback(ob_remote_peer *p,
                         ob_remote_state_callback callback, void *data)
{
    if (!p) return OB_REMOTE_EINVAL;
    pthread_mutex_lock(&p->mu); p->recovery.callback = callback;
    p->recovery.callback_data = data; p->recovery.callback_pending = 1;
    pthread_mutex_unlock(&p->mu); ob_wake(p); return 0;
}
int ob_remote_server_set_state_callback(ob_remote_server *s,
                         ob_remote_state_callback callback, void *data)
{
    if (!s) return OB_REMOTE_EINVAL;
    pthread_mutex_lock(&s->mu); s->recovery.callback = callback;
    s->recovery.callback_data = data; s->recovery.callback_pending = 1;
    pthread_mutex_unlock(&s->mu); return 0;
}
int ob_remote_peer_reconnect(ob_remote_peer *p, ob_remote_error *error)
{
    if (!p) return ob_error(error, OB_REMOTE_EINVAL, 0, NULL);
    pthread_mutex_lock(&p->mu);
    int rc = atomic_load(&p->stop) ? (p->result ? p->result : OB_REMOTE_ECLOSED) : 0;
    if (!rc && p->recovery.info.state != OB_REMOTE_STATE_CONNECTED) {
        atomic_store(&p->recovery.requested, 1); pthread_cond_broadcast(&p->cv);
    }
    if (rc && error) *error = p->error;
    pthread_mutex_unlock(&p->mu); ob_wake(p);
    return rc ? rc : ob_error(error, 0, 0, NULL);
}
int ob_remote_server_reconnect(ob_remote_server *s, ob_remote_error *error)
{
    if (!s) return ob_error(error, OB_REMOTE_EINVAL, 0, NULL);
    pthread_mutex_lock(&s->mu);
    int rc = atomic_load(&s->stop) ? (s->result ? s->result : OB_REMOTE_ECLOSED) : 0;
    if (!rc && s->recovery.info.state != OB_REMOTE_STATE_CONNECTED) {
        atomic_store(&s->recovery.requested, 1); pthread_cond_broadcast(&s->cv);
    }
    if (rc && error) *error = s->error;
    pthread_mutex_unlock(&s->mu);
    return rc ? rc : ob_error(error, 0, 0, NULL);
}
