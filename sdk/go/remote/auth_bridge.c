#include "auth_bridge.h"
extern int go_ob_auth_begin(uintptr_t, ob_auth_credentials *, ob_auth_pending *, int *);
extern int go_ob_auth_prepare(uintptr_t, ob_auth_credentials *, ob_auth_pending *);
extern int go_ob_auth_commit(uintptr_t, ob_auth_credentials *, ob_auth_pending *);
extern void go_ob_auth_end(uintptr_t);
static int begin(void *user, ob_auth_credentials *c, ob_auth_pending *p, int *present) {
    return go_ob_auth_begin((uintptr_t)user,c,p,present);
}
static int prepare(void *user,const ob_auth_credentials *c,const ob_auth_pending *p) {
    return go_ob_auth_prepare((uintptr_t)user,(ob_auth_credentials *)c,(ob_auth_pending *)p);
}
static int commit(void *user,const ob_auth_credentials *c,const ob_auth_pending *p) {
    return go_ob_auth_commit((uintptr_t)user,(ob_auth_credentials *)c,(ob_auth_pending *)p);
}
static void end(void *user) { go_ob_auth_end((uintptr_t)user); }
void ob_go_auth_storage_init(ob_auth_options *o,uintptr_t handle) {
    o->user=(void *)handle;o->begin=begin;o->prepare=prepare;o->commit=commit;o->end=end;
}
