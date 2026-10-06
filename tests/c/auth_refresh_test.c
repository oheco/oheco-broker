#define _POSIX_C_SOURCE 200809L
#include "ob_auth.h"
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Standalone native C SDK acceptance. Run ONLY with an isolated open-register
 * control fixture whose access TTL is short (e.g. 200ms–2s). No Go runtime,
 * credentials files, private production state or unverified TLS are used. */
static int64_t now_ms(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static void pause_ms(unsigned n) {struct timespec t={(time_t)(n/1000),(long)(n%1000)*1000000};nanosleep(&t,NULL);}
struct store {
    pthread_mutex_t lock;
    ob_auth_credentials credentials;
    ob_auth_pending pending;
    int has_pending,begins,ends,prepares,commits;
};
static int begin(void *user,ob_auth_credentials *c,ob_auth_pending *p,int *present) {
    struct store *s=user;pthread_mutex_lock(&s->lock);s->begins++;
    *c=s->credentials;*p=s->pending;*present=s->has_pending;return 0;
}
static int prepare(void *user,const ob_auth_credentials *c,const ob_auth_pending *p) {
    (void)c;struct store *s=user;s->pending=*p;s->has_pending=1;s->prepares++;return 0;
}
static int commit(void *user,const ob_auth_credentials *c,const ob_auth_pending *p) {
    (void)p;struct store *s=user;s->credentials=*c;s->has_pending=0;ob_auth_pending_clear(&s->pending);s->commits++;return 0;
}
static void end(void *user) {struct store *s=user;s->ends++;pthread_mutex_unlock(&s->lock);}
struct reader {ob_api_client *api;atomic_int *failed;};
static void *read_account(void *user) {
    struct reader *r=user;
    for(unsigned i=0;i<10;i++) {
        char *response=NULL;ob_api_error e={0};
        if(ob_api_request(r->api,"GET","/v1/me",NULL,NULL,&response,&e))atomic_store(r->failed,1);
        ob_api_response_free(response);pause_ms(15);
    }return NULL;
}
int main(int argc,char **argv) {
    if(argc!=2) {fprintf(stderr,"Usage: auth_refresh_test ISOLATED_FIXTURE_ORIGIN\n");return 2;}
    ob_api_options base={.base_url=argv[1],.timeout_ms=3000};ob_api_error e={0};
    ob_api_client *bootstrap=ob_api_client_create(&base,&e);
    if(!bootstrap){fprintf(stderr,"bootstrap failure (%d)\n",e.code);return 1;}
    ob_api_credentials registration={0};
    if(ob_api_credentials_generate(&registration,&e)){ob_api_client_destroy(bootstrap);return 1;}
    char body[256];snprintf(body,sizeof(body),"{\"name\":\"%s\",\"password\":\"%s\"}",registration.name,registration.password);
    char *response=NULL;
    int rc=ob_api_request(bootstrap,"POST","/v1/auth/register","",body,&response,&e);
    ob_api_credentials_clear(&registration);memset(body,0,sizeof(body));
    struct store store={0};pthread_mutex_init(&store.lock,NULL);
    if(!rc)rc=ob_auth_credentials_parse(response,&store.credentials,&e);
    ob_api_response_free(response);ob_api_client_destroy(bootstrap);
    if(rc){fprintf(stderr,"refresh fixture registration failure (%d HTTP=%ld curl=%d: %s)\n",e.code,e.http_status,e.transport_code,e.message);pthread_mutex_destroy(&store.lock);return 1;}
    ob_auth_options auth={.struct_size=sizeof(auth),.version=1,.credentials=store.credentials,
        .user=&store,.begin=begin,.prepare=prepare,.commit=commit,.end=end};
    ob_api_client *api=ob_api_client_create_with_auth(&base,&auth,&e);
    ob_auth_credentials_clear(&auth.credentials);
    if(!api){fprintf(stderr,"auth client failure (%d)\n",e.code);return 1;}
    ob_auth_manager *manager=ob_api_client_auth_manager(api);ob_auth_credentials snapshot={0};
    int64_t deadline=now_ms()+12000;
    do {pause_ms(20);rc=ob_auth_manager_snapshot(manager,&snapshot,&e);}while(!rc&&snapshot.generation<3&&now_ms()<deadline);
    if(rc||snapshot.generation<3){fprintf(stderr,"idle refresh deadline exceeded\n");rc=1;goto done;}
    pthread_t threads[8];atomic_int failed;atomic_init(&failed,0);struct reader reader={api,&failed};unsigned started=0;
    for(;started<8;started++)if(pthread_create(&threads[started],NULL,read_account,&reader))break;
    for(unsigned i=0;i<started;i++)pthread_join(threads[i],NULL);
    if(started!=8||atomic_load(&failed)){fprintf(stderr,"concurrent account request failed\n");rc=1;goto done;}
    if(ob_auth_manager_snapshot(manager,&snapshot,&e)){rc=1;goto done;}
    printf("{\"standalone_c\":true,\"generation\":%llu,\"proactive_idle\":true,\"concurrent_requests\":80}\n",(unsigned long long)snapshot.generation);
done:
    ob_api_client_destroy(api); /* joins worker BEFORE native callback state dies */
    pthread_mutex_lock(&store.lock);if(store.begins!=store.ends||store.has_pending)rc=1;pthread_mutex_unlock(&store.lock);
    ob_auth_credentials_clear(&snapshot);ob_auth_credentials_clear(&store.credentials);ob_auth_pending_clear(&store.pending);
    pthread_mutex_destroy(&store.lock);return rc?1:0;
}
