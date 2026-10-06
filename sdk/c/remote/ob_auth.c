#define _POSIX_C_SOURCE 200809L
#include "ob_api_internal.h"
#include "ob_json.h"
#include <openssl/rand.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#define AUTH_MAX_GENERATION UINT64_C(9007199254740990)
struct ob_auth_manager {
    pthread_mutex_t mu, operation;
    pthread_cond_t cv;
    clockid_t cv_clock;
    pthread_t worker;
    int worker_started, terminal, failures;
    atomic_int stop;
    ob_api_client *transport;
    ob_auth_options options;
    ob_auth_credentials credentials;
    ob_auth_pending pending;
    int has_pending;
    int64_t next_due, retry_after;
    ob_api_error last_error;
};
static void erase(void *p, size_t n) { volatile unsigned char *q=p; while(n--) *q++=0; }
void ob_auth_credentials_clear(ob_auth_credentials *c) { if(c) erase(c,sizeof(*c)); }
void ob_auth_pending_clear(ob_auth_pending *p) { if(p) erase(p,sizeof(*p)); }
static int error(ob_api_error *e, int code, long status, const char *text) {
    if(e) { memset(e,0,sizeof(*e)); e->code=code; e->http_status=status;
        snprintf(e->message,sizeof(e->message),"%s",text); }
    return code;
}
static int64_t epoch_ms(void) { struct timespec t; clock_gettime(CLOCK_REALTIME,&t); return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static int64_t mono_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static int hex(const char *s,size_t n) {
    for(size_t i=0;i<n;i++) if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return 0;
    return s[n]==0;
}
static int uuid(const char s[37]) {
    if(s[36]||s[14]!='4'||!strchr("89ab",s[19])) return 0;
    for(unsigned i=0;i<36;i++) {
        if(i==8||i==13||i==18||i==23) { if(s[i]!='-')return 0; }
        else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return 0;
    } return 1;
}
static int credentials_valid(const ob_auth_credentials *c) {
    return uuid(c->auth_session_id)&&hex(c->token,64)&&hex(c->refresh_token,64)
        &&strcmp(c->token,c->refresh_token)&&c->generation>0&&c->generation<=AUTH_MAX_GENERATION
        &&c->token_expires_at_ms>0&&c->refresh_expires_at_ms>0;
}
static int pending_valid(const ob_auth_pending *p,const ob_auth_credentials *c) {
    return uuid(p->auth_session_id)&&uuid(p->request_id)&&!strcmp(p->auth_session_id,c->auth_session_id)
        &&p->expected_generation==c->generation&&hex(p->next_token,64)&&hex(p->next_refresh_token,64)
        &&strcmp(p->next_token,p->next_refresh_token)&&strcmp(p->next_token,c->token)
        &&strcmp(p->next_token,c->refresh_token)&&strcmp(p->next_refresh_token,c->token)
        &&strcmp(p->next_refresh_token,c->refresh_token);
}
static void encode(const unsigned char *bytes,size_t n,char *out) {
    static const char chars[]="0123456789abcdef";
    for(size_t i=0;i<n;i++) { out[2*i]=chars[bytes[i]>>4]; out[2*i+1]=chars[bytes[i]&15]; } out[2*n]=0;
}
static int new_pending(ob_auth_pending *p,const ob_auth_credentials *c) {
    unsigned char bytes[80]; char raw[33];
    if(RAND_bytes(bytes,sizeof(bytes))!=1) {erase(bytes,sizeof(bytes));return 0;}
    memset(p,0,sizeof(*p)); memcpy(p->auth_session_id,c->auth_session_id,37); p->expected_generation=c->generation;
    bytes[6]=(bytes[6]&15)|64; bytes[8]=(bytes[8]&63)|128;
    encode(bytes,16,raw); snprintf(p->request_id,37,"%.8s-%.4s-%.4s-%.4s-%.12s",raw,raw+8,raw+12,raw+16,raw+20);
    encode(bytes+16,32,p->next_token); encode(bytes+48,32,p->next_refresh_token);
    erase(bytes,sizeof(bytes)); erase(raw,sizeof(raw)); return pending_valid(p,c);
}
/* UTC RFC3339Nano, complete spelling; never infer/ignore timezone or fractions. */
static int64_t timestamp(const char *s) {
    if(!s||strlen(s)<20||strlen(s)>30)return 0;
    int y,m,d,h,min,sec,n=0;
    if(sscanf(s,"%4d-%2d-%2dT%2d:%2d:%2d%n",&y,&m,&d,&h,&min,&sec,&n)!=6||n!=19
        ||s[4]!='-'||s[7]!='-'||s[10]!='T'||s[13]!=':'||s[16]!=':'
        ||y<1970||y>9999||m<1||m>12||d<1||h<0||h>23||min<0||min>59||sec<0||sec>59)return 0;
    for(int i=0;i<19;i++)if(i!=4&&i!=7&&i!=10&&i!=13&&i!=16&&(s[i]<'0'||s[i]>'9'))return 0;
    static const int month_days[]={31,28,31,30,31,30,31,31,30,31,30,31};
    int leap=(y%4==0&&y%100!=0)||y%400==0;
    if(d>month_days[m-1]+(m==2&&leap))return 0;
    int millis=0; const char *p=s+19;
    if(*p=='.') {p++;int digits=0;while(*p>='0'&&*p<='9') {if(digits<3)millis=millis*10+(*p-'0');digits++;p++;}
        if(!digits||digits>9)return 0;while(digits++<3)millis*=10;}
    if(*p!='Z'||p[1])return 0;
    int adjusted=y-(m<=2),era=adjusted/400,yoe=adjusted-era*400;
    int shifted=m+(m>2?-3:9),doy=(153*shifted+2)/5+d-1;
    int64_t days=(int64_t)era*146097+yoe*365+yoe/4-yoe/100+doy-719468;
    return ((days*24+h)*60+min)*60000+(int64_t)sec*1000+millis;
}
static const char *string(cJSON *j,const char *key) {cJSON *v=cJSON_GetObjectItemCaseSensitive(j,key);return cJSON_IsString(v)?v->valuestring:NULL;}
static void json_destroy(cJSON *j) {
    if(j) {for(cJSON *v=j->child;v;v=v->next) if(v->valuestring)erase(v->valuestring,strlen(v->valuestring));cJSON_Delete(j);}
}
static cJSON *auth_json(const char *text) {
    if(!text||strnlen(text,OB_API_MAX_RESPONSE_BYTES+1u)>OB_API_MAX_RESPONSE_BYTES)return NULL;
    int quoted=0;
    for(const char *p=text;*p;p++) {
        if(!quoted){if(*p=='\"')quoted=1;continue;}
        if(*p=='\"'){quoted=0;continue;}
        if(*p=='\\') {if(p[1]=='u'&&!strncmp(p+2,"0000",4))return NULL;if(!p[1])return NULL;p++;}
    }
    cJSON *j=ob_json_parse_complete(text,strlen(text));
    if(!cJSON_IsObject(j)){json_destroy(j);return NULL;}
    unsigned fields=0;
    for(cJSON *a=j->child;a;a=a->next) {
        if(++fields>32){json_destroy(j);return NULL;}
        for(cJSON *b=a->next;b;b=b->next)if(!a->string||!b->string||!strcmp(a->string,b->string)){json_destroy(j);return NULL;}
    }
    return j;
}
int ob_auth_credentials_parse(const char *body,ob_auth_credentials *out,ob_api_error *e) {
    if(e)memset(e,0,sizeof(*e));if(!out)return error(e,OB_API_INVALID,0,"Invalid account credential output");
    ob_auth_credentials_clear(out);cJSON *j=auth_json(body);
    const char *sid=string(j,"auth_session_id"),*token=string(j,"token"),*refresh=string(j,"refresh_token");
    uint64_t generation=0;
    int valid=sid&&strlen(sid)==36&&token&&strlen(token)==64&&refresh&&strlen(refresh)==64
        &&ob_json_uint_field(body,strlen(body),"generation",1,AUTH_MAX_GENERATION,&generation);
    if(valid) {memcpy(out->auth_session_id,sid,37);memcpy(out->token,token,65);memcpy(out->refresh_token,refresh,65);
        out->generation=generation;out->token_expires_at_ms=timestamp(string(j,"token_expires_at"));
        out->refresh_expires_at_ms=timestamp(string(j,"refresh_expires_at"));valid=credentials_valid(out);}
    json_destroy(j);
    if(!valid){ob_auth_credentials_clear(out);return error(e,OB_API_JSON,0,"Invalid account credential response");}return 0;
}
static int receipt(const char *body,const ob_auth_credentials *before,const ob_auth_pending *p,ob_auth_credentials *after) {
    if(!body)return 0;size_t len=strlen(body);cJSON *j=auth_json(body);
    const char *sid=string(j,"auth_session_id"),*access=string(j,"token_expires_at"),*refresh=string(j,"refresh_expires_at");
    uint64_t generation=0;unsigned count=0;int valid=cJSON_IsObject(j);
    for(cJSON *v=j?j->child:NULL;v;v=v->next) {count++;if(!v->string||
        (strcmp(v->string,"auth_session_id")&&strcmp(v->string,"generation")&&strcmp(v->string,"token_expires_at")&&strcmp(v->string,"refresh_expires_at")))valid=0;
        for(cJSON *w=v->next;w;w=w->next)if(w->string&&v->string&&!strcmp(v->string,w->string))valid=0;}
    valid=valid&&count==4&&sid&&!strcmp(sid,before->auth_session_id)
        &&ob_json_uint_field(body,len,"generation",before->generation+1,before->generation+1,&generation);
    int64_t a=timestamp(access),r=timestamp(refresh);valid=valid&&a>0&&r>0;
    if(valid) {*after=*before;after->generation=generation;after->token_expires_at_ms=a;after->refresh_expires_at_ms=r;
        memcpy(after->token,p->next_token,65);memcpy(after->refresh_token,p->next_refresh_token,65);}
    json_destroy(j);return valid;
}
static int cancelled(void *user) {return atomic_load(&((ob_auth_manager *)user)->stop);}
struct refresh_cancel {ob_auth_manager *manager;int (*callback)(void *);void *user;};
static int refresh_cancelled(void *user) {
    struct refresh_cancel *c=user;return cancelled(c->manager)||(c->callback&&c->callback(c->user));
}
static void schedule_locked(ob_auth_manager *m) {
    int64_t remaining=m->credentials.token_expires_at_ms-epoch_ms();
    int64_t lead=m->options.refresh_before_ms?m->options.refresh_before_ms:600000;
    if(remaining>0&&lead>remaining/5)lead=remaining/5;
    if(lead<1)lead=1;
    /* Jitter only brings the deadline forward, never past access expiry. */
    unsigned char random=0;int64_t jitter=lead/20;if(jitter>30000)jitter=30000;
    if(jitter&&RAND_bytes(&random,1)==1)jitter=jitter*random/255;else jitter=0;
    m->next_due=mono_ms()+(remaining>lead+jitter?remaining-lead-jitter:0);
    m->retry_after=0;
}
static int same_credentials(const ob_auth_credentials *a,const ob_auth_credentials *b) {
    return a->generation==b->generation&&!strcmp(a->token,b->token)&&!strcmp(a->refresh_token,b->refresh_token)
        &&a->token_expires_at_ms==b->token_expires_at_ms&&a->refresh_expires_at_ms==b->refresh_expires_at_ms;
}
static int rotate(ob_auth_manager *m,int force,uint64_t requested_generation,ob_api_error *e,
                  int (*callback)(void *),void *user) {
    ob_auth_credentials working={0},after={0};ob_auth_pending pending={0};int has_pending=0,begun=0,result=0;
    char *body=NULL,*response=NULL;cJSON *j=NULL;
    struct refresh_cancel cancellation={m,callback,user};
    for(;;) {
        if(refresh_cancelled(&cancellation))return error(e,OB_API_CANCELLED,0,"Account refresh cancelled");
        int acquired=pthread_mutex_trylock(&m->operation);
        if(!acquired)break;
        if(acquired!=EBUSY)return error(e,OB_API_INVALID,0,"Account refresh coordination failed");
        struct timespec delay={0,10000000};nanosleep(&delay,NULL);
    }
    if(refresh_cancelled(&cancellation)) {result=error(e,OB_API_CANCELLED,0,"Account refresh cancelled");goto done;}
    pthread_mutex_lock(&m->mu);working=m->credentials;pending=m->pending;has_pending=m->has_pending;
    int due=mono_ms()>=m->next_due;
    pthread_mutex_unlock(&m->mu);
    if(m->options.begin) {
        begun=1;
        if(m->options.begin(m->options.user,&working,&pending,&has_pending)) {result=error(e,OB_API_STORAGE,0,"Credential storage coordination failed");goto done;}
    }
    if(!credentials_valid(&working)||strcmp(working.auth_session_id,m->options.credentials.auth_session_id)) {
        result=error(e,OB_API_AUTH,0,"Account authority changed; explicit login required");goto done;
    }
    pthread_mutex_lock(&m->mu);
    if(working.generation<m->credentials.generation||
        (working.generation==m->credentials.generation&&!same_credentials(&working,&m->credentials))) {
        pthread_mutex_unlock(&m->mu);result=error(e,OB_API_STORAGE,0,"Credential storage is stale or inconsistent");goto done;
    }
    int adopted=working.generation>m->credentials.generation;
    if(adopted) {m->credentials=working;ob_auth_pending_clear(&m->pending);m->has_pending=0;schedule_locked(m);due=mono_ms()>=m->next_due;}
    pthread_mutex_unlock(&m->mu);
    /* A pending attempt from an older committed generation must never overwrite
     * the newer profile. Storage Begin owns clearing stale durable journals. */
    if(has_pending&&pending.expected_generation<working.generation)has_pending=0;
    if(has_pending&&!pending_valid(&pending,&working)) {result=error(e,OB_API_STORAGE,0,"Invalid pending credential refresh");goto done;}
    /* A committed pending attempt may have extended the current family's idle
     * deadline beyond this predecessor's stored deadline. Only its validated
     * exact replay may bypass local expiry; the server checks live/revoked
     * authority before returning a receipt. Fresh attempts still fail closed. */
    if(!has_pending&&working.refresh_expires_at_ms<=epoch_ms()) {result=error(e,OB_API_AUTH,401,"Refresh authority expired; explicit login required");goto done;}
    if(!has_pending&&(!force||adopted||working.generation!=requested_generation)&&!due&&working.token_expires_at_ms>epoch_ms())goto done;
    if(!has_pending) {
        if(!new_pending(&pending,&working)) {result=error(e,OB_API_CRYPTO,0,"Secure refresh credential generation failed");goto done;}
        if(m->options.prepare&&m->options.prepare(m->options.user,&working,&pending)) {result=error(e,OB_API_STORAGE,0,"Credential refresh preparation failed");goto done;}
        has_pending=1;
    }
    pthread_mutex_lock(&m->mu);m->pending=pending;m->has_pending=1;pthread_mutex_unlock(&m->mu);
    if(refresh_cancelled(&cancellation)) {result=error(e,OB_API_CANCELLED,0,"Account refresh cancelled");goto done;}
    j=cJSON_CreateObject();
    if(!j||!cJSON_AddStringToObject(j,"auth_session_id",working.auth_session_id)||
        !cJSON_AddNumberToObject(j,"expected_generation",(double)pending.expected_generation)||
        !cJSON_AddStringToObject(j,"request_id",pending.request_id)||
        !cJSON_AddStringToObject(j,"next_token",pending.next_token)||
        !cJSON_AddStringToObject(j,"next_refresh_token",pending.next_refresh_token)||!(body=cJSON_PrintUnformatted(j))) {
        result=error(e,OB_API_NOMEM,0,"Allocation failed");goto done;
    }
    result=ob_api_request_cancelled(m->transport,"POST","/v1/auth/refresh",working.refresh_token,body,&response,e,refresh_cancelled,&cancellation);
    if(result) {if(refresh_cancelled(&cancellation))result=error(e,OB_API_CANCELLED,0,"Account refresh cancelled");goto done;}
    if(!receipt(response,&working,&pending,&after)) {result=error(e,OB_API_JSON,0,"Invalid credential refresh receipt");goto done;}
    if(m->options.commit&&m->options.commit(m->options.user,&after,&pending)) {result=error(e,OB_API_STORAGE,0,"Credential refresh commit failed");goto done;}
    pthread_mutex_lock(&m->mu);m->credentials=after;ob_auth_pending_clear(&m->pending);m->has_pending=0;schedule_locked(m);pthread_mutex_unlock(&m->mu);
done:
    if(begun)m->options.end(m->options.user);
    pthread_mutex_lock(&m->mu);
    if(result) {
        if(e)m->last_error=*e;
        m->terminal=result==OB_API_AUTH||(e&&(e->http_status==401||e->http_status==403));
        if(m->failures<5)m->failures++;
        m->retry_after=mono_ms()+((int64_t)1<<(m->failures-1))*1000;
    } else {memset(&m->last_error,0,sizeof(m->last_error));m->terminal=0;m->failures=0;m->retry_after=0;}
    pthread_cond_broadcast(&m->cv);pthread_mutex_unlock(&m->mu);
    json_destroy(j);if(body){erase(body,strlen(body));cJSON_free(body);}ob_api_response_free(response);
    ob_auth_credentials_clear(&working);ob_auth_credentials_clear(&after);ob_auth_pending_clear(&pending);
    pthread_mutex_unlock(&m->operation);return result;
}
static int refresh(ob_auth_manager *m,int force,ob_api_error *e,int (*callback)(void *),void *user) {
    if(e)memset(e,0,sizeof(*e));if(!m)return error(e,OB_API_INVALID,0,"No account refresh manager");
    pthread_mutex_lock(&m->mu);uint64_t generation=m->credentials.generation;pthread_mutex_unlock(&m->mu);
    int rc=rotate(m,!!force,generation,e,callback,user);
    if(!rc) {
        pthread_mutex_lock(&m->mu);
        int expired=m->credentials.token_expires_at_ms<=epoch_ms();
        int live=m->credentials.refresh_expires_at_ms>epoch_ms();
        generation=m->credentials.generation;
        pthread_mutex_unlock(&m->mu);
        /* A durable pending receipt can be older than the access TTL. Confirm
         * it first, then use the committed child refresh for one new rotation. */
        if(expired&&live)rc=rotate(m,1,generation,e,callback,user);
    }
    return rc;
}
int ob_auth_manager_refresh(ob_auth_manager *m,int force,ob_api_error *e) {return refresh(m,force,e,NULL,NULL);}
int ob_auth_manager_refresh_cancelled(ob_auth_manager *m,int force,ob_api_error *e,int (*callback)(void *),void *user) {
    return refresh(m,force,e,callback,user);
}
int ob_auth_manager_snapshot(ob_auth_manager *m,ob_auth_credentials *c,ob_api_error *e) {
    if(e)memset(e,0,sizeof(*e));if(!m||!c)return error(e,OB_API_INVALID,0,"Invalid account snapshot arguments");
    pthread_mutex_lock(&m->mu);*c=m->credentials;pthread_mutex_unlock(&m->mu);return 0;
}
int ob_auth_account_bearer(ob_auth_manager *m,char token[65],ob_api_error *e,int (*cancel)(void *),void *user) {
    if(cancel&&cancel(user))return error(e,OB_API_CANCELLED,0,"Account request cancelled");
    pthread_mutex_lock(&m->mu);int64_t now=mono_ms();
    int expired=m->credentials.token_expires_at_ms<=epoch_ms();
    int attempt=(now>=m->next_due||m->options.begin)&&now>=m->retry_after&&!m->terminal;
    ob_api_error last=m->last_error;pthread_mutex_unlock(&m->mu);
    if(attempt) {int rc=refresh(m,0,e,cancel,user);if(rc&&expired)return rc;}
    pthread_mutex_lock(&m->mu);expired=m->credentials.token_expires_at_ms<=epoch_ms();
    int terminal=m->terminal;last=m->last_error;
    if(!expired&&!terminal)memcpy(token,m->credentials.token,65);
    pthread_mutex_unlock(&m->mu);
    if(terminal||expired) {if(last.code) {if(e)*e=last;return last.code;}
        return error(e,OB_API_AUTH,401,"Account credentials expired; refresh required");}
    if(cancel&&cancel(user)) {erase(token,65);return error(e,OB_API_CANCELLED,0,"Account request cancelled");}
    return 0;
}
static void *worker(void *user) {
    ob_auth_manager *m=user;
    while(!cancelled(m)) {
        pthread_mutex_lock(&m->mu);int64_t now=mono_ms();
        int due=!m->terminal&&(m->has_pending||now>=m->next_due)&&now>=m->retry_after;
        pthread_mutex_unlock(&m->mu);
        if(due) {ob_api_error e={0};rotate(m,0,0,&e,NULL,NULL);continue;}
        pthread_mutex_lock(&m->mu);
        if(!cancelled(m)) {struct timespec t;clock_gettime(m->cv_clock,&t);t.tv_nsec+=100000000;
            t.tv_sec+=t.tv_nsec/1000000000;t.tv_nsec%=1000000000;pthread_cond_timedwait(&m->cv,&m->mu,&t);}
        pthread_mutex_unlock(&m->mu);
    }return NULL;
}
void ob_auth_manager_cancel(ob_auth_manager *m) {
    if(!m)return;atomic_store(&m->stop,1);pthread_mutex_lock(&m->mu);pthread_cond_broadcast(&m->cv);pthread_mutex_unlock(&m->mu);
}
void ob_auth_manager_destroy(ob_auth_manager *m) {
    if(!m)return;ob_auth_manager_cancel(m);
    if(m->worker_started)pthread_join(m->worker,NULL);
    ob_api_client_destroy(m->transport);pthread_cond_destroy(&m->cv);pthread_mutex_destroy(&m->operation);pthread_mutex_destroy(&m->mu);
    erase(m,sizeof(*m));free(m);
}
ob_auth_manager *ob_api_client_auth_manager(ob_api_client *c) {return c?c->auth:NULL;}
ob_api_client *ob_api_client_create_with_auth(const ob_api_options *base,const ob_auth_options *o,ob_api_error *e) {
    if(!o||o->struct_size!=sizeof(*o)||o->version!=1||!credentials_valid(&o->credentials)||o->refresh_before_ms<0||
        o->refresh_timeout_ms<0||o->refresh_timeout_ms>30000||
        (base&&base->tenant_token&&*base->tenant_token&&strcmp(base->tenant_token,o->credentials.token))||
        ((o->begin||o->prepare||o->commit||o->end)&&!(o->begin&&o->prepare&&o->commit&&o->end))) {
        error(e,OB_API_INVALID,0,"Invalid account refresh options");return NULL;
    }
    ob_api_client *c=ob_api_client_create(base,e);if(!c)return NULL;
    ob_auth_manager *m=calloc(1,sizeof(*m));if(!m) {ob_api_client_destroy(c);error(e,OB_API_NOMEM,0,"Allocation failed");return NULL;}
    int mu_ready=0,op_ready=0,cv_ready=0;
    if(pthread_mutex_init(&m->mu,NULL))goto init_error;mu_ready=1;
    if(pthread_mutex_init(&m->operation,NULL))goto init_error;op_ready=1;
    pthread_condattr_t attr;if(pthread_condattr_init(&attr))goto init_error;
    m->cv_clock=CLOCK_REALTIME;
    if(!pthread_condattr_setclock(&attr,CLOCK_MONOTONIC))m->cv_clock=CLOCK_MONOTONIC;
    int cv_result=pthread_cond_init(&m->cv,&attr);pthread_condattr_destroy(&attr);if(cv_result)goto init_error;cv_ready=1;
    m->options=*o;m->credentials=o->credentials;
    /* Retain only the immutable authority binding in options, not predecessor
     * secrets that no longer serve any request or recovery purpose. */
    ob_auth_credentials_clear(&m->options.credentials);
    memcpy(m->options.credentials.auth_session_id,o->credentials.auth_session_id,37);
    atomic_init(&m->stop,0);schedule_locked(m);
    ob_api_options transport=*base;transport.tenant_token=NULL;transport.timeout_ms=o->refresh_timeout_ms?o->refresh_timeout_ms:10000;
    m->transport=ob_api_client_create(&transport,e);if(!m->transport)goto init_error;
    if(c->tenant_token){erase(c->tenant_token,strlen(c->tenant_token));free(c->tenant_token);c->tenant_token=NULL;}
    c->auth=m;
    if(pthread_create(&m->worker,NULL,worker,m)) {c->auth=NULL;goto init_error;}
    m->worker_started=1;return c;
init_error:
    ob_api_client_destroy(m->transport);
    if(cv_ready)pthread_cond_destroy(&m->cv);if(op_ready)pthread_mutex_destroy(&m->operation);if(mu_ready)pthread_mutex_destroy(&m->mu);
    erase(m,sizeof(*m));free(m);ob_api_client_destroy(c);error(e,OB_API_NOMEM,0,"Account refresh initialization failed");return NULL;
}
