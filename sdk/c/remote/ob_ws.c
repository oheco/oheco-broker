#define _POSIX_C_SOURCE 200809L
#include "ob_ws.h"
#include "ob_api_internal.h"
#include "ob_json.h"
#include <curl/websockets.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <inttypes.h>

struct queued { struct queued *next; cJSON *json; size_t bytes; };
struct ob_ws {
    ob_api_client *api;
    int broker;
    char *id, *bearer;
    CURL *easy;
    struct curl_slist *headers, *resolve;
    curl_socket_t socket;
    ob_ws_cancel cancel; void *arg;
    pthread_t owner;
    uint64_t next_id, pending[8];
    char *frame; size_t used, frame_offset, header_bytes;
    int fragment, subprotocol, header_invalid;
    struct queued *head, *tail;
    size_t count, bytes;
};
static uint64_t now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static int fail(ob_api_error *e, int code, long status, const char *text) {
    if (e) { memset(e,0,sizeof(*e)); e->code=code; e->http_status=status;
        snprintf(e->message,sizeof(e->message),"%s",text); }
    return code;
}
static int owner(ob_ws *w) { return w && pthread_equal(w->owner,pthread_self()); }
static int cancelled(ob_ws *w) { return w->cancel && w->cancel(w->arg); }
static void wipe(char *s) { if (s) { volatile char *p=s; size_t n=strlen(s); while(n--) *p++=0; } }
static const char *str(cJSON *j,const char *k) {
    cJSON *v=cJSON_GetObjectItemCaseSensitive(j,k); return cJSON_IsString(v)?v->valuestring:NULL;
}
static int integer(cJSON *v, uint64_t min, uint64_t max) {
    return cJSON_IsNumber(v) && isfinite(v->valuedouble) && v->valuedouble >= (double)min
        && v->valuedouble <= (double)max && floor(v->valuedouble)==v->valuedouble;
}
/* cJSON is pristine; parser invocation is serialized in ob_json. Validate
 * UTF-8, NUL escapes and duplicate keys ourselves instead of patching it. */
static int utf8(const unsigned char *s,size_t n) {
    for(size_t i=0;i<n;) {
        unsigned c=s[i++], need; uint32_t cp, min;
        if(c<128) { if(!c) return 0; continue; }
        if(c>=0xc2 && c<=0xdf) {need=1;cp=c&31;min=128;}
        else if(c>=0xe0 && c<=0xef) {need=2;cp=c&15;min=2048;}
        else if(c>=0xf0 && c<=0xf4) {need=3;cp=c&7;min=65536;}
        else return 0;
        if(need>n-i) return 0;
        while(need--) {c=s[i++];if((c&0xc0)!=0x80)return 0;cp=(cp<<6)|(c&63);}
        if(cp<min || cp>0x10ffff || (cp>=0xd800 && cp<=0xdfff))return 0;
    } return 1;
}
static int unique(cJSON *j,unsigned depth,unsigned *nodes) {
    if(depth>32||++*nodes>16384)return 0;
    unsigned members=0;
    for(cJSON *a=j?j->child:NULL;a;a=a->next) {
        /* Bound quadratic object-key comparison work, not only heap bytes. */
        if(cJSON_IsObject(j)) {
            if(++members>512)return 0;
            for(cJSON *b=a->next;b;b=b->next)
                if(!a->string || !b->string || !strcmp(a->string,b->string))return 0;
        }
        if(!unique(a,depth+1,nodes))return 0;
    } return 1;
}
static int fields(cJSON *j,const char *const *names,unsigned n) {
    unsigned seen=0; if(!cJSON_IsObject(j))return 0;
    for(cJSON *v=j->child;v;v=v->next) {
        unsigned i;for(i=0;i<n;i++)if(v->string&&!strcmp(v->string,names[i]))break;
        if(i==n||(seen&(1u<<i)))return 0; seen|=1u<<i;
    } return seen==((1u<<n)-1);
}
static int enqueue(ob_ws *w) {
    if(!utf8((unsigned char*)w->frame,w->used))return OB_API_JSON;
    int quoted=0;
    for(size_t i=0;i<w->used;i++) {
        char c=w->frame[i];if(c=='"')quoted=!quoted;
        else if(quoted&&c=='\\') {
            if(i+5<w->used && w->frame[i+1]=='u' && !memcmp(w->frame+i+2,"0000",4))return OB_API_JSON;
            ++i;
        }
    }
    cJSON *j=ob_json_parse_complete(w->frame,w->used);
    unsigned nodes=0;
    if(!j||!unique(j,0,&nodes)) {cJSON_Delete(j);return OB_API_JSON;}
    cJSON *version=cJSON_GetObjectItemCaseSensitive(j,"v");const char *type=str(j,"type");
    int ok=integer(version,1,1)&&type&&ob_json_uint_field(w->frame,w->used,"v",1,1,NULL); uint64_t id=0;
    static const char *const result[]={"v","type","id","status","body"};
    static const char *const push[]={"v","type","body"};
    static const char *const message[]={"v","type","sequence","data"};
    static const char *const revoked[]={"v","type","status","body"};
    if(ok&&!strcmp(type,"result")) {
        cJSON *v=cJSON_GetObjectItemCaseSensitive(j,"id");
        ok=fields(j,result,5)&&integer(v,1,9007199254740991ULL)
            &&ob_json_uint_field(w->frame,w->used,"id",1,9007199254740991ULL,&id)
            &&integer(cJSON_GetObjectItemCaseSensitive(j,"status"),100,599)
            &&ob_json_uint_field(w->frame,w->used,"status",100,599,NULL);
        if(ok) {ok=0;
            for(unsigned i=0;i<8;i++)if(w->pending[i]==id){ok=1;break;}
            for(struct queued *q=w->head;q;q=q->next)if(str(q->json,"type")&&!strcmp(str(q->json,"type"),"result")
                &&cJSON_GetObjectItemCaseSensitive(q->json,"id")->valuedouble==(double)id)ok=0;
        }
    } else if(ok&&(!strcmp(type,"sessions")||!strcmp(type,"capabilities"))) {
        ok=fields(j,push,3)&&cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(j,"body"))
            &&(w->broker?!strcmp(type,"sessions"):!strcmp(type,"capabilities"));
    } else if(ok&&!strcmp(type,"message")) {
        ok=!w->broker&&fields(j,message,4)&&integer(cJSON_GetObjectItemCaseSensitive(j,"sequence"),1,9007199254740991ULL)
            &&ob_json_uint_field(w->frame,w->used,"sequence",1,9007199254740991ULL,NULL)
            &&str(j,"data")&&strlen(str(j,"data"))<=32768;
    } else if(ok&&!strcmp(type,"revoked")) {
        ok=fields(j,revoked,4)&&integer(cJSON_GetObjectItemCaseSensitive(j,"status"),400,599)
            &&ob_json_uint_field(w->frame,w->used,"status",400,599,NULL)
            &&cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(j,"body"));
    } else ok=0;
    if(!ok){cJSON_Delete(j);return OB_API_JSON;}
    if(w->count>=OB_WS_MAX_QUEUE_COUNT || w->used>OB_WS_MAX_QUEUE_BYTES-w->bytes) {
        cJSON_Delete(j);return OB_API_LIMIT;
    }
    struct queued *q=calloc(1,sizeof(*q));if(!q){cJSON_Delete(j);return OB_API_NOMEM;}
    q->json=j;q->bytes=w->used;
    if(w->tail)w->tail->next=q;else w->head=q;w->tail=q;w->count++;w->bytes+=q->bytes;
    return 0;
}
ob_ws *ob_ws_create(ob_api_client *api,int broker,const char *id,const char *bearer,ob_ws_cancel cancel,void *arg) {
    if(!api||!id||strlen(id)!=36||!bearer||!*bearer||strlen(bearer)>8192)return NULL;
    for(const char *p=id;*p;p++)if(!strchr("0123456789abcdef-",*p))return NULL;
    for(const char *p=bearer;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||strchr("._~+/-=",*p)))return NULL;
    ob_ws *w=calloc(1,sizeof(*w));if(!w)return NULL;
    w->api=api;w->broker=broker;w->id=strdup(id);w->bearer=strdup(bearer);
    w->cancel=cancel;w->arg=arg;w->owner=pthread_self();w->socket=CURL_SOCKET_BAD;
    w->frame=malloc(OB_WS_MAX_FRAME+1);
    if(!w->id||!w->bearer||!w->frame){wipe(w->bearer);free(w->bearer);free(w->id);free(w->frame);free(w);return NULL;}
    return w;
}
void ob_ws_disconnect(ob_ws *w) {
    if(!owner(w))return;
    if(w->easy)curl_easy_cleanup(w->easy);w->easy=NULL;w->socket=CURL_SOCKET_BAD;
    for(struct curl_slist *h=w->headers;h;h=h->next)wipe(h->data);
    curl_slist_free_all(w->headers);curl_slist_free_all(w->resolve);w->headers=w->resolve=NULL;
    while(w->head){struct queued *q=w->head;w->head=q->next;cJSON_Delete(q->json);free(q);}
    w->tail=NULL;w->count=w->bytes=w->used=w->frame_offset=w->header_bytes=0;
    w->fragment=w->subprotocol=w->header_invalid=0;memset(w->pending,0,sizeof(w->pending));
}
void ob_ws_destroy(ob_ws *w) { if(!owner(w))return;ob_ws_disconnect(w);wipe(w->bearer);free(w->bearer);free(w->id);free(w->frame);free(w); }
int ob_ws_connected(const ob_ws *w) {return w&&w->easy&&w->socket!=CURL_SOCKET_BAD;}
static int progress(void *arg,curl_off_t a,curl_off_t b,curl_off_t c,curl_off_t d) {
    (void)a;(void)b;(void)c;(void)d;return cancelled(arg);
}
static size_t header(char *p,size_t size,size_t count,void *arg) {
    ob_ws *w=arg;if(count&&size>SIZE_MAX/count)return 0;size_t n=size*count;
    if(n>65536-w->header_bytes)return 0;w->header_bytes+=n;
    const char *key="Sec-WebSocket-Protocol:";size_t k=strlen(key);
    if(n>=k&&!strncasecmp(p,key,k)) {
        size_t end=n;while(end>k&&(p[end-1]=='\r'||p[end-1]=='\n'||p[end-1]==' '||p[end-1]=='\t'))end--;
        size_t start=k;while(start<end&&(p[start]==' '||p[start]=='\t'))start++;
        if(w->subprotocol || end-start!=strlen("ob-signaling-v1") || memcmp(p+start,"ob-signaling-v1",end-start))w->header_invalid=1;
        else w->subprotocol=1;
    } return n;
}
int ob_ws_connect(ob_ws *w,uint64_t consumed,long timeout,ob_api_error *e) {
    if(!owner(w)||consumed>9007199254740991ULL)return fail(e,OB_API_INVALID,0,"Invalid WebSocket owner/cursor");
    ob_ws_disconnect(w);if(cancelled(w))return fail(e,OB_API_TRANSPORT,0,"WebSocket cancelled");
    char path[180];snprintf(path,sizeof(path),w->broker?"/v1/ws/brokers/%s":"/v1/ws/sessions/%s?after=%" PRIu64,w->id,consumed);
    const char *base=w->api->base_url;const char *tail=base+(!strncmp(base,"https://",8)?8:7);
    char *url=malloc(strlen(base)+strlen(path)+1),*auth=malloc(strlen(w->bearer)+23);
    if(!url||!auth){free(url);free(auth);return fail(e,OB_API_NOMEM,0,"WebSocket allocation failed");}
    sprintf(url,"%s%s%s",!strncmp(base,"https://",8)?"wss://":"ws://",tail,path);
    sprintf(auth,"Authorization: Bearer %s",w->bearer);
    w->headers=curl_slist_append(NULL,auth);wipe(auth);free(auth);
    struct curl_slist *tmp=w->headers?curl_slist_append(w->headers,"Sec-WebSocket-Protocol: ob-signaling-v1"):NULL;
    if(!tmp){free(url);ob_ws_disconnect(w);return fail(e,OB_API_NOMEM,0,"WebSocket allocation failed");}w->headers=tmp;
    if(w->api->localhost_resolve)w->resolve=curl_slist_append(NULL,w->api->localhost_resolve);
    w->easy=curl_easy_init();CURLcode rc=CURLE_FAILED_INIT;long status=0;
    if(!w->easy)goto done;
    if(timeout<=0||timeout>w->api->timeout_ms)timeout=w->api->timeout_ms;
#define OPT(k,v) do {rc=curl_easy_setopt(w->easy,k,v);if(rc!=CURLE_OK)goto done;}while(0)
    OPT(CURLOPT_URL,url);OPT(CURLOPT_CONNECT_ONLY,2L);OPT(CURLOPT_HTTPHEADER,w->headers);
    OPT(CURLOPT_NOSIGNAL,1L);OPT(CURLOPT_TIMEOUT_MS,timeout);OPT(CURLOPT_CONNECTTIMEOUT_MS,timeout);
    OPT(CURLOPT_PROXY,"");OPT(CURLOPT_FOLLOWLOCATION,0L);OPT(CURLOPT_MAXREDIRS,0L);
    OPT(CURLOPT_PROTOCOLS_STR,"ws,wss");OPT(CURLOPT_REDIR_PROTOCOLS_STR,"wss");
    /* Pristine dependency profile compiles netrc/cookies out entirely. */
    OPT(CURLOPT_VERBOSE,0L);
    OPT(CURLOPT_SSL_VERIFYPEER,1L);OPT(CURLOPT_SSL_VERIFYHOST,2L);OPT(CURLOPT_SSLVERSION,(long)CURL_SSLVERSION_TLSv1_2);
    OPT(CURLOPT_SSL_CTX_FUNCTION,ob_api_secure_ssl_context);OPT(CURLOPT_HTTP_VERSION,(long)CURL_HTTP_VERSION_1_1);
    OPT(CURLOPT_HEADERFUNCTION,header);OPT(CURLOPT_HEADERDATA,w);
    OPT(CURLOPT_NOPROGRESS,0L);OPT(CURLOPT_XFERINFOFUNCTION,progress);OPT(CURLOPT_XFERINFODATA,w);
    if(w->api->ca_file)OPT(CURLOPT_CAINFO,w->api->ca_file);
    if(w->resolve)OPT(CURLOPT_RESOLVE,w->resolve);
    rc=curl_easy_perform(w->easy);curl_easy_getinfo(w->easy,CURLINFO_RESPONSE_CODE,&status);
    if(rc==CURLE_OK&&status==101&&w->subprotocol&&!w->header_invalid)
        rc=curl_easy_getinfo(w->easy,CURLINFO_ACTIVESOCKET,&w->socket);
    else if(rc==CURLE_OK)rc=CURLE_WEIRD_SERVER_REPLY;
#undef OPT
 done:
    free(url);
    if(rc==CURLE_OK&&w->socket!=CURL_SOCKET_BAD){if(e)memset(e,0,sizeof(*e));return 0;}
    ob_ws_disconnect(w);int result=fail(e,status>=400?OB_API_HTTP:OB_API_TRANSPORT,status,"WebSocket upgrade/TLS verification failed");
    if(e)e->transport_code=(int)rc;return result;
}
static int wait_socket(ob_ws *w,short events,unsigned ms) {
    struct pollfd p={w->socket,events,0};int rc;
    do {rc=poll(&p,1,(int)(ms>100?100:ms));}while(rc<0&&errno==EINTR&&!cancelled(w));
    return rc<0||p.revents&(POLLERR|POLLHUP|POLLNVAL)?-1:0;
}
int ob_ws_pump(ob_ws *w,unsigned wait_ms,ob_api_error *e) {
    if(!owner(w)||!ob_ws_connected(w))return fail(e,OB_API_TRANSPORT,0,"WebSocket disconnected");
    if(cancelled(w))return fail(e,OB_API_TRANSPORT,0,"WebSocket cancelled");
    unsigned char chunk[8192];size_t n=0;const struct curl_ws_frame *m=NULL;
    CURLcode rc=curl_ws_recv(w->easy,chunk,sizeof(chunk),&n,&m);
    if(rc==CURLE_AGAIN){if(wait_ms&&wait_socket(w,POLLIN,wait_ms))goto transport;return 0;}
    if(rc!=CURLE_OK)goto transport;
    if(!m)goto invalid;
    if(m->flags&CURLWS_CLOSE)goto transport;
    if(m->flags&(CURLWS_PING|CURLWS_PONG))return 0; /* curl automatic PONG is enabled. */
    if(!(m->flags&CURLWS_TEXT)||m->flags&(CURLWS_BINARY|CURLWS_OFFSET)
        ||m->offset<0||m->bytesleft<0||m->offset!=(curl_off_t)w->frame_offset)goto invalid;
    if((uint64_t)m->offset+n+(uint64_t)m->bytesleft>OB_WS_MAX_FRAME||n>OB_WS_MAX_FRAME-w->used)goto limit;
    memcpy(w->frame+w->used,chunk,n);w->used+=n;w->frame_offset+=n;
    if(!m->bytesleft) {
        w->frame_offset=0;
        if(m->flags&CURLWS_CONT){w->fragment=1;return 0;}
        w->frame[w->used]=0;int result=enqueue(w);w->used=0;w->fragment=0;
        if(result){ob_ws_disconnect(w);return fail(e,result,0,"Invalid/overflow WebSocket application frame");}
    } return 0;
 limit: ob_ws_disconnect(w);return fail(e,OB_API_LIMIT,0,"WebSocket frame/message limit exceeded");
 invalid: ob_ws_disconnect(w);return fail(e,OB_API_JSON,0,"Invalid WebSocket text frame");
 transport: ob_ws_disconnect(w);return fail(e,OB_API_TRANSPORT,0,"WebSocket connection lost");
}
static int send_text(ob_ws *w,const char *text,unsigned timeout,ob_api_error *e) {
    size_t n=strlen(text),offset=0;if(n>OB_WS_MAX_FRAME)return fail(e,OB_API_LIMIT,0,"WebSocket send limit");
    uint64_t end=now_ms()+timeout;
    while(offset<n) {
        if(cancelled(w)||now_ms()>=end){ob_ws_disconnect(w);return fail(e,OB_API_TRANSPORT,0,"WebSocket send cancelled/timed out");}
        size_t sent=0;CURLcode rc=curl_ws_send(w->easy,text+offset,n-offset,&sent,0,CURLWS_TEXT);
        offset+=sent;
        if(rc!=CURLE_OK&&rc!=CURLE_AGAIN){ob_ws_disconnect(w);return fail(e,OB_API_TRANSPORT,0,"WebSocket send failed");}
        if(offset<n&&(rc==CURLE_AGAIN||!sent)) {
            /* Receive push/PING while the socket is write-blocked. */
            int r=ob_ws_pump(w,0,e);if(r)return r;
            if(wait_socket(w,POLLOUT,20)){ob_ws_disconnect(w);return fail(e,OB_API_TRANSPORT,0,"WebSocket send disconnected");}
        }
    } return 0;
}
int ob_ws_begin(ob_ws *w,const char *op,const cJSON *body,uint64_t *id,unsigned timeout,ob_api_error *e) {
    if(!owner(w)||!ob_ws_connected(w)||!op||!id)return fail(e,OB_API_INVALID,0,"Invalid WebSocket RPC");
    static const char *const peer[]={"heartbeat","capabilities","send","approve","turn","delete"};
    int valid=w->broker?(!strcmp(op,"heartbeat")||!strcmp(op,"offline")):0;
    if(!w->broker)for(unsigned i=0;i<6;i++)if(!strcmp(op,peer[i]))valid=1;
    if(!valid)return fail(e,OB_API_INVALID,0,"Invalid scoped WebSocket operation");
    unsigned slot;for(slot=0;slot<8&&w->pending[slot];slot++) {}
    if(slot==8)return fail(e,OB_API_LIMIT,0,"WebSocket RPC limit");
    if(w->next_id>=9007199254740991ULL)return fail(e,OB_API_LIMIT,0,"WebSocket RPC IDs exhausted");
    *id=++w->next_id;cJSON *j=cJSON_CreateObject();
    if(!j)return fail(e,OB_API_NOMEM,0,"WebSocket allocation failed");
    cJSON_AddNumberToObject(j,"v",1);cJSON_AddStringToObject(j,"type","request");cJSON_AddNumberToObject(j,"id",(double)*id);
    cJSON_AddStringToObject(j,"op",op);cJSON_AddItemToObject(j,"body",body?cJSON_Duplicate(body,1):cJSON_CreateNull());
    char *text=cJSON_PrintUnformatted(j);cJSON_Delete(j);
    if(!text)return fail(e,OB_API_NOMEM,0,"WebSocket allocation failed");
    w->pending[slot]=*id;int rc=send_text(w,text,timeout,e);
    if(rc)w->pending[slot]=0;
    wipe(text);cJSON_free(text);return rc;
}
static cJSON *remove_queue(ob_ws *w,struct queued **link) {
    struct queued *q=*link;*link=q->next;if(q==w->tail){w->tail=w->head;while(w->tail&&w->tail->next)w->tail=w->tail->next;}
    w->count--;w->bytes-=q->bytes;cJSON *j=q->json;free(q);return j;
}
int ob_ws_result(ob_ws *w,uint64_t id,int *status,cJSON **body) {
    if(body)*body=NULL;if(!owner(w))return 0;
    for(struct queued **q=&w->head;*q;q=&(*q)->next) {
        const char *type=str((*q)->json,"type");
        if(type&&!strcmp(type,"result")&&cJSON_GetObjectItemCaseSensitive((*q)->json,"id")->valuedouble==(double)id) {
            cJSON *j=remove_queue(w,q);if(status)*status=cJSON_GetObjectItemCaseSensitive(j,"status")->valueint;
            if(body)*body=cJSON_DetachItemFromObjectCaseSensitive(j,"body");cJSON_Delete(j);
            for(unsigned i=0;i<8;i++)if(w->pending[i]==id)w->pending[i]=0;return 1;
        }
    }return 0;
}
cJSON *ob_ws_pop(ob_ws *w,const char *type) {
    if(!owner(w))return NULL;
    for(struct queued **q=&w->head;*q;q=&(*q)->next)if(str((*q)->json,"type")&&!strcmp(str((*q)->json,"type"),type))return remove_queue(w,q);
    return NULL;
}
int ob_ws_ack(ob_ws *w,uint64_t consumed,ob_api_error *e) {
    if(!owner(w)||!ob_ws_connected(w)||!consumed||consumed>9007199254740991ULL)return fail(e,OB_API_INVALID,0,"Invalid consumed cursor");
    char text[96];snprintf(text,sizeof(text),"{\"v\":1,\"type\":\"ack\",\"sequence\":%" PRIu64 "}",consumed);
    return send_text(w,text,500,e);
}
