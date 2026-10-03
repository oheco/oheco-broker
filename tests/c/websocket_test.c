#define _GNU_SOURCE
#include "ob_ws.h"
#include "ob_json.h"
#include <curl/curl.h>
#include "peer/internal.h"
#include "peer/crypto.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Authenticated RFC6455 wire fixture: no libcurl mocks, HTTP polling or ambient
 * service. Its only accepted route/auth/subprotocol matches frozen scope. */
static const char sid[]="00000000-0000-0000-0000-000000000001";
static SSL_CTX *tls_context;
static ob_remote_peer tls_files;
static char keylog_path[1200];
static _Thread_local SSL *fixture_tls;
struct fixture { int fd, mode, error; uint16_t port; pthread_t thread; atomic_int accepted, ack; };
static int io(int fd,void *buf,size_t n,int writing) {
    size_t off=0;while(off<n){ssize_t k=fixture_tls ? (writing ? SSL_write(fixture_tls,(char*)buf+off,(int)(n-off)) : SSL_read(fixture_tls,(char*)buf+off,(int)(n-off))) : (writing?send(fd,(char*)buf+off,n-off,MSG_NOSIGNAL):recv(fd,(char*)buf+off,n-off,0));
        if(k<=0)return -1;off+=(size_t)k;}return 0;
}
static int frame(int fd,unsigned opcode,int fin,const char *text,size_t n) {
    unsigned char h[10];size_t size=2;h[0]=(unsigned char)((fin?128:0)|opcode);
    if(n<126)h[1]=(unsigned char)n;
    else if(n<=65535){h[1]=126;h[2]=(unsigned char)(n>>8);h[3]=(unsigned char)n;size=4;}
    else{h[1]=127;for(unsigned i=0;i<8;i++)h[2+i]=(unsigned char)((uint64_t)n>>(56-i*8));size=10;}
    return io(fd,h,size,1)||io(fd,(void*)text,n,1);
}
static char *receive(int fd,unsigned *opcode) {
    unsigned char h[2],extra[8],mask[4];if(io(fd,h,2,0))return NULL;
    *opcode=h[0]&15;if(!(h[1]&128))return NULL;uint64_t n=h[1]&127;
    if(n==126){if(io(fd,extra,2,0))return NULL;n=((unsigned)extra[0]<<8)|extra[1];}
    else if(n==127){if(io(fd,extra,8,0))return NULL;n=0;for(unsigned i=0;i<8;i++)n=(n<<8)|extra[i];}
    if(n>OB_WS_MAX_FRAME||io(fd,mask,4,0))return NULL;
    char *data=malloc((size_t)n+1);if(!data)return NULL;
    if(io(fd,data,(size_t)n,0)){free(data);return NULL;}
    for(size_t i=0;i<n;i++)data[i]^=mask[i%4];data[n]=0;return data;
}
static int result(int fd,uint64_t id) {
    char text[160];int n=snprintf(text,sizeof(text),"{\"v\":1,\"type\":\"result\",\"id\":%llu,\"status\":200,\"body\":{\"ok\":true}}",(unsigned long long)id);
    return frame(fd,1,1,text,(size_t)n);
}
static void *serve(void *arg) {
    struct fixture *f=arg;char *large=NULL;int fd=accept(f->fd,NULL,NULL);if(fd<0){f->error=1;return NULL;}
    struct timeval timeout={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    if(f->mode>=9&&f->mode<=12) {
        if(f->mode==12) { struct pollfd wait={fd,POLLIN,0}; poll(&wait,1,2000); struct timespec t={1,200000000}; nanosleep(&t,NULL); goto done; }
        fixture_tls=SSL_new(tls_context);
        if(!fixture_tls||!SSL_set_fd(fixture_tls,fd)||SSL_accept(fixture_tls)!=1)goto done;
    }
    char request[16384];size_t used=0;
    while(used<sizeof(request)-1){if(io(fd,request+used,1,0))goto bad;request[++used]=0;if(strstr(request,"\r\n\r\n"))break;}
    if(!strstr(request,"GET /v1/ws/sessions/00000000-0000-0000-0000-000000000001?after=0 HTTP/1.1\r\n")
        ||!strstr(request,"Authorization: Bearer fixture-token\r\n")||!strstr(request,"Sec-WebSocket-Protocol: ob-signaling-v1\r\n")
        ||strstr(request,"Cookie:")||strstr(request,"Proxy-Authorization:"))goto bad;
    char *key=strstr(request,"Sec-WebSocket-Key: ");if(!key)goto bad;key+=19;char *end=strstr(key,"\r\n");if(!end||end-key>64)goto bad;
    char combined[128];snprintf(combined,sizeof(combined),"%.*s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",(int)(end-key),key);
    unsigned char hash[20];char accept[64];SHA1((unsigned char*)combined,strlen(combined),hash);EVP_EncodeBlock((unsigned char*)accept,hash,20);
    char response[512];int n=snprintf(response,sizeof(response),"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s\r\n",accept,f->mode==7?"":"Sec-WebSocket-Protocol: ob-signaling-v1\r\n");
    if(io(fd,response,(size_t)n,1))goto bad;atomic_store(&f->accepted,1);
    const char *caps="{\"v\":1,\"type\":\"capabilities\",\"body\":{\"peer_authenticated\":false,\"latency\":0.125}}";
    if(f->mode==21||f->mode==23) {
        size_t size=f->mode==21?100000:240000;char *blob=malloc(size+1);cJSON *j=cJSON_CreateObject(),*body=cJSON_CreateObject();
        if(!blob||!j||!body){free(blob);cJSON_Delete(j);cJSON_Delete(body);goto bad;}
        memset(blob,'x',size);blob[size]=0;cJSON_AddStringToObject(body,"blob",blob);free(blob);
        cJSON_AddNumberToObject(body,"latency",0.125);cJSON_AddItemToObject(j,"body",body);
        cJSON_AddNumberToObject(j,"v",1);cJSON_AddStringToObject(j,"type","capabilities");
        large=cJSON_PrintUnformatted(j);cJSON_Delete(j);if(!large)goto bad;caps=large;
        if(f->mode==23){for(unsigned i=0;i<5;i++)if(frame(fd,1,1,caps,strlen(caps)))break;goto done;}
    }
    if(f->mode==22){char *huge=malloc(OB_WS_MAX_FRAME+1);if(!huge)goto bad;memset(huge,'x',OB_WS_MAX_FRAME+1);
        frame(fd,1,0,huge,OB_WS_MAX_FRAME/2);frame(fd,0,1,huge+OB_WS_MAX_FRAME/2,OB_WS_MAX_FRAME/2+1);free(huge);goto done;}
    if(f->mode==1){frame(fd,2,1,caps,strlen(caps));goto done;}
    if(f->mode==2){const char *badjson="{\"v\":1,\"v\":1,\"type\":\"capabilities\",\"body\":{}}";frame(fd,1,1,badjson,strlen(badjson));goto done;}
    if(f->mode==3){char *huge=malloc(OB_WS_MAX_FRAME+1);memset(huge,'x',OB_WS_MAX_FRAME+1);frame(fd,1,1,huge,OB_WS_MAX_FRAME+1);free(huge);goto done;}
    if(f->mode==4){for(unsigned i=0;i<OB_WS_MAX_QUEUE_COUNT+1;i++)if(frame(fd,1,1,caps,strlen(caps)))break;goto done;}
    if(f->mode==5){const char badutf[]={123,34,(char)0xc0,(char)0x80,34,58,49,125};frame(fd,1,1,badutf,sizeof(badutf));goto done;}
    if(f->mode==6){const char *unknown="{\"v\":1,\"type\":\"capabilities\",\"body\":{},\"extra\":1}";frame(fd,1,1,unknown,strlen(unknown));goto done;}
    if(f->mode==7)goto done;
    if(f->mode==8){const char *nul="{\"v\":1,\"type\":\"capabilities\",\"body\":{\"x\":\"a\\u0000b\"}}";frame(fd,1,1,nul,strlen(nul));goto done;}
    if(f->mode>=13&&f->mode<=20) {
        if(f->mode==15||f->mode==16||f->mode==19||f->mode==20) {
            unsigned opcode;char *request=receive(fd,&opcode);if(!request||opcode!=1){free(request);goto bad;}
            cJSON *j=ob_peer_json_parse(request);free(request);
            cJSON *id=cJSON_GetObjectItemCaseSensitive(j,"id");int valid=cJSON_IsNumber(id)&&id->valuedouble==1;cJSON_Delete(j);if(!valid)goto bad;
        }
        const char *wrong[] = {
            "{\"v\":1.0000000000000001,\"type\":\"capabilities\",\"body\":{}}",
            "{\"v\":1,\"type\":\"message\",\"sequence\":1.0000000000000001,\"data\":\"opaque\"}",
            "{\"v\":1,\"type\":\"result\",\"id\":1.0000000000000001,\"status\":200,\"body\":{}}",
            "{\"v\":1,\"type\":\"result\",\"id\":1,\"status\":200.0000000000000001,\"body\":{}}",
            "{\"v\":1e0,\"type\":\"capabilities\",\"body\":{}}",
            "{\"v\":1,\"type\":\"message\",\"sequence\":1e0,\"data\":\"opaque\"}",
            "{\"v\":1,\"type\":\"result\",\"id\":1e0,\"status\":200,\"body\":{}}",
            "{\"v\":1,\"type\":\"result\",\"id\":1,\"status\":2e2,\"body\":{}}",
        };
        const char *text=wrong[f->mode-13];frame(fd,1,1,text,strlen(text));goto done;
    }
    /* Fragmented application message with an intervening RFC6455 PING. */
    size_t half=strlen(caps)/2;if(frame(fd,1,0,caps,half)||frame(fd,9,1,"ping",4)||frame(fd,0,1,caps+half,strlen(caps)-half))goto bad;
    const char *msg="{\"v\":1,\"type\":\"message\",\"sequence\":1,\"data\":\"invalid authenticated envelope\"}";
    if(frame(fd,1,1,msg,strlen(msg)))goto bad;
    uint64_t ids[2]={0};unsigned got=0;
    while(got<2) {
        unsigned opcode;char *text=receive(fd,&opcode);if(!text)goto bad;
        if(opcode==10){free(text);continue;}
        cJSON *j=ob_peer_json_parse(text);free(text);
        cJSON *id=cJSON_GetObjectItemCaseSensitive(j,"id"),*body=cJSON_GetObjectItemCaseSensitive(j,"body");
        const char *op=NULL;cJSON *v=cJSON_GetObjectItemCaseSensitive(j,"op");if(cJSON_IsString(v))op=v->valuestring;
        int valid=op&&!strcmp(op,"heartbeat")&&cJSON_IsNull(body);
        if(f->mode==21&&got==1) {
            cJSON *data=cJSON_GetObjectItemCaseSensitive(body,"data"),*seq=cJSON_GetObjectItemCaseSensitive(body,"sequence");
            valid=op&&!strcmp(op,"send")&&cJSON_IsString(data)&&strlen(data->valuestring)==32000&&cJSON_IsNumber(seq)&&seq->valuedouble==1;
        }
        if(!cJSON_IsNumber(id)||!valid){cJSON_Delete(j);goto bad;}
        ids[got++]=(uint64_t)id->valuedouble;cJSON_Delete(j);
    }
    /* Results deliberately arrive in reverse order amid pending pushes. */
    if(result(fd,ids[1])||result(fd,ids[0]))goto bad;
    for(;;){unsigned opcode;char *text=receive(fd,&opcode);if(!text)break;
        cJSON *j=ob_peer_json_parse(text);free(text);cJSON *type=cJSON_GetObjectItemCaseSensitive(j,"type");
        if(cJSON_IsString(type)&&!strcmp(type->valuestring,"ack"))atomic_store(&f->ack,1);cJSON_Delete(j);
    }
 done: cJSON_free(large);if(fixture_tls){SSL_free(fixture_tls);fixture_tls=NULL;}shutdown(fd,SHUT_RDWR);close(fd);return NULL;
 bad: f->error=(f->mode==10||f->mode==11)?0:1;goto done;
}
static int start(struct fixture *f,int mode) {
    memset(f,0,sizeof(*f));f->mode=mode;f->fd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);socklen_t n=sizeof(a);
    if(f->fd<0||bind(f->fd,(struct sockaddr*)&a,sizeof(a))||listen(f->fd,1)||getsockname(f->fd,(struct sockaddr*)&a,&n))return -1;
    f->port=ntohs(a.sin_port);return pthread_create(&f->thread,NULL,serve,f);
}
static void finish(struct fixture *f) {shutdown(f->fd,SHUT_RDWR);pthread_join(f->thread,NULL);close(f->fd);}
static int test_case(int mode) {
    struct fixture f;if(start(&f,mode))return -1;
    char url[96];snprintf(url,sizeof(url),"%s://%s:%u",(mode>=9&&mode<=12)?"https":"http",mode==11?"localhost":"127.0.0.1",f.port);
    ob_api_options o={url,NULL,(mode>=9&&mode<=12&&mode!=10)?tls_files.cert_path:NULL,1000};ob_api_error e={0};ob_api_client *api=ob_api_client_create(&o,&e);
    ob_ws *ws=ob_ws_create(api,0,sid,"fixture-token",NULL,NULL);uint64_t before=ob_now_us();
    int rc=ws?ob_ws_connect(ws,0,1000,&e):OB_API_NOMEM;uint64_t elapsed=ob_now_us()-before;
    if(mode==7||mode==10||mode==11||mode==12){int ok=rc!=0;
        if(mode==10||mode==11)ok=ok&&e.transport_code==CURLE_PEER_FAILED_VERIFICATION&&!atomic_load(&f.accepted);
        if(mode==12)ok=ok&&e.transport_code==CURLE_OPERATION_TIMEDOUT&&elapsed>=700000&&elapsed<1600000;
        ob_ws_destroy(ws);ob_api_client_destroy(api);finish(&f);return ok&&!f.error?0:-1;}
    if(rc){fprintf(stderr,"upgrade mode %d rc %d status %ld transport %d\n",mode,rc,e.http_status,e.transport_code);goto bad;}
    if((mode>0&&mode<=8)||(mode>=13&&mode!=21)) {
        if(mode==15||mode==16||mode==19||mode==20){uint64_t id;if(ob_ws_begin(ws,"heartbeat",NULL,&id,500,&e))goto bad;}
        uint64_t end=ob_now_us()+2000000;
        while(!rc&&ob_now_us()<end)rc=ob_ws_pump(ws,10,&e);
        int wanted=(mode==3||mode==4||mode==22||mode==23)?OB_API_LIMIT:OB_API_JSON;
        int ok=rc==wanted;ob_ws_destroy(ws);ob_api_client_destroy(api);finish(&f);
        if(!ok)fprintf(stderr,"mode %d expected %d got %d %s\n",mode,wanted,rc,e.message);return ok&&!f.error?0:-1;
    }
    /* Local outbound frame budget cannot leave a phantom pending ID. */
    cJSON *oversize=cJSON_CreateObject();char *huge=malloc(OB_WS_MAX_FRAME+1);
    if(!oversize||!huge){cJSON_Delete(oversize);free(huge);goto bad;}
    memset(huge,'x',OB_WS_MAX_FRAME);huge[OB_WS_MAX_FRAME]=0;cJSON_AddStringToObject(oversize,"data",huge);free(huge);
    uint64_t rejected_id;
    for(unsigned i=0;i<9;i++)if(ob_ws_begin(ws,"send",oversize,&rejected_id,500,&e)!=OB_API_LIMIT){cJSON_Delete(oversize);goto bad;}
    cJSON_Delete(oversize);
    uint64_t ids[2];if(ob_ws_begin(ws,"heartbeat",NULL,&ids[0],500,&e))goto bad;
    if(mode==21) {
        cJSON *body=cJSON_CreateObject();char *data=malloc(32001);if(!body||!data){free(data);cJSON_Delete(body);goto bad;}
        memset(data,'x',32000);data[32000]=0;cJSON_AddStringToObject(body,"data",data);free(data);cJSON_AddNumberToObject(body,"sequence",1);
        int failed=ob_ws_begin(ws,"send",body,&ids[1],500,&e);cJSON_Delete(body);if(failed)goto bad;
    } else if(ob_ws_begin(ws,"heartbeat",NULL,&ids[1],500,&e))goto bad;
    int got[2]={0},status;uint64_t end=ob_now_us()+2000000;
    while((!got[0]||!got[1])&&ob_now_us()<end){if(ob_ws_pump(ws,10,&e))goto bad;
        for(unsigned i=0;i<2;i++){cJSON *body=NULL;if(ob_ws_result(ws,ids[i],&status,&body)){got[i]=status==200&&cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(body,"ok"));cJSON_Delete(body);}}
    }
    cJSON *caps=ob_ws_pop(ws,"capabilities"),*message=ob_ws_pop(ws,"message");
    if(!got[0]||!got[1]||!caps||!message){cJSON_Delete(caps);cJSON_Delete(message);goto bad;}
    ob_remote_peer p={0};p.session_id=(char*)sid;char *payload=NULL;
    cJSON *data=cJSON_GetObjectItemCaseSensitive(message,"data");
    if(ob_decode_signal(&p,data->valuestring,1,"confirm",1,&payload)!=OB_REMOTE_EAUTH||p.rx_sequence){free(payload);cJSON_Delete(caps);cJSON_Delete(message);goto bad;}
    /* Deliberately no ob_ws_ack: authenticated semantic failure consumes zero. */
    cJSON_Delete(caps);cJSON_Delete(message);ob_ws_destroy(ws);ob_api_client_destroy(api);finish(&f);
    return !f.error&&!atomic_load(&f.ack)?0:-1;
 bad: fprintf(stderr,"WS fixture mode %d failed: %s\n",mode,e.message);ob_ws_destroy(ws);ob_api_client_destroy(api);finish(&f);return -1;
}
static void tls_cleanup(void) {
    SSL_CTX_free(tls_context); unlink(keylog_path); ob_certificate_cleanup(&tls_files);
}
static int tls_setup(void) {
    if(ob_make_certificate(&tls_files))return -1;
    atexit(tls_cleanup);
    BIO *b=BIO_new_file(tls_files.key_path,"r");EVP_PKEY *key=b?PEM_read_bio_PrivateKey(b,NULL,NULL,NULL):NULL;BIO_free(b);
    b=BIO_new_file(tls_files.cert_path,"r");X509 *cert=b?PEM_read_bio_X509(b,NULL,NULL,NULL):NULL;BIO_free(b);
    X509_EXTENSION *san=X509V3_EXT_nconf_nid(NULL,NULL,NID_subject_alt_name,"IP:127.0.0.1");
    int ok=cert&&key&&san&&X509_add_ext(cert,san,-1)&&X509_sign(cert,key,EVP_sha256());X509_EXTENSION_free(san);
    b=ok?BIO_new_file(tls_files.cert_path,"w"):NULL;ok=ok&&b&&PEM_write_bio_X509(b,cert);BIO_free(b);
    tls_context=SSL_CTX_new(TLS_server_method());ok=ok&&tls_context&&SSL_CTX_use_certificate(tls_context,cert)&&SSL_CTX_use_PrivateKey(tls_context,key);
    X509_free(cert);EVP_PKEY_free(key);
    snprintf(keylog_path,sizeof(keylog_path),"%s/keylog",tls_files.cert_dir);
    /* Hostile ambient settings are test inputs. SDK must not mutate them or
     * follow proxies, and must clear secrets on its private SSL_CTX. */
    setenv("SSLKEYLOGFILE",keylog_path,1);setenv("http_proxy","http://127.0.0.1:1",1);setenv("https_proxy","http://127.0.0.1:1",1);setenv("ALL_PROXY","socks5://127.0.0.1:1",1);setenv("NO_PROXY","",1);
    return ok?0:-1;
}
static int integer_tests(void) {
    const char *valid="{\"body\":{\"v\":1.5,\"ids\":[1e0,2.25],\"text\":\"{,}\\\"\"},\"\\u0076\":1,\"id\":9007199254740991,\"sequence\":0}";
    cJSON *j=ob_peer_json_parse(valid);uint64_t n=0;
    if(!j)return -1;cJSON_Delete(j);
    if(!ob_json_uint_field(valid,strlen(valid),"v",1,1,&n)||n!=1
        ||!ob_json_uint_field(valid,strlen(valid),"id",1,9007199254740991ULL,&n)||n!=9007199254740991ULL
        ||!ob_json_uint_field(valid,strlen(valid),"sequence",0,0,&n)||n)return -1;
    const char *bad[]={"1.0000000000000001","1.0","1e0","-0","9007199254740992","18446744073709551616"};
    char text[160];
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
        snprintf(text,sizeof(text),"{\"body\":{\"sequence\":1},\"sequence\":%s}",bad[i]);
        j=ob_peer_json_parse(text);if(!j)return -1;cJSON_Delete(j);
        if(ob_json_uint_field(text,strlen(text),"sequence",0,9007199254740991ULL,&n))return -1;
    }
    printf("PASS lexical top-level unsigned schema numbers, escaped ASCII keys, JSON-safe boundary; nested floats/opaque strings preserved\n");return 0;
}
static void *parallel_test(void *arg) {int *r=arg;*r=test_case(0);return NULL;}
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);
    if(tls_setup()||integer_tests())return 1;
    const curl_version_info_data *v=curl_version_info(CURLVERSION_NOW);unsigned protocols=0;
    for(const char *const *p=v->protocols;*p;p++){if(!strcmp(*p,"http"))protocols|=1;else if(!strcmp(*p,"https"))protocols|=2;else if(!strcmp(*p,"ws"))protocols|=4;else if(!strcmp(*p,"wss"))protocols|=8;else return 1;}
    if(protocols!=15)return 1;
    for(int i=0;i<=8;i++)if(test_case(i))return 1;
    for(int i=13;i<=23;i++)if(test_case(i))return 1;
    printf("PASS actual 100KiB multi-read fragmented TEXT with PING, 32KiB-class send, aggregate fragmented-message and total queued-byte limits\n");
    printf("PASS raw WS v/id/status/sequence rounded tiny-fraction and exponent rejection, outbound oversize without pending-ID leaks\n");
    printf("PASS actual authenticated WS fragmentation/PING/result correlation/push preservation/MAC no-ACK and strict binary/duplicate/oversize/queue/UTF-8/known-fields/subprotocol/NUL rejection\n");
    for(int i=9;i<=12;i++)if(test_case(i)){fprintf(stderr,"FAIL WSS mode %d\n",i);return 1;}
    struct stat keylog;if(!stat(keylog_path,&keylog)&&keylog.st_size)return 1;
    if(strcmp(getenv("SSLKEYLOGFILE"),keylog_path)||strcmp(getenv("https_proxy"),"http://127.0.0.1:1"))return 1;
    printf("PASS actual WSS private CA, untrusted CA/hostname rejection, bounded TLS stall, disabled ambient proxies and no TLS keylog secrets (empty file allowed)\n");
    pthread_t threads[4];int results[4];
    for(unsigned i=0;i<4;i++)if(pthread_create(&threads[i],NULL,parallel_test,&results[i]))return 1;
    for(unsigned i=0;i<4;i++){pthread_join(threads[i],NULL);if(results[i])return 1;}
    printf("PASS four concurrent private WS handles and shared pristine cJSON parser; profile HTTP HTTPS WS WSS only\n");return 0;
}
