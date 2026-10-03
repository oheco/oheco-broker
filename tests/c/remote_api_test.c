#define _POSIX_C_SOURCE 200809L
#include "ob_api.h"
#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static char test_root[4096], certificate_root[4096];
static void cleanup_temporary_files(void) {
    char path[8192];
    if (*test_root) { snprintf(path,sizeof(path),"%s/tls-keys.log",test_root);unlink(path);rmdir(test_root); }
    if (*certificate_root) { snprintf(path,sizeof(path),"%s/ca.pem",certificate_root);unlink(path);rmdir(certificate_root); }
}
struct fixture { int fd, port; SSL_CTX *tls; pthread_t thread; atomic_int stop, requests; ob_api_credentials registered; };
struct wire { int fd; SSL *tls; };
static int wire_read(struct wire *w,char *p,int n) { return w->tls ? SSL_read(w->tls,p,n) : (int)recv(w->fd,p,(size_t)n,0); }
static int wire_write(struct wire *w,const char *p,size_t n) {
    while (n) {
        int sent = w->tls ? SSL_write(w->tls,p,(int)n) : (int)send(w->fd,p,n,MSG_NOSIGNAL);
        if (sent<=0) return 0;
        p+=sent; n-=(size_t)sent;
    }
    return 1;
}
static void reply(struct wire *w,int status,const char *body) {
    char header[256];
    int n=snprintf(header,sizeof(header),"HTTP/1.1 %d Test\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",status,strlen(body));
    if (wire_write(w,header,(size_t)n)) (void)wire_write(w,body,strlen(body));
}
static void serve(struct fixture *f,struct wire *w) {
    char request[16384]; size_t used=0;
    while (used<sizeof(request)-1) {
        int n=wire_read(w,request+used,(int)(sizeof(request)-1-used));
        if (n<=0) return;
        used+=(size_t)n; request[used]=0;
        char *end=strstr(request,"\r\n\r\n");
        if (end) {
            size_t want=(size_t)(end+4-request);
            char *cl=strstr(request,"Content-Length:");
            if (cl && cl<end) want+=(size_t)strtoul(cl+15,NULL,10);
            if (used>=want) break;
        }
    }
    atomic_fetch_add(&f->requests,1);
    char method[16],path[256];
    if (sscanf(request,"%15s %255s",method,path)!=2) return;
    if (!strcmp(path,"/v1/tenants/register")) {
        /* Commit the credentials in the fixture, then lose the entire receipt. */
        char *name=strstr(request,"\"name\":\""),*password=strstr(request,"\"password\":\"");
        CHECK(name && password && !strstr(request,"Authorization:"));name+=8;password+=12;
        CHECK(strlen(name)>=44 && strlen(password)>=33 && name[43]=='\"' && password[32]=='\"');
        memcpy(f->registered.name,name,43);f->registered.name[43]=0;
        memcpy(f->registered.password,password,32);f->registered.password[32]=0;
        return;
    }
    if (!strcmp(path,"/v1/tenants/login")) {
        CHECK(!strstr(request,"Authorization:"));
        if (*f->registered.name && strstr(request,f->registered.name) && strstr(request,f->registered.password))
            reply(w,200,"{\"tenant\":{},\"token\":\"recovered-fixture-token\"}");
        else reply(w,401,"{\"error\":\"invalid login\"}");
        return;
    }
    if (!strcmp(path,"/v1/large")) {
        const char *header="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        if (!wire_write(w,header,strlen(header))) return;
        char chunk[8192]; memset(chunk,'x',sizeof(chunk));
        for (size_t n=0;n<OB_API_MAX_RESPONSE_BYTES+sizeof(chunk);n+=sizeof(chunk)) {
            if (!wire_write(w,"2000\r\n",6) || !wire_write(w,chunk,sizeof(chunk)) || !wire_write(w,"\r\n",2)) return;
        }
        (void)wire_write(w,"0\r\n\r\n",5); return;
    }
    if (!strcmp(path,"/v1/headerbudget")) {
        (void)wire_write(w,"HTTP/1.1 200 OK\r\n",17);
        char header[1024]; memset(header,'x',sizeof(header)); memcpy(header,"X-Test: ",8);
        header[1022]='\r';header[1023]='\n';
        for(int i=0;i<80;i++) if (!wire_write(w,header,sizeof(header))) return;
        (void)wire_write(w,"Content-Length: 2\r\n\r\n{}",23); return;
    }
    if (!strcmp(path,"/v1/slow")) {
        struct timespec delay={0,350000000}; nanosleep(&delay,NULL); reply(w,200,"{}"); return;
    }
    if (!strcmp(path,"/v1/invalid")) { reply(w,200,"not JSON"); return; }
    if (!strcmp(path,"/v1/hash")) { reply(w,200,"{\"tenant\":{\"password_hash\":\"never-return-this\"}}"); return; }
    if (!strcmp(path,"/v1/error")) { reply(w,403,"{\"error\":\"denied\"}"); return; }
    if (!strcmp(path,"/v1/empty")) { reply(w,204,""); return; }
    if (!strcmp(path,"/v1/redirect")) {
        const char *response="HTTP/1.1 302 Redirect\r\nLocation: /v1/check\r\nContent-Length: 2\r\n\r\n{}";
        (void)wire_write(w,response,strlen(response)); return;
    }
    const char *auth="none";
    if (strstr(request,"Authorization: Bearer tenant-token\r\n")) auth="tenant";
    if (strstr(request,"Authorization: Bearer explicit-token\r\n")) auth="explicit";
    char body[256]; snprintf(body,sizeof(body),"{\"method\":\"%s\",\"auth\":\"%s\",\"body\":%s}",method,auth,strstr(request,"{\"value\":1}")?"true":"false");
    reply(w,200,body);
}
static void *serve_thread(void *arg) {
    struct fixture *f=arg;
    while (!atomic_load(&f->stop)) {
        int fd=accept(f->fd,NULL,NULL);
        if (fd<0) { if (errno==EINTR) continue; break; }
        struct timeval limit={2,0};
        (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit));
        struct wire w={fd,NULL};
        if (f->tls) { w.tls=SSL_new(f->tls); CHECK(w.tls); SSL_set_fd(w.tls,fd); }
        if (!w.tls || SSL_accept(w.tls)==1) serve(f,&w);
        SSL_free(w.tls); close(fd);
    }
    return NULL;
}
static void fixture_start(struct fixture *f,SSL_CTX *tls) {
    memset(f,0,sizeof(*f)); atomic_init(&f->stop,0);atomic_init(&f->requests,0);f->tls=tls;
    f->fd=socket(AF_INET,SOCK_STREAM,0); CHECK(f->fd>=0);
    struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK(bind(f->fd,(struct sockaddr *)&addr,sizeof(addr))==0); CHECK(listen(f->fd,64)==0);
    socklen_t size=sizeof(addr); CHECK(getsockname(f->fd,(struct sockaddr *)&addr,&size)==0); f->port=ntohs(addr.sin_port);
    CHECK(pthread_create(&f->thread,NULL,serve_thread,f)==0);
}
static void fixture_stop(struct fixture *f) { atomic_store(&f->stop,1);shutdown(f->fd,SHUT_RDWR);pthread_join(f->thread,NULL);close(f->fd);ob_api_credentials_clear(&f->registered); }
static SSL_CTX *tls_context(const char *ca_file,int matching_host) {
    EVP_PKEY_CTX *keyctx=EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL); CHECK(keyctx);
    CHECK(EVP_PKEY_keygen_init(keyctx)==1); CHECK(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyctx,NID_X9_62_prime256v1)==1);
    EVP_PKEY *key=NULL; CHECK(EVP_PKEY_keygen(keyctx,&key)==1);EVP_PKEY_CTX_free(keyctx);
    X509 *cert=X509_new();CHECK(cert);CHECK(X509_set_version(cert,2)==1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert),1)==1);
    CHECK(X509_gmtime_adj(X509_get_notBefore(cert),-60));CHECK(X509_gmtime_adj(X509_get_notAfter(cert),3600));
    CHECK(X509_set_pubkey(cert,key)==1);
    X509_NAME *name=X509_get_subject_name(cert);
    CHECK(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"local-fixture",-1,-1,0)==1);
    CHECK(X509_set_issuer_name(cert,name)==1);
    X509V3_CTX v3; X509V3_set_ctx(&v3,cert,cert,NULL,NULL,0);
    X509_EXTENSION *ext=X509V3_EXT_nconf_nid(NULL,&v3,NID_subject_alt_name,matching_host?"IP:127.0.0.1,DNS:localhost":"DNS:wrong.invalid");
    CHECK(ext);CHECK(X509_add_ext(cert,ext,-1)==1);X509_EXTENSION_free(ext);
    CHECK(X509_sign(cert,key,EVP_sha256())>0);
    FILE *file=fopen(ca_file,"w");CHECK(file);CHECK(PEM_write_X509(file,cert)==1);CHECK(fclose(file)==0);
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());CHECK(ctx);
    CHECK(SSL_CTX_use_certificate(ctx,cert)==1);CHECK(SSL_CTX_use_PrivateKey(ctx,key)==1);
    X509_free(cert);EVP_PKEY_free(key);return ctx;
}
static ob_api_client *new_client(const char *url,const char *token,const char *ca,long timeout) {
    ob_api_options options={url,token,ca,timeout};ob_api_error e;
    ob_api_client *client=ob_api_client_create(&options,&e);CHECK(client);return client;
}
struct parallel_arg { ob_api_client *client; int ok; };
static void *parallel_request(void *arg) {
    struct parallel_arg *a=arg;a->ok=1;
    for(int i=0;i<10;i++) {
        ob_api_error e;char *out=NULL;
        int rc=ob_api_request(a->client,"GET","/v1/check",NULL,NULL,&out,&e);
        if(rc!=OB_API_OK || !out || !strstr(out,"\"auth\":\"tenant\"")) a->ok=0;
        ob_api_response_free(out);
    }
    return NULL;
}
static void security_tests(void) {
    const char *invalid[]={"http://example.com","ftp://127.0.0.1","https://user:secret@example.com","https://example.com/v1","https://example.com/?query=1","https://example.com/#fragment","http://127.0.0.1.evil.invalid","http://[::ffff:127.0.0.1]"};
    for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {ob_api_options o={invalid[i],NULL,NULL,0};ob_api_error e;CHECK(!ob_api_client_create(&o,&e));CHECK(e.code==OB_API_INVALID);}
    struct fixture http;fixture_start(&http,NULL);
    char url[128];snprintf(url,sizeof(url),"http://127.0.0.1:%d",http.port);
    ob_api_client *c=new_client(url,"tenant-token",NULL,0);ob_api_error e;char *out=NULL;
    const char *methods[]={"GET","POST","PATCH","DELETE"};
    for(size_t i=0;i<4;i++) {
        const char *body=i?"{\"value\":1}":NULL;
        int rc=ob_api_request(c,methods[i],"/v1/check",NULL,body,&out,&e);
        if(rc!=OB_API_OK) fprintf(stderr,"HTTP fixture error code=%d status=%ld transport=%d %s\n",rc,e.http_status,e.transport_code,e.message);
        CHECK(rc==OB_API_OK);
        CHECK(e.http_status==200 && strstr(out,methods[i]) && strstr(out,"\"auth\":\"tenant\""));
        CHECK(strstr(out,i?"\"body\":true":"\"body\":false"));ob_api_response_free(out);out=NULL;
    }
    CHECK(ob_api_request(c,"GET","/v1/check","explicit-token",NULL,&out,&e)==OB_API_OK);CHECK(strstr(out,"\"auth\":\"explicit\""));ob_api_response_free(out);
    CHECK(ob_api_request(c,"GET","/v1/check","",NULL,&out,&e)==OB_API_OK);CHECK(strstr(out,"\"auth\":\"none\""));ob_api_response_free(out);
    const char *badpaths[]={"/v1/../me","/v1/%2e%2e/me","//evil/v1/me","https://evil/v1/me","/v1/me#frag","/v1/me\r\nInjected: yes","/v1//me","/v1/me?x=%2f"};
    int requests=atomic_load(&http.requests);
    for(size_t i=0;i<sizeof(badpaths)/sizeof(badpaths[0]);i++) CHECK(ob_api_request(c,"GET",badpaths[i],NULL,NULL,&out,&e)==OB_API_INVALID && !out);
    CHECK(ob_api_request(c,"PUT","/v1/check",NULL,NULL,&out,&e)==OB_API_INVALID);
    CHECK(ob_api_request(c,"GET","/v1/check","token\r\nInjected: yes",NULL,&out,&e)==OB_API_INVALID);
    CHECK(ob_api_broker_get(c,"a/../../me",&out,&e)==OB_API_INVALID);
    CHECK(ob_api_request(c,"POST","/v1/check",NULL,"{} trailing",&out,&e)==OB_API_JSON);
    char *big=malloc(OB_API_MAX_REQUEST_BYTES+2u);CHECK(big);memset(big,'x',OB_API_MAX_REQUEST_BYTES+1u);big[OB_API_MAX_REQUEST_BYTES+1u]=0;
    CHECK(ob_api_request(c,"POST","/v1/check",NULL,big,&out,&e)==OB_API_LIMIT);free(big);
    CHECK(atomic_load(&http.requests)==requests);
    CHECK(ob_api_request(c,"GET","/v1/error",NULL,NULL,&out,&e)==OB_API_HTTP && e.http_status==403 && out);ob_api_response_free(out);
    CHECK(ob_api_request(c,"GET","/v1/invalid",NULL,NULL,&out,&e)==OB_API_JSON && !out);
    CHECK(ob_api_request(c,"GET","/v1/hash",NULL,NULL,&out,&e)==OB_API_JSON && !out);
    CHECK(ob_api_request(c,"GET","/v1/large",NULL,NULL,&out,&e)==OB_API_LIMIT && !out);
    CHECK(ob_api_request(c,"GET","/v1/headerbudget",NULL,NULL,&out,&e)==OB_API_LIMIT && !out);
    CHECK(ob_api_request(c,"GET","/v1/empty",NULL,NULL,&out,&e)==OB_API_OK && out && !*out);ob_api_response_free(out);
    requests=atomic_load(&http.requests);CHECK(ob_api_request(c,"GET","/v1/redirect",NULL,NULL,&out,&e)==OB_API_HTTP && e.http_status==302);ob_api_response_free(out);CHECK(atomic_load(&http.requests)==requests+1);
    pthread_t threads[8];struct parallel_arg args[8];
    for(size_t i=0;i<8;i++) {args[i].client=c;CHECK(pthread_create(&threads[i],NULL,parallel_request,&args[i])==0);}
    for(size_t i=0;i<8;i++) {pthread_join(threads[i],NULL);CHECK(args[i].ok);}
    ob_api_credentials lost;
    CHECK(ob_api_tenant_register(c,&lost,&out,&e)==OB_API_TRANSPORT && !out);
    CHECK(strlen(lost.name)==43 && lost.name[21]=='4' && strlen(lost.password)==32);
    CHECK(ob_api_tenant_login(c,lost.name,lost.password,&out,&e)==OB_API_OK && strstr(out,"recovered-fixture-token"));ob_api_response_free(out);
    ob_api_credentials_clear(&lost);CHECK(!lost.name[0] && !lost.password[0]);
    CHECK(ob_api_credentials_generate(&lost,&e)==OB_API_OK);
    CHECK(ob_api_tenant_register_credentials(c,lost.name,lost.password,"fixture@example.invalid",&out,&e)==OB_API_TRANSPORT && !out);
    CHECK(ob_api_tenant_login(c,lost.name,lost.password,&out,&e)==OB_API_OK);ob_api_response_free(out);ob_api_credentials_clear(&lost);
    puts("PASS committed registration with lost receipt retains login recovery credentials");
    ob_api_client_destroy(c);
    char localhost_url[128];snprintf(localhost_url,sizeof(localhost_url),"http://localhost:%d",http.port);
    c=new_client(localhost_url,NULL,NULL,1000);
    CHECK(ob_api_request(c,"GET","/v1/check",NULL,NULL,&out,&e)==OB_API_OK);ob_api_response_free(out);
    ob_api_client_destroy(c);c=new_client(url,NULL,NULL,100);
    struct timespec before,after;clock_gettime(CLOCK_MONOTONIC,&before);
    CHECK(ob_api_request(c,"GET","/v1/slow",NULL,NULL,&out,&e)==OB_API_TRANSPORT && !out);
    clock_gettime(CLOCK_MONOTONIC,&after);CHECK((after.tv_sec-before.tv_sec)*1000+(after.tv_nsec-before.tv_nsec)/1000000<1000);
    ob_api_client_destroy(c);fixture_stop(&http);
    const char *tmp=getenv("TMPDIR");CHECK(tmp && *tmp);
    char *directory=malloc(strlen(tmp)+32);CHECK(directory);sprintf(directory,"%s/ob-api-test.XXXXXX",tmp);CHECK(mkdtemp(directory));
    CHECK(strlen(directory)<sizeof(certificate_root));strcpy(certificate_root,directory);
    char ca[4096];CHECK(snprintf(ca,sizeof(ca),"%s/ca.pem",directory)<(int)sizeof(ca));
    SSL_CTX *ctx;struct fixture https;
    const int versions[]={TLS1_2_VERSION,TLS1_3_VERSION};
    for(size_t v=0;v<sizeof(versions)/sizeof(versions[0]);v++) {
        ctx=tls_context(ca,1);
        CHECK(SSL_CTX_set_min_proto_version(ctx,versions[v])==1);
        CHECK(SSL_CTX_set_max_proto_version(ctx,versions[v])==1);
        fixture_start(&https,ctx);snprintf(url,sizeof(url),"https://127.0.0.1:%d",https.port);
        c=new_client(url,NULL,NULL,3000);CHECK(ob_api_request(c,"GET","/v1/check",NULL,NULL,&out,&e)==OB_API_TRANSPORT && !out);ob_api_client_destroy(c);
        c=new_client(url,"tenant-token",ca,3000);CHECK(ob_api_request(c,"GET","/v1/check",NULL,NULL,&out,&e)==OB_API_OK && e.http_status==200);ob_api_response_free(out);
        for(size_t i=0;i<8;i++) {args[i].client=c;CHECK(pthread_create(&threads[i],NULL,parallel_request,&args[i])==0);}
        for(size_t i=0;i<8;i++) {pthread_join(threads[i],NULL);CHECK(args[i].ok);}
        ob_api_client_destroy(c);fixture_stop(&https);SSL_CTX_free(ctx);
    }
    ctx=tls_context(ca,0);fixture_start(&https,ctx);snprintf(url,sizeof(url),"https://127.0.0.1:%d",https.port);
    c=new_client(url,NULL,ca,3000);CHECK(ob_api_request(c,"GET","/v1/check",NULL,NULL,&out,&e)==OB_API_TRANSPORT && !out);ob_api_client_destroy(c);
    fixture_stop(&https);SSL_CTX_free(ctx);CHECK(unlink(ca)==0);CHECK(rmdir(directory)==0);*certificate_root=0;free(directory);
    puts("PASS native HTTP/HTTPS verification, injection, budgets, errors, redirects, timeout, concurrency");
}

static char *json_string(const char *response,const char *key) {
    const char *end=NULL;cJSON *j=cJSON_ParseWithOpts(response,&end,1);CHECK(j);
    cJSON *v=cJSON_GetObjectItemCaseSensitive(j,key);CHECK(cJSON_IsString(v));
    char *s=strdup(v->valuestring);CHECK(s);cJSON_Delete(j);return s;
}
static char *nested_string(const char *response,const char *object,const char *key) {
    const char *end=NULL;cJSON *j=cJSON_ParseWithOpts(response,&end,1);CHECK(j);
    cJSON *v=cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(j,object),key);CHECK(cJSON_IsString(v));
    char *s=strdup(v->valuestring);CHECK(s);cJSON_Delete(j);return s;
}
#define OK(call) do { int rc=(call);if(rc!=OB_API_OK)fprintf(stderr,"Control operation failed: code=%d status=%ld %s\n",rc,e.http_status,e.message);CHECK(rc==OB_API_OK && out); } while(0)
#define FREE_OUT() do { ob_api_response_free(out);out=NULL; } while(0)
static void control_tests(const char *url) {
    ob_api_client *anon=new_client(url,NULL,NULL,10000),*tenant,*second;
    ob_api_error e;char *out=NULL;ob_api_credentials creds,other;
    OK(ob_api_tenant_register(anon,&creds,&out,&e));CHECK(strlen(creds.name)==43 && !strncmp(creds.name,"tenant-",7) && strlen(creds.password)==32);
    char *token=json_string(out,"token");FREE_OUT();
    tenant=new_client(url,token,NULL,10000);ob_api_response_free(token);
    OK(ob_api_tenant_login(anon,creds.name,creds.password,&out,&e));FREE_OUT();
    OK(ob_api_account_get(tenant,&out,&e));CHECK(!strstr(out,"password"));FREE_OUT();
    OK(ob_api_account_update(tenant,NULL,"native-api-test@example.invalid",&out,&e));token=json_string(out,"token");FREE_OUT();ob_api_client_destroy(tenant);tenant=new_client(url,token,NULL,10000);ob_api_response_free(token);
    OK(ob_api_capabilities(tenant,&out,&e));FREE_OUT();OK(ob_api_usage(tenant,&out,&e));FREE_OUT();
    OK(ob_api_broker_register(tenant,"native-api-local-test",&out,&e));
    char *broker=nested_string(out,"broker","id"),*device=json_string(out,"device_token");FREE_OUT();
    OK(ob_api_broker_list(tenant,&out,&e));CHECK(strstr(out,broker));FREE_OUT();
    OK(ob_api_broker_get(tenant,broker,&out,&e));FREE_OUT();
    OK(ob_api_broker_rename(tenant,broker,"native-api-renamed",&out,&e));FREE_OUT();
    OK(ob_api_broker_usage(tenant,broker,&out,&e));FREE_OUT();
    OK(ob_api_broker_heartbeat(anon,broker,device,&out,&e));FREE_OUT();
    OK(ob_api_broker_offline(anon,broker,device,&out,&e));FREE_OUT();
    OK(ob_api_broker_heartbeat(anon,broker,device,&out,&e));FREE_OUT();
    OK(ob_api_session_create(tenant,broker,"never",&out,&e));
    char *session=json_string(out,"session_id"),*session_token=json_string(out,"session_token");FREE_OUT();
    OK(ob_api_broker_sessions(anon,broker,device,&out,&e));CHECK(strstr(out,session));FREE_OUT();
    OK(ob_api_session_get(anon,session,session_token,&out,&e));FREE_OUT();
    OK(ob_api_session_capabilities(anon,session,session_token,&out,&e));FREE_OUT();
    OK(ob_api_session_heartbeat(anon,session,session_token,&out,&e));FREE_OUT();
    CHECK(ob_api_session_turn(anon,session,session_token,&out,&e)==OB_API_HTTP && e.http_status==403);FREE_OUT();
    OK(ob_api_session_message_send(anon,session,session_token,1,"opaque-test-client",&out,&e));FREE_OUT();
    OK(ob_api_session_messages(anon,session,device,0,&out,&e));CHECK(strstr(out,"opaque-test-client"));FREE_OUT();
    OK(ob_api_session_messages(anon,session,session_token,0,&out,&e));CHECK(!strstr(out,"opaque-test-client"));FREE_OUT();
    OK(ob_api_session_message_send(anon,session,device,1,"opaque-test-device",&out,&e));FREE_OUT();
    OK(ob_api_session_messages(anon,session,session_token,0,&out,&e));CHECK(strstr(out,"opaque-test-device"));FREE_OUT();
    OK(ob_api_session_approve(anon,session,device,0,&out,&e));FREE_OUT();
    CHECK(ob_api_session_turn(anon,session,session_token,&out,&e)==OB_API_HTTP && e.http_status==403);FREE_OUT();
    const char *admin=getenv("OB_API_TEST_ADMIN_TOKEN");
    if(admin && *admin) {
        OK(ob_api_account_get(tenant,&out,&e));char *tenant_id=nested_string(out,"tenant","id");FREE_OUT();
        char admin_path[256];CHECK(snprintf(admin_path,sizeof(admin_path),"/v1/admin/tenants/%s/relay",tenant_id)<(int)sizeof(admin_path));ob_api_response_free(tenant_id);
        OK(ob_api_request(anon,"POST",admin_path,admin,"{\"enabled\":true}",&out,&e));FREE_OUT();
        OK(ob_api_capabilities(tenant,&out,&e));CHECK(strstr(out,"\"relay_enabled\":true") && strstr(out,"\"turn_available\":true"));FREE_OUT();
        OK(ob_api_session_create(tenant,broker,"force",&out,&e));
        char *relay_session=json_string(out,"session_id"),*relay_token=json_string(out,"session_token");FREE_OUT();
        CHECK(ob_api_session_turn(anon,relay_session,relay_token,&out,&e)==OB_API_HTTP && e.http_status==403);FREE_OUT();
        OK(ob_api_session_approve(anon,relay_session,device,1,&out,&e));FREE_OUT();
        OK(ob_api_session_turn(anon,relay_session,relay_token,&out,&e));
        char *username=json_string(out,"username"),*turn_password=json_string(out,"password");CHECK(*username && *turn_password && strstr(out,"\"urls\""));ob_api_response_free(username);ob_api_response_free(turn_password);FREE_OUT();
        OK(ob_api_session_delete(anon,relay_session,relay_token,&out,&e));FREE_OUT();ob_api_response_free(relay_session);ob_api_response_free(relay_token);
        puts("PASS force-relay approval gate and short-lived TURN credentials");
    }
    OK(ob_api_session_create(tenant,broker,"never",&out,&e));
    char *extra_session=json_string(out,"session_id"),*extra_token=json_string(out,"session_token");FREE_OUT();
    OK(ob_api_session_delete(anon,extra_session,extra_token,&out,&e));FREE_OUT();ob_api_response_free(extra_session);ob_api_response_free(extra_token);
    OK(ob_api_tenant_register(anon,&other,&out,&e));token=json_string(out,"token");FREE_OUT();second=new_client(url,token,NULL,10000);ob_api_response_free(token);
    CHECK(ob_api_broker_get(second,broker,&out,&e)==OB_API_HTTP && (e.http_status==403 || e.http_status==404));FREE_OUT();
    ob_api_client_destroy(second);ob_api_credentials_clear(&other);
    CHECK(ob_api_broker_token_rotate(tenant,broker,&out,&e)==OB_API_HTTP && e.http_status==409);FREE_OUT();
    OK(ob_api_broker_offline(anon,broker,device,&out,&e));FREE_OUT();
    OK(ob_api_broker_token_rotate(tenant,broker,&out,&e));char *newdevice=json_string(out,"device_token");FREE_OUT();
    CHECK(ob_api_broker_heartbeat(anon,broker,device,&out,&e)==OB_API_HTTP && e.http_status==401);FREE_OUT();ob_api_response_free(device);device=newdevice;
    OK(ob_api_broker_heartbeat(anon,broker,device,&out,&e));FREE_OUT();
    ob_api_response_free(session);ob_api_response_free(session_token);
    OK(ob_api_session_create(tenant,broker,"never",&out,&e));
    session=json_string(out,"session_id");session_token=json_string(out,"session_token");FREE_OUT();
    OK(ob_api_session_get(anon,session,session_token,&out,&e));FREE_OUT();
    const char *newpassword="native-strong-local-password-32";
    OK(ob_api_account_password(tenant,newpassword,&out,&e));token=json_string(out,"token");FREE_OUT();
    CHECK(ob_api_account_get(tenant,&out,&e)==OB_API_HTTP && e.http_status==401);FREE_OUT();
    CHECK(ob_api_broker_heartbeat(anon,broker,device,&out,&e)==OB_API_HTTP && e.http_status==401);FREE_OUT();
    CHECK(ob_api_session_get(anon,session,session_token,&out,&e)==OB_API_HTTP && e.http_status==401);FREE_OUT();
    ob_api_client_destroy(tenant);tenant=new_client(url,token,NULL,10000);ob_api_response_free(token);
    CHECK(ob_api_tenant_login(anon,creds.name,creds.password,&out,&e)==OB_API_HTTP && e.http_status==401);FREE_OUT();
    OK(ob_api_tenant_login(anon,creds.name,newpassword,&out,&e));FREE_OUT();
    OK(ob_api_broker_delete(tenant,broker,&out,&e));FREE_OUT();
    OK(ob_api_broker_list(tenant,&out,&e));CHECK(!strstr(out,broker));FREE_OUT();
    OK(ob_api_tenant_logout(tenant,&out,&e));FREE_OUT();
    CHECK(ob_api_account_get(tenant,&out,&e)==OB_API_HTTP && e.http_status==401);FREE_OUT();
    ob_api_response_free(broker);ob_api_response_free(device);ob_api_response_free(session);ob_api_response_free(session_token);
    ob_api_credentials_clear(&creds);ob_api_client_destroy(tenant);ob_api_client_destroy(anon);
    puts("PASS native control account, broker, device, session, signaling, authorization, revocation flow");
}
int main(int argc,char **argv) {
    signal(SIGPIPE,SIG_IGN);
    const char *tmp=getenv("TMPDIR");CHECK(tmp && *tmp);
    CHECK(snprintf(test_root,sizeof(test_root),"%s/ob-api-env.XXXXXX",tmp)<(int)sizeof(test_root));
    CHECK(mkdtemp(test_root));CHECK(atexit(cleanup_temporary_files)==0);
    char keylog[8192];snprintf(keylog,sizeof(keylog),"%s/tls-keys.log",test_root);
    int existing=argc==2 && !strcmp(argv[1],"--keylog-existing");
    const char *marker="existing caller file; preserve bytes\n";
    if(existing) { FILE *file=fopen(keylog,"w");CHECK(file);CHECK(fputs(marker,file)>=0);CHECK(fclose(file)==0); }
    CHECK(setenv("SSLKEYLOGFILE",keylog,1)==0);
    if(argc==1 || existing) security_tests();
    else if(argc==3 && !strcmp(argv[1],"--control")) control_tests(argv[2]);
    else {fprintf(stderr,"usage: remote_api_test [--keylog-existing | --control http://127.0.0.1:PORT]\n");return 2;}
    CHECK(getenv("SSLKEYLOGFILE") && !strcmp(getenv("SSLKEYLOGFILE"),keylog));
    /* Pristine curl may open/create this file before the per-context callback.
     * Require no new bytes/secrets, not the former patched no-file-touch claim. */
    struct stat info;CHECK(stat(keylog,&info)==0);
    CHECK(info.st_size==(off_t)(existing?strlen(marker):0));
    FILE *file=fopen(keylog,"r");CHECK(file);
    if(existing) { char contents[128];CHECK(fgets(contents,sizeof(contents),file));CHECK(!strcmp(contents,marker)); }
    CHECK(fgetc(file)==EOF);CHECK(!ferror(file));CHECK(fclose(file)==0);
    puts("PASS SDK TLS keylog suppression; no appended secrets, caller environment unchanged");
    return 0;
}
