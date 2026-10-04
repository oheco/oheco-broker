#define _GNU_SOURCE
#include "ob_remote.h"
#include "ob_api.h"
#include "peer/internal.h"
#include "peer/crypto.h"
#include <arpa/inet.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "peer_policy_test.c"
#ifdef OB_UDP_TRACE
extern void ob_mapping_udp_trace_dump(void);
#endif
#ifdef OB_UDP_COUNTERS
extern void ob_mapping_udp_counters_dump(void);
#endif
struct echo { int fd, udp; uint16_t port; pthread_t thread; atomic_int stop; atomic_uint udp_received, udp_echoed; atomic_int udp_last_error; };
static void pause_ms(unsigned n)
{ struct timespec t = {n/1000, (long)(n%1000)*1000000}; while(nanosleep(&t,&t)&&errno==EINTR){} }
static void timeout(int fd)
{ struct timeval tv = {5,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv)); }
static int all(int fd, unsigned char *data, size_t n, int writing)
{
    size_t pos = 0;
    while (pos < n) { ssize_t k = writing ? send(fd,data+pos,n-pos,MSG_NOSIGNAL) : recv(fd,data+pos,n-pos,0);
        if (k <= 0) return -1; pos += (size_t)k; }
    return 0;
}
static void *echo_worker(void *data)
{
    struct echo *e = data; unsigned char bytes[65536];
    while (!atomic_load(&e->stop)) {
        struct pollfd pollfd = {e->fd,POLLIN,0};
        if (poll(&pollfd,1,100) <= 0) continue;
        if (e->udp) { struct sockaddr_storage addr; socklen_t len = sizeof(addr);
            ssize_t n = recvfrom(e->fd,bytes,sizeof(bytes),0,(struct sockaddr *)&addr,&len);
            if (n >= 0) {
                atomic_fetch_add(&e->udp_received,1);
                ssize_t echoed=sendto(e->fd,bytes,(size_t)n,0,(struct sockaddr *)&addr,len);
                atomic_store(&e->udp_last_error,echoed<0?errno:0);
                if(echoed==n)atomic_fetch_add(&e->udp_echoed,1);
            }
        } else {
            int fd = accept(e->fd,NULL,NULL); if (fd < 0) continue; timeout(fd);
            while (!atomic_load(&e->stop)) {
                struct pollfd incoming = {fd,POLLIN,0}; if (poll(&incoming,1,100) <= 0) continue;
                ssize_t n = recv(fd,bytes,sizeof(bytes),0); if (n <= 0) break;
                if (all(fd,bytes,(size_t)n,1)) break;
            }
            close(fd);
        }
    }
    return NULL;
}
static int echo_start(struct echo *e, int udp)
{
    memset(e,0,sizeof(*e)); e->udp = udp; e->fd = socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0);
    struct sockaddr_in addr = {0}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    socklen_t len=sizeof(addr);
    if (e->fd < 0 || bind(e->fd,(struct sockaddr *)&addr,sizeof(addr)) || getsockname(e->fd,(struct sockaddr *)&addr,&len)
        || (!udp && listen(e->fd,32))) { if (e->fd >= 0) close(e->fd); e->fd=-1; return -1; }
    e->port=ntohs(addr.sin_port);
    if (pthread_create(&e->thread,NULL,echo_worker,e)) { close(e->fd); e->fd=-1; return -1; }
    return 0;
}
static void echo_stop(struct echo *e)
{ if (e->fd >= 0) { atomic_store(&e->stop,1); pthread_join(e->thread,NULL); close(e->fd); e->fd=-1; } }
static int connected(uint16_t port, int udp)
{
    int fd=socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0); if (fd < 0) return -1; timeout(fd);
    struct sockaddr_in addr = {0}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK); addr.sin_port=htons(port);
    if (connect(fd,(struct sockaddr *)&addr,sizeof(addr))) { close(fd); return -1; } return fd;
}
static int tcp_check(uint16_t port)
{
    int fd=connected(port,0); if (fd < 0) return -1;
    unsigned char sent[16384], received[16384]; int result=-1;
    for (unsigned block=0; block<32; ++block) {
        for (size_t i=0;i<sizeof(sent);++i) sent[i]=(unsigned char)(i+block);
        if (all(fd,sent,sizeof(sent),1) || all(fd,received,sizeof(received),0) || memcmp(sent,received,sizeof(sent))) {
            fprintf(stderr,"TCP block %u failed errno=%d\n",block,errno);goto done;
        }
    }
    if (shutdown(fd,SHUT_WR)) goto done;
    unsigned char b; ssize_t end=recv(fd,&b,1,0);if(end!=0){fprintf(stderr,"TCP FIN failed n=%zd errno=%d\n",end,errno);goto done;}
    result=0;
done: close(fd); return result;
}
static int udp_check(uint16_t port, ob_remote_peer *peer, ob_remote_server *server, struct echo *target)
{
    const char *stage="socket"; ssize_t n=-1; size_t wanted=0;
    int a=connected(port,1), b=connected(port,1), result=-1;
    unsigned char *sent=malloc(65507), *received=malloc(65507);
    if (a<0 || b<0 || !sent || !received) goto done;
    const char one[]="source-a",two[]="source-b";
    stage="source-a-send";wanted=sizeof(one);n=send(a,one,sizeof(one),0);if(n!=(ssize_t)sizeof(one))goto done;
    stage="source-b-send";wanted=sizeof(two);n=send(b,two,sizeof(two),0);if(n!=(ssize_t)sizeof(two))goto done;
    stage="source-b-recv";wanted=sizeof(two);n=recv(b,received,65507,0); if(n!=(ssize_t)sizeof(two)||memcmp(two,received,sizeof(two)))goto done;
    stage="source-a-recv";wanted=sizeof(one);n=recv(a,received,65507,0); if(n!=(ssize_t)sizeof(one)||memcmp(one,received,sizeof(one)))goto done;
    stage="zero-send";wanted=0;n=send(a,"",0,0);if(n!=0)goto done;
    stage="zero-recv";n=recv(a,received,65507,0);if(n!=0)goto done;
    const size_t lengths[]={512,513,16384,65507};
    for(size_t t=0;t<sizeof(lengths)/sizeof(lengths[0]);++t){size_t size=lengths[t];
        for(size_t i=0;i<size;++i)sent[i]=(unsigned char)(i*7+t);
        stage="payload-send";wanted=size;n=send(a,sent,size,0);if(n!=(ssize_t)size)goto done;
        stage="payload-recv";n=recv(a,received,65507,0); if(n!=(ssize_t)size||memcmp(sent,received,size))goto done;
    }
    result=0;
done:
    if(result){
        int saved_errno=n<0?errno:0;ob_remote_connection_info pi={0},si={0};
        int pr=ob_remote_peer_get_state(peer,&pi),sr=ob_remote_server_get_state(server,&si);
        fprintf(stderr,"UDP diagnostic stage=%s expected=%zu n=%zd errno=%d target_received=%u target_echoed=%u target_errno=%d peer_rc=%d peer_state=%d peer_generation=%llu peer_attempts=%u server_rc=%d server_state=%d server_generation=%llu server_attempts=%u\n",
            stage,wanted,n,saved_errno,atomic_load(&target->udp_received),atomic_load(&target->udp_echoed),atomic_load(&target->udp_last_error),
            pr,(int)pi.state,(unsigned long long)pi.generation,pi.attempts,sr,(int)si.state,(unsigned long long)si.generation,si.attempts);
    }
    if(a>=0)close(a);if(b>=0)close(b);free(sent);free(received);return result;
}
static char *test_signal(const char *sid, const unsigned char key[32],
                          double version, double sequence, const char *type, const char *payload)
{
    unsigned char mac[32];char hex[65];
    if(ob_signal_mac(key,1,type,payload,mac))return NULL;
    ob_hex(mac,32,hex);cJSON *j=cJSON_CreateObject();
    cJSON_AddNumberToObject(j,"v",version);cJSON_AddStringToObject(j,"sid",sid);
    cJSON_AddNumberToObject(j,"seq",sequence);cJSON_AddStringToObject(j,"t",type);
    cJSON_AddStringToObject(j,"payload",payload);cJSON_AddStringToObject(j,"mac",hex);
    char *data=cJSON_PrintUnformatted(j);cJSON_Delete(j);return data;
}
static int parser_and_binding_tests(void)
{
    const char *sid="00000000-0000-0000-0000-000000000001",*bid="00000000-0000-0000-0000-000000000002";
    ob_remote_peer client={0},server={0};unsigned char cm[32]={3},sm[32]={4};
    client.session_id=server.session_id=(char *)sid;client.broker_id=server.broker_id=(char *)bid;
    server.is_server=1;client.shared_len=server.shared_len=64;
    memset(client.shared,7,64);memcpy(server.shared,client.shared,64);
    if(ob_derive_keys(&client,cm,sm)||ob_derive_keys(&server,cm,sm)
        ||CRYPTO_memcmp(client.tx_key,server.rx_key,32)||CRYPTO_memcmp(client.rx_key,server.tx_key,32))return -1;
    char *data=test_signal(sid,client.tx_key,1,1,"ice","original"),*payload=NULL;
    if(!data||ob_decode_signal(&server,data,1,"ice",1,&payload)||strcmp(payload,"original")){free(data);free(payload);return -1;}
    free(payload);payload=NULL;
    if(!ob_decode_signal(&server,data,1,"ice",1,&payload)){free(data);free(payload);return -1;}
    server.rx_sequence=0;
    if(!ob_decode_signal(&server,data,1.5,"ice",1,&payload)){free(data);free(payload);return -1;}
    free(data);
    const double versions[]={1.5,1,1};const double sequences[]={1,1.5,9007199254740992.0};
    for(size_t i=0;i<3;++i){data=test_signal(sid,client.tx_key,versions[i],sequences[i],"ice","original");
        int rejected=data&&ob_decode_signal(&server,data,1,"ice",1,&payload)!=0;free(data);free(payload);payload=NULL;if(!rejected)return -1;}
    data=test_signal(sid,server.tx_key,1,1,"ice","original");
    int rejected=data&&ob_decode_signal(&server,data,1,"ice",1,&payload)!=0;free(data);free(payload);payload=NULL;if(!rejected)return -1;
    sm[0]^=1;if(ob_derive_keys(&client,cm,sm))return -1;
    data=test_signal(sid,client.tx_key,1,1,"ice","original");
    rejected=data&&ob_decode_signal(&server,data,1,"ice",1,&payload)!=0;free(data);free(payload);payload=NULL;if(!rejected)return -1;
    sm[0]^=1;client.session_id="00000000-0000-0000-0000-000000000003";
    if(ob_derive_keys(&client,cm,sm))return -1;
    data=test_signal(sid,client.tx_key,1,1,"ice","original");
    rejected=data&&ob_decode_signal(&server,data,1,"ice",1,&payload)!=0;free(data);free(payload);payload=NULL;if(!rejected)return -1;
    client.session_id=(char *)sid;if(ob_derive_keys(&client,cm,sm))return -1;
    data=test_signal(sid,client.tx_key,1,1,"ice","original");cJSON *j=data?ob_peer_json_parse(data):NULL;free(data);
    if(!j)return -1;
    cJSON_ReplaceItemInObjectCaseSensitive(j,"t",cJSON_CreateString("confirm"));data=cJSON_PrintUnformatted(j);cJSON_Delete(j);
    rejected=data&&ob_decode_signal(&server,data,1,"confirm",1,&payload)!=0;free(data);free(payload);payload=NULL;if(!rejected)return -1;
    unsigned char mac[32];char hex[65],raw[512];if(ob_signal_mac(client.tx_key,1,"ice","original",mac))return -1;ob_hex(mac,32,hex);
    const char *nul_types[]={"ice\\u0000suffix","ice","ice"};
    const char *nul_payloads[]={"original","original\\u0000suffix","original"};
    for(size_t i=0;i<3;++i){
        snprintf(raw,sizeof(raw),"{\"v\":1,\"sid\":\"%s%s\",\"seq\":1,\"t\":\"%s\",\"payload\":\"%s\",\"mac\":\"%s\"}",sid,i==2?"\\u0000suffix":"",nul_types[i],nul_payloads[i],hex);
        if(!ob_decode_signal(&server,raw,1,"ice",1,&payload)){free(payload);return -1;}
    }
    snprintf(raw,sizeof(raw),"{\"v\":1,\"v\":1,\"sid\":\"%s\",\"seq\":1,\"t\":\"ice\",\"payload\":\"original\",\"mac\":\"%s\"}",sid,hex);
    if(!ob_decode_signal(&server,raw,1,"ice",1,&payload)){free(payload);return -1;}
    const char *raw_numbers[]={"1.0000000000000001","1.0","1e0","-0","9007199254740992"};
    for(size_t i=0;i<sizeof(raw_numbers)/sizeof(raw_numbers[0]);++i)for(unsigned which=0;which<2;++which){
        snprintf(raw,sizeof(raw),"{\"v\":%s,\"sid\":\"%s\",\"seq\":%s,\"t\":\"ice\",\"payload\":\"original\",\"mac\":\"%s\"}",
                 which?"1":raw_numbers[i],sid,which?raw_numbers[i]:"1",hex);
        if(!ob_decode_signal(&server,raw,1,"ice",1,&payload)||server.rx_sequence){free(payload);return -1;}
    }
    printf("PASS raw envelope v/seq rounded tiny-fraction, decimal/exponent, sign and unsafe-integer rejection without consumption\n");
    j=ob_peer_json_parse("[\"\\\\u0000\"]");if(!j)return -1;cJSON_Delete(j);
    j=ob_peer_json_parse("{\"sdp\":\"opaque\\u0000suffix\"}");if(j){cJSON_Delete(j);return -1;}
    server.rx_sequence=UINT64_C(9007199254740991);data=test_signal(sid,client.tx_key,1,1,"ice","original");
    rejected=data&&ob_decode_signal(&server,data,1,"ice",1,&payload)!=0;free(data);free(payload);if(!rejected)return -1;
    unsigned char fingerprint[32]={8},exporter[32]={9},proof[32],changed[32];
    if(ob_channel_mac(client.shared,64,fingerprint,exporter,0,proof)
        ||ob_channel_mac(client.shared,64,fingerprint,exporter,1,changed)||!CRYPTO_memcmp(proof,changed,32))return -1;
    exporter[0]^=1;if(ob_channel_mac(client.shared,64,fingerprint,exporter,0,changed)||!CRYPTO_memcmp(proof,changed,32))return -1;exporter[0]^=1;
    fingerprint[0]^=1;if(ob_channel_mac(client.shared,64,fingerprint,exporter,0,changed)||!CRYPTO_memcmp(proof,changed,32))return -1;
    OPENSSL_cleanse(client.shared,64);OPENSSL_cleanse(server.shared,64);
    printf("PASS strict fraction/NUL/replay/reflection/transcript/session/channel-binding rejection\n");return 0;
}
static int unit_tests(void)
{
    unsigned char key[32]={1},a[32],b[32],decoded[32];char text[65];
    if(ob_signal_mac(key,1,"ice","original",a)||ob_signal_mac(key,1,"ice","tampered",b)||!CRYPTO_memcmp(a,b,32))return -1;
    if(ob_signal_mac(key,2,"ice","original",b)||!CRYPTO_memcmp(a,b,32))return -1;
    ob_hex(a,32,text);if(ob_unhex(text,decoded,32)||CRYPTO_memcmp(a,decoded,32))return -1;
    if(!ob_unhex("invalid",decoded,32))return -1;
    printf("PASS signalling MAC payload/sequence tamper and strict hex\n");
    for(int wrong=0;wrong<3;++wrong){
        SPAKE2_CTX *client=SPAKE2_CTX_new(spake2_role_alice,(const unsigned char *)"client",6,(const unsigned char *)"broker",6);
        SPAKE2_CTX *server=SPAKE2_CTX_new(wrong==2?spake2_role_alice:spake2_role_bob,(const unsigned char *)"broker",6,(const unsigned char *)"client",6);
        unsigned char cm[32],sm[32],ck[64],sk[64];size_t cn=0,sn=0,ckn=0,skn=0;
        int ok=client&&server&&SPAKE2_generate_msg(client,cm,&cn,sizeof(cm),(const unsigned char *)"test-password",13)
            &&SPAKE2_generate_msg(server,sm,&sn,sizeof(sm),(const unsigned char *)(wrong==1?"wrong-password":"test-password"),wrong==1?14:13)
            &&SPAKE2_process_msg(client,ck,&ckn,sizeof(ck),sm,sn)&&SPAKE2_process_msg(server,sk,&skn,sizeof(sk),cm,cn);
        if(ok)ok=ckn==skn&&((CRYPTO_memcmp(ck,sk,ckn)!=0)==(wrong!=0));
        SPAKE2_CTX_free(client);SPAKE2_CTX_free(server);OPENSSL_cleanse(ck,sizeof(ck));OPENSSL_cleanse(sk,sizeof(sk));
        if(!ok)return -1;
    }
    printf("PASS upstream SPAKE2 equal/wrong password and role confusion keys\n");
    if(parser_and_binding_tests() || ob_peer_policy_tests())return -1;
    ob_remote_peer cert_peer={0};int cert_ok=0;
    if(!ob_make_certificate(&cert_peer)){
        BIO *bio=BIO_new_file(cert_peer.cert_path,"r");X509 *cert=bio?PEM_read_bio_X509(bio,NULL,NULL,NULL):NULL;
        unsigned char *der=NULL;int size=cert?i2d_X509(cert,&der):0;
        if(size>0&&ob_certificate_matches(&cert_peer,der,(size_t)size)){
            cert_peer.fingerprint[0]^=1;
            int pin_rejected=!ob_certificate_matches(&cert_peer,der,(size_t)size);
            cert_peer.fingerprint[0]^=1;der[size-1]^=1;
            cert_ok=pin_rejected&&!ob_certificate_matches(&cert_peer,der,(size_t)size);
        }
        OPENSSL_free(der);X509_free(cert);BIO_free(bio);
    }
    ob_certificate_cleanup(&cert_peer);if(!cert_ok)return -1;
    printf("PASS actual DER certificate pin and mutated pin/certificate rejection\n");
    ob_remote_server acl_server={0};ob_remote_peer acl_peer={0};acl_peer.server=&acl_server;acl_peer.is_server=acl_peer.ready=1;
    ob_remote_allow_rule rule={"127.0.0.0/8",12345,12345,OB_REMOTE_TCP};
    struct sockaddr_storage address;socklen_t length=sizeof(address);
    if(ob_target_resolve(&acl_peer,"127.0.0.1",12345,OB_REMOTE_TCP,&address,&length)!=OB_REMOTE_EACL)return -1;
    acl_server.rules=&rule;acl_server.rule_count=1;
    if(ob_target_resolve(&acl_peer,"127.0.0.1",12345,OB_REMOTE_TCP,&address,&length)
        ||ob_target_resolve(&acl_peer,"127.0.0.1",12346,OB_REMOTE_TCP,&address,&length)!=OB_REMOTE_EACL
        ||ob_target_resolve(&acl_peer,"127.0.0.1",12345,OB_REMOTE_UDP,&address,&length)!=OB_REMOTE_EACL)return -1;
    printf("PASS default-deny and chosen-IP CIDR/port/protocol target ACL\n");return 0;
}
int main(int argc,char **argv)
{
    setvbuf(stdout,NULL,_IONBF,0);
    if(unit_tests()) { fprintf(stderr,"FAIL native crypto unit tests\n");return 1; }
    if(argc<2){printf("Integration not run: supply local control base URL [--force] [--idle].\n");return 0;}
    int force=0,idle=0,result=1;
    for(int i=2;i<argc;++i){if(!strcmp(argv[i],"--force"))force=1;else if(!strcmp(argv[i],"--idle"))idle=1;
        else{fprintf(stderr,"Unknown test option\n");return 2;}}
    ob_api_client *anonymous=NULL,*api=NULL;ob_remote_server *server=NULL;ob_remote_peer *peer=NULL,*peer2=NULL,*bad=NULL;
    ob_remote_map *maps[8]={0};char *response=NULL;struct echo tcp={.fd=-1},udp={.fd=-1};
    ob_remote_error error={0};ob_api_error ae={0};char registered_id[37]={0};
    ob_api_credentials credentials={0};
    ob_api_options ao={argv[1],NULL,NULL,3000};
    anonymous=ob_api_client_create(&ao,&ae);if(!anonymous)goto done;
    if(ob_api_tenant_register(anonymous,&credentials,&response,&ae))goto done;
    cJSON *registration=cJSON_Parse(response);
    if(force){
        const char *admin=getenv("OB_PEER_TEST_ADMIN_TOKEN");
        cJSON *tenant=cJSON_GetObjectItemCaseSensitive(registration,"tenant");
        cJSON *id=cJSON_GetObjectItemCaseSensitive(tenant,"id");char path[160];
        if(!admin||!cJSON_IsString(id)){fprintf(stderr,"--force requires isolated control admin in OB_PEER_TEST_ADMIN_TOKEN\n");cJSON_Delete(registration);goto done;}
        snprintf(path,sizeof(path),"/v1/admin/tenants/%s/relay",id->valuestring);
        char *grant=NULL;int rc=ob_api_request(anonymous,"POST",path,admin,"{\"enabled\":true}",&grant,&ae);ob_api_response_free(grant);
        cJSON_Delete(registration);registration=NULL;ob_api_response_free(response);response=NULL;
        if(rc||ob_api_tenant_login(anonymous,credentials.name,credentials.password,&response,&ae))goto done;
        registration=cJSON_Parse(response);
    }
    cJSON *token=cJSON_GetObjectItemCaseSensitive(registration,"token");
    if(cJSON_IsString(token)){ao.tenant_token=token->valuestring;api=ob_api_client_create(&ao,&ae);}
    cJSON_Delete(registration);ob_api_response_free(response);response=NULL;ob_api_credentials_clear(&credentials);if(!api)goto done;
    if(echo_start(&tcp,0)||echo_start(&udp,1))goto done;
    ob_remote_allow_rule rules[]={{"127.0.0.1",tcp.port,tcp.port,OB_REMOTE_TCP},{"127.0.0.1",udp.port,udp.port,OB_REMOTE_UDP}};
    ob_remote_serve_options so={0};so.allow_rules=rules;so.allow_rule_count=2;so.setup_timeout_ms=15000;
    if(ob_remote_serve(api,"native-peer-test","separate-peer-password",&so,&server,&error))goto done;
    snprintf(registered_id,sizeof(registered_id),"%s",ob_remote_server_id(server));
    ob_remote_connect_options co={0};co.timeout_ms=15000;co.relay_mode=force?OB_REMOTE_RELAY_FORCE:OB_REMOTE_RELAY_AUTO;
    int rc=ob_remote_connect(api,ob_remote_server_id(server),"wrong-peer-password",&co,&bad,&error);
    if(rc!=OB_REMOTE_EAUTH||bad){fprintf(stderr,"wrong password result %d: %s\n",rc,error.message);goto done;}
    printf("PASS live wrong peer password rejected\n");
    if(ob_remote_connect(api,ob_remote_server_id(server),"separate-peer-password",&co,&peer,&error))goto done;
    if(idle){
        printf("WAIT 100 seconds without application traffic (beyond 90s QUIC idle timeout)\n");
        pause_ms(100000);
        if(ob_remote_peer_status(peer,&error))goto done;
        printf("PASS QUIC keepalive preserves authenticated idle peer for 100 seconds\n");
    }
    if(ob_remote_portmap_tcp(peer,NULL,0,"127.0.0.1",tcp.port,&maps[0],&error)
        ||ob_remote_portmap_tcp(peer,NULL,0,"127.0.0.1",tcp.port,&maps[1],&error)
        ||ob_remote_portmap_udp(peer,NULL,0,"127.0.0.1",udp.port,&maps[2],&error))goto done;
    if(tcp_check(ob_remote_map_local_port(maps[0]))||tcp_check(ob_remote_map_local_port(maps[1]))){fprintf(stderr,"FAIL TCP echo/FIN\n");goto done;}
    printf("PASS multiple TCP mappings 512KiB bidirectional echo and FIN\n");
    if(udp_check(ob_remote_map_local_port(maps[2]),peer,server,&udp)){fprintf(stderr,"FAIL UDP sources/zero/fragmentation\n");goto done;}
    printf("PASS UDP source isolation, zero-length, 512/513/16384/65507-byte fragments\n");
    /* A valid authenticated peer still cannot open an unlisted target port. */
    uint16_t denied=tcp.port==65535?1:(uint16_t)(tcp.port+1);
    if(ob_remote_portmap_tcp(peer,NULL,0,"127.0.0.1",denied,&maps[3],&error))goto done;
    int fd=connected(ob_remote_map_local_port(maps[3]),0);if(fd<0)goto done;
    unsigned char byte=1;send(fd,&byte,1,MSG_NOSIGNAL);ssize_t n=recv(fd,&byte,1,0);close(fd);
    if(n>0|| (n<0&&errno!=ECONNRESET)){fprintf(stderr,"FAIL target ACL rejection\n");goto done;}
    printf("PASS authenticated target ACL denied\n");
    if(!force)co.relay_mode=OB_REMOTE_RELAY_NEVER;
    if(ob_remote_connect(api,ob_remote_server_id(server),"separate-peer-password",&co,&peer2,&error)
        ||ob_remote_portmap_tcp(peer2,NULL,0,"127.0.0.1",tcp.port,&maps[4],&error)
        ||tcp_check(ob_remote_map_local_port(maps[4])))goto done;
    printf("PASS independent second peer and mapping\n");
    if(force){
        if(ob_api_usage(api,&response,&ae))goto done;
        cJSON *usage=cJSON_Parse(response),*bytes=cJSON_GetObjectItemCaseSensitive(usage,"lifetime");
        int counted=cJSON_IsNumber(bytes)&&bytes->valuedouble>=1048576;
        cJSON_Delete(usage);ob_api_response_free(response);response=NULL;
        if(!counted){fprintf(stderr,"FAIL actual TURN relay payload accounting missing\n");goto done;}
        printf("PASS actual control TURN accounts at least 1MiB relayed ciphertext\n");
    }
    /* Revocation closes native listeners; handles remain safe to close later. */
    ob_remote_server_close(server);server=NULL;
    for(unsigned i=0;i<100&&!ob_remote_peer_status(peer,&error);++i)pause_ms(100);
    if(!ob_remote_peer_status(peer,&error)){fprintf(stderr,"FAIL close did not revoke peer\n");goto done;}
    for(size_t i=0;i<8;++i)if(maps[i]){ob_remote_map_close(maps[i]);maps[i]=NULL;}
    ob_remote_peer_close(peer);peer=NULL;ob_remote_peer_close(peer2);peer2=NULL;
    printf("PASS server shutdown revokes forwarding and safe mapping cleanup\n");
    if(ob_remote_serve(api,"native-peer-test","separate-peer-password",&so,&server,&error))goto done;
    if(strcmp(registered_id,ob_remote_server_id(server))){fprintf(stderr,"FAIL restored broker UUID changed\n");goto done;}
    printf("PASS offline broker restored with same UUID without name collision\n");
    printf("PASS native peer integration (%s)\n",force?"forced TURN":"direct ICE");result=0;
done:
    if(result){
        fprintf(stderr,"FAIL integration: remote=%d http=%d %s api=%d status=%ld %s\n",error.code,error.http_status,error.message,ae.code,ae.http_status,ae.message);
        if(peer){ob_remote_error pe;int pr=ob_remote_peer_status(peer,&pe);fprintf(stderr,"Peer status=%d %s\n",pr,pe.message);}
        if(server){ob_remote_error se;int sr=ob_remote_server_status(server,&se);fprintf(stderr,"Server status=%d %s\n",sr,se.message);}
    }
    for(size_t i=0;i<8;++i)if(maps[i])ob_remote_map_close(maps[i]);
    if(bad)ob_remote_peer_close(bad);if(peer)ob_remote_peer_close(peer);if(peer2)ob_remote_peer_close(peer2);
    if(server)ob_remote_server_close(server);
    ob_api_credentials_clear(&credentials);
    echo_stop(&tcp);echo_stop(&udp);ob_api_response_free(response);
    ob_api_client_destroy(api);ob_api_client_destroy(anonymous);
#ifdef OB_UDP_TRACE
    ob_mapping_udp_trace_dump();
#endif
#ifdef OB_UDP_COUNTERS
    ob_mapping_udp_counters_dump();
#endif
    return result;
}
