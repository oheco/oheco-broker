/* SDK-owned offline native API probe; all upstream sources remain separate. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/curve25519.h>
#include <openssl/mem.h>
#include <juice/juice.h>
#include <cjson/cJSON.h>
#include <xquic/xquic.h>
#include "ob_json.h"

#define REQUIRE(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

static void timer_cb(xqc_usec_t delay, void *user)
{ (void)delay; (void)user; }
static ssize_t udp_cb(const unsigned char *buf, size_t size,
    const struct sockaddr *peer, socklen_t peerlen, void *user)
{ (void)buf; (void)peer; (void)peerlen; (void)user; return (ssize_t)size; }

static void spake_pair(int mismatch)
{
    const uint8_t alice[] = "native-probe-alice", bob[] = "native-probe-bob";
    const uint8_t password[] = "test-only password", wrong[] = "different test-only password";
    uint8_t ma[SPAKE2_MAX_MSG_SIZE], mb[SPAKE2_MAX_MSG_SIZE];
    uint8_t ka[SPAKE2_MAX_KEY_SIZE], kb[SPAKE2_MAX_KEY_SIZE];
    size_t la=0, lb=0, kla=0, klb=0;
    SPAKE2_CTX *a=SPAKE2_CTX_new(spake2_role_alice, alice,sizeof(alice)-1,bob,sizeof(bob)-1);
    SPAKE2_CTX *b=SPAKE2_CTX_new(spake2_role_bob,bob,sizeof(bob)-1,alice,sizeof(alice)-1);
    REQUIRE(a&&b);
    REQUIRE(SPAKE2_generate_msg(a,ma,&la,sizeof(ma),password,sizeof(password)-1));
    REQUIRE(SPAKE2_generate_msg(b,mb,&lb,sizeof(mb),mismatch?wrong:password,mismatch?sizeof(wrong)-1:sizeof(password)-1));
    REQUIRE(la==32&&lb==32);
    REQUIRE(SPAKE2_process_msg(a,ka,&kla,sizeof(ka),mb,lb));
    REQUIRE(SPAKE2_process_msg(b,kb,&klb,sizeof(kb),ma,la));
    REQUIRE(kla==64&&klb==64);
    REQUIRE((CRYPTO_memcmp(ka,kb,kla)!=0)==mismatch);
    SPAKE2_CTX_free(a);SPAKE2_CTX_free(b);OPENSSL_cleanse(ka,sizeof(ka));OPENSSL_cleanse(kb,sizeof(kb));
}

static void *parse_thread(void *opaque)
{
    uintptr_t ordinal=(uintptr_t)opaque;
    for (unsigned i=0;i<512;++i) {
        REQUIRE(ob_json_parse_complete("{invalid}",9)==NULL);
        char valid[96]; int n=snprintf(valid,sizeof(valid),"{\"thread\":%u,\"value\":%u}",(unsigned)ordinal,i);
        REQUIRE(n>0&&(size_t)n<sizeof(valid));
        cJSON *json=ob_json_parse_complete(valid,(size_t)n);
        REQUIRE(json&&cJSON_GetObjectItemCaseSensitive(json,"thread")->valueint==(int)ordinal);
        REQUIRE(cJSON_GetObjectItemCaseSensitive(json,"value")->valueint==(int)i);
        cJSON_Delete(json);
    }
    return NULL;
}
int main(void)
{
    pthread_t threads[8];
    for(uintptr_t i=0;i<8;++i)REQUIRE(pthread_create(&threads[i],NULL,parse_thread,(void*)i)==0);
    for(unsigned i=0;i<8;++i)REQUIRE(pthread_join(threads[i],NULL)==0);
    spake_pair(0);spake_pair(1);
    uint8_t msg[SPAKE2_MAX_MSG_SIZE],key[SPAKE2_MAX_KEY_SIZE];size_t mlen=0,klen=0;
    SPAKE2_CTX *bad=SPAKE2_CTX_new(spake2_role_alice,NULL,0,NULL,0);
    REQUIRE(bad&&SPAKE2_generate_msg(bad,msg,&mlen,sizeof(msg),(const uint8_t*)"test-only",9));
    REQUIRE(!SPAKE2_process_msg(bad,key,&klen,sizeof(key),msg,1));SPAKE2_CTX_free(bad);
    cJSON *json=ob_json_parse_complete("{\"native\":true,\"version\":1}",27);
    REQUIRE(json&&cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json,"native")));
    char *serialized=cJSON_PrintUnformatted(json);REQUIRE(serialized);cJSON_free(serialized);cJSON_Delete(json);
    REQUIRE(ob_json_parse_complete("{}{}",4)==NULL);
    juice_config_t ice={0};ice.bind_address="127.0.0.1";juice_agent_t *agent=juice_create(&ice);REQUIRE(agent);
    char sdp[JUICE_MAX_SDP_STRING_LEN];REQUIRE(juice_get_local_description(agent,sdp,sizeof(sdp))==0);
    REQUIRE(strstr(sdp,"a=ice-ufrag:")&&strstr(sdp,"a=ice-pwd:"));
    REQUIRE(juice_set_remote_description(agent,"invalid")<0);juice_destroy(agent);
    xqc_config_t config;REQUIRE(xqc_engine_get_default_config(&config,XQC_ENGINE_CLIENT)==0);config.sendmmsg_on=0;
    xqc_engine_callback_t callbacks={0};callbacks.set_event_timer=timer_cb;
    xqc_transport_callbacks_t transport={0};transport.write_socket=udp_cb;xqc_engine_ssl_config_t tls={0};
    xqc_engine_t *engine=xqc_engine_create(XQC_ENGINE_CLIENT,&config,&tls,&callbacks,&transport,NULL);REQUIRE(engine);
    struct sockaddr_in local={0},peer={0};local.sin_family=peer.sin_family=AF_INET;
    local.sin_addr.s_addr=peer.sin_addr.s_addr=htonl(INADDR_LOOPBACK);local.sin_port=htons(31301);peer.sin_port=htons(31302);
    const unsigned char invalid_packet[]={0};
    REQUIRE(xqc_engine_packet_process(engine,invalid_packet,sizeof(invalid_packet),(struct sockaddr*)&local,sizeof(local),(struct sockaddr*)&peer,sizeof(peer),1,NULL)<0);
    xqc_stream_t *(*volatile stream_api)(xqc_engine_t*,const xqc_cid_t*,xqc_stream_settings_t*,void*)=xqc_stream_create;
    xqc_int_t (*volatile datagram_api)(xqc_connection_t*,void*,size_t,uint64_t*,xqc_data_qos_level_t)=xqc_datagram_send;
    REQUIRE(stream_api&&datagram_api);xqc_engine_destroy(engine);
    puts("PASS pristine xquic/BoringSSL API and SPAKE2; libjuice ICE; SDK-serialized pristine cJSON concurrency");
    return 0;
}
