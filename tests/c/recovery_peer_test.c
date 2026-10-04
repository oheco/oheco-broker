/* Public-API interactive driver for tests/peer_recovery.py. */
#define _GNU_SOURCE
#include "ob_remote.h"
#include "ob_api.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t output_mu=PTHREAD_MUTEX_INITIALIZER;
static uint64_t millis(void) {struct timespec value;clock_gettime(CLOCK_MONOTONIC,&value);return (uint64_t)value.tv_sec*1000+(uint64_t)value.tv_nsec/1000000;}
static void json_string(const char *text)
{
    putchar('"');for(const unsigned char *p=(const unsigned char *)text;*p;++p){if(*p=='"'||*p=='\\'){putchar('\\');putchar(*p);}else if(*p<32)printf("\\u%04x",(unsigned)*p);else putchar(*p);}putchar('"');
}
static void print_info(const char *event,const ob_remote_connection_info *info)
{
    pthread_mutex_lock(&output_mu);
    printf("{\"event\":\"%s\",\"state\":%d,\"attempts\":%u,\"generation\":%" PRIu64 ",\"next_retry_ms\":%" PRIu64 ",\"error\":%d,\"http_status\":%d,\"message\":",event,(int)info->state,info->attempts,info->generation,info->next_retry_ms,info->last_error.code,info->last_error.http_status);
    json_string(info->last_error.message);puts("}");
    pthread_mutex_unlock(&output_mu);
}
static void state_callback(const ob_remote_connection_info *info,void *unused) {(void)unused;print_info("state",info);}
static void udp_stats(void)
{
    void (*stats)(uint64_t *,uint64_t *)=dlsym(RTLD_DEFAULT,"ob_test_udp_fault_stats");
    uint64_t sent=0,received=0;if(stats)stats(&sent,&received);
    pthread_mutex_lock(&output_mu);
    printf("{\"event\":\"fault_stats\",\"active\":%s,\"sent\":%" PRIu64 ",\"received\":%" PRIu64 "}\n",stats?"true":"false",sent,received);
    pthread_mutex_unlock(&output_mu);
}
static int fault_probe(void)
{
    int fd=socket(AF_INET,SOCK_DGRAM,0);struct sockaddr_in address={0};socklen_t length=sizeof(address);
    address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(fd<0||bind(fd,(struct sockaddr *)&address,sizeof(address))||getsockname(fd,(struct sockaddr *)&address,&length))return 2;
    ssize_t sent=sendto(fd,"probe",5,0,(struct sockaddr *)&address,length);int saved=errno;
    struct pollfd pending={fd,POLLIN,0};int readable=poll(&pending,1,150);
    char bytes[16];ssize_t received=readable>0?recvfrom(fd,bytes,sizeof(bytes),0,NULL,NULL):-1;
    printf("{\"event\":\"fault_probe\",\"sent\":%zd,\"errno\":%d,\"readable\":%d,\"received\":%zd}\n",sent,saved,readable,received);
    if(sent!=5||received!=5){close(fd);return 2;}
    const char *file=getenv("OB_TEST_UDP_FAULT_FILE");if(!file){close(fd);return 2;}
    int other=socket(AF_INET,SOCK_DGRAM,0);struct sockaddr_in remote=address;remote.sin_port=0;length=sizeof(remote);
    if(other<0||bind(other,(struct sockaddr *)&remote,sizeof(remote))||getsockname(other,(struct sockaddr *)&remote,&length)){close(fd);if(other>=0)close(other);return 2;}
    for(int hard=0;hard<2;++hard){
        FILE *flag=fopen(file,"w");if(!flag){close(other);close(fd);return 2;}fputs(hard?"hard":"drop",flag);fclose(flag);
        if(sendto(fd,"",0,0,(struct sockaddr *)&address,sizeof(address))!=0||poll(&pending,1,150)!=1||recvfrom(fd,bytes,sizeof(bytes),0,NULL,NULL)!=0)goto bad_probe;
        struct msghdr wake={0};wake.msg_name=&address;wake.msg_namelen=sizeof(address);
        if(sendmsg(fd,&wake,0)!=0||poll(&pending,1,150)!=1)goto bad_probe;
        struct iovec buffer={bytes,sizeof(bytes)};struct msghdr incoming={0};incoming.msg_iov=&buffer;incoming.msg_iovlen=1;
        if(recvmsg(fd,&incoming,0)!=0)goto bad_probe;
        ssize_t normal=sendto(fd,"blocked",7,0,(struct sockaddr *)&address,sizeof(address));
        if((hard?(normal!=-1||errno!=ENETDOWN):normal!=7)||poll(&pending,1,150)!=0)goto bad_probe;
        ssize_t zero=sendto(fd,"",0,0,(struct sockaddr *)&remote,sizeof(remote));struct pollfd other_pending={other,POLLIN,0};
        if((hard?(zero!=-1||errno!=ENETDOWN):zero!=0)||poll(&other_pending,1,150)!=0)goto bad_probe;
    }
    unlink(file);udp_stats();printf("{\"event\":\"self_wakeup_probe\",\"passed\":true}\n");close(other);close(fd);return 0;
bad_probe:
    unlink(file);fprintf(stderr,"UDP fault self-wakeup/peer-drop regression failed errno=%d\n",errno);close(other);close(fd);return 2;
}
struct burst_call {ob_remote_peer *peer;ob_remote_server *server;int result;};
static void *burst_worker(void *data)
{struct burst_call *call=data;ob_remote_error error={0};call->result=call->peer?ob_remote_peer_reconnect(call->peer,&error):ob_remote_server_reconnect(call->server,&error);return NULL;}
static void print_maps(ob_remote_map *tcp,ob_remote_map *udp)
{
    pthread_mutex_lock(&output_mu);
    printf("{\"event\":\"maps\",\"tcp_port\":%u,\"udp_port\":%u,\"tcp_handle\":\"%p\",\"udp_handle\":\"%p\"}\n",ob_remote_map_local_port(tcp),ob_remote_map_local_port(udp),(void *)tcp,(void *)udp);
    pthread_mutex_unlock(&output_mu);
}
int main(int argc,char **argv)
{
    setvbuf(stdout,NULL,_IONBF,0);
    if(argc==2&&!strcmp(argv[1],"--fault-probe"))return fault_probe();
    if((argc!=6&&argc!=7)|| (strcmp(argv[1],"serve")&&strcmp(argv[1],"connect"))) {fprintf(stderr,"usage: recovery_peer_test serve|connect API broker-name|broker-UUID TCP-target-port UDP-target-port [never|force|auto]\n");return 2;}
    ob_remote_relay_mode relay=OB_REMOTE_RELAY_NEVER;
    if(argc==7){if(!strcmp(argv[6],"force"))relay=OB_REMOTE_RELAY_FORCE;else if(!strcmp(argv[6],"auto"))relay=OB_REMOTE_RELAY_AUTO;else if(strcmp(argv[6],"never"))return 2;}
    const char *token=getenv("OB_RECOVERY_ACCOUNT_TOKEN"),*password=getenv("OB_RECOVERY_PEER_PASSWORD");
    if(!token||!password)return 2;
    unsigned tcp_port=(unsigned)strtoul(argv[4],NULL,10),udp_port=(unsigned)strtoul(argv[5],NULL,10);
    if(!tcp_port||tcp_port>65535||!udp_port||udp_port>65535)return 2;
    ob_api_options api_options={argv[2],token,NULL,1500};ob_api_error api_error={0};ob_remote_error error={0};
    ob_api_client *api=ob_api_client_create(&api_options,&api_error);if(!api)return 2;
    ob_remote_server *server=NULL;ob_remote_peer *peer=NULL;ob_remote_map *tcp=NULL,*udp=NULL;int result=1;
    ob_remote_reconnect_policy policy;ob_remote_reconnect_policy_init(&policy);
    policy.max_attempts=2;policy.initial_delay_ms=250;policy.max_delay_ms=500;policy.retry_budget_ms=12000;policy.flow_grace_ms=120000;policy.stable_reset_ms=30000;policy.transport_timeout_ms=3000;
    const char *delay=getenv("OB_RECOVERY_RETRY_DELAY_MS");if(delay)policy.initial_delay_ms=policy.max_delay_ms=(uint32_t)strtoul(delay,NULL,10);
    const char *grace=getenv("OB_RECOVERY_FLOW_GRACE_MS");if(grace)policy.flow_grace_ms=(uint32_t)strtoul(grace,NULL,10);
    const char *idle=getenv("OB_RECOVERY_TRANSPORT_TIMEOUT_MS");if(idle)policy.transport_timeout_ms=(uint32_t)strtoul(idle,NULL,10);
    if(!strcmp(argv[1],"serve")) {
        ob_remote_allow_rule rules[]={{"127.0.0.1",(uint16_t)tcp_port,(uint16_t)tcp_port,OB_REMOTE_TCP},{"127.0.0.1",(uint16_t)udp_port,(uint16_t)udp_port,OB_REMOTE_UDP}};
        ob_remote_serve_options options={0};options.allow_rules=rules;options.allow_rule_count=2;options.setup_timeout_ms=8000;options.udp_idle_timeout_ms=120000;
        if(ob_remote_serve(api,argv[3],password,&options,&server,&error)||ob_remote_server_set_reconnect_policy(server,&policy,&error)||ob_remote_server_set_state_callback(server,state_callback,NULL))goto done;
        pthread_mutex_lock(&output_mu);printf("{\"event\":\"server_ready\",\"broker_id\":\"%s\"}\n",ob_remote_server_id(server));pthread_mutex_unlock(&output_mu);
    } else {
        ob_remote_connect_options options={0};options.relay_mode=relay;options.timeout_ms=8000;options.udp_idle_timeout_ms=120000;
        if(ob_remote_connect_async(api,argv[3],password,&options,&peer,&error)||ob_remote_peer_set_reconnect_policy(peer,&policy,&error)||ob_remote_peer_set_state_callback(peer,state_callback,NULL))goto done;
        pthread_mutex_lock(&output_mu);printf("{\"event\":\"peer_created\",\"handle\":\"%p\"}\n",(void *)peer);pthread_mutex_unlock(&output_mu);
    }
    for(;;) {
        ob_remote_connection_info info={0};int rc=peer?ob_remote_peer_get_state(peer,&info):ob_remote_server_get_state(server,&info);if(rc)goto done;
        if(peer&&info.state==OB_REMOTE_STATE_CONNECTED&&!tcp) {
            if(ob_remote_portmap_tcp(peer,NULL,0,"127.0.0.1",(uint16_t)tcp_port,&tcp,&error)||ob_remote_portmap_udp(peer,NULL,0,"127.0.0.1",(uint16_t)udp_port,&udp,&error))goto done;
            print_maps(tcp,udp);
        }
        struct pollfd input={STDIN_FILENO,POLLIN,0};if(poll(&input,1,50)<0) {if(errno==EINTR)continue;goto done;}
        if(!(input.revents&(POLLIN|POLLHUP)))continue;
        char line[80];if(!fgets(line,sizeof(line),stdin)) {result=0;break;}
        if(!strncmp(line,"state",5)) {print_info("snapshot",&info);if(tcp)print_maps(tcp,udp);udp_stats();}
        else if(!strncmp(line,"reconnect",9)) {uint64_t start=millis();rc=peer?ob_remote_peer_reconnect(peer,&error):ob_remote_server_reconnect(server,&error);pthread_mutex_lock(&output_mu);printf("{\"event\":\"manual\",\"result\":%d,\"elapsed_ms\":%" PRIu64 "}\n",rc,millis()-start);pthread_mutex_unlock(&output_mu);}
        else if(!strncmp(line,"burst",5)) {
            unsigned count=(unsigned)strtoul(line+5,NULL,10);if(!count||count>32)count=16;
            pthread_t threads[32];struct burst_call calls[32];unsigned launched=0;
            for(;launched<count;++launched){calls[launched]=(struct burst_call){peer,server,OB_REMOTE_EIO};if(pthread_create(&threads[launched],NULL,burst_worker,&calls[launched]))break;}
            unsigned accepted=0;for(unsigned i=0;i<launched;++i){pthread_join(threads[i],NULL);if(calls[i].result==OB_REMOTE_OK)++accepted;}
            pthread_mutex_lock(&output_mu);printf("{\"event\":\"burst\",\"requested\":%u,\"launched\":%u,\"accepted\":%u}\n",count,launched,accepted);pthread_mutex_unlock(&output_mu);
        }
        else if(!strncmp(line,"close",5)) {result=0;break;}
        else {fprintf(stderr,"unknown driver command\n");goto done;}
    }
done:
    if(result)fprintf(stderr,"recovery driver failed rc=%d http=%d %s\n",error.code,error.http_status,error.message);
    uint64_t start=millis();if(tcp)ob_remote_map_close(tcp);if(udp)ob_remote_map_close(udp);
    if(peer)ob_remote_peer_close(peer);if(server)ob_remote_server_close(server);ob_api_client_destroy(api);
    pthread_mutex_lock(&output_mu);printf("{\"event\":\"closed\",\"elapsed_ms\":%" PRIu64 ",\"result\":%d}\n",millis()-start,result);pthread_mutex_unlock(&output_mu);
    return result;
}
