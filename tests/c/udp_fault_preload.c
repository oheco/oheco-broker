/* Test-only UDP interface failure/blackhole. Never linked into SDK artifacts. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static pthread_once_t fault_once = PTHREAD_ONCE_INIT;
static char *fault_file;
static ssize_t (*next_sendto)(int,const void *,size_t,int,const struct sockaddr *,socklen_t);
static ssize_t (*next_sendmsg)(int,const struct msghdr *,int);
static ssize_t (*next_recvfrom)(int,void *,size_t,int,struct sockaddr *,socklen_t *);
static ssize_t (*next_recvmsg)(int,struct msghdr *,int);
static _Atomic uint64_t dropped_send, dropped_receive;
static void fault_init(void)
{
    const char *file = getenv("OB_TEST_UDP_FAULT_FILE");
    if (file && *file) fault_file = strdup(file);
    next_sendto = dlsym(RTLD_NEXT,"sendto"); next_sendmsg = dlsym(RTLD_NEXT,"sendmsg");
    next_recvfrom = dlsym(RTLD_NEXT,"recvfrom"); next_recvmsg = dlsym(RTLD_NEXT,"recvmsg");
}
/* File contents: "drop [public-map-port]" or "hard [public-map-port]".
 * Excluding the UDP map port lets paused application datagrams reach the SDK,
 * so the harness checks stale packet policy rather than dropping them here. */
static int fault_mode(int socket_fd)
{
    int saved = errno, type = 0; socklen_t length = sizeof(type);
    if (!fault_file || getsockopt(socket_fd,SOL_SOCKET,SO_TYPE,&type,&length) || type != SOCK_DGRAM) { errno=saved; return 0; }
    struct sockaddr_storage address; length=sizeof(address);
    if (getsockname(socket_fd,(struct sockaddr *)&address,&length) || (address.ss_family!=AF_INET && address.ss_family!=AF_INET6)) { errno=saved; return 0; }
    int fd=open(fault_file,O_RDONLY|O_CLOEXEC); if(fd<0) { errno=saved; return 0; }
    char text[80]={0}; ssize_t n=read(fd,text,sizeof(text)-1); close(fd);
    unsigned excluded=0; char mode[16]={0};
    if(n>0) (void)sscanf(text,"%15s %u",mode,&excluded);
    unsigned port = address.ss_family==AF_INET ? ntohs(((struct sockaddr_in *)&address)->sin_port) : ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    errno=saved;
    if(excluded && excluded==port) return 0;
    return !strcmp(mode,"drop") ? 1 : !strcmp(mode,"hard") ? 2 : 0;
}
/* libjuice wakes its UDP worker with an empty datagram to its OWN socket.
 * Preserve that control message, while still faulting empty peer datagrams. */
static int self_datagram(int fd,const struct sockaddr *address,socklen_t length)
{
    int saved=errno;struct sockaddr_storage bound;socklen_t bound_length=sizeof(bound);
    if(!address || getsockname(fd,(struct sockaddr *)&bound,&bound_length)) {errno=saved;return 0;}
    int self=0;
    if(address->sa_family==AF_INET && bound.ss_family==AF_INET && length>=sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *remote=(const struct sockaddr_in *)address,*local=(const struct sockaddr_in *)&bound;
        self=remote->sin_port==local->sin_port && ((ntohl(remote->sin_addr.s_addr)>>24)==127 || remote->sin_addr.s_addr==local->sin_addr.s_addr);
    } else if(address->sa_family==AF_INET6 && bound.ss_family==AF_INET6 && length>=sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *remote=(const struct sockaddr_in6 *)address,*local=(const struct sockaddr_in6 *)&bound;
        int loopback=IN6_IS_ADDR_LOOPBACK(&remote->sin6_addr) || (IN6_IS_ADDR_V4MAPPED(&remote->sin6_addr) && remote->sin6_addr.s6_addr[12]==127);
        self=remote->sin6_port==local->sin6_port && (loopback || !memcmp(&remote->sin6_addr,&local->sin6_addr,sizeof(remote->sin6_addr)));
    }
    errno=saved;return self;
}
/* The public test driver resolves this optional symbol to prove interposition
 * actually occurred on the native platform. */
void ob_test_udp_fault_stats(uint64_t *sent,uint64_t *received)
{ *sent=atomic_load(&dropped_send); *received=atomic_load(&dropped_receive); }
ssize_t sendto(int fd,const void *data,size_t size,int flags,const struct sockaddr *address,socklen_t length)
{
    pthread_once(&fault_once,fault_init);
    int mode=size==0 && self_datagram(fd,address,length) ? 0 : fault_mode(fd);
    if(mode) { atomic_fetch_add(&dropped_send,1); if(mode==2) {errno=ENETDOWN;return -1;} return (ssize_t)size; }
    if(!next_sendto) {errno=ENOSYS;return -1;} return next_sendto(fd,data,size,flags,address,length);
}
ssize_t sendmsg(int fd,const struct msghdr *message,int flags)
{
    pthread_once(&fault_once,fault_init);
    size_t size=0;for(size_t i=0;i<(size_t)message->msg_iovlen;++i)size+=message->msg_iov[i].iov_len;
    int mode=size==0 && self_datagram(fd,message->msg_name,message->msg_namelen) ? 0 : fault_mode(fd);
    if(mode) {
        atomic_fetch_add(&dropped_send,1); if(mode==2) {errno=ENETDOWN;return -1;}
        return (ssize_t)size;
    }
    if(!next_sendmsg) {errno=ENOSYS;return -1;} return next_sendmsg(fd,message,flags);
}
ssize_t recvfrom(int fd,void *data,size_t size,int flags,struct sockaddr *address,socklen_t *length)
{
    pthread_once(&fault_once,fault_init);
    if(!next_recvfrom) {errno=ENOSYS;return -1;}
    struct sockaddr_storage source;socklen_t source_length=sizeof(source);
    struct sockaddr *actual=address?address:(struct sockaddr *)&source;socklen_t *actual_length=address?length:&source_length;
    ssize_t result=next_recvfrom(fd,data,size,flags,actual,actual_length);
    if(result>=0 && !(result==0 && actual_length && self_datagram(fd,actual,*actual_length)) && fault_mode(fd)) {atomic_fetch_add(&dropped_receive,1);errno=EAGAIN;return -1;} return result;
}
ssize_t recvmsg(int fd,struct msghdr *message,int flags)
{
    pthread_once(&fault_once,fault_init);
    if(!next_recvmsg) {errno=ENOSYS;return -1;}
    struct sockaddr_storage source;struct msghdr local=*message;int capture=!message->msg_name;
    if(capture){local.msg_name=&source;local.msg_namelen=sizeof(source);}
    struct msghdr *actual=capture?&local:message;
    ssize_t result=next_recvmsg(fd,actual,flags);
    if(capture && result>=0){message->msg_flags=local.msg_flags;message->msg_controllen=local.msg_controllen;}
    if(result>=0 && !(result==0 && self_datagram(fd,actual->msg_name,actual->msg_namelen)) && fault_mode(fd)) {atomic_fetch_add(&dropped_receive,1);errno=EAGAIN;return -1;} return result;
}
