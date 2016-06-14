
#include <signal.h>  
#include <stdio.h>  
#include <errno.h>  
#include <stdlib.h>  
  
#include <netinet/in_systm.h>  
#include <netinet/ip.h>  
#include <netinet/ip_icmp.h>  
#include <arpa/inet.h>  
#include <netdb.h>  
#include <sys/un.h>  
  
#define BUFSIZE 1500  
#define  DATA_LEN 56   
  
struct proto   
{  
    struct sockaddr *sasend; /* sockaddr{} for send, from getaddrinfo */  
    struct sockaddr *sarecv; /* sockaddr{} for receiving */  
    socklen_t salen; /* length of sockaddr{}s */  
    int icmpproto; /* IPPROTO_xxx value for ICMP */  
};  
int g_sockfd;  
struct proto g_proto = { NULL, NULL, 0, IPPROTO_ICMP };  
  
void proc_msg(char *, ssize_t, struct msghdr *, struct timeval *);  
  
void send_msg(void);  
  
void readloop(void);  
  
void sig_alrm(int);  
  
void tv_sub(struct timeval *, struct timeval *);  
  
struct addrinfo *host_serv(const char *host,   
    const char *serv, int family, int socktype);  
  
char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen);  
  
uint16_t in_cksum(uint16_t *addr, int len);  
  
void error_quit(const char *str);  
 
char Sendmsg[DATA_LEN];
  
int main(int argc, char **argv)  
{   
    int c;  
    struct addrinfo *ai;  
    struct sockaddr_in *sin;  
    char *ip_address;  
    char *host;  
  
    if( argc != 3 )  
        error_quit("usage: myping <hostname> msg");  
  
    host = argv[1];  
    memcpy(Sendmsg,argv[2],DATA_LEN);
    //设置定时器，每秒钟向服务器发送一次请求  
    signal(SIGALRM, sig_alrm);  
  
    //获取服务器的信息（addrinfo结构）  
    ai = host_serv(host, NULL, 0, 0);  
    ip_address = sock_ntop_host(ai->ai_addr, ai->ai_addrlen);  
  
    printf("PING %s (%s): %d data bytes\n",  
        ai->ai_canonname ? ai->ai_canonname : ip_address,  
        ip_address, DATA_LEN);  
  
    //如果返回的协议簇不是AF_INET(IPv4)，则退出  
    if ( ai->ai_family != AF_INET )  
        error_quit("unknown address family");  
  
    g_proto.sasend = ai->ai_addr;  
    g_proto.sarecv = calloc(1, ai->ai_addrlen);  
    g_proto.salen = ai->ai_addrlen;  
  
    readloop();  
  
    return 0;  
}  
  
void readloop(void)  
{  
    int size;  
    char recvbuf[BUFSIZE];  
    char controlbuf[BUFSIZE];  
    struct msghdr msg;  
    struct iovec iov;  
    ssize_t n;  
    struct timeval tval;  
  
    g_sockfd = socket(g_proto.sasend->sa_family, SOCK_RAW, g_proto.icmpproto);  
    if( -1 == g_sockfd )  
        error_quit("socket error");  
  
  
    size = 60 * 1024;  
    setsockopt(g_sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));  
  
    sig_alrm(SIGALRM);  
  
    //为recvmsg调用设置msghdr结构  
    iov.iov_base = recvbuf;  
    iov.iov_len = sizeof(recvbuf);  
    msg.msg_name = g_proto.sarecv;  
    msg.msg_iov = &iov;  
    msg.msg_iovlen = 1;  
    msg.msg_control = controlbuf;  
  
    while( 1 )  
    {  
        msg.msg_namelen = g_proto.salen;  
        msg.msg_controllen = sizeof(controlbuf);  
        n = recvmsg(g_sockfd, &msg, 0);  
        if (n < 0)  
        {  
            if (errno == EINTR)  
                continue;  
            else  
                error_quit("recvmsg error");  
        }  
  
        printf("msg:%s\n",recvbuf);
        printf("control:%s\n",controlbuf);
        gettimeofday(&tval, NULL);  
        proc_msg(recvbuf, n, &msg, &tval);  
    }  
}  
  
void proc_msg(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv)  
{  
    int hlen1, icmplen;  
    double rtt;  
    struct ip *ip;  
    struct icmp *icmp;  
    struct timeval *tvsend;  
  
    //将服务器返回的字符串强转为ip结构  
    ip = (struct ip *) ptr;   
  
    //得到IP表头的长度  
    hlen1 = ip->ip_hl << 2;   
  
    //如果不是ICMP的应答，则返回  
    if (ip->ip_p != IPPROTO_ICMP)  
        return;  
  
    icmp = (struct icmp *) (ptr + hlen1);   
    if ( (icmplen = len - hlen1) < 8)  
        return;  
  
    //不是回显应答，返回  
    if (icmp->icmp_type != ICMP_ECHOREPLY)   
        return;  
  
    //不是我们发出请求的应答，返回  
    //if (icmp->icmp_id != g_pid)  
    //    return;

    if (icmplen < 16)  
        return;  
  
    //tvsend = (struct timeval *) icmp->icmp_data;  
    char *ms = (char *) icmp->icmp_data;
    //tv_sub(tvrecv, tvsend);  
    //rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;  
  
    //printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",  
    //    icmplen, sock_ntop_host(g_proto.sarecv, g_proto.salen),  
    //    icmp->icmp_seq, ip->ip_ttl, rtt);  
 
    printf("msg:%s\n",(char *)ms);
}  
  
  
void send_msg(void)  
{  
    int len;  
    int res;  
    struct icmp *icmp;  
    char sendbuf[BUFSIZE];  
    static int nsent = 0;  
  
    icmp = (struct icmp *) sendbuf;  
  
    //ICMP回显请求  
    icmp->icmp_type = ICMP_ECHO;  
    icmp->icmp_code = 1;  
  
    //icmp->icmp_id = g_pid;  
    icmp->icmp_id = 0;
    icmp->icmp_seq = nsent++;  
  
    memset(icmp->icmp_data, 0, DATA_LEN); 
    //char *msg = "httpd hahahaha\n";
    memcpy((char *)icmp->icmp_data,Sendmsg,DATA_LEN);
    //icmp->icmp_data[0] =(char *) msg;
    int i;
    printf("===\n");
    //for( i = 0; i < 15; i++) {
    //    printf("%d ",msg[i]);
    //}
    //printf("\n");
    //gettimeofday((struct timeval *)icmp->icmp_data, NULL);  
  
    len = 8 + DATA_LEN;  
    icmp->icmp_cksum = 0;  
    icmp->icmp_cksum = in_cksum((u_short *) icmp, len);  
  
    res = sendto(g_sockfd, sendbuf, len, 0, g_proto.sasend, g_proto.salen);  
    if( -1 == res )  
        error_quit("sendto error");  
}  
  
  
void sig_alrm(int signo)  
{  
    send_msg();  
    alarm(1);  
}  
  
void tv_sub(struct timeval *out, struct timeval *in)  
{  
    if ( (out->tv_usec -= in->tv_usec) < 0)   
    {   
        --out->tv_sec;  
        out->tv_usec += 1000000;  
    }  
    out->tv_sec -= in->tv_sec;  
}  
  
struct addrinfo *host_serv(const char *host, const char *serv, int family, int socktype)  
{  
    int n;  
    struct addrinfo hints, *res;  
  
    memset(&hints, 0, sizeof(struct addrinfo));  
    hints.ai_flags = AI_CANONNAME;  
    hints.ai_family = family;   
    hints.ai_socktype = socktype;  
  
    n = getaddrinfo(host, serv, &hints, &res);  
    if ( n != 0 )  
        error_quit("getaddrinfo error");  
  
    return res;  
}  
  
char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen)  
{  
    static char str[128];  
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;  
  
    if( sa->sa_family != AF_INET )  
        error_quit("sock_ntop_host: the type must be AF_INET");  
  
    if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)  
        error_quit("inet_ntop error");  
  
    return str;  
}  
  
uint16_t in_cksum(uint16_t *addr, int len)  
{  
    int nleft = len;  
    uint32_t sum = 0;  
    uint16_t *w = addr;  
    uint16_t answer = 0;  
  
    /* 
    * Our algorithm is simple, using a 32 bit accumulator (sum), we add 
    * sequential 16 bit words to it, and at the end, fold back all the 
    * carry bits from the top 16 bits into the lower 16 bits. 
    */  
    while (nleft > 1)   
    {  
        sum += *w++;  
        nleft -= 2;  
    }  
  
    /* 4mop up an odd byte, if necessary */  
    if (nleft == 1) {  
        *(unsigned char *)(&answer) = *(unsigned char *)w ;  
        sum += answer;  
    }  
  
    /* 4add back carry outs from top 16 bits to low 16 bits */  
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */  
    sum += (sum >> 16); /* add carry */  
    answer = ~sum; /* truncate to 16 bits */  
    return(answer);  
}  
  
void error_quit(const char *str)  
{  
    fprintf(stderr, "%s", str);     
    if( errno != 0 )      
        fprintf(stderr, " : %s", strerror(errno));      
    fprintf(stderr, "\n");          
    exit(1);   
}
