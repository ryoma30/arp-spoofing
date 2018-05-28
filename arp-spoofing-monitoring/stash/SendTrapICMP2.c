#include "../header/SendTrapICMP2.h"


int main(int argc, char *argv[])
{
    char host[256] = {0};
    int cnt = 0, ret = 0;
    struct addrinfo hints, *res;
    int recvfd = 0, sendfd = 0;
    struct timeval tv;

    if(argc != 2){
        fprintf(stdout, "Usage: myping distination\n");
        return -1;
    }
    strncpy(host, argv[1], 256);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    ret = getaddrinfo(host, NULL, &hints, &res);
    if((ret != 0) || (res == NULL)){
        fprintf(stdout, "distination not found!\n");
        return -1;
    }
    addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
    pid = getpid();

    /* create recv socket */
    recvfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(recvfd < 0){
        perror("socket error");
        return -1;
    }
    /* create send socket */
    sendfd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sendfd < 0){
        perror("socket error");
        return -1;
    }

    for(cnt = 0; cnt < 3; cnt++){
        if(send_icmp_echo_request(sendfd) < 0){
            break;
        }
        gettimeofday(&tv, NULL);
        if(recv_icmp_echo_reply(recvfd, &tv) < 0){
            fprintf(stdout, "Destination Host Unreachable\n");
        }
        sleep(1);
    }
    close(recvfd);
    close(sendfd);
    return 0;
}

unsigned short calc_checksum(int len, void *start)
{
    unsigned short *p;
    unsigned long sum = 0;

    p = (unsigned short *)start;
    while(len > 1){
        sum += *p;
        p++;
        len -= sizeof(unsigned short);
    }
    if(len){
        sum += *(uint8_t *)p;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (unsigned short)(~sum & 0xffff);
}

int send_icmp_echo_request(int sockfd)
{
    struct packet {
        struct iphdr ip;
        struct icmphdr icmp;
        char data[64];
    }packet;
    int datalen = 0, len = 0;
    struct sockaddr_in to;

    /* set icmp data */
    memset(&packet, 0, sizeof(struct packet));
    strcpy(packet.data, "trap icmp");
    datalen = strlen(packet.data);
    packet.icmp.type = ICMP_ECHO;
    packet.icmp.un.echo.id = htons(pid);
    packet.icmp.un.echo.sequence = htons(++sequence);
    datalen += sizeof(struct icmphdr);
    packet.icmp.checksum = calc_checksum(datalen, &(packet.icmp));
    /* set ip header */
    /* (id, tot_len, saddr and check are set automatically.) */
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    datalen += sizeof(struct iphdr);
    packet.ip.tot_len = 0;
    packet.ip.id = 0;
    packet.ip.frag_off = htons(0x02 << 13);
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_ICMP;
    packet.ip.daddr = *(uint32_t *)&addr;
    packet.ip.saddr = 0;
    packet.ip.check = 0;




    /* send icmp */
    memset(&to, 0, sizeof(struct sockaddr_in));
    to.sin_family = PF_INET;
    to.sin_addr = addr;
    len = sendto(sockfd, &packet, datalen, 0, 
            (struct sockaddr *)&to, sizeof(to));
            printf("-------%d\n", (int)sizeof(to));
    if(len < 0){
        perror("sendto error");
    }
    return len;
}

int recv_icmp_echo_reply(int sockfd, struct timeval *tv)
{
    struct iphdr *ip;
    struct icmphdr *icmp;
    char buf[ETHER_MAX_LEN] = {0};
    char sip[16] = {0};
    unsigned short icmpid, icmpseq;
    int len = 0, icmplen = 0, usec = 0;
    double msec;
    struct timeval now, tout;
    fd_set readfd;

    while(1){
        gettimeofday(&now, NULL);
        if(now.tv_sec >= (tv->tv_sec + 2)){
            return -1;    /* timeout */
        }
        memset(buf, 0, sizeof(buf));
        FD_ZERO(&readfd);
        FD_SET(sockfd, &readfd);
        tout.tv_sec = 0;
        tout.tv_usec = 100000;
        if(select(sockfd +1, &readfd, NULL, NULL, &tout) <= 0){
            continue;
        }
        if(FD_ISSET(sockfd, &readfd) == 0){
            continue;
        }
        len = recv(sockfd, buf, sizeof(buf), 0);
        if(len < 0){
            perror("recv error");
            return -1;
        }
        gettimeofday(&now, NULL);
        ip = (struct iphdr *)(buf + sizeof(struct ether_header));
        if((ip->protocol != IPPROTO_ICMP) || (ip->saddr != addr.s_addr)){
            continue;
        }
        icmp = (struct icmphdr *)((char *)ip + sizeof(struct iphdr));
        icmpid = ntohs(icmp->un.echo.id);
        if((icmp->type != ICMP_ECHOREPLY) || (icmpid != pid)){
            continue;
        }
        icmpseq = ntohs(icmp->un.echo.sequence);
        icmplen = ntohs(ip->tot_len) - sizeof(struct iphdr);
        sprintf(sip, "%s", inet_ntoa(*(struct in_addr *)&(ip->saddr)));
        usec = ((now.tv_sec)&0x03) * 1000000 + now.tv_usec;
        usec = usec - ((tv->tv_sec)&0x03) * 1000000 - tv->tv_usec;
        msec = (double)usec / 1000;
        fprintf(stdout,    "%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
            icmplen, sip, icmpseq, ip->ttl, msec);
        break;
    }
    return len;
}