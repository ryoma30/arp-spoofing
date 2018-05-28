#include "../header/SendTrapIcmp.h"


int cnt=1;

// void mac2char16(char* macadd, char* mac_str){
//     char* mac = macadd;
//     //char mac_str[6];
//     char temp[3];
//     int i;
//     for(i = 0; i < 6; i++){
//         temp[0] = mac[i * 3 + 0];
//         temp[1] = mac[i * 3 + 1];
//         temp[2] = 0x00;
//         mac_str[i] = strtol(temp, NULL, 16);
//         //printf("mac_str[%d] = %d\n", i, mac_str[i]);
//     }
// }

ushort getCheckSum(ushort* data, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *data++;
        size -= sizeof(ushort);
    }
    if (size) {
        cksum += *(unsigned char*)data;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (ushort)(~cksum);
}
 
void setEthHeader(struct ether_header*  pEthHdr, char* smac, char* dmac) {
    char mac_str[6], mac_str2[6] , mac_str3[6];
    mac2char16(dmac, mac_str3); //Ether宛先mac
    mac2char16(smac, mac_str2); 
    memcpy(pEthHdr->ether_dhost, mac_str3, 6);
    memcpy(pEthHdr->ether_shost, mac_str2, 6);
    pEthHdr->ether_type = htons(ETHERTYPE_IP);
 }

//ICMPヘッダを作成します。
void setIcmpHeader(struct icmphdr* pIcmpHdr, int cnt) {
    pIcmpHdr->type = 8;
    pIcmpHdr->code = 0;
    pIcmpHdr->un.echo.id = 999;
    pIcmpHdr->un.echo.sequence = htons(cnt);
    pIcmpHdr->checksum = 0;
    pIcmpHdr->checksum = getCheckSum((ushort*)pIcmpHdr, sizeof(struct icmphdr)+32);
}
 
void setIpHeader(const char* srcAddr, const char* dstAddr, struct iphdr* pIpHdr) {
    pIpHdr->ihl = 0x5;
    pIpHdr->version = 0x4;
    pIpHdr->tos = 0x0;
    pIpHdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr)+32);
    pIpHdr->id = 0x8f8f;
    pIpHdr->frag_off = 0x0;
    pIpHdr->ttl = 0x33;
    pIpHdr->protocol = 0x1;
    pIpHdr->saddr = inet_addr(srcAddr);
    pIpHdr->daddr = inet_addr(dstAddr);
    //pIcmpHdr->checksum = 0;
    pIpHdr->check = getCheckSum((ushort*)pIpHdr, sizeof(struct iphdr));
}
 
int main(int argc, char *argv[])
//int sendTrapIcmp(char* ifname, char* smac, char* dmac, char* sip, char* dip)
{

    //送信用ソケットの作成
    int icmp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(icmp_sock < 0){
        perror("socket error");
        return -1;
    }

    //送信先設定
    struct sockaddr_ll sockaddr;
    memset(&sockaddr, 0x0, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_ALL);
    //sockaddr.sll_ifindex = if_nametoindex(ifname);
    sockaddr.sll_ifindex = if_nametoindex(argv[1]);
    sockaddr.sll_halen = 6;

    //送信,受信パケット格納配列
    char packet[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)+32];
    char buf[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)+32];
    
    //ether header
    struct ether_header *eh;
    eh = (struct ether_header *)packet;
    //setEthHeader(eh,smac ,dmac);
    setEthHeader(eh, "7c:b7:33:00:d3:8d", "40:b8:37:ce:d4:5e");
    
    //ip header
    struct iphdr *ih;
    ih = (struct iphdr *)(packet+sizeof(struct ether_header));
    //setIpHeader(sip, dip, ih);
    setIpHeader("192.168.10.127", "192.168.10.233", ih);
    //icmp header
    struct icmphdr *ich;
    ich = (struct icmphdr *)(packet+sizeof(struct ether_header) + sizeof(struct iphdr));
    memcpy(packet+sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), "abcdefghijklmnopqrstuvwxyzhello!",32);
    setIcmpHeader(ich, cnt);

    // while (1)
    // {
        int n;
        sleep(1);
        if ((n = sendto(icmp_sock, (char *)packet, sizeof(packet),
                   0, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))< 0)
        {
            perror("sendto");
            printf("errno: %d\n", errno);
            return 1;
        }else{
            cnt++;
            setIcmpHeader(ich, cnt);
        }

        memset(buf, 0, sizeof(buf));
        int fromlen = sizeof(sockaddr);
        if((n = recvfrom(icmp_sock, (char *)buf, sizeof(buf), 
                    0, (struct sockaddr *)&sockaddr, (socklen_t*)&fromlen)) < 1){
            perror("receive");
        }else{
            // struct icmphdr* recv_icmp = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
            // printf( "type       ->  %d\n"
            //         "code       ->  %d\n"
            //         "id         ->  %d\n"
            //         "sequence   ->  %d\n"
            //         ,recv_icmp->type
            //         ,recv_icmp->code
            //         ,recv_icmp->un.echo.id
            //         ,recv_icmp->un.echo.sequence);
            //return 1;
        }
//    }
   cnt = 1;


return 0;

}
