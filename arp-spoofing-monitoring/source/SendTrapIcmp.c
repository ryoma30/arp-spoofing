#include "../header/SendTrapIcmp.h"



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
    mac2char16(smac, mac_str2); 
    mac2char16(dmac, mac_str3); //Ether宛先mac
    memcpy(pEthHdr->ether_shost, mac_str2, 6);
    memcpy(pEthHdr->ether_dhost, mac_str3, 6);
    pEthHdr->ether_type = htons(ETHERTYPE_IP);
 }

//ICMPヘッダを作成します。
void setIcmpHeader(struct icmphdr* pIcmpHdr, int identify, int cnt) {
    pIcmpHdr->type = 8;
    pIcmpHdr->code = 0;
    pIcmpHdr->un.echo.id = htons(identify);
    pIcmpHdr->un.echo.sequence = htons(cnt);
    seq_num = cnt;
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
    pIpHdr->check = 0; //以前までのチャックサム値を消しておく
    pIpHdr->check = getCheckSum((ushort*)pIpHdr, sizeof(struct iphdr));
}
 
//int main(int argc, char *argv[])
int sendTrapIcmp(char* ifname, char* smac, char* dmac, char* sip, char* dip)
{
    int cnt=1;
    int identify=999;

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
    sockaddr.sll_ifindex = if_nametoindex(ifname);
    //sockaddr.sll_ifindex = if_nametoindex(argv[1]);
    sockaddr.sll_halen = 6;

    //送信,受信パケット格納配列
    char packet[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)+32];
    char buf[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)+32];
    
    //ether header
    struct ether_header *eh;
    eh = (struct ether_header *)packet;
    setEthHeader(eh,smac ,dmac);
    //setEthHeader(eh, "7c:b7:33:00:d3:8d", "a4:ba:db:fa:ac:9a");
    
    //ip header
    struct iphdr *ih;
    ih = (struct iphdr *)(packet+sizeof(struct ether_header));
    setIpHeader(sip, dip, ih);
    //setIpHeader("192.168.10.127", "192.168.10.189", ih);
    //icmp header
    struct icmphdr *ich;
    ich = (struct icmphdr *)(packet+sizeof(struct ether_header) + sizeof(struct iphdr));
    memcpy(packet+sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), "abcdefghijklmnopqrstuvwxyzhello!",32);
    setIcmpHeader(ich, identify, cnt);


    //printf("dmac %s\n" , dmac);
    while (cnt <= 3)
    {
        sleep(1);
        int n;
        if ((n = sendto(icmp_sock, (char *)packet, sizeof(packet),
                   0, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))< 0)
        {
            perror("sendto");
            printf("errno: %d\n", errno);
            return 1;
        }else{
            cnt++;
            setIcmpHeader(ich, identify, cnt);
        }

        memset(buf, 0, sizeof(buf));
        int fromlen = sizeof(sockaddr);
        if((n = recvfrom(icmp_sock, (char *)buf, sizeof(buf), 
                    0, (struct sockaddr *)&sockaddr, (socklen_t*)&fromlen)) < 1){
            perror("receive");
        }else{
            clock_t ct = clock();
            while(clock() - ct < 1000){
                struct ether_header* recv_eth = (struct ether_header*)(buf);
                struct icmphdr* recv_icmp = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
                
                // for(int i=sizeof(struct ether_header) + sizeof(struct iphdr); 
                //         i<sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr); i++){
                //     printf("%02X\n", (unsigned char)buf[i]);
                // }
                // printf( "type       ->  %02X\n"
                //         "code       ->  %02X\n"
                //         "id         ->  %u\n"
                //         "sequence   ->  %u\n"
                //         ,(unsigned char)recv_icmp->type
                //         ,(unsigned char)recv_icmp->code
                //         ,ntohs(recv_icmp->un.echo.id)
                //         ,ntohs(recv_icmp->un.echo.sequence));
                if((u_int16_t)(identify) == ntohs(recv_icmp->un.echo.id) /*&& recv_icmp->type == 0*/){
                    char mac_str[ETH_ALEN];
                    mac2char16(dmac, mac_str);
                    // printf("%d \n", recv_icmp->type);
                    // print_analysis(recv_eth->ether_shost, "recv eth", ETH_ALEN);
                    // print_analysis(mac_str, "mac_str ", ETH_ALEN);
                    if(memcmp(recv_eth->ether_shost, mac_str, ETH_ALEN) != 0 || recv_icmp->type != 0){
                        //spoof[].attacker_type = 1;
                        //printf("違うやつから返ってきた\n");
                        return 0;
                    }else{
                        // print_analysis(recv_eth->ether_shost, "recv eth", ETH_ALEN);
                        // print_analysis(mac_str, "mac_str ", ETH_ALEN);
                    }
                    //printf("good job\n");
                    //spoof[0].attacker_type = -1;
                    return 1;
                }
                //return 1;
            }

        }
    }
   //cnt = 1;
//spoof[0].attacker_type = 0;
//printf("何も帰ってきません\n");

return 0;

}
