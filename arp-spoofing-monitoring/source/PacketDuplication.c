#include "../header/PacketDuplication.h"




void setEthHeader2(struct ether_header*  pEthHdr, char* smac, char* dmac) {
    char mac_str[6], mac_str2[6] , mac_str3[6];
    mac2char16(smac, mac_str2); 
    mac2char16(dmac, mac_str3); //Ether宛先mac
    memcpy(pEthHdr->ether_shost, mac_str2, 6);
    memcpy(pEthHdr->ether_dhost, mac_str3, 6);
    pEthHdr->ether_type = htons(ETHERTYPE_IP);
 }


void setIpHeader2(const char* srcAddr, const char* dstAddr, struct iphdr* pIpHdr, int plen) {
    //pIpHdr->ihl = 0x5;
   // pIpHdr->version = 0x4;
    //pIpHdr->tos = 0x0;
    pIpHdr->tot_len = htons(plen-14);
    //pIpHdr->id = 0x8f8f;
  //  pIpHdr->frag_off = 0x0;
    //   pIpHdr->ttl = 0x54;
   // pIpHdr->protocol = 0x1;    
    //pIpHdr->saddr = inet_addr(srcAddr);
    pIpHdr->daddr = inet_addr(dstAddr);
    pIpHdr->check = 0; //以前までのチャックサム値を消しておく
    pIpHdr->check = getCheckSum((ushort*)pIpHdr, sizeof(struct iphdr));
}
 
int packetDuplication(char *packet, int packet_size, char *ifname, char *smac, char *sip, char *t_dmac, char *f_dmac, char *t_dip, char *f_dip)
//int sendTrapIcmp(char* ifname, char* smac, char* dmac, char* sip, char* dip)
{
    //printf("psize :::%d\n", packet_size);
    //送信用ソケットの作成
    int icmp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(icmp_sock < 0){
        perror("socket error");
        return -1;
    }

    //送信先設定
    struct sockaddr_ll sockaddr;
    memset(&sockaddr, 0x0, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_IP);
    sockaddr.sll_ifindex = if_nametoindex(ifname);
    //sockaddr.sll_ifindex = if_nametoindex(argv[1]);
    sockaddr.sll_halen = 6;

    //送信,受信パケット格納配列
    //char packet[sizeof(struct eh) + sizeof(struct iphdr) + sizeof(struct icmphdr)+32];
    char buf[packet_size];
    
    //ether header
    struct ether_header *eh;
    eh = (struct ether_header *)packet;
    //setEthHeader(eh,smac ,dmac);
    setEthHeader2(eh, smac, t_dmac);
    
    //ih header
    struct iphdr *ih;
    ih = (struct iphdr *)(packet+sizeof(struct ether_header));
    // setIpHeader(sip, dip, ih);
    setIpHeader2(sip, t_dip, ih, packet_size);
    
    //icmp header
    // struct icmphdr *ich;
    // ich = (struct icmphdr *)(packet+sizeof(struct eh) + sizeof(struct iphdr));
    // memcpy(packet+sizeof(struct eh) + sizeof(struct iphdr) + sizeof(struct icmphdr), "abcdefghijklmnopqrstuvwxyzhello!",32);
    // setIcmpHeader(ich, identify, cnt);
    int fromlen, n;
    // while (1)
    // {
        //sleep(3);
        // setEthHeader2(eh, smac, f_dmac);
        // setIpHeader2(sip, f_dip, ih, packet_size);
        
        // if ((n = sendto(icmp_sock, (char *)packet, packet_size,
        //            0, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))< 0)
        // {
        //     perror("sendto");
        //     printf("errno: %d\n", errno);
        //     return 1;
        // }else{
        //     //setIcmpHeader(ich, identify, cnt);
        // }

        // memset(buf, 0, sizeof(buf));
        // fromlen = sizeof(sockaddr);
        // if((n = recvfrom(icmp_sock, (char *)buf, sizeof(buf), 
        //             0, (struct sockaddr *)&sockaddr, (socklen_t*)&fromlen)) < 1){
        //     perror("receive");
        // }else{
        //         //printf("received\n");
        // }
        setEthHeader2(eh, smac, t_dmac);
        setIpHeader2(sip, t_dip, ih, packet_size);
        
    int count =0;
    //while(count < 1){
        if ((n = sendto(icmp_sock, (char *)packet, packet_size,
            0, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))< 0)
        {
            perror("sendto");
            printf("errno: %d\n", errno);
            return 1;
        }else{
            //char ip_address_s[15], ip_address_d[15];
            //memcpy(ip_address_s, ih->saddr, 15);
            //memcpy(ip_address_d, ih->daddr, 15);
            //if(ih->protocol == 17){
            //printf("smac -> %s \n", smac);
            //printf("sip  -> %s \n", sip);
            // printf("---------------------\n");
            // printf("ip_v = 0x%x\n", ih->version);
            // printf("ip_hl = 0x%x\n", ih->ihl);
            // printf("ip_tos = 0x%.2x\n", ih->tos);
            // printf("ip_len = %d bytes\n", ntohs(ih->tot_len));
            // printf("ip_id = 0x%.4x\n", ntohs(ih->id));
            // printf("ip_off = 0x%.4x\n", ntohs(ih->frag_off));
            // printf("ip_ttl = 0x%.2x\n", ih->ttl);
            // printf("ip_p = 0x%.2x\n", ih->protocol);
            // printf("ip_sum = 0x%.4x\n", ntohs(ih->check));
            // //printf("ip_src = %2u\n", ih->saddr);
            // //printf("ip_dst = %2u\n", ih->daddr);
            // //printf("---------------------\n");
            // printf("ether_shost = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
            // eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
            // eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
            // printf("ether_dhost = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
            // eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
            // eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
            // printf("%04x\n", ntohs(eh->ether_type));
            // printf("count %d\n", count);
            //}
        }
        //count++;
    //}
        // memset(buf, 0, sizeof(buf));
        // fromlen = sizeof(sockaddr);
        // if((n = recvfrom(icmp_sock, (char *)buf, sizeof(buf), 
        //             0, (struct sockaddr *)&sockaddr, (socklen_t*)&fromlen)) < 1){
        //     perror("receive");
        // }else{

        // }
        // }
   

  /* 終了 */
  close(icmp_sock);
return 0;

}
