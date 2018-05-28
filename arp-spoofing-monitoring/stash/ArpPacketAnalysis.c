#include "../header/ArpPacketAnalysis.h"
#include <pcap.h>

void arpPacketAnalysis(){
    //int

     arp_sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if(arp_sock < 0) {
        perror("create arp sock");
        printf("errno: %d\n",errno);
        return;
    }
    /* ARPパケットを受信するIFをeth0に限定 */
    struct sockaddr_ll sockaddr;
    memset(&sockaddr, 0x0, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_ARP);
    sockaddr.sll_ifindex = if_nametoindex("wlp2s0");
    if(bind(arp_sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
        perror("bind arp sock");
        printf("errno: %d\n",errno);
        return;
    }

    while(1) {
      //char buf[256];
      memset(buf,0x0,sizeof(buf));
      int arp_size = recvfrom(arp_sock, buf, sizeof(buf), 0, NULL, NULL);
      if(arp_size < 0) {
         perror("recvfrom");
         printf("errno: %d\n",errno);
      }

      /* 受信したデータはARPパケットなので、その形にキャストして情報にアクセスする */
      struct ether_arp *arppack = (struct ether_arp*) buf;
      printf("operation : %d\n", ntohs(arppack->ea_hdr.ar_op));
      print_ethaddr("sender hardware address", arppack->arp_sha);
      print_ip("sender protocol address", arppack->arp_spa);
      print_ethaddr("target hardware address", arppack->arp_tha);
      print_ip("target protocol address", arppack->arp_tpa);
    }
    return;
}

void print_ip(char* name, unsigned char* ipaddr) {
   printf("%s : %3d.%3d.%3d.%3d\n",name,ipaddr[0],ipaddr[1],ipaddr[2],ipaddr[3]);
}

void print_ethaddr(char* name, unsigned char* ethaddr) {
   printf("%s : %02x:%02x:%02x:%02x:%02x:%02x\n",name,ethaddr[0],ethaddr[1],ethaddr[2],ethaddr[3],ethaddr[4],ethaddr[5]);
}