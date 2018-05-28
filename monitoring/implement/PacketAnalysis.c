#include "../header/PacketAnalysis.h"

void packetAnalysis(u_char *user,                  // pcap_loop関数の第4引数
                    const struct pcap_pkthdr *h , // 受信したPacketの補足情報
                    const u_char *p ){

    ip = (struct ip *)(p+ETH_HLEN);
    ether_header = (struct ether_header *)p;
    ether_arp = (struct ether_arp *)(p+ETH_HLEN);
 

    return;
}

void mac2char16(char* macadd, char* mac_str){
    char* mac = macadd;
    //char mac_str[6];
    char temp[3];
    int i;
    for(i = 0; i < 6; i++){
        temp[0] = mac[i * 3 + 0];
        temp[1] = mac[i * 3 + 1];
        temp[2] = 0x00;
        mac_str[i] = strtol(temp, NULL, 16);
       // printf("mac_str[%d] = %d\n", i, mac_str[i]);
    }

}