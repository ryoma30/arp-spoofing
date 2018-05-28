#include "../header/PacketAnalysis.h"

void packetAnalysis(u_char *user,                  // pcap_loop関数の第4引数
                    const struct pcap_pkthdr *h , // 受信したPacketの補足情報
                    const u_char *p ){
    
    packet_len = h->len;
    // printf("plen :::%d\n", packet_len);
    packet = malloc(sizeof(char) * packet_len);
    memcpy(packet, p, packet_len);
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

void macReshape(char* macadd, int mac_size){
    char mac_tmp[mac_size];     
    int count58 = 0;            //':'の文字コードが58,':'出現までのカウント
    int k = 0, i = 0;

    for(i=0; i<mac_size; i++){

        if(macadd[i] == 58){
            if(count58 < 2){
                mac_tmp[k] = 48;
                mac_tmp[k+1] = macadd[i-1];
                mac_tmp[k+2] = macadd[i];
                count58 = 0;
                k += 3;
            }else{
                mac_tmp[k] = macadd[i-2];
                mac_tmp[k+1] = macadd[i-1];
                mac_tmp[k+2] = macadd[i];
                count58 = 0;
                k += 3;
            }

        }else{
            if(k > 14){
                break;
            }
            count58++;
        }

    }
    if(macadd[i+1] == 0){
        mac_tmp[k] = 48;
        mac_tmp[k+1] = macadd[i];
    }else{
        mac_tmp[k] = macadd[i];
        mac_tmp[k+1] = macadd[i+1];  
    }

    for(i=0; i< mac_size; i++){
        macadd[i] = mac_tmp[i];
    }
    //これないと最後文字化け
    macadd[mac_size] = '\0';
}