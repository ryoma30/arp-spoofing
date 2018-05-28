#include "../header/ArpPacketAnalysis.h"

int warn_count=0;
void arpPacketAnalysis(){
                char mac_str[6], mac_str2[6];
                mac2char16("ff:ff:ff:ff:ff:ff", mac_str); 
                mac2char16("00:00:00:00:00:00", mac_str2); 

                if((memcmp(ether_header->ether_dhost, mac_str, ETH_ALEN) != 0)  && (memcmp(ether_arp->arp_tha, mac_str2, ETH_ALEN) != 0)){
                    if(memcmp(ether_header->ether_shost, ether_arp->arp_sha, ETH_ALEN) != 0 ||
                        memcmp(ether_header->ether_dhost, ether_arp->arp_tha, ETH_ALEN) != 0){
                            warn_count++;
                            printf("------------------[ %d ][warn]------------------\n", warn_count);
                            print_analysis(ether_header->ether_shost, "ether_header sender", ETH_ALEN);
                            print_analysis(ether_header->ether_dhost, "ether_header   dest", ETH_ALEN);
                            print_analysis(ether_arp->arp_sha,        "arp_header   sender", ETH_ALEN);
                            print_analysis(ether_arp->arp_tha,        "arp_header     dest", ETH_ALEN);
                            printf("------------------------------------------------\n");
                        }
                }
}

void print_analysis(u_int8_t *pct, char *mac, int size_m){
    printf("%s -> ", mac);
    for(int i=0; i < size_m - 1; i++){
    printf("%.2x:", pct[i]);
    }
    printf("%.2x\n", pct[size_m-1]);
}

void ip2char(u_int8_t *pct, int size_m, char *cast_char){
    char *cast_tmp;
    for(int i=0; i < size_m; i++){
        cast_tmp[i] = (char)((int)(pct[i]));
        //printf("%s.", cast_tmp[i]);
    }
    printf("%s.", cast_tmp);
    //for(int i=0; i<size_m-1; i++){
       // strcat(cast_char, (char *)(cast_tmp[i]));
       cast_char = (char *)(cast_tmp);
    //}
    //cast_char = cast_tmp;
    printf("ip-> %s\n", cast_char);
    //printf("%.2x\n", pct[size_m-1]);
    
}

void print_ip(char* name, unsigned char* ipaddr) {
   printf("%s : %3d.%3d.%3d.%3d\n",name,ipaddr[0],ipaddr[1],ipaddr[2],ipaddr[3]);
}

void print_ethaddr(char* name, unsigned char* ethaddr) {
   printf("%s : %02x:%02x:%02x:%02x:%02x:%02x\n",name,ethaddr[0],ethaddr[1],ethaddr[2],ethaddr[3],ethaddr[4],ethaddr[5]);
}