/**
 * パケットキャプチャ部分 
 **/

#include "../header/PacketCap.h"

int main(){
  pcap_t *pd = NULL;
  char ebuf[PCAP_ERRBUF_SIZE];

  if( (pd = pcap_open_live( "wlp2s0" ,             // インターフェイス名
                             DPCP_RCV_MAXSIZE ,  // 最大受信サイズ(最初の68byteまで受信する)
                             DPCP_PROMSCS_MODE , // 自分宛以外のパケットも処理の対象にする
                             DPCP_RCV_TIMEOUT ,  // タイムアウト時間(ミリ秒)
                             ebuf )) == NULL ){
    // error
    exit(-1);
  }

  if( pcap_loop( pd ,
                 DPCP_NOLIMIT_LOOP , // エラーが発生するまで取得を続ける
                 start_pktfunc,      // パケット受信した時のCallBack関数
                 NULL                   //  CallBack関数へ渡す引数
               ) < 0 ){
    // error
    exit(-1);
  }
  pcap_close(pd);
  return 0;
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

void start_pktfunc( u_char *user,                  // pcap_loop関数の第4引数
                    const struct pcap_pkthdr *h , // 受信したPacketの補足情報
                    const u_char *p               // 受信したpacketへのポインタ
                  ){
  // packet処理
    struct ip *ip;
    struct ether_header *ether_header;
    struct ether_arp *ether_arp;
    ip = (struct ip *)(p+14);
    ether_header = (struct ether_header *)p;
    ether_arp = (struct ether_arp *)(p+14);
    if(ntohs(ether_header->ether_type) == ETHERTYPE_ARP){

      char mac_str[6], mac_str2[6];
      mac2char16("ff:ff:ff:ff:ff:ff", mac_str); 
      mac2char16("00:00:00:00:00:00", mac_str2); 
     if((memcmp(ether_header->ether_dhost, mac_str, ETH_ALEN) != 0)  && (memcmp(ether_arp->arp_tha, mac_str2, ETH_ALEN) != 0)){
       // printf("broad \n");
        if(memcmp(ether_header->ether_shost, ether_arp->arp_sha, ETH_ALEN) != 0 ||
          memcmp(ether_header->ether_dhost, ether_arp->arp_tha, ETH_ALEN) != 0){
          printf("!!!!!!!!!!!!!!warning!!!!!!!!!!!!!!!!\n");
          printf("ether_header sender:");
          for(int i=0; i < ETH_ALEN - 1; i++){
            printf("%.2x:", ether_header->ether_shost[i]);
          }
          printf("%.2x\n", ether_header->ether_shost[ETH_ALEN-1]);
          printf("arp_header sender:");
          for(int i=0; i < ETH_ALEN - 1; i++){
            printf("%.2x:", ether_arp->arp_sha[i]);
          }
          printf("%.2x\n", ether_arp->arp_sha[ETH_ALEN-1]);
           printf("ether_header dest:");
          for(int i=0; i < ETH_ALEN - 1; i++){
            printf("%.2x:", ether_header->ether_dhost[i]);
          }
          printf("%.2x\n", ether_header->ether_dhost[ETH_ALEN-1]);
          printf("arp_header dest:");
          for(int i=0; i < ETH_ALEN - 1; i++){
            printf("%.2x:", ether_arp->arp_tha[i]);
          }
          printf("%.2x\n", ether_arp->arp_tha[ETH_ALEN-1]);
        }
      }
    }
    // printf("---------------------\n");
    // printf("ip_v = 0x%x\n", ip->ip_v);
    // printf("ip_hl = 0x%x\n", ip->ip_hl);
    // printf("ip_tos = 0x%.2x\n", ip->ip_tos);
    // printf("ip_len = %d bytes\n", ntohs(ip->ip_len));
    // printf("ip_id = 0x%.4x\n", ntohs(ip->ip_id));
    // printf("ip_off = 0x%.4x\n", ntohs(ip->ip_off));
    // printf("ip_ttl = 0x%.2x\n", ip->ip_ttl);
    // printf("ip_p = 0x%.2x\n", ip->ip_p);
    // printf("ip_sum = 0x%.4x\n", ntohs(ip->ip_sum));
    // printf("ip_src = %s\n", inet_ntoa(ip->ip_src));
    // printf("ip_dst = %s\n", inet_ntoa(ip->ip_dst));
    // printf("---------------------\n");
  //   printf("ether_shost = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", 
  //           ether_header->ether_shost[0], ether_header->ether_shost[1], ether_header->ether_shost[2],
  //           ether_header->ether_shost[3], ether_header->ether_shost[4], ether_header->ether_shost[5]);
  //  // printf("%04x\n", ntohs(ether_header->ether_type));
  //   if(ntohs(ether_header->ether_type) == ETHERTYPE_ARP){
  //     printf("ether_arp = %02x:%02x:%02x:%02x:%02x:%02x\n",
  //             ether_arp->arp_sha[0], ether_arp->arp_sha[1], ether_arp->arp_sha[2],
  //             ether_arp->arp_sha[3], ether_arp->arp_sha[4], ether_arp->arp_sha[5]);
  //   }

}