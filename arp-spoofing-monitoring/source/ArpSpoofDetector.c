/**
 * ARPスプーフィング検知 
 **/

#include "../header/ArpSpoofDetector.h"

int main(int argc, char* argv[]){

    //検知システムのIP,MAC(現状手動)
    char *dev_mac = "00:0c:29:8a:b3:48";
    char *dev_ip = "192.168.2.50";
    
    pcap_t *pd = NULL;              //パケットキャプチャディスクリプタ
    char ebuf[PCAP_ERRBUF_SIZE];    //エラーメッセージ用格納配列
    
  if (argc != 2) {
    printf("usage : %s IF\n", argv[0]);
    return 1;
  }
    //パケットキャプチャするデバイスのオープン
    if( (pd = pcap_open_live( argv[1] ,            // インターフェイス名
                             DPCP_RCV_MAXSIZE ,     // 最大受信サイズ(最初の68byteまで受信する)
                             DPCP_PROMSCS_MODE ,    // 自分宛以外のパケットも処理の対象にする
                             DPCP_RCV_TIMEOUT ,     // タイムアウト時間(ミリ秒)
                             ebuf )) == NULL ){
    // error
    exit(-1);
    }
    //パケットキャプチャループ
    char ip_address[IP_CHAR_LEN], mac_address[MAC_CHAR_LEN], mac_address_d[MAC_CHAR_LEN];
    while(1){
        if( pcap_loop(  pd ,
                        1, //DPCP_NOLIMIT_LOOP , // エラーが発生するまで取得を続ける
                        packetAnalysis,      // パケット受信した時のCallBack関数
                        NULL                //  CallBack関数へ渡す引数
                    ) < 0 ){

            exit(-1);
        }else{
            //ARPパケット受信時
            if(ntohs(ether_header->ether_type) == ETHERTYPE_ARP){ 
                
                //受信ARPパケットの送信元<IP, MAC>の検証
                memcpy(ip_address, inet_ntop(AF_INET, ether_arp->arp_spa, ip_address, IP_CHAR_LEN), IP_CHAR_LEN);
                memcpy(mac_address, (ether_ntoa((struct ether_addr *)ether_arp->arp_sha)), MAC_CHAR_LEN);
                memcpy(mac_address_d, (ether_ntoa((struct ether_addr *)ether_header->ether_dhost)), MAC_CHAR_LEN);
                
                //MACアドレスの再構築
                macReshape(mac_address, MAC_CHAR_LEN);               
                macReshape(mac_address_d, MAC_CHAR_LEN);

                //自分以外のARPパケットについて
                if(memcmp(mac_address, dev_mac, MAC_CHAR_LEN) != 0){

                    //イーサネットフレーム,ARPパケットのMACアドレスの比較
                    arpPacketAnalysis();    
                    //マッピングDBへのクエリ
                    queryMappingDB(ip_address, mac_address);
                    switch(ip_mac){
                        case IP_MAC_T:
                            break;
                        case IP_T:
                            if(sendTrapIcmp(argv[1], dev_mac, mac_address, dev_ip, ip_address) > 0){
                                setNewEntry(ip_address, mac_address);
                            }else{
                                if(memcmp(spoof[0].attacker_mac, mac_address, MAC_CHAR_LEN) != 0 && memcmp(spoof[1].attacker_mac, mac_address, MAC_CHAR_LEN) !=0/*
                                    memcmp(spoof[0].target_ip, ip_address, IP_CHAR_LEN) != 0*/){
                                //printf("send arp\n");
                                if(strlen(spoof[0].target_mac)== 0){
                                char unti1[MAC_CHAR_LEN], unti2[IP_CHAR_LEN];
                                getPairValue(unti1, "mac_address", "ip_address", ip_address);
                                getPairValue(unti2, "ip_address", "mac_address", mac_address_d);
                                //printf("%s %s\n",unti1, unti2);
                                //sendArp(argv[1],unti1 , mac_address_d, ip_address, unti2);
                                memcpy(spoof[0].attacker_mac, mac_address, MAC_CHAR_LEN);
                                memcpy(spoof[0].victim_mac, mac_address_d, MAC_CHAR_LEN);  
                                memcpy(spoof[0].target_mac, unti1, MAC_CHAR_LEN); 
                                memcpy(spoof[0].target_ip, ip_address, IP_CHAR_LEN);  
                                printf("-----------------------------------------------------------------------\n");
                                printf("攻撃者 MAC : %s \n", spoof[0].attacker_mac);
                                printf("偽装先 IP  : %s \n", spoof[0].target_ip);                             
                                printf("偽装先 MAC : %s \n", spoof[0].target_mac);  
                                printf("%s が <%s, %s>を装っています\n", spoof[0].attacker_mac, spoof[0].target_ip, spoof[0].target_mac);
                                printf("-----------------------------------------------------------------------\n");
                                insertIptables(ip_address, ether_arp->arp_sha);
                                // printf("attacker    : %s \n", spoof.attacker_mac);
                                // printf("victim      : %s \n", spoof.victim_mac);
                                // printf("target mac  : %s \n", spoof.target_mac);
                                // printf("target ip   : %s \n", spoof.target_ip);                                
                                // printf("type        : %d \n", spoof.attacker_type);
                                // printf("target : %s \n", target_mac);
                                }
                                    /*else{
                                                                        char unti1[MAC_CHAR_LEN], unti2[IP_CHAR_LEN];
                                getPairValue(unti1, "mac_address", "ip_address", ip_address);
                                getPairValue(unti2, "ip_address", "mac_address", mac_address_d);
                                //printf("%s %s\n",unti1, unti2);
                                //sendArp(argv[1],unti1 , mac_address_d, ip_address, unti2);
                                memcpy(spoof[1].attacker_mac, mac_address, MAC_CHAR_LEN);
                                memcpy(spoof[1].victim_mac, mac_address_d, MAC_CHAR_LEN);  
                                memcpy(spoof[1].target_mac, unti1, MAC_CHAR_LEN); 
                                memcpy(spoof[1].target_ip, ip_address, IP_CHAR_LEN);  
                                printf("-----------------------------------------------------------------------\n");
                                printf("攻撃者 MAC2 : %s \n", spoof[1].attacker_mac);
                                printf("偽装先 IP2  : %s \n", spoof[1].target_ip);                             
                                printf("偽装先 MAC2 : %s \n", spoof[1].target_mac);  
                                printf("%s が <%s, %s>を装っています\n", spoof[1].attacker_mac, spoof[1].target_ip, spoof[1].target_mac);
                                printf("-----------------------------------------------------------------------\n");
                                insertIptables(ip_address, ether_arp->arp_sha);
                                    }*/
                            }
                            }
                            break;
                        case MAC_T:
                            if(sendTrapIcmp(argv[1], dev_mac, mac_address, dev_ip, ip_address) > 0){
                                setNewEntry(ip_address, mac_address);
                            }else{

                            }
                            break;
                        case IP_MAC_F:
                            if(sendTrapIcmp(argv[1], dev_mac, mac_address, dev_ip, ip_address) > 0){
                                setNewEntry(ip_address, mac_address);
                            }else{

                            }
                            break;                                                                

                        default: break;
                    }
                }
            }else if(/*ip->ip_p == 17 && */ntohs(ether_header->ether_type) == ETHERTYPE_IP /*&& spoof.attacker_type == 0*//*ntohs(ether_header->ether_type) == ETHERTYPE_IP*/){
                /*
                被害者->攻撃者のパケットを複製
                被害者->正規のパケットを作成
                */
                //printf("IP\n");
                //memcpy(ip_address, inet_ntop(AF_INET, ether_arp->arp_spa, ip_address, IP_CHAR_LEN), IP_CHAR_LEN);
                memcpy(ip_address, inet_ntoa(ip->ip_dst), IP_CHAR_LEN);
                memcpy(mac_address, (ether_ntoa((struct ether_addr *)ether_header->ether_dhost)), MAC_CHAR_LEN);
                macReshape(mac_address, MAC_CHAR_LEN);  
                  
                if(memcmp(spoof[0].attacker_mac, mac_address, MAC_CHAR_LEN) == 0 && memcmp(spoof[0].target_ip, ip_address, IP_CHAR_LEN) == 0){
                printf("<%s, %s>\n", ip_address, mac_address);


                                    
                //printf("attacker\n");
                    // printf("%s\n"
                    //         "%s\n"
                    //         "%s\n"
                    //         , spoof.victim_mac, mac_address, ip_address);
                    //if(memcmp(mac_address ,"00:0c:29:87:eb:9c", MAC_CHAR_LEN) == 0){
                        //printf("IPなう\n");
                        packetDuplication(packet, packet_len, argv[1], dev_mac, dev_ip,
                                        spoof[0].target_mac, mac_address, 
                                        ip_address, ip_address);
                    //}
                }/*else if(memcmp(spoof[1].attacker_mac, mac_address, MAC_CHAR_LEN) == 0 && memcmp(spoof[1].target_ip, ip_address, IP_CHAR_LEN) == 0){
 packetDuplication(packet, packet_len, argv[1], dev_mac, dev_ip,
                                        spoof[1].target_mac, mac_address, 
                                        ip_address, ip_address);
                }*/
                /*
                攻撃者->被害者
                正規->被害者
                ２つが一定時間ないにきたら
                攻撃者からのパケットを止める処理
                */
                //以下、TCPを確立させるための処理
             



                

            }
        }
    }

    pcap_close(pd);

    printf("close\n");
    return 0;
}