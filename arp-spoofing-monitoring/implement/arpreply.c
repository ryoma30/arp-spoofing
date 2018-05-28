/**
 * ARPパケット作成用
 * */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

void mac2char16(char *, char *);

// int count_mac = 1;
// char *cmac = "";
int main(int argc, char *argv[])
{

    int arp_sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (arp_sock < 0)
    {
        perror("create arp sock");
        printf("errno: %d\n", errno);
        return 1;
    }

    /* 送信設定
     * 送信元のIFにargv[1]指定->MACアドレスがetherパケットに設定
     * 送信先はブロードキャスト
     */
    struct sockaddr_ll sockaddr;
    memset(&sockaddr, 0x0, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_ARP);
    sockaddr.sll_ifindex = if_nametoindex(argv[1]);
    sockaddr.sll_halen = 6;
    // memset(&sockaddr.sll_addr, 0xff, 6);

    /* MACアドレス取得
     * arpパケットに設定するための情報
     */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], 6);

    //char mac[6];
    //mac2char16("00:90:fe:ab:da:0d", mac); //arp送信元mac
    //strncpy(ifr.ifr_hwaddr, mac, 6);

    if (ioctl(arp_sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("get mac adder");
        printf("errno: %d\n", errno);
        return 1;
    }

    /* 
     * 送信元MACアドレス: argv[1]のMACアドレス
     * 送信元IPアドレス : argv[3]
     * 宛先IPアドレス   : argv[2]
     * ターゲットMACアドレスは未設定
     */
    //arpパケットの設定
    struct ether_arp arpPacket;
    memset(&arpPacket, 0x0, sizeof(arpPacket));
    arpPacket.arp_hrd = htons(1);
    arpPacket.arp_pro = htons(ETHERTYPE_IP);
    arpPacket.arp_hln = 6;
    arpPacket.arp_pln = 4;
    arpPacket.arp_op = htons(ARPOP_REPLY);

    //手動MACアドレス
    char mac_str[6], mac_str2[6], mac_str3[6];
    mac2char16("00:0c:29:87:eb:9c", mac_str);  //arp送信元mac
    mac2char16("00:00:00:00:00:00", mac_str2); //arp宛先mac
    mac2char16("00:0c:29:8a:b3:48", mac_str3); //Ether宛先mac

    memcpy(sockaddr.sll_addr, mac_str3, 6); //Etherヘッダ宛先MAC

    memcpy(arpPacket.arp_sha, mac_str /*ifr.ifr_hwaddr.sa_data*/, 6); //送信元MAC
    memcpy(arpPacket.arp_tha, mac_str2, 6);                           //宛先MAC
    inet_aton(argv[3], (struct in_addr *)&arpPacket.arp_spa);         //送信元IP
    //*cmac = (char)count_mac;
    //strcat(argv[2], cmac);
    inet_aton(argv[2], (struct in_addr *)&arpPacket.arp_tpa); //宛先IP
    //count_mac++;
    //if(count_mac == 254)count_mac = 0;

    while (1)
    {
        sleep(3);
        if (sendto(arp_sock, (char *)&arpPacket, sizeof(arpPacket),
                   0, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
        {
            perror("sendto");
            printf("errno: %d\n", errno);
            return 1;
        }
    }

    return 0;
}

void mac2char16(char *macadd, char *mac_str)
{
    char *mac = macadd;
    //char mac_str[6];
    char temp[3];
    int i;
    for (i = 0; i < 6; i++)
    {
        temp[0] = mac[i * 3 + 0];
        temp[1] = mac[i * 3 + 1];
        temp[2] = 0x00;
        mac_str[i] = strtol(temp, NULL, 16);
        //printf("mac_str[%d] = %d\n", i, mac_str[i]);
    }
}