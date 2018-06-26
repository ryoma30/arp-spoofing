#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define IP_CHAR_LEN 15

// ARPソケットの作成
int create_arp_sock();

// インターフェース名からのIP,MACアドレスの取得
void set_if_info(int sock, char *if_name, char* if_ip, unsigned char* if_mac);

// ソケットアドレス
void set_sockaddr(struct sockaddr_ll *sll, char *if_name);

// ARPの設定
void set_arp_header(struct ether_arp *arpPacket, unsigned char *s_mac, char *s_ip, unsigned char *t_mac, char *t_ip, int op);

// ターゲットホストのMACアドレス取得
void get_t_mac(int arp_sock, struct ether_arp arpPacket, struct sockaddr_ll sll, int sll_size, char *t_ip, unsigned char *t_mac);

// 文字列をunsigned charのMACアドレスに変換
void char2mac(char* macadd, unsigned char* mac_str);

// MACアドレスの出力
void print_macaddr(unsigned char* macaddr);

// ARPスプーフィングの実行
void arp_spoofing(char *argv[]);