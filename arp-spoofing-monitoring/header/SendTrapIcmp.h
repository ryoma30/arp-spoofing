#ifndef _Send_Trap_Icmp_H_
#define _Send_Trap_Icmp_H_


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>

#include "PacketAnalysis.h"
#include "ArpPacketAnalysis.h"
//MACアドレス手動設定用
void mac2char16(char *, char *);

/*
 * チェックサムを計算する関数です。
 * ICMPヘッダのチェックサムフィールドを埋めるために利用します。
 * IPヘッダなどでも全く同じ計算を利用するので、
 * IPヘッダのチェックサム計算用としても利用できます。
 */

//チェックサムの計算
ushort getCheckSum(ushort*, int);

//イーサヘッダの作成
void setEthHeader(struct ether_header*, char*, char*);

//icmpヘッダの作成
void setIcmpHeader(struct icmphdr*, int, int);

//IPヘッダの作成
void setIpHeader(const char*, const char*, struct iphdr*);

int sendTrapIcmp(char *, char*, char*, char*, char*);

struct SPOOF
{
    char attacker_mac[18];
    char victim_mac[18];
    int attacker_type;
    char target_mac[18];
    char target_ip[15];
};

struct SPOOF spoof[2];
int id_num;
unsigned short seq_num;




#endif //_Send_Trap_Icmp_H_