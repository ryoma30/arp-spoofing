#ifndef _Packet_Analysis_H_
#define _Packet_Analysis_H_

#include <stdio.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <pcap.h>

char *packet;
int packet_len;
struct ip *ip;
struct ether_header *ether_header;
struct ether_arp *ether_arp;
void packetAnalysis();

//MACアドレス手動設定用
void mac2char16(char *, char *);
//先頭の0が省略されたMACアドレスの再構築
void macReshape(char *, int);

#endif //_Packet_Analysis_H_