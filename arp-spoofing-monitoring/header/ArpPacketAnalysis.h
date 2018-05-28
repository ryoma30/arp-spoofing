#ifndef _Arp_Packet_Analysis_H_
#define _Arp_Packet_Analysis_H_


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

#include "PacketAnalysis.h"

int arp_sock;

char buf[256];
void arpPacketAnalysis();

void ip2char(u_int8_t *, int, char *);

//ＩＰアドレス出力
void print_ip(char* , unsigned char*);
//MACアドレス出力
void print_ethaddr(char*, unsigned char*);

void print_analysis(u_int8_t *, char *, int);

#endif //_Arp_Packet_Analysis_H_