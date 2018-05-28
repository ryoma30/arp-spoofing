#ifndef _Packet_Cap_H_
#define _Packet_Cap_H_

#include <pcap.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <string.h>

//#include "PacketAnalysis.h"

#define DPCP_RCV_MAXSIZE   68
#define DPCP_PROMSCS_MODE  1
#define DPCP_RCV_TIMEOUT   1000
#define DPCP_NOLIMIT_LOOP  -1


//arphdr_t *arpheader = NULL;

void start_pktfunc( u_char *,const struct pcap_pkthdr * ,const u_char *);

//MACアドレス手動設定用
void mac2char16(char *, char *);

#endif //_Packet_Cap_H_