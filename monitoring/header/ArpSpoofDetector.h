#ifndef _Arp_Spoof_Detector_H_
#define _Arp_Spoof_Detector_H_

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <net/if.h>


#include "ArpPacketAnalysis.h"
#include "PacketAnalysis.h"
#include "QueryMappingDB.h"
#include "SendTrapIcmp.h"
#include "SendArp.h"
#include "PacketDuplication.h"
#include "InsertIptables.h"
//#include "PacketCap.h"

#define DPCP_RCV_MAXSIZE   68
#define DPCP_PROMSCS_MODE  1
#define DPCP_RCV_TIMEOUT   1000
#define DPCP_NOLIMIT_LOOP  -1
#define IP_CHAR_LEN 15
#define MAC_CHAR_LEN 17
#define IP_PROTOCOL_TCP 0x06

//arphdr_t *arpheader = NULL;

void start_pktfunc( u_char *,const struct pcap_pkthdr * ,const u_char *);

//MACアドレス手動設定用
void mac2char16(char *, char *);

// //ＩＰアドレス出力
// void print_ip(char* , unsigned char*);
// //MACアドレス出力
// void print_ethaddr(char*, unsigned char*);

#endif // _Arp_Spoof_Detector_H_