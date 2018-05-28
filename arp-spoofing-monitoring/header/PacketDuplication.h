#ifndef _Packet_Duplication_H_
#define _Packet_Duplication_H_


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

#include "SendTrapIcmp.h"
//チェックサムの計算

//イーサヘッダの作成
void setEthHeader2(struct ether_header*, char*, char*);


//IPヘッダの作成
void setIpHeader2(const char*, const char*, struct iphdr*, int );


int packetDuplication(char *, int, char *, char *, char *, char *,char *, char *, char *);

#endif //_Packet_Duplication_h_