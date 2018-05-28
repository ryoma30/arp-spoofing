#ifndef _Send_Arp_H_
#define _Send_Arp_H_
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

#include "PacketAnalysis.h"

//void mac2char16(char *, char *);
int sendArp(char *ifname, char* smac, char* dmac, char* sip, char* dip);

#endif //_Send_Arp_H_