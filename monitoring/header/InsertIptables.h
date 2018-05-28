#ifndef _Insert_Iptables_H_
#define _Insert_Iptables_H_
/*
 * code to insert :-
 * iptables -A INPUT -s 156.145.1.3 -d 168.220.1.9 -i eth0 -p tcp --sport 0:80 --dport 0:51201 -m limit --limit 2000/s --limit-burst 10 -m physdev-in eth0 -j ACCEPT
 */

#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_mac.h>
#include <netinet/if_ether.h>
//#include "linux/netfilter/xt_limit.h"
//#include "linux/netfilter/xt_physdev.h"
#include <netinet/in.h>

int insertIptables(char *,unsigned char *);

#endif //_Insert_Iptables_H_