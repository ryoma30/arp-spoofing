/*
 * code to insert :-
 * iptables -A INPUT -s 156.145.1.3 -d 168.220.1.9 -i eth0 -p tcp --sport 0:80 --dport 0:51201 -m limit --limit 2000/s --limit-burst 10 -m physdev-in eth0 -j ACCEPT
 */

#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <libiptc/libiptc.h>
#include "linux/netfilter/xt_limit.h"
#include "linux/netfilter/xt_physdev.h"
#include <netinet/in.h>

int main(void)
{
        struct xtc_handle *h;
        const ipt_chainlabel chain = "INPUT";
        const char * tablename = "filter";

        struct ipt_entry * e;
        struct ipt_entry_match * match_proto, * match_limit, * match_physdev;
        struct xt_standard_target * target;
        struct ipt_tcp * tcpinfo;
        struct xt_rateinfo * rateinfo;
        struct xt_physdev_info * physdevinfo;
        unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, size_ipt_tcp, size_rateinfo, size_physdevinfo, total_length;

        size_ipt_entry = XT_ALIGN(sizeof(struct ipt_entry));
        size_ipt_entry_match = XT_ALIGN(sizeof(struct ipt_entry_match));
        size_ipt_entry_target = XT_ALIGN(sizeof(struct xt_standard_target));
        size_ipt_tcp = XT_ALIGN(sizeof(struct ipt_tcp));
        size_rateinfo = XT_ALIGN(sizeof(struct xt_rateinfo));
        size_physdevinfo = XT_ALIGN(sizeof(struct xt_physdev_info));
        total_length =  size_ipt_entry + size_ipt_entry_match * 3 + size_ipt_entry_target + size_ipt_tcp + size_rateinfo + size_physdevinfo;


        //memory allocation for all structs that represent the netfilter rule we want to insert
        e = calloc(1, total_length);
        if(e == NULL)
        {
                printf("malloc failure");
                exit(1);
        }

        //offsets to the other bits:
        //target struct begining
        e->target_offset = size_ipt_entry + size_ipt_entry_match * 3 + size_ipt_tcp + size_rateinfo + size_physdevinfo;
        //next "e" struct, end of the current one
        e->next_offset = total_length;

        //set up packet matching rules: -s 156.145.1.3 -d 168.220.1.9 -i eth0 part
        //of our desirable rule
        e->ip.src.s_addr = inet_addr("156.145.1.3");
        e->ip.smsk.s_addr= inet_addr("255.255.255.255");
        e->ip.dst.s_addr = inet_addr("168.220.1.9");
        e->ip.dmsk.s_addr= inet_addr("255.255.255.255"); 
        e->ip.invflags |= IPT_INV_SRCIP;
        e->ip.proto = IPPROTO_TCP;
        e->nfcache = 0;
        strcpy(e->ip.iniface, "eth0");

        //match structs setting:
        //set match rule for the protocol to use
        //-p tcp part of our desirable rule
        match_proto = (struct ipt_entry_match *) e->elems;
        match_proto->u.match_size = size_ipt_entry_match + size_ipt_tcp;
        strcpy(match_proto->u.user.name, "tcp");//set name of the module, we will use in this match

        //set match rule for the packet number per time limitation - against DoS attacks
        //-m limit part of our desirable rule
        match_limit = (struct ipt_entry_match *) (e->elems + match_proto->u.match_size);
        match_limit->u.match_size = size_ipt_entry_match + size_rateinfo;
        strcpy(match_limit->u.user.name, "limit");//set name of the module, we will use in this match

        //set match rule for specific Ethernet card (interface)
        //-m physdev part of our desirable rule
        match_physdev = (struct ipt_entry_match *) (e->elems + match_proto->u.match_size + match_limit->u.match_size);
        match_physdev->u.match_size = size_ipt_entry_match + size_physdevinfo;
        strcpy(match_physdev->u.user.name, "physdev");//set name of the module, we will use in this match

        //tcp module - match extension
        //--sport 0:80 --dport 0:51201 part of our desirable rule
        tcpinfo = (struct ipt_tcp *)match_proto->data;
        tcpinfo->spts[0] = ntohs(0);
        tcpinfo->spts[1] = ntohs(0x5000);
        tcpinfo->dpts[0] = ntohs(0);
        tcpinfo->dpts[1] = ntohs(0x1C8);


        //limit module - match extension
        //--limit 2000/s --limit-burst 10â part of our desirable rule
        rateinfo = (struct xt_rateinfo *)match_limit->data;
        rateinfo->avg = 5;
        rateinfo->burst = 10;

        //physdev module - match extension
        //-in eth0 part of our desirable rule
        physdevinfo = (struct xt_physdev_info *)match_physdev->data;
        strcpy(physdevinfo->physindev, "eth0");
        memset(physdevinfo->in_mask, 0xFF, IFNAMSIZ);
        physdevinfo->bitmask = 1;

        target = (struct xt_standard_target *)(e->elems + size_ipt_entry_match * 3 + size_ipt_tcp + size_rateinfo + size_physdevinfo);
        target->target.u.target_size = size_ipt_entry_target;
        strcpy(target->target.u.user.name, "ACCEPT");

        h = iptc_init(tablename);
        if ( !h )
        {
                printf("Error initializing: %s\n", iptc_strerror(errno));
                exit(errno);
        }

        int x = iptc_append_entry(chain, e, h);
        if (!x)
        {
                printf("Error append_entry: %s\n", iptc_strerror(errno));
                exit(errno);
        }
        printf("%s\n", target->target.data);
        int y = iptc_commit(h);
        if (!y)
        {
                printf("Error commit: %s\n", iptc_strerror(errno));
                exit(errno);
        }

        exit(0);

}