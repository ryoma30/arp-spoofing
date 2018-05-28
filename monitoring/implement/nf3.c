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

int insertIptables(unsigned char *mac_address)
{
        struct xtc_handle *h;
        const ipt_chainlabel chain = "FORWARD";
        const char * tablename = "filter";

        struct ipt_entry * e;
        struct ipt_entry_match * match_mac;
        struct xt_standard_target * target;
        struct xt_mac_info * macinfo;

        unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, size_mac_info, total_length;

        size_ipt_entry = XT_ALIGN(sizeof(struct ipt_entry));
        size_ipt_entry_match = XT_ALIGN(sizeof(struct ipt_entry_match));
        size_ipt_entry_target = XT_ALIGN(sizeof(struct xt_standard_target));
        size_mac_info = XT_ALIGN(sizeof(struct xt_mac_info));
        total_length =  size_ipt_entry + size_ipt_entry_match  + size_ipt_entry_target +  size_mac_info;


        //memory allocation for all structs that represent the netfilter rule we want to insert
        e = calloc(1, total_length);
        if(e == NULL)
        {
                printf("malloc failure");
                exit(1);
        }

        //offsets to the other bits:
        //target struct begining
        e->target_offset = size_ipt_entry + size_ipt_entry_match + size_mac_info;
        //next "e" struct, end of the current one
        e->next_offset = total_length;

        //set up packet matching rules: -s 156.145.1.3 -d 168.220.1.9 -i eth0 part
        //of our desirable rule
        e->ip.src.s_addr = inet_addr("156.145.1.3");
        e->ip.smsk.s_addr= inet_addr("255.255.255.255");
        //e->ip.dst.s_addr = inet_addr("168.220.1.9");
        //e->ip.dmsk.s_addr= inet_addr("255.255.255.255"); 


        //match structs setting:
        //-m mac --mac-source
        match_mac = (struct ipt_entry_match *) e->elems;
        match_mac->u.match_size = size_ipt_entry_match + size_mac_info;
        strcpy(match_mac->u.user.name, "mac");//set name of the module, we will use in this match

        //limit module - match extension
        //--limit 2000/s --limit-burst 10â part of our desirable rule
        macinfo = (struct xt_mac_info *)match_mac->data;
        memcpy(macinfo->srcaddr, source_mac, 6);
        // macinfo->srcaddr[0] = 0;
        // macinfo->srcaddr[1] = 0;
        // macinfo->srcaddr[2] = 0;
        // macinfo->srcaddr[3] = 0;
        // macinfo->srcaddr[4] = 0;
        // macinfo->srcaddr[5] = 0;


        target = (struct xt_standard_target *)(e->elems + size_ipt_entry_match  + size_mac_info);
        target->target.u.target_size = size_ipt_entry_target;
        strcpy(target->target.u.user.name, "DROP");

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
        printf("%s", target->target.data);
        int y = iptc_commit(h);
        if (!y)
        {
                printf("Error commit: %s\n", iptc_strerror(errno));
                exit(errno);
        }

        exit(0);

}