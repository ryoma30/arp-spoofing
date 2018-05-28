#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <linux/netfilter/xt_mac.h>
#include <libiptc/libiptc.h>

// function to create Mark based match 
    struct ipt_entry_match* get_mac_target() {

        struct ipt_entry_match *match;
        struct xt_mac_info *m;
        size_t size;
        size =   XT_ALIGN(sizeof(struct ipt_entry_match))
            + XT_ALIGN(sizeof(struct xt_mac_info));

        match = calloc(1, size);
        match->u.user.match_size = size;
        strncpy(match->u.user.name, "mac", sizeof(match->u.user.name));
        m = (struct xt_mac_info*)match->data;

       // memset(m->srcaddr , 000000, 6);
       //memset(m->srcaddr, 1, sizeof(char)*ETH_ALEN);
        //m->srcaddr = {0x00, 0x0d, 0x3f, 0xcd, 0x02, 0x5f};
        m->invert = 1;
        m->srcaddr[0] = 0x00;
        m->srcaddr[1] = 0x00;
        m->srcaddr[2] = 0x00;
        m->srcaddr[3] = 0x00;
        m->srcaddr[4] = 0x00;
        m->srcaddr[5] = 0x00;
        // memset(m->srcaddr[0] , 0x00, 1);
        // memset(m->srcaddr[1] , 0x00, 1);
        // memset(m->srcaddr[2] , 0x0d, 1);
        // memset(m->srcaddr[3] , 0x3f, 1);
        // memset(m->srcaddr[4] , 0xcd, 1);       
        // memset(m->srcaddr[5] , 0x02, 1);
         return match;
    }

//function : to create final ipt_enrty  


  static struct ipt_entry*
    make_entry(const char * saddr)
    {
   int r = 0;
    struct ipt_entry * e;
    struct ipt_entry_match *match = get_mac_target();
    struct xt_mac_info *m = NULL;
    struct ipt_entry_target *target = NULL;

    e = calloc(1, sizeof(struct ipt_entry));
    target = calloc(1, sizeof(struct ipt_entry_target));
    //m = calloc(1, sizeof(*m));
    //m->mark = 0xff;
    //e->ip.proto = IPPROTO_IP;
    //e->nfcache = NFC_IP_DST_PT;
    //if () {
        //e->ip.src.s_addr = inet_addr(saddr);
        unsigned int a, b;
         inet_pton(AF_INET, "1.2.3.4", &a);
        e->ip.src.s_addr = a;
        e->ip.smsk.s_addr = INADDR_NONE;
inet_pton(AF_INET, "1.4.3.4", &b);
        e->ip.dst.s_addr  = b;
        e->ip.dmsk.s_addr = 0xFFFFFFFF;
        e->ip.invflags |= IPT_INV_DSTIP;
        //e->ip.invflags |= IPT_INV_SRCIP;
        //e->ip.smsk.s_addr = INADDR_NONE;
        //printf("\n SNAT");
        target->u.user.target_size = XT_ALIGN (sizeof (struct ipt_entry_target));
        
        strncpy (target->u.user.name, "DROP", sizeof(target->u.user.name));

            e->target_offset = sizeof(struct ipt_entry)
        + match->u.match_size;
    e->next_offset = sizeof(struct ipt_entry)
        + match->u.match_size + target->u.user.target_size;
      //  target = get_snat_target(iaddr, 0);
   // } else {
       // printf("\n DNAT");
        //e->ip.dst.s_addr = inet_addr(rhost);
      //  e->ip.dmsk.s_addr = INADDR_NONE;
      //  target = get_dnat_target(iaddr, 0);
    //}
    //match->u.user.revision = 1;
    //e->nfcache |= NFC_UNKNOWN;
    // e = realloc(e, sizeof(struct ipt_entry)
    //         + match->u.match_size + target->u.target_size);
    // memcpy(e->elems, match, match->u.match_size);
    // memcpy(e->elems + match->u.match_size, target, target->u.target_size);
    // e->target_offset = sizeof(struct ipt_entry)
    //     + match->u.match_size;
    // e->next_offset = sizeof(struct ipt_entry)
    //     + match->u.match_size + target->u.target_size;

// #if 0
//     e = realloc(e, sizeof(struct ipt_entry) + sizeof(*m));
//     //+ target->u.target_size);
//     //memcpy(e->elems , target, target->u.target_size);
//     memcpy(e->elems , m, sizeof(*m));
//     e->target_offset = sizeof(struct ipt_entry);
//     e->next_offset = sizeof(struct ipt_entry) + sizeof(*m);
// #endif
    //free(target);
    //free(m);
    return e;
    }


int
     main(int argc, char **argv)
    {
        struct ipt_entry *entry;
        struct xtc_handle *h;
        int ret = 1;
        const char *chain = "FORWARD",  *table = "filter";
        char *match_mask;

        h = iptc_init (table);
        if (!h) {
            fprintf (stderr, "Could not init IPTC library: %s\n", iptc_strerror (errno));
            goto out;
        }

        entry = make_entry("1.1.2.1");
        //if (op) {
            if (!iptc_append_entry (chain, (struct ipt_entry *) entry, h)) {
                fprintf (stderr, "Could not insert a rule in iptables (table %s): "
                                 "%s\n", table, iptc_strerror (errno));
                goto out;
            }
        // } else {
        //     match_mask = (unsigned char *)malloc(entry->next_offset);
        //     memset(match_mask, 0xFF, entry->next_offset);

        //     if (!iptc_delete_entry (chain, (struct ipt_entry *) entry,
        //                                     match_mask, h)) {
        //         fprintf (stderr, "Could not delete a rule in iptables (table %s): "
        //                          "%s\n", table, iptc_strerror (errno));
        //         goto out;
        //     }
        // }
    dump_entries(h);
        if (!iptc_commit (h)) {
            fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n"
                            , table, iptc_strerror (errno));
            goto out;
        }

        ret = 0;
    out:
        if (entry) free(entry);
        if (h) iptc_free (h);

        return ret;
    }