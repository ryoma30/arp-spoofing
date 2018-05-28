#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <linux/netfilter/xt_mac.h>
#include <libiptc/libiptc.h>


struct ipt_entry_match* get_mac_target()
{
    struct ipt_entry_match *match;
    struct xt_mac_info *m;

    size_t size;
    size = XT_ALIGN(sizeof(struct ipt_entry_match)) + XT_ALIGN(sizeof(struct xt_mac_info));

    match = calloc(1, size);
    //memset(match, 0, size);printf("a\n");
    match->u.match_size = size;             
    strncpy(match->u.user.name, "mac", sizeof(match->u.user.name));


    m = (struct xt_mac_info*)match->data;
    //memcpy(m->srcaddr, "ff:ff:ff:ff:ff:ff", 6);
    m->srcaddr[0] = 0xa1; 
    m->srcaddr[1] = 0xa1;
    m->srcaddr[2] = 0xa1;
    m->srcaddr[3] = 0xa1;
    m->srcaddr[4] = 0xa1;
    m->srcaddr[5] = 0xa1;
    //m->invert  
}

static struct ipt_entry* make_entry()
{
    struct ipt_entry *e;
    struct ipt_entry_match *match = get_mac_target();
    struct ipt_entry_target *target;

    e = calloc(1, sizeof(struct ipt_entry));
    target = calloc(1, sizeof(struct ipt_entry_target));
    //memset(target, 0, sizeof(struct ipt_entry_target));printf("a\n");

    target->u.user.target_size = XT_ALIGN (sizeof(struct ipt_entry_target));
    strncpy(target->u.user.name, "DROP", sizeof (target->u.user.name));

    e->target_offset = sizeof(struct ipt_entry);
    e->next_offset = e->target_offset + target->u.user.target_size + match->u.match_size;

    memcpy(e->elems, match, match->u.match_size);
    memcpy(e->elems + match->u.match_size, target->u.user.name, target->u.user.target_size);

    return e;
}

int main(){
    struct ipt_entry *entry;
    struct xtc_handle *h;
    const char *chain = "FORWARD";
    const char *table = "filter";
    int ret = 1;
    h = iptc_init(table);
    if (!h)
    {
      fprintf (stderr, "Could not init IPTC library: %s\n", iptc_strerror (errno));
      goto out;
    }
    //memset(entry, 0, sizeof(struct ipt_entry));
    entry = make_entry();   
    if (!iptc_append_entry (chain, (struct ipt_entry *) entry, h))
    {
      fprintf (stderr, "Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
      goto out;
    }

    if (!iptc_commit (h)) {
    fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n"
                    , table, iptc_strerror (errno));
        goto out;
    }

    ret = 0;
    out:
        if(entry)free(entry);
        if(h) iptc_free(h);

        return ret;

}



