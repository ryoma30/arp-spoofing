#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/netfilter/xt_mac.h>
#include <libiptc/libiptc.h>
 
static int
insert_rule (const char *table,
             const char *chain, 
             unsigned int src,
             int inverted_src,
             unsigned int dest,
             int inverted_dst,
             const char *target)
{
  struct
    {
      struct ipt_entry entry;
      struct xt_standard_target target;
      struct xt_entry_match match;
      struct xt_mac_info *m;
    } entry;
  struct xtc_handle *h;
  struct xt_mac_info *m;
  int ret = 1;
 
  h = iptc_init (table);
  if (!h)
    {
      fprintf (stderr, "Could not init IPTC library: %s\n", iptc_strerror (errno));
      goto out;
    }
 
  memset (&entry, 0, sizeof (entry));
  printf("debug\n");
  /* target */
  entry.target.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
  entry.match.u.user.match_size = XT_ALIGN (sizeof (struct xt_entry_match) /*+ sizeof(struct xt_mac_info)*/);
  strncpy (entry.target.target.u.user.name, "DROP", sizeof (entry.target.target.u.user.name));
  strncpy (entry.match.u.user.name, "mac-source", sizeof (entry.match.u.user.name));
  entry.m = (struct xt_mac_info *)entry.match.data;  
  entry.m->srcaddr[0] = 0x11;
  entry.m->srcaddr[1] = 0x12;
  entry.m->srcaddr[2] = 0x11;
  entry.m->srcaddr[3] = 0x11;
  entry.m->srcaddr[4] = 0x11;
  entry.m->srcaddr[5] = 0x11;
  //entry.match.data = entry.m;
  //memset(entry.m->srcaddr, 0, sizeof(char)*ETH_ALEN); 
  //entry.m->invert = 1;  printf("debug\n");
  //entry.target.mac
  /* entry */
  entry.entry.target_offset = sizeof (struct ipt_entry);
  entry.entry.next_offset = entry.entry.target_offset + entry.target.target.u.user.target_size; + entry.match.u.user.match_size;
  
  if (src)
    {
      entry.entry.ip.src.s_addr  = src;
      entry.entry.ip.smsk.s_addr = 0xFFFFFFFF;
      if (inverted_src)
        entry.entry.ip.invflags |= IPT_INV_SRCIP;
    }
 
  // if (dest)
  //   {
  //     entry.entry.ip.dst.s_addr  = dest;
  //     entry.entry.ip.dmsk.s_addr = 0xFFFFFFFF;
  //     if (inverted_dst)
  //       entry.entry.ip.invflags |= IPT_INV_DSTIP;
  //   }
   // memcpy(entry.entry.elems,  "-m --mac-source 00:0c:29:8a:b3:48", 35);
 
  if (!iptc_append_entry (chain, (struct ipt_entry *) &entry, h))
    {
      fprintf (stderr, "Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
      goto out;
    }
 dump_entries(h);
  if (!iptc_commit (h))
    {
      fprintf (stderr, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
      goto out;
    }
   
  ret = 0;
out:
  if (h)
    iptc_free (h);


  return ret;
}
 
int main (int argc, char **argv)
{
  unsigned int a, b;
 
  inet_pton (AF_INET, "1.2.3.4", &a);
  inet_pton (AF_INET, "4.3.2.1", &b);
 
  insert_rule ("filter",
               "FORWARD",
               a,
               0,
               b,
               1,
               "DROP");
  return 0;
}