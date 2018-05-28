
/*
 *  sample program
 *  ping test program
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <errno.h>



int sequence;
pid_t pid;
struct in_addr addr;
unsigned short calc_checksum(int , void *);
int send_icmp_echo_request(int);
int recv_icmp_echo_reply(int, struct timeval*);