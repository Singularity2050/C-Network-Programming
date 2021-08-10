#include <stdio.h>
#include <string.h>
#define __linux__
#ifndef __linux__
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "ip.h"

void dump_ip_header(struct ip *ip){
    char src_ip[1024];
    char dst_ip[1024];

    strcpy(src_ip,inet_ntoa(ip->ip_src));//hexadecimal to string
    strcpy(dst_ip,inet_ntoa(ip->ip_dst));//hexadecimal to string

    printf("[IP] %s->%s(ttl:%d,cksum: 0x%04x)\n",
           src_ip,dst_ip,ip->ip_ttl,ntohs(ip->ip_sum));

    //since inet_ntoa function allocate data statically, we do not have to make array to print it
    printf("[IP] %s->%s(ttl:%d,cksum: 0x%04x)\n",
           inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst),ip->ip_ttl,ntohs(ip->ip_sum));
}

