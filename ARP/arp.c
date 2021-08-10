#include <stdio.h>
#include <string.h>

#define __linux__
#ifndef __linux__
    #include <winsock2.h>
#else
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

#include "arp.h"

void dump_arp_header(struct ether_arp *arp)
{
    char src_ip[1024],dst_ip[1024];

    unsigned char *s = arp->arp_sha; //sender hardware address
    unsigned char *t = arp->arp_tha; //target hardware address

    struct in_addr ina_src_ip, ina_dst_ip;
    //sender IP
    memcpy(&(ina_src_ip.s_addr), arp->arp_spa,4); // to change hexadecimal to string
    sprintf(src_ip, "%s", inet_ntoa(ina_src_ip)); // Hexadecimal to string
    //target IP
    memcpy(&(ina_dst_ip.s_addr),arp->arp_tpa,4); // to change hexadecimal to string
    sprintf(dst_ip,"%s",inet_ntoa(ina_dst_ip)); // Hexadecimal to string

    printf("[ARP][OP:%d][%02x:%02x:%02x:%02x:%02x:%02x->"
           "%02x:%02x:%02x:%02x:%02x:%02x][%s->%s]\n",
           ntohs(arp->arp_op),// ARP Request or ARP Reply
           s[0],s[1],s[2],s[3],s[4],s[5], //sender hardware address
           t[0],t[1],t[2],t[3],t[4],t[5], //target hardware address
           src_ip, dst_ip);//sender and target IP
}
