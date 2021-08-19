#include <stdio.h>
#include <string.h>

#define __linux__
#ifndef __linux__
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "../Ethernet/ethernet.h"
#include "../ARP/arp.h"
#include "../IP/ip.h"
#include "../TCP/tcp.h"
#include "../UDP/udp.h"
#include "../ICMP/icmp.h"

#include "pcap.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    //    struct pcap_pkthr {
    //        struct timeval ts; //time stamp
    //        bpf_u_int32 caplen; //length of portion present
    //        bpf_u_int32 len; // length this packet(off wire)
    //    };
    unsigned char *buffer = (unsigned char *)pkt_data;// data
    void *header_ptr = buffer + sizeof(struct ether_header);
    struct ether_header *ether_header = (struct ether_header *)buffer; // first protocol is ethernet
    struct ip *ip;
    void *next_header_ptr;
    printf("------------------------------------------------------------------------\n");

    dump_ether_header(ether_header);

    switch(ntohs(ether_header->ether_type)){
        case ETHERTYPE_ARP:
        {
            dump_arp_header((struct ether_arp *) header_ptr); //second protocol
            break;
        }
        case ETHERTYPE_IP:
        {
            dump_ip_header((struct ip*)header_ptr);//second protocol

            ip = (struct ip *)header_ptr;
            next_header_ptr = ((char*)ip) + (ip->ip_hl <<2); //next length of ip header is ip_hl(4byte) * 4

            switch(ip->ip_p){
                case IPPROTO_TCP:
                {
                    dump_tcp_header(ip); //third protocol
                    break;
                }
                case IPPROTO_UDP:
                {
                    dump_udp_header((struct udphdr *)next_header_ptr);//third protocol
                    break;
                }
                case IPPROTO_ICMP:
                {
                    dump_icmp_header((struct icmphdr *) next_header_ptr);//third protocol
                    break;
                }
            }
            break;
        }
    }
    printf("------------------------------------------------------------------------\n");
}

int main(int argc, char **argv)
{
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs; //get interface info
    pcap_if_t *d; //interface pointer
    struct pcap_addr *a;
    int i = 0;
    int no;

    if(pcap_findalldevs(&alldevs,errbuf) <0){ // find all interface device
        printf("pcap_findalldevs error\n");
        return 1;
    }
    for(d=alldevs;d;d=d->next){
        printf("%d : %s\n",++i,(d->description)?(d->description):(d->name)); //if there if description, print it, otherwise print name of the interface.
    }
    printf("number : ");
    scanf("%d", &no); // select a certain device

    if(!(no > 0 && no <= i)){
        printf("number error\n");
        return 1;
    }
    for(d=alldevs, i =0; d; d=d->next){
        if(no== ++i) break;
    }
    //pcap_open_live function is the function that could open detail information about a certain interface.
    //pcap_open_live( char *device, int snaplen, int promisc, int to_ms, char *ebuf);
    // device = (name of the interface),
    // snaplen = maximum size of packet
    // promiscuous Mode (1) Nonpromiscuous Mode (0)
    // to_ms = limit of reading time (1000 = 1 second?)
    // ebuf = error buffer( error message)
    if(!(adhandle=pcap_open_live(d->name,65536,1, 1000,errbuf))){
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    pcap_freealldevs(alldevs);
    // pcap_loop is a function to see packet continuously that network device received
    // when network device get packet, pcap_loop call handler function.
    // int pcap_loop (pcap_t *p, int cnt, pcap_handler callback, u_char *user);
    // *p should be include return value about pcap_open_live
    // cnt is number of packet will receive. ( 0 means infinite)
    // callback is when network device get message then call callback function
    // user is parameter value for pcap_handler()
    pcap_loop(adhandle,0,packet_handler,NULL);
    //void packet_handeler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    // param is when pcap_loop function is called, then pcap_loop will provide value of its' parameter( container)
    // header is pointer address of pcap_pkthdr (when data get from the other network device, create pcap_pkthder)
    //pkt_data is data start address
    pcap_close(adhandle);
    return 0;
}