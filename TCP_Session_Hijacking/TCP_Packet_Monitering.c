#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define __linux__
#ifndef __linux__
#include <winsock2.h>
#else
#include <netinet/in.h>
	#include <arpa/inet.h>
#endif

#include "../TCPLIB/tcplib.h"
#include "pcap.h"

#define	STRSIZE 1024

enum { ARGV_CMD, ARGV_IP, ARGV_PORT };

void packet_handler(
        u_char *param, const struct pcap_pkthdr *header,
        const u_char *pkt_data);

struct param_data
{
    unsigned int filter_ip;
    unsigned short filter_port;
};


int main(int argc, char **argv)
{
    //checking argc
    if(argc != 3) {
        printf("Usage : %s [ip] [port]\n", argv[ARGV_CMD]);
        return 1;
    }
    //1. See all network devices
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs,*d;

    pcap_t *adhandle;
    if(pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }
    int i = 0; //total number of devices
    for(d=alldevs; d; d=d->next) {
        printf("%d :  %s\n",++i, (d->description)?(d->description):(d->name));
    }
    //2. select the device
    int no;
    printf("number : ");
    scanf("%d", &no);

    if(!(no > 0 && no <= i)) {
        printf("number error\n");
        return 1;
    }
    for(d=alldevs, i=0; d; d=d->next) {
        if(no == ++i)  break;
    }

    //3. making tool that can open a device for capturing
    if(!(adhandle= pcap_open_live(d->name, 65536, 1,	1000, errbuf))) {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    //4. making parameter data to filter ip or port
    struct param_data param_data;
    param_data.filter_ip = inet_addr(argv[ARGV_IP]);
    param_data.filter_port = ntohs(atoi(argv[ARGV_PORT]));
    //5. process packets from a live capture
    //pcap_loop( capturing tool, count, callback, parameter data);
    pcap_loop(adhandle, 0, packet_handler, (unsigned char *)&param_data);

    pcap_freealldevs(alldevs);
    pcap_close(adhandle);

    return 0;
}

void packet_handler(
        u_char *param, const struct pcap_pkthdr *header,
        const u_char *pkt_data)
{
    //1. save packet data into the buffer, re-save parameter into the structure
    unsigned char *buffer= (unsigned char *)pkt_data; //actual data
    struct param_data *pd = (struct param_data *)param; //parameter
    //2. categorizing
    //2-1. ethernet header
    struct ether_header *ether_header = (struct ether_header *)buffer;
    //2-2 IP header
    struct ip *ip = NULL;
    ip = (struct ip *)(buffer + sizeof(struct ether_header));

    //3.filter
    //3-1. Ethernet IP filter
    if(ntohs(ether_header->ether_type) != ETHERTYPE_IP) return;
    //3-2. TCP protocol and filtered Ip filter
    if((ip->ip_p == IPPROTO_TCP) && (
            (ip->ip_src.s_addr == pd->filter_ip) ||
            (ip->ip_dst.s_addr == pd->filter_ip))) {
        //2-3 TCP header
        struct tcphdr *tcphdr = NULL;
        tcphdr = (struct tcphdr *)((char *)ip + (ip->ip_hl << 2));
        //3-3 filtered Port filter
        if(tcphdr->th_dport == pd->filter_port ||
           tcphdr->th_sport == pd->filter_port) {
            //4. convert readable form
            char str_sip[STRSIZE], str_dip[STRSIZE], flags[STRSIZE];
            int pos = 0;

            strcpy(str_sip, inet_ntoa(ip->ip_src));
            strcpy(str_dip, inet_ntoa(ip->ip_dst));

            if((tcphdr->th_flags & TH_SYN) == TH_SYN) flags[pos++] = 'S';
            if((tcphdr->th_flags & TH_FIN) == TH_FIN) flags[pos++] = 'F';
            if((tcphdr->th_flags & TH_RST) == TH_RST) flags[pos++] = 'R';
            if((tcphdr->th_flags & TH_PUSH)== TH_PUSH)flags[pos++] = 'P';
            if((tcphdr->th_flags & TH_ACK) == TH_ACK) flags[pos++] = 'A';
            if((tcphdr->th_flags & TH_URG) == TH_URG) flags[pos++] = 'U';

            flags[pos] = '\0';


            printf("%s:%d->%s:%d "\
				"(seq : %u, flags : %s, len : %d)\n",
                   str_sip, ntohs(tcphdr->th_sport),
                   str_dip, ntohs(tcphdr->th_dport),
                   ntohl(tcphdr->th_seq),
                   (pos)?flags:"unknown", ntohs(ip->ip_len));
        }
    }
}
