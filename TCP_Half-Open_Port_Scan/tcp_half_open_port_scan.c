// TCP half Open Port Scan is using flags in TCP protocol.
// Since if we change Flags value, role of the TCP protocol is changed. and we call this bit as control bit.
// Flags is 9 bits. ( NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN )
// NS  : concealment ECN-nonce ( Explicit Congestion Notification (ECN) is an extension to the Internet Protocol and to the Transmission Control Protocol)
// CWR : Congestion Window Reduced flag. (set by sending host) letting know sending host got TCP segment included with ECE flags, and responded by Congestion control mechanism
// ECE : represent ECN-Echo flag. If SYN is 1, ECN is available to the host. If SYN is changed to 0, than means packet with ECE is accepted correctly.
// URG : Urgent pointer
// ACK : Acknowledgment field
// PSH : Push function
// RST : Connection reset
// SYN : Synchronous Sequence number ( 1 means first sequence number, 0 means cumulative sequence number)
// FIN : Connection Ending
// Different with IP, TCP protocol does not calculate checksum value with only TCP header and data segment. Have to make TCP Pseudo Header additionally.
// TCP Pseudo Header is virtual header and it is created for saving checksum.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define __linux__
#ifndef __linux__ /* for windows */
#include <winsock2.h>
#include <windows.h>
#define CREATE_THREAD(id,function,param) \
		CreateThread(NULL,0,function,param,0,&id);
#define THREAD_TYPE_RETURN DWORD WINAPI
#define THREAD_TYPE_PARAM LPVOID
#define THREAD_TYPE_ID DWORD
#define SLEEP(x)	Sleep(x*1000)
#else	/* for linux */
#include <unistd.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <pthread.h>
	#define CREATE_THREAD(id,function,param) \
		pthread_create(&id,NULL,function,param);
	#define THREAD_TYPE_RETURN void*
	#define THREAD_TYPE_PARAM void*
	#define THREAD_TYPE_ID pthread_t
	#define SLEEP(x)	sleep(x)
#endif

#include "pcap.h"
#include "../TCPLIB/tcplib.h"

#define	STR_IP_LENGTH 1024

enum {
    ARGV_CMD,
    ARGV_MY_MAC,
    ARGV_DEST_MAC,
    ARGV_TARGET_IP,
    ARGV_START_PORT,
    ARGV_END_PORT
};

void packet_handler(
        u_char *param,
        const struct pcap_pkthdr *header, const u_char *pkt_data
);

struct param_data
{
    pcap_t *adhandle;
    int start_port;
    int end_port;
};

THREAD_TYPE_RETURN thread_function(THREAD_TYPE_PARAM param);

int main(int argc, char **argv)
{
    if(argc != 6) {
        printf(
                "Usage : %s [my mac] [target mac(local) or gateway mac(external)] [target IP] "\
			"[start port] [end port]\n",
                argv[0]);
        return 1;
    }
    //find all the network device that listed and linked with my computer
    pcap_if_t *alldevs, *d;
    int no, i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }
    for(d=alldevs; d; d=d->next) {
        printf("%d :  %s\n",++i, (d->description)?(d->description):(d->name));
    }
    printf("number : ");
    scanf("%d", &no);
    if(!(no > 0 && no <= i)) {
        printf("number error\n");
        return 1;
    }
    for(d=alldevs, i=0; d; d=d->next) {
        if(no == ++i)  break;
    }
    //Key
    struct param_data param_data;
    if(!(param_data.adhandle=
                 pcap_open_live(d->name, 65536, 1,	1000, errbuf))) {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return 1;
    }
    // Find My Ethernet IP
    struct pcap_addr *a;
    struct in_addr my_ip;
    for(a = d->addresses; a; a=a->next) {
        if(a->addr->sa_family == AF_INET) {
            struct sockaddr_in *in_addr
                    = (struct sockaddr_in *)a->addr;
            my_ip.s_addr = in_addr->sin_addr.s_addr;
            break;
        }
    }
    //create Thread
    THREAD_TYPE_ID thread_id;
    CREATE_THREAD(thread_id, thread_function, &param_data);

    // Making TCP full Packet
    //Making Packet
    struct tcp_packet packet;
    memset(&packet, 0x00, sizeof(packet));

    int port, start_port, end_port;
    //Ethernet Protocol : Destination Address( 6 bytes ), Source Address( 6 bytes ), Ethernet Type(2 bytes)
    strmac_to_buffer(
            argv[ARGV_DEST_MAC], packet.ether_header.ether_dhost); //Destination Address( 6 bytes )
    strmac_to_buffer(
            argv[ARGV_MY_MAC], packet.ether_header.ether_shost); // Source Address( 6 bytes )
    packet.ether_header.ether_type = htons(ETHERTYPE_IP); // Ethernet Type(2 bytes)

    // TCP protocol : using make_tcp_header function( packet, source IP, source random port, target IP, target port, random syn, no ack, syn flag)
    param_data.start_port = start_port = atoi(argv[ARGV_START_PORT]);
    param_data.end_port = end_port = atoi(argv[ARGV_END_PORT]);

    for(port = start_port; port <=end_port; port += 1) {

        make_tcp_header(
                &packet,
                inet_ntoa(my_ip), rand(),
                argv[ARGV_TARGET_IP], port, rand(), 0, TH_SYN);
    // IP protocol : using make_ip_header function( packet.ip, source IP, target IP, sizeof tcp= total length);
        make_ip_header(&(packet.ip),
                       inet_ntoa(my_ip), argv[ARGV_TARGET_IP], sizeof(struct tcphdr));
    //send packet ( key, packet, packet size)
        pcap_sendpacket(
                param_data.adhandle, (unsigned char *)&packet, sizeof(packet)
        );
    }

    SLEEP(3);

    pcap_freealldevs(alldevs);
    pcap_close(param_data.adhandle);

    return 0;
}

THREAD_TYPE_RETURN thread_function(THREAD_TYPE_PARAM param)
{
struct param_data * param_ptr =
        (struct param_data *)param;
//pcap_loop( key, number of packet will capture(0 is unlimited mode),callback, received packet)
pcap_loop(
        param_ptr->adhandle, 0, packet_handler, (unsigned char *)param);// if second attribute 0 is changed to 5, then packet_handler will be called 5 times.

return 0;
}
//packet_handler( param_ptr, packet header, packet data)
void packet_handler(
        u_char *param,
        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    unsigned char *buffer = (unsigned char *)pkt_data; //received packet
    struct ether_header *ether_header = (struct ether_header *)buffer; //Ethernet header
    struct param_data *param_ptr = (struct param_data *)param;//sending packet info

    if(ntohs(ether_header->ether_type) == ETHERTYPE_IP) {

        struct ip *ip =
                (struct ip *)(buffer + sizeof(struct ether_header));//IP header = Ethernet header address + size of ethernet header
        struct tcphdr *tcphdr = NULL;

        if(ip->ip_p != IPPROTO_TCP) return; //if the packet is not TCP then return

        tcphdr = (struct tcphdr *)((char *)ip + (ip->ip_hl << 2));// TCP header = IP header + size of IP header( ip_hl * 4)

        if((ntohs(tcphdr->th_sport) >=  param_ptr->start_port) &&  //if port that received packet is in user required the area
           (ntohs(tcphdr->th_sport) <= param_ptr->end_port)) {

            if(((tcphdr->th_flags & TH_SYN) == TH_SYN) && // than check if the packet has SYN + ACK
               ((tcphdr->th_flags & TH_ACK) == TH_ACK)) {

                printf("%s:%d\n",
                       inet_ntoa(ip->ip_src), ntohs(tcphdr->th_sport)); // than print it.
            }
        }
    }
}
