#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define __linux__

#ifndef __linux__
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "../IP/ip.h"
#include "tcp.h"
#ifndef __linux__
#pragma pack(push,1)
#endif
struct packet{
    struct ip ip; //ip protocol
    struct tcphdr tcphdr; //tcp protocol
    char buffer[100]; // payload, data
}
#ifndef __linux__
    ;
    #pragma pack(pop)
#else
    __attribute__((__packed__)); // same as #pragma pack(pop)
#endif

void dump_tcp_header(void * iphdr){ //TCP header address is provided from IP header
    //Since Because to print out payload(data), device have to calculate total length of data from IP header
    //Total length in IP not TCP.
    char flagbuffer[1024], databuffer[1024];

    int i, cut_size, pos =0; //cutsize is MTO size
    int iphdr_len, tcphdr_len, data_len;// ip header length, tcp header length, data length.
    unsigned char *data_ptr;

    struct tcphdr *tcphdr; //TCP header structure
    struct ip *ip = (struct ip *)iphdr; // ip header structure

    iphdr_len = ip->ip_hl << 2; //ip header length : Header length * 4 (bytes)
    //ip offset is include payload data but tcp offset does not include payload data. just size of header
    tcphdr = (struct tcphdr *)((char *)ip + iphdr_len);
    tcphdr_len = tcphdr->th_off <<2; // tcp header length is offset * 4 (bytes)

    //Data(payload) Size = Total Length in IP header - size of IP header - Size of TCP header
    data_len = ntohs(ip->ip_len) - tcphdr_len - iphdr_len;
    data_ptr = (unsigned char *)tcphdr + tcphdr_len;// [IP][TCP][Payload]

    if(tcphdr ->th_flags & TH_FIN) flagbuffer[pos++] = 'F';
    if(tcphdr ->th_flags & TH_SYN) flagbuffer[pos++] = 'S';
    if(tcphdr ->th_flags & TH_RST) flagbuffer[pos++] = 'R';
    if(tcphdr ->th_flags & TH_PUSH) flagbuffer[pos++] = 'P';
    if(tcphdr ->th_flags & TH_ACK) flagbuffer[pos++] = 'A';
    if(tcphdr ->th_flags & TH_URG) flagbuffer[pos++] = 'U'; //urgent
    flagbuffer[pos] = '\0'; //pos is position
    //if data is bigger than 40bites, then cut_size is 40 other wise its' data length
    cut_size = (data_len > 40)?40:data_len;
    for(i=0; i < cut_size; i+= 1){
        databuffer[i] = (isprint(data_ptr[i]))?data_ptr[i]:'.';
    }
    databuffer[cut_size] ='\0'; //cut data (fragmentation)

    printf("[TCP][%d->%d][seq : %u][ack : %u][flags : %s] %s\n",
           ntohs(tcphdr->th_sport),ntohs(tcphdr->th_dport),
           ntohl(tcphdr->th_seq),ntohl(tcphdr->th_ack),
           flagbuffer,databuffer);

}
