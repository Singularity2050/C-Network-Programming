#include <stdio.h>
#include <ctype.h>
#include <string.h>
#define __linux__

#ifndef __linux__
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "udp.h"

#ifndef __linux__
#pragma pack(push,1)
#endif
struct packet{
    struct udphdr udphdr;
    char data[100];
}
//#ifndef __linux__
//    ;
//#pragma pack(pop)
//#else
//    __attribute__((__packed__));
//#endif
;
void dump_udp_header(struct udphdr *udphdr){
    int i, cut_size, data_len;
    char databuffer[1024];
    unsigned char *data_ptr;

    data_len = ntohs(udphdr->uh_ulen) - sizeof(struct udphdr); // data length = Length - udp header length
    data_ptr = (unsigned char *)udphdr + sizeof(struct udphdr);

    cut_size = (data_len > 40 ? 40:data_len);

    for(i = 0; i<cut_size; i+= 1){
        databuffer[i] = (isprint(data_ptr[i]))?data_ptr[i]:'.';
    }

    databuffer[cut_size] = '\0';
    printf("[UDP][%d->%d][len:%d]%s\n",
           ntohs(udphdr->uh_sport),ntohs(udphdr->uh_dport),
           ntohs(udphdr->uh_ulen),databuffer
    );
}
