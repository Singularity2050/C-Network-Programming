#ifndef PROTOCOL_IP_H
#define PROTOCOL_IP_H

#include <stdint.h>

#ifndef __linux__
#include <winsock2.h>
#pragma pack(push,1)
#else
    #include <netinet/in.h>
#endif
struct ip{
    uint8_t ip_hl:4; //ip header length
    uint8_t ip_v:4; // ip version
    uint8_t ip_tos; // ip type of service
    uint16_t ip_len; //total length
    uint16_t ip_id; // identification
    uint16_t ip_off; //fragment offset field
#define IP_RE 0x8000 //reserved fragment flag
#define IP_DF 0x4000 //don't fragments flag
#define IP_MF 0x2000 //more fragments flag
#define IP_OFFMASK 0x1fff //mask for fragmenting bits
uint8_t ip_ttl; //time to live
uint8_t ip_p; //protocol
uint16_t ip_sum; // check sum
struct in_addr ip_src, ip_dst; //source and dest address
}
#ifndef __linux__
;
#pragma pack(pop)
#else
__attribute__((__packed__));
#endif
void dump_ip_header(struct ip *ip);

#endif //PROTOCOL_IP_H
