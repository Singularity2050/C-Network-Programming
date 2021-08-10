#ifndef ICMP_H
#define ICMP_H
#include <stdint.h>

#ifndef __linux__
    #pragma pack(push,1)
#endif
struct icmphdr
{
    uint8_t type; //message type
    uint8_t code; //type sub-code
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
}
#ifndef __linux__
    ;
    #pragma pack(pop)
#else
__attribute__((__packed__));
#endif

void dump_icmp_header(struct icmphdr *icmphdr);
#endif //PROTOCOL_ICMP_H
