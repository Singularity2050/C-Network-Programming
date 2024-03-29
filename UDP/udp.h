//
// Created by 박시제 on 2021/08/07.
//

#ifndef PROTOCOL_UDP_H
#define PROTOCOL_UDP_H
#include <stdint.h>

#ifndef __linux__
#pragma pack(push,1)
#endif
struct udphdr{
    uint16_t uh_sport; //source port
    uint16_t uh_dport; //destination port
    uint16_t uh_ulen;//udp length
    uint16_t uh_sum; //udp checksum
}
#ifndef __linux__
;
#pragma pack(pop)
#else
__attribute__((__packed__));
#endif
void dump_udp_header(struct udphdr *udphdr);
#endif //PROTOCOL_UDP_H
