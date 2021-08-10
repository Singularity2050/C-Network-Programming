cmake_minimum_required(VERSION 3.19)
project(protocol C)

set(CMAKE_C_STANDARD 99)

add_library(protocol Ethernet/ethernet.c Ethernet/ethernet.h ARP/arp.c ARP/arp.h IP/ip.c IP/ip.h TCP/tcp.h TCP/tcp.c UDP/udp.h UDP/udp.c ICMP/icmp.c ICMP/icmp.h sniffing.c ARPLIB/arplib.c ARPLIB/arplib.h arplibTest.c)