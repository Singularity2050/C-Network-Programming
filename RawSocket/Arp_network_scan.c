
#include <linux/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <printf.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <arpa/inet.h>


#include "../ARPLIB/arplib.h"

#define HWADDRLEN 6
#define IPADDRLEN 4

#define BUFMAX 4096

enum{
    ARGV_CMD,
    ARGV_INTERFACE,
    ARGV_START_IP,
    ARGV_END_IP
};

void *thread_function(void *p);

int main(int argc, char **argv)
{
    int sock;
    pthread_t thread_id;

    struct ifreq ifr; //interface
    struct in_addr my_ip; //The in_addr structure represents an IPv4 address
    struct sockaddr_ll sll; // The sockaddr_ll structure is a device-independent physical-layer address.
    struct arp_packet arp_packet; //arp packet = arp protocol + ethernet protocol
    unsigned int arp_source_ip, arp_target_ip;
    unsigned int ip, start_ip, end_ip;
    unsigned char my_mac[HWADDRLEN]; // 6bytes
    unsigned char anymac[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    unsigned char *arp_source_mac, *ether_source_mac, *ether_dest_mac;

    if(argc != 4){
        printf("Usage : %s [interface][Start IP][End IP]\n",argv[0]);
        return 1;
    }

    if((sock = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        perror("socket");
        return 1;
    }
    // initialize interface container
    memset(&ifr,0x00,sizeof(ifr));
    // put name of the interface on ifr structure
    strcpy(ifr.ifr_name,argv[ARGV_INTERFACE]);
    //find ethernet device information associated with socket and store it into ifr structure
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
        perror("ioctl");
    }

    memcpy(my_mac,ifr.ifr_hwaddr.sa_data,HWADDRLEN);

    memset(&ifr,0x00,sizeof(ifr));
    strcpy(ifr.ifr_name,argv[ARGV_INTERFACE]);
    if(ioctl(sock,SIOCGIFADDR,&ifr) <0){
        perror("ioctl");
        return 1;
    }
    //The SOCKADDR_IN structure specifies a transport address and port for the AF_INET address family
    struct sockaddr_in *addr_ptr = (struct sockaddr_in *)&(ifr.ifr_addr);
    memcpy(&my_ip.s_addr,&(addr_ptr->sin_addr.s_addr),IPADDRLEN);

    memset(&ifr,0x00,sizeof(ifr));
    strcpy(ifr.ifr_name,argv[ARGV_INTERFACE]);
    if(ioctl(sock,SIOCGIINDEX,&ifr) <0){
        perror("ioctl");
        return 1;
    }

    memset(&sll,0x00,sizeof(sll));

    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if(bind(sock,(struct sockaddr *)&sll,sizeof(sll)<0)){
        perror("bind");
        return 1;
    }

    pthread_create(&thread_id,NULL,thread_function,&sock);

    arp_source_ip = my_ip.s_addr;
    arp_target_ip = inet_addr(argv[ARGV_START_IP]);

    ether_dest_mac =anymac;
    ether_source_mac = arp_source_mac = my_mac;

    make_ether_header(
            &(arp_packet.ether_header),
            ether_dest_mac, ether_source_mac, ETHERTYPE_IP);

    start_ip = ntohl(inet_addr(argv[ARGV_START_IP]));
    end_ip = ntohl(inet_addr(argv[ARGV_END_IP]));

    for(ip= start_ip; ip <= end_ip; ip++){
        arp_target_ip = htonl(ip);

        make_arp_header(
                &(arp_packet.ether_arp),arp_source_mac,arp_source_ip,
                NULL,arp_target_ip,ARPOP_REQUEST
                );

        if(sendto(sock,&arp_packet, sizeof(arp_packet),0,
                  (struct sockaddr *)&sll,sizeof(sll)<0)){
            perror("sendto");
            break;
        }
        sleep(1);
    }
    sleep(3);
    return 0;
}

void *thread_function(void *p)
{
    int len;
    char buffer[BUFMAX];
    unsigned char *m;
    int sock = *(int*)p;

    while((len = read(sock,buffer,BUFMAX))>0){
        struct ether_header *ether_header =
                (struct ether_header *) buffer;
        if(ntohs(ether_header->ether_type) == ETHERTYPE_ARP){
            struct ether_arp *ether_arp =
                    (struct ether_arp *) (buffer + sizeof(struct ether_header));

            if(ntohs(ether_arp->arp_op) != ARPOP_REPLY) continue; //escape if clauses

            m = ether_arp->arp_sha;

            struct  in_addr src_ip;
            memcpy(&(src_ip.s_addr),ether_arp->arp_spa, IPADDRLEN);

            printf("%s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                   inet_ntoa(src_ip),m[0],m[1],m[2],m[3],m[4],m[5]);
        }
    }
    return NULL;
}