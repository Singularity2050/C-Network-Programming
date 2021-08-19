#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define __linux__
#include "../ICMPLIB/icmplib.h"

#define BUFMAX 4096
#define WAITTIME 3

enum{ ARGV_CMD,ARGV_IP};

int main(int argc, char **argv)
{

    if(argc != 2){
        printf("usage : %s [IP]\n",argv[ARGV_CMD]);
        return 1;
    }
    //---------------------packet for sending--------------------------------------------------
    char buffer[BUFMAX];
    struct timeval tv; //data area
    struct icmp icmp_packet;
    //1.create and initialize socket (data level)
    int sock,len;
    if((sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0){ //IPPROTO_ICMP : control message protocol
        perror("socket");
        return 1;
    }
    memset(&tv,0x00,sizeof(tv));
    tv.tv_sec = WAITTIME;
    /* SOL_SOCKET  : options for socket level     */
    /* SO_RCVTIMEO : receive timeout              */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    //2. intialize ICMP protocol (linked layer)
    memset(&icmp_packet,0x00,sizeof(icmp_packet));
    //3. set ICMP protocol
    icmp_packet.icmp_type = 8;
    icmp_packet.icmp_code = 0;
    icmp_packet.icmp_id = htons(1);
    icmp_packet.icmp_seq = htons(1);
    icmp_packet.icmp_cksum = 0;
    icmp_packet.icmp_cksum = cksum(
            (unsigned short*)&icmp_packet,sizeof(icmp_packet)
            );
    //4. set target address
    struct sockaddr_in addr;
    memset(&addr,0x00, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[ARGV_IP]);

    //5.send ICMP to the target
    if(sendto(sock,&icmp_packet,sizeof(icmp_packet),0,
              (struct sockaddr *)&addr,sizeof(addr))<0){
        perror("sendto ");
    }

    //receiving data
    //if the device get data, len will be bigger than 0, and data will be store in buffer
    while((len = read(sock, buffer, BUFMAX))>0){ //read function will wait for 3 second, if read function couldn't get data, return -1
        struct ip *ip = (struct ip *) buffer; //store IP
        int ip_header_len = ip->ip_hl <<2; //ip header length is ip->ip_hl * 4

        if(ip->ip_p == IPPROTO_ICMP){ //if protocol is ICMP, then printf it
            struct icmp *icmp = (struct icmp *)(buffer +ip_header_len);

            printf("from : %s\n",inet_ntoa(ip->ip_src));
            printf("ICMP Type : %d\n",icmp->icmp_type);
            printf("ICMP Code : %d\n",icmp->icmp_code);
        }
    }
    close(sock);
    return 0;
}
