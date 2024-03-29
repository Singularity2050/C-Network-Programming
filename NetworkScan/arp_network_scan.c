#include <stdio.h>
#include <string.h>
#define __linux__
#ifndef __linux__ // for windows
    #include <winsock2.h>
    #include <windows.h>
    #define CREATE_THREAD(id,function,param) CreateThread(NULL,0,function,param,0,&id);
    #define THREAD_TYPE_RETURE DWORD WINAPI //Calling Convention
    #define THREAD_TYPE_PARAM LPVOID //Calling Convention
    #define THREAD_TYPE_ID DWORD //Calling Convention
    #define SLEEP(x) Sleep(x*1000) //Calling Convention
#else //for linux
    #include <unistd.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <pthread.h>
    #define CREATE_THREAD(id,function,param) pthread_create(&id,NULL,function,param);
    #define THREAD_TYPE_RETURN void*
    #define THREAD_TYPE_PARAM void*
    #define THREAD_TYPE_ID pthread_t
    #define SLEEP(x) sleep(x)
#endif

#include "pcap.h"
#include "../ARPLIB/arplib.h"
// if you use arp -a and see 192.168.1.25 is on the table,but it does not appear your code,
// than the reason is that the target device is temporary turn offed
// router or your device itself could send ARP reply to your device.
enum{
    ARGV_CMD,
    ARGV_MY_MAC,
    ARGV_START_IP,
    ARGV_END_IP
};

void packet_handler(
        u_char *param,
        const struct pcap_pkthdr *header, const u_char *pkt_data
        );

//Linux :  void * thread_function(void * param);
//Windows: DWORD WINAPI thread_function(LPVOID param); there is return value
//A DWORD is a 32-bit unsigned integer
//WINAPI is a macro specifying the calling convention (__stdcall, __cdecl etc.) of the function.
//LPVOID is void*

THREAD_TYPE_RETURN thread_function(THREAD_TYPE_PARAM param);

int main(int argc, char**argv)
{
    int no, i = 0;
    char errbuf[PCAP_ERRBUF_SIZE]; //error buffer for received packet
    pcap_t *adhandle; // pcap_t 구조체는 네트워크 디바이스나 패킷에 들어있는 pcap파일에서 패킷을 읽는데 사용되는 Handle이다.
    pcap_if_t *alldevs, *d; // Interface information

    THREAD_TYPE_ID thread_id; //Windows : DWORD thread_id Linux: pthread_t thread_id;

    struct pcap_addr *a; //network ip addresses( IP, board casting IP, netmake, destination address)
    struct in_addr my_ip; //Internet Address
    struct arp_packet arp_packet; //arp packet = ethernet header + arp header

    unsigned int arp_source_ip, arp_target_ip;
    unsigned int ip, start_ip, end_ip;
    unsigned char my_mac[6];
    unsigned char anymac[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    unsigned char *arp_source_mac, *ether_source_mac, *ether_dest_mac;

    if(argc != 4){
        printf("Usage : %s[my mac][Start IP][End IP]\n",argv[0]);
        return 1;
    }
    //using pcap_findalldevs function, get all the interface in local area or network are.
    if(pcap_findalldevs(&alldevs,errbuf) <0){
        printf("pcap_findalldevs error\n");
        return 1;
    }
    for(d=alldevs; d; d=d->next){
        printf("%d : %s\n",++i,(d->description)?(d->description):(d->name));
    }
    printf("number :");
    scanf("%d",&no);

    if(!(no > 0 && no <= i)){
        printf("number error\n");
        return 1;
    }
    for(d=alldevs, i =0; d; d=d->next){ //select certain interface
        if(no== ++i) break;
    }

    for(a = d->addresses;a; a=a->next){
        struct sockaddr_in *in_addr =
                (struct sockaddr_in *)a->addr;

        if(a->addr->sa_family == AF_INET){
            my_ip.s_addr = in_addr->sin_addr.s_addr;
            break;
        }
    }
    strmac_to_buffer(argv[ARGV_MY_MAC],my_mac);
    //open the certain interface, and gather IP address from the interfaces
    if(!(adhandle = pcap_open_live(d->name,65536,1,1000,errbuf))){ //adhandle contain interface info
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return 1;
    }
    CREATE_THREAD(thread_id,thread_function,adhandle); // pcap_loop to receive data, using adhandle to see the data

    //ARP Protocol

    ether_dest_mac = anymac;
    ether_source_mac = arp_source_mac = my_mac;

    make_ether_header(
            &(arp_packet.ether_header),
            ether_dest_mac, ether_source_mac,ETHERTYPE_ARP
            );

    //Range of Search + arp protocol
    arp_source_ip = my_ip.s_addr;
    arp_target_ip = inet_addr(argv[ARGV_START_IP]);

    start_ip = ntohl(inet_addr(argv[ARGV_START_IP]));
    end_ip = ntohl(inet_addr(argv[ARGV_END_IP]));

    for(ip = start_ip; ip <= end_ip; ip++){

        arp_target_ip = htonl(ip);
        struct in_addr ipAddr; //Internet Address
        ipAddr.s_addr = arp_target_ip;
        printf("sending %s\n",inet_ntoa(ipAddr));
        //making ARP protocol
        make_arp_header(
                &(arp_packet.ether_arp),arp_source_mac,arp_source_ip,
                NULL,arp_target_ip,ARPOP_REQUEST
                );
        //send socket
        pcap_sendpacket(
                adhandle,(unsigned char *)&arp_packet,sizeof(arp_packet)
                ); //send
                SLEEP(1);

    }
    SLEEP(3);

    pcap_freealldevs(alldevs);
    pcap_close(adhandle);
    return 0;
}
// start with thread create function in main function
THREAD_TYPE_RETURN thread_function(THREAD_TYPE_PARAM param)
{
    pcap_loop((pcap_t *)param,0,packet_handler,NULL); // when device received packet, call packet_handler()function
    return 0;
}

void packet_handler(
        u_char *param,
        const struct pcap_pkthdr *header, const u_char *pkt_data
        )
{
    unsigned char *m; //hardware address
    struct in_addr src_ip;// IPv4 address
    unsigned char *buffer = (unsigned char *)pkt_data; //received packet
    struct ether_header *ether_header = (struct ether_header *)buffer;// Ethernet header + ARP header

    if(ntohs(ether_header->ether_type) == ETHERTYPE_ARP){
        struct ether_arp *ether_arp
                = (struct ether_arp *)(buffer +sizeof(struct ether_header )); //pass Ethernet header and go to ARP header

        if(ntohs(ether_arp->arp_op) == ARPOP_REPLY){ //only ARP Reply
            printf("received");
            m = ether_arp->arp_sha; //mac address
            memcpy(&(src_ip.s_addr),ether_arp->arp_spa, 4);

            printf("%s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
                   inet_ntoa(src_ip),m[0],m[1],m[2],m[3],m[4],m[5]);
        }
    }
}
