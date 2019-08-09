#include <stdio.h>
#include <pcap.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

#include <packet_header.h>
#include <packet_handle.h>


ETHER_HDR* ether_hdr;
ARP_HDR* arp_hdr;
ARP_PKT* arp_req;
ARP_PKT* arp_rpy;

uint8_t sendpacket[42];

void usage() {
  printf("syntax: pcap_test <interface> <sender_ip> <target_ip> \n");
  printf("sample: pcap_test wlan0 1.1.1.1 2.2.2.2\n");
}

int main(int argc, char** argv)
{
    if (argc < 3) {
      usage();
      return -1;
    }

    char* dev=argv[1];
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int flag;

    ether_hdr = (ETHER_HDR*)malloc(sizeof(ETHER_HDR));
    arp_hdr=(ARP_HDR*)malloc(sizeof(ARP_HDR));
    arp_req=(ARP_PKT*)malloc(sizeof(ARP_PKT));
    arp_rpy=(ARP_PKT*)malloc(sizeof(ARP_PKT));

    get_info(dev,1); //my mac
    get_info(dev,2); //my ip


    if ((handle = pcap_open_live(dev, BUFSIZ,1, 1000, errbuf))==NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    make_arp_packet(argv[2],argv[3],1);

//    for(int i=0;i<42;i++)
//    {printf("%.2x ",sendpacket[i]);}


    if (pcap_sendpacket(handle, sendpacket, sizeof(ARP_PKT) /* size */ ) != 0 )
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
        return -1;
    }


    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);
        flag=get_packet(header->caplen,packet);
        if(flag==1)break;
    }

    make_arp_packet(argv[2],argv[3],3);

    while(1){
    if (pcap_sendpacket(handle, sendpacket, sizeof(ARP_PKT) /* size */ ) != 0 )
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
        return -1;
    } sleep(1);}

//    for(int i=0;i<42;i++)
//    {printf("%.2x ",sendpacket[i]);}
    pcap_close(handle);

    return 0;
}
