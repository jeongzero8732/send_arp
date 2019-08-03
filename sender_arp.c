#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#define MAC_LEN 6
#define IP_LEN 4

typedef struct ether_header
{
        uint8_t  eth_dst[MAC_LEN];       //6byte
        uint8_t  eth_src[MAC_LEN];       //6byte
        uint16_t eth_type;                      //2byte
}ETHER_HDR;

typedef struct arp_hdr {
        uint16_t hardware_type;
        uint16_t protoco_type;
        uint8_t hardware_size;
        uint8_t protocol_size;
        uint8_t sender_macaddr[MAC_LEN];
        uint8_t sender_ipaddr[IP_LEN];
        uint8_t recv_macddr[MAC_LEN];
        uint8_t rece_ipaddr[IP_LEN];
}ARP_HDR;

int main(int arc, char* argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];

  char *device;


  int i;

 printf("%s\n",device = pcap_lookupdev(errbuf));

        return 0;
}

