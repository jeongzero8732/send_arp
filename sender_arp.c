#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#define MAC_LEN 6
#define IP_LEN 4
#define HWADDR_len 6

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
        uint8_t target_macddr[MAC_LEN];
        uint8_t target_ipaddr[IP_LEN];
}ARP_HDR;

typedef struct total_header
{
	ETHER_HDR* eth;
	ARP_HDR* arp;
}T_HDR;

ETHER_HDR* ether_hdr;
ARP_HDR* arp_hdr;
T_HDR* t_hdr;

uint8_t send_packet[42];
uint8_t* recv_packet;
void find_mac();

int main(int arc, char* argv[])
{
 	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t *macaddr;
	int i;
	char* dev=argv[1];
	pcap_t* handle;

	strcat(t_hdr->eth,ether_hdr);
	//strcat(send_packet,ether_hdr->eth_dst);
		

//	if(pcap_sendpacket(handle,packet,42)!=0)
	{
//		printf(stderr,"Error sending the packet!!\n",pcap_geterr(handle));
	}
	/*
		1. arp request for get target mac_addr, with target_ip 
	*/
	find_mac(argv[1]);

        return 0;
}

void find_mac(char* device)
{
    int i;
    uint32_t fd;
    struct ifreq ifr;
    char* iface=device;
    unsigned char *mac = NULL;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    }
    for(i=0;i<MAC_LEN;i++)
    {
	arp_hdr->sender_macaddr[i]=mac[i];	
    }	
    printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , arp_hdr->sender_macaddr[0], arp_hdr->sender_macaddr[1], arp_hdr->sender_macaddr[2], arp_hdr->sender_macaddr[3], arp_hdr->sender_macaddr[4], arp_hdr->sender_macaddr[5]);
    

    close(fd);

}
