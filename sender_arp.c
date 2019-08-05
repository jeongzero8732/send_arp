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
#include <stdlib.h>
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

	#define ETHERNET 1 
        uint16_t hardware_type;

	#define ARP 0x0800
        uint16_t protocol_type;
        uint8_t hardware_size; //6
        uint8_t protocol_size; //4
        uint8_t sender_macaddr[MAC_LEN];
        uint8_t sender_ipaddr[IP_LEN];
        uint8_t target_macddr[MAC_LEN];
        uint8_t target_ipaddr[IP_LEN];
}ARP_HDR;

ETHER_HDR* ether_hdr;
ARP_HDR* arp_hdr;

uint8_t send_packet[42];
uint8_t* recv_packet;
void find_mac();
void make_arp_packet(ETHER_HDR*,ARP_HDR*);
void make_eth_packet(ETHER_HDR*);
void ExtractPkt(int, const u_char*);

int main(int arc, char* argv[])
{
 	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t *macaddr;
	int i;
	ether_hdr = (ETHER_HDR*)malloc(sizeof(ETHER_HDR));
	arp_hdr=(ARP_HDR*)malloc(sizeof(ARP_HDR));
	char* dev=argv[1];
	pcap_t* handle;
	find_mac(argv[1]);

	make_arp_packet(ether_hdr, arp_hdr);

	while(1)
	{
		struct pcap_pkthdr* header;
   		const u_char* packet;
    		int res = pcap_next_ex(handle, &header, &packet);
    		if (res == 0) continue;
    		if (res == -1 || res == -2) break;
		ExtractPkt(header->caplen,packet);
	}
	for(int j=0;j<14;j++){
	printf("%x \n",send_packet[j]);}

	if (pcap_sendpacket(handle, send_packet, 42 /* size */ ) != 0 )
	{
		printf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
	}

        return 0;
}

void make_eth_packet(ETHER_HDR* ether_hdr)
{
	
	ether_hdr->eth_dst[0]=0xFF;
	ether_hdr->eth_dst[1]=0xFF;
	ether_hdr->eth_dst[2]=0xFF;
	ether_hdr->eth_dst[3]=0xFF;
	ether_hdr->eth_dst[4]=0xFF;
	ether_hdr->eth_dst[5]=0xFF;
	ether_hdr->eth_type=htons(0x0806);
	
	
	strcat(send_packet,ether_hdr->eth_dst);
	strcat(send_packet,ether_hdr->eth_src);
	send_packet[12]=0x08;
	send_packet[13]=0x06;
}

void make_arp_packet(ETHER_HDR* ether_hdr, ARP_HDR* arp_hdr)
{
	make_eth_packet(ether_hdr);
	arp_hdr->hardware_type=ETHERNET;
	arp_hdr->protocol_type=htons(ARP);
	arp_hdr->hardware_size=MAC_LEN;
	arp_hdr->protocol_size=IP_LEN;
	strncpy(arp_hdr->sender_macaddr,ether->eth_src,6);
	strncpy(arp_hdr->snedr_ipaddr);
	memcpy(arp_hdr->sender_macaddr,ether_hdr->eth_src,6);
	strcat(send_packet,arp_hdr->sender_maccaddr);
	for(int i=)	

}
void find_mac(char* device)
{
    int i;
    uint32_t fd;
    struct ifreq ifr;
    char* iface=device;
    uint8_t* mac=NULL;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        mac = (uint8_t*)ifr.ifr_hwaddr.sa_data;
    }
    for(i=0;i<MAC_LEN;i++)
    {
        ether_hdr->eth_src[i] = mac[i];
//	memcpy(ether_hdr->eth_src,mac,6);
	//ether_hdr->eth_src[i]=mac[i];	
    }	
    //printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , arp_hdr->sender_macaddr[0], arp_hdr->sender_macaddr[1], arp_hdr->sender_macaddr[2], arp_hdr->sender_macaddr[3], arp_hdr->sender_macaddr[4], arp_hdr->sender_macaddr[5]);
    
	
    close(fd);

}

void ExtractPkt(int size, const u_char* packet)
{
	ether_hdr = (ETHER_HDR *)packet;
	
	if(ntohs(ether_hdr->eth_type) == 0x0800 )
	{
		//ip header
		ip_hdr=(IP_HDR*)(packet + sizeof(ETHER_HDR));
	
		switch(ip_hdr->ip_proto)
		{
			case 6: //TCP Protocol
			Extract_Tcp_Pkt(size,packet);
			break;
			default:
			break;
		}
	}
	
}
