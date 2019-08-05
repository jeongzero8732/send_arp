#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
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

	#define ETHERNET 0x0001 
        uint16_t hardware_type;

	#define ARP 0x0800
        uint16_t protocol_type;

	#define HARD_SIZE 0x06
        uint8_t hardware_size; //6
	#define PRO_SIZE 0x04
        uint8_t protocol_size; //4

	uint16_t opcode;
        uint8_t sender_macaddr[MAC_LEN];
        uint32_t sender_ipaddr;
        uint8_t target_macaddr[MAC_LEN];
        uint32_t target_ipaddr;
}ARP_HDR;

ETHER_HDR* ether_hdr;
ARP_HDR* arp_hdr;

uint8_t send_packet[42];
uint8_t* recv_packet;
void find_mac();
void make_arp_request(ETHER_HDR*,ARP_HDR*,char*);
void make_eth_packet(ETHER_HDR*);
void ExtractPkt(int, const u_char*);
void find_IP(char*);

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
	find_IP(argv[1]);
	make_arp_request(ether_hdr, arp_hdr,argv[2]);

	/*while(1)
	{
		struct pcap_pkthdr* header;
   		const u_char* packet;
    		int res = pcap_next_ex(handle, &header, &packet);
    		if (res == 0) continue;
    		if (res == -1 || res == -2) break;
		//ExtractPkt(header->caplen,packet);
	}*/

	for(int j=0;j<42;j++){
	printf("[%d. %.02x]",j,send_packet[j]);}

	//if (pcap_sendpacket(handle, send_packet, 42 /* size */ ) != 0 )
	{
		//printf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
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
	memcpy(send_packet+6,ether_hdr->eth_src,6);
	send_packet[12]=0x08;
	send_packet[13]=0x06;
}

void make_arp_request(ETHER_HDR* ether_hdr, ARP_HDR* arp_hdr, char* sender_ip)
{
	make_eth_packet(ether_hdr);

	arp_hdr->hardware_type = htons(ETHERNET);
	arp_hdr->protocol_type = htons(ARP);
	arp_hdr->hardware_size = htons(HARD_SIZE);
	arp_hdr->protocol_size = htons(PRO_SIZE);
	arp_hdr->opcode=htons(0x0001);
	
	//strncpy(arp_hdr->sender_macaddr,ether->eth_src,6);
	//strncpy(arp_hdr->snedr_ipaddr);
	memcpy(arp_hdr->sender_macaddr,ether_hdr->eth_src,6);
	memcpy(arp_hdr->target_macaddr,"0x000000000000",6);
	arp_hdr->target_ipaddr=inet_addr(sender_ip);

	memcpy(send_packet+14,arp_hdr,28);
	
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
	printf("%x--\n",ether_hdr->eth_src[i]);
//	memcpy(ether_hdr->eth_src,mac,6);
	//ether_hdr->eth_src[i]=mac[i];	
    }	
    //printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , arp_hdr->sender_macaddr[0], arp_hdr->sender_macaddr[1], arp_hdr->sender_macaddr[2], arp_hdr->sender_macaddr[3], arp_hdr->sender_macaddr[4], arp_hdr->sender_macaddr[5]);
    
	
    close(fd);

}

void find_IP(char* device)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) 
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }


    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL)
            continue;  

        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if((strcmp(ifa->ifa_name,device)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            printf("\tInterface : <%s>\n",ifa->ifa_name );
            printf("\t  Address : <%s>\n", host);
	    arp_hdr->sender_ipaddr=inet_addr(host);
	   printf("--%x--\n",arp_hdr->sender_ipaddr);
        }
    }

    freeifaddrs(ifaddr);
}

/*
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
		//	Extract_Tcp_Pkt(size,packet);
			break;
			default:
			break;
		}
	}
	
}
*/
