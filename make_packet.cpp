#include "my_info.h"
#include "packet_header.h"
#include <string.h>
#include <arpa/inet.h>


// make arp_packet
void make_arp_request(char* sender_ip,char* target_ip,int num)
{
    /*
        1. check reqeust or reply
        2. check broadcast or multicast
    */

    make_ether_packet(num);

    // 1. arp_reqeust and broadcast
    arp_hdr->hardware_type = htons(ETHERNET);
    arp_hdr->protocol_type = htons(ARP);
    arp_hdr->hardware_size = HARD_SIZE;
    arp_hdr->protocol_size = PRO_SIZE;
    arp_hdr->opcode=htons(0x0001);

    memcpy(arp_hdr->sender_macaddr,ether_hdr->eth_src,6);
    memset(arp_hdr->target_macaddr,0x00,6);
    arp_hdr->target_ipaddr=inet_addr(sender_ip);

    memcpy(&(arp_req->eth),ether_hdr,sizeof(ETHER_HDR));
    memcpy(&(arp_req->arp),arp_hdr,sizeof(ARP_HDR));
    memcpy(sendpacket,&(arp_req->eth),sizeof(ETHER_HDR));
    memcpy(sendpacket+sizeof(ETHER_HDR),&(arp_req->arp),sizeof(ARP_HDR));
}
void make_arp_request_multicast(char* sender_ip, char* target_ip)
{

}
void make_arp_reply(char* sender_ip, char* target_ip,int num)
{
    make_ether_packet(num);
    arp_hdr->hardware_type = htons(ETHERNET);
    arp_hdr->protocol_type = htons(ARP);
    arp_hdr->hardware_size = HARD_SIZE;
    arp_hdr->protocol_size = PRO_SIZE;
    arp_hdr->opcode=htons(0x0002);

    memcpy(arp_hdr->sender_macaddr,ether_hdr->eth_src,6);
    arp_hdr->sender_ipaddr=inet_addr(target_ip);

    //memset(arp_hdr->target_macaddr,0x00,6);
    memcpy(arp_hdr->target_macaddr,arp_rpy->arp.target_macaddr,6);
    arp_hdr->target_ipaddr=inet_addr(sender_ip);

    memcpy(&(arp_rpy->eth),ether_hdr,sizeof(ETHER_HDR));
    memcpy(&(arp_rpy->arp),arp_hdr,sizeof(ARP_HDR));
    memcpy(sendpacket,&(arp_rpy->eth),sizeof(ETHER_HDR));
    memcpy(sendpacket+sizeof(ETHER_HDR),&(arp_rpy->arp),sizeof(ARP_HDR));
}
