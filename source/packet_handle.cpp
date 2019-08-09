#include "packet_handle.h"
#include "packet_header.h"
#include "my_info.h"
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

void get_info(char* device,int num)
{
    switch(num)
    {
        case 1:
           my_mac(device);
           break;
        case 2:
           my_ip(device);
           break;
        default:
           break;
    }
}

int get_packet(int size, const uint8_t* packet)
{
    ETHER_HDR* get_eth=NULL;
    ARP_HDR* get_arp=NULL;

    get_eth = (ETHER_HDR *)packet;

        if(ntohs(get_eth->eth_type) == 0x0806 )
        {
            //arp header
            get_arp=(ARP_HDR*)(packet + sizeof(ETHER_HDR));


            //1. check arp_reply
            //2. check sender_ip is target and target_ip is target
            //3. extract target's mac addr
            if(ntohs(get_arp->opcode)==0x0002)
            {              printf("123\n");
                if((get_arp->sender_ipaddr==arp_req->arp.target_ipaddr) && memcmp(get_arp->target_macaddr,arp_req->arp.sender_macaddr,6)==0)
                {           printf("456\n");printf("%x %x %x %x %x %x\n",get_arp->sender_macaddr[0],get_arp->sender_macaddr[1],get_arp->sender_macaddr[2],get_arp->sender_macaddr[3],get_arp->sender_macaddr[4],get_arp->sender_macaddr[5]);
                    memcpy(arp_rpy->arp.target_macaddr,get_arp->sender_macaddr,6);
                    return 1;
                }
            }
        }
        return 0;
}

void make_packet(char* sender_ip,char* target_ip)
{
    make_arp_packet(sender_ip,target_ip,1);
}

void send_packet()
{

}

