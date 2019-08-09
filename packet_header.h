#ifndef PACKET_HEADER_H
#define PACKET_HEADER_H

#include <stdint.h>

#pragma pack(push, 1)
typedef struct ether_header
{
        #define MAC_LEN 6
        uint8_t  eth_dst[6];       //6byte
        uint8_t  eth_src[6];       //6byte
        #define E_ARP 0x0806
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
        uint8_t sender_macaddr[6];
        uint32_t sender_ipaddr;
        uint8_t target_macaddr[6];
        uint32_t target_ipaddr;
}ARP_HDR;

typedef struct arp_packet
{
    ETHER_HDR eth;
    ARP_HDR arp;
}ARP_PKT;
#pragma pop(1)

extern ETHER_HDR* ether_hdr;
extern ARP_HDR* arp_hdr;
extern ARP_PKT* arp_req;
extern ARP_PKT* arp_rpy;
extern uint8_t sendpacket[42];
extern uint8_t MY_MAC[6];
#endif // PACKET_HEADER_H
