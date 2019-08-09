#pragma once

#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "packet_header.h"
#include "make_pakcet.h"
#include "packet_handle.h"

uint8_t My_MAC[6];

void my_mac(char* device)
{
    int i;
    int fd;
    struct ifreq ifr;
    char* iface=device;
    uint8_t* mac=NULL;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr))
    {
        mac = (uint8_t*)ifr.ifr_hwaddr.sa_data;
    }

//    for(i=0;i<6;i++)
//    {
//        ether_hdr->eth_src[i] = mac[i];
//    }
   // printf("--%x %x %x %x %x %x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    memcpy(My_MAC,mac, 6);
   // printf("--%x %x %x %x %x %x\n",ether_hdr->eth_src[0],ether_hdr->eth_src[1],ether_hdr->eth_src[2],ether_hdr->eth_src[3],ether_hdr->eth_src[4],ether_hdr->eth_src[5]);


        close(fd);
}

void my_ip(char* device)
{
    int n;
    struct ifreq ifr;
    char* array=device;
    char* buf=NULL;

    n = socket(AF_INET, SOCK_DGRAM, 0);
    //Type of address to retrieve - IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
    //Copy the interface name in the ifreq structure
    strncpy(ifr.ifr_name , array , IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
    close(n);

    //display result
    printf("IP Address is %s - %s\n" , array , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );

   // printf("%x %x %x %x",buf[0],buf[1],buf[2],buf[3],buf[4]);
    arp_hdr->sender_ipaddr=(uint32_t)(inet_addr(inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr)));
    printf("@@@@@%x\n",arp_hdr->sender_ipaddr);


}

void make_ether_packet(int num)
{
    /*
        1. check broadcast or multicast
    */
    uint8_t broad[6];
    memset(broad,0xff,6);
    memcpy(ether_hdr->eth_src,My_MAC,6);
    memcpy(ether_hdr->eth_dst,num==1?broad:arp_rpy->arp.target_macaddr,6);//modify later
    ether_hdr->eth_type=htons(E_ARP);
}

void make_arp_packet(char* sender_ip, char* target_ip,int num)
{   
    switch(num)
    {
        case 1:
        make_arp_request(sender_ip,target_ip,num);
        break;
        case 2:
        make_arp_request_multicast(sender_ip,target_ip);
        break;
        case 3:
        make_arp_reply(sender_ip,target_ip,num);
        break;
        default:
        break;
    }

}

