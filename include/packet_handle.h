#ifndef PACKET_HANDLE_H
#define PACKET_HANDLE_H



#include "my_info.h"
#include <stdint.h>

void get_info(char*,int);
int get_packet(int size, const uint8_t* packet);
void make_packet(char*,char*);
void send_packet();

#endif // PACKET_HANDLE_H
