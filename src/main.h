#ifndef _MAIN_H_
#define _MAIN_H_

#include "rule_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/if_ether.h>
#include "uthash.h"

//enum ACTION{BLOCK, PASS};
//enum PROTOCOL{TCP, ICMP, UDP};

typedef unsigned char u_char;
char hwaddr_buffer[(ETHER_ADDR_LEN * 3) + 1];

struct nat_hdr{
	uint16_t ep1_port;
	int used;
} nat_hdr_t;
struct nat_hdr tcpnat[65536];
struct nat_hdr udpnat[65536];

uint32_t unpack_32(uint8_t *buf);

void pack_32(uint32_t val, uint8_t *buf);

int hex2dec(char c);

int hwaddr_aton(char *txt, u_char *addr);

char *hwaddr_ntoa(const unsigned char *hwaddr, size_t hwlen);

//uint16_t ip_checksum(void *buf, size_t hdr_len);
uint16_t ip_checksum(void* vdata,size_t length);

uint16_t getrand(int min, int max);

void init();

#endif
