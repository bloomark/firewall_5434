#ifndef _VIRTUAL_INTERFACE_H_
#define _VIRTUAL_INTERFACE_H_
#include "main.h"
#include "pcap_handler.h"
#include "rule_parse.h"
#include "list.h"
#include <pthread.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>

#define HI_NIBBLE(b) (((b) >> 4) & 0x0F)
#define LO_NIBBLE(b) ((b) & 0x0F)

char *ep1_hwaddr;
char *ep1s_hwaddr;

char *ep1_ipaddr;

pcap_t* ep1s_descr;

void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);
/* http://yuba.stanford.edu/~casado/pcap/section1.html */
void* read_virtual_interface();

unsigned char *ep1_mac_addr;
unsigned char *wlan_mac_addr;
unsigned char *gateway_mac_addr;
unsigned char *ep1s_mac_addr;

char *virtual_dev;

int count;

#endif
