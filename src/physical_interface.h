#ifndef _PHYSICAL_INTERFACE_H_
#define _PHYSICAL_INTERFACE_H_
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

char *wlan_hwaddr;
char *wlan_ipaddr;
char *gateway_hwaddr;

pcap_t* wlan_descr;

void physical_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);
/* http://yuba.stanford.edu/~casado/pcap/section1.html */
void* read_physical_interface();

char *physical_dev;

#endif
