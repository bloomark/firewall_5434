#ifndef _PCAP_HANDLER_H_
#define _PCAP_HANDLER_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "main.h"
#include "rule_parse.h"
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>

/*
 * place your function/data structure definitions here.
 */
typedef struct ether_hdr{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t ethertype;
	uint8_t data[0];
} ethernet_hdr_t;

/*
 * IP HEADER
 */
typedef struct ip_hdr{
	uint8_t version_ihl;
	uint8_t dscp_ecn;
	uint8_t total_len[2];
	uint8_t identification[2];
	uint8_t flags_offset[2];
	uint8_t ttl; 
	uint8_t protocol;
	uint8_t checksum[2];
	//uint8_t src_ip[4];
	//uint8_t dst_ip[4];
	struct in_addr srcip;
	struct in_addr dstip;
	uint8_t options_and_data[0];
} ip_hdr_t;	

/*
 * TCP HEADER
 */
typedef struct tcp_hdr{
	//uint8_t src_port[2];
	//uint8_t dst_port[2];
	uint16_t srcport;
	uint16_t dstport;
	uint8_t seq_num[4];
	uint8_t ack_num[4];
	uint8_t offset_rsvd;
	uint8_t flags;
	uint8_t window_size[2];
	uint8_t checksum[2];
	uint8_t urgent[2];
	uint8_t options_and_data[0];
} tcp_hdr_t;

typedef struct udp_hdr{
	uint8_t srcport[2];
	uint8_t dstport[2];
	uint8_t length[2];
	uint8_t checksum[2];
	uint8_t options_and_data[0];
} udp_hdr_t;

typedef struct icmp_hdr{
	uint8_t type;
	uint8_t code;
	uint8_t checksum[2];
	uint8_t identifier[2];
	uint8_t sequence[2];
} icmp_hdr_t;

typedef struct arp_hdr{
    uint8_t htype[2];
    uint8_t ptype[2];
    uint8_t hlen;
    uint8_t plen;
    uint8_t oper[2];
    uint8_t sender_mac[ETHER_ADDR_LEN];
    uint8_t srcip[4];
    uint8_t receiver_mac[ETHER_ADDR_LEN];
    uint8_t dstip[4];
} arp_hdr_t;

typedef struct pseudo_hdr{
	struct in_addr srcip;
	struct in_addr dstip;
	uint8_t zeroes;
	uint8_t protocol;
	uint16_t tcplen;
	uint16_t srcport;
    uint16_t dstport;
    uint8_t seq_num[4];
    uint8_t ack_num[4];
    uint8_t offset_rsvd;
    uint8_t flags;
    uint8_t window_size[2];
    uint8_t checksum[2];
    uint8_t urgent[2];
    uint8_t options_and_data[0];
} pseudo_hdr_t;
	
pcap_dumper_t *dumphandle;

void read_pcap_file(char *pcaptestfile);
enum ACTION process_packet(const u_char *packet);

#endif
