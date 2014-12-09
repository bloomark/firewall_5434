#include "pcap_handler.h"
#include "main.h"
#include "rule_parse.h"
#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

void read_pcap_file(char *pcaptestfile){
	struct pcap_pkthdr *header;
	pcap_t *handle;	
	char errbuf[PCAP_ERRBUF_SIZE];
	const uint8_t *packet = NULL;
	char *outfile = "firewalldump.pcap";
	enum ACTION result;

	handle = pcap_open_offline(pcaptestfile, errbuf);
	if(handle == NULL){
		printf("Couldn't open pcap file. Exiting\n");
		exit(1);
	}

	dumphandle = pcap_dump_open(handle, outfile);
	if(dumphandle == NULL){
		printf("Couldn't open firewalldump.pcal. Exiting.\n");
		exit(1);
	}

	while(1){
		int res = pcap_next_ex(handle, &header, &packet);
		
		if(res == -2)
			break;

		result = process_packet(packet);
		if(result == PASS)
			pcap_dump((u_char *)dumphandle, header, (u_char *)packet);
	}
	
	pcap_dump_close(dumphandle);
	pcap_close(handle);
	return;
}

enum ACTION process_packet(const u_char *packet){
	struct ether_hdr *ethernet;
	struct ip_hdr *ip;
	enum PROTOCOL protocol;
	uint32_t srcip, dstip;
	uint16_t srcport, dstport;
	enum ACTION result = 0;
	
	ethernet = (struct ether_hdr *)packet;
	ip = (struct ip_hdr *)ethernet->data;
	srcip = ntohl(ip->srcip.s_addr);
    dstip = ntohl(ip->dstip.s_addr);

	struct findrule_hdr *find = (struct findrule_hdr *)malloc(sizeof(struct findrule_hdr));
	find->srcip = srcip;
	find->dstip = dstip;

	if(ip->protocol == IPPROTO_TCP){
		protocol = TCP;
		struct tcp_hdr *tcp;
		tcp = (struct tcp_hdr *)ip->options_and_data;
		srcport = ntohs(tcp->srcport);
		dstport = ntohs(tcp->dstport);

		/*struct findrule_hdr *find = (struct findrule_hdr *)malloc(sizeof(struct findrule_hdr));
		find->protocol = protocol;
		find->srcip = srcip;
		find->dstip = dstip;*/
		find->srcport = srcport;
		find->dstport = dstport;
		
		//result = find_rule(find);
	}	
	else if(ip->protocol == IPPROTO_UDP){
		protocol = UDP;
		//TODO
		//Enter TCP Handling code
		struct udp_hdr *udp;
		udp = (struct udp_hdr *)ip->options_and_data;
		memcpy(&srcport, udp->srcport, sizeof(uint16_t));
        memcpy(&dstport, udp->dstport, sizeof(uint16_t));
		srcport = ntohs(srcport);
		dstport = ntohs(dstport);

		find->srcport = srcport;
		find->dstport = dstport;
	}
	else if(ip->protocol == IPPROTO_ICMP){
		protocol = ICMP;
		//TODO
		//ENTER ICMP Handling code
		find->srcport = 0x0000;
		find->dstport = 0x0000;
	}
	
	find->protocol = protocol;
	result = find_rule(find);
	
	return result;
}
