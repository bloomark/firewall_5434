#include "virtual_interface.h"
#include "physical_interface.h"

void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    //static int count = 1;
    //printf("\nep1s: Packet number [%d], length of this packet is: %d\n", count++, pkthdr->len);

    struct ether_hdr *ethernet;
    ethernet = (struct ether_hdr *)packet;

    if(ntohs(ethernet->ethertype) == ETHERTYPE_ARP){
        //printf("Ethertype = %u\n", (unsigned int)ntohs(ethernet->ethertype));
        struct arp_hdr *arp;
        arp = (struct arp_hdr *)ethernet->data;
        if(memcmp(ep1_mac_addr, arp->sender_mac, ETHER_ADDR_LEN) == 0){

            memcpy(ethernet->dst_mac, ethernet->src_mac, ETHER_ADDR_LEN);
            memcpy(ethernet->src_mac, ep1s_mac_addr, ETHER_ADDR_LEN);

            memcpy(arp->receiver_mac, arp->sender_mac, ETHER_ADDR_LEN);
            memcpy(arp->sender_mac, ep1s_mac_addr, ETHER_ADDR_LEN);

            uint32_t temp;
            memcpy(&temp, arp->srcip, sizeof(uint32_t));
            memcpy(arp->srcip, arp->dstip, sizeof(uint32_t));
            memcpy(arp->dstip, &temp, sizeof(uint32_t));

            uint16_t temp_oper = htons(2);
            memcpy(arp->oper, &temp_oper, sizeof(uint16_t));

            if(pcap_sendpacket(ep1s_descr, (u_char *)ethernet, pkthdr->len) != 0)
                printf("Could't send ARP response\n");
            else
                printf("Sent ARP response\n");
        }
    }
	else if(ntohs(ethernet->ethertype) == ETHERTYPE_IP){
		enum PROTOCOL protocol;
		enum ACTION result = 0;
		struct ip_hdr *ip;
		ip = (struct ip_hdr *)ethernet->data;
		if(ip->protocol == IPPROTO_ICMP){
			protocol = ICMP;

			//No need to modify the icmp packet

			/*Modifying the ipv4 header
			Change srcip to ipaddress of wlan0
			Recalculate checksum
			*/
			uint16_t ipchecksum = 0x0000;
			struct in_addr tmpip;
			inet_aton(wlan_ipaddr, &tmpip);
			ip->srcip = tmpip;
			memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));
			ipchecksum = ip_checksum(ip, sizeof(ip_hdr_t));
			memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));

			/*Modify the ethernet header
			src_mac is the mac address of wlan0
			dst_mac is the mac address of the gateway
			*/
			memcpy(ethernet->src_mac, wlan_mac_addr, ETHER_ADDR_LEN);
			memcpy(ethernet->dst_mac, gateway_mac_addr, ETHER_ADDR_LEN);

			struct findrule_hdr *find = (struct findrule_hdr *)malloc(sizeof(struct findrule_hdr));
	        find->protocol = protocol;
			find->srcip = ntohl(ip->srcip.s_addr);
	        find->dstip = ntohl(ip->dstip.s_addr);
	        find->srcport = 0;
    	    find->dstport = 0;

			result = find_rule(find);
			free(find);				
			if(result == BLOCK){
				printf("Blocked packet.\n");
					return;
			}

			if(pcap_sendpacket(wlan_descr, (u_char *)ethernet, pkthdr->len) != 0)
				printf("Couldn't send ICMP packet to physical interface\n");
			else
				printf("Sent ICMP packet to physical interface\n");
		}
		else if(ip->protocol == IPPROTO_TCP){
			protocol = TCP;
			struct tcp_hdr *tcp;
			tcp = (struct tcp_hdr *)ip->options_and_data;
			
			/*Perform NAT on the port numbers
			Get a random number in the range 50000 to 65535 and if it is already mapped to a port, reroll.
			This is the outgoing portnumber on the physical interface
			*/
			uint16_t natport = ntohs(tcp->srcport);
			tcpnat[natport].used = 1;
			
			/*Modifying the TCP header
			Set checksum to 0.
			Change sourceport to the natport.
			Recompute the checksum.
			*/
			uint16_t tcpchecksum = 0x0000;
			uint16_t blankify = 0x0000;
			memcpy(&tcpchecksum, tcp->checksum, 16);
			memcpy(tcp->checksum, &blankify, sizeof(uint16_t));

			//Modifying the IP header
			uint16_t ipchecksum = 0x0000;
            struct in_addr tmpip;
            inet_aton(wlan_ipaddr, &tmpip);
            ip->srcip = tmpip;
            memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));
            ipchecksum = ip_checksum(ip, sizeof(ip_hdr_t));
            memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));
		
			/*uint16_t totlen;
			memcpy(&totlen, ip->total_len, sizeof(uint16_t));
			totlen = ntohs(totlen);
	
			uint16_t tcpoptlen = tcp->offset_rsvd&0x00f0;
			tcpoptlen = tcpoptlen>>4;
			tcpoptlen = tcpoptlen * 4 - 20;
			printf("Offset = %u\n", tcpoptlen);

			uint16_t iphl = ip->version_ihl&0x000f;
            iphl *= 4;

			uint16_t tcpdatalen = totlen - (tcpoptlen + 20) - iphl;

			uint16_t pseudotcplen = sizeof(struct tcp_hdr) + sizeof(struct pseudo_hdr) + tcpdatalen;*/

			/*Create pseudoheader
			Compute TCP checksum*/
			uint16_t iphl = ip->version_ihl&0x000f;
			iphl *= 4;
			uint16_t totlen;
			memcpy(&totlen, ip->total_len, sizeof(uint16_t));
			totlen = ntohs(totlen);
			uint16_t tcplen = totlen - iphl;
			if(tcplen % 2 == 1)
				tcplen++;
			//tcplen = htons(tcplen);
			
			struct pseudo_hdr *pseudo = (struct pseudo_hdr *)calloc(1, sizeof(struct pseudo_hdr) + (tcplen - sizeof(struct tcp_hdr)));
			tcplen = htons(tcplen);
			//struct pseudo_hdr *pseudo = (struct pseudo_hdr *)malloc(pseudotcplen);
			if(pseudo == NULL){
				printf("Couldn't malloc\n");
				exit(1);
			}

			//Copying data into the pseudo header			
			pseudo->srcip = ip->srcip;
			pseudo->dstip = ip->dstip;
			pseudo->zeroes = 0x00;
			pseudo->protocol = IPPROTO_TCP;
			//pseudo->tcplen = htons(sizeof(struct tcp_hdr) + tcpoptlen + tcpdatalen);
			pseudo->tcplen = tcplen;
			memcpy(&(pseudo->srcport), &(tcp->srcport), ntohs(pseudo->tcplen));
			
			//Calculate TCP Checksum
			tcpchecksum = 0x0000;
			tcpchecksum = ip_checksum(pseudo, 4*3 + ntohs(tcplen));
			//tcpchecksum = ip_checksum(pseudo, pseudotcplen);
			memcpy(tcp->checksum, &tcpchecksum, sizeof(uint16_t));
			free(pseudo);

			//Modifying the Ethernet header
			memcpy(ethernet->src_mac, wlan_mac_addr, ETHER_ADDR_LEN);
            memcpy(ethernet->dst_mac, gateway_mac_addr, ETHER_ADDR_LEN);
		
			struct findrule_hdr *find = (struct findrule_hdr *)malloc(sizeof(struct findrule_hdr));
            find->protocol = protocol;
            find->srcip = ntohl(ip->srcip.s_addr);
            find->dstip = ntohl(ip->dstip.s_addr);
            find->srcport = ntohs(tcp->srcport);
            find->dstport = ntohs(tcp->dstport);

			result = find_rule(find);
            free(find);
            if(result == BLOCK){
                printf("Blocked packet.\n");
                    return;
            }

            if(pcap_sendpacket(wlan_descr, (u_char *)ethernet, pkthdr->len) != 0)
                printf("Couldn't send TCP packet to physical interface\n");
            else
                printf("Sent TCP packet to physical interface\n");
		}
		else if(ip->protocol == IPPROTO_UDP){
			protocol = UDP;
			struct udp_hdr *udp;
			udp = (struct udp_hdr *)ip->options_and_data;
			uint16_t srcport, dstport;
			memcpy(&srcport, udp->srcport, sizeof(uint16_t));
			memcpy(&dstport, udp->dstport, sizeof(uint16_t));
			printf("Source port = %u\nDestination port = %u\n", ntohs(srcport), ntohs(dstport));

			/*Perform NAT on the port numbers
            Get a random number in the range 50000 to 65535 and if it is already mapped to a port, reroll.
            This is the outgoing portnumber on the physical interface
            */
            uint16_t natport = ntohs(srcport);
            tcpnat[natport].used = 1;
			
			uint16_t udpchecksump = 0x0000;
			memcpy(udp->checksum, &udpchecksump, sizeof(uint16_t));
			
			//Modifying the IP header
            uint16_t ipchecksum = 0x0000;
            struct in_addr tmpip;
            inet_aton(wlan_ipaddr, &tmpip);
            ip->srcip = tmpip;
            memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));
            ipchecksum = ip_checksum(ip, sizeof(ip_hdr_t));
            memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));	

			/*Modify the ethernet header
            src_mac is the mac address of wlan0
            dst_mac is the mac address of the gateway
            */
            memcpy(ethernet->src_mac, wlan_mac_addr, ETHER_ADDR_LEN);
            memcpy(ethernet->dst_mac, gateway_mac_addr, ETHER_ADDR_LEN);

            struct findrule_hdr *find = (struct findrule_hdr *)malloc(sizeof(struct findrule_hdr));
            find->protocol = protocol;
            find->srcip = ntohl(ip->srcip.s_addr);
            find->dstip = ntohl(ip->dstip.s_addr);
            find->srcport = ntohs(srcport);
            find->dstport = ntohs(dstport);

            result = find_rule(find);
            free(find);
            if(result == BLOCK){
                printf("Blocked packet.\n");
                    return;
            }

            if(pcap_sendpacket(wlan_descr, (u_char *)ethernet, pkthdr->len) != 0)
                printf("Couldn't send UDP packet to physical interface\n");
            else
                printf("Sent UDP packet to physical interface\n");
		}
	}
}

/* Based on the implementation here 
http://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap*/
void* read_virtual_interface(){
    //char *virtual_dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    //pcap_if_t *alldevs, *d;
    //char dev_buff[64] = {0};

	printf("Malloc 1\n");
    ep1_mac_addr = (u_char *)malloc(ETHER_ADDR_LEN * sizeof(u_char));
    hwaddr_aton(ep1_hwaddr, ep1_mac_addr);

    printf("Malloc 2\n");
    wlan_mac_addr = (u_char *)malloc(ETHER_ADDR_LEN * sizeof(u_char));
    hwaddr_aton(wlan_hwaddr, wlan_mac_addr);

    printf("Malloc 3\n");
    gateway_mac_addr = (u_char *)malloc(ETHER_ADDR_LEN *sizeof(u_char));
    hwaddr_aton(gateway_hwaddr, gateway_mac_addr);

	ep1s_mac_addr = (u_char *)malloc(ETHER_ADDR_LEN * sizeof(u_char));
	hwaddr_aton(ep1s_hwaddr, ep1s_mac_addr);

    //virtual_dev = "ep1s";
    // fetch the network address and network mask
    pcap_lookupnet(virtual_dev, &pNet, &pMask, errbuf);

    // Now, open device for sniffing
    ep1s_descr = pcap_open_live(virtual_dev, BUFSIZ, 0,-1, errbuf);
    if(ep1s_descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
		exit(1);
    }

    // Compile the filter expression
    if(pcap_compile(ep1s_descr, &fp, '\0', 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        exit(1);
    }

    // Set the filter compiled above
    if(pcap_setfilter(ep1s_descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    // For every packet received, call the callback function
    // For now, maximum limit on number of packets is specified
    // by user.
    pcap_loop(ep1s_descr, -1, callback, NULL);

	pcap_close(ep1s_descr);
    printf("\nDone with packet sniffing on ep1s!\n");
    return 0;
}
