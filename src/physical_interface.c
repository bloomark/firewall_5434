#include "physical_interface.h"
#include "virtual_interface.h"

void physical_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    //static int count = 1;
    //printf("\nwlan0: Packet number [%d], length of this packet is: %d\n", count++, pkthdr->len);

    u_char *ep1_mac_addr = (u_char *)malloc(ETHER_ADDR_LEN * sizeof(u_char));
    hwaddr_aton(ep1_hwaddr, ep1_mac_addr);

	u_char *ep1s_mac_addr = (u_char *)malloc(ETHER_ADDR_LEN * sizeof(u_char));
    hwaddr_aton(ep1s_hwaddr, ep1s_mac_addr);

    struct ether_hdr *ethernet;
    ethernet = (struct ether_hdr *)packet;
	
	if(ntohs(ethernet->ethertype) == ETHERTYPE_IP){
		enum PROTOCOL protocol;
        enum ACTION result = 0;
		struct ip_hdr *ip;
		ip = (struct ip_hdr *)ethernet->data;
		if(ip->protocol == IPPROTO_ICMP){
			protocol = ICMP;
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
			
			//No need to modify the icmp packet

			/*Modifying the ipv4 header
			Change dstip to the ipaddress of ep1s
			Recompute checksum
			*/
			uint16_t ipchecksum = 0x0000;
			struct in_addr tmpip;
			inet_aton(ep1_ipaddr, &tmpip);
			ip->dstip = tmpip;
			memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));
			ipchecksum = ip_checksum(ip, sizeof(ip_hdr_t));
			memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));	
			
			/*Modifying the ethernet header
			Change the src_mac to ep1s
			Change the dst_mac to ep1
			*/
            memcpy(ethernet->src_mac, ep1s_mac_addr, ETHER_ADDR_LEN);
            memcpy(ethernet->dst_mac, ep1_mac_addr, ETHER_ADDR_LEN);

            if(pcap_sendpacket(ep1s_descr, (u_char *)ethernet, pkthdr->len) != 0)
                printf("Could't send ICMP packet to ep1s\n");
            else
                printf("Sent ICMP packet to ep1s\n");
		}
		else if(ip->protocol == IPPROTO_TCP){
			protocol = TCP;
			struct tcp_hdr *tcp;
			tcp = (struct tcp_hdr *)ip->options_and_data;

			if(tcp->flags == 0x2A)
				return;

			uint16_t natport = ntohs(tcp->dstport);
			if(tcpnat[natport].used != 1)
				return;
			
			struct findrule_hdr *state_find = (struct findrule_hdr *)malloc(sizeof(struct findrule_hdr));
            state_find->protocol = protocol;
            state_find->dstip = ntohl(ip->dstip.s_addr);
            state_find->srcip = ntohl(ip->srcip.s_addr);
            state_find->dstport = ntohs(tcp->dstport);
            state_find->srcport = ntohs(tcp->srcport);
			
			connection_hash_t hashed_rule;
    		memcpy(&(hashed_rule.key), state_find, sizeof(struct findrule_hdr));
			printf("%u:%u -> %u:%u\n", hashed_rule.key.srcip, hashed_rule.key.srcport, hashed_rule.key.dstip, hashed_rule.key.dstport);
			/*Statefullness not working :(*/
	    	hashed_rule.key.action = PASS;
			connection_hash_t *seen_before;
	    	seen_before = find_rule_in_hash(hashed_rule);
		    if(!seen_before && (tcp->flags == 0x11 || tcp->flags == 0x01)){
				printf("Not seen before!!!!\n\n");
    	    	return;
			}

			/////////////////////////////////////////////////////////
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

			/*Modifying the tcp header
			Set checksum to 0
			Change destination port to nat[natport]
			Recompute checksum
			*/
			uint16_t tcpchecksum = 0x0000;
            uint16_t blankify = 0x0000;
            memcpy(&tcpchecksum, tcp->checksum, 16);
            memcpy(tcp->checksum, &blankify, sizeof(uint16_t));

			/*Modifying the ipv4 header */
            uint16_t ipchecksum = 0x0000;
            struct in_addr tmpip;
            inet_aton(ep1_ipaddr, &tmpip);
            ip->dstip = tmpip;
            memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));
            ipchecksum = ip_checksum(ip, sizeof(ip_hdr_t));
            memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));    

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
            if(pseudo == NULL){
                printf("Couldn't malloc\n");
                exit(1);
            }

            //Copying data into the pseudo header           
            pseudo->srcip = ip->srcip;
            pseudo->dstip = ip->dstip;
            pseudo->zeroes = 0x00;
            pseudo->protocol = IPPROTO_TCP;
            pseudo->tcplen = tcplen;
            memcpy(&(pseudo->srcport), &(tcp->srcport), ntohs(pseudo->tcplen));

            //Calculate TCP Checksum
            tcpchecksum = 0x0000;
            tcpchecksum = ip_checksum(pseudo, 12 + ntohs(tcplen));
            memcpy(tcp->checksum, &tcpchecksum, sizeof(uint16_t));
            free(pseudo);

            /*Modifying the ethernet header */
            memcpy(ethernet->src_mac, ep1s_mac_addr, ETHER_ADDR_LEN);
            memcpy(ethernet->dst_mac, ep1_mac_addr, ETHER_ADDR_LEN);

            if(pcap_sendpacket(ep1s_descr, (u_char *)ethernet, pkthdr->len) != 0)
                printf("Could't send TCP packet to ep1s\n");
            else
                printf("Sent TCP packet to ep1s\n");
		}
		else if(ip->protocol == IPPROTO_UDP){
			protocol = UDP;
			struct udp_hdr *udp;
            udp = (struct udp_hdr *)ip->options_and_data;
            uint16_t srcport, dstport;
			memcpy(&srcport, udp->srcport, sizeof(uint16_t));
            memcpy(&dstport, udp->dstport, sizeof(uint16_t));

			/*uint16_t natport = ntohs(tcp->dstport);
            if(tcpnat[natport].used != 1)
                return;
			*/

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

			uint16_t udpchecksump = 0x0000;
            memcpy(udp->checksum, &udpchecksump, sizeof(uint16_t));

			/*Modifying the ipv4 header */
            uint16_t ipchecksum = 0x0000;
            struct in_addr tmpip;
            inet_aton(ep1_ipaddr, &tmpip);
            ip->dstip = tmpip;
            memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));
            ipchecksum = ip_checksum(ip, sizeof(ip_hdr_t));
            memcpy(ip->checksum, &ipchecksum, sizeof(uint16_t));

			/*Modifying the ethernet header */
            memcpy(ethernet->src_mac, ep1s_mac_addr, ETHER_ADDR_LEN);
            memcpy(ethernet->dst_mac, ep1_mac_addr, ETHER_ADDR_LEN);

			if(pcap_sendpacket(ep1s_descr, (u_char *)ethernet, pkthdr->len) != 0)
                printf("Couldn't send UDP packet to physical interface\n");
            else
                printf("Sent UDP packet to physical interface\n");			
		}
	}
}

/* Based on the implementation here
http://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap*/
void* read_physical_interface(){
    //char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;        // to hold compiled program
    bpf_u_int32 pMask;            // subnet mask
    bpf_u_int32 pNet;             // ip address
    //pcap_if_t *alldevs, *d;
    //char dev_buff[64] = {0};
	
    //dev = "wlan0";
    // fetch the network address and network mask
    pcap_lookupnet(physical_dev, &pNet, &pMask, errbuf);

    // Now, open device for sniffing
    wlan_descr = pcap_open_live(physical_dev, BUFSIZ, 0,-1, errbuf);
    if(wlan_descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
		exit(1);
    }
	
    // Compile the filter expression
    if(pcap_compile(wlan_descr, &fp, '\0', 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        exit(1);
    }

    // Set the filter compiled above
    if(pcap_setfilter(wlan_descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

	count = 0;	
    // For every packet received, call the callback function
    // For now, maximum limit on number of packets is specified
    // by user.
    pcap_loop(wlan_descr, -1, physical_callback, NULL);
	
	pcap_close(wlan_descr);
    printf("\nDone with packet sniffing on the physical interface!\n");
    return 0;
}
