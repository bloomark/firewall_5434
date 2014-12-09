#include <pthread.h>
#include <time.h>
#include "main.h"
#include "rule_parse.h"
#include "virtual_interface.h"
#include "physical_interface.h"

pthread_t threads[4];

void init(){
	printf("Size of pseudo - %zd\n", sizeof(struct pseudo_hdr));
	flow_hash = NULL;
	
	INIT_LIST_HEAD(&rules.mylist);
    file_name = "input_rules.txt";
    read_rules();
    traverse_rules();

    ep1_hwaddr = "c2:c9:ed:6e:6d:70";
    ep1s_hwaddr = "42:e7:1f:18:f0:5f";
	ep1_ipaddr = "10.0.0.1";

	wlan_ipaddr = "10.132.3.205";
	wlan_hwaddr = "00:23:14:d0:6a:30";
	gateway_hwaddr = "00:17:df:cc:18:00";

	virtual_dev = "ep1s";
	physical_dev = "wlan0";
}

/*
 From http://www.dreamincode.net/forums/topic/69684-how-to-use-rand-in-a-certain-range-of-numbers/
 */
uint16_t getrand(int min, int max){
	return(rand()%(max-min)+min);
}

/*
 From Z's slides
 */
uint32_t unpack_32(uint8_t *buf){
    uint32_t val;
    memcpy(&val, buf, sizeof(uint32_t));
    return ntohl(val);
}

void pack_32(uint32_t val, uint8_t *buf){
    val = htonl(val);
    memcpy(buf, &val, sizeof(uint32_t));
}

int hex2dec(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/*
 Based on some code I found on github, unable to find the source right now
 */
int hwaddr_aton(char *txt, u_char *addr){
    int i;
    for (i = 0; i < 6; i++)
    {
        int a, b;

        a = hex2dec(*txt++);
        if (a < 0)
            return -1;
        b = hex2dec(*txt++);
        if (b < 0)
            return -1;
        *addr++ = (a << 4) | b;
        if (i < 5 && *txt++ != ':')
            return -1;
    }
    return 0;
}

char *hwaddr_ntoa(const unsigned char *hwaddr, size_t hwlen){
    char *p = hwaddr_buffer;
    size_t i;

    for (i = 0; i < hwlen && i < ETHER_ADDR_LEN; i++) {
        if (i > 0)
            *p ++= ':';
        p += snprintf(p, 3, "%.2x", hwaddr[i]);
    }

    *p ++= '\0';

    return hwaddr_buffer;
}

/*
 Find the checksum of a given span of data. 
 Taken from http://stackoverflow.com/questions/1962746/how-do-i-compute-an-rfc-791-ip-header-checksum
 */
uint16_t ip_checksum(void* vdata, size_t length){
	size_t hdr_len = length;
	unsigned long sum = 0;
	const uint16_t *ip1;
 
	ip1 = vdata;
	while (hdr_len > 1)
	{
	sum += *ip1++;
	if (sum & 0x80000000)
		sum = (sum & 0xFFFF) + (sum >> 16);
		hdr_len -= 2;
	}
 
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return(~sum);
}
/*uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}*/

int main(int argc, char **argv){
    /*INIT_LIST_HEAD(&rules.mylist);
    file_name = "input_rules.txt";
	read_rules();
	traverse_rules();
	ep1_hwaddr = "06:9f:d8:90:e5:11";
	ep1s_hwaddr = "3a:91:cb:1b:e0:de";*/
	init();
	
	if(argc == 2){
		printf("Reading pcap file %s...\n", argv[1]);
		read_pcap_file(argv[1]);
		printf("Done reading pcap file!\n");
	}
	else{
		printf("Running with real traffic\n");
		int res;
		res = pthread_create(&(threads[0]), NULL, &read_virtual_interface, NULL);
		if(res != 0){
			printf("Couldn't start virtual_interface thread\n");
			exit(1);
		}
		res = pthread_create(&(threads[1]), NULL, &read_physical_interface, NULL);
		if(res != 0){
			printf("Couldn't start physical_interface thread\n");
		}
		pthread_join(threads[0], NULL);
		pthread_join(threads[1], NULL);
	}

	return 0;
}
