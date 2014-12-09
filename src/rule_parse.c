#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rule_parse.h"
#include "list.h"

void read_rules(){
	if(pthread_mutex_init(&(rules_lock),NULL) != 0){
        printf("Couldn't initialize rules_lock\n");
        exit(1);
    }
	
	printf("Reading rules from %s...\n", file_name);
	FILE *fp;

	fp = fopen(file_name, "r");
	
	if(fp == NULL){
		printf("Couldn't open file\n");
		exit(1);
	}

	char line[256];
	
	while(fgets(line, sizeof(line), fp)){
		struct rule_hdr *new_rule;
		new_rule = (struct rule_hdr *)malloc(sizeof(struct rule_hdr));
		
		char *newline = line;
		char *rest;
		char *token;
		
		//ACTION
		token = strtok_r(newline, " ", &rest);
		newline = rest;
		if(strcmp(token, "allow") == 0)
			new_rule->action = PASS;
		else
			new_rule->action = BLOCK;

		//PROTOCOL
		token = strtok_r(newline, " ", &rest);
        newline = rest;
		if(strcmp(token, "tcp") == 0)
			new_rule->protocol = TCP;
		else if(strcmp(token, "udp") == 0)
			new_rule->protocol = UDP;
		else if(strcmp(token, "icmp") == 0)
			new_rule->protocol = ICMP;
		else if(strcmp(token, "any") == 0)
			new_rule->protocol = ANY;

		//SRCIP
		token = strtok_r(newline, " ", &rest);
        newline = rest;
		if(strcmp(token, "any") == 0){
			new_rule->srcipstart = 0;
			new_rule->srcipmask = 32;
			//new_rule->srcipstop = 4294967295;
		}
		else{
			struct in_addr sip;
			char *temp = token, *save;
			char *ipaddr = strtok_r(temp, "/", &save);
			char *mask = strtok_r(NULL, "/", &save);
			inet_aton(ipaddr, &sip);
			new_rule->srcipstart = htonl(sip.s_addr);
			if(mask == NULL) new_rule->srcipmask = 0;
			else new_rule->srcipmask = atoi(mask);
		}

		//SRCPORT
		token = strtok_r(newline, " ", &rest);
        newline = rest;
		if(strcmp(token, "any") == 0){
			new_rule->srcportstart = 0;
			new_rule->srcportstop = 65535;
		}
		else{
			char *startport, *endport;
			char *temp = token, *save;
			
			startport = strtok_r(temp, "-", &save);
			endport = strtok_r(NULL, "-", &save);

			new_rule->srcportstart = atoi(startport);
			if(endport == NULL) new_rule->srcportstop = new_rule->srcportstart;
            else new_rule->srcportstop = atoi(endport);
			printf("%d-%d\n", new_rule->srcportstart, new_rule->srcportstop);
		}

		//DSTIP
		token = strtok_r(newline, " ", &rest);
        newline = rest;
        if(strcmp(token, "any") == 0){
            new_rule->dstipstart = 0;
			new_rule->dstipmask = 32;
			//new_rule->dstipstop = 4294967295;
		}
        else{
			struct in_addr dip;
            char *temp = token, *save;
            char *ipaddr = strtok_r(temp, "/", &save);
            char *mask = strtok_r(NULL, "/", &save);
            inet_aton(ipaddr, &dip);
            new_rule->dstipstart = htonl(dip.s_addr);
            if(mask == NULL) new_rule->dstipmask = 0;
            else new_rule->dstipmask = atoi(mask);
        }

		//DSTPORT
		token = strtok_r(newline, " ", &rest);
        newline = rest;
		if(strncmp(token, "any", 3) == 0){
            new_rule->dstportstart = 0;
            new_rule->dstportstop = 65535;
        }
        else{
            char *startport, *endport;
            char *temp = token, *save;

            startport = strtok_r(temp, "-", &save);
            endport = strtok_r(NULL, "-", &save);

            new_rule->dstportstart = atoi(startport);
            if(endport == NULL) new_rule->dstportstop = new_rule->dstportstart;
            else new_rule->dstportstop = atoi(endport);
            printf("%d-%d\n", new_rule->dstportstart, new_rule->dstportstop);
        }
		
		pthread_mutex_lock(&rules_lock);
		//Adds a new rule at the head of the linked list
		list_add_tail(&(new_rule->mylist), &(rules.mylist));
		pthread_mutex_unlock(&rules_lock);
	}
	printf("Initialized rules!\n");
	fclose(fp);
	return;
}

void traverse_rules(){
	printf("ACTION\tPROT\tSOURCE IP\tSRCPORT\tDESTINATION IP\tDSTPORT\n");
	struct rule_hdr *current;

	pthread_mutex_lock(&rules_lock);
	list_for_each(rulepos, &rules.mylist){
		current = list_entry(rulepos, struct rule_hdr, mylist);
		printf("%d\t%d\t%u\t%d\t%u\t%d\n", current->action, current->protocol, current->srcipstart,
		current->srcportstop, current->dstipstart, current->dstportstop);
	}
	pthread_mutex_unlock(&rules_lock);

	printf("Done printing rules!\n");
	return;
}

connection_hash_t *find_rule_in_hash(connection_hash_t l){
	//printf("Searching hash\n");
	connection_hash_t *s;
	HASH_FIND(hh, flow_hash, &l.key, sizeof(struct findrule_hdr), s);
	return s;
}

enum ACTION find_rule(struct findrule_hdr *find){
    pthread_mutex_lock(&rules_lock);
	connection_hash_t hashed_rule;
	memcpy(&(hashed_rule.key), find, sizeof(struct findrule_hdr));
	
	connection_hash_t *blocked, *allowed;
	hashed_rule.key.action = BLOCK;
	blocked = find_rule_in_hash(hashed_rule);
	if(blocked){
		printf("Found blocked rule in hash\n");
		pthread_mutex_unlock(&rules_lock);
		return BLOCK;
	}

	hashed_rule.key.action = PASS;
	allowed = find_rule_in_hash(hashed_rule);
    if(allowed){
        printf("Found allowed rule in hash\n");
		pthread_mutex_unlock(&rules_lock);
        return PASS;
    }
	
	printf("Searching for rule %u:%d -> %u:%d in the rule list...\n", find->srcip, find->srcport, find->dstip, find->dstport);
	struct rule_hdr *current;

	connection_hash_t *r = (connection_hash_t *)malloc(sizeof(connection_hash_t));
    //pthread_mutex_lock(&rules_lock);
    list_for_each(rulepos, &rules.mylist){
        current = list_entry(rulepos, struct rule_hdr, mylist);
		if(current->protocol == find->protocol || current->protocol == ANY){
		if(matchsubnet(current->srcipstart, find->srcip, current->srcipmask)){
			if(current->srcportstart <= find->srcport && current->srcportstop >= find->srcport){
				if(matchsubnet(current->dstipstart, find->dstip, current->dstipmask)){
					if(current->dstportstart <= find->dstport && current->dstportstop >= find->dstport){
						//connection_hash_t *r = (connection_hash_t *)malloc(sizeof(connection_hash_t));
						memcpy(&(r->key), find, sizeof(struct findrule_hdr));
						if(current->action == PASS){
							r->key.action = PASS;
							printf("Hashing pass\n");
							HASH_ADD(hh, flow_hash, key, sizeof(struct findrule_hdr), r);
							pthread_mutex_unlock(&rules_lock);
							return PASS;
						}
						else{
							r->key.action = BLOCK;
							printf("Hashing block\n");
							HASH_ADD(hh, flow_hash, key, sizeof(struct findrule_hdr), r);
							pthread_mutex_unlock(&rules_lock);
							return BLOCK;
						}
					}
				}
			}
		}
		}
	}

	memcpy(&(r->key), find, sizeof(struct findrule_hdr));
	r->key.action = BLOCK;
	printf("Hashing block\n");
	HASH_ADD(hh, flow_hash, key, sizeof(struct findrule_hdr), r);
	pthread_mutex_unlock(&rules_lock);	
	printf("Couldn't find rule.\n");

	return BLOCK;
}

int matchsubnet(uint32_t ip1, uint32_t ip2, int mask){
	uint32_t m;
	if(mask == 32)
		return 1;
	else{
		m = ((~0) << (mask));
		if((ip1&m) == (ip2&m))
			return 1;
		else
			return 0;
	}
}
