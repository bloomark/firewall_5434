#ifndef _RULE_PARSE_H_
#define _RULE_PARSE_H_
#include <pthread.h>
#include <stdint.h>
#include "main.h"
#include "list.h"
#include "uthash.h"

enum ACTION{BLOCK, PASS};
enum PROTOCOL{TCP, ICMP, UDP, ANY};

pthread_mutex_t rules_lock;

char *file_name;

typedef struct rule_hdr{
	enum PROTOCOL protocol;
	uint32_t srcipstart;
	int srcipmask;
	uint32_t dstipstart;
	int dstipmask;
	uint16_t srcportstart;
	uint16_t srcportstop;
	uint16_t dstportstart;
	uint16_t dstportstop;
	enum ACTION action;
	struct list_head mylist;
}ruleheader;

typedef struct findrule_hdr{
	enum PROTOCOL protocol;
	uint32_t srcip;
	uint16_t srcport;
	uint32_t dstip;
	uint16_t dstport;
	enum ACTION action;
}findruleheader;

typedef struct{
    struct findrule_hdr key;
    UT_hash_handle hh;
} connection_hash_t;

connection_hash_t *flow_hash;

connection_hash_t *find_rule_in_hash(connection_hash_t l);
enum ACTION find_rule(struct findrule_hdr *find);
void read_rules();
void traverse_rules();
int matchsubnet(uint32_t ip1, uint32_t ip2, int mask);

struct list_head *rulepos;
struct rule_hdr rules;
#endif
