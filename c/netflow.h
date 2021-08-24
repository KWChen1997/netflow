#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#ifndef MYNETFLOW
#define MYNETFLOW

#define NIPQUAD(addr) \
	((unsigned char*)&addr)[0], \
	((unsigned char*)&addr)[1], \
	((unsigned char*)&addr)[2], \
	((unsigned char*)&addr)[3]

#define NIPQUAD_FORMAT "%u.%u.%u.%u"

struct filter{
	uint32_t saddr;
	uint32_t smask;
	uint32_t daddr;
	uint32_t dmask;
};

struct connection {
	char proto;
	uint32_t saddr;
	uint16_t sport;
	uint32_t daddr;
	uint16_t dport;
	uint64_t packets;
	uint64_t bytes;
	uint8_t valid;
};

struct track{
	char type[10];
        char ip1[16];
	uint16_t port1;
	uint16_t port2;
        char ip2[16];
        uint64_t packets;
        uint64_t bytes;
};

void connection_init();
void connection_add(struct connection *conn);
void connection_expand();
void connection_history();
void connection_top5();
int connection_comp(const void *lhs, const void *rhs);
int test(struct connection *connection, struct filter *filter);
char* ntoa(uint32_t net);
uint32_t createmask(int num);
#endif
