#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include<sys/un.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include "netflow.h"

#define TRACK_CAP 65535
#define HASHSIZE 65535

unsigned int cap;
unsigned int idx;
struct connection *history;
struct connection *rate;
unsigned int list[65536];
struct nfct_handle *h;
int family;
int filefd;
int sockfd;
int clifd;


unsigned int min(unsigned int a, unsigned int b){
	return (a < b)? a : b;
}

int test(struct connection *connection, struct filter *filter){
	return (filter->saddr == 0 || ((ntohl(connection->saddr) & filter->smask) == (ntohl(filter->saddr) & filter->smask))) &&
	       (filter->daddr == 0 || ((ntohl(connection->daddr) & filter->dmask) == (ntohl(filter->daddr) & filter->dmask)));
}

uint32_t createmask(int num){
	uint32_t mask = 0xFFFFFFFF;
	mask = (mask >> (32 - num)) << (32 - num);
	return mask;
}

/*
 * hash function to map (ip1,ip2,port1,port2) -> int
 * */
unsigned int hash1(uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2){
	unsigned int hashval = 0;

	hashval = (hashval * 31 +  ((unsigned char*)&ip1)[0]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip1)[1]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip1)[2]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip1)[3]) % HASHSIZE;

	hashval = (hashval * 31 +  ((unsigned char*)&ip2)[0]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip2)[1]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip2)[2]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip2)[3]) % HASHSIZE;

	hashval = (port1 + 31 * hashval) % HASHSIZE;
	hashval = (port2 + 31 * hashval) % HASHSIZE;

	return hashval;
}

/*
 * hash function to map (ip1,ip2,port1,port2) -> int
 * */
unsigned int hash2(uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2){
	unsigned int hashval = 0;

	hashval = (hashval * 37 +  ((unsigned char*)&ip1)[0]) % HASHSIZE;
	hashval = (hashval * 37 +  ((unsigned char*)&ip1)[1]) % HASHSIZE;
	hashval = (hashval * 37 +  ((unsigned char*)&ip1)[2]) % HASHSIZE;
	hashval = (hashval * 37 +  ((unsigned char*)&ip1)[3]) % HASHSIZE;

	hashval = (hashval * 37 +  ((unsigned char*)&ip2)[0]) % HASHSIZE;
	hashval = (hashval * 37 +  ((unsigned char*)&ip2)[1]) % HASHSIZE;
	hashval = (hashval * 37 +  ((unsigned char*)&ip2)[2]) % HASHSIZE;
	hashval = (hashval * 37 +  ((unsigned char*)&ip2)[3]) % HASHSIZE;

	hashval = (port1 + 37 * hashval) % HASHSIZE;
	hashval = (port2 + 37 * hashval) % HASHSIZE;

	return hashval;
}


char *ntoa(uint32_t net){

	char *ip = (char*)malloc(sizeof(char)*16);
	snprintf(ip,16,"%u.%u.%u.%u", NIPQUAD(net));
	return ip;
}


/*
 * initialize the memory for saving connection data and packet rate
 * */
void connection_init(){
	assert(history == NULL);
	assert(rate == NULL);

	history = (struct connection*)malloc(sizeof(struct connection) * TRACK_CAP);
	if(history == NULL){
		perror("history malloc failed!");
		exit(1);
	}
	memset(history, 0, sizeof(struct connection) * TRACK_CAP);

	rate = (struct connection*)malloc(sizeof(struct connection) * TRACK_CAP);
	if(rate == NULL){
		perror("history malloc failed!");
		exit(1);
	}
	memset(rate, 0, sizeof(struct connection) * TRACK_CAP);
	
	memset(list,0,sizeof(unsigned int) * TRACK_CAP);
	idx = 0;
	cap = 0;
	return;
}

/*
 * update the state of the connection and calculate the packet rate
 * */
void connection_add(struct connection *conn){
	int j = 0;
	unsigned int h1 = hash1(conn->saddr,conn->daddr,conn->sport,conn->dport);
	unsigned int h2 = hash2(conn->saddr,conn->daddr,conn->sport,conn->dport);

	unsigned int hashval = h1;
	struct connection *target = history + hashval;
	while(target->valid){
		if(target->proto == conn->proto &&
			target->saddr == conn->saddr &&
			target->daddr == conn->daddr &&
			target->sport == conn->sport &&
			target->dport == conn->dport){
			break;
		}
		fprintf(stderr, "Collision %d\n", j);
		j++;
		hashval = (h1 + (j * h2) % HASHSIZE ) % HASHSIZE;
		target = history + hashval;
	}
	memcpy(rate + hashval, conn, sizeof(struct connection));
	rate[hashval].packets -= history[hashval].packets;
	rate[hashval].bytes -= history[hashval].bytes;
	memcpy(target, conn, sizeof(struct connection));
	list[idx] = hashval;
	idx++;
	return;
}

/*
 * print all the tracked connections
 * */
void connection_history(){
	int i = 0;
	struct timeval curTime;
	gettimeofday(&curTime, NULL);
	time_t rawtime;
	struct tm *timeinfo;
	char buf[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(buf, 80, "%H:%M:%S", timeinfo);

	fprintf(stderr,"-------------------\n");
	fprintf(stderr,"Current time: %s.%03ld\n",buf,curTime.tv_usec/1000);
	
	fprintf(stderr,"%-10s %-15s %-7s %-15s %-7s %10s %10s\n","type", "ip1", "port1", "ip2", "port2", "packets", "bytes");
	for(i = 0; i < idx; i++){
		fprintf(stderr,"%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n", getprotobynumber(history[list[i]].proto)->p_name, ntoa(history[list[i]].saddr), history[list[i]].sport, ntoa(history[list[i]].daddr), history[list[i]].dport, history[list[i]].packets, history[list[i]].bytes);
		//write(STDOUT_FILENO, history + list[i], sizeof(struct connection));
	}
	
	//write(STDOUT_FILENO, &(struct connection){.proto = 0, .saddr = 0, .sport = 0, .daddr = 0, .dport = 0, .packets = 0, .bytes = 0, .valid = 0}, sizeof(struct connection));
	
	return;
}

/*
 * print all the tracked connection rate
 * */
void connection_rate(){
	int i = 0;
	struct timeval curTime;
	gettimeofday(&curTime, NULL);
	time_t rawtime;
	struct tm *timeinfo;
	char buf[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(buf, 80, "%H:%M:%S", timeinfo);

	fprintf(stderr,"-------------------\n");
	fprintf(stderr,"Current time: %s.%03ld\n",buf,curTime.tv_usec/1000);
	
	fprintf(stderr,"%-10s %-15s %-7s %-15s %-7s %10s %10s\n","type", "ip1", "port1", "ip2", "port2", "packets", "bytes");
	for(i = 0; i < idx; i++){
		fprintf(stderr,"%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n", getprotobynumber(rate[list[i]].proto)->p_name, ntoa(rate[list[i]].saddr), rate[list[i]].sport, ntoa(rate[list[i]].daddr), rate[list[i]].dport, rate[list[i]].packets, rate[list[i]].bytes);
		//write(STDOUT_FILENO, rate + list[i], sizeof(struct connection));
	}
	
	//write(STDOUT_FILENO, &(struct connection){.proto = 0, .saddr = 0, .sport = 0, .daddr = 0, .dport = 0, .packets = 0, .bytes = 0, .valid = 0}, sizeof(struct connection));
	
	return;
}


/*
 * sort all the tracked connection by packet counts
 * */
int connection_list_comp(const void *lhs, const void *rhs){
	struct connection *tlhs = rate + *(unsigned int*)lhs;
	struct connection *trhs = rate + *(unsigned int*)rhs;
	return (trhs->packets - tlhs->packets);
}

/*
 * callback function for conntrack query
 * */
int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data){

	struct connection connection;
	struct filter *filter = data;

	memset(&connection,0,sizeof(struct connection));

	connection.valid = 1;

	// extract information from nf_conntrack object
	if(nfct_attr_is_set(ct,ATTR_ORIG_L4PROTO)){	
		connection.proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_IPV4_SRC)){
		connection.saddr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_IPV4_DST)){
		connection.daddr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_PORT_SRC)){
		connection.sport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_PORT_DST)){
		connection.dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_COUNTER_PACKETS)){
		connection.packets += nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
	}
	if(nfct_attr_is_set(ct,ATTR_REPL_COUNTER_PACKETS)){
		connection.packets += nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_COUNTER_BYTES)){
		connection.bytes += nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
	}
	if(nfct_attr_is_set(ct,ATTR_REPL_COUNTER_BYTES)){
		connection.bytes += nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
	}

	// simple filter for conntrack data
	if(!test(&connection,filter)){
		return 	NFCT_CB_CONTINUE;
	}

	// update the conntrack data list
	connection_add(&connection);
	// keep track of the 5 connections with highest packet rate
	//qsort(top,6,sizeof(struct connection), connection_comp);
	
	return NFCT_CB_CONTINUE;
}

void sigtimer(int signo){
	int ret;
	idx = 0;
	//connection_clear_top();
	memset(list,0,sizeof(unsigned int) * TRACK_CAP);

	ret = nfct_query(h, NFCT_Q_DUMP, &family);
	if(ret == -1){
		perror("nfct_query");
		exit(-1);
	}
	qsort(list,idx,sizeof(unsigned int),connection_list_comp);
	connection_rate();
	return;	
}

void sigint_h(int signo){
	nfct_close(h);

	//close(filefd);
	signal(SIGINT,SIG_DFL);
	printf("\n");
	exit(0);
}
	

int main(int argc, char *argv[]){
	struct itimerval value, ovalue;
	int ret;
	struct filter filter;
	memset(&filter,0,sizeof(filter));
	family = AF_INET;
	clifd = 0;

	signal(SIGALRM,sigtimer);
	signal(SIGINT,sigint_h);

	// 100 ms setting
	/*
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 1;
	value.it_interval.tv_sec = 0;
	value.it_interval.tv_usec = 100000;
	*/
	// 1 sec setting
	//*
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 1;
	value.it_interval.tv_sec = 1;
	value.it_interval.tv_usec = 0;
	//*/
	
	int opt;
	char buf[19] = "";
	char *ptr;
	struct in_addr net;
	while((opt = getopt(argc, argv, "hs:d:T:t:")) != -1){
		switch(opt){
			case 'h':
				fprintf(stderr,"Usage: ./netflow [-s <ip>] [-d <ip>] [-T <second>] [-t <millisecond>]\n\tNote: -T/-t are exclusive\n");
				exit(0);
				break;
			case 's':
				strncpy(buf,optarg,19);
				ptr = strtok(buf,"/");
				inet_aton(ptr,&net);
				filter.saddr = net.s_addr;
				ptr = strtok(NULL,"/");
				if(ptr != NULL)
					filter.smask = createmask(atoi(ptr));
				else
					filter.smask = 0xFFFFFFFF;
				break;
			case 'd':
				strncpy(buf,optarg,19);
				ptr = strtok(buf,"/");
				inet_aton(ptr,&net);
				filter.daddr = net.s_addr;
				ptr = strtok(NULL,"/");
				if(ptr != NULL)
					filter.dmask = createmask(atoi(ptr));
				else
					filter.dmask = 0xFFFFFFFF;
				break;
			case 't':
				value.it_interval.tv_usec = atoi(optarg) * 1000;
				value.it_interval.tv_sec = 0;
				break;
			case 'T':
				value.it_interval.tv_sec = atoi(optarg);
				value.it_interval.tv_usec = 0;
				break;
			/*case 'o':
				filefd = open(optarg, O_WRONLY|O_CREAT, 0666);
				dup2(filefd,1);
				break;*/
			case '?':
				fprintf(stderr,"\tUsage: ./netflow [-s <ip>] [-d <ip>] [-T <second>] [-t <millisecond>]\n\t\tNote: -T/-t are exclusive\n");
				exit(-1);
		}
	}

	connection_init();

	h = nfct_open(CONNTRACK, 0);
	if(!h){
		perror("nfct_open");
		exit(-1);
	}

	ret = nfct_callback_register(h, NFCT_T_ALL, cb, &filter);
	if(ret == -1){
		perror("nfct_callback_register");
		exit(-1);
	}


	fprintf(stderr,"Start conntrack ...\n");
	
	ret = setitimer(ITIMER_REAL,&value,&ovalue);
	if(ret == -1){
		perror("setitimer");
		exit(-1);
	}
	
	for(;;){}
	//sigtimer(SIGALRM);

	// should not be executed

	nfct_close(h);
	
	return 0;
}
