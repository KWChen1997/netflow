#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include <mysql.h>

#include "../netflow.h"

int main(){
	pid_t pid;
	int pipefd[2];
	if(pipe2(pipefd, O_DIRECT) == -1){
		perror("pipe");
		exit(-1);
	}

	if((pid = fork()) == -1){
		perror("fork");
		exit(-1);
	}
	if(pid == 0){
		// child
		// write to pipefd[1]
		dup2(pipefd[1],STDOUT_FILENO);
		close(pipefd[0]);
		if(execl("../netflow", "netflow", "-s","10.42.0.205",NULL) == -1){
			perror("exec");
			exit(-1);
		}
	}
	else{
		// parent
		// read from pipefd[0]
		close(pipefd[1]);
		MYSQL *con = mysql_init(NULL);
		if(con == NULL){
			fprintf(stderr, "%s\n", mysql_error(con));
			kill(pid, SIGKILL);
			exit(-1);
		}
	
		if(mysql_real_connect(con, "localhost", "root", "kwchen", "dnsprofile", 0, NULL, 0) == NULL){
			fprintf(stderr, "%s\n", mysql_error(con));
			kill(pid, SIGKILL);
			mysql_close(con);
			exit(-1);
		}
		/*
		if(mysql_query(con, "USE dnsprofile;")){
			fprintf(stderr, "%s\n", mysql_error(con));
			kill(pid, SIGKILL);
			mysql_close(con);
			exit(-1);
		}
		*/
		struct connection conn;
		int rc;
		char buf[1024];
		int status;
		while(1){
			rc = read(pipefd[0], &conn, sizeof(struct connection));
			if(rc == 0)
				break;
			if(conn.valid == 0){
				printf("--------------------------------\n");
				continue;
			}
			snprintf(buf, sizeof(buf), "INSERT IGNORE access VALUE (\'%u.%u.%u.%u\', \'%u.%u.%u.%u\');", NIPQUAD(conn.saddr), NIPQUAD(conn.daddr));
			printf("src %u.%u.%u.%u sport %u dst %u.%u.%u.%u dport %u packets %lu\n", NIPQUAD(conn.saddr), conn.sport, NIPQUAD(conn.daddr), conn.dport, conn.packets);
			
			if(mysql_query(con, buf)){
				fprintf(stderr, "%s\n", mysql_error(con));
				kill(pid, SIGKILL);
				mysql_close(con);
				exit(-1);
			}
			
			//printf("qry_name %s ip %s\n", qry.name, qry.addr);

		}
		waitpid(pid,NULL,0);
	}
	
	return 0;
}
