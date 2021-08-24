CC=gcc
CFLAGS= -g -Wall
CLIBS= -lnetfilter_conntrack
PROG=netflow

all: $(PROG)

$(PROG):$(PROG).c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

server:server.c
	$(CC) $(CFLAGS) -o $@ $^
clean:
	rm $(PROG) server
