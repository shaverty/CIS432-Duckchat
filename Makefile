CC=g++

CFLAGS=-Wall -W -g 

LOADLIBES=-lsocket -lnsl

all: client server

client: client.cpp raw.c
	$(CC) client.cpp raw.c $(LOADLIBES) $(CFLAGS) -o client

server: server.cpp 
	$(CC) server.cpp $(LOADLIBES) $(CFLAGS) -o server

clean:
	rm -f client server *.o
