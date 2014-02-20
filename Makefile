CFLAGS := -ggdb
CC := g++
DEBUG ?= 

OBJS := traceroute.o icmpManager.o icmpClass.o udpManager.o udpClass.o

all: tp-traceroute

tp-traceroute: 	$(OBJS) main.cpp
		$(CC) $(CFLAGS) $(DEBUG) $^ -o $@

traceroute.o: 	traceroute.cpp
		g++ -c $(CFLAGS) $(DEBUG) traceroute.cpp
icmpClass.o: 	icmpClass.cpp 
		g++ -c $(CFLAGS) $(DEBUG) icmpClass.cpp
icmpManager.o:	icmpManager.cpp
		g++ -c $(CFLAGS) $(DEBUG) icmpManager.cpp
udpClass.o: 	udpClass.cpp 
		g++ -c $(CFLAGS) $(DEBUG) udpClass.cpp
udpManager.o:	udpManager.cpp
		g++ -c $(CFLAGS) $(DEBUG) udpManager.cpp
	
clean:
	rm *.o
	rm tp-traceroute
clean_obj:
	rm *.o
