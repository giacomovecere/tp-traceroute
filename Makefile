CFLAGS := -ggdb
CC := g++

OBJS := traceroute.o icmpManager.o icmpClass.o udpManager.o udpClass.o

all: tp-traceroute

tp-traceroute: $(OBJS) main.cpp
	$(CC) $(CFLAGS) $^ -o $@

traceroute.o: 	traceroute.cpp
		g++ -c -ggdb traceroute.cpp
icmp.o: icmpClass.cpp icmpManager.cpp
	g++ -c -ggdb icmpClass.cpp icmpManager.cpp
udp.o: 	udpClass.cpp udpManager.cpp
	g++ -c -ggdb udpClass.cpp udpManager.cpp
	
clean:
	rm *.o
	rm tp-traceroute
	
clean_obj:
	rm *.o
