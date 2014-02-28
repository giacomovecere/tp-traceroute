CFLAGS := -ggdb
CC := g++
DEBUG ?= 

OBJS := traceroute.o icmpManager.o icmpClass.o udpHLManager.o udpRawClass.o udpRawManager-o

all: tp-traceroute

tp-traceroute: 	$(OBJS) main.cpp
		$(CC) $(CFLAGS) $(DEBUG) $^ -o $@

traceroute.o: 	traceroute.cpp
		g++ -c $(CFLAGS) $(DEBUG) traceroute.cpp
icmpClass.o: 	icmpClass.cpp 
		g++ -c $(CFLAGS) $(DEBUG) icmpClass.cpp
icmpManager.o:	icmpManager.cpp
		g++ -c $(CFLAGS) $(DEBUG) icmpManager.cpp
udpHLManager.o:	udpHLManager.cpp
		g++ -c $(CFLAGS) $(DEBUG) udpHLManager.cpp
udpRawClass.o:	udpRawClass.cpp
		g++ -c $(CFLAGS) $(DEBUG) udpRawClass.cpp
udpRawManager.o:udpRawManager.cpp
		g++ -c $(CFLAGS) $(DEBUG) udpRawManager.cpp
						
	
clean:
	rm *.o
	rm tp-traceroute
clean_obj:
	rm *.o
