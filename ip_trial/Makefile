CFLAGS := -ggdb
CC := g++
DEBUG ?= 

OBJS := udpHLManager.o udpRawClass.o udpRawManager.o ipManager.o ipClass.o

all: iptrial

iptrial: 	$(OBJS) main.cpp
		$(CC) $(CFLAGS) $(DEBUG) $^ -o $@

udpHLManager.o:	udpHLManager.cpp
		g++ -c $(CFLAGS) $(DEBUG) udpHLManager.cpp
udpRawClass.o:	udpRawClass.cpp
		g++ -c $(CFLAGS) $(DEBUG) udpRawClass.cpp
udpRawManager.o:udpRawManager.cpp
		g++ -c $(CFLAGS) $(DEBUG) udpRawManager.cpp
ipClass.o: 	ipClass.cpp
		g++ -c $(CFLAGS) $(DEBUG) ipClass.cpp
ipManager.o: 	ipManager.cpp
		g++ -c $(CFLAGS) $(DEBUG) ipManager.cpp

						
	
clean:
	rm *.o
	rm tp-traceroute
clean_obj:
	rm *.o
