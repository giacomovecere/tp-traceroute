all: tp-traceroute

tp-traceroute: main.o traceroute.o icmp.o udp.o
	g++ main.o icmpManager.o icmpClass.o udpManager.o udpClass.o traceroute.o -o tp-traceroute
main.o: main.cpp
	g++ -c -ggdb main.cpp
traceroute.o: traceroute.cpp
	g++ -c -ggdb traceroute.cpp
icmp.o: icmpClass.cpp icmpManager.cpp
	g++ -c -ggdb icmpClass.cpp icmpManager.cpp
udp.o: udpClass.cpp udpManager.cpp
	g++ -c -ggdb udpClass.cpp udpManager.cpp
clean:
	rm *.o
