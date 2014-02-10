/*ICMP header file*/
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstdlib>
#include <cstring>

using namespace std;

struct icmpPacket{
	
	char buffer[28];       //28 bytes of the ICMP message payload
	struct icmp* rec_msg;  
	int sockfd;            //file descriptor of the socket
	struct sockaddr router_source;   //filled by the sender
	
};


class icmpClass{
	
	icmpPacket datagram;
	//parameters of the UDP message sent needed to do the checking
	int sent_port;
	int dest_port;
	char* ipAddress;     //ip of the router that answers
	
	public:
	icmpClass(int s, int d);
	
	//returns the whole buffer of the ICMP packet
	char* getBuffer();
	
	//returns the socket on which receive the ICMP
	int getSocket();
	
	//returns the IP of the source of the ICMP
	char* getIP();
	
	//returns the port on which the UDP probe was sent
	int getPort();
	
	//receive the ICMP packet
	int recv(int* );
	
};
