/*ICMP header file*/
#include <netinet/ip.h>
#include <netiniet/ip_icmp.h>
#include <sys/socket.h>

using namespace std;

struct icmpPacket{
	
	char buffer[28];       //28 bytes of the ICMP message payload
	struct icmp* rec_msg;  
	int sockfd;            //file descriptor of the socket
	struct sockaddr router_source;   //filled by the sender
	
};


class icmpClass{
	
	icmpPacket datagram;
	
	public:
	icmpClass();
	
	char* getBuffer();
	
	int getSocket();
	
	char* getSource();
	
	bool recv(int* );
	
};
