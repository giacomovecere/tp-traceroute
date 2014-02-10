/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "trace_header.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define LENGTH_PAYLOAD 4

using namespace std;

struct udpPacket {
	int sockfd;
	struct sockaddr_in dest, src;
	char payload[LENGTH_PAYLOAD];
	uint16_t checksum;
};

class udpClass{
	udpPacket datagram;
		
	public:
	udpClass(char*, uint16_t);
	
	void setDestPort(uint16_t);
	
	void setTtl(int);
	
	int getSock();
	
	sockaddr_in getSrcAddr();

	sockaddr_in getDestAddr();
	
	void setPayload(char*);
	
	uint16_t getChecksum();
};

