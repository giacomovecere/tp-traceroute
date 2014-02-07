/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#define LENGTH_PAYLOAD 4

struct udpPacket {
	int sockfd;
	struct sockaddr_in dest, src;
	char payload[LENGTH_PAYLOAD];
	uint16_t checksum;
};

class udp{
	udpPacket datagram;
	
	public:
	udp(char*, int, int);
	
	void setTtl(int);
	
	int getSock();
	
	sockaddr_in getSrcAddr();

	sockaddr_in getDestAddr();
	
	void setPayload(char*);
	
	uint16_t computeChecksum(uint16_t*, int);
};

