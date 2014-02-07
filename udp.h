/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

struct udpPacket {
	int sockfd;
	struct sockaddr_in addr;
	char* payload;
	uint16_t checksum;
};

class udp{
	udpPacket datagram;
	
	public:
	udp(char*, char*, char*, char*);
	
	void setTtl(int);
	
	int getSock();
	
	sockaddr_in getSockAddr();
	
	voi setPayload(char* payload);
	
	uint16_t computeChecksum(uint16_t* datagram, int length);
};

