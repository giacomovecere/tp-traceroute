#include "udp.h"

udp::udp(char* dest_addr, int dest_port,int source_port) {
    
    datagram.sockfd=Socket(AF_INET, SOCK_DGRAM, 0);   //socket file descriptor
    
    //destination structure initialization
    datagram.dest.sin_family=AF_INET;                
    datagram.dest.sin_port=htons(dest_port);        
    inet_pton(AF_INET, dest_addr, &datagram.dest.sin_addr);
    
    //source structure initialization
    datagram.src.sin_family=AF_INET;
    datagram.src.sin_port=htons(source_port);
    inet_pton(AF_INET, INADDR_ANY, &datagram.src.sin_addr);
    
    //bind the socket to the source address and port
    bind(datagram.sockfd, &datagram.src.sin_adrr, sizeof(sockaddr)); 
    	
}

/* Method for setting the 'Time to Leave' field in the IP Header */
void udp::setTtl(int ttl) {
	Setsockopt(datagram.sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
}

/* The method returns the socket file descriptor of the established connection*/
int udp::getSock() {
	return datagram.sockfd;
}

/* The method returns the sockaddr_in structure that contains the details 
 * of the source host */
sockaddr_in udp::getSrcAddr() {
	return datagram.src;
}

/* The method returns the sockaddr_in structure that contains the details 
 * of the destination host */
sockaddr_in udp::getDestAddr() {
	return datagram.dest;
}

/* The method returns the payload of the datagram */
void udp::setPayload(char* buff) {
	strcpy(datagram.payload, buff);
}

uint16_t getChecksum() {
	char dgram[16 + LENGTH_PAYLOAD];
	
	memcpy(dgram, &datagram.src.sin_addr, sizeof(datagram.src.sin_addr));
	memcpy(dgram + 4, &datagram.dest.sin_addr, sizeof(datagram.dest.sin_addr));
	memcpy(dgram + 8, (void*)&AF_INET, 2);
	memcpy(dgram + 10, &datagram.src.sin_port, sizeof(datagram.src.sin_port));
	memcpy(dgram + 12, &datagram.dest.sin_port, sizeof(datagram.dest.sin_port));
	memcpy(dgram + 14, (void*)&LENGTH_PAYLOAD, 2);	
	memcpy(dgram + 16, datagram.payload, LENGTH_PAYLOAD);

	return computeChecksum(dgram, 16 + LENGTH_PAYLOAD);
}	

/* Compute Internet Checksum by addind all the data contained in the 
 * datagram. A part of the IP Header (src_address, dest_address, protocol), 
 * the entire UDP Header and the payload*/
uint16 udp::computeChecksum(const uint16* dgram, int length) {
	uint32 sum = 0;

	while (length > 1) {
		sum += *dgram++;
		length -= 2;
	}

	if (length > 0) sum += *(uint8*)dgram;

	// Put the sum on 16 bits by adding the two 16-bits parts
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}
