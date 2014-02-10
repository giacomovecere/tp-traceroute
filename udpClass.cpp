#include "udpClass.h"

udpClass::udpClass(char* dest_addr, uint16_t source_port) {
    
    datagram.sockfd=socket(AF_INET, SOCK_DGRAM, 0);   //socket file descriptor
    
    //source structure initialization
    datagram.src.sin_family=AF_INET;
    datagram.src.sin_port=htons(source_port);
    inet_pton(AF_INET, INADDR_ANY, &datagram.src.sin_addr);
    
    //bind the socket to the source address and port
    bind(datagram.sockfd, (sockaddr*)&datagram.src, sizeof(sockaddr)); 
    	
}

/* Method for setting the destination port */
void udpClass::setTtl(uint16_t dest_port) {
    //destination structure initialization
    datagram.dest.sin_family=AF_INET;                
    datagram.dest.sin_port=htons(dest_port);        
    inet_pton(AF_INET, dest_addr, &datagram.dest.sin_addr);
}

/* Method for setting the 'Time to Leave' field in the IP Header */
void udpClass::setTtl(int ttl) {
	setsockopt(datagram.sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
}

/* The method returns the socket file descriptor of the established connection*/
int udpClass::getSock() {
	return datagram.sockfd;
}

/* The method returns the sockaddr_in structure that contains the details 
 * of the source host */
sockaddr_in udpClass::getSrcAddr() {
	return datagram.src;
}

/* The method returns the sockaddr_in structure that contains the details 
 * of the destination host */
sockaddr_in udpClass::getDestAddr() {
	return datagram.dest;
}

/* The method returns the payload of the datagram */
void udpClass::setPayload(char* buff) {
	memcpy(datagram.payload, buff, sizeof(buff));
}


/* Compute Internet Checksum by addind all the data contained in the 
 * datagram. A part of the IP Header (src_address, dest_address, protocol), 
 * the entire UDP Header and the payload*/
uint16_t computeChecksum(const uint16_t* dgram, int length) {
	uint32_t sum = 0;

	while (length > 1) {
		sum += *dgram++;
		length -= 2;
	}

	if (length > 0) sum += *(uint8_t*)dgram;

	// Put the sum on 16 bits by adding the two 16-bits parts
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

uint16_t udpClass::getChecksum() {
	int length = 16 + LENGTH_PAYLOAD;
	int length_pay = LENGTH_PAYLOAD;
	char dgram[length];
	const int proto = 0x11;
	
	memcpy(dgram, &datagram.src.sin_addr, sizeof(datagram.src.sin_addr));
	memcpy(dgram + 4, &datagram.dest.sin_addr, sizeof(datagram.dest.sin_addr));
	memcpy(dgram + 8, &proto, 2);
	memcpy(dgram + 10, &datagram.src.sin_port, sizeof(datagram.src.sin_port));
	memcpy(dgram + 12, &datagram.dest.sin_port, sizeof(datagram.dest.sin_port));
	memcpy(dgram + 14, (void*)&length_pay, 2);	
	memcpy(dgram + 16, datagram.payload, length_pay);

	return computeChecksum((uint16_t*)dgram, length);
}	

