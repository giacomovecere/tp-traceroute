#include "udp.h"

udpClass::udpClass(uint16_t source_port=0) {
    
    sockfd=socket(AF_INET, SOCK_DGRAM, 0);   //socket file descriptor
    
    //source structure initialization
    src.sin_family=AF_INET;
    src.sin_port=htons(source_port);
    inet_pton(AF_INET, INADDR_ANY, &src.sin_addr);
    
    //bind the socket to the source address and port
    bind(sockfd, (sockaddr*)&src, sizeof(sockaddr)); 
    	
}

/* Method for setting the destination address and port */
void udpClass::setDest(char* dest_addr, uint16_t dest_port) {
    //destination structure initialization
    dest.sin_family=AF_INET;                
    dest.sin_port=htons(dest_port);        
    inet_pton(AF_INET, dest_addr, &dest.sin_addr);
}

/* Method for setting the 'Time to Leave' field in the IP Header */
void udpClass::setTtl(int ttl) {
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
}

/* The method returns the socket file descriptor of the established connection*/
int udpClass::getSock() {
    return sockfd;
}

/* The method returns the sockaddr_in structure that contains the details 
 * of the source host */
sockaddr_in udpClass::getSrc() {
    return src;
}

/* The method returns the sockaddr_in structure that contains the details 
 * of the destination host */
sockaddr_in udpClass::getDest() {
    return dest;
}

/* The method returns the payload of the datagram */
void udpClass::setPayload(char* buff) {
    memcpy(payload, buff, sizeof(buff));
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
    
    memcpy(dgram, &src.sin_addr, sizeof(src.sin_addr));
    memcpy(dgram + 4, &dest.sin_addr, sizeof(dest.sin_addr));
    memcpy(dgram + 8, &proto, 2);
    memcpy(dgram + 10, &src.sin_port, sizeof(src.sin_port));
    memcpy(dgram + 12, &dest.sin_port, sizeof(dest.sin_port));
    memcpy(dgram + 14, (void*)&length_pay, 2);	
    memcpy(dgram + 16, payload, length_pay);

    return computeChecksum((uint16_t*)dgram, length);
}	

