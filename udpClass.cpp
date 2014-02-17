#include "udp.h"
#include <iomanip>

udpClass::udpClass(uint16_t source_port=0) {
    
    sockfd=socket(AF_INET, SOCK_DGRAM, 0);   //socket file descriptor
    
    char buff[50];
    
    //source structure initialization
    src.sin_family=AF_INET;
    src.sin_port=htons(source_port);
    
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa ->ifa_addr->sa_family==AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer); 
	}
    }
    
    memcpy(&src.sin_addr, tmpAddrPtr, sizeof(in_addr));
    
    //bind the socket to the source address and port
    bind(sockfd, (sockaddr*)&src, sizeof(sockaddr)); 
    
    freeifaddrs(ifAddrStruct);
    	
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
sockaddr_in* udpClass::getDest() {
    return &dest;
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
    
    //for(int i=0; i<length; i++)
	//sum+=dgram[i];
    while (length > 1) {
        sum += (*dgram++);
        length -= 2;
    }
    
    
    if (length > 0) sum += *(uint8_t*)dgram;

    // Put the sum on 16 bits by adding the two 16-bits parts
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

uint16_t udpClass::getChecksum() {
    uint16_t total_length = LENGTH_PSEUDO_IP + LENGTH_UDP_HEADER + LENGTH_PAYLOAD;
    uint16_t length = LENGTH_UDP_HEADER + LENGTH_PAYLOAD; 
    uint16_t length_pay =  LENGTH_PAYLOAD;
    uint8_t dgram[total_length];
    const uint16_t proto = 0x1100;
    const int chs = 0x0000;
    //uint16_t print[total_length/2];
    //pseudo IP header
    memcpy(dgram, &src.sin_addr, sizeof(src.sin_addr));
    memcpy(dgram + 4, &dest.sin_addr, sizeof(dest.sin_addr));
    memcpy(dgram + 8, &proto, 2);
    dgram[10]=0x00;
    dgram[11]=0x0c;
    
    //UDP header
    memcpy(dgram + 12, &src.sin_port, sizeof(src.sin_port));
    memcpy(dgram + 14, &dest.sin_port, sizeof(dest.sin_port));
    dgram[16]=0x00;
    dgram[17]=0x0c;
    memcpy(dgram + 18, &chs, 2);
    
    //payload UDP
    memcpy(dgram + 20, payload, length_pay);
    
    /*for(int i=0; i<24; i++)
      fprintf(stdout, "%4x ", dgram[i]);
    cout<<endl;*/
    
    int z = computeChecksum((uint16_t*)dgram, total_length);
    fprintf(stdout, "Checksum: %4x ", z);
    
    return z;
}	

