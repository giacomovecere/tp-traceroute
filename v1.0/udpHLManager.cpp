/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
 #include "udp.h"

udpHLManager::udpHLManager(uint16_t src_port) {        
    // Creation of DGRAM socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    
    //source structure initialization
    src.sin_family = AF_INET;
    src.sin_port = htons(src_port);
    
    //retrieve external ip address of the source host 
    struct ifaddrs * ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    void * tmpAddrPtr = NULL;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa ->ifa_addr->sa_family == AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
        }
    }
    
    memcpy(&src.sin_addr, tmpAddrPtr, sizeof(in_addr));
    
    //bind the socket to the source address and port
    bind(sockfd, (sockaddr*)&src, sizeof(sockaddr)); 
    
    freeifaddrs(ifAddrStruct);  
} 
	    
/* @Purpose: send n udp probes to a destination with the ttl field that varies
 *           according to the traceroute mechanism, hence the ttl is increased
 *           at each time, the payload is changed in order to avoid load-balancing
 * @Parameters:
 *          (IN)
 *              ip_address: destination ipaddress in host format
 *              dest_port: destination port
 *              ttl: time to live field in the ipheader
 *              payload: payload of the udp packet
 *              n_probe: number of probes to send
 *          (INOUT)
 *              vett_addr: already allocated outside, is useful to save all the 
 *                         future needed informations
 * @Returns: the result of the send, true if it's ok false otherwise
 */
bool udpHLManager::send(char* ip_address, uint16_t dest_port, int ttl, int payload, 
                        int n_probe, addr* vett_addr) {
    
    //NOTE c_payload becomes a void pointer to a memory location
    char c_payload[sizeof(int)];
    int probe;
    
    //set the TTL
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
    
    //destination structure initialization
    dest.sin_family=AF_INET;                
    dest.sin_port=htons(dest_port);        
    inet_pton(AF_INET, ip_address, &dest.sin_addr);
    
    for(probe = 0; probe < n_probe; probe++) {
        // converts payload from int to character
        memcpy(c_payload, &payload, sizeof(int));
        
        // calculates the checksum of the packet
        vett_addr[probe].checksum = computeChecksum(src, &dest, c_payload);

        // setting the current time
        gettimeofday(&vett_addr[probe].time, NULL);

        // sends the UDP packet 
        int x = sendto(sockfd, c_payload, sizeof(c_payload), 0, (sockaddr *)&dest,
                       sizeof(sockaddr));
        if(x == -1) {
            cerr<<"Error: sendto error"<<endl;
            return false;
        }
        
        /* set the return field at false, it will be set to true if the probe 
         * receives an answer */
        vett_addr[probe].ret = false;
        
        // changhes the payload for changing the checksum field [as Paris-traceroute does]
        payload++;
    }
    return true;
}		

/* @Purpose: compute the internet checksum of the udp packet
 * @Parameters: 
 *              (IN) 
 *                  dgram: represents the fields on which compute the checksum:
 *                  length: length of dgram
 * @Returns: the computed checksum
 */
uint16_t calcChecksum(const uint16_t* dgram, int length) {
    uint32_t sum = 0;
    
    //scan the datagram and add to each other all the fields
    while (length > 1) {
        sum += (*dgram++);
        length -= 2;
    }
    
    
    if (length > 0) sum += *(uint8_t*)dgram;

    // Put the sum on 16 bits by adding the two 16-bits parts
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    
    //complement 1 of the sum
    return ~sum;
}

/* NOTE: the UDP checksum needs to be computed in the byte ordering used by 
 * the network, not by the processor, source address and port and destination 
 * address and port are already ordered according to the network, this is done 
 * in the inet_pton and htons functions in the constructor and setDest function. 
 * The fields that need to be ordered are the protocol and the length of the
 * whole packet*/
/* NOTE: The fields on which the Checksum is computed are:
 *          PSEUDO_IP_HEADER 
 * |        Source IP Address       |
 * |        Dest   IP Address       |
 * |  00  | Proto  |   UDP Length   |
 *          UDP_PACKET
 * |  Source Port  | Destination Port |
 * |  UDP_LENGTH   | Checksum (0x0000)|
 * |        Payload                   |
 */
/* @Purpose: arrange the fields to compute the checksum and then do it
 * @Parameters:
 *          (IN)
 *              src: source address in network format
 *              dst: destination address in network format
 *              payload: payload of the UDP packet 
 * @Returns: the computed checksum
 */
uint16_t computeChecksum(sockaddr_in src, sockaddr_in* dest, char* payload) {
    
    //this is a temporary variable used to change byte ordering
    uint16_t rotated;
    
    /* total_length: referred to the length of the whole datagram that will be 
     * used to compute the checksum length is referred to the length of the UDP 
     * packet (udp header + payload) 
     * length_pay: referred to the length of the payload
     * chs: checksum
     * proto: the udp protocol
     */
    uint16_t total_length = LENGTH_PSEUDO_IP + LENGTH_UDP_HEADER + LENGTH_PAYLOAD;
    uint16_t length = LENGTH_UDP_HEADER + LENGTH_PAYLOAD; 
    uint16_t length_pay =  LENGTH_PAYLOAD;
    uint8_t dgram[total_length];
    uint16_t proto = 0x0011;
    int chs = 0x0000;
    
    //all the memcopy are useful to preapre the structure on which we need 
    //to compute the checksum
    rotated = htons (proto);
    memcpy(dgram, &src.sin_addr, sizeof(src.sin_addr));
    memcpy(dgram + 4, &dest->sin_addr, sizeof(dest->sin_addr));
    memcpy(dgram + 8, &rotated, 2);
    
    rotated = htons(length);
    
    memcpy(dgram + 10, &rotated, 2);
    
    //UDP header
    memcpy(dgram + 12, &src.sin_port, sizeof(src.sin_port));
    memcpy(dgram + 14, &dest->sin_port, sizeof(dest->sin_port));
    
    memcpy(dgram + 16, &rotated, 2);
    memcpy(dgram + 18, &chs, 2);
    
    //payload UDP
    memcpy(dgram + 20, payload, length_pay);
    
    chs = calcChecksum((uint16_t*)dgram, total_length);
    
    #ifdef _DEBUG
        fprintf(stdout, "Checksum generated: %4x \n\n", chs);
    #endif
    return chs;
}   

