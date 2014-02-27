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

// fill the udphdr structure with source and destination ports
udpRawClass::udpRawClass(uint16_t src_port, uint16_t dest_port) {
    udp_hdr->source = htons(src_port);
    udp_hdr->dest = htons(dest_port);
}

/* fill the iphdr structure by calling an instance of ipManager.
 * The fields sent are the destination address and the timestamp address */
void udpRawClass::setTs(char* dest_ip, char* ts_ip) {
    ipManager iMan = new ipManager();
    ip_hdr = iMan.prepareHeader_UDP(dest_ip, ts_ip);
}

/* sets the length field in the udp_hdr structure and compute the checksum for the UDP Header.
 * the checksum is calculated on the Pseudo IP Header, the UDP Header and the UDP Payload */
uint16_t* udpRawClass::setLengthAndChecksum(char* payload) {
    //temporary variable used to change byte ordering
    uint16_t rotated;
    
    /* total_length is referred to the length of the whole datagram that will be used to compute the checksum
     * length is referred to the length of the UDP packet (udp header + payload)
     * length_pay is referred to the length of the payload
     * chs is the checksum
     * proto is the udp protocol
     */
    uint16_t total_length = LENGTH_PSEUDO_IP + LENGTH_UDP_HEADER + LENGTH_PAYLOAD;
    uint16_t length = LENGTH_UDP_HEADER + LENGTH_PAYLOAD; 
    uint16_t length_pay =  LENGTH_PAYLOAD;
    uint8_t dgram[total_length];
    uint16_t proto = 0x0011; // UDP Protocol value
    int zeros = 0x0000; // zeros
    int z;
    
    // Set the length in the udp_hdr structure
    udp_hdr->len = htons(sizeof(struct udphdr) + sizeof(payload));
    
    // Pseudo IP Header
    rotated = htons (proto);
    memcpy(dgram, &ip_hdr->ip_src, sizeof(ip_hdr->ip_src));
    memcpy(dgram + 4, &ip_hdr->ip_dst, sizeof(ip_hdr->ip_dst));
    memcpy(dgram + 8, &rotated, 2);
    
    rotated = htons(length);
    memcpy(dgram + 10, &rotated, 2);
    
    //UDP header
    memcpy(dgram + 12, &udp_hdr->source, sizeof(udp_hdr->source));
    memcpy(dgram + 14, &udp_hdr->dest, sizeof(udp_hdr->dest));
    
    memcpy(dgram + 16, &rotated, 2);
    memcpy(dgram + 18, &zeros, 2);
    
    //payload UDP
    memcpy(dgram + 20, payload, length_pay);
    
    udp_hdr->check = computeChecksum((uint16_t*)dgram, total_length);
    memcpy(dgram + 18, &udp_hdr->check, 2);
    
    #ifdef _DEBUG
        fprintf(stdout, "Checksum generated: %4x \n\n", udp_hdr->check);
    #endif
        
    return (uint16_t*) dgram;
}

/* fill the sockaddr_in structure related to the destination */
void udpRawClass::setDest(sockaddr_in* dest) {
    //dest->sin_addr = ip_hdr->ip_dst; it's the same
    *dest.sin_addr = ip_hdr->ip_dst;
    *dest.sin_family = AF_INET;
    *dest.sin_port = udp_hdr->dest;
}
