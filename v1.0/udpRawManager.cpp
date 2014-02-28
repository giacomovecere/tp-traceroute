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

/* Constructor of the class: sets the information that are the same for the entire detection process */
udpRawManager::udpRawManager(uint16_t src_port, uint16_t dest_port) {
    
    // Create a packet with the provided information
    udpRawPacket = new udpRawClass(src_port, dest_port);
    
    // Create a raw socket with UDP protocol
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);  
    if(sockfd < 0) {
        cerr<<"error in building the socket\n";
        exit(EXIT_FAILURE);
    }
}

/* Sends an UDP Probe to the destination specified. Puts the timestamp address in the IP Header */
bool udpRawManager::tpSend(char* dest_ip, char* ts_ip, char* payload) {
    int r;
    sockaddr_in dest;
    uint16_t* buffer;
    
    // set the destination and the address of the node that has to put a timpestamp
    udpRawPacket->setTs(dest_ip, ts_ip);
    
    // set the length of the packet and calculate che checksum of the UDP Packet
    udpRawPacket->setLengthAndChecksum(payload, buffer);
    
    // set the destination structure to which the packet is going to be sent
    udpRawPacket->setDest(&dest);
    
    // send the UDP packet 
    r = sendto(sockfd, buffer, sizeof(buffer), 0, (sockaddr *)dest, sizeof(sockaddr));
    if(r == -1) {
        cerr<<"Error: sendto error"<<endl;
        return false;
    }
    
    return true;
}