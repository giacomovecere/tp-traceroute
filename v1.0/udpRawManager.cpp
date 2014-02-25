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
udpRawManager::udpRawManager(uint16_t src_port, char* dest_ip, uint16_t dest_port) {
    
    // Create a packet with the provided information
    udpRawPacket = new udpRawClass(src_port, dest_ip, dest_port);
    
    // Create a raw socket with UDP protocol
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);  
    if(sockfd < 0) {
        cerr<<"error in building the socket\n";
        exit(EXIT_FAILURE);
    }
}

bool udpRawManager::tpSend(char* ts_ip, char* payload) {
    int r;
    
    udpRawPacket->setTs(ts_ip);
    
    
    // send the UDP packet 
    r = sendto(sockfd, payload, sizeof(payload), 0, (sockaddr *)dest, sizeof(sockaddr));
    if(r == -1) {
        cerr<<"Error: sendto error"<<endl;
        return false;
    }
    
}