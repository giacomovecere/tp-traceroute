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
    
    int on;
    
    // Create a packet with the provided information
    udpRawPacket = new udpRawClass(src_port, dest_port);
    
    // Create a raw socket with UDP protocol
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP); 
    
    //set the option to let the OS know that the ip header will be put by us
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on , sizeof(on));
    
    if(sockfd < 0) {
        cerr<<"error in building the socket\n";
        exit(EXIT_FAILURE);
    }
}

/* Sends an UDP Probe to the destination specified. 
 *Puts the timestamp address in the IP Header */
bool udpRawManager::tpSend(char* dest_ip, char* ts_ip, char* payload) {
    int r;
    sockaddr_in dest;
    uint16_t* buffer;
    uint16_t* ipHdr;
    uint16_t total_buffer[(IP_TS_LENGTH*4)+LENGTH_PAYLOAD];
    // set the destination and the address of the node that has to put a timpestamp
    udpRawPacket->setTs(dest_ip, ts_ip);
    
    // set the length of the packet and calculate che checksum of the UDP Packet
    udpRawPacket->setLengthAndChecksum(payload, buffer);
    
    // set the destination structure to which the packet is going to be sent
    udpRawPacket->setDest(&dest);
    
    /*IP part*/
    ipManager ipm = new ipManager;
    ipHdr=ipm.prepareHeader();
    
    
    
    // send the UDP packet 
    r = sendto(sockfd, buffer, sizeof(buffer), 0, (sockaddr *)dest, sizeof(sockaddr));
    if(r == -1) {
        cerr<<"Error: sendto error"<<endl;
        return false;
    }
    
    return true;
}