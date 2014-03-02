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
    
    int one = 1;
    
    // Create a packet with the provided information
    udpRawPacket = new udpRawClass(src_port, dest_port);
    
    // Create a raw socket with UDP protocol
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP); 
    
    //set the option to let the OS know that the ip header will be put by us
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one , sizeof(one))<0) 
        cout<<"ERROR\n";
    
    if(sockfd < 0 || one < 0) {
        cout<<"error in building the socket\n";
        exit(EXIT_FAILURE);
    }
    cout<<"udpRawManager ok"<<endl;
}

/* Sends an UDP Probe to the destination specified. 
 *Puts the timestamp address in the IP Header */
bool udpRawManager::tpSend(char* dest_ip, char* ts_ip, char* payload) {
    int r;
    sockaddr_in dest;
    uint16_t* buffer;
    uint8_t* ipHdr;
    uint8_t total_buffer[(IP_TS_LENGTH*4)+LENGTH_PAYLOAD];
    // set the destination and the address of the node that has to put a timpestamp
    ipHdr = udpRawPacket->setTs(dest_ip, ts_ip);
    
    // set the length of the packet and calculate che checksum of the UDP Packet
    udpRawPacket->setLengthAndChecksum(payload, buffer);
    
    // set the destination structure to which the packet is going to be sent
    udpRawPacket->setDest(&dest);
    
    /*IP part*/
    //ipManager ipm = ipManager();
    //ipHdr=ipm.prepareHeader(dest_ip, ts_ip);
    memcpy(total_buffer, ipHdr, IP_TS_LENGTH*4);
    memcpy(total_buffer+IP_TS_LENGTH*4, payload, LENGTH_PAYLOAD);
    
    cout<<"printing\n";
    
    for(int i=0; i<(IP_TS_LENGTH*4)+LENGTH_PAYLOAD; i++)
        cout<<(int)total_buffer[i]<<'\t';
    cout<<endl;
    
    // send the UDP packet 
    r = sendto(sockfd, total_buffer, (IP_TS_LENGTH*4)+LENGTH_PAYLOAD, 0, 
               (sockaddr *)&dest, sizeof(sockaddr));
    if(r == -1) {
        cout<<"Error: sendto error"<<endl;
        return false;
    }
    
    return true;
}