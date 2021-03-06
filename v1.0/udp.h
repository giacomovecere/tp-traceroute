/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
#pragma once    /* Avoid multiple include of this file during compilation */
#include "ip.h"

/* UDP High Level Manager: manages the transmission of an UDP packet with SOCK_DGRAM socket */
class udpHLManager {
    //socket file descriptor
    int sockfd;
    sockaddr_in src, dest;
    
    public:
    // The constructor opens 
    udpHLManager(uint16_t);
    
    /* 
     * Sends 'n_probe' UDP packets to the destination specified in 
     * the parameteres of the method. 
     * It fills 'vett_addr' with the information required 
    */
    bool send(char*, uint16_t, int, int, int, addr*);   

};

/* Handles the creation of an UDP packet prepared for being trasmitted on a RAW socket */
class udpRawClass {
    ipManager* ipM;
    in_addr src_address;
    in_addr dst_address;
    udphdr udp_hdr;    //udp header
    uint8_t* ip_hdr;
    
public:
    // fill the udphdr structure with source and destination ports
    udpRawClass(uint16_t, uint16_t);
    ~udpRawClass();
    
    /* fill the iphdr structure by calling an instance of ipManager.
    * The fields sent are the destination address and the timestamp address */
    uint8_t* setTs(char*, char*);
       
    /* sets the length field in the udp_hdr structure and compute the checksum 
     * for the UDP Header. The checksum is calculated on the Pseudo IP Header, 
     * the UDP Header and the UDP Payload */
    void setLengthAndChecksum(char*);
    
    /* fill the sockaddr_in structure related to the destination */
    void setDest(sockaddr_in*);
    
    uint8_t* getHeader() {return (uint8_t*)&udp_hdr;};
    in_addr getSource() {return src_address;};
    
};

/* Manages the transmission of an UDP packet on a RAW socket, using a RAW packet
 * created by udpRawClass */
class udpRawManager {
    //socket file descriptor
    int sockfd;
    udpRawClass* udpRawPacket;
    
public:
    
    /* Constructor: creates a raw udp socket and creates a new udpRawPacket */
    udpRawManager(uint16_t, uint16_t);
    //destroyer
    ~udpRawManager();
    
    /* Sends an UDP Probe to the destination specified. Puts the timestamp 
     *address in the IP Header */
    bool tpSend(char*, char*, char*);
};

/* The two functions compute the Internet Checksum by adding all the data 
 * contained in the datagram. A part of the IP Header, the pseudo IP Header 
 * (src_address, dest_address, protocol and UDP length), the entire UDP Header 
 * and the payload*/
uint16_t calcChecksum(const uint16_t*, int);
uint16_t computeChecksum(sockaddr_in, sockaddr_in*, char*);    
