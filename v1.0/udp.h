/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "ip.h"
#include <iomanip>
#include <ifaddrs.h>

#define LENGTH_PAYLOAD 4
#define LENGTH_UDP_HEADER 8

using namespace std;

/*
 * ip: ip address
 * time: timestamp
 * checksum: checksum of the packet
 * ret: it is set if we receive a reply to the sent packet
 */

class udpClass {
    
    //socket file descriptor
    int sockfd;
    //destination and source address
    sockaddr_in dest, src;
    //payload of the UDP packet
    char payload[LENGTH_PAYLOAD];
    //software computed checksum of the UDP packet
    uint16_t checksum;
    
public:
    
    udpClass(uint16_t);
    
    /* get Methods */
    int getSock();
    sockaddr_in getSrc();
    sockaddr_in* getDest();
    uint16_t getChecksum();

    /* set Methods */
    void setDest(char*, uint16_t);
    void setTtl(int);
    void setPayload(char*);

};

class udpManager {
	udpClass* udpPacket;
	
    public:
    // The constructor sets the source port by calling the udpClass constructor
    udpManager(uint16_t);
    
    /* 
     * Sends 'n_probe' UDP packets to the destination specified in the parameteres
     * of the method. 
	 * It fills 'vett_addr' with the information required 
    */
    bool send(char*, uint16_t, int, int, int, addr*);	
    
};

class udpRawClass {
    ip* ip_hdr;         //ip header
    udphdr* udp_hdr;    //udp header
    
public:
    // fill the udphdr structure with source and destination ports
    udpRawClass(uint16_t, char*, uint16_t);
    
    /* fill the iphdr structure by calling an instance of ipManager.
    * The fields sent are the destination address and the timestamp address */
    void setTs(char*, char*);
       
    /* sets the length field in the udp_hdr structure and compute the checksum for the UDP Header.
    * the checksum is calculated on the Pseudo IP Header, the UDP Header and the UDP Payload */
    uint16_t setLengthAndChecksum(char*);
    
    /* fill the sockaddr_in structure related to the destination */
    void setDest(sockaddr_in*);
};

class udpRawManager {
    //socket file descriptor
    int sockfd;
    udpRawClass* udpRawPacket;
    
public:
    
    /* Constructor of the class: creates a raw udp socket and creates a new udpRawPacket */
    udpRawManager(uint16_t, uint16_t);
    
    /* Sends an UDP Probe to the destination specified. Puts the timestamp address in the IP Header */
    bool tpSend(char*, char*, char*);
};

/* Compute Internet Checksum by addind all the data contained in the 
 * datagram. A part of the IP Header (src_address, dest_address, protocol), 
 * the entire UDP Header and the payload*/
uint16_t computeChecksum(const uint16_t*, int);