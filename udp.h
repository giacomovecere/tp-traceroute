/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "trace_header.h"

#define LENGTH_PAYLOAD 4
#define LENGTH_UDP_HEADER 8
#include <ifaddrs.h>

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
    
    int getSock();

    sockaddr_in getSrc();

    sockaddr_in* getDest();

    uint16_t getChecksum();

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
