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

using namespace std;


class udpClass {
    
    int sockfd;
    sockaddr_in dest, src;
    char payload[LENGTH_PAYLOAD];
    uint16_t checksum;
    
    public:
    udpClass(uint16_t);

    void setDest(char*, uint16_t);

    void setTtl(int);

    int getSock();

    sockaddr_in getSrc();

    sockaddr_in getDest();

    void setPayload(char*);

    uint16_t getChecksum();
};

class udpManager : public udpClass {

    public:
    udpManager(uint16_t);

    addr* send(char*, uint16_t, int, int, int);	
    
};
