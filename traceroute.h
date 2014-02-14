/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 * Traceroute Header File
 * 
 */
 
#include "udp.h"
#include "icmp.h"

// time to wait for ICMP reply packets (at maximum) 
#define TIMEOUT_SELECT 3

class traceroute {
    list<addr> array[MAX_TTL_DEF];
    uint16_t src_port; 
    
    public:
    
    traceroute(uint16_t);
    
    bool trace(char*, int, uint16_t);
    
    list<addr> getList();
    
    friend ostream& operator<<(ostream& output, traceroute& t);
	
};
