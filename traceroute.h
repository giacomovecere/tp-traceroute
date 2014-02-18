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
#include <sys/socket.h>
// #include <sys/types>
#include <netdb.h>
#include "trace_header.h"

// time to wait for ICMP reply packets (at maximum) 
#define TIMEOUT_SELECT 5

class traceroute {
    list<addr> array_ip_list[MAX_TTL_DEF];
    uint16_t src_port; 
    
    public:
    
    traceroute(uint16_t);
    ~traceroute();
    
    bool trace(char*, int, uint16_t);
    
    list<addr>* getArrayList();
    
    friend ostream& operator<<(ostream& output, traceroute& t);
	
};
